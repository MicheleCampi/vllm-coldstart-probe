# vllm-coldstart-probe

eBPF-based investigation tool for vLLM cold-start latency on NVIDIA GPUs.

Captures kernel-side syscall traces during model load to support phase
decomposition of cold-start time. Each tracked syscall produces an
ENTER/EXIT event pair so userspace can compute per-call duration and
attribute latency to specific phases (file lookup, weight bytes read,
memory mapping, fd cleanup).

The userspace consumer (`vllm-probe`) loads the eBPF program, attaches
it to the kernel tracepoints, drains the ring buffer on a dedicated
blocking thread, filters by PID, and streams events as JSONL to stdout
or a file.

## Status

Captures both sides of vLLM cold-start on a real GPU:

- **Syscalls** (kernel tracepoints): `openat`, `read`, `mmap`, `close`,
  each traced enter + exit for per-call duration.
- **libcuda C API** (uprobes + uretprobes): `cuInit`, `cuModuleLoadData`,
  `cuMemAlloc_v2`, `cuLaunchKernel`, each traced entry + return so the
  time spent inside each driver call is measured, not just when it fires.

Validated end-to-end on Lambda Labs A10 and A100 (Ubuntu 22.04, kernel
6.8.0-nvidia) under vLLM 0.22, across a four-phase study: where cold-start
time goes (Phase A), how it scales with model size (B), how quantization
changes it (C), and what common workarounds actually cost (D). See the
Findings sections below.

## Findings — Phase A: where the time goes (Mistral-7B, FP16, eager)

First full capture, page cache dropped immediately before launch, so
weight reads hit the SSD rather than RAM. Wall-clock cold-start was
about 18 seconds. The probe attributes time as follows.

Kernel I/O — total ~1.22 s:

| syscall | calls  | total   | notes                          |
|---------|--------|---------|--------------------------------|
| read    | 23,137 | 1037 ms | p50 1.1 us, max 44 ms          |
| openat  | 19,454 |  154 ms | file + library lookups         |
| mmap    |  1,846 |   16 ms | few; weights are read(), mmap'd|
| close   | 16,803 |   16 ms |                                |

libcuda calls — total ~1.49 s, but dominated by a few outliers:

| function         | calls | total   | p50    | max     |
|------------------|-------|---------|--------|---------|
| cuLaunchKernel   |   947 | 1337 ms | 4.2 us | 1287 ms |
| cuInit           |     6 |  123 ms | 5 us   |  123 ms |
| cuMemAlloc_v2    |   179 |   34 ms | 106 us |    2 ms |
| cuModuleLoadData |     1 |    1 ms | 780 us |    1 ms |

The headline: cold-start is neither I/O-bound nor dominated by the
volume of CUDA calls. Kernel I/O is ~7% of wall time. The 947
cuLaunchKernel calls are individually trivial (p50 4.2 us) except for
**one** that takes 1.29 s — almost certainly the first kernel launch
triggering JIT compilation. Likewise cuInit is one 123 ms call plus
five no-ops. Roughly 85% of the ~18 s is spent neither in syscalls nor
inside these driver calls: it is GPU compute, synchronization, and
Python-level work between the traced calls, which the next round of
probes (more libcuda / libtorch entry points) can attribute further.
Findings below for what the first full capture revealed.

## Findings — Phase B: scaling with model size

Same probe against Qwen2.5-Instruct-AWQ at three sizes (7B/14B/32B on
A10/A10/A100), quantization held constant to isolate size:

| model   | params | load time | kernel I/O | cuLaunchKernel | cuMemAlloc |
|---------|--------|-----------|-----------|----------------|------------|
| 7B-AWQ  | 7B     | 18.97 s   | ~1.86 s   | 3,475          | 161        |
| 14B-AWQ | 14B    | 25.02 s   | ~2.27 s   | 6,547          | 372        |
| 32B-AWQ | 32B    | 28.36 s   | ~1.93 s   | 8,691          | 418        |

Parameters grow 4.6x, load time grows 1.5x: cold start scales strongly
sub-linearly. `cuInit`/`cuModuleLoadData` are fixed costs. Kernel I/O is
flat (AWQ weights are small; not I/O-bound at any size). The *count* of
kernels and allocations grows sub-linearly; the *time* inside launches is
dominated by noisy synchronization outliers, not by weight volume.

## Findings — Phase C: the quantization tax

Same model (Qwen2.5-7B-Instruct), three precisions, on the same A10:

| precision | load time | cuLaunchKernel | cuMemAlloc |
|-----------|-----------|----------------|------------|
| FP16      | 15.05 s   | 843            | 164        |
| AWQ 4-bit | 18.97 s   | 3,475          | 161        |
| GPTQ 4-bit| 12.32 s   | 2,019          | 166        |

`cuMemAlloc` is constant (same architecture), but quantization multiplies
warmup kernels: AWQ issues 4.1x the `cuLaunchKernel` of FP16, GPTQ 2.4x —
the dequantization kernels each quantized layer adds. AWQ and GPTQ are not
equivalent at cold start. Load time does not track kernel count directly:
GPTQ is fastest despite more kernels than FP16, because it reads ~5 GB
from disk versus FP16's ~15 GB.

## Findings — Phase D: what the workarounds actually cost

Two interventions on Qwen2.5-7B-Instruct FP16, A10, against the eager
cold-cache baseline (15.05 s, 843 kernels):

| config              | load time | cuLaunchKernel |
|---------------------|-----------|----------------|
| baseline (eager)    | 15.05 s   | 843            |
| CUDA graphs enabled | 47.72 s   | 66,353         |
| warm page cache     | 11.70 s   | 843            |

Enabling CUDA graphs (`enforce_eager=False`) makes cold start **3.2x
slower** and issues **79x** the kernels: vLLM runs every batch shape to
capture the graphs. CUDA graphs speed up steady-state inference but pay a
brutal cold-start price — a real trade-off for scale-to-zero workloads. A
warm page cache saves ~3 s (the `read` I/O), confirming I/O is real but a
minority of cold start. The lever that moves cold start most is a config
flag, not the disk.

## Workspace layout

- `probe-common/` — shared `#[repr(C)]` types crossing the kernel/user
  boundary. `SyscallEvent` is the wire format on the ring buffer.
- `probe/` — userspace loader, CLI (`vllm-probe` binary), ring buffer
  drainer, and JSONL writer.
- `probe-ebpf/` — kernel-side eBPF program. Workspace member but
  excluded from `default-members` so plain `cargo build` ignores it;
  `aya-build` (invoked from `probe/build.rs`) compiles it for the
  `bpfel-unknown-none` target as part of building `probe`.

## Build prerequisites

- Linux ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux` present).
- Rust stable (≥ 1.80) and nightly with `rust-src` for the eBPF target.
- `bpf-linker` (`cargo install bpf-linker`). LLVM system libraries
  are not required: `bpf-linker` uses the libLLVM embedded in rustc
  nightly via `aya-rustc-llvm-proxy`.
- `CAP_BPF` + `CAP_PERFMON` (or run as root) to load eBPF programs
  and attach to tracepoints.

## Building

A single command builds both the userspace binary and the embedded
eBPF program:

```sh
cargo build -p probe
```

The eBPF crate is compiled by `aya-build` invoked from `probe/build.rs`
and the resulting BPF ELF is embedded into the userspace binary via
`include_bytes!`.

## Usage

```sh
# Trace a specific PID for 30 seconds, write events to a file
sudo ./target/debug/vllm-probe --pid 12345 --duration 30 --output trace.jsonl

# Trace to stdout (default)
sudo ./target/debug/vllm-probe --pid 12345 --duration 30
```

CLI flags:

- `--pid <PID>` (required): the process to trace. Currently single-PID;
  multi-PID requires either a userspace-side filter list or revisiting
  kernel-side filtering (see Limitations).
- `--duration <SECS>` (default 60): how long to capture before detaching.
- `--output <PATH>` (optional): JSONL output file. Stdout if unset.

## Output format

One JSON object per line. Schema:

```json
{
  "timestamp_ns": 8126029867356,
  "pid": 12855,
  "tid": 12855,
  "syscall_nr": 257,
  "kind": 0,
  "ret": 0
}
```

- `timestamp_ns`: monotonic nanoseconds from `bpf_ktime_get_ns()`.
  Use the difference between paired ENTER and EXIT timestamps to
  compute syscall duration.
- `kind`: 0 for ENTER, 1 for EXIT.
- `syscall_nr`: x86_64 syscall number. `openat = 257`, `read = 0`,
  `mmap = 9`, `close = 3`.
- `ret`: syscall return value on EXIT (positive = success/fd,
  negative = `-errno`). Always 0 on ENTER.

Pair ENTER and EXIT records on `(pid, tid, syscall_nr)` to compute
per-call duration.

## Limitations

- **PID filtering happens in userspace**, not in the kernel program.
  A kernel-side filter using `HashMap` or `Array` maps was attempted
  but rustc + aya 0.13.1 dead-code-eliminated the map definitions in
  this toolchain combination. The userspace filter is correct and
  fast enough for capture on an idle host but pays the ring buffer
  cost for every syscall on the machine. See the design note in
  `probe-ebpf/src/main.rs` for full context.
- **x86_64 only.** Syscall numbers are hardcoded for this
  architecture. Adding a build-time arch dispatch is straightforward
  but not done yet.
- **Userspace tracing covers libcuda only.** Four driver entry points
  are traced (cuInit, cuModuleLoadData, cuMemAlloc_v2, cuLaunchKernel).
  The ~85% of cold-start that sits between these calls — GPU compute,
  libtorch, Python — is not yet attributed; more entry points would
  narrow it down. Uretprobes record call duration but not the CUresult
  return value (not needed for timing).

## License

Apache-2.0. See `LICENSE`.
