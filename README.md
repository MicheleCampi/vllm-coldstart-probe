# vllm-coldstart-probe

eBPF-based investigation tool for vLLM cold-start latency on NVIDIA GPUs.

Captures kernel-side syscall traces during model load to support phase
decomposition of cold-start time. Each tracked syscall produces an
ENTER/EXIT event pair so userspace can compute per-call duration and
attribute latency to specific phases (file lookup, weight bytes read,
memory mapping, fd cleanup).

The userspace consumer (`vllm-probe`) loads the eBPF program, attaches
it to the kernel tracepoints, drains the ring buffer on a dedicated
blocking thread, filters by PID (`--pid 0` keeps every process), and
streams events as JSONL to stdout or a file.

## Status

Captures both sides of vLLM cold-start on a real GPU:

- **Syscalls** (kernel tracepoints): `openat`, `read`, `mmap`, `close`,
  each traced enter + exit for per-call duration.
- **libcuda C API** (uprobes + uretprobes): `cuInit`, `cuModuleLoadData`,
  `cuMemAlloc_v2`, `cuLaunchKernel`, each traced entry + return so the
  time spent inside each driver call is measured, not just when it fires.

Validated end-to-end on Lambda Labs A10 and A100 (Ubuntu 22.04, kernel
6.8.0-nvidia). The vLLM version was not captured per run; the notes taken
during the sessions name 0.21.0 for the first node and 0.22 for the phase B
node. The study has four phases: where cold-start
time goes (Phase A), how it scales with model size (B), how quantization
changes it (C), and what common workarounds actually cost (D). See the
Findings sections below.

## How the numbers are produced

- **Captures.** Ten, listed in [`analysis/CAPTURES.md`](analysis/CAPTURES.md)
  with their SHA-256, start time, GPU and the PIDs involved. The capture
  files are not in this repository: nine hold every process on the node.
  The scripts that took them are in [`capture/`](capture/).
- **Syscall figures** are `analysis/analyze.py` on each capture filtered to
  the loader and vLLM's EngineCore PIDs (`--pid`); `analysis/summarize.sh`
  regenerates every output in `analysis/summaries/`. Without the filter the
  counts include the node's other processes: for the 14B capture the
  syscall time is 24.82 s instead of 2.27 s.
- **libcuda figures** come from EngineCore alone, filtered or not.
- **Load time** is the time to construct `LLM(...)` as the capture loader
  prints it (`capture/load_model.py`): building the engine, not serving a
  request.
- **What the probe does not see.** The weights do not pass through the
  four traced syscalls: in the seven captures checked, the loader's and
  EngineCore's `read`s move 0.53 to 0.54 GiB per load, while Mistral-7B's
  weights alone are 13.5 GiB (its three safetensors shards on Hugging
  Face). Syscall figures are time spent in those syscalls, not disk I/O.
- **Lost events.** The probe's writer dropped up to 1,493 events per
  capture (CAPTURES.md); losses inside the kernel ring buffer are not
  counted.

## Findings — Phase A: where the time goes (Mistral-7B, FP16, eager)

Capture `mistral-7b-a10-cold-start-uretprobe.jsonl` (30 May), page cache
dropped immediately before launch. Its load time was not kept: the only
load time recorded for a phase A capture, 11.73 s, comes from the first
capture, which filtered on the loader's PID and so has none of
EngineCore's events.
Syscall figures are `analyze.py --pid 2534 --pid 2637` on this capture.

Syscall time — total ~1.22 s:

| syscall | calls  | total   | notes                          |
|---------|--------|---------|--------------------------------|
| read    | 23,137 | 1037 ms | p50 1.1 us, max 44 ms          |
| openat  | 19,454 |  154 ms | file + library lookups         |
| mmap    |  1,846 |   16 ms | file mappings; faults untraced  |
| close   | 16,803 |   16 ms |                                |

These `read`s move 0.53 GiB, against 13.5 GiB of weights: the weights
reach memory some other way, so this is syscall time, not disk I/O.

libcuda calls — total ~1.49 s, but dominated by a few outliers:

| function         | calls | total   | p50    | max     |
|------------------|-------|---------|--------|---------|
| cuLaunchKernel   |   947 | 1337 ms | 4.2 us | 1287 ms |
| cuInit           |     6 |  123 ms | 5 us   |  123 ms |
| cuMemAlloc_v2    |   179 |   34 ms | 106 us |    2 ms |
| cuModuleLoadData |     1 |    1 ms | 780 us |    1 ms |

The traced calls take 1.22 s in the four syscalls and 1.49 s inside the four
libcuda functions. The 947 cuLaunchKernel calls are individually trivial
(p50 4.2 us) except for **one** that takes 1.29 s: launch 516, 7.21 s after
the first, so not a first-launch cost. cuInit is one 123 ms call plus five
that return in microseconds. How much of the load is disk I/O this capture
cannot say: the weights do not pass through the traced syscalls, and its
load time was not kept, so no share of the total is computed here.

## Findings — Phase B: scaling with model size

Same probe against Qwen2.5-Instruct-AWQ at three sizes (7B/14B/32B on
A10/A10/A100). Quantization is held constant, but the 32B ran on an A100,
so its row changes the GPU as well as the size:

| model   | params | load time | syscall time | cuLaunchKernel | cuMemAlloc |
|---------|--------|-----------|-----------|----------------|------------|
| 7B-AWQ  | 7B     | 18.97 s   | ~1.86 s   | 3,475          | 161        |
| 14B-AWQ | 14B    | 25.02 s   | ~2.27 s   | 6,547          | 372        |
| 32B-AWQ | 32B    | 28.36 s   | ~1.93 s   | 8,691          | 418        |

The 14B capture dropped 1,493 events, so its counts are lower bounds. On
the same A10, doubling the parameters (7B to 14B) makes the load 1.32x
longer; the 32B, on the A100, takes 1.50x the 7B's time with 4.6x its
parameters. `cuInit` and `cuModuleLoadData` are called 6 times and once at
every size. Syscall time stays around 2 s; as in phase A, the traced `read`s
move 0.54 GiB at every size, not the weights. Kernel launches grow
sub-linearly (1.88x for 2x the parameters, 2.50x for 4.6x); allocations grow
2.31x from 7B to 14B and 2.60x to 32B. The time inside launches is dominated
by single calls: the longest launch is 93%, 57% and 43% of it (7B, 14B,
32B).

## Findings — Phase C: the quantization tax

Same model (Qwen2.5-7B-Instruct), three precisions, on the same A10:

| precision | load time | cuLaunchKernel | cuMemAlloc |
|-----------|-----------|----------------|------------|
| FP16      | 15.05 s   | 843            | 164        |
| AWQ 4-bit | 18.97 s   | 3,475          | 161        |
| GPTQ 4-bit| 12.32 s   | 2,019          | 166        |

`cuMemAlloc` stays at 161 to 166 calls, while quantization multiplies kernel
launches: AWQ issues 4.1x the `cuLaunchKernel` of FP16, GPTQ 2.4x. AWQ and
GPTQ are not equivalent at cold start. Load time does not track kernel
count directly: GPTQ is fastest despite more kernels than FP16. Its 4-bit
checkpoint is smaller; the probe cannot show whether that is why, since the
traced `read`s move 0.53 to 0.54 GiB in all three captures. The GPTQ
capture dropped 539 events and the FP16 one 114.

## Findings — Phase D: what the workarounds actually cost

Two interventions on Qwen2.5-7B-Instruct FP16, A10, against the eager
cold-cache baseline (15.05 s, 843 kernels):

| config              | load time | cuLaunchKernel |
|---------------------|-----------|----------------|
| baseline (eager)    | 15.05 s   | 843            |
| CUDA graphs enabled | 47.72 s   | 66,353         |
| warm page cache     | 11.70 s   | 843            |

Enabling CUDA graphs (`enforce_eager=False`) makes the load **3.2x
slower** and issues **79x** the kernel launches, a cost to weigh for
scale-to-zero workloads. A
warm page cache cuts the load by 3.35 s, while traced `read` time falls by
only 0.66 s (1.045 to 0.383 s): most of the saving lies outside the traced
syscalls. The warm load followed a discarded warm-up load of the same model
(`capture/run_capture_d.sh`). The largest change measured is still the
config flag: CUDA graphs add 32.67 s. The warm-cache capture dropped 1,256
events and the CUDA-graph one 82, so their counts are lower bounds.

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

- `--pid <PID>` (required): the process to trace, or `0` for every process
  on the node (`probe/src/main.rs:284`). vLLM's EngineCore is a subprocess
  started after the probe attaches, so a single PID misses it: the captures
  in `data/` use `0` and are filtered afterwards with
  `analysis/analyze.py --pid`.
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
- `syscall_nr` 1000 to 1003 are libcuda uprobes: `cuInit`,
  `cuModuleLoadData`, `cuMemAlloc_v2`, `cuLaunchKernel`. `kind` is 0 on the
  function's entry and 1 on its return; `ret` is always 0, since the
  CUresult is not captured.

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
  The time between these calls — GPU compute, libtorch, Python — is not
  attributed; more entry points would narrow it down. Uretprobes record
  call duration but not the CUresult return value (not needed for timing).
- **Weight I/O is not traced.** The weights do not pass through the four
  traced syscalls (see "How the numbers are produced"), so the probe
  cannot say what share of a load is disk I/O.
- **Event loss is only partly counted.** The writer counts the events it
  drops (`probe/src/main.rs:161-162`); when the kernel ring buffer is full,
  `EVENTS.reserve` fails and the event is lost without a count
  (`probe-ebpf/src/main.rs`).

## License

Apache-2.0. See `LICENSE`.
