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

Functional capture for four syscalls: `openat`, `read`, `mmap`, `close`.
Each is traced enter + exit. Validated end-to-end on Linux 6.8 with a
Python-generated syscall workload; ring buffer absorbs the traffic
without drops at the current 256 KiB sizing.

Not yet integrated with a real vLLM workload — that work lands next,
along with uprobes for libtorch and libcuda to capture the userspace
side of the cold-start timeline.

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
- **No uprobe support yet.** Only kernel tracepoints. Userspace
  function tracing (libtorch, libcuda) is planned for phase
  decomposition beyond the kernel boundary.

## License

Apache-2.0. See `LICENSE`.
