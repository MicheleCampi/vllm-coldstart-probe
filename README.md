# vllm-coldstart-probe

eBPF-based investigation tool for vLLM cold-start latency on NVIDIA GPUs.

Traces syscalls and selected userspace functions during model load to
decompose cold-start time into kernel-attributable phases (file I/O, mmap,
CUDA init) versus userspace-attributable phases (weight parsing, sharding,
graph compilation).

**Status:** early scaffolding. Toolchain and build pipeline validated; no
functional probes attached yet.

## Workspace layout

- `probe-common/` — shared `repr(C)` types crossing the kernel/user boundary.
- `probe/` — userspace loader and CLI (`vllm-probe` binary).
- `probe-ebpf/` — kernel-side eBPF program. Excluded from the workspace
  because it builds for the `bpfel-unknown-none` target with a separate
  toolchain.

## Build prerequisites

- Linux ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux` present).
- Rust stable (≥ 1.80) and nightly with `rust-src` for the eBPF target.
- LLVM ≥ 20 system libraries are *not* required: `bpf-linker` uses the
  libLLVM embedded in rustc nightly via `aya-rustc-llvm-proxy`.
- `bpf-linker` installed via `cargo install bpf-linker`.

## Building

```sh
# Userspace
cargo build -p probe

# Kernel-side (separate target, separate toolchain)
cd probe-ebpf && cargo build
```

## License

Apache-2.0. See `LICENSE`.
