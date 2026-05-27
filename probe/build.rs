//! Build script for the `probe` userspace binary.
//!
//! Invokes `aya-build` to compile the sibling `probe-ebpf` crate for the
//! `bpfel-unknown-none` target. The resulting BPF ELF is placed in
//! `OUT_DIR/probe` (matching the `[[bin]] name = "probe"` in probe-ebpf)
//! and embedded into the userspace binary via `include_bytes!`.

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "probe-ebpf",
            root_dir: "../probe-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )?;
    Ok(())
}
