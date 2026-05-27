//! vLLM cold-start eBPF probe — user-space loader and CLI.
//!
//! Loads the eBPF program embedded at build time, attaches it to the
//! `sys_enter_openat` tracepoint, and keeps it active for the configured
//! duration. Ring buffer consumption is added in a later step.

use anyhow::{Context, Result};
use aya::{Ebpf, programs::TracePoint};
use clap::Parser;
use log::{info, warn};

/// 8-byte aligned wrapper for the embedded eBPF ELF.
///
/// `include_bytes!` produces a `&'static [u8]` with only byte alignment.
/// The `object` crate (used by aya for ELF parsing) requires the buffer
/// to be aligned to the natural alignment of `FileHeader64` (8 bytes).
/// Without this wrapper, parsing fails with a misleading "Invalid ELF
/// header size or alignment" error even on perfectly valid ELF files.
#[repr(C, align(8))]
struct AlignedBytes<B: ?Sized>(B);

static PROBE_OBJECT: &AlignedBytes<[u8]> = &AlignedBytes(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/probe"
)));

#[derive(Parser, Debug)]
#[command(version, about = "vLLM cold-start eBPF probe", long_about = None)]
struct Cli {
    /// PID of the process to trace (typically the vLLM worker).
    /// Currently informational only — kernel-side does not filter yet.
    #[arg(long)]
    pid: u32,

    /// Capture duration in seconds. The probe detaches and exits afterwards.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Output file for JSONL events. Defaults to stdout if unset.
    #[arg(long)]
    output: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let cli = Cli::parse();
    info!(
        "probe starting: pid={} duration={}s output={:?}",
        cli.pid, cli.duration, cli.output
    );

    let mut ebpf = Ebpf::load(&PROBE_OBJECT.0)
        .context("failed to load eBPF program (check CAP_BPF + CAP_PERFMON)")?;

    if let Err(err) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("aya-log init failed (continuing without kernel logs): {err}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("probe_sys_enter_openat")
        .context("program `probe_sys_enter_openat` not found in ELF")?
        .try_into()
        .context("program is not a TracePoint")?;
    program
        .load()
        .context("failed to load tracepoint into kernel (verifier rejected?)")?;
    program
        .attach("syscalls", "sys_enter_openat")
        .context("failed to attach to syscalls:sys_enter_openat")?;

    info!("probe attached to syscalls:sys_enter_openat — capturing events");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received Ctrl-C, shutting down");
        }
        () = tokio::time::sleep(std::time::Duration::from_secs(cli.duration)) => {
            info!("duration elapsed, shutting down");
        }
    }

    Ok(())
}
