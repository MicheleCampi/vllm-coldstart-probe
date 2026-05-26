//! vLLM cold-start eBPF probe — user-space loader and CLI.
//!
//! Loads a syscall + uprobe eBPF program into the kernel, attaches it to the
//! tracked PID, and streams events from a ring buffer to stdout as JSONL.

use anyhow::Result;
use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
#[command(version, about = "vLLM cold-start eBPF probe", long_about = None)]
struct Cli {
    /// PID of the process to trace (typically the vLLM worker).
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

    // TODO: load eBPF program, attach probes, poll ring buffer.
    // For now, just wait for Ctrl-C or duration to elapse.
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
