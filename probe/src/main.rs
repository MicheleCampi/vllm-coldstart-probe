//! vLLM cold-start eBPF probe — user-space loader and CLI.
//!
//! Loads the eBPF program embedded at build time, attaches it to the
//! `sys_enter_openat` tracepoint, drains events from the ring buffer
//! on a dedicated blocking thread, and writes them as JSON Lines to
//! stdout (default) or a file (via `--output`).

use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use clap::Parser;
use log::{info, warn};
use probe_common::SyscallEvent;
use tokio::sync::mpsc;

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

/// Channel capacity between the polling thread and the main task.
/// Large enough to absorb short bursts; the polling thread drops events
/// (with a warn log) if the consumer can't keep up.
const CHANNEL_CAPACITY: usize = 4096;

/// Polling interval when the ring buffer is empty. Tuning trade-off:
/// shorter = lower latency, more CPU; longer = batchier reads.
/// 1ms is a good default for cold-start capture (sub-millisecond latency
/// is irrelevant when the phenomenon being measured spans seconds).
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Flush the output writer every N events. Trade-off: more flushes means
/// less data lost on crash, more syscalls; fewer means better throughput,
/// more in-flight data at risk.
const FLUSH_EVERY: u64 = 1000;

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

/// Drains the ring buffer on a blocking thread, forwarding events to the
/// async consumer via `tx`. Returns when `tx` is closed (consumer dropped).
fn drain_ring_buffer(
    mut events: RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<SyscallEvent>,
) {
    let mut total_drained: u64 = 0;
    let mut total_dropped: u64 = 0;

    loop {
        let mut drained_this_iter = 0u64;
        while let Some(item) = events.next() {
            if item.len() != std::mem::size_of::<SyscallEvent>() {
                log::error!(
                    "ring buffer entry size mismatch: got {} bytes, expected {}",
                    item.len(),
                    std::mem::size_of::<SyscallEvent>()
                );
                continue;
            }
            // SAFETY: `SyscallEvent` is `#[repr(C)]`, `Copy`, and contains
            // only POD fields. The ring buffer entry was written by our own
            // eBPF program with the same struct definition (via the shared
            // `probe-common` crate), so the bytes are a valid `SyscallEvent`.
            let event: SyscallEvent = unsafe {
                std::ptr::read_unaligned(item.as_ptr().cast::<SyscallEvent>())
            };

            match tx.try_send(event) {
                Ok(()) => {
                    total_drained += 1;
                    drained_this_iter += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    total_dropped += 1;
                    if total_dropped.is_multiple_of(1000) {
                        log::warn!(
                            "consumer backpressure: {total_dropped} events dropped so far"
                        );
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    info!(
                        "consumer closed, ring buffer drainer exiting (total: {total_drained} drained, {total_dropped} dropped)"
                    );
                    return;
                }
            }
        }
        if drained_this_iter == 0 {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// Construct the JSONL output writer: stdout when `output` is `None`,
/// otherwise a buffered file writer. The returned writer is sent across
/// thread boundaries so it must be `Send`.
fn build_writer(output: Option<&std::path::Path>) -> Result<Box<dyn Write + Send>> {
    match output {
        None => Ok(Box::new(BufWriter::new(std::io::stdout()))),
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("failed to create output file {}", path.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
    }
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

    {
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
    }

    {
        let program: &mut TracePoint = ebpf
            .program_mut("probe_sys_exit_openat")
            .context("program `probe_sys_exit_openat` not found in ELF")?
            .try_into()
            .context("program is not a TracePoint")?;
        program
            .load()
            .context("failed to load tracepoint into kernel (verifier rejected?)")?;
        program
            .attach("syscalls", "sys_exit_openat")
            .context("failed to attach to syscalls:sys_exit_openat")?;
    }

    let events: RingBuf<_> = ebpf
        .take_map("EVENTS")
        .context("ring buffer map `EVENTS` not found in ELF")?
        .try_into()
        .context("map `EVENTS` is not a RingBuf")?;

    let mut writer = build_writer(cli.output.as_deref())?;

    info!("probe attached to syscalls:sys_enter_openat + sys_exit_openat, userspace-filtering for pid={}", cli.pid);

    let (tx, mut rx) = mpsc::channel::<SyscallEvent>(CHANNEL_CAPACITY);
    let drainer = tokio::task::spawn_blocking(move || drain_ring_buffer(events, tx));

    let mut consumed: u64 = 0;
    let deadline = tokio::time::sleep(Duration::from_secs(cli.duration));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received Ctrl-C, shutting down");
                break;
            }
            () = &mut deadline => {
                info!("duration elapsed, shutting down");
                break;
            }
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        if ev.pid != cli.pid {
                            continue;
                        }
                        consumed += 1;
                        match serde_json::to_writer(&mut writer, &ev) {
                            Ok(()) => {
                                if let Err(err) = writer.write_all(b"\n") {
                                    log::error!("failed to write newline: {err}");
                                    break;
                                }
                            }
                            Err(err) => {
                                log::error!("failed to serialize event: {err}");
                                continue;
                            }
                        }
                        if consumed.is_multiple_of(FLUSH_EVERY) {
                            if let Err(err) = writer.flush() {
                                log::error!("failed to flush writer: {err}");
                                break;
                            }
                        }
                    }
                    None => {
                        warn!("drainer channel closed unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    if let Err(err) = writer.flush() {
        log::error!("final flush failed: {err}");
    }
    info!("total events consumed: {consumed}");
    drop(rx);
    let _ = drainer.await;
    Ok(())
}
