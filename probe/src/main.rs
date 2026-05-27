//! vLLM cold-start eBPF probe — user-space loader and CLI.
//!
//! Loads the eBPF program embedded at build time, attaches enter+exit
//! tracepoints for the cold-start-relevant syscalls (openat, read, mmap,
//! close), drains events from the ring buffer on a dedicated blocking
//! thread, filters by PID in userspace, and writes JSONL to stdout
//! (default) or a file (via `--output`).

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

const CHANNEL_CAPACITY: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(1);
const FLUSH_EVERY: u64 = 1000;

/// Syscalls we attach to during cold-start capture. Each entry produces
/// two kernel programs: `probe_sys_enter_<short>` and `probe_sys_exit_<short>`,
/// attached to `syscalls/sys_enter_<short>` and `syscalls/sys_exit_<short>`
/// tracepoints respectively. Short names must match the macro invocations
/// in `probe-ebpf/src/main.rs`.
const TRACED_SYSCALLS: &[&str] = &["openat", "read", "mmap", "close"];

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

/// Load + attach a single tracepoint by Rust function name and kernel hook.
///
/// Borrows `ebpf` mutably only for the duration of this call, so the next
/// attach can run cleanly without scope juggling at the call site.
fn attach_tracepoint(
    ebpf: &mut Ebpf,
    rust_fn_name: &str,
    category: &str,
    event: &str,
) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(rust_fn_name)
        .with_context(|| format!("program `{rust_fn_name}` not found in ELF"))?
        .try_into()
        .with_context(|| format!("program `{rust_fn_name}` is not a TracePoint"))?;
    program
        .load()
        .with_context(|| format!("failed to load tracepoint `{rust_fn_name}` into kernel"))?;
    program
        .attach(category, event)
        .with_context(|| format!("failed to attach `{rust_fn_name}` to {category}:{event}"))?;
    Ok(())
}

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
            // SAFETY: SyscallEvent is repr(C), Copy, POD; written by our
            // own kernel-side program via the shared probe-common crate.
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

    // Attach enter+exit pair for every syscall in TRACED_SYSCALLS.
    for syscall in TRACED_SYSCALLS {
        attach_tracepoint(
            &mut ebpf,
            &format!("probe_sys_enter_{syscall}"),
            "syscalls",
            &format!("sys_enter_{syscall}"),
        )?;
        attach_tracepoint(
            &mut ebpf,
            &format!("probe_sys_exit_{syscall}"),
            "syscalls",
            &format!("sys_exit_{syscall}"),
        )?;
    }

    let events: RingBuf<_> = ebpf
        .take_map("EVENTS")
        .context("ring buffer map `EVENTS` not found in ELF")?
        .try_into()
        .context("map `EVENTS` is not a RingBuf")?;

    let mut writer = build_writer(cli.output.as_deref())?;

    info!(
        "probe attached to {} syscalls ({} tracepoints), userspace-filtering for pid={}",
        TRACED_SYSCALLS.len(),
        TRACED_SYSCALLS.len() * 2,
        cli.pid
    );

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
