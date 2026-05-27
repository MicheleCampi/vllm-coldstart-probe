//! vLLM cold-start eBPF probe — kernel-side program.
//!
//! Attaches to syscall tracepoints and uprobes, emits `SyscallEvent` records
//! to a ring buffer consumed by the user-space loader.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use probe_common::SyscallEvent;

/// Ring buffer carrying `SyscallEvent` records to user space.
///
/// Sized at 256 KiB (must be a power of two, in bytes). Large enough to
/// absorb the syscall burst at vLLM startup without drops; small enough to
/// stay well within the per-program eBPF memory budget.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

/// `openat` syscall number on x86_64. Hardcoded for now; we add a build-time
/// architecture dispatch when we expand beyond x86_64.
const SYS_OPENAT: u32 = 257;

/// Tracepoint on `sys_enter_openat`. Emits one `SyscallEvent` per invocation,
/// regardless of PID — user-space is responsible for filtering. No PID filter
/// here yet to keep the kernel-side logic minimal during pipeline validation.
#[tracepoint]
pub fn probe_sys_enter_openat(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve a slot in the ring buffer. If the buffer is full, drop the
    // event silently — blocking the syscall hot path is worse than a gap.
    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_enter(timestamp_ns, pid, tid, SYS_OPENAT);
    unsafe {
        core::ptr::write(entry.as_mut_ptr(), event);
    }
    entry.submit(0);

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
