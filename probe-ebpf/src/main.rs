//! vLLM cold-start eBPF probe — kernel-side program.
//!
//! Attaches to syscall tracepoints (enter+exit pairs) and emits a
//! `SyscallEvent` per side, allowing userspace to compute syscall duration
//! by matching enter/exit records on (pid, tid, syscall_nr) tuples.
//!
//! # PID filtering design note
//!
//! A kernel-side PID filter using `Array<u32>` or `HashMap<u32, u8>` was
//! attempted but the map was consistently dead-code-eliminated by rustc
//! in this aya 0.13.1 + nightly toolchain combination, even with
//! `pub static mut` and `unsafe { &mut MAP }.get(...)` wrappers matching
//! the pattern used by aya-log. The lookup helper call was emitted but
//! the linker dropped both the map and the helper invocation. Userspace
//! filtering is the pragmatic alternative: every syscall from every
//! process reaches userspace via the ring buffer, and the consumer
//! discards events whose PID does not match the target. Overhead is
//! tolerable for cold-start capture on an otherwise-idle machine.

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

/// Byte offset of the `ret` field within the `sys_exit_*` tracepoint
/// context on x86_64. The layout is: 8 bytes common header + 8 bytes
/// syscall_nr (long), then the i64 return value. Confirmed against
/// /sys/kernel/tracing/events/syscalls/sys_exit_openat/format.
const SYS_EXIT_RET_OFFSET: usize = 16;

/// Tracepoint on `sys_enter_openat`. Emits one ENTER event per invocation
/// for every process; userspace filters by PID.
#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn probe_sys_enter_openat(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

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

/// Tracepoint on `sys_exit_openat`. Emits one EXIT event per invocation,
/// carrying the syscall return value (positive = fd, negative = -errno).
/// Userspace pairs ENTER and EXIT by (pid, tid, syscall_nr) and computes
/// duration = exit.timestamp_ns - enter.timestamp_ns.
#[tracepoint(name = "sys_exit_openat", category = "syscalls")]
pub fn probe_sys_exit_openat(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Read the ret value from the tracepoint context. If the read fails
    // (out-of-bounds or other verifier rejection), default to 0; userspace
    // will see a zero ret on exit and can flag it as suspicious if needed.
    let ret: i64 = unsafe { ctx.read_at::<i64>(SYS_EXIT_RET_OFFSET) }.unwrap_or(0);

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_exit(timestamp_ns, pid, tid, SYS_OPENAT, ret);
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
