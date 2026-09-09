//! vLLM cold-start eBPF probe — kernel-side program.
//!
//! Attaches enter+exit tracepoint pairs for the syscalls relevant to
//! model-load cold-start (openat, read, mmap, close) and uprobes on
//! userspace library functions (currently the libcuda C API) to attribute
//! the large userspace/GPU portion of cold-start that syscalls cannot see.
//! Every probe emits a `SyscallEvent`; userspace pairs syscall enter/exit
//! on (pid, tid, syscall_nr) and treats uprobe events (id >= 1000) as
//! one-sided phase markers.
//!
//! # PID filtering design note
//!
//! A kernel-side PID filter using `Array<u32>` or `HashMap<u32, u8>` was
//! attempted but the map was consistently dead-code-eliminated by rustc
//! in this aya 0.13.1 + nightly toolchain combination, even with
//! `pub static mut` and `unsafe { &mut MAP }.get(...)` wrappers matching
//! the pattern used by aya-log. The lookup helper call was emitted but
//! the linker dropped both the map and the helper invocation. Userspace
//! filtering is the pragmatic alternative: every event from every process
//! reaches userspace via the ring buffer, and the consumer discards
//! events whose PID does not match the target. Overhead is tolerable for
//! cold-start capture on an otherwise-idle machine.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::RingBuf,
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use probe_common::SyscallEvent;

/// Ring buffer carrying `SyscallEvent` records to user space.
///
/// Sized at 256 KiB (must be a power of two, in bytes). Large enough to
/// absorb the syscall burst at vLLM startup without drops; small enough to
/// stay well within the per-program eBPF memory budget.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

/// Byte offset of the `ret` field within the `sys_exit_*` tracepoint
/// context on x86_64. The layout is: 8 bytes common header + 8 bytes
/// syscall_nr (long), then the i64 return value. Confirmed against
/// /sys/kernel/tracing/events/syscalls/sys_exit_<any>/format.
const SYS_EXIT_RET_OFFSET: usize = 16;

/// Shared emit logic for ENTER events. Inlined so each tracepoint stays
/// a single compact eBPF program the verifier can check quickly.
#[inline(always)]
fn emit_enter(syscall_nr: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_enter(timestamp_ns, pid, tid, syscall_nr);
    unsafe {
        core::ptr::write(entry.as_mut_ptr(), event);
    }
    entry.submit(0);

    0
}

/// Shared emit logic for EXIT events. Reads the syscall return value
/// from the tracepoint context and includes it in the emitted event.
#[inline(always)]
fn emit_exit(ctx: TracePointContext, syscall_nr: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let ret: i64 = unsafe { ctx.read_at::<i64>(SYS_EXIT_RET_OFFSET) }.unwrap_or(0);

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_exit(timestamp_ns, pid, tid, syscall_nr, ret);
    unsafe {
        core::ptr::write(entry.as_mut_ptr(), event);
    }
    entry.submit(0);

    0
}

/// Generates a paired enter/exit tracepoint for a given syscall.
///
/// The explicit `name = ...` and `category = "syscalls"` arguments are
/// load-bearing: without them the `#[tracepoint]` macro generates the
/// generic `link_section = "tracepoint"` for both functions, and the
/// linker silently drops the second one because they collide in the
/// same section.
macro_rules! define_syscall_tracepoint {
    ($short:ident, $syscall_nr:expr) => {
        ::paste::paste! {
            #[tracepoint(name = "" "sys_enter_" $short "", category = "syscalls")]
            pub fn [<probe_sys_enter_ $short>](_ctx: TracePointContext) -> u32 {
                emit_enter($syscall_nr)
            }

            #[tracepoint(name = "" "sys_exit_" $short "", category = "syscalls")]
            pub fn [<probe_sys_exit_ $short>](ctx: TracePointContext) -> u32 {
                emit_exit(ctx, $syscall_nr)
            }
        }
    };
}

// x86_64 syscall numbers. Source: arch/x86/entry/syscalls/syscall_64.tbl
// in the Linux kernel source. Hardcoded for now; build-time arch dispatch
// when we expand beyond x86_64.
define_syscall_tracepoint!(openat, 257);
define_syscall_tracepoint!(read, 0);
define_syscall_tracepoint!(mmap, 9);
define_syscall_tracepoint!(close, 3);

// ---- Uprobe section (userspace function tracing) ----
//
// Event IDs >= 1000 distinguish uprobe events from syscall events
// (which use the real syscall number, all < 1000) in the shared
// SyscallEvent stream. The userspace analysis splits on this boundary.
//
// Each libcuda symbol gets a pair: a uprobe on ENTER and a uretprobe on
// RETURN, both emitting the same event_id with different `kind` values.
// Pairing them in analysis gives the time spent inside the call rather
// than only the interval between successive entries — which matters here,
// because the finding this probe exists for is a single cuLaunchKernel
// that takes 1.29 s against a 4.2 us median, and an interval between two
// entries could not tell that apart from a gap in the caller.
//
// An earlier version captured entries only, and this comment described
// that. The uretprobe side arrived with the `define_uprobe!` pair below;
// the data files carry both shapes, with `-uretprobe` in the name for the
// paired captures.

/// Shared emit logic for uprobe ENTER events. Inlined so each generated
/// uprobe stays a single compact eBPF program.
#[inline(always)]
fn emit_uprobe(event_id: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_enter(timestamp_ns, pid, tid, event_id);
    unsafe {
        core::ptr::write(entry.as_mut_ptr(), event);
    }
    entry.submit(0);

    0
}

/// Shared emit logic for uprobe RETURN events. Emits an EXIT-kind event
/// carrying the same event_id, so userspace pairs entry/return the same
/// way it pairs syscall enter/exit. The CUDA return value is not captured
/// (passed as 0): for cold-start phase timing the duration matters, not
/// the CUresult code.
#[inline(always)]
fn emit_uprobe_ret(event_id: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        return 0;
    };

    let event = SyscallEvent::new_exit(timestamp_ns, pid, tid, event_id, 0);
    unsafe {
        core::ptr::write(entry.as_mut_ptr(), event);
    }
    entry.submit(0);

    0
}

/// Generates an entry uprobe `probe_<short>` and a return uretprobe
/// `probe_<short>_ret`, both tagged with `event_id`. The userspace side
/// attaches the entry function as a uprobe and the _ret function as a
/// uretprobe to the same symbol; pairing entry/return in analysis gives
/// the time spent inside each CUDA call.
macro_rules! define_uprobe {
    ($short:ident, $event_id:expr) => {
        ::paste::paste! {
            #[uprobe]
            pub fn [<probe_ $short>](_ctx: ProbeContext) -> u32 {
                emit_uprobe($event_id)
            }

            #[uretprobe]
            pub fn [<probe_ $short _ret>](_ctx: RetProbeContext) -> u32 {
                emit_uprobe_ret($event_id)
            }
        }
    };
}

// libcuda C-API entry points relevant to cold-start. Event ids are local
// to this tool (>= 1000) and must match the event-id name map in
// analysis/analyze.py. The userspace side (TRACED_UPROBES) maps each Rust
// function name to the concrete symbol and library to attach to.
define_uprobe!(cu_init, 1000);
define_uprobe!(cu_module_load_data, 1001);
define_uprobe!(cu_mem_alloc, 1002);
define_uprobe!(cu_launch_kernel, 1003);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
