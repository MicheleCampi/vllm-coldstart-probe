//! vLLM cold-start eBPF probe — kernel-side program.
//!
//! Attaches to syscall tracepoints and uprobes, emits `SyscallEvent` records
//! to a ring buffer consumed by the user-space loader.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

/// Stub tracepoint on `sys_enter_openat`. Currently a no-op — exists only to
/// validate the eBPF build pipeline end-to-end. Real logic lands next.
#[tracepoint]
pub fn probe_sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = ctx;
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
