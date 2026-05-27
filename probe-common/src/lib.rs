#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

/// Event emitted from the eBPF probe when a tracked syscall enters or exits.
///
/// This struct crosses the kernel/user boundary via a ring buffer, so its
/// layout must be stable (`repr(C)`) and contain only POD fields.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize))]
pub struct SyscallEvent {
    /// Monotonic nanosecond timestamp from `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// PID of the process that invoked the syscall.
    pub pid: u32,
    /// TID of the thread that invoked the syscall.
    pub tid: u32,
    /// Syscall number (architecture-specific, x86_64 here).
    pub syscall_nr: u32,
    /// Event kind: 0 = enter, 1 = exit.
    pub kind: u8,
    /// Padding to align the struct to 8 bytes. Not part of the public event
    /// schema, so it is skipped during serialization.
    #[cfg_attr(feature = "user", serde(skip))]
    _pad: [u8; 3],
    /// Return value on exit (raw `i64` from kernel), 0 on enter.
    pub ret: i64,
}

impl SyscallEvent {
    pub const KIND_ENTER: u8 = 0;
    pub const KIND_EXIT: u8 = 1;

    /// Construct an enter event. `ret` is always zero for enter events.
    #[must_use]
    pub const fn new_enter(timestamp_ns: u64, pid: u32, tid: u32, syscall_nr: u32) -> Self {
        Self {
            timestamp_ns,
            pid,
            tid,
            syscall_nr,
            kind: Self::KIND_ENTER,
            _pad: [0; 3],
            ret: 0,
        }
    }

    /// Construct an exit event with the syscall return value.
    #[must_use]
    pub const fn new_exit(
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        syscall_nr: u32,
        ret: i64,
    ) -> Self {
        Self {
            timestamp_ns,
            pid,
            tid,
            syscall_nr,
            kind: Self::KIND_EXIT,
            _pad: [0; 3],
            ret,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}
