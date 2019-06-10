//! Read memeroy of an running process to find salsa20 keys

use sysinfo::{ProcessExt, SystemExt};

pub fn get_process_pid(process_name: &str) -> usize {
    let system = sysinfo::System::new();
    let pid = system.get_process_by_name(process_name)[0].pid() as usize;
    pid
}

/// Used to search the memory of process
///
/// # Example
/// ```no_run
///     use poeproto::mem::ProcessMemory;
///     let prog = ProcessMemory::new(1337);
///     let positions = prog.search(&b"expand 32-byte k"[..], 64, 1*1024);
/// ```

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcessMemory;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::ProcessMemory;
