//! Architecture-agnostic syscall semantics.
//!
//! Thin architecture adapters should decode ABI-specific register state into a
//! `SyscallInvocation`, call these helpers, and then write the resulting value
//! back into guest registers.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::macos::analysis::AnalysisServices;
use crate::macos::byte_preview::lossy_data_preview;
use crate::macos::{
    align_up, read_cstring, resolve_guest_path, syscall_event, RuntimeMode, TraceEvent,
    TraceMetadata,
};
use crate::{Emulator, MacOsError};

pub enum SyscallFdEntry {
    HostFile(File),
    SyntheticCursor(Cursor<Vec<u8>>),
}

#[derive(Clone)]
pub struct SyscallRuntimeState {
    pub runtime_mode: RuntimeMode,
    pub done_addr: u64,
    pub heap_base: u64,
    pub mmap_base: u64,
    pub mmap_end: u64,
    pub mmap_next: Arc<AtomicU64>,
    pub syscall_count: Arc<AtomicUsize>,
    pub next_fd: Arc<AtomicU64>,
    pub saw_exit: Arc<AtomicBool>,
    pub fd_table: Arc<Mutex<HashMap<u64, SyscallFdEntry>>>,
    pub guest_fs_base: PathBuf,
}

impl SyscallRuntimeState {
    pub fn new(
        done_addr: u64,
        heap_base: u64,
        mmap_base: u64,
        mmap_end: u64,
        guest_fs_base: PathBuf,
    ) -> Self {
        Self {
            done_addr,
            runtime_mode: RuntimeMode::Analysis,
            heap_base,
            mmap_base,
            mmap_end,
            mmap_next: Arc::new(AtomicU64::new(mmap_base)),
            syscall_count: Arc::new(AtomicUsize::new(0)),
            next_fd: Arc::new(AtomicU64::new(3)),
            saw_exit: Arc::new(AtomicBool::new(false)),
            fd_table: Arc::new(Mutex::new(HashMap::new())),
            guest_fs_base,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallInvocation {
    pub num: u64,
    pub name: &'static str,
    pub pc: u64,
    pub args: [u64; 6],
}

#[derive(Debug, Clone)]
pub struct SyscallOutcome {
    pub return_value: u64,
    pub stop_addr: Option<u64>,
    pub event: TraceEvent,
}

pub fn default_syscall_name(num: u64) -> &'static str {
    match num {
        0x2000001 => "exit",
        0x2000003 => "read",
        0x2000004 => "write",
        0x2000005 => "open",
        0x2000006 => "close",
        0x2000007 => "mprotect",
        0x2000049 => "munmap",
        0x2000068 => "brk",
        0x20000C5 => "mmap",
        _ => "unknown",
    }
}

pub fn default_guest_fs_base(binary_path: &Path, rootfs_dir_name: &str) -> PathBuf {
    binary_path
        .ancestors()
        .find(|a| a.file_name().and_then(|n| n.to_str()) == Some(rootfs_dir_name))
        .map(|x| x.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn handle_basic_macos_syscall(
    emu: &mut dyn Emulator,
    invocation: &SyscallInvocation,
    metadata: &TraceMetadata,
    runtime: &SyscallRuntimeState,
    plugin_name: &str,
) -> Result<SyscallOutcome, MacOsError> {
    let sc = runtime.syscall_count.fetch_add(1, Ordering::Relaxed);
    let mut event = syscall_event(metadata, invocation.name)
        .arg("Plugin", plugin_name)
        .arg("Num", format!("0x{:X}", invocation.num))
        .arg("Index", sc.to_string())
        .arg("PC", format!("0x{:X}", invocation.pc))
        .arg("Arg0", format!("0x{:X}", invocation.args[0]))
        .arg("Arg1", format!("0x{:X}", invocation.args[1]))
        .arg("Arg2", format!("0x{:X}", invocation.args[2]));

    let mut return_value = 0u64;
    let mut stop_addr = None;

    match invocation.num {
        0x2000001 => {
            runtime.saw_exit.store(true, Ordering::Relaxed);
            stop_addr = Some(runtime.done_addr);
            event = event
                .arg("ExitCode", invocation.args[0].to_string())
                .arg("Result", "0");
        }
        0x2000004 => {
            let fd = invocation.args[0] as i32;
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            if fd == 1 || fd == 2 {
                if let Ok(data) = emu.read_memory(buf, count) {
                    event = event.arg("Preview", lossy_data_preview(&data, 256));
                }
            }
            return_value = count as u64;
            event = event
                .arg("Fd", fd.to_string())
                .arg("Count", count.to_string())
                .arg("Result", count.to_string());
        }
        0x2000003 => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let mut nread = 0usize;
            if let Ok(mut table) = runtime.fd_table.lock() {
                if let Some(file) = table.get_mut(&fd) {
                    let mut tmp = vec![0u8; count];
                    nread = match file {
                        SyscallFdEntry::HostFile(file) => Read::read(file, &mut tmp).unwrap_or(0),
                        SyscallFdEntry::SyntheticCursor(cursor) => {
                            Read::read(cursor, &mut tmp).unwrap_or(0)
                        }
                    };
                    if nread > 0 {
                        let _ = emu.write_memory(buf, &tmp[..nread]);
                    }
                }
            }
            return_value = nread as u64;
            event = event
                .arg("Fd", fd.to_string())
                .arg("Buf", format!("0x{:X}", buf))
                .arg("Count", count.to_string())
                .arg("Result", nread.to_string());
        }
        0x20000C5 => {
            let req_addr = invocation.args[0];
            let len = align_up(invocation.args[1].max(0x1000), 0x1000);
            let mut map_addr = if req_addr == 0 {
                runtime.mmap_next.fetch_add(len, Ordering::Relaxed)
            } else if req_addr >= runtime.mmap_base && req_addr + len <= runtime.mmap_end {
                req_addr
            } else {
                runtime.mmap_next.fetch_add(len, Ordering::Relaxed)
            };
            map_addr = align_up(map_addr, 0x1000);
            return_value = if map_addr + len > runtime.mmap_end {
                u64::MAX
            } else {
                map_addr
            };
            event = event
                .arg("ReqAddr", format!("0x{:X}", req_addr))
                .arg("Len", format!("0x{:X}", len))
                .arg("Result", format!("0x{:X}", return_value));
        }
        0x2000007 | 0x2000049 => {
            event = event.arg("Result", "0");
        }
        0x2000068 => {
            return_value = runtime.heap_base + 0x100000;
            event = event.arg("Result", format!("0x{:X}", return_value));
        }
        0x2000005 => {
            let path_ptr = invocation.args[0];
            let flags = invocation.args[1];
            let creating = (flags & 0x200) != 0;
            let raw_path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let resolved = resolve_guest_path(&runtime.guest_fs_base, &raw_path);
            let fd = runtime.next_fd.fetch_add(1, Ordering::Relaxed);
            let analysis = AnalysisServices::for_mode(runtime.runtime_mode);
            let entry = match File::open(&resolved) {
                Ok(file) => SyscallFdEntry::HostFile(file),
                Err(_) if creating => SyscallFdEntry::SyntheticCursor(Cursor::new(Vec::new())),
                Err(_) if analysis.is_none() => {
                    return_value = u64::MAX;
                    event = event
                        .arg("Path", raw_path)
                        .arg("Resolved", resolved.display().to_string())
                        .arg("Result", format!("0x{:X}", u64::MAX))
                        .arg("Errno", "2");
                    return Ok(SyscallOutcome {
                        return_value,
                        stop_addr,
                        event,
                    });
                }
                Err(_) => SyscallFdEntry::SyntheticCursor(Cursor::new(
                    analysis
                        .expect("analysis service checked above")
                        .materialize_synthetic_file_bytes(&raw_path, 4096),
                )),
            };
            if let Ok(mut table) = runtime.fd_table.lock() {
                table.insert(fd, entry);
                return_value = fd;
                event = event
                    .arg("Path", raw_path)
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Result", fd.to_string())
                    .arg("Synthetic", (!resolved.exists()).to_string());
            } else {
                return_value = u64::MAX;
                event = event
                    .arg("Path", raw_path)
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Result", format!("0x{:X}", u64::MAX));
            }
        }
        0x2000006 => {
            let fd = invocation.args[0];
            if let Ok(mut table) = runtime.fd_table.lock() {
                table.remove(&fd);
            }
            event = event.arg("Fd", fd.to_string()).arg("Result", "0");
        }
        _ => {
            event = event.arg("Result", "0");
        }
    }

    Ok(SyscallOutcome {
        return_value,
        stop_addr,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_syscall_name_maps_common_calls() {
        assert_eq!(default_syscall_name(0x2000004), "write");
        assert_eq!(default_syscall_name(0x20000C5), "mmap");
        assert_eq!(default_syscall_name(0xDEAD), "unknown");
    }

    #[test]
    fn default_guest_fs_base_falls_back_to_workspace() {
        let base =
            default_guest_fs_base(Path::new(r"fixtures\macos\bin\sample.macho"), "arm64_ios");
        assert_eq!(base, PathBuf::from("."));
    }
}
