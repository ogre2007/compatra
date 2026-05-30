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
use crate::macos::compat::CompatibilityServices;
use crate::macos::{
    align_up, read_cstring, resolve_guest_path, syscall_event, RuntimeMode, TraceEvent,
    TraceMetadata,
};
use crate::{Emulator, MacOsError};

const SYSCALL_EXIT: u64 = 0x2000001;
const SYSCALL_READ: u64 = 0x2000003;
const SYSCALL_WRITE: u64 = 0x2000004;
const SYSCALL_OPEN: u64 = 0x2000005;
const SYSCALL_CLOSE: u64 = 0x2000006;
const SYSCALL_MPROTECT: u64 = 0x2000007;
const SYSCALL_UNLINK: u64 = 0x200000A;
const SYSCALL_CHDIR: u64 = 0x200000C;
const SYSCALL_FCHDIR: u64 = 0x200000D;
const SYSCALL_GETPID: u64 = 0x2000014;
const SYSCALL_GETUID: u64 = 0x2000018;
const SYSCALL_GETEUID: u64 = 0x2000019;
const SYSCALL_MUNMAP: u64 = 0x2000049;
const SYSCALL_RECVMSG: u64 = 0x200001B;
const SYSCALL_SENDMSG: u64 = 0x200001C;
const SYSCALL_RECVFROM: u64 = 0x200001D;
const SYSCALL_ACCEPT: u64 = 0x200001E;
const SYSCALL_GETPEERNAME: u64 = 0x200001F;
const SYSCALL_GETSOCKNAME: u64 = 0x2000020;
const SYSCALL_ACCESS: u64 = 0x2000021;
const SYSCALL_GETPPID: u64 = 0x2000027;
const SYSCALL_DUP: u64 = 0x2000029;
const SYSCALL_GETEGID: u64 = 0x200002B;
const SYSCALL_GETGID: u64 = 0x200002F;
const SYSCALL_SYMLINK: u64 = 0x2000039;
const SYSCALL_READLINK: u64 = 0x200003A;
const SYSCALL_UMASK: u64 = 0x200003C;
const SYSCALL_FCNTL: u64 = 0x200005C;
const SYSCALL_DUP2: u64 = 0x200005A;
const SYSCALL_SELECT: u64 = 0x200005D;
const SYSCALL_SOCKET: u64 = 0x2000061;
const SYSCALL_CONNECT: u64 = 0x2000062;
const SYSCALL_BIND: u64 = 0x2000068;
const SYSCALL_SETSOCKOPT: u64 = 0x2000069;
const SYSCALL_LISTEN: u64 = 0x200006A;
const SYSCALL_GETTIMEOFDAY: u64 = 0x2000074;
const SYSCALL_GETSOCKOPT: u64 = 0x2000076;
const SYSCALL_READV: u64 = 0x2000078;
const SYSCALL_WRITEV: u64 = 0x2000079;
const SYSCALL_RENAME: u64 = 0x2000080;
const SYSCALL_SENDTO: u64 = 0x2000085;
const SYSCALL_SHUTDOWN: u64 = 0x2000086;
const SYSCALL_SOCKETPAIR: u64 = 0x2000087;
const SYSCALL_MKDIR: u64 = 0x2000088;
const SYSCALL_RMDIR: u64 = 0x2000089;
const SYSCALL_STAT: u64 = 0x20000BC;
const SYSCALL_FSTAT: u64 = 0x20000BD;
const SYSCALL_LSTAT: u64 = 0x20000BE;
const SYSCALL_GETRLIMIT: u64 = 0x20000C2;
const SYSCALL_SETRLIMIT: u64 = 0x20000C3;
const SYSCALL_PREAD: u64 = 0x2000099;
const SYSCALL_PWRITE: u64 = 0x200009A;
const SYSCALL_MMAP: u64 = 0x20000C5;
const SYSCALL_LSEEK: u64 = 0x20000C7;
const SYSCALL_SYSCTL: u64 = 0x20000CA;
const SYSCALL_STAT64: u64 = 0x2000152;
const SYSCALL_FSTAT64: u64 = 0x2000153;
const SYSCALL_LSTAT64: u64 = 0x2000154;
const SYSCALL_READ_NOCANCEL: u64 = 0x200018C;
const SYSCALL_WRITE_NOCANCEL: u64 = 0x200018D;
const SYSCALL_OPEN_NOCANCEL: u64 = 0x200018E;
const SYSCALL_CLOSE_NOCANCEL: u64 = 0x200018F;
const SYSCALL_RECVMSG_NOCANCEL: u64 = 0x2000191;
const SYSCALL_SENDMSG_NOCANCEL: u64 = 0x2000192;
const SYSCALL_RECVFROM_NOCANCEL: u64 = 0x2000193;
const SYSCALL_ACCEPT_NOCANCEL: u64 = 0x2000194;
const SYSCALL_FCNTL_NOCANCEL: u64 = 0x2000196;
const SYSCALL_SELECT_NOCANCEL: u64 = 0x2000197;
const SYSCALL_CONNECT_NOCANCEL: u64 = 0x2000199;
const SYSCALL_READV_NOCANCEL: u64 = 0x200019B;
const SYSCALL_WRITEV_NOCANCEL: u64 = 0x200019C;
const SYSCALL_SENDTO_NOCANCEL: u64 = 0x200019D;
const SYSCALL_PREAD_NOCANCEL: u64 = 0x200019E;
const SYSCALL_PWRITE_NOCANCEL: u64 = 0x200019F;
const SYSCALL_POLL_NOCANCEL: u64 = 0x20001A1;
const SYSCALL_GETENTROPY: u64 = 0x20001F4;

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
        SYSCALL_EXIT => "exit",
        SYSCALL_READ => "read",
        SYSCALL_WRITE => "write",
        SYSCALL_OPEN => "open",
        SYSCALL_CLOSE => "close",
        SYSCALL_MPROTECT => "mprotect",
        SYSCALL_UNLINK => "unlink",
        SYSCALL_CHDIR => "chdir",
        SYSCALL_FCHDIR => "fchdir",
        SYSCALL_GETPID => "getpid",
        SYSCALL_GETUID => "getuid",
        SYSCALL_GETEUID => "geteuid",
        SYSCALL_MUNMAP => "munmap",
        SYSCALL_RECVMSG => "recvmsg",
        SYSCALL_SENDMSG => "sendmsg",
        SYSCALL_ACCEPT => "accept",
        SYSCALL_GETPEERNAME => "getpeername",
        SYSCALL_GETSOCKNAME => "getsockname",
        SYSCALL_ACCESS => "access",
        SYSCALL_GETPPID => "getppid",
        SYSCALL_DUP => "dup",
        SYSCALL_GETEGID => "getegid",
        SYSCALL_GETGID => "getgid",
        SYSCALL_SYMLINK => "symlink",
        SYSCALL_READLINK => "readlink",
        SYSCALL_UMASK => "umask",
        SYSCALL_DUP2 => "dup2",
        SYSCALL_FCNTL => "fcntl",
        SYSCALL_SELECT => "select",
        SYSCALL_SOCKET => "socket",
        SYSCALL_CONNECT => "connect",
        SYSCALL_BIND => "bind",
        SYSCALL_SETSOCKOPT => "setsockopt",
        SYSCALL_LISTEN => "listen",
        SYSCALL_GETTIMEOFDAY => "gettimeofday",
        SYSCALL_GETSOCKOPT => "getsockopt",
        SYSCALL_READV => "readv",
        SYSCALL_WRITEV => "writev",
        SYSCALL_RENAME => "rename",
        SYSCALL_SENDTO => "sendto",
        SYSCALL_SHUTDOWN => "shutdown",
        SYSCALL_SOCKETPAIR => "socketpair",
        SYSCALL_MKDIR => "mkdir",
        SYSCALL_RMDIR => "rmdir",
        SYSCALL_STAT => "stat",
        SYSCALL_FSTAT => "fstat",
        SYSCALL_LSTAT => "lstat",
        SYSCALL_GETRLIMIT => "getrlimit",
        SYSCALL_SETRLIMIT => "setrlimit",
        SYSCALL_PREAD => "pread",
        SYSCALL_PWRITE => "pwrite",
        SYSCALL_MMAP => "mmap",
        SYSCALL_LSEEK => "lseek",
        SYSCALL_SYSCTL => "sysctl",
        SYSCALL_STAT64 => "stat64",
        SYSCALL_FSTAT64 => "fstat64",
        SYSCALL_LSTAT64 => "lstat64",
        SYSCALL_RECVFROM => "recvfrom",
        SYSCALL_READ_NOCANCEL => "read_nocancel",
        SYSCALL_WRITE_NOCANCEL => "write_nocancel",
        SYSCALL_OPEN_NOCANCEL => "open_nocancel",
        SYSCALL_CLOSE_NOCANCEL => "close_nocancel",
        SYSCALL_RECVMSG_NOCANCEL => "recvmsg_nocancel",
        SYSCALL_SENDMSG_NOCANCEL => "sendmsg_nocancel",
        SYSCALL_RECVFROM_NOCANCEL => "recvfrom_nocancel",
        SYSCALL_ACCEPT_NOCANCEL => "accept_nocancel",
        SYSCALL_FCNTL_NOCANCEL => "fcntl_nocancel",
        SYSCALL_SELECT_NOCANCEL => "select_nocancel",
        SYSCALL_CONNECT_NOCANCEL => "connect_nocancel",
        SYSCALL_READV_NOCANCEL => "readv_nocancel",
        SYSCALL_WRITEV_NOCANCEL => "writev_nocancel",
        SYSCALL_SENDTO_NOCANCEL => "sendto_nocancel",
        SYSCALL_PREAD_NOCANCEL => "pread_nocancel",
        SYSCALL_PWRITE_NOCANCEL => "pwrite_nocancel",
        SYSCALL_POLL_NOCANCEL => "poll_nocancel",
        SYSCALL_GETENTROPY => "getentropy",
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
        SYSCALL_EXIT => {
            runtime.saw_exit.store(true, Ordering::Relaxed);
            stop_addr = Some(runtime.done_addr);
            event = event
                .arg("ExitCode", invocation.args[0].to_string())
                .arg("Result", "0");
        }
        SYSCALL_GETPID | SYSCALL_GETPPID | SYSCALL_GETUID | SYSCALL_GETEUID | SYSCALL_GETGID
        | SYSCALL_GETEGID => {
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                match invocation.num {
                    SYSCALL_GETPID => compat.getpid(),
                    SYSCALL_GETPPID => compat.getppid(),
                    SYSCALL_GETUID => compat.getuid(),
                    SYSCALL_GETEUID => compat.geteuid(),
                    SYSCALL_GETGID => compat.getgid(),
                    SYSCALL_GETEGID => compat.getegid(),
                    _ => None,
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Result", return_value.to_string());
                if let Some(errno) = result.errno {
                    event = event.arg("Errno", errno.to_string());
                }
            } else {
                return_value = match invocation.num {
                    SYSCALL_GETPID | SYSCALL_GETPPID => 1,
                    _ => 0,
                };
                event = event.arg("Result", return_value.to_string());
            }
        }
        SYSCALL_UMASK => {
            let mask = invocation.args[0];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.umask(mask))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Mask", format!("0x{:X}", mask))
                    .arg("Result", return_value.to_string());
            } else {
                event = event
                    .arg("Mask", format!("0x{:X}", mask))
                    .arg("Result", "0");
            }
        }
        SYSCALL_GETTIMEOFDAY => {
            let tv_ptr = invocation.args[0];
            let tz_ptr = invocation.args[1];
            let mach_absolute_time_ptr = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.gettimeofday(emu, tv_ptr, tz_ptr, mach_absolute_time_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Timeval", format!("0x{:X}", tv_ptr))
                    .arg("Timezone", format!("0x{:X}", tz_ptr))
                    .arg(
                        "MachAbsoluteTime",
                        format!("0x{:X}", mach_absolute_time_ptr),
                    )
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Timeval", format!("0x{:X}", tv_ptr))
                    .arg("Timezone", format!("0x{:X}", tz_ptr))
                    .arg("Result", "0");
            }
        }
        SYSCALL_GETENTROPY => {
            let buf = invocation.args[0];
            let count = invocation.args[1] as usize;
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.getentropy(emu, buf, count))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Buf", format!("0x{:X}", buf))
                    .arg("Count", count.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event
                    .arg("Buf", format!("0x{:X}", buf))
                    .arg("Count", count.to_string())
                    .arg("Result", "0");
            }
        }
        SYSCALL_WRITE | SYSCALL_WRITE_NOCANCEL => {
            let fd = invocation.args[0] as i32;
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            if fd == 1 || fd == 2 {
                if let Ok(data) = emu.read_memory(buf, count) {
                    event = event.arg("Preview", lossy_data_preview(&data, 256));
                }
            } else if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.write_fd(emu, fd as u64, buf, count))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Count", count.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                    return Ok(SyscallOutcome {
                        return_value,
                        stop_addr,
                        event,
                    });
                }
            }
            return_value = count as u64;
            event = event
                .arg("Fd", fd.to_string())
                .arg("Count", count.to_string())
                .arg("Result", count.to_string());
        }
        SYSCALL_READ | SYSCALL_READ_NOCANCEL => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let mut nread = 0usize;
            let mut handled = false;
            if let Ok(mut table) = runtime.fd_table.lock() {
                if let Some(file) = table.get_mut(&fd) {
                    handled = true;
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
            if !handled && fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.read_fd(emu, fd, buf, count))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Buf", format!("0x{:X}", buf))
                        .arg("Count", count.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                    return Ok(SyscallOutcome {
                        return_value,
                        stop_addr,
                        event,
                    });
                }
            }
            return_value = nread as u64;
            event = event
                .arg("Fd", fd.to_string())
                .arg("Buf", format!("0x{:X}", buf))
                .arg("Count", count.to_string())
                .arg("Result", nread.to_string());
        }
        SYSCALL_READV | SYSCALL_READV_NOCANCEL => {
            let fd = invocation.args[0];
            let iov_ptr = invocation.args[1];
            let iovcnt = invocation.args[2];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.readv_fd(emu, fd, iov_ptr, iovcnt))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Iov", format!("0x{:X}", iov_ptr))
                        .arg("IovCnt", iovcnt.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_WRITEV | SYSCALL_WRITEV_NOCANCEL => {
            let fd = invocation.args[0];
            let iov_ptr = invocation.args[1];
            let iovcnt = invocation.args[2];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.writev_fd(emu, fd, iov_ptr, iovcnt))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Iov", format!("0x{:X}", iov_ptr))
                        .arg("IovCnt", iovcnt.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_PREAD | SYSCALL_PREAD_NOCANCEL => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let offset = invocation.args[3];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.pread_fd(emu, fd, buf, count, offset))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Buf", format!("0x{:X}", buf))
                        .arg("Count", count.to_string())
                        .arg("Offset", offset.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_PWRITE | SYSCALL_PWRITE_NOCANCEL => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let offset = invocation.args[3];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.pwrite_fd(emu, fd, buf, count, offset))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Buf", format!("0x{:X}", buf))
                        .arg("Count", count.to_string())
                        .arg("Offset", offset.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Preview", lossy_data_preview(&result.preview, 128));
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_LSEEK => {
            let fd = invocation.args[0];
            let offset = invocation.args[1];
            let whence = invocation.args[2];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.lseek_fd(fd, offset, whence))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Offset", offset.to_string())
                        .arg("Whence", whence.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string());
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_DUP => {
            let fd = invocation.args[0];
            if fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.dup_fd(fd))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string());
                } else {
                    event = event.arg("Fd", fd.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_DUP2 => {
            let from = invocation.args[0];
            let to = invocation.args[1];
            if from > 2 && to > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.dup2_fd(from, to))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("From", from.to_string())
                        .arg("To", to.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string());
                } else {
                    event = event.arg("From", from.to_string()).arg("Result", "0");
                }
            } else {
                event = event.arg("From", from.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_SELECT | SYSCALL_SELECT_NOCANCEL => {
            let nfds = invocation.args[0];
            let readfds_ptr = invocation.args[1];
            let writefds_ptr = invocation.args[2];
            let exceptfds_ptr = invocation.args[3];
            let timeout_ptr = invocation.args[4];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.select_fds(
                        emu,
                        nfds,
                        readfds_ptr,
                        writefds_ptr,
                        exceptfds_ptr,
                        timeout_ptr,
                    )
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Nfds", nfds.to_string())
                    .arg("ReadFds", format!("0x{:X}", readfds_ptr))
                    .arg("WriteFds", format!("0x{:X}", writefds_ptr))
                    .arg("ExceptFds", format!("0x{:X}", exceptfds_ptr))
                    .arg("Timeout", format!("0x{:X}", timeout_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Result", "0");
            }
        }
        SYSCALL_MMAP => {
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
        SYSCALL_MPROTECT | SYSCALL_MUNMAP => {
            event = event.arg("Result", "0");
        }
        SYSCALL_OPEN | SYSCALL_OPEN_NOCANCEL => {
            let path_ptr = invocation.args[0];
            let flags = invocation.args[1];
            let mode = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.open_path_arg0(emu, path_ptr, flags, mode))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", result.path)
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
                return Ok(SyscallOutcome {
                    return_value,
                    stop_addr,
                    event,
                });
            }
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
        SYSCALL_ACCESS => {
            let path_ptr = invocation.args[0];
            let mode = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.access_path(emu, path_ptr, mode))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_CHDIR => {
            let path_ptr = invocation.args[0];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.chdir_path(emu, path_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_FCHDIR => {
            let fd = invocation.args[0];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fchdir_fd(fd))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_STAT | SYSCALL_STAT64 => {
            let path_ptr = invocation.args[0];
            let stat_ptr = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.stat_path(emu, path_ptr, stat_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", stat_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_LSTAT | SYSCALL_LSTAT64 => {
            let path_ptr = invocation.args[0];
            let stat_ptr = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.lstat_path(emu, path_ptr, stat_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", stat_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_FSTAT | SYSCALL_FSTAT64 => {
            let fd = invocation.args[0];
            let stat_ptr = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fstat_fd(emu, fd, stat_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Buf", format!("0x{:X}", stat_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_GETRLIMIT | SYSCALL_SETRLIMIT => {
            let resource = invocation.args[0];
            let rlp_ptr = invocation.args[1];
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if invocation.num == SYSCALL_GETRLIMIT {
                    compat.getrlimit(emu, resource, rlp_ptr)
                } else {
                    compat.setrlimit(emu, resource, rlp_ptr)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Resource", resource.to_string())
                    .arg("Rlimit", format!("0x{:X}", rlp_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Resource", resource.to_string())
                    .arg("Rlimit", format!("0x{:X}", rlp_ptr))
                    .arg("Result", "0");
            }
        }
        SYSCALL_SYSCTL => {
            let name_ptr = invocation.args[0];
            let namelen = invocation.args[1];
            let oldp = invocation.args[2];
            let oldlenp = invocation.args[3];
            let newp = invocation.args[4];
            let newlen = invocation.args[5];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.sysctl(emu, name_ptr, namelen, oldp, oldlenp, newp, newlen)
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Name", format!("0x{:X}", name_ptr))
                    .arg("NameLen", namelen.to_string())
                    .arg("Old", format!("0x{:X}", oldp))
                    .arg("OldLen", format!("0x{:X}", oldlenp))
                    .arg("New", format!("0x{:X}", newp))
                    .arg("NewLen", newlen.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event
                    .arg("Name", format!("0x{:X}", name_ptr))
                    .arg("NameLen", namelen.to_string())
                    .arg("Result", "0");
            }
        }
        SYSCALL_MKDIR => {
            let path_ptr = invocation.args[0];
            let mode = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.mkdir_path(emu, path_ptr, mode))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_RMDIR => {
            let path_ptr = invocation.args[0];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.rmdir_path(emu, path_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_UNLINK => {
            let path_ptr = invocation.args[0];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.unlink_path(emu, path_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_RENAME => {
            let from_ptr = invocation.args[0];
            let to_ptr = invocation.args[1];
            let from = read_cstring(emu, from_ptr, 1024).unwrap_or_default();
            let to = read_cstring(emu, to_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.rename_path(emu, from_ptr, to_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("From", from)
                    .arg("To", to)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("From", from).arg("To", to).arg("Result", "0");
            }
        }
        SYSCALL_READLINK => {
            let path_ptr = invocation.args[0];
            let buf_ptr = invocation.args[1];
            let count = invocation.args[2] as usize;
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.readlink_path(emu, path_ptr, buf_ptr, count))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Path", path).arg("Result", "0");
            }
        }
        SYSCALL_SYMLINK => {
            let target_ptr = invocation.args[0];
            let link_ptr = invocation.args[1];
            let target = read_cstring(emu, target_ptr, 1024).unwrap_or_default();
            let link = read_cstring(emu, link_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.symlink_path(emu, target_ptr, link_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Target", target)
                    .arg("Link", link)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Target", target)
                    .arg("Link", link)
                    .arg("Result", "0");
            }
        }
        SYSCALL_CLOSE | SYSCALL_CLOSE_NOCANCEL => {
            let fd = invocation.args[0];
            let mut removed_synthetic = false;
            if let Ok(mut table) = runtime.fd_table.lock() {
                removed_synthetic = table.remove(&fd).is_some();
            }
            if !removed_synthetic && fd > 2 {
                if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.close_fd(fd))
                {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Fd", fd.to_string())
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string());
                    return Ok(SyscallOutcome {
                        return_value,
                        stop_addr,
                        event,
                    });
                }
            }
            event = event.arg("Fd", fd.to_string()).arg("Result", "0");
        }
        SYSCALL_SOCKET => {
            let domain = invocation.args[0];
            let kind = invocation.args[1];
            let protocol = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.socket(domain, kind, protocol))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Domain", domain.to_string())
                    .arg("Type", kind.to_string())
                    .arg("Protocol", protocol.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Result", "0");
            }
        }
        SYSCALL_ACCEPT | SYSCALL_ACCEPT_NOCANCEL => {
            let fd = invocation.args[0];
            let sockaddr_ptr = invocation.args[1];
            let sockaddr_len_ptr = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.accept_socket(emu, fd, sockaddr_ptr, sockaddr_len_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLenPtr", format!("0x{:X}", sockaddr_len_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_GETPEERNAME | SYSCALL_GETSOCKNAME => {
            let fd = invocation.args[0];
            let sockaddr_ptr = invocation.args[1];
            let sockaddr_len_ptr = invocation.args[2];
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if invocation.num == SYSCALL_GETPEERNAME {
                    compat.getpeername_socket(emu, fd, sockaddr_ptr, sockaddr_len_ptr)
                } else {
                    compat.getsockname_socket(emu, fd, sockaddr_ptr, sockaddr_len_ptr)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLenPtr", format!("0x{:X}", sockaddr_len_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_FCNTL | SYSCALL_FCNTL_NOCANCEL => {
            let fd = invocation.args[0];
            let cmd = invocation.args[1];
            let arg = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fcntl_fd(fd, cmd, arg))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Cmd", format!("0x{:X}", cmd))
                    .arg("Arg", format!("0x{:X}", arg))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_CONNECT | SYSCALL_CONNECT_NOCANCEL => {
            let fd = invocation.args[0];
            let sockaddr_ptr = invocation.args[1];
            let sockaddr_len = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.connect_socket(emu, fd, sockaddr_ptr, sockaddr_len))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLen", sockaddr_len.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_BIND => {
            let fd = invocation.args[0];
            let sockaddr_ptr = invocation.args[1];
            let sockaddr_len = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.bind_socket(emu, fd, sockaddr_ptr, sockaddr_len))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLen", sockaddr_len.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_LISTEN => {
            let fd = invocation.args[0];
            let backlog = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.listen_socket(fd, backlog))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Backlog", backlog.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_SENDMSG | SYSCALL_SENDMSG_NOCANCEL => {
            let fd = invocation.args[0];
            let msg_ptr = invocation.args[1];
            let flags = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.sendmsg_socket(emu, fd, msg_ptr, flags))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Msg", format!("0x{:X}", msg_ptr))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_RECVMSG | SYSCALL_RECVMSG_NOCANCEL => {
            let fd = invocation.args[0];
            let msg_ptr = invocation.args[1];
            let flags = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.recvmsg_socket(emu, fd, msg_ptr, flags))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Msg", format!("0x{:X}", msg_ptr))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_SENDTO | SYSCALL_SENDTO_NOCANCEL => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let flags = invocation.args[3];
            let sockaddr_ptr = invocation.args[4];
            let sockaddr_len = invocation.args[5];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.sendto_socket(emu, fd, buf, count, flags, sockaddr_ptr, sockaddr_len)
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Count", count.to_string())
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLen", sockaddr_len.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_RECVFROM | SYSCALL_RECVFROM_NOCANCEL => {
            let fd = invocation.args[0];
            let buf = invocation.args[1];
            let count = invocation.args[2] as usize;
            let flags = invocation.args[3];
            let sockaddr_ptr = invocation.args[4];
            let sockaddr_len_ptr = invocation.args[5];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.recvfrom_socket(
                        emu,
                        fd,
                        buf,
                        count,
                        flags,
                        sockaddr_ptr,
                        sockaddr_len_ptr,
                    )
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Count", count.to_string())
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("SockAddr", format!("0x{:X}", sockaddr_ptr))
                    .arg("SockAddrLenPtr", format!("0x{:X}", sockaddr_len_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_SHUTDOWN => {
            let fd = invocation.args[0];
            let how = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.shutdown_socket(fd, how))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("How", how.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_SOCKETPAIR => {
            let domain = invocation.args[0];
            let kind = invocation.args[1];
            let protocol = invocation.args[2];
            let sv_ptr = invocation.args[3];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.socketpair(emu, domain, kind, protocol, sv_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Domain", domain.to_string())
                    .arg("Type", kind.to_string())
                    .arg("Protocol", protocol.to_string())
                    .arg("SocketVec", format!("0x{:X}", sv_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Result", "0");
            }
        }
        SYSCALL_POLL_NOCANCEL => {
            let fds_ptr = invocation.args[0];
            let nfds = invocation.args[1];
            let timeout = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.poll_fds(emu, fds_ptr, nfds, timeout))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("PollFds", format!("0x{:X}", fds_ptr))
                    .arg("Nfds", nfds.to_string())
                    .arg("Timeout", timeout.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Result", "0");
            }
        }
        SYSCALL_SETSOCKOPT => {
            let fd = invocation.args[0];
            let level = invocation.args[1];
            let option_name = invocation.args[2];
            let option_value_ptr = invocation.args[3];
            let option_len = invocation.args[4];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.setsockopt_socket(
                        emu,
                        fd,
                        level,
                        option_name,
                        option_value_ptr,
                        option_len,
                    )
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Level", level.to_string())
                    .arg("Option", option_name.to_string())
                    .arg("OptionLen", option_len.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
        }
        SYSCALL_GETSOCKOPT => {
            let fd = invocation.args[0];
            let level = invocation.args[1];
            let option_name = invocation.args[2];
            let option_value_ptr = invocation.args[3];
            let option_len_ptr = invocation.args[4];
            if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                    compat.getsockopt_socket(
                        emu,
                        fd,
                        level,
                        option_name,
                        option_value_ptr,
                        option_len_ptr,
                    )
                })
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Level", level.to_string())
                    .arg("Option", option_name.to_string())
                    .arg("OptionLenPtr", format!("0x{:X}", option_len_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event.arg("Fd", fd.to_string()).arg("Result", "0");
            }
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
        assert_eq!(default_syscall_name(0x200000A), "unlink");
        assert_eq!(default_syscall_name(0x200000C), "chdir");
        assert_eq!(default_syscall_name(0x200000D), "fchdir");
        assert_eq!(default_syscall_name(0x2000014), "getpid");
        assert_eq!(default_syscall_name(0x2000018), "getuid");
        assert_eq!(default_syscall_name(0x2000019), "geteuid");
        assert_eq!(default_syscall_name(0x200001B), "recvmsg");
        assert_eq!(default_syscall_name(0x200001C), "sendmsg");
        assert_eq!(default_syscall_name(0x200001E), "accept");
        assert_eq!(default_syscall_name(0x2000021), "access");
        assert_eq!(default_syscall_name(0x2000027), "getppid");
        assert_eq!(default_syscall_name(0x2000029), "dup");
        assert_eq!(default_syscall_name(0x200002B), "getegid");
        assert_eq!(default_syscall_name(0x200002F), "getgid");
        assert_eq!(default_syscall_name(0x2000039), "symlink");
        assert_eq!(default_syscall_name(0x200003A), "readlink");
        assert_eq!(default_syscall_name(0x200003C), "umask");
        assert_eq!(default_syscall_name(0x200005A), "dup2");
        assert_eq!(default_syscall_name(0x200005C), "fcntl");
        assert_eq!(default_syscall_name(0x200005D), "select");
        assert_eq!(default_syscall_name(0x2000061), "socket");
        assert_eq!(default_syscall_name(0x2000068), "bind");
        assert_eq!(default_syscall_name(0x2000074), "gettimeofday");
        assert_eq!(default_syscall_name(0x2000078), "readv");
        assert_eq!(default_syscall_name(0x2000079), "writev");
        assert_eq!(default_syscall_name(0x2000080), "rename");
        assert_eq!(default_syscall_name(0x2000085), "sendto");
        assert_eq!(default_syscall_name(0x2000087), "socketpair");
        assert_eq!(default_syscall_name(0x2000088), "mkdir");
        assert_eq!(default_syscall_name(0x2000089), "rmdir");
        assert_eq!(default_syscall_name(0x20000BC), "stat");
        assert_eq!(default_syscall_name(0x20000BD), "fstat");
        assert_eq!(default_syscall_name(0x20000BE), "lstat");
        assert_eq!(default_syscall_name(0x20000C2), "getrlimit");
        assert_eq!(default_syscall_name(0x20000C3), "setrlimit");
        assert_eq!(default_syscall_name(0x2000099), "pread");
        assert_eq!(default_syscall_name(0x200009A), "pwrite");
        assert_eq!(default_syscall_name(0x20000C5), "mmap");
        assert_eq!(default_syscall_name(0x20000C7), "lseek");
        assert_eq!(default_syscall_name(0x20000CA), "sysctl");
        assert_eq!(default_syscall_name(0x2000152), "stat64");
        assert_eq!(default_syscall_name(0x2000153), "fstat64");
        assert_eq!(default_syscall_name(0x2000154), "lstat64");
        assert_eq!(default_syscall_name(0x200018C), "read_nocancel");
        assert_eq!(default_syscall_name(0x200018D), "write_nocancel");
        assert_eq!(default_syscall_name(0x200018E), "open_nocancel");
        assert_eq!(default_syscall_name(0x200018F), "close_nocancel");
        assert_eq!(default_syscall_name(0x2000191), "recvmsg_nocancel");
        assert_eq!(default_syscall_name(0x2000192), "sendmsg_nocancel");
        assert_eq!(default_syscall_name(0x2000194), "accept_nocancel");
        assert_eq!(default_syscall_name(0x2000196), "fcntl_nocancel");
        assert_eq!(default_syscall_name(0x200019B), "readv_nocancel");
        assert_eq!(default_syscall_name(0x20001A1), "poll_nocancel");
        assert_eq!(default_syscall_name(0x20001F4), "getentropy");
        assert_eq!(default_syscall_name(0xDEAD), "unknown");
    }

    #[test]
    fn default_guest_fs_base_falls_back_to_workspace() {
        let base =
            default_guest_fs_base(Path::new(r"fixtures\macos\bin\sample.macho"), "arm64_ios");
        assert_eq!(base, PathBuf::from("."));
    }
}
