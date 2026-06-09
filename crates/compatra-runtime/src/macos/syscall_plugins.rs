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

use crate::macos::analysis::materialize_missing_file_for_mode;
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
const SYSCALL_WAIT4: u64 = 0x2000007;
const SYSCALL_UNLINK: u64 = 0x200000A;
const SYSCALL_CHDIR: u64 = 0x200000C;
const SYSCALL_FCHDIR: u64 = 0x200000D;
const SYSCALL_CHMOD: u64 = 0x200000F;
const SYSCALL_GETPID: u64 = 0x2000014;
const SYSCALL_GETUID: u64 = 0x2000018;
const SYSCALL_GETEUID: u64 = 0x2000019;
const SYSCALL_RECVMSG: u64 = 0x200001B;
const SYSCALL_SENDMSG: u64 = 0x200001C;
const SYSCALL_RECVFROM: u64 = 0x200001D;
const SYSCALL_ACCEPT: u64 = 0x200001E;
const SYSCALL_GETPEERNAME: u64 = 0x200001F;
const SYSCALL_GETSOCKNAME: u64 = 0x2000020;
const SYSCALL_ACCESS: u64 = 0x2000021;
const SYSCALL_GETPPID: u64 = 0x2000027;
const SYSCALL_DUP: u64 = 0x2000029;
const SYSCALL_PIPE: u64 = 0x200002A;
const SYSCALL_GETEGID: u64 = 0x200002B;
const SYSCALL_GETGID: u64 = 0x200002F;
const SYSCALL_IOCTL: u64 = 0x2000036;
const SYSCALL_SYMLINK: u64 = 0x2000039;
const SYSCALL_READLINK: u64 = 0x200003A;
const SYSCALL_UMASK: u64 = 0x200003C;
const SYSCALL_MUNMAP: u64 = 0x2000049;
const SYSCALL_MPROTECT: u64 = 0x200004A;
const SYSCALL_MADVISE: u64 = 0x200004B;
const SYSCALL_DUP2: u64 = 0x200005A;
const SYSCALL_FCNTL: u64 = 0x200005C;
const SYSCALL_SELECT: u64 = 0x200005D;
const SYSCALL_FSYNC: u64 = 0x200005F;
const SYSCALL_SOCKET: u64 = 0x2000061;
const SYSCALL_CONNECT: u64 = 0x2000062;
const SYSCALL_BIND: u64 = 0x2000068;
const SYSCALL_SETSOCKOPT: u64 = 0x2000069;
const SYSCALL_LISTEN: u64 = 0x200006A;
const SYSCALL_GETTIMEOFDAY: u64 = 0x2000074;
const SYSCALL_GETRUSAGE: u64 = 0x2000075;
const SYSCALL_GETSOCKOPT: u64 = 0x2000076;
const SYSCALL_READV: u64 = 0x2000078;
const SYSCALL_WRITEV: u64 = 0x2000079;
const SYSCALL_FCHMOD: u64 = 0x200007C;
const SYSCALL_RENAME: u64 = 0x2000080;
const SYSCALL_SENDTO: u64 = 0x2000085;
const SYSCALL_SHUTDOWN: u64 = 0x2000086;
const SYSCALL_SOCKETPAIR: u64 = 0x2000087;
const SYSCALL_MKDIR: u64 = 0x2000088;
const SYSCALL_RMDIR: u64 = 0x2000089;
const SYSCALL_STATFS: u64 = 0x200009D;
const SYSCALL_FSTATFS: u64 = 0x200009E;
const SYSCALL_STAT: u64 = 0x20000BC;
const SYSCALL_FSTAT: u64 = 0x20000BD;
const SYSCALL_LSTAT: u64 = 0x20000BE;
const SYSCALL_GETRLIMIT: u64 = 0x20000C2;
const SYSCALL_SETRLIMIT: u64 = 0x20000C3;
const SYSCALL_GETDIRENTRIES: u64 = 0x20000C4;
const SYSCALL_PREAD: u64 = 0x2000099;
const SYSCALL_PWRITE: u64 = 0x200009A;
const SYSCALL_MMAP: u64 = 0x20000C5;
const SYSCALL_LSEEK: u64 = 0x20000C7;
const SYSCALL_TRUNCATE: u64 = 0x20000C8;
const SYSCALL_FTRUNCATE: u64 = 0x20000C9;
const SYSCALL_SYSCTL: u64 = 0x20000CA;
const SYSCALL_GETATTRLIST: u64 = 0x20000DC;
const SYSCALL_GETDIRENTRIESATTR: u64 = 0x20000DE;
const SYSCALL_FGETATTRLIST: u64 = 0x20000E4;
const SYSCALL_POLL: u64 = 0x20000E6;
const SYSCALL_SHARED_REGION_CHECK_NP: u64 = 0x2000126;
const SYSCALL_ISSETUGID: u64 = 0x2000147;
const SYSCALL_STAT64: u64 = 0x2000152;
const SYSCALL_FSTAT64: u64 = 0x2000153;
const SYSCALL_LSTAT64: u64 = 0x2000154;
const SYSCALL_GETDIRENTRIES64: u64 = 0x2000158;
const SYSCALL_STATFS64: u64 = 0x2000159;
const SYSCALL_FSTATFS64: u64 = 0x200015A;
const SYSCALL_KQUEUE: u64 = 0x200016A;
const SYSCALL_KEVENT: u64 = 0x200016B;
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
const SYSCALL_OPENAT: u64 = 0x20001CF;
const SYSCALL_RENAMEAT: u64 = 0x20001D1;
const SYSCALL_FACCESSAT: u64 = 0x20001D2;
const SYSCALL_FCHMODAT: u64 = 0x20001D3;
const SYSCALL_FSTATAT: u64 = 0x20001D5;
const SYSCALL_UNLINKAT: u64 = 0x20001D8;
const SYSCALL_READLINKAT: u64 = 0x20001D9;
const SYSCALL_MKDIRAT: u64 = 0x20001DB;
const SYSCALL_GETENTROPY: u64 = 0x20001F4;

const AT_FDCWD: u64 = (-2i64) as u64;
const DARWIN_STATFS_SIZE: usize = 2168;

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
    pub extra_register_writes: Vec<(&'static str, u64)>,
    pub stop_addr: Option<u64>,
    pub event: TraceEvent,
}

fn zero_guest_memory(emu: &mut dyn Emulator, addr: u64, size: usize) {
    if addr != 0 && size != 0 {
        let _ = emu.write_memory(addr, &vec![0; size]);
    }
}

fn write_guest_u32(emu: &mut dyn Emulator, addr: u64, value: u32) {
    if addr != 0 {
        let _ = emu.write_memory(addr, &value.to_le_bytes());
    }
}

fn write_guest_u64(emu: &mut dyn Emulator, addr: u64, value: u64) {
    if addr != 0 {
        let _ = emu.write_memory(addr, &value.to_le_bytes());
    }
}

fn dirfd_label(dirfd: Option<u64>) -> String {
    match dirfd {
        Some(AT_FDCWD) => "AT_FDCWD".to_string(),
        Some(fd) => fd.to_string(),
        None => "-".to_string(),
    }
}

pub fn default_syscall_name(num: u64) -> &'static str {
    match num {
        SYSCALL_EXIT => "exit",
        SYSCALL_READ => "read",
        SYSCALL_WRITE => "write",
        SYSCALL_OPEN => "open",
        SYSCALL_CLOSE => "close",
        SYSCALL_WAIT4 => "wait4",
        SYSCALL_MPROTECT => "mprotect",
        SYSCALL_UNLINK => "unlink",
        SYSCALL_CHDIR => "chdir",
        SYSCALL_FCHDIR => "fchdir",
        SYSCALL_CHMOD => "chmod",
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
        SYSCALL_PIPE => "pipe",
        SYSCALL_GETEGID => "getegid",
        SYSCALL_GETGID => "getgid",
        SYSCALL_IOCTL => "ioctl",
        SYSCALL_SYMLINK => "symlink",
        SYSCALL_READLINK => "readlink",
        SYSCALL_UMASK => "umask",
        SYSCALL_MADVISE => "madvise",
        SYSCALL_DUP2 => "dup2",
        SYSCALL_FCNTL => "fcntl",
        SYSCALL_SELECT => "select",
        SYSCALL_FSYNC => "fsync",
        SYSCALL_SOCKET => "socket",
        SYSCALL_CONNECT => "connect",
        SYSCALL_BIND => "bind",
        SYSCALL_SETSOCKOPT => "setsockopt",
        SYSCALL_LISTEN => "listen",
        SYSCALL_GETTIMEOFDAY => "gettimeofday",
        SYSCALL_GETRUSAGE => "getrusage",
        SYSCALL_GETSOCKOPT => "getsockopt",
        SYSCALL_READV => "readv",
        SYSCALL_WRITEV => "writev",
        SYSCALL_FCHMOD => "fchmod",
        SYSCALL_RENAME => "rename",
        SYSCALL_SENDTO => "sendto",
        SYSCALL_SHUTDOWN => "shutdown",
        SYSCALL_SOCKETPAIR => "socketpair",
        SYSCALL_MKDIR => "mkdir",
        SYSCALL_RMDIR => "rmdir",
        SYSCALL_STATFS => "statfs",
        SYSCALL_FSTATFS => "fstatfs",
        SYSCALL_STAT => "stat",
        SYSCALL_FSTAT => "fstat",
        SYSCALL_LSTAT => "lstat",
        SYSCALL_GETRLIMIT => "getrlimit",
        SYSCALL_SETRLIMIT => "setrlimit",
        SYSCALL_GETDIRENTRIES => "getdirentries",
        SYSCALL_PREAD => "pread",
        SYSCALL_PWRITE => "pwrite",
        SYSCALL_MMAP => "mmap",
        SYSCALL_LSEEK => "lseek",
        SYSCALL_TRUNCATE => "truncate",
        SYSCALL_FTRUNCATE => "ftruncate",
        SYSCALL_SYSCTL => "sysctl",
        SYSCALL_GETATTRLIST => "getattrlist",
        SYSCALL_GETDIRENTRIESATTR => "getdirentriesattr",
        SYSCALL_FGETATTRLIST => "fgetattrlist",
        SYSCALL_POLL => "poll",
        SYSCALL_SHARED_REGION_CHECK_NP => "shared_region_check_np",
        SYSCALL_ISSETUGID => "issetugid",
        SYSCALL_STAT64 => "stat64",
        SYSCALL_FSTAT64 => "fstat64",
        SYSCALL_LSTAT64 => "lstat64",
        SYSCALL_GETDIRENTRIES64 => "getdirentries64",
        SYSCALL_STATFS64 => "statfs64",
        SYSCALL_FSTATFS64 => "fstatfs64",
        SYSCALL_KQUEUE => "kqueue",
        SYSCALL_KEVENT => "kevent",
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
        SYSCALL_OPENAT => "openat",
        SYSCALL_RENAMEAT => "renameat",
        SYSCALL_FACCESSAT => "faccessat",
        SYSCALL_FCHMODAT => "fchmodat",
        SYSCALL_FSTATAT => "fstatat",
        SYSCALL_UNLINKAT => "unlinkat",
        SYSCALL_READLINKAT => "readlinkat",
        SYSCALL_MKDIRAT => "mkdirat",
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
    let mut extra_register_writes = Vec::new();
    let mut stop_addr = None;

    match invocation.num {
        SYSCALL_EXIT => {
            runtime.saw_exit.store(true, Ordering::Relaxed);
            stop_addr = Some(runtime.done_addr);
            event = event
                .arg("ExitCode", invocation.args[0].to_string())
                .arg("Result", "0");
        }
        SYSCALL_WAIT4 => {
            let pid = invocation.args[0];
            let status_ptr = invocation.args[1];
            let options = invocation.args[2];
            let rusage_ptr = invocation.args[3];
            write_guest_u32(emu, status_ptr, 0);
            zero_guest_memory(emu, rusage_ptr, 256);
            event = event
                .arg("Pid", pid.to_string())
                .arg("Status", format!("0x{:X}", status_ptr))
                .arg("Options", format!("0x{:X}", options))
                .arg("Rusage", format!("0x{:X}", rusage_ptr))
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
        SYSCALL_ISSETUGID => {
            event = event.arg("Result", "0");
        }
        SYSCALL_SHARED_REGION_CHECK_NP => {
            let start_address_ptr = invocation.args[0];
            write_guest_u64(emu, start_address_ptr, 0);
            event = event
                .arg("StartAddress", format!("0x{:X}", start_address_ptr))
                .arg("Result", "0");
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
        SYSCALL_GETRUSAGE => {
            let who = invocation.args[0];
            let rusage_ptr = invocation.args[1];
            zero_guest_memory(emu, rusage_ptr, 256);
            event = event
                .arg("Who", who.to_string())
                .arg("Rusage", format!("0x{:X}", rusage_ptr))
                .arg("Result", "0");
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
                        extra_register_writes,
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
                        extra_register_writes,
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
        SYSCALL_PIPE => {
            let mut host_proxy = false;
            let mut errno = None;
            let (read_fd, write_fd) = if let Some(result) =
                CompatibilityServices::for_mode(runtime.runtime_mode)
                    .and_then(|compat| compat.pipe_pair())
            {
                host_proxy = true;
                errno = Some(result.errno);
                (result.read_fd, result.write_fd)
            } else {
                let read_fd = runtime.next_fd.fetch_add(2, Ordering::Relaxed);
                let write_fd = read_fd.saturating_add(1);
                if let Ok(mut table) = runtime.fd_table.lock() {
                    table.insert(
                        read_fd,
                        SyscallFdEntry::SyntheticCursor(Cursor::new(Vec::new())),
                    );
                    table.insert(
                        write_fd,
                        SyscallFdEntry::SyntheticCursor(Cursor::new(Vec::new())),
                    );
                }
                (read_fd, write_fd)
            };
            return_value = read_fd;
            if read_fd != u64::MAX {
                extra_register_writes.push(("x1", write_fd));
            }
            event = event
                .arg("HostProxy", host_proxy.to_string())
                .arg("ReadFd", read_fd.to_string())
                .arg("WriteFd", write_fd.to_string())
                .arg("Result", read_fd.to_string());
            if let Some(errno) = errno {
                event = event.arg("Errno", errno.to_string());
            }
            if read_fd != u64::MAX {
                event = event.arg("ResultX1", write_fd.to_string());
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
        SYSCALL_MPROTECT | SYSCALL_MUNMAP | SYSCALL_MADVISE => {
            event = event
                .arg("Addr", format!("0x{:X}", invocation.args[0]))
                .arg("Len", format!("0x{:X}", invocation.args[1]))
                .arg("Result", "0");
        }
        SYSCALL_OPEN | SYSCALL_OPEN_NOCANCEL | SYSCALL_OPENAT => {
            let is_openat = invocation.num == SYSCALL_OPENAT;
            let dirfd = is_openat.then_some(invocation.args[0]);
            let path_ptr = if is_openat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let flags = if is_openat {
                invocation.args[2]
            } else {
                invocation.args[1]
            };
            let mode = if is_openat {
                invocation.args[3]
            } else {
                invocation.args[2]
            };
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let Some(dirfd) = dirfd {
                    compat.openat_path(emu, dirfd, path_ptr, flags, mode)
                } else {
                    compat.open_path_arg0(emu, path_ptr, flags, mode)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", result.path)
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
                return Ok(SyscallOutcome {
                    return_value,
                    extra_register_writes,
                    stop_addr,
                    event,
                });
            }
            let creating = (flags & 0x200) != 0;
            let raw_path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let resolved = resolve_guest_path(&runtime.guest_fs_base, &raw_path);
            let fd = runtime.next_fd.fetch_add(1, Ordering::Relaxed);
            let entry = match File::open(&resolved) {
                Ok(file) => SyscallFdEntry::HostFile(file),
                Err(_) if creating => SyscallFdEntry::SyntheticCursor(Cursor::new(Vec::new())),
                Err(_) => {
                    match materialize_missing_file_for_mode(runtime.runtime_mode, &raw_path, 4096) {
                        Some(bytes) => SyscallFdEntry::SyntheticCursor(Cursor::new(bytes)),
                        None => {
                            return_value = u64::MAX;
                            event = event
                                .arg("Path", raw_path)
                                .arg("DirFd", dirfd_label(dirfd))
                                .arg("Resolved", resolved.display().to_string())
                                .arg("Result", format!("0x{:X}", u64::MAX))
                                .arg("Errno", "2");
                            return Ok(SyscallOutcome {
                                return_value,
                                extra_register_writes,
                                stop_addr,
                                event,
                            });
                        }
                    }
                }
            };
            if let Ok(mut table) = runtime.fd_table.lock() {
                table.insert(fd, entry);
                return_value = fd;
                event = event
                    .arg("Path", raw_path)
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Result", fd.to_string())
                    .arg("Synthetic", (!resolved.exists()).to_string());
            } else {
                return_value = u64::MAX;
                event = event
                    .arg("Path", raw_path)
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Result", format!("0x{:X}", u64::MAX));
            }
        }
        SYSCALL_ACCESS | SYSCALL_FACCESSAT => {
            let is_faccessat = invocation.num == SYSCALL_FACCESSAT;
            let dirfd = is_faccessat.then_some(invocation.args[0]);
            let path_ptr = if is_faccessat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let mode = if is_faccessat {
                invocation.args[2]
            } else {
                invocation.args[1]
            };
            let flags = is_faccessat.then_some(invocation.args[3]);
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let Some(dirfd) = dirfd {
                    compat.faccessat_path(emu, dirfd, path_ptr, mode, flags.unwrap_or(0))
                } else {
                    compat.access_path(emu, path_ptr, mode)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg(
                        "Flags",
                        flags
                            .map(|value| format!("0x{:X}", value))
                            .unwrap_or_else(|| "-".to_string()),
                    )
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Path", path)
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Result", "0");
            }
        }
        SYSCALL_CHMOD => {
            let path_ptr = invocation.args[0];
            let mode = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.chmod_path(emu, path_ptr, mode))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", "0");
            }
        }
        SYSCALL_FCHMOD => {
            let fd = invocation.args[0];
            let mode = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fchmod_fd(fd, mode))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Fd", fd.to_string())
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", "0");
            }
        }
        SYSCALL_FCHMODAT => {
            let dirfd = invocation.args[0];
            let path_ptr = invocation.args[1];
            let mode = invocation.args[2];
            let flags = invocation.args[3];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fchmodat_path(emu, dirfd, path_ptr, mode, flags))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("DirFd", dirfd_label(Some(dirfd)))
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("DirFd", dirfd_label(Some(dirfd)))
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", "0");
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
        SYSCALL_FSTATAT => {
            let dirfd = invocation.args[0];
            let path_ptr = invocation.args[1];
            let stat_ptr = invocation.args[2];
            let flags = invocation.args[3];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fstatat_path(emu, dirfd, path_ptr, stat_ptr, flags));
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("DirFd", dirfd_label(Some(dirfd)))
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", stat_ptr))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("DirFd", dirfd_label(Some(dirfd)))
                    .arg("Path", path)
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Result", "0");
            }
        }
        SYSCALL_STATFS | SYSCALL_STATFS64 => {
            let path_ptr = invocation.args[0];
            let buf_ptr = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.statfs_path(emu, path_ptr, buf_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                zero_guest_memory(emu, buf_ptr, DARWIN_STATFS_SIZE);
                event = event
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Result", "0");
            }
        }
        SYSCALL_FSTATFS | SYSCALL_FSTATFS64 => {
            let fd = invocation.args[0];
            let buf_ptr = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fstatfs_fd(emu, fd, buf_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                zero_guest_memory(emu, buf_ptr, DARWIN_STATFS_SIZE);
                event = event
                    .arg("Fd", fd.to_string())
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Result", "0");
            }
        }
        SYSCALL_TRUNCATE => {
            let path_ptr = invocation.args[0];
            let length = invocation.args[1];
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.truncate_path(emu, path_ptr, length))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Path", path)
                    .arg("Length", length.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Path", path)
                    .arg("Length", length.to_string())
                    .arg("Result", "0");
            }
        }
        SYSCALL_FTRUNCATE => {
            let fd = invocation.args[0];
            let length = invocation.args[1];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.ftruncate_fd(fd, length))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Length", length.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("Fd", fd.to_string())
                    .arg("Length", length.to_string())
                    .arg("Result", "0");
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
        SYSCALL_MKDIR | SYSCALL_MKDIRAT => {
            let is_mkdirat = invocation.num == SYSCALL_MKDIRAT;
            let dirfd = is_mkdirat.then_some(invocation.args[0]);
            let path_ptr = if is_mkdirat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let mode = if is_mkdirat {
                invocation.args[2]
            } else {
                invocation.args[1]
            };
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let Some(dirfd) = dirfd {
                    compat.mkdirat_path(emu, dirfd, path_ptr, mode)
                } else {
                    compat.mkdir_path(emu, path_ptr, mode)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg("Result", "0");
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
        SYSCALL_UNLINK | SYSCALL_UNLINKAT => {
            let is_unlinkat = invocation.num == SYSCALL_UNLINKAT;
            let dirfd = is_unlinkat.then_some(invocation.args[0]);
            let path_ptr = if is_unlinkat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let flags = is_unlinkat.then_some(invocation.args[2]);
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let Some(dirfd) = dirfd {
                    compat.unlinkat_path(emu, dirfd, path_ptr, flags.unwrap_or(0))
                } else {
                    compat.unlink_path(emu, path_ptr)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg(
                        "Flags",
                        flags
                            .map(|value| format!("0x{:X}", value))
                            .unwrap_or_else(|| "-".to_string()),
                    )
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg("Result", "0");
            }
        }
        SYSCALL_RENAME | SYSCALL_RENAMEAT => {
            let is_renameat = invocation.num == SYSCALL_RENAMEAT;
            let fromfd = is_renameat.then_some(invocation.args[0]);
            let from_ptr = if is_renameat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let tofd = is_renameat.then_some(invocation.args[2]);
            let to_ptr = if is_renameat {
                invocation.args[3]
            } else {
                invocation.args[1]
            };
            let from = read_cstring(emu, from_ptr, 1024).unwrap_or_default();
            let to = read_cstring(emu, to_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let (Some(fromfd), Some(tofd)) = (fromfd, tofd) {
                    compat.renameat_path(emu, fromfd, from_ptr, tofd, to_ptr)
                } else {
                    compat.rename_path(emu, from_ptr, to_ptr)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("FromDirFd", dirfd_label(fromfd))
                    .arg("From", from)
                    .arg("ToDirFd", dirfd_label(tofd))
                    .arg("To", to)
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string());
            } else {
                event = event
                    .arg("FromDirFd", dirfd_label(fromfd))
                    .arg("From", from)
                    .arg("ToDirFd", dirfd_label(tofd))
                    .arg("To", to)
                    .arg("Result", "0");
            }
        }
        SYSCALL_READLINK | SYSCALL_READLINKAT => {
            let is_readlinkat = invocation.num == SYSCALL_READLINKAT;
            let dirfd = is_readlinkat.then_some(invocation.args[0]);
            let path_ptr = if is_readlinkat {
                invocation.args[1]
            } else {
                invocation.args[0]
            };
            let buf_ptr = if is_readlinkat {
                invocation.args[2]
            } else {
                invocation.args[1]
            };
            let count = if is_readlinkat {
                invocation.args[3]
            } else {
                invocation.args[2]
            } as usize;
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let result = CompatibilityServices::for_mode(runtime.runtime_mode).and_then(|compat| {
                if let Some(dirfd) = dirfd {
                    compat.readlinkat_path(emu, dirfd, path_ptr, buf_ptr, count)
                } else {
                    compat.readlink_path(emu, path_ptr, buf_ptr, count)
                }
            });
            if let Some(result) = result {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event
                    .arg("DirFd", dirfd_label(dirfd))
                    .arg("Path", path)
                    .arg("Result", "0");
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
        SYSCALL_GETDIRENTRIES | SYSCALL_GETDIRENTRIES64 => {
            let fd = invocation.args[0];
            let buf_ptr = invocation.args[1];
            let count = invocation.args[2];
            let position_ptr = invocation.args[3];
            write_guest_u64(emu, position_ptr, 0);
            event = event
                .arg("Fd", fd.to_string())
                .arg("Buf", format!("0x{:X}", buf_ptr))
                .arg("Count", count.to_string())
                .arg("Position", format!("0x{:X}", position_ptr))
                .arg("Result", "0");
        }
        SYSCALL_GETATTRLIST | SYSCALL_FGETATTRLIST => {
            let subject = invocation.args[0];
            let attrlist_ptr = invocation.args[1];
            let buffer_ptr = invocation.args[2];
            let buffer_size = invocation.args[3] as usize;
            let options = invocation.args[4];
            if let Some(compat) = CompatibilityServices::for_mode(runtime.runtime_mode) {
                let result = if invocation.num == SYSCALL_GETATTRLIST {
                    compat.getattrlist_path(
                        emu,
                        subject,
                        attrlist_ptr,
                        buffer_ptr,
                        buffer_size,
                        options,
                    )
                } else {
                    compat.fgetattrlist_fd(
                        emu,
                        subject,
                        attrlist_ptr,
                        buffer_ptr,
                        buffer_size,
                        options,
                    )
                };
                if let Some(result) = result {
                    return_value = result.return_value;
                    event = event
                        .arg("HostProxy", "true")
                        .arg("Subject", format!("0x{:X}", subject))
                        .arg("AttrList", format!("0x{:X}", attrlist_ptr))
                        .arg("Buffer", format!("0x{:X}", buffer_ptr))
                        .arg("BufferSize", buffer_size.to_string())
                        .arg("Options", format!("0x{:X}", options))
                        .arg("Result", return_value.to_string())
                        .arg("Errno", result.errno.to_string())
                        .arg("Transferred", result.transferred.to_string());
                }
            } else {
                if buffer_size >= 4 {
                    write_guest_u32(emu, buffer_ptr, 4);
                }
                event = event
                    .arg("Subject", format!("0x{:X}", subject))
                    .arg("AttrList", format!("0x{:X}", attrlist_ptr))
                    .arg("Buffer", format!("0x{:X}", buffer_ptr))
                    .arg("BufferSize", buffer_size.to_string())
                    .arg("Result", "0");
            }
        }
        SYSCALL_GETDIRENTRIESATTR => {
            let fd = invocation.args[0];
            let attrlist_ptr = invocation.args[1];
            let buffer_ptr = invocation.args[2];
            let buffer_size = invocation.args[3];
            let count_ptr = invocation.args[4];
            let basep = invocation.args[5];
            write_guest_u32(emu, count_ptr, 0);
            write_guest_u64(emu, basep, 0);
            event = event
                .arg("Fd", fd.to_string())
                .arg("AttrList", format!("0x{:X}", attrlist_ptr))
                .arg("Buffer", format!("0x{:X}", buffer_ptr))
                .arg("BufferSize", buffer_size.to_string())
                .arg("Count", format!("0x{:X}", count_ptr))
                .arg("Base", format!("0x{:X}", basep))
                .arg("Result", "0");
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
                        extra_register_writes,
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
        SYSCALL_IOCTL => {
            let fd = invocation.args[0];
            let request = invocation.args[1];
            let data_ptr = invocation.args[2];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.ioctl_fd(emu, fd, request, data_ptr))
            {
                return_value = result.return_value;
                event = event
                    .arg("HostProxy", "true")
                    .arg("Fd", fd.to_string())
                    .arg("Request", format!("0x{:X}", request))
                    .arg("Data", format!("0x{:X}", data_ptr))
                    .arg("Result", return_value.to_string())
                    .arg("Errno", result.errno.to_string())
                    .arg("Preview", lossy_data_preview(&result.preview, 128));
            } else {
                event = event
                    .arg("Fd", fd.to_string())
                    .arg("Request", format!("0x{:X}", request))
                    .arg("Data", format!("0x{:X}", data_ptr))
                    .arg("Result", "0");
            }
        }
        SYSCALL_FSYNC => {
            let fd = invocation.args[0];
            if let Some(result) = CompatibilityServices::for_mode(runtime.runtime_mode)
                .and_then(|compat| compat.fsync_fd(fd))
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
        SYSCALL_KQUEUE => {
            let fd = runtime.next_fd.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut table) = runtime.fd_table.lock() {
                table.insert(fd, SyscallFdEntry::SyntheticCursor(Cursor::new(Vec::new())));
            }
            return_value = fd;
            event = event
                .arg("Fd", fd.to_string())
                .arg("Result", fd.to_string());
        }
        SYSCALL_KEVENT => {
            let fd = invocation.args[0];
            let changelist = invocation.args[1];
            let nchanges = invocation.args[2];
            let eventlist = invocation.args[3];
            let nevents = invocation.args[4];
            event = event
                .arg("Fd", fd.to_string())
                .arg("ChangeList", format!("0x{:X}", changelist))
                .arg("NChanges", nchanges.to_string())
                .arg("EventList", format!("0x{:X}", eventlist))
                .arg("NEvents", nevents.to_string())
                .arg("Result", "0");
        }
        SYSCALL_POLL | SYSCALL_POLL_NOCANCEL => {
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
        extra_register_writes,
        stop_addr,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::{ArchType, LogLevel};
    use std::any::Any;
    use std::collections::HashMap;

    struct TestEmulator {
        memory: HashMap<u64, u8>,
    }

    impl TestEmulator {
        fn new() -> Self {
            Self {
                memory: HashMap::new(),
            }
        }
    }

    impl Emulator for TestEmulator {
        fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, MacOsError> {
            Ok((0..size)
                .map(|offset| *self.memory.get(&(addr + offset as u64)).unwrap_or(&0))
                .collect())
        }

        fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MacOsError> {
            for (offset, byte) in data.iter().enumerate() {
                self.memory.insert(addr + offset as u64, *byte);
            }
            Ok(())
        }

        fn read_reg(&self, _reg: &str) -> Result<u64, MacOsError> {
            Ok(0)
        }

        fn write_reg(&mut self, _reg: &str, _value: u64) -> Result<(), MacOsError> {
            Ok(())
        }

        fn stack_push(&mut self, _value: u64) -> Result<(), MacOsError> {
            Ok(())
        }

        fn stack_pop(&mut self) -> Result<u64, MacOsError> {
            Ok(0)
        }

        fn stack_read(&self, _offset: i64) -> Result<u64, MacOsError> {
            Ok(0)
        }

        fn hook_syscall(
            &mut self,
            _handler: Box<dyn FnMut(&mut dyn Emulator) -> Result<i64, MacOsError> + Send>,
        ) {
        }

        fn run(&mut self, _begin: u64, _end: Option<u64>) -> Result<(), MacOsError> {
            Ok(())
        }

        fn arch_type(&self) -> ArchType {
            ArchType::Arm64
        }

        fn log(&mut self, _level: LogLevel, _msg: &str) {}

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    #[test]
    fn default_syscall_name_maps_common_calls() {
        assert_eq!(default_syscall_name(0x2000007), "wait4");
        assert_eq!(default_syscall_name(0x200004A), "mprotect");
        assert_eq!(default_syscall_name(0x200004B), "madvise");
        assert_eq!(default_syscall_name(0x2000004), "write");
        assert_eq!(default_syscall_name(0x200000A), "unlink");
        assert_eq!(default_syscall_name(0x200000C), "chdir");
        assert_eq!(default_syscall_name(0x200000D), "fchdir");
        assert_eq!(default_syscall_name(0x200000F), "chmod");
        assert_eq!(default_syscall_name(0x2000014), "getpid");
        assert_eq!(default_syscall_name(0x2000018), "getuid");
        assert_eq!(default_syscall_name(0x2000019), "geteuid");
        assert_eq!(default_syscall_name(0x200001B), "recvmsg");
        assert_eq!(default_syscall_name(0x200001C), "sendmsg");
        assert_eq!(default_syscall_name(0x200001E), "accept");
        assert_eq!(default_syscall_name(0x2000021), "access");
        assert_eq!(default_syscall_name(0x2000027), "getppid");
        assert_eq!(default_syscall_name(0x2000029), "dup");
        assert_eq!(default_syscall_name(0x200002A), "pipe");
        assert_eq!(default_syscall_name(0x200002B), "getegid");
        assert_eq!(default_syscall_name(0x200002F), "getgid");
        assert_eq!(default_syscall_name(0x2000036), "ioctl");
        assert_eq!(default_syscall_name(0x2000039), "symlink");
        assert_eq!(default_syscall_name(0x200003A), "readlink");
        assert_eq!(default_syscall_name(0x200003C), "umask");
        assert_eq!(default_syscall_name(0x200005A), "dup2");
        assert_eq!(default_syscall_name(0x200005C), "fcntl");
        assert_eq!(default_syscall_name(0x200005D), "select");
        assert_eq!(default_syscall_name(0x200005F), "fsync");
        assert_eq!(default_syscall_name(0x2000061), "socket");
        assert_eq!(default_syscall_name(0x2000068), "bind");
        assert_eq!(default_syscall_name(0x2000074), "gettimeofday");
        assert_eq!(default_syscall_name(0x2000075), "getrusage");
        assert_eq!(default_syscall_name(0x2000078), "readv");
        assert_eq!(default_syscall_name(0x2000079), "writev");
        assert_eq!(default_syscall_name(0x200007C), "fchmod");
        assert_eq!(default_syscall_name(0x2000080), "rename");
        assert_eq!(default_syscall_name(0x2000085), "sendto");
        assert_eq!(default_syscall_name(0x2000087), "socketpair");
        assert_eq!(default_syscall_name(0x2000088), "mkdir");
        assert_eq!(default_syscall_name(0x2000089), "rmdir");
        assert_eq!(default_syscall_name(0x200009D), "statfs");
        assert_eq!(default_syscall_name(0x200009E), "fstatfs");
        assert_eq!(default_syscall_name(0x20000BC), "stat");
        assert_eq!(default_syscall_name(0x20000BD), "fstat");
        assert_eq!(default_syscall_name(0x20000BE), "lstat");
        assert_eq!(default_syscall_name(0x20000C2), "getrlimit");
        assert_eq!(default_syscall_name(0x20000C3), "setrlimit");
        assert_eq!(default_syscall_name(0x20000C4), "getdirentries");
        assert_eq!(default_syscall_name(0x2000099), "pread");
        assert_eq!(default_syscall_name(0x200009A), "pwrite");
        assert_eq!(default_syscall_name(0x20000C5), "mmap");
        assert_eq!(default_syscall_name(0x20000C7), "lseek");
        assert_eq!(default_syscall_name(0x20000C8), "truncate");
        assert_eq!(default_syscall_name(0x20000C9), "ftruncate");
        assert_eq!(default_syscall_name(0x20000CA), "sysctl");
        assert_eq!(default_syscall_name(0x20000DC), "getattrlist");
        assert_eq!(default_syscall_name(0x20000E6), "poll");
        assert_eq!(default_syscall_name(0x2000126), "shared_region_check_np");
        assert_eq!(default_syscall_name(0x2000147), "issetugid");
        assert_eq!(default_syscall_name(0x2000152), "stat64");
        assert_eq!(default_syscall_name(0x2000153), "fstat64");
        assert_eq!(default_syscall_name(0x2000154), "lstat64");
        assert_eq!(default_syscall_name(0x2000158), "getdirentries64");
        assert_eq!(default_syscall_name(0x2000159), "statfs64");
        assert_eq!(default_syscall_name(0x200015A), "fstatfs64");
        assert_eq!(default_syscall_name(0x200016A), "kqueue");
        assert_eq!(default_syscall_name(0x200016B), "kevent");
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
        assert_eq!(default_syscall_name(0x20001CF), "openat");
        assert_eq!(default_syscall_name(0x20001D1), "renameat");
        assert_eq!(default_syscall_name(0x20001D2), "faccessat");
        assert_eq!(default_syscall_name(0x20001D3), "fchmodat");
        assert_eq!(default_syscall_name(0x20001D5), "fstatat");
        assert_eq!(default_syscall_name(0x20001D8), "unlinkat");
        assert_eq!(default_syscall_name(0x20001D9), "readlinkat");
        assert_eq!(default_syscall_name(0x20001DB), "mkdirat");
        assert_eq!(default_syscall_name(0x20001F4), "getentropy");
        assert_eq!(default_syscall_name(0xDEAD), "unknown");
    }

    #[test]
    fn default_guest_fs_base_falls_back_to_workspace() {
        let base =
            default_guest_fs_base(Path::new(r"fixtures\macos\bin\sample.macho"), "arm64_ios");
        assert_eq!(base, PathBuf::from("."));
    }

    #[test]
    fn wait4_syscall_zeroes_status_and_rusage_buffers() {
        let mut emu = TestEmulator::new();
        emu.write_memory(0x1000, &[0xAA; 4]).unwrap();
        emu.write_memory(0x2000, &[0xAA; 32]).unwrap();
        let runtime = SyscallRuntimeState::new(0xDEAD, 0, 0x4000_0000, 0x5000_0000, ".".into());
        let invocation = SyscallInvocation {
            num: SYSCALL_WAIT4,
            name: default_syscall_name(SYSCALL_WAIT4),
            pc: 0x100,
            args: [123, 0x1000, 0, 0x2000, 0, 0],
        };

        let outcome = handle_basic_macos_syscall(
            &mut emu,
            &invocation,
            &TraceMetadata::new(),
            &runtime,
            "test",
        )
        .unwrap();

        assert_eq!(outcome.return_value, 0);
        assert_eq!(emu.read_memory(0x1000, 4).unwrap(), vec![0; 4]);
        assert_eq!(emu.read_memory(0x2000, 32).unwrap(), vec![0; 32]);
    }

    #[test]
    fn statfs_syscall_zeroes_fallback_buffer() {
        let mut emu = TestEmulator::new();
        emu.write_memory(0x1000, b"/tmp\0").unwrap();
        emu.write_memory(0x2000, &[0xAA; 32]).unwrap();
        let runtime = SyscallRuntimeState::new(0xDEAD, 0, 0x4000_0000, 0x5000_0000, ".".into());
        let invocation = SyscallInvocation {
            num: SYSCALL_STATFS64,
            name: default_syscall_name(SYSCALL_STATFS64),
            pc: 0x100,
            args: [0x1000, 0x2000, 0, 0, 0, 0],
        };

        let outcome = handle_basic_macos_syscall(
            &mut emu,
            &invocation,
            &TraceMetadata::new(),
            &runtime,
            "test",
        )
        .unwrap();

        assert_eq!(outcome.return_value, 0);
        assert_eq!(emu.read_memory(0x2000, 32).unwrap(), vec![0; 32]);
    }

    #[test]
    fn pipe_syscall_returns_second_fd_in_x1_outcome() {
        let mut emu = TestEmulator::new();
        let runtime = SyscallRuntimeState::new(0xDEAD, 0, 0x4000_0000, 0x5000_0000, ".".into());
        let invocation = SyscallInvocation {
            num: SYSCALL_PIPE,
            name: default_syscall_name(SYSCALL_PIPE),
            pc: 0x100,
            args: [0, 0, 0, 0, 0, 0],
        };

        let outcome = handle_basic_macos_syscall(
            &mut emu,
            &invocation,
            &TraceMetadata::new(),
            &runtime,
            "test",
        )
        .unwrap();

        assert_eq!(outcome.return_value, 3);
        assert_eq!(outcome.extra_register_writes, vec![("x1", 4)]);
    }
}
