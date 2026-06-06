//! macOS Syscall implementation
//!
//! This module provides syscall number mapping and basic syscall handlers

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}
/// for Compatra's macOS userland emulation.
use crate::macos::imports::{
    notify_synthetic_fd_close, notify_synthetic_fd_read, notify_synthetic_fd_write,
};
use crate::Emulator;
use crate::MacOsError;
use crate::UnicornEmulator;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::time::{SystemTime, UNIX_EPOCH};

//pub mod map;

enum EmulatedFile {
    Host(std::fs::File),
    Urandom,
}

pub const SYSCALL_EXIT: u64 = 0x2000001;
pub const SYSCALL_READ: u64 = 0x2000003;
pub const SYSCALL_WRITE: u64 = 0x2000004;
pub const SYSCALL_OPEN: u64 = 0x2000005;
pub const SYSCALL_CLOSE: u64 = 0x2000006;
pub const SYSCALL_MPROTECT: u64 = 0x2000007;
pub const SYSCALL_MUNMAP: u64 = 0x2000049;
pub const SYSCALL_MMAP: u64 = 0x20000C5;
pub const SYSCALL_LSEEK: u64 = 0x20000C7;
pub const SYSCALL_STAT64: u64 = 0x2000152;
pub const SYSCALL_FSTAT64: u64 = 0x2000153;
pub const SYSCALL_BRK: u64 = 0x2000068;
pub const SYSCALL_GETPID: u64 = 0x2000020;
pub const SYSCALL_SYSCTL: u64 = 0x2000087;
pub const SYSCALL_NANOSLEEP: u64 = 0x20000A2;
pub const SYSCALL_GETUID: u64 = 0x2000017;
pub const SYSCALL_GETGID: u64 = 0x2000018;
pub const SYSCALL_SETUID: u64 = 0x200001A;
pub const SYSCALL_GETEUID: u64 = 0x200001B;
pub const SYSCALL_GETEGID: u64 = 0x200001C;
pub const SYSCALL_GETTID: u64 = 0x2000009;
pub const SYSCALL_KILL: u64 = 0x2000008;
pub const SYSCALL_EXIT_GROUP: u64 = 0x20000A7;
const SYNTHETIC_IMPORT_FD_BASE: i32 = 0x1_0000;

pub struct SyscallContext {
    pub syscall_number: u64,
    pub args: [u64; 6],
}

impl SyscallContext {
    pub fn arg(&self, n: usize) -> u64 {
        if n < 6 {
            self.args[n]
        } else {
            0
        }
    }
}

fn syscall_name(num: u64) -> &'static str {
    match num {
        SYSCALL_EXIT => "exit",
        SYSCALL_EXIT_GROUP => "exit_group",
        SYSCALL_READ => "read",
        SYSCALL_WRITE => "write",
        SYSCALL_OPEN => "open",
        SYSCALL_CLOSE => "close",
        SYSCALL_MPROTECT => "mprotect",
        SYSCALL_MUNMAP => "munmap",
        SYSCALL_MMAP => "mmap",
        SYSCALL_LSEEK => "lseek",
        SYSCALL_STAT64 => "stat64",
        SYSCALL_FSTAT64 => "fstat64",
        SYSCALL_BRK => "brk",
        SYSCALL_GETPID => "getpid",
        SYSCALL_GETUID => "getuid",
        SYSCALL_GETGID => "getgid",
        SYSCALL_SETUID => "setuid",
        SYSCALL_GETEUID => "geteuid",
        SYSCALL_GETEGID => "getegid",
        SYSCALL_GETTID => "gettid",
        SYSCALL_KILL => "kill",
        SYSCALL_SYSCTL => "sysctl",
        SYSCALL_NANOSLEEP => "nanosleep",
        _ => "unknown",
    }
}

fn normalize_syscall_number(arch: crate::macos::ArchType, num: u64) -> u64 {
    // Some ARM/ARM64 samples use compact BSD numbers (e.g. 4 for write)
    // instead of class-encoded xnu values (0x2000004).
    if matches!(arch, crate::macos::ArchType::Arm64) && num > 0 && num < 0x2000000 {
        0x2000000 | num
    } else {
        num
    }
}

fn stop_emulation_if_possible(emu: &mut dyn Emulator) {
    if let Some(uc) = emu.as_any_mut().downcast_mut::<UnicornEmulator>() {
        let _ = uc.stop_emulation();
    }
}

fn map_region_if_unicorn(emu: &mut dyn Emulator, addr: u64, size: u64) {
    if let Some(uc) = emu.as_any_mut().downcast_mut::<UnicornEmulator>() {
        let _ = uc.map_writable_code_memory(addr, size);
    }
}

fn read_cstring(emu: &mut dyn Emulator, addr: u64, max_len: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..max_len {
        let b = emu.read_memory(addr + i as u64, 1).ok()?;
        if b.is_empty() || b[0] == 0 {
            break;
        }
        out.push(b[0]);
    }
    Some(String::from_utf8_lossy(&out).to_string())
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

const DARWIN_PAGE_SIZE: u64 = 0x4000;

fn synthetic_clock_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn read_u32(emu: &mut dyn Emulator, addr: u64) -> Option<u32> {
    let data = emu.read_memory(addr, 4).ok()?;
    let bytes: [u8; 4] = data.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(emu: &mut dyn Emulator, addr: u64) -> Option<u64> {
    let data = emu.read_memory(addr, 8).ok()?;
    let bytes: [u8; 8] = data.as_slice().try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn read_timespec_duration_ns(emu: &mut dyn Emulator, addr: u64) -> u64 {
    if addr == 0 {
        return 0;
    }
    let secs = read_u64(emu, addr).unwrap_or(0);
    let nanos = read_u64(emu, addr + 8).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

fn write_sysctl_scalar(emu: &mut dyn Emulator, oldp: u64, oldlenp: u64, value: u64) -> i64 {
    if oldlenp != 0 {
        let _ = emu.write_memory(oldlenp, &(8u64).to_le_bytes());
    }
    if oldp != 0 {
        let _ = emu.write_memory(oldp, &value.to_le_bytes());
    }
    0
}

fn emulate_sysctl(
    emu: &mut dyn Emulator,
    name_ptr: u64,
    namelen: u64,
    oldp: u64,
    oldlenp: u64,
) -> i64 {
    const CTL_HW: u32 = 6;
    const HW_PAGESIZE: u32 = 7;

    let mib0 = read_u32(emu, name_ptr).unwrap_or(0);
    let mib1 = if namelen >= 2 {
        read_u32(emu, name_ptr + 4).unwrap_or(0)
    } else {
        0
    };

    match (mib0, mib1) {
        (CTL_HW, HW_PAGESIZE) => write_sysctl_scalar(emu, oldp, oldlenp, DARWIN_PAGE_SIZE),
        _ => 0,
    }
}

fn write_fake_stat(emu: &mut dyn Emulator, buf: u64, size: u64) {
    // Minimal Darwin-like struct stat payload.
    // Most callers in our emulation path only care about successful return.
    const STAT_SIZE: usize = 128;
    if buf == 0 {
        return;
    }
    let mut out = vec![0u8; STAT_SIZE];
    // Store file size at one likely 64-bit location used by many ABIs.
    // Keeping this best-effort while preserving broad compatibility.
    out[48..56].copy_from_slice(&size.to_le_bytes());
    let _ = emu.write_memory(buf, &out);
}

fn is_synthetic_import_fd(fd: i32) -> bool {
    fd >= SYNTHETIC_IMPORT_FD_BASE
}

pub fn create_default_syscall_handler(
) -> Box<dyn FnMut(&mut dyn Emulator) -> Result<i64, MacOsError> + Send + 'static> {
    let mut next_mmap_base: u64 = 0x4000_0000;
    let mut current_brk: u64 = 0x5000_0000;
    let mut next_fd: i32 = 3;
    let mut files: HashMap<i32, EmulatedFile> = HashMap::new();
    let mut synthetic_time_ns: u64 = synthetic_clock_seed();

    Box::new(move |emu: &mut dyn Emulator| -> Result<i64, MacOsError> {
        let arch = emu.arch_type();

        let raw_syscall_number = emu.read_reg("x16")?;
        let args = [
            emu.read_reg("x0")?,
            emu.read_reg("x1")?,
            emu.read_reg("x2")?,
            emu.read_reg("x3")?,
            emu.read_reg("x4")?,
            emu.read_reg("x5")?,
        ];
        let syscall_number = normalize_syscall_number(arch, raw_syscall_number);
        let arch_name = "arm64";
        let name = syscall_name(syscall_number);
        println!(
            "[SYSCALL][{}] 0x{:x} (raw=0x{:x}) {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            arch_name,
            syscall_number,
            raw_syscall_number,
            name,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5]
        );
        let result = match syscall_number {
            SYSCALL_EXIT => {
                let exit_code = args[0] as i32;
                println!("[SYSCALL] process requested exit({})", exit_code);
                stop_emulation_if_possible(emu);
                0
            }
            SYSCALL_EXIT_GROUP => {
                let exit_code = args[0] as i32;
                println!("[SYSCALL] process requested exit_group({})", exit_code);
                stop_emulation_if_possible(emu);
                0
            }
            SYSCALL_READ => {
                let fd = args[0] as i32;
                let buf_ptr = args[1];
                let count = args[2] as usize;
                if fd == 0 {
                    0
                } else if is_synthetic_import_fd(fd) {
                    notify_synthetic_fd_read(fd as u64, count as u64);
                    if count != 0 {
                        let _ = emu.write_memory(buf_ptr, &vec![0u8; count]);
                    }
                    0
                } else if let Some(file) = files.get_mut(&fd) {
                    match file {
                        EmulatedFile::Host(file) => {
                            let mut buf = vec![0u8; count];
                            match file.read(&mut buf) {
                                Ok(n) => {
                                    let _ = emu.write_memory(buf_ptr, &buf[..n]);
                                    n as i64
                                }
                                Err(_) => -1,
                            }
                        }
                        EmulatedFile::Urandom => {
                            let mut buf = vec![0u8; count];
                            let mut state =
                                buf_ptr ^ ((count as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15_u64;
                            for byte in &mut buf {
                                state ^= state >> 12;
                                state ^= state << 25;
                                state ^= state >> 27;
                                *byte = state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8;
                            }
                            let _ = emu.write_memory(buf_ptr, &buf);
                            count as i64
                        }
                    }
                } else {
                    -1
                }
            }
            SYSCALL_WRITE => {
                let fd = args[0] as i32;
                let buf_ptr = args[1];
                let count = args[2] as usize;
                if fd == 1 || fd == 2 {
                    if let Ok(data) = emu.read_memory(buf_ptr, count) {
                        let output = String::from_utf8_lossy(&data);
                        print!("{}", output);
                    }
                    count as i64
                } else if is_synthetic_import_fd(fd) {
                    notify_synthetic_fd_write(fd as u64, count as u64);
                    count as i64
                } else {
                    count as i64
                }
            }
            SYSCALL_OPEN => {
                let path_ptr = args[0];
                let flags = args[1] as i32;
                let _mode = args[2] as u32;
                match read_cstring(emu, path_ptr, 4096) {
                    Some(path) => {
                        println!("[SYSCALL][{}] open path=\"{}\"", arch_name, path);
                        if path == "/dev/urandom" {
                            let fd = next_fd;
                            next_fd += 1;
                            files.insert(fd, EmulatedFile::Urandom);
                            println!(
                                "[SYSCALL][{}] open mapped to synthetic urandom fd={}",
                                arch_name, fd
                            );
                            fd as i64
                        } else {
                            // macOS/BSD compatibility (subset): 0=RDONLY, 1=WRONLY, 2=RDWR
                            let accmode = flags & 0x3;
                            let mut opts = OpenOptions::new();
                            match accmode {
                                0 => {
                                    opts.read(true);
                                }
                                1 => {
                                    opts.write(true);
                                }
                                _ => {
                                    opts.read(true).write(true);
                                }
                            }
                            if (flags & 0x0200) != 0 {
                                opts.create(true);
                            }
                            if (flags & 0x0400) != 0 {
                                opts.truncate(true);
                            }
                            if (flags & 0x0008) != 0 {
                                opts.append(true);
                            }

                            match opts.open(&path) {
                                Ok(file) => {
                                    let fd = next_fd;
                                    next_fd += 1;
                                    files.insert(fd, EmulatedFile::Host(file));
                                    fd as i64
                                }
                                Err(err) => {
                                    println!("[SYSCALL][{}] open failed: {}", arch_name, err);
                                    -1
                                }
                            }
                        }
                    }
                    None => -1,
                }
            }
            SYSCALL_CLOSE => {
                let fd = args[0] as i32;
                if (0..=2).contains(&fd) {
                    0
                } else if is_synthetic_import_fd(fd) {
                    notify_synthetic_fd_close(fd as u64);
                    0
                } else if files.remove(&fd).is_some() {
                    0
                } else {
                    -1
                }
            }
            SYSCALL_MMAP => {
                let req_addr = args[0];
                let len = args[1].max(1);
                let fd = args[4] as i32;
                let file_off = args[5];

                let map_size = align_up(len, 0x1000);
                let addr = if req_addr != 0 {
                    align_up(req_addr, 0x1000)
                } else {
                    let a = align_up(next_mmap_base, 0x1000);
                    next_mmap_base = a + map_size;
                    a
                };

                map_region_if_unicorn(emu, addr, map_size);

                if fd >= 3 {
                    if is_synthetic_import_fd(fd) {
                        return Ok(addr as i64);
                    }
                    if let Some(file) = files.get_mut(&fd) {
                        if let EmulatedFile::Host(file) = file {
                            if file.seek(SeekFrom::Start(file_off)).is_ok() {
                                let mut buf = vec![0u8; len as usize];
                                if let Ok(n) = file.read(&mut buf) {
                                    let _ = emu.write_memory(addr, &buf[..n]);
                                }
                            }
                        }
                    }
                }

                addr as i64
            }
            SYSCALL_MUNMAP => 0,
            SYSCALL_LSEEK => {
                let fd = args[0] as i32;
                let offset = args[1] as i64;
                let whence = args[2] as i32;
                if whence != 0 && whence != 1 && whence != 2 {
                    -1
                } else {
                    let seek_from = match whence {
                        0 => SeekFrom::Start(offset.max(0) as u64),
                        1 => SeekFrom::Current(offset),
                        _ => SeekFrom::End(offset),
                    };

                    if (0..=2).contains(&fd) || is_synthetic_import_fd(fd) {
                        0
                    } else if let Some(file) = files.get_mut(&fd) {
                        match file {
                            EmulatedFile::Host(file) => match file.seek(seek_from) {
                                Ok(pos) => pos as i64,
                                Err(_) => -1,
                            },
                            EmulatedFile::Urandom => 0,
                        }
                    } else {
                        -1
                    }
                }
            }
            SYSCALL_STAT64 => {
                let path_ptr = args[0];
                let buf = args[1];
                match read_cstring(emu, path_ptr, 4096) {
                    Some(path) => match std::fs::metadata(&path) {
                        Ok(meta) => {
                            write_fake_stat(emu, buf, meta.len());
                            0
                        }
                        Err(_) => -1,
                    },
                    None => -1,
                }
            }
            SYSCALL_FSTAT64 => {
                let fd = args[0] as i32;
                let buf = args[1];
                if (0..=2).contains(&fd) {
                    write_fake_stat(emu, buf, 0);
                    0
                } else if is_synthetic_import_fd(fd) {
                    write_fake_stat(emu, buf, 0);
                    0
                } else if let Some(file) = files.get_mut(&fd) {
                    match file {
                        EmulatedFile::Host(file) => match file.metadata() {
                            Ok(meta) => {
                                write_fake_stat(emu, buf, meta.len());
                                0
                            }
                            Err(_) => -1,
                        },
                        EmulatedFile::Urandom => {
                            write_fake_stat(emu, buf, 0);
                            0
                        }
                    }
                } else {
                    -1
                }
            }
            SYSCALL_BRK => {
                let req = args[0];
                if req == 0 {
                    current_brk as i64
                } else {
                    if req > current_brk {
                        let old_aligned = align_up(current_brk, 0x1000);
                        let new_aligned = align_up(req, 0x1000);
                        if new_aligned > old_aligned {
                            map_region_if_unicorn(emu, old_aligned, new_aligned - old_aligned);
                        }
                    }
                    current_brk = req;
                    current_brk as i64
                }
            }
            SYSCALL_GETPID => 1,
            SYSCALL_SYSCTL => emulate_sysctl(emu, args[0], args[1], args[2], args[3]),
            SYSCALL_NANOSLEEP => {
                let req_ptr = args[0];
                let rem_ptr = args[1];
                let sleep_ns = read_timespec_duration_ns(emu, req_ptr);
                synthetic_time_ns = synthetic_time_ns.saturating_add(sleep_ns.max(1));
                if rem_ptr != 0 {
                    let _ = emu.write_memory(rem_ptr, &[0u8; 16]);
                }
                0
            }
            SYSCALL_GETUID => 0,
            SYSCALL_GETGID => 0,
            SYSCALL_GETEUID => 0,
            SYSCALL_GETEGID => 0,
            _ => 0,
        };

        // Unicorn resumes from the instruction after `svc` on arm64.
        // Advancing PC here skips the stub's trailing `ret` and strands
        // execution inside the synthetic import page instead of returning
        // to the original caller.
        emu.write_reg("x0", result as u64)?;
        println!(
            "[SYSCALL][{}] 0x{:x} (raw=0x{:x}) {} -> {}",
            arch_name, syscall_number, raw_syscall_number, name, result
        );

        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::{ArchType, LogLevel};
    use std::any::Any;
    use std::collections::HashMap;

    struct TestEmulator {
        arch: ArchType,
        regs: HashMap<String, u64>,
    }

    impl TestEmulator {
        fn new(arch: ArchType) -> Self {
            Self {
                arch,
                regs: HashMap::new(),
            }
        }
    }

    impl Emulator for TestEmulator {
        fn read_memory(&self, _addr: u64, size: usize) -> Result<Vec<u8>, MacOsError> {
            Ok(vec![0; size])
        }

        fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), MacOsError> {
            Ok(())
        }

        fn read_reg(&self, reg: &str) -> Result<u64, MacOsError> {
            Ok(*self.regs.get(reg).unwrap_or(&0))
        }

        fn write_reg(&mut self, reg: &str, value: u64) -> Result<(), MacOsError> {
            self.regs.insert(reg.to_string(), value);
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
            self.arch
        }

        fn log(&mut self, _level: LogLevel, _msg: &str) {}

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    #[test]
    fn test_normalize_arm64_compact_syscall_number() {
        assert_eq!(normalize_syscall_number(ArchType::Arm64, 4), SYSCALL_WRITE);
        assert_eq!(normalize_syscall_number(ArchType::Arm64, 1), SYSCALL_EXIT);
    }

    #[test]
    fn test_arm64_syscall_handler_keeps_pc_for_stub_ret() {
        let mut emu = TestEmulator::new(ArchType::Arm64);
        emu.write_reg("x16", 4).unwrap();
        emu.write_reg("x0", 1).unwrap(); // fd
        emu.write_reg("x1", 0x1000).unwrap();
        emu.write_reg("x2", 3).unwrap(); // count
        emu.write_reg("pc", 0x3000).unwrap();

        let mut handler = create_default_syscall_handler();
        let ret = handler(&mut emu).unwrap();

        assert_eq!(ret, 3);
        assert_eq!(emu.read_reg("x0").unwrap(), 3);
        assert_eq!(emu.read_reg("pc").unwrap(), 0x3000);
    }

    #[test]
    fn test_emulate_sysctl_hw_pagesize() {
        struct MemoryEmulator {
            regs: HashMap<String, u64>,
            memory: HashMap<u64, u8>,
        }

        impl MemoryEmulator {
            fn new() -> Self {
                Self {
                    regs: HashMap::new(),
                    memory: HashMap::new(),
                }
            }
        }

        impl Emulator for MemoryEmulator {
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

            fn read_reg(&self, reg: &str) -> Result<u64, MacOsError> {
                Ok(*self.regs.get(reg).unwrap_or(&0))
            }

            fn write_reg(&mut self, reg: &str, value: u64) -> Result<(), MacOsError> {
                self.regs.insert(reg.to_string(), value);
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

        let mut emu = MemoryEmulator::new();
        emu.write_memory(0x1000, &6u32.to_le_bytes()).unwrap();
        emu.write_memory(0x1004, &7u32.to_le_bytes()).unwrap();

        let ret = emulate_sysctl(&mut emu, 0x1000, 2, 0x2000, 0x3000);
        assert_eq!(ret, 0);

        let oldp = emu.read_memory(0x2000, 8).unwrap();
        let oldlenp = emu.read_memory(0x3000, 8).unwrap();
        assert_eq!(
            u64::from_le_bytes(oldp.try_into().unwrap()),
            DARWIN_PAGE_SIZE
        );
        assert_eq!(u64::from_le_bytes(oldlenp.try_into().unwrap()), 8);
    }
}
