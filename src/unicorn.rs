macro_rules! eprintln {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::eprintln!($($arg)*);
        }
    };
}

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::any::Any;
use std::sync::{Arc, Mutex};

use unicorn_engine::{unicorn_const::HookType, Arch, MemType, Mode, Prot, RegisterARM64, Unicorn};

use crate::macos::arm64_runner_support::{
    arm64_memory_event, arm64_thread_event, emit_arm64_event,
};
use crate::macos::os::{ArchType, Emulator as EmulatorTrait, LogLevel, MacOsError};
use crate::SharedTraceBus;

#[derive(Clone, Copy)]
struct LazyMapRegion {
    start: u64,
    end: u64,
    prot: Prot,
}

fn format_memory_value(value: i64, size: usize) -> String {
    if size == 0 {
        return "[]".to_string();
    }
    let bytes = value.to_le_bytes();
    let take = size.min(bytes.len());
    let rendered = bytes[..take]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    format!("[{}]", rendered)
}

pub struct UnicornEmulator {
    uc: Unicorn<'static, ()>,
    arch: ArchType,
    automap_low_page: bool,
    lazy_map_regions: Arc<Mutex<Vec<LazyMapRegion>>>,
    lazy_map_hook_installed: bool,
    syscall_handler:
        Option<Box<dyn FnMut(&mut dyn EmulatorTrait) -> Result<i64, MacOsError> + Send + 'static>>,
    syscall_hooks_installed: bool,
}

impl UnicornEmulator {
    pub fn new(arch: ArchType) -> Result<Self, MacOsError> {
        let uc = Unicorn::new(Arch::ARM64, Mode::ARM)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to create unicorn: {}", e)))?;

        Ok(Self {
            uc,
            arch,
            automap_low_page: false,
            lazy_map_regions: Arc::new(Mutex::new(Vec::new())),
            lazy_map_hook_installed: false,
            syscall_handler: None,
            syscall_hooks_installed: false,
        })
    }

    pub fn new_arm64() -> Result<Self, MacOsError> {
        Self::new(ArchType::Arm64)
    }

    pub fn map_code_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE | Prot::EXEC)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn map_data_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn reserve_lazy_data_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.reserve_lazy_memory(addr, size, Prot::READ | Prot::WRITE)
    }

    pub fn reserve_lazy_memory(
        &mut self,
        addr: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MacOsError> {
        self.ensure_lazy_map_hook()?;
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        let mut regions = self
            .lazy_map_regions
            .lock()
            .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
        regions.push(LazyMapRegion { start, end, prot });
        Ok(())
    }

    pub fn unmap_lazy_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        {
            let mut regions = self
                .lazy_map_regions
                .lock()
                .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
            let mut next = Vec::with_capacity(regions.len());
            for region in regions.iter().copied() {
                if end <= region.start || start >= region.end {
                    next.push(region);
                    continue;
                }
                if start > region.start {
                    next.push(LazyMapRegion {
                        start: region.start,
                        end: start,
                        prot: region.prot,
                    });
                }
                if end < region.end {
                    next.push(LazyMapRegion {
                        start: end,
                        end: region.end,
                        prot: region.prot,
                    });
                }
            }
            *regions = next;
        }

        let mut cur = start;
        while cur < end {
            let _ = self.uc.mem_unmap(cur, 0x1000);
            cur = cur.saturating_add(0x1000);
        }
        Ok(())
    }

    pub fn protect_lazy_memory(
        &mut self,
        addr: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MacOsError> {
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        {
            let mut regions = self
                .lazy_map_regions
                .lock()
                .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
            let mut next = Vec::with_capacity(regions.len() + 2);
            let mut covered = false;
            for region in regions.iter().copied() {
                if end <= region.start || start >= region.end {
                    next.push(region);
                    continue;
                }
                if start > region.start {
                    next.push(LazyMapRegion {
                        start: region.start,
                        end: start,
                        prot: region.prot,
                    });
                }
                next.push(LazyMapRegion {
                    start: start.max(region.start),
                    end: end.min(region.end),
                    prot,
                });
                if end < region.end {
                    next.push(LazyMapRegion {
                        start: end,
                        end: region.end,
                        prot: region.prot,
                    });
                }
                covered = true;
            }
            if !covered {
                next.push(LazyMapRegion { start, end, prot });
            }
            *regions = next;
        }

        let mut cur = start;
        while cur < end {
            let _ = self.uc.mem_protect(cur, 0x1000, prot);
            cur = cur.saturating_add(0x1000);
        }
        Ok(())
    }

    pub fn map_writable_code_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE | Prot::EXEC)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn add_code_hook<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<(), MacOsError>
    where
        F: Fn(&mut UnicornEmulator, u64, u32) + Send + 'static,
    {
        let self_ptr: *mut UnicornEmulator = self as *mut UnicornEmulator;
        self.uc
            .add_code_hook(begin, end, move |_uc, addr, size| unsafe {
                callback(&mut *self_ptr, addr, size);
            })
            .map(|_| ())
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add code hook: {}", e)))
    }

    fn ensure_syscall_hooks(&mut self) -> Result<(), MacOsError> {
        if !(self.syscall_handler.is_some() && !self.syscall_hooks_installed) {
            return Ok(());
        }

        let self_ptr: *mut UnicornEmulator = self as *mut UnicornEmulator;
        match self.arch {
            ArchType::Arm64 => {
                self.uc
                    .add_intr_hook(move |_uc, intno| unsafe {
                        // AArch64 SVC triggers interrupt number 2 in Unicorn.
                        if intno != 2 {
                            return;
                        }
                        let emu = &mut *self_ptr;
                        let mut handler_opt = emu.syscall_handler.take();
                        if let Some(mut handler) = handler_opt.take() {
                            let _ = handler(emu);
                            emu.syscall_handler = Some(handler);
                        }
                    })
                    .map_err(|e| {
                        MacOsError::Unicorn(format!("Failed to add ARM64 interrupt hook: {}", e))
                    })?;
            }
        }
        self.syscall_hooks_installed = true;
        Ok(())
    }

    fn ensure_lazy_map_hook(&mut self) -> Result<(), MacOsError> {
        if self.lazy_map_hook_installed {
            return Ok(());
        }

        let lazy_map_regions = self.lazy_map_regions.clone();
        self.uc
            .add_mem_hook(
                HookType::MEM_UNMAPPED,
                1,
                0,
                move |uc, _mem_type, addr, size, _value| {
                    let page_start = addr & !0xFFF;
                    let page_end =
                        (addr.saturating_add(size as u64).saturating_add(0xFFF)) & !0xFFF;
                    let region = {
                        let regions = match lazy_map_regions.lock() {
                            Ok(guard) => guard,
                            Err(_) => return false,
                        };
                        regions
                            .iter()
                            .find(|region| addr >= region.start && addr < region.end)
                            .copied()
                    };
                    let Some(region) = region else {
                        return false;
                    };

                    let map_start = page_start.max(region.start);
                    let map_end = page_end.min(region.end);
                    if map_start >= map_end {
                        return false;
                    }

                    let mut cur = map_start;
                    while cur < map_end {
                        match uc.mem_map(cur, 0x1000, region.prot) {
                            Ok(()) => {}
                            Err(_) => {
                                if uc.mem_read_as_vec(cur, 1).is_err() {
                                    return false;
                                }
                            }
                        }
                        cur = cur.saturating_add(0x1000);
                    }
                    true
                },
            )
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add lazy map hook: {}", e)))?;
        self.lazy_map_hook_installed = true;
        Ok(())
    }

    pub fn run_with_limits(
        &mut self,
        begin: u64,
        end: Option<u64>,
        timeout_usecs: u64,
        instruction_count: usize,
    ) -> Result<(), MacOsError> {
        self.ensure_syscall_hooks()?;

        self.uc
            .emu_start(
                begin,
                end.unwrap_or(u64::MAX),
                timeout_usecs,
                instruction_count,
            )
            .map_err(|e| MacOsError::Unicorn(format!("Emulation failed: {}", e)))
    }

    pub fn stop_emulation(&mut self) -> Result<(), MacOsError> {
        self.uc
            .emu_stop()
            .map_err(|e| MacOsError::Unicorn(format!("Failed to stop emulation: {}", e)))
    }

    pub fn install_unmapped_memory_debug_hook(
        &mut self,
        trace_bus: &Option<SharedTraceBus>,
    ) -> Result<(), MacOsError> {
        let arch = self.arch;
        let automap_low_page = self.automap_low_page;
        let lazy_map_regions = self.lazy_map_regions.clone();
        let trace_bus_for_memhook = trace_bus.clone();
        self.uc
            .add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, move |uc, mem_type, addr, size, value| {
                let (pc_reg, sp_reg): (i32, i32) = match arch {
                    ArchType::Arm64 => (RegisterARM64::PC as i32, RegisterARM64::SP as i32),
                };
                let pc = uc.reg_read(pc_reg).unwrap_or(0);
                let sp = uc.reg_read(sp_reg).unwrap_or(0);
                let code = uc.mem_read_as_vec(pc, 8).unwrap_or_default();
                let value_bytes = format_memory_value(value, size as usize);
                let is_lazy_reserved_touch = {
                    let regions = match lazy_map_regions.lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            eprintln!("[UNMAPPED] failed to lock lazy map regions");
                            return false;
                        }
                    };
                    regions.iter().any(|region| addr >= region.start && addr < region.end)
                };
                let is_go_post_exit_tail = matches!(arch, ArchType::Arm64)
                    && matches!(mem_type, MemType::WRITE_UNMAPPED)
                    && addr == 0x3ea;
                if is_go_post_exit_tail {
                    eprintln!(
                        "[UNMAPPED][{:?}] expected Go post-exit tail addr=0x{:x} size={} value=0x{:x} bytes={} pc=0x{:x} sp=0x{:x} code={:02x?}",
                        arch, addr, size, value as u64, value_bytes, pc, sp, code
                    );
                } else if is_lazy_reserved_touch {
                let event = arm64_memory_event("Lazymap_write")
                    .arg("Addr", format!("0x{:X}", addr))
                    .arg("Size", format!("0x{:X}", size))
                    .arg("Memtype", format!("{:?}", mem_type)) 
                    .arg("Value", format!("0x{:X}", value))
                                        .arg("Bytes", format!("{}", value_bytes))

                    .arg("pc", format!("0x{:X}", pc))
                    .arg("Code", format!("{:02x?}", code));
                emit_arm64_event(&trace_bus_for_memhook, event);
                } else {
                    eprintln!(
                        "[UNMAPPED][{:?}] kind={:?} addr=0x{:x} size={} value=0x{:x} bytes={} pc=0x{:x} sp=0x{:x} code={:02x?}",
                        arch, mem_type, addr, size, value as u64, value_bytes, pc, sp, code
                    );
                }
                if automap_low_page && addr < 0x1000 {
                    let _ = uc.mem_map(0, 0x1000, Prot::READ | Prot::WRITE);
                    return true;
                }
                false
            })
            .map(|_| ())
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add unmapped memory hook: {}", e)))
    }

    pub fn set_automap_low_page(&mut self, enabled: bool) {
        self.automap_low_page = enabled;
    }
}

impl EmulatorTrait for UnicornEmulator {
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, MacOsError> {
        let mut data = vec![0u8; size];
        self.uc
            .mem_read(addr, &mut data)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to read memory: {}", e)))?;
        Ok(data)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MacOsError> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to write memory: {}", e)))
    }

    fn read_reg(&self, reg: &str) -> Result<u64, MacOsError> {
        match self.arch {
            ArchType::Arm64 => {
                let rid = match reg {
                    "x0" => RegisterARM64::X0,
                    "x1" => RegisterARM64::X1,
                    "x2" => RegisterARM64::X2,
                    "x3" => RegisterARM64::X3,
                    "x4" => RegisterARM64::X4,
                    "x5" => RegisterARM64::X5,
                    "x6" => RegisterARM64::X6,
                    "x7" => RegisterARM64::X7,
                    "x8" => RegisterARM64::X8,
                    "x9" => RegisterARM64::X9,
                    "x10" => RegisterARM64::X10,
                    "x11" => RegisterARM64::X11,
                    "x12" => RegisterARM64::X12,
                    "x13" => RegisterARM64::X13,
                    "x14" => RegisterARM64::X14,
                    "x15" => RegisterARM64::X15,
                    "x16" => RegisterARM64::X16,
                    "x17" => RegisterARM64::X17,
                    "x18" => RegisterARM64::X18,
                    "x19" => RegisterARM64::X19,
                    "x20" => RegisterARM64::X20,
                    "x21" => RegisterARM64::X21,
                    "x22" => RegisterARM64::X22,
                    "x23" => RegisterARM64::X23,
                    "x24" => RegisterARM64::X24,
                    "x25" => RegisterARM64::X25,
                    "x26" => RegisterARM64::X26,
                    "x27" => RegisterARM64::X27,
                    "x28" => RegisterARM64::X28,
                    "tpidr_el0" => RegisterARM64::TPIDR_EL0,
                    "tpidrro_el0" => RegisterARM64::TPIDRRO_EL0,
                    "fp" => RegisterARM64::FP,
                    "lr" => RegisterARM64::LR,
                    "sp" => RegisterARM64::SP,
                    "pc" => RegisterARM64::PC,
                    _ => {
                        return Err(MacOsError::InvalidArgument(format!(
                            "Unknown register: {}",
                            reg
                        )))
                    }
                };
                self.uc
                    .reg_read(rid)
                    .map_err(|e| MacOsError::Unicorn(format!("Failed to read register: {}", e)))
            }
        }
    }

    fn write_reg(&mut self, reg: &str, value: u64) -> Result<(), MacOsError> {
        match self.arch {
            ArchType::Arm64 => {
                let rid = match reg {
                    "x0" => RegisterARM64::X0,
                    "x1" => RegisterARM64::X1,
                    "x2" => RegisterARM64::X2,
                    "x3" => RegisterARM64::X3,
                    "x4" => RegisterARM64::X4,
                    "x5" => RegisterARM64::X5,
                    "x6" => RegisterARM64::X6,
                    "x7" => RegisterARM64::X7,
                    "x8" => RegisterARM64::X8,
                    "x9" => RegisterARM64::X9,
                    "x10" => RegisterARM64::X10,
                    "x11" => RegisterARM64::X11,
                    "x12" => RegisterARM64::X12,
                    "x13" => RegisterARM64::X13,
                    "x14" => RegisterARM64::X14,
                    "x15" => RegisterARM64::X15,
                    "x16" => RegisterARM64::X16,
                    "x17" => RegisterARM64::X17,
                    "x18" => RegisterARM64::X18,
                    "x19" => RegisterARM64::X19,
                    "x20" => RegisterARM64::X20,
                    "x21" => RegisterARM64::X21,
                    "x22" => RegisterARM64::X22,
                    "x23" => RegisterARM64::X23,
                    "x24" => RegisterARM64::X24,
                    "x25" => RegisterARM64::X25,
                    "x26" => RegisterARM64::X26,
                    "x27" => RegisterARM64::X27,
                    "x28" => RegisterARM64::X28,
                    "tpidr_el0" => RegisterARM64::TPIDR_EL0,
                    "tpidrro_el0" => RegisterARM64::TPIDRRO_EL0,
                    "fp" => RegisterARM64::FP,
                    "lr" => RegisterARM64::LR,
                    "sp" => RegisterARM64::SP,
                    "pc" => RegisterARM64::PC,
                    _ => {
                        return Err(MacOsError::InvalidArgument(format!(
                            "Unknown register: {}",
                            reg
                        )))
                    }
                };
                self.uc
                    .reg_write(rid, value)
                    .map_err(|e| MacOsError::Unicorn(format!("Failed to write register: {}", e)))
            }
        }
    }

    fn stack_push(&mut self, value: u64) -> Result<(), MacOsError> {
        let sp = self.read_reg("sp")?;
        let new_sp = sp - 8;
        self.write_memory(new_sp, &value.to_le_bytes())?;
        self.write_reg("sp", new_sp)
    }

    fn stack_pop(&mut self) -> Result<u64, MacOsError> {
        let sp = self.read_reg("sp")?;
        let data = self.read_memory(sp, 8)?;
        let value = u64::from_le_bytes(data[..8].try_into().unwrap());
        self.write_reg("sp", sp + 8)?;
        Ok(value)
    }

    fn stack_read(&self, offset: i64) -> Result<u64, MacOsError> {
        let sp = self.read_reg("sp")?;
        let addr = (sp as i64 + offset) as u64;
        let data = self.read_memory(addr, 8)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    fn hook_syscall(
        &mut self,
        handler: Box<dyn FnMut(&mut dyn EmulatorTrait) -> Result<i64, MacOsError> + Send>,
    ) {
        self.syscall_handler = Some(handler);
    }

    fn run(&mut self, begin: u64, end: Option<u64>) -> Result<(), MacOsError> {
        self.run_with_limits(begin, end, 0, 0)
    }

    fn arch_type(&self) -> ArchType {
        self.arch
    }

    fn log(&mut self, level: LogLevel, msg: &str) {
        match level {
            LogLevel::Debug => println!("[DEBUG] {}", msg),
            LogLevel::Info => println!("[INFO] {}", msg),
            LogLevel::Warn => println!("[WARN] {}", msg),
            LogLevel::Error => println!("[ERROR] {}", msg),
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
