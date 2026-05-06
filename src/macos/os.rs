//! macOS OS abstraction layer for Machina
//!
//! This module provides the core OS layer abstraction for emulating macOS binaries
//! and kernel extensions (KEXTs). It includes memory management, syscall handling,
//! event management, and MAC policy enforcement.

use std::any::Any;
use std::collections::HashMap;

use crate::macos::events::MacOsEventManager;
use crate::macos::policy::MacOsPolicyManager;
use crate::macos::structs::{KmodInfo, MacPolicyList};

/// Architecture type for the emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchType {
    /// 64-bit ARM architecture
    Arm64,
}

/// Logging level for emulator output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Error types for macOS emulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsError {
    /// Unicorn engine error
    Unicorn(String),
    /// Memory access error
    Memory(String),
    /// Syscall not implemented
    SyscallNotImplemented(u64),
    /// Invalid argument
    InvalidArgument(String),
    /// Loader error
    LoaderError(String),
}

impl std::fmt::Display for MacOsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacOsError::Unicorn(s) => write!(f, "Unicorn error: {}", s),
            MacOsError::Memory(s) => write!(f, "Memory error: {}", s),
            MacOsError::SyscallNotImplemented(n) => write!(f, "Syscall not implemented: {}", n),
            MacOsError::InvalidArgument(s) => write!(f, "Invalid argument: {}", s),
            MacOsError::LoaderError(s) => write!(f, "Loader error: {}", s),
        }
    }
}

impl std::error::Error for MacOsError {}

impl From<std::io::Error> for MacOsError {
    fn from(err: std::io::Error) -> Self {
        MacOsError::LoaderError(err.to_string())
    }
}

/// Core emulator trait that abstracts the underlying CPU emulation engine.
///
/// This trait must be implemented by the underlying emulation engine (e.g., Unicorn)
/// to provide a consistent interface for the OS layer.
pub trait Emulator: Any {
    /// Read memory from the specified address.
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, MacOsError>;

    /// Write memory to the specified address.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MacOsError>;

    /// Read a register value.
    fn read_reg(&self, reg: &str) -> Result<u64, MacOsError>;

    /// Write a register value.
    fn write_reg(&mut self, reg: &str, value: u64) -> Result<(), MacOsError>;

    /// Push a value onto the stack.
    fn stack_push(&mut self, value: u64) -> Result<(), MacOsError>;

    /// Pop a value from the stack.
    fn stack_pop(&mut self) -> Result<u64, MacOsError>;

    /// Read a value from the stack at the given offset.
    fn stack_read(&self, offset: i64) -> Result<u64, MacOsError>;

    /// Install a syscall hook handler.
    fn hook_syscall(
        &mut self,
        handler: Box<dyn FnMut(&mut dyn Emulator) -> Result<i64, MacOsError> + Send>,
    );

    /// Run emulation from begin address until end (optional).
    fn run(&mut self, begin: u64, end: Option<u64>) -> Result<(), MacOsError>;

    /// Get the architecture type.
    fn arch_type(&self) -> ArchType;

    /// Log a message at the specified level.
    fn log(&mut self, level: LogLevel, msg: &str);

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct Heap {
    base: u64,
    current: u64,
    #[allow(dead_code)]
    size: usize,
    allocations: HashMap<u64, usize>,
}

impl Heap {
    pub fn new(base: u64, size: usize) -> Self {
        Self {
            base,
            current: base,
            size,
            allocations: HashMap::new(),
        }
    }

    pub fn alloc(&mut self, size: usize) -> u64 {
        let aligned_size = (size + 0xF) & !0xF;
        let addr = self.current;
        self.current += aligned_size as u64;
        self.allocations.insert(addr, aligned_size);
        addr
    }

    pub fn free(&mut self, addr: u64) {
        if let Some(_size) = self.allocations.remove(&addr) {
            // Simple heap: just track allocations, no coalescing
        }
    }

    pub fn clear(&mut self) {
        self.current = self.base;
        self.allocations.clear();
    }
}

pub struct MacOs {
    pub heap: Heap,
    pub ev_manager: MacOsEventManager,
    pub policy_manager: MacOsPolicyManager,
    pub run_flag: bool,
    pub hook_ret: HashMap<u64, u64>,
    pub saved_rip: Option<u64>,
    pub kext_object: Option<u64>,
    pub mac_policy_list: Option<MacPolicyList>,
    entry_point: Option<u64>,
    exit_point: Option<u64>,
    #[allow(dead_code)]
    timeout: u64,
    #[allow(dead_code)]
    count: u64,
}

impl MacOs {
    pub fn new(_emulator: &mut dyn Emulator, heap_base: u64, heap_size: usize) -> Self {
        let heap = Heap::new(heap_base, heap_size);
        let ev_manager = MacOsEventManager::new();
        let policy_manager = MacOsPolicyManager::new();

        Self {
            heap,
            ev_manager,
            policy_manager,
            run_flag: true,
            hook_ret: HashMap::new(),
            saved_rip: None,
            kext_object: None,
            mac_policy_list: None,
            entry_point: None,
            exit_point: None,
            timeout: 0,
            count: 0,
        }
    }

    pub fn load(&mut self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        match emulator.arch_type() {
            ArchType::Arm64 => {
                emulator.log(
                    LogLevel::Info,
                    "ARM64 macOS: enabling VFP and hooking syscalls",
                );
            }
        }
        Ok(())
    }

    pub fn load_kext(
        &mut self,
        emulator: &mut dyn Emulator,
        kernel_symbols: &HashMap<String, u64>,
        kext_info: &KextLoadInfo,
    ) -> Result<(), MacOsError> {
        self.heap.clear();

        if let Some(&mac_policy_list_addr) = kernel_symbols.get("_mac_policy_list") {
            let policy_addr = self.heap.alloc(std::mem::size_of::<MacPolicyList>());
            let policy_list = MacPolicyList::new(policy_addr);
            emulator.write_memory(mac_policy_list_addr, &policy_addr.to_le_bytes())?;
            self.mac_policy_list = Some(policy_list);
            emulator.log(
                LogLevel::Debug,
                &format!("Setup mac_policy_list at 0x{:x}", policy_addr),
            );
        }

        if let Some(&allproc_addr) = kernel_symbols.get("_allproc") {
            self.ev_manager.set_allproc(allproc_addr);
            self.ev_manager
                .add_process(0, "head", &mut self.heap, emulator)?;
            self.ev_manager
                .add_process(0x1337, "demigod", &mut self.heap, emulator)?;
            self.ev_manager
                .add_process(1, "tail", &mut self.heap, emulator)?;
        }

        if kext_info.io_kit {
            self.load_iokit_driver(emulator, kext_info)?;
        } else {
            self.load_kmod_info(emulator, kext_info)?;
        }

        Ok(())
    }

    fn load_iokit_driver(
        &mut self,
        emulator: &mut dyn Emulator,
        kext_info: &KextLoadInfo,
    ) -> Result<(), MacOsError> {
        emulator.stack_push(0)?;
        self.saved_rip = Some(0xffffff8000a163bd);
        emulator.run(kext_info.kext_alloc, None)?;

        let kext_obj = emulator.read_reg("rax")?;
        self.kext_object = Some(kext_obj);
        emulator.log(
            LogLevel::Debug,
            &format!("Created kext object at 0x{:x}", kext_obj),
        );

        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff8000a16020);
        emulator.run(kext_info.kext_init, None)?;

        if emulator.read_reg("rax")? == 0 {
            emulator.log(LogLevel::Debug, "Failed to initialize kext object");
            return Ok(());
        }
        emulator.log(LogLevel::Debug, "Initialized kext object");

        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff8000a16102);
        emulator.run(kext_info.kext_attach, None)?;

        if emulator.read_reg("rax")? == 0 {
            emulator.log(LogLevel::Debug, "Failed to attach kext object");
            return Ok(());
        }
        emulator.log(LogLevel::Debug, "Attached kext object 1st time");

        let tmp = self.heap.alloc(8);
        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        emulator.write_reg("rdx", tmp)?;
        self.saved_rip = Some(0xffffff8000a16184);
        emulator.run(kext_info.kext_probe, None)?;
        self.heap.free(tmp);
        emulator.log(LogLevel::Debug, "Probed kext object");

        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff8000a16198);
        emulator.run(kext_info.kext_detach, None)?;
        emulator.log(LogLevel::Debug, "Detached kext object");

        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff8000a168a3);
        emulator.run(kext_info.kext_attach, None)?;

        if emulator.read_reg("rax")? == 0 {
            emulator.log(LogLevel::Debug, "Failed to attach kext object");
            return Ok(());
        }
        emulator.log(LogLevel::Debug, "Attached kext object 2nd time");

        emulator.write_reg("rdi", kext_obj)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff8000a168ed);
        emulator.run(kext_info.kext_start, None)?;

        Ok(())
    }

    fn load_kmod_info(
        &mut self,
        emulator: &mut dyn Emulator,
        kext_info: &KextLoadInfo,
    ) -> Result<(), MacOsError> {
        let kmod_info_addr = self.heap.alloc(std::mem::size_of::<KmodInfo>());
        emulator.log(
            LogLevel::Debug,
            &format!("Created fake kmod_info at 0x{:x}", kmod_info_addr),
        );

        let mut kmod_info = KmodInfo::new(kmod_info_addr);
        kmod_info.next = 0;
        kmod_info.info_version = 1;
        kmod_info.id = 1;
        kmod_info.name = kext_info.bundle_identifier.clone();
        kmod_info.version = kext_info.bundle_version.clone();
        kmod_info.reference_count = 0;
        kmod_info.reference_list = 0;
        kmod_info.address = kext_info.slide;
        kmod_info.size = kext_info.kext_size;
        kmod_info.hdr_size = kext_info.hdr_size;
        kmod_info.start = kext_info.kext_start;
        kmod_info.stop = kext_info.kext_stop;

        kmod_info.write_to_memory(emulator)?;
        emulator.log(LogLevel::Debug, "Initialized kmod_info");

        emulator.write_reg("rdi", kmod_info_addr)?;
        emulator.write_reg("rsi", 0)?;
        self.saved_rip = Some(0xffffff80009c2c16);
        emulator.run(kext_info.kext_start, None)?;

        Ok(())
    }

    pub fn run(
        &mut self,
        emulator: &mut dyn Emulator,
        entry_point: Option<u64>,
        exit_point: Option<u64>,
        kext_name: Option<&str>,
    ) -> Result<(), MacOsError> {
        if kext_name.is_some() {
            if let Some(saved_rip) = self.saved_rip {
                emulator.stack_push(saved_rip)?;
                if !self.hook_ret.contains_key(&saved_rip) {
                    let hook_id = self.hook_ret.len() as u64;
                    self.hook_ret.insert(saved_rip, hook_id);
                }
            } else {
                emulator.stack_push(0)?;
            }
        }

        self.entry_point = entry_point;
        if let Some(ep) = exit_point {
            self.exit_point = Some(ep);
        }

        let begin = self.entry_point.unwrap_or(entry_point.unwrap_or(0));
        let end = self.exit_point;

        match emulator.run(begin, end) {
            Ok(()) => {
                self.run_flag = false;
                Ok(())
            }
            Err(e) => {
                self.run_flag = false;
                Err(e)
            }
        }
    }

    pub fn hook_syscall(
        &mut self,
        emulator: &mut dyn Emulator,
        handler: Box<dyn FnMut(&mut dyn Emulator) -> Result<i64, MacOsError> + Send>,
    ) {
        emulator.hook_syscall(handler);
    }
}

pub struct KextLoadInfo {
    pub bundle_identifier: String,
    pub bundle_version: String,
    pub slide: u64,
    pub kext_size: u64,
    pub hdr_size: u64,
    pub kext_alloc: u64,
    pub kext_init: u64,
    pub kext_start: u64,
    pub kext_stop: u64,
    pub kext_attach: u64,
    pub kext_probe: u64,
    pub kext_detach: u64,
    pub io_kit: bool,
}
