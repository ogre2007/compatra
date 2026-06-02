//! Mach-O binary loader
//!
//! Loads Mach-O binaries into memory for emulation.

pub mod command;
pub mod consts;
pub mod header;
pub mod parser;

use crate::macos::imports::{
    install_synthetic_macho_imports, patch_macho_import_pointer_sections,
    process_macho_chained_fixups,
};
use crate::macos::Emulator;
use crate::macos::LogLevel;
use crate::macos::MacOsError;
use crate::UnicornEmulator;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use self::command::{LoadCommand, SegmentCommand32, SegmentCommand64};
use self::consts::cpu_type;
use self::parser::MachoBinary;

const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone)]
pub struct MachOLoader {
    pub binary: MachoBinary,
    pub source_path: Option<PathBuf>,
    pub slide: u64,
    pub dyld_slide: u64,
    pub entry_point: u64,
    pub load_address: u64,
    pub vm_end_addr: u64,
    pub stack_address: u64,
    pub stack_size: u64,
    pub stack_sp: u64,
    pub kext_size: u64,
    pub kernel_symbols: HashMap<String, u64>,
    pub is_driver: bool,
    pub kext_name: Option<String>,
    pub using_dyld: bool,
}

impl MachOLoader {
    pub fn new(binary: MachoBinary) -> Self {
        Self {
            binary,
            source_path: None,
            slide: 0,
            dyld_slide: 0,
            entry_point: 0,
            load_address: 0,
            vm_end_addr: 0,
            stack_address: 0,
            stack_size: 0,
            stack_sp: 0,
            kext_size: 0,
            kernel_symbols: HashMap::new(),
            is_driver: false,
            kext_name: None,
            using_dyld: false,
        }
    }

    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MacOsError> {
        let source_path = path.as_ref().to_path_buf();
        let binary = MachoBinary::parse_file(&source_path)?;
        let mut loader = Self::new(binary);
        loader.source_path = Some(source_path);

        Ok(loader)
    }

    pub fn from_data(data: &[u8]) -> Result<Self, MacOsError> {
        let binary = MachoBinary::parse(data)?;
        Ok(Self::new(binary))
    }

    pub fn set_kernel_symbols(&mut self, symbols: HashMap<String, u64>) {
        self.kernel_symbols = symbols;
    }

    pub fn load_kernel_symbols_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, MacOsError> {
        let kernel = MachoBinary::parse_file(path)?;
        let symbols = kernel.get_defined_symbols();
        let count = symbols.len();
        self.kernel_symbols = symbols;

        Ok(count)
    }

    pub fn load(
        &mut self,
        emulator: &mut dyn Emulator,
        stack_address: u64,
        stack_size: u64,
        mmap_address: u64,
    ) -> Result<(), MacOsError> {
        self.stack_address = stack_address;
        self.stack_size = stack_size;
        self.stack_sp = stack_address + stack_size;
        self.is_driver = self.binary.is_driver;

        emulator.log(LogLevel::Info, &format!("Loading Mach-O binary..."));
        emulator.log(
            LogLevel::Info,
            &format!(
                "  File type: {}",
                self.binary
                    .header_64
                    .as_ref()
                    .map(|h| h.file_type_name())
                    .or_else(|| self.binary.header_32.as_ref().map(|h| h.file_type_name()))
                    .unwrap_or("Unknown")
            ),
        );
        emulator.log(
            LogLevel::Info,
            &format!("  Entry point: 0x{:x}", self.entry_point),
        );

        if self.is_driver {
            self.load_driver(emulator)?;
        } else {
            self.load_macho(emulator, mmap_address)?;
            self.setup_registers(emulator)?;
        }

        Ok(())
    }

    pub fn load_macho(
        &mut self,
        emulator: &mut dyn Emulator,
        mmap_address: u64,
    ) -> Result<(), MacOsError> {
        self.vm_end_addr = mmap_address;

        let mut binary_entry = 0u64;
        let mut proc_entry = 0u64;
        let slide = self.slide;
        let commands = self.binary.commands.clone();
        let current_binary = self.binary.clone();
        let header_address = current_binary.header_address();
        let mut dyld_path: Option<String> = None;

        for cmd in &commands {
            match cmd {
                LoadCommand::Unixthread(thread_cmd) => {
                    binary_entry = thread_cmd.entry + slide;
                    proc_entry = thread_cmd.entry + slide;
                    emulator.log(
                        LogLevel::Debug,
                        &format!("  Thread entry: 0x{:x}", binary_entry),
                    );
                }
                LoadCommand::Main(main_cmd) => {
                    binary_entry = main_cmd.entryoff + header_address + slide;
                    proc_entry = main_cmd.entryoff + header_address + slide;
                    emulator.log(
                        LogLevel::Debug,
                        &format!("  Main entry: 0x{:x}", binary_entry),
                    );
                }
                LoadCommand::Dylinker(cmd) => {
                    dyld_path = Some(cmd.name.clone());
                }
                _ => {}
            }
        }

        for cmd in &commands {
            match cmd {
                LoadCommand::Segment64(seg) => {
                    self.load_segment64_with_binary(emulator, seg, &current_binary, self.slide)?;
                }
                LoadCommand::Segment(seg) => {
                    self.load_segment32_with_binary(emulator, seg, &current_binary, self.slide)?;
                }
                _ => {}
            }
        }

        if self.should_try_dyld() {
            if let Some(raw_dyld_path) = dyld_path {
                match self.try_load_dylinker(emulator, &raw_dyld_path, mmap_address)? {
                    Some(dyld_entry) => {
                        self.entry_point = dyld_entry;
                        self.using_dyld = true;
                    }
                    None => {
                        self.entry_point = proc_entry;
                        self.using_dyld = false;
                    }
                }
            } else {
                self.entry_point = proc_entry;
                self.using_dyld = false;
            }
        } else {
            if dyld_path.is_some() {
                emulator.log(
                    LogLevel::Info,
                    "Skipping dyld and using no-dyld fallback (set MACHINA_USE_DYLD=1 to enable dyld loading)",
                );
            }
            self.entry_point = proc_entry;
            self.using_dyld = false;
        }

        self.load_address = binary_entry;

        if !self.using_dyld {
            self.apply_no_dyld_stub_fallback(emulator)?;
        }

        self.setup_stack_with_bootstrap(emulator, header_address)?;

        emulator.log(
            LogLevel::Info,
            &format!("Binary loaded at: 0x{:x}", self.load_address),
        );
        emulator.log(
            LogLevel::Info,
            &format!("Entry point: 0x{:x}", self.entry_point),
        );

        if self.using_dyld {
            emulator.log(LogLevel::Info, "Using dyld entry point");
        }

        Ok(())
    }

    fn should_try_dyld(&self) -> bool {
        matches!(
            std::env::var("MACHINA_USE_DYLD").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
        )
    }

    fn is_arm64_binary(&self) -> bool {
        self.binary
            .header_64
            .as_ref()
            .map(|h| h.cputype == cpu_type::CPU_TYPE_ARM64)
            .unwrap_or(false)
    }

    fn find_arm64_ret_gadget(&self) -> Option<u64> {
        let text_seg = self.binary.get_segment_by_name("__TEXT")?;
        let text_data = self.binary.get_segment("__TEXT")?;
        let pattern = [0xC0, 0x03, 0x5F, 0xD6]; // ret

        for (offset, window) in text_data.windows(4).enumerate() {
            if window == pattern {
                return Some(text_seg.vmaddr + offset as u64 + self.slide);
            }
        }

        None
    }

    fn patch_pointer_section_to_target(
        &mut self,
        emulator: &mut dyn Emulator,
        section: &self::command::Section64,
        target: u64,
    ) -> Result<usize, MacOsError> {
        let ptr_count = (section.size / 8) as usize;
        for i in 0..ptr_count {
            let ptr_addr = section.addr + self.slide + (i as u64 * 8);
            emulator.write_memory(ptr_addr, &target.to_le_bytes())?;
        }
        Ok(ptr_count)
    }

    fn apply_arm64_no_dyld_stub_fallback(
        &mut self,
        emulator: &mut dyn Emulator,
    ) -> Result<(), MacOsError> {
        if !self.is_arm64_binary() {
            return Ok(());
        }

        let Some(target) = self.find_arm64_ret_gadget() else {
            emulator.log(
                LogLevel::Warn,
                "No ARM64 'ret' gadget found in __TEXT for no-dyld fallback",
            );
            return Ok(());
        };

        let mut patched = 0usize;
        if let Some(section) = self.binary.get_lazy_symbol_ptr_section().cloned() {
            patched += self.patch_pointer_section_to_target(emulator, &section, target)?;
        }
        if let Some(section) = self.binary.get_nl_symbol_ptr_section().cloned() {
            patched += self.patch_pointer_section_to_target(emulator, &section, target)?;
        }

        if patched > 0 {
            emulator.log(
                LogLevel::Info,
                &format!(
                    "Applied ARM64 no-dyld fallback: patched {} symbol pointers to 0x{:x}",
                    patched, target
                ),
            );
        }

        Ok(())
    }

    fn apply_no_dyld_stub_fallback(
        &mut self,
        emulator: &mut dyn Emulator,
    ) -> Result<(), MacOsError> {
        let mut synthetic_base = ((self.vm_end_addr + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
        if let Some(unicorn) = emulator.as_any_mut().downcast_mut::<UnicornEmulator>() {
            synthetic_base = 0x3100_0000_u64;
            let _ = unicorn.map_writable_code_memory(synthetic_base, PAGE_SIZE * 4);
        }

        let arch = if self.is_arm64_binary() {
            Some(crate::macos::ArchType::Arm64)
        } else {
            None
        };

        if let Some(arch) = arch {
            let install_result = install_synthetic_macho_imports(emulator, arch, synthetic_base);
            match install_result {
                Ok(synthetic) => {
                    let patch_result = patch_macho_import_pointer_sections(
                        emulator,
                        self,
                        arch,
                        synthetic.zero_stub_addr,
                        &synthetic.syscall_stubs,
                        &synthetic.symbol_stubs,
                        &synthetic.data_symbols,
                    );
                    let chain_result = process_macho_chained_fixups(
                        emulator,
                        self,
                        arch,
                        synthetic.zero_stub_addr,
                        &synthetic.syscall_stubs,
                        &synthetic.symbol_stubs,
                        &synthetic.data_symbols,
                    );
                    match (patch_result, chain_result) {
                        (Ok((patched, mapped_to_syscall, unresolved_fallback)), Ok(chain)) => {
                            emulator.log(
                                LogLevel::Info,
                                &format!(
                                    "Applied synthetic no-dyld import fallback: patched={}, syscall_stubs={}, unresolved={}, chained_bound={}, chained_rebased={}, chained_unresolved={}",
                                    patched,
                                    mapped_to_syscall,
                                    unresolved_fallback,
                                    chain.bound,
                                    chain.rebased,
                                    chain.unresolved,
                                ),
                            );
                            return Ok(());
                        }
                        (Ok(_), Err(err)) => {
                            emulator.log(
                                LogLevel::Warn,
                                &format!(
                                    "Chained-fixups processing failed, using gadget fallback: {}",
                                    err
                                ),
                            );
                        }
                        (Err(err), _) => {
                            emulator.log(
                                LogLevel::Warn,
                                &format!(
                                    "Synthetic no-dyld import fallback failed, using gadget fallback: {}",
                                    err
                                ),
                            );
                        }
                    }
                }
                Err(err) => {
                    emulator.log(
                        LogLevel::Warn,
                        &format!(
                            "Synthetic no-dyld import fallback failed, using gadget fallback: {}",
                            err
                        ),
                    );
                }
            }
        }

        self.apply_arm64_no_dyld_stub_fallback(emulator)?;
        Ok(())
    }

    pub fn load_driver(&mut self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let loadbase = 0xffffff7000000000u64;
        self.slide = loadbase;
        self.load_address = loadbase;

        let commands = self.binary.commands.clone();

        for cmd in &commands {
            match cmd {
                LoadCommand::Segment64(seg) => {
                    self.load_segment64(emulator, seg)?;
                }
                LoadCommand::Segment(seg) => {
                    self.load_segment32(emulator, seg)?;
                }
                _ => {}
            }
        }

        self.apply_driver_relocations(emulator, loadbase)?;

        self.kext_size = self.vm_end_addr - loadbase;
        emulator.log(
            LogLevel::Info,
            &format!("KEXT size: 0x{:x}", self.kext_size),
        );

        Ok(())
    }

    fn apply_driver_relocations(
        &mut self,
        emulator: &mut dyn Emulator,
        loadbase: u64,
    ) -> Result<(), MacOsError> {
        let (local_relocs, external_relocs) = self.binary.get_dysymtab_relocations();

        for reloc in &local_relocs {
            self.apply_local_relocation(emulator, loadbase, reloc)?;
        }

        let local_defined = self.binary.get_defined_symbols();
        for reloc in &external_relocs {
            self.apply_external_relocation(emulator, loadbase, reloc, &local_defined)?;
        }

        emulator.log(
            LogLevel::Info,
            &format!(
                "Applied driver relocations: local={}, external={}",
                local_relocs.len(),
                external_relocs.len()
            ),
        );

        Ok(())
    }

    fn apply_local_relocation(
        &mut self,
        emulator: &mut dyn Emulator,
        loadbase: u64,
        reloc: &self::parser::RelocationInfo,
    ) -> Result<(), MacOsError> {
        let width = match reloc.length {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };

        let reloc_addr = reloc.address;
        let target = loadbase.wrapping_add(reloc_addr);
        let current = match emulator.read_memory(target, width) {
            Ok(bytes) if bytes.len() == width => match width {
                1 => bytes[0] as u64,
                2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()) as u64,
                4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64,
                _ => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            },
            _ => return Ok(()),
        };

        let updated = current.wrapping_add(loadbase);

        let out = match width {
            1 => vec![updated as u8],
            2 => (updated as u16).to_le_bytes().to_vec(),
            4 => (updated as u32).to_le_bytes().to_vec(),
            _ => updated.to_le_bytes().to_vec(),
        };
        emulator.write_memory(target, &out)?;

        Ok(())
    }

    fn apply_external_relocation(
        &mut self,
        emulator: &mut dyn Emulator,
        loadbase: u64,
        reloc: &self::parser::RelocationInfo,
        local_defined: &HashMap<String, u64>,
    ) -> Result<(), MacOsError> {
        let width = match reloc.length {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };

        let reloc_addr = reloc.address;
        let symbol_index = reloc.symbolnum as usize;
        let target = loadbase.wrapping_add(reloc_addr);
        let Some((name, n_value, _n_type)) = self.binary.get_symbol_by_index(symbol_index) else {
            return Ok(());
        };

        let stripped = name.trim_start_matches('_');
        let resolved = self
            .kernel_symbols
            .get(&name)
            .copied()
            .or_else(|| self.kernel_symbols.get(stripped).copied())
            .or_else(|| local_defined.get(&name).map(|v| loadbase.wrapping_add(*v)))
            .or_else(|| {
                local_defined
                    .get(stripped)
                    .map(|v| loadbase.wrapping_add(*v))
            })
            .or_else(|| {
                if n_value != 0 {
                    Some(loadbase.wrapping_add(n_value))
                } else {
                    None
                }
            });

        if let Some(value) = resolved {
            let out = match width {
                1 => vec![value as u8],
                2 => (value as u16).to_le_bytes().to_vec(),
                4 => (value as u32).to_le_bytes().to_vec(),
                _ => value.to_le_bytes().to_vec(),
            };
            emulator.write_memory(target, &out)?;
        } else {
            emulator.log(
                LogLevel::Warn,
                &format!("Unresolved external relocation symbol '{}'", name),
            );
        }

        Ok(())
    }

    fn load_segment64(
        &mut self,
        emulator: &mut dyn Emulator,
        seg: &SegmentCommand64,
    ) -> Result<(), MacOsError> {
        let binary = self.binary.clone();
        self.load_segment64_with_binary(emulator, seg, &binary, self.slide)
    }

    fn load_segment32(
        &mut self,
        emulator: &mut dyn Emulator,
        seg: &SegmentCommand32,
    ) -> Result<(), MacOsError> {
        let binary = self.binary.clone();
        self.load_segment32_with_binary(emulator, seg, &binary, self.slide)
    }

    fn load_segment64_with_binary(
        &mut self,
        emulator: &mut dyn Emulator,
        seg: &SegmentCommand64,
        binary: &MachoBinary,
        slide: u64,
    ) -> Result<(), MacOsError> {
        let seg_name = seg.segname_str();
        let vaddr_start = seg.vmaddr + slide;
        let vaddr_end = seg.vmaddr + seg.vmsize + slide;
        let seg_size = seg.vmsize;

        if seg_size == 0 {
            return Ok(());
        }

        if seg_name == "__PAGEZERO" {
            emulator.log(
                LogLevel::Debug,
                &format!(
                    "Loading __PAGEZERO at VM[0x{:x}:0x{:x}]",
                    vaddr_start, vaddr_end
                ),
            );
            let _page_size = PAGE_SIZE as usize;
        } else {
            let mut actual_size = seg.filesize;
            let mut aligned_end = vaddr_end;

            if aligned_end % PAGE_SIZE != 0 {
                aligned_end = ((aligned_end / PAGE_SIZE) + 1) * PAGE_SIZE;
                actual_size = aligned_end - vaddr_start;
            }

            emulator.log(
                LogLevel::Debug,
                &format!(
                    "Loading {} at VM[0x{:x}:0x{:x}]",
                    seg_name, vaddr_start, aligned_end
                ),
            );

            let mut data = if let Some(segment_data) = binary.get_segment(&seg_name) {
                segment_data.clone()
            } else {
                Vec::new()
            };
            if data.len() < actual_size as usize {
                data.resize(actual_size as usize, 0);
            }
            emulator.write_memory(vaddr_start, &data)?;
            emulator.log(
                LogLevel::Debug,
                &format!("  Wrote {} bytes to 0x{:x}", data.len(), vaddr_start),
            );

            if self.vm_end_addr < aligned_end {
                self.vm_end_addr = aligned_end;
            }
        }

        Ok(())
    }

    fn load_segment32_with_binary(
        &mut self,
        emulator: &mut dyn Emulator,
        seg: &SegmentCommand32,
        binary: &MachoBinary,
        slide: u64,
    ) -> Result<(), MacOsError> {
        let seg_name = seg.segname_str();
        let vaddr_start = seg.vmaddr as u64 + slide;
        let vaddr_end = seg.vmaddr as u64 + seg.vmsize as u64 + slide;
        let seg_size = seg.vmsize as u64;

        if seg_size == 0 {
            return Ok(());
        }

        if seg_name == "__PAGEZERO" {
            emulator.log(
                LogLevel::Debug,
                &format!(
                    "Loading __PAGEZERO at VM[0x{:x}:0x{:x}]",
                    vaddr_start, vaddr_end
                ),
            );
            let _page_size = PAGE_SIZE as usize;
        } else {
            let mut actual_size = seg.filesize as u64;
            let mut aligned_end = vaddr_end;

            if aligned_end % PAGE_SIZE != 0 {
                aligned_end = ((aligned_end / PAGE_SIZE) + 1) * PAGE_SIZE;
                actual_size = aligned_end - vaddr_start;
            }

            emulator.log(
                LogLevel::Debug,
                &format!(
                    "Loading {} at VM[0x{:x}:0x{:x}]",
                    seg_name, vaddr_start, aligned_end
                ),
            );

            let mut data = if let Some(segment_data) = binary.get_segment(&seg_name) {
                segment_data.clone()
            } else {
                Vec::new()
            };
            if data.len() < actual_size as usize {
                data.resize(actual_size as usize, 0);
            }
            emulator.write_memory(vaddr_start, &data)?;
            emulator.log(
                LogLevel::Debug,
                &format!("  Wrote {} bytes to 0x{:x}", data.len(), vaddr_start),
            );

            if self.vm_end_addr < aligned_end {
                self.vm_end_addr = aligned_end;
            }
        }

        Ok(())
    }

    fn try_load_dylinker(
        &mut self,
        emulator: &mut dyn Emulator,
        raw_dyld_path: &str,
        mmap_address: u64,
    ) -> Result<Option<u64>, MacOsError> {
        let dyld_path = match self.resolve_dylinker_path(raw_dyld_path) {
            Some(path) => path,
            None => {
                emulator.log(
                    LogLevel::Warn,
                    &format!("Unable to resolve dyld path '{}'", raw_dyld_path),
                );
                return Ok(None);
            }
        };

        let dyld_binary = MachoBinary::parse_file(&dyld_path)?;
        let dyld_commands = dyld_binary.commands.clone();
        let mut dyld_entry = 0u64;

        for cmd in &dyld_commands {
            match cmd {
                LoadCommand::Unixthread(thread_cmd) => {
                    dyld_entry = thread_cmd.entry + self.dyld_slide;
                }
                LoadCommand::Main(main_cmd) => {
                    dyld_entry = main_cmd.entryoff + dyld_binary.header_address() + self.dyld_slide;
                }
                _ => {}
            }
        }

        for cmd in &dyld_commands {
            match cmd {
                LoadCommand::Segment64(seg) => {
                    self.load_segment64_with_binary(emulator, seg, &dyld_binary, self.dyld_slide)?;
                }
                LoadCommand::Segment(seg) => {
                    self.load_segment32_with_binary(emulator, seg, &dyld_binary, self.dyld_slide)?;
                }
                _ => {}
            }
        }

        if self.vm_end_addr < mmap_address {
            self.vm_end_addr = mmap_address;
        }

        emulator.log(
            LogLevel::Info,
            &format!("Loaded dyld from '{}'", dyld_path.display()),
        );

        Ok(Some(dyld_entry))
    }

    fn resolve_dylinker_path(&self, raw: &str) -> Option<PathBuf> {
        let dylinker = raw.trim_matches('\0');
        let path = Path::new(dylinker);

        if path.exists() {
            return Some(path.to_path_buf());
        }

        if let Some(source_path) = &self.source_path {
            let source_dir = source_path.parent().unwrap_or_else(|| Path::new("."));

            if !path.is_absolute() {
                let candidate = source_dir.join(path);
                if candidate.exists() {
                    return Some(candidate);
                }
            }

            let rel = dylinker.trim_start_matches(['/', '\\']);
            for ancestor in source_dir.ancestors() {
                let candidate = ancestor.join(rel);
                if candidate.exists() {
                    return Some(candidate);
                }
            }

            let dylinker_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("dyld");
            if let Ok(entries) = fs::read_dir(source_dir) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    if let Some(name) = file_name.to_str() {
                        if name.starts_with(dylinker_name) {
                            let candidate = source_dir.join(name);
                            if candidate.is_file() {
                                return Some(candidate);
                            }
                        }
                    }
                }
            }
        }

        if let Some(candidate) = self.resolve_dylinker_from_repository(path, dylinker) {
            return Some(candidate);
        }

        None
    }

    fn resolve_dylinker_from_repository(&self, path: &Path, dylinker: &str) -> Option<PathBuf> {
        let rel = dylinker.trim_start_matches(['/', '\\']);
        let dylinker_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("dyld");

        for root in self.repository_search_roots() {
            let exact = root.join(rel);
            if exact.is_file() {
                return Some(exact);
            }

            let parent = exact.parent().unwrap_or(&root);
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let candidate = entry.path();
                    if !candidate.is_file() {
                        continue;
                    }
                    if let Some(name) = candidate.file_name().and_then(|s| s.to_str()) {
                        if name.starts_with(dylinker_name) {
                            return Some(candidate);
                        }
                    }
                }
            }
        }

        None
    }

    fn repository_search_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();

        if let Some(source_path) = &self.source_path {
            for ancestor in source_path.ancestors() {
                roots.push(ancestor.join("fixtures").join("macos").join("dyld"));
            }
        }

        if let Ok(current_dir) = std::env::current_dir() {
            roots.push(current_dir.join("fixtures").join("macos").join("dyld"));
        }

        roots
    }

    pub fn get_entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn get_load_address(&self) -> u64 {
        self.load_address
    }

    pub fn get_segments(&self) -> Vec<&SegmentCommand64> {
        self.binary.segments.iter().collect()
    }

    pub fn get_segment_names(&self) -> Vec<String> {
        self.binary
            .segments
            .iter()
            .map(|s| s.segname_str())
            .collect()
    }

    pub fn setup_stack(
        &mut self,
        emulator: &mut dyn Emulator,
        stack_address: u64,
        stack_size: u64,
    ) -> Result<(), MacOsError> {
        self.stack_address = stack_address;
        self.stack_size = stack_size;
        self.stack_sp = stack_address + stack_size;
        self.setup_stack_with_bootstrap(emulator, self.binary.header_address())
    }

    fn setup_stack_with_bootstrap(
        &mut self,
        emulator: &mut dyn Emulator,
        header_address: u64,
    ) -> Result<(), MacOsError> {
        let binary_path = self
            .source_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "program".to_string());

        emulator.log(
            LogLevel::Debug,
            &format!(
                "Setting up stack at 0x{:x} (size: 0x{:x})",
                self.stack_address, self.stack_size
            ),
        );

        let argv = vec![binary_path.clone()];
        let env = vec!["PATH=/usr/bin:/bin".to_string()];
        let apple = vec![binary_path];

        let string_block = self.make_stack_string_block(&argv, &env, &apple);
        let string_base = self.push_stack_bytes_aligned(emulator, &string_block)?;

        let mut ptr = string_base;
        let mut argv_ptrs = Vec::with_capacity(argv.len());
        let mut env_ptrs = Vec::with_capacity(env.len());
        let mut apple_ptrs = Vec::with_capacity(apple.len());

        for item in argv.iter().rev() {
            argv_ptrs.push(ptr);
            ptr += item.len() as u64 + 1;
        }

        for item in env.iter().rev() {
            env_ptrs.push(ptr);
            ptr += item.len() as u64 + 1;
        }

        for item in apple.iter().rev() {
            apple_ptrs.push(ptr);
            ptr += item.len() as u64 + 1;
        }

        self.push_stack_ptr(emulator, 0)?;
        for ptr in apple_ptrs {
            self.push_stack_ptr(emulator, ptr)?;
        }

        self.push_stack_ptr(emulator, 0)?;
        for ptr in env_ptrs {
            self.push_stack_ptr(emulator, ptr)?;
        }

        self.push_stack_ptr(emulator, 0)?;
        for ptr in argv_ptrs {
            self.push_stack_ptr(emulator, ptr)?;
        }

        self.push_stack_ptr(emulator, argv.len() as u64)?;
        if self.using_dyld {
            // Keep behavior close to Python loader: when dyld is in play, push the
            // original Mach-O header address as an extra bootstrap value.
            self.push_stack_ptr(emulator, header_address)?;
        }

        emulator.write_reg("sp", self.stack_sp)?;

        emulator.log(
            LogLevel::Debug,
            &format!("Stack pointer set to 0x{:x}", self.stack_sp),
        );

        Ok(())
    }

    fn push_stack_ptr(
        &mut self,
        emulator: &mut dyn Emulator,
        value: u64,
    ) -> Result<u64, MacOsError> {
        let ptr_size = 8;
        self.stack_sp -= ptr_size;
        emulator.write_memory(self.stack_sp, &value.to_le_bytes())?;
        Ok(self.stack_sp)
    }

    fn push_stack_bytes_aligned(
        &mut self,
        emulator: &mut dyn Emulator,
        data: &[u8],
    ) -> Result<u64, MacOsError> {
        let align = 8;
        let padded_len = if data.len() as u64 % align == 0 {
            data.len() as u64
        } else {
            ((data.len() as u64 / align) + 1) * align
        };

        self.stack_sp -= padded_len;
        let addr = self.stack_sp;
        emulator.write_memory(addr, data)?;
        if padded_len > data.len() as u64 {
            let padding = vec![0u8; (padded_len - data.len() as u64) as usize];
            emulator.write_memory(addr + data.len() as u64, &padding)?;
        }

        Ok(addr)
    }

    fn make_stack_string_block(
        &self,
        argv: &[String],
        env: &[String],
        apple: &[String],
    ) -> Vec<u8> {
        let mut result = Vec::new();

        for item in apple {
            let mut bytes = item.as_bytes().to_vec();
            bytes.push(0);
            bytes.extend_from_slice(&result);
            result = bytes;
        }

        for item in env {
            let mut bytes = item.as_bytes().to_vec();
            bytes.push(0);
            bytes.extend_from_slice(&result);
            result = bytes;
        }

        for item in argv {
            let mut bytes = item.as_bytes().to_vec();
            bytes.push(0);
            bytes.extend_from_slice(&result);
            result = bytes;
        }

        result
    }

    fn pointer_size(&self) -> u64 {
        8
    }

    fn read_stack_ptr(&self, emulator: &dyn Emulator, addr: u64) -> Result<u64, MacOsError> {
        let ptr_size = self.pointer_size() as usize;
        let data = emulator.read_memory(addr, ptr_size)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    fn stack_vector_end(&self, emulator: &dyn Emulator, start: u64) -> Result<u64, MacOsError> {
        let ptr_size = self.pointer_size();
        let mut cursor = start;
        loop {
            let value = self.read_stack_ptr(emulator, cursor)?;
            cursor += ptr_size;
            if value == 0 {
                return Ok(cursor);
            }
        }
    }

    pub fn setup_registers(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let unixthread = self.binary.commands.iter().find_map(|cmd| match cmd {
            LoadCommand::Unixthread(thread) => Some(thread),
            _ => None,
        });

        if let Some(regs) = unixthread.and_then(|t| t.registers.arm64.as_ref()) {
            emulator.write_reg("x0", regs.x0)?;
            emulator.write_reg("x1", regs.x1)?;
            emulator.write_reg("x2", regs.x2)?;
            emulator.write_reg("x3", regs.x3)?;
            emulator.write_reg("x4", regs.x4)?;
            emulator.write_reg("x5", regs.x5)?;
            emulator.write_reg("x6", regs.x6)?;
            emulator.write_reg("x7", regs.x7)?;
            emulator.write_reg("x8", regs.x8)?;
            emulator.write_reg("x9", regs.x9)?;
            emulator.write_reg("x10", regs.x10)?;
            emulator.write_reg("x11", regs.x11)?;
            emulator.write_reg("x12", regs.x12)?;
            emulator.write_reg("x13", regs.x13)?;
            emulator.write_reg("x14", regs.x14)?;
            emulator.write_reg("x15", regs.x15)?;
            emulator.write_reg("x16", regs.x16)?;
            emulator.write_reg("x17", regs.x17)?;
            emulator.write_reg("x18", regs.x18)?;
            emulator.write_reg("x19", regs.x19)?;
            emulator.write_reg("x20", regs.x20)?;
            emulator.write_reg("x21", regs.x21)?;
            emulator.write_reg("x22", regs.x22)?;
            emulator.write_reg("x23", regs.x23)?;
            emulator.write_reg("x24", regs.x24)?;
            emulator.write_reg("x25", regs.x25)?;
            emulator.write_reg("x26", regs.x26)?;
            emulator.write_reg("x27", regs.x27)?;
            emulator.write_reg("x28", regs.x28)?;
            emulator.write_reg("fp", regs.x29)?;
            let sp = if regs.sp >= self.stack_address
                && regs.sp <= self.stack_address.saturating_add(self.stack_size)
            {
                regs.sp
            } else {
                self.stack_sp
            };
            emulator.write_reg("sp", sp)?;
            emulator.write_reg("pc", regs.pc)?;
            emulator.log(
                LogLevel::Debug,
                "ARM64 registers initialized from LC_UNIXTHREAD",
            );
        } else {
            emulator.write_reg("pc", self.entry_point)?;
            for i in 0..29 {
                emulator.write_reg(&format!("x{}", i), 0)?;
            }
            let ptr_size = self.pointer_size();
            let argc = self.read_stack_ptr(emulator, self.stack_sp)?;
            let argv = self.stack_sp + ptr_size;
            let envp = self.stack_vector_end(emulator, argv)?;
            let apple = self.stack_vector_end(emulator, envp)?;
            emulator.write_reg("x0", argc)?;
            emulator.write_reg("x1", argv)?;
            emulator.write_reg("x2", envp)?;
            emulator.write_reg("x3", apple)?;
            emulator.write_reg("fp", 0)?;
            emulator.write_reg("lr", 0)?;
            emulator.write_reg("sp", self.stack_sp)?;
            emulator.log(LogLevel::Debug, "ARM64 registers initialized");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::loader::consts::*;
    use crate::macos::{ArchType, Emulator, LogLevel, MacOsError};
    use std::collections::HashMap;

    struct TestEmulator {
        memory: Vec<u8>,
        regs: HashMap<String, u64>,
        arch: ArchType,
    }

    impl TestEmulator {
        fn new(memory_size: usize) -> Self {
            Self {
                memory: vec![0; memory_size],
                regs: HashMap::new(),
                arch: ArchType::Arm64,
            }
        }

        fn with_arch(memory_size: usize, arch: ArchType) -> Self {
            Self {
                memory: vec![0; memory_size],
                regs: HashMap::new(),
                arch,
            }
        }
    }

    impl Emulator for TestEmulator {
        fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, MacOsError> {
            let start = addr as usize;
            let end = start.saturating_add(size);
            if end > self.memory.len() {
                return Err(MacOsError::Memory("Out of bounds read".to_string()));
            }

            Ok(self.memory[start..end].to_vec())
        }

        fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MacOsError> {
            let start = addr as usize;
            let end = start.saturating_add(data.len());
            if end > self.memory.len() {
                return Err(MacOsError::Memory("Out of bounds write".to_string()));
            }

            self.memory[start..end].copy_from_slice(data);
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

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    fn minimal_macho64(cputype: u32, cpusubtype: u32) -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&cputype.to_le_bytes());
        data[8..12].copy_from_slice(&cpusubtype.to_le_bytes());
        data[12..16].copy_from_slice(&file_type::MH_EXECUTE.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    fn write_fat_arch(
        data: &mut [u8],
        offset: usize,
        cputype: u32,
        cpusubtype: u32,
        slice_offset: u32,
        slice_size: u32,
    ) {
        data[offset..offset + 4].copy_from_slice(&cputype.to_be_bytes());
        data[offset + 4..offset + 8].copy_from_slice(&cpusubtype.to_be_bytes());
        data[offset + 8..offset + 12].copy_from_slice(&slice_offset.to_be_bytes());
        data[offset + 12..offset + 16].copy_from_slice(&slice_size.to_be_bytes());
        data[offset + 16..offset + 20].copy_from_slice(&12u32.to_be_bytes());
    }

    #[test]
    fn test_macho_loader_creation() {
        let loader = MachOLoader::new(MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: None,
            header_32: None,
            commands: vec![],
            segments: vec![],
            entry_point: Some(0x1000),
            is_driver: false,
            segments_data: HashMap::new(),
        });

        assert_eq!(loader.slide, 0);
        assert_eq!(loader.dyld_slide, 0);
        assert_eq!(loader.entry_point, 0);
        assert_eq!(loader.load_address, 0);
    }

    #[test]
    fn test_macho_binary_creation() {
        let binary = MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: Some(crate::macos::loader::header::MachHeader64 {
                magic: 0xFEEDFACF,
                cputype: 0x01000007,
                cpusubtype: 0x30,
                filetype: 0x02,
                ncmds: 0,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            }),
            header_32: None,
            commands: vec![],
            segments: vec![],
            entry_point: Some(0x1000),
            is_driver: false,
            segments_data: HashMap::new(),
        };

        assert!(binary.is_64_bit());
        assert!(!binary.is_driver);
    }

    #[test]
    fn test_macho_header64_parse() {
        let mut data = vec![0u8; 32];

        data[0..4].copy_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&cpu_type::CPU_TYPE_X86_64.to_le_bytes());
        data[8..12].copy_from_slice(&0x30u32.to_le_bytes());
        data[12..16].copy_from_slice(&file_type::MH_EXECUTE.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        let header = crate::macos::loader::header::MachHeader64::parse(&data, false).unwrap();

        assert_eq!(header.magic, magic::MH_MAGIC_64);
        assert_eq!(header.cputype, cpu_type::CPU_TYPE_X86_64);
        assert_eq!(header.filetype, file_type::MH_EXECUTE);
    }

    #[test]
    fn test_macho_magic_detection() {
        assert_eq!(
            crate::macos::loader::header::MachOMagic::from_u32(magic::MH_MAGIC_64),
            crate::macos::loader::header::MachOMagic::Magic64
        );
        assert_eq!(
            crate::macos::loader::header::MachOMagic::from_u32(magic::MH_MAGIC_32),
            crate::macos::loader::header::MachOMagic::Magic32
        );
        assert_eq!(
            crate::macos::loader::header::MachOMagic::from_u32(magic::FAT_MAGIC),
            crate::macos::loader::header::MachOMagic::Fat
        );
        assert_eq!(
            crate::macos::loader::header::MachOMagic::from_u32(0xDEADBEEF),
            crate::macos::loader::header::MachOMagic::Unknown
        );
    }

    #[test]
    fn test_macho_binary_parse_minimal() {
        let mut data = vec![0u8; 32];

        data[0..4].copy_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&cpu_type::CPU_TYPE_X86_64.to_le_bytes());
        data[8..12].copy_from_slice(&0x30u32.to_le_bytes());
        data[12..16].copy_from_slice(&file_type::MH_EXECUTE.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        let binary = MachoBinary::parse(&data).unwrap();

        assert!(binary.is_64_bit());
        assert!(!binary.is_driver);
        assert!(binary.header_64.is_some());
        assert_eq!(binary.commands.len(), 0);
    }

    #[test]
    fn test_fat_parse_prefers_arm64_slice_over_x86_64() {
        let x86 = minimal_macho64(cpu_type::CPU_TYPE_X86_64, cpu_type::CPU_SUBTYPE_X86_64_ALL);
        let arm64 = minimal_macho64(cpu_type::CPU_TYPE_ARM64, cpu_type::CPU_SUBTYPE_ARM64_ALL);
        let x86_offset = 0x100usize;
        let arm64_offset = 0x200usize;
        let mut fat = vec![0u8; arm64_offset + arm64.len()];
        fat[0..4].copy_from_slice(&magic::FAT_CIGAM.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        write_fat_arch(
            &mut fat,
            8,
            cpu_type::CPU_TYPE_X86_64,
            cpu_type::CPU_SUBTYPE_X86_64_ALL,
            x86_offset as u32,
            x86.len() as u32,
        );
        write_fat_arch(
            &mut fat,
            28,
            cpu_type::CPU_TYPE_ARM64,
            cpu_type::CPU_SUBTYPE_ARM64_ALL,
            arm64_offset as u32,
            arm64.len() as u32,
        );
        fat[x86_offset..x86_offset + x86.len()].copy_from_slice(&x86);
        fat[arm64_offset..arm64_offset + arm64.len()].copy_from_slice(&arm64);

        assert!(MachoBinary::is_fat(&fat));
        assert!(MachoBinary::fat_contains_cpu(
            &fat,
            cpu_type::CPU_TYPE_X86_64
        ));
        assert!(MachoBinary::fat_contains_cpu(
            &fat,
            cpu_type::CPU_TYPE_ARM64
        ));

        let binary = MachoBinary::parse(&fat).unwrap();
        assert_eq!(
            binary.header_64.as_ref().map(|header| header.cputype),
            Some(cpu_type::CPU_TYPE_ARM64)
        );
    }

    #[test]
    fn test_segment_command() {
        use crate::macos::loader::command::SegmentCommand64;

        let seg = SegmentCommand64 {
            segname: *b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            vmaddr: 0x1000,
            vmsize: 0x2000,
            fileoff: 0x1000,
            filesize: 0x1000,
            maxprot: 0x05,
            initprot: 0x05,
            nsects: 0,
            flags: 0,
            sections: vec![],
            reloff: 0,
            nreloc: 0,
        };

        assert_eq!(seg.segname_str(), "__TEXT");
        assert_eq!(seg.vmaddr, 0x1000);
        assert_eq!(seg.vmsize, 0x2000);
    }

    #[test]
    fn test_load_command_enum() {
        use crate::macos::loader::command::LoadCommand;
        use crate::macos::loader::consts::load_command::LC_SEGMENT_64;

        let cmd = LoadCommand::Unknown {
            cmd_id: LC_SEGMENT_64,
            cmd_size: 72,
            data: vec![],
        };

        assert_eq!(cmd.cmd_id(), LC_SEGMENT_64);
    }

    #[test]
    fn test_file_type_names() {
        use crate::macos::loader::header::MachHeader64;

        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data[12..16].copy_from_slice(&file_type::MH_EXECUTE.to_le_bytes());

        let header = MachHeader64::parse(&data, false).unwrap();
        assert_eq!(header.file_type_name(), "Executable");

        let mut data2 = vec![0u8; 32];
        data2[0..4].copy_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data2[12..16].copy_from_slice(&file_type::MH_KEXT_BUNDLE.to_le_bytes());

        let header2 = MachHeader64::parse(&data2, false).unwrap();
        assert_eq!(header2.file_type_name(), "KEXT Bundle");
        assert!(header2.is_driver());
    }

    #[test]
    fn test_version_min_command() {
        use crate::macos::loader::command::VersionMinCommand;

        let version: u32 = (10 << 16) | (15 << 8) | 1;
        let cmd = VersionMinCommand {
            version,
            reserved: 0,
        };

        assert_eq!(cmd.version_string(), "10.15.1");
    }

    #[test]
    fn test_stack_bootstrap_pushes_header_for_dyld() {
        let binary = MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: None,
            header_32: None,
            commands: vec![],
            segments: vec![SegmentCommand64 {
                segname: *b"__PAGEZERO\0\0\0\0\0\0",
                vmaddr: 0,
                vmsize: 0x1000,
                fileoff: 0,
                filesize: 0,
                maxprot: 0,
                initprot: 0,
                nsects: 0,
                flags: 0,
                sections: vec![],
                reloff: 0,
                nreloc: 0,
            }],
            entry_point: Some(0),
            is_driver: false,
            segments_data: HashMap::new(),
        };

        let mut loader = MachOLoader::new(binary);
        loader.using_dyld = true;

        let mut emu = TestEmulator::new(0x20000);
        loader.setup_stack(&mut emu, 0x10000, 0x1000).unwrap();

        let top = emu.read_memory(loader.stack_sp, 8).unwrap();
        let top_val = u64::from_le_bytes(top.try_into().unwrap());
        assert_eq!(top_val, 0x1000);

        let next = emu.read_memory(loader.stack_sp + 8, 8).unwrap();
        let next_val = u64::from_le_bytes(next.try_into().unwrap());
        assert_eq!(next_val, 1);
    }

    #[test]
    fn test_lc_main_entry_includes_pagezero() {
        let main_entryoff = 0x200;
        let pagezero_size = 0x1000;

        let binary = MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: Some(crate::macos::loader::header::MachHeader64 {
                magic: magic::MH_MAGIC_64,
                cputype: cpu_type::CPU_TYPE_X86_64,
                cpusubtype: 0,
                filetype: file_type::MH_EXECUTE,
                ncmds: 1,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            }),
            header_32: None,
            commands: vec![LoadCommand::Main(
                crate::macos::loader::command::MainCommand {
                    entryoff: main_entryoff,
                    stacksize: 0,
                },
            )],
            segments: vec![SegmentCommand64 {
                segname: *b"__PAGEZERO\0\0\0\0\0\0",
                vmaddr: 0,
                vmsize: pagezero_size,
                fileoff: 0,
                filesize: 0,
                maxprot: 0,
                initprot: 0,
                nsects: 0,
                flags: 0,
                sections: vec![],
                reloff: 0,
                nreloc: 0,
            }],
            entry_point: Some(main_entryoff),
            is_driver: false,
            segments_data: HashMap::new(),
        };

        let mut loader = MachOLoader::new(binary);
        let mut emu = TestEmulator::new(0x40000);

        loader.load(&mut emu, 0x20000, 0x2000, 0x30000).unwrap();

        assert_eq!(loader.get_entry_point(), main_entryoff + pagezero_size);
        assert_eq!(loader.get_load_address(), main_entryoff + pagezero_size);
    }

    #[test]
    fn test_dysymtab_relocation_parsing() {
        let mut data = vec![0u8; 0x80];

        // local relocation entry at 0x20:
        // r_address = 0x10, r_length=3 (8 bytes), r_extern=0
        data[0x20..0x24].copy_from_slice(&(0x10_i32).to_le_bytes());
        data[0x24..0x28].copy_from_slice(&(0x0600_0000_u32).to_le_bytes());

        // external relocation entry at 0x28:
        // r_address = 0x18, r_symbolnum=2, r_length=3, r_extern=1
        data[0x28..0x2c].copy_from_slice(&(0x18_i32).to_le_bytes());
        data[0x2c..0x30].copy_from_slice(&(0x0e00_0002_u32).to_le_bytes());

        let binary = MachoBinary {
            data,
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: None,
            header_32: None,
            commands: vec![LoadCommand::Dysymtab(
                crate::macos::loader::command::DysymtabCommand {
                    ilocalsym: 0,
                    nlocalsym: 0,
                    iextdefsym: 0,
                    nextdefsym: 0,
                    iundefsym: 0,
                    nundefsym: 0,
                    tocoff: 0,
                    ntoc: 0,
                    modtaboff: 0,
                    nmodtab: 0,
                    extrefsymoff: 0,
                    nextrefsyms: 0,
                    indirectsymoff: 0,
                    nindirectsyms: 0,
                    extreloff: 0x28,
                    nextrel: 1,
                    locreloff: 0x20,
                    nlocrel: 1,
                },
            )],
            segments: vec![],
            entry_point: None,
            is_driver: true,
            segments_data: HashMap::new(),
        };

        let (local, external) = binary.get_dysymtab_relocations();
        assert_eq!(local.len(), 1);
        assert_eq!(external.len(), 1);
        assert!(!local[0].is_extern);
        assert!(external[0].is_extern);
        assert_eq!(external[0].symbolnum, 2);

        let merged = binary.get_relocations();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_symtab_symbol_lookup_and_defined_symbols() {
        let mut data = vec![0u8; 0x100];

        // nlist_64 at symoff=0x20
        data[0x20..0x24].copy_from_slice(&(1_u32).to_le_bytes()); // n_strx -> "_foo"
        data[0x24] = 0x0f; // n_type (N_SECT | N_EXT)
        data[0x25] = 1; // n_sect
        data[0x26..0x28].copy_from_slice(&0_u16.to_le_bytes()); // n_desc
        data[0x28..0x30].copy_from_slice(&(0x1234_u64).to_le_bytes()); // n_value

        // string table at stroff=0x60 : "\0_foo\0"
        data[0x60] = 0;
        data[0x61..0x66].copy_from_slice(b"_foo\0");

        let binary = MachoBinary {
            data,
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: Some(crate::macos::loader::header::MachHeader64 {
                magic: magic::MH_MAGIC_64,
                cputype: cpu_type::CPU_TYPE_X86_64,
                cpusubtype: 0,
                filetype: file_type::MH_EXECUTE,
                ncmds: 1,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            }),
            header_32: None,
            commands: vec![LoadCommand::Symtab(
                crate::macos::loader::command::SymtabCommand {
                    symoff: 0x20,
                    nsyms: 1,
                    stroff: 0x60,
                    strsize: 0x20,
                },
            )],
            segments: vec![],
            entry_point: None,
            is_driver: false,
            segments_data: HashMap::new(),
        };

        let sym = binary.get_symbol_by_index(0).unwrap();
        assert_eq!(sym.0, "_foo");
        assert_eq!(sym.1, 0x1234);

        let defined = binary.get_defined_symbols();
        assert_eq!(defined.get("_foo").copied(), Some(0x1234));
    }

    #[test]
    fn test_unixthread_x86_32_entry_parse() {
        use crate::macos::loader::command::UnixThreadCommand;
        use crate::macos::loader::consts::thread_flavor::X86_THREAD_STATE32;

        let mut data = vec![0u8; 8 + 64];
        data[0..4].copy_from_slice(&X86_THREAD_STATE32.to_le_bytes());
        data[4..8].copy_from_slice(&(16_u32).to_le_bytes());
        data[8 + 40..8 + 44].copy_from_slice(&(0x401000_u32).to_le_bytes()); // eip

        let cmd = UnixThreadCommand::parse(&data, false).unwrap();
        assert_eq!(cmd.entry, 0x401000);
        assert!(cmd.registers.x86_32.is_some());
    }

    #[test]
    fn test_unixthread_arm32_entry_parse() {
        use crate::macos::loader::command::UnixThreadCommand;
        use crate::macos::loader::consts::thread_flavor::ARM_THREAD_STATE32;

        let mut data = vec![0u8; 8 + 68];
        data[0..4].copy_from_slice(&ARM_THREAD_STATE32.to_le_bytes());
        data[4..8].copy_from_slice(&(17_u32).to_le_bytes());
        data[8 + 15 * 4..8 + 16 * 4].copy_from_slice(&(0x81234_u32).to_le_bytes()); // pc

        let cmd = UnixThreadCommand::parse(&data, false).unwrap();
        assert_eq!(cmd.entry, 0x81234);
        assert!(cmd.registers.arm32.is_some());
        assert!(cmd.registers.x86_32.is_none());
    }

    #[test]
    fn test_load_macho_32_segment_and_entry() {
        let seg = crate::macos::loader::command::SegmentCommand32 {
            segname: *b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            vmaddr: 0x1000,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 4,
            maxprot: 0x5,
            initprot: 0x5,
            nsects: 0,
            flags: 0,
            sections: vec![],
        };
        let thread = crate::macos::loader::command::UnixThreadCommand {
            flavor: thread_flavor::X86_THREAD_STATE32,
            count: 16,
            entry: 0x1000,
            registers: crate::macos::loader::command::ThreadRegisters::default(),
        };

        let mut segments_data = HashMap::new();
        segments_data.insert("__TEXT".to_string(), vec![0x90, 0x90, 0xc3, 0x00]);

        let binary = MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic32,
            header_64: None,
            header_32: None,
            commands: vec![LoadCommand::Segment(seg), LoadCommand::Unixthread(thread)],
            segments: vec![],
            entry_point: Some(0x1000),
            is_driver: false,
            segments_data,
        };

        let mut loader = MachOLoader::new(binary);
        let mut emu = TestEmulator::new(0x20000);
        loader.load(&mut emu, 0x8000, 0x2000, 0x3000).unwrap();

        assert_eq!(loader.get_entry_point(), 0x1000);
        assert_eq!(loader.get_load_address(), 0x1000);
        assert_eq!(emu.read_memory(0x1000, 3).unwrap(), vec![0x90, 0x90, 0xc3]);
    }

    #[test]
    fn test_setup_registers_uses_unixthread_arm64() {
        let regs: command::Arm64ThreadState = crate::macos::loader::command::Arm64ThreadState {
            x0: 1,
            x1: 2,
            x2: 3,
            x3: 4,
            x4: 5,
            x5: 6,
            x6: 7,
            x7: 8,
            x8: 9,
            x9: 10,
            x10: 11,
            x11: 12,
            x12: 13,
            x13: 14,
            x14: 15,
            x15: 16,
            x16: 17,
            x17: 18,
            x18: 19,
            x19: 20,
            x20: 21,
            x21: 22,
            x22: 23,
            x23: 24,
            x24: 25,
            x25: 26,
            x26: 27,
            x27: 28,
            x28: 29,
            x29: 30,
            sp: 0x10000,
            pc: 0x20000,
        };

        let thread = crate::macos::loader::command::UnixThreadCommand {
            flavor: thread_flavor::ARM_THREAD_STATE64,
            count: 33,
            entry: regs.pc,
            registers: crate::macos::loader::command::ThreadRegisters {
                x86_32: None,
                x86_64: None,
                arm32: None,
                arm64: Some(regs),
            },
        };

        let binary = MachoBinary {
            data: vec![],
            magic: crate::macos::loader::header::MachOMagic::Magic64,
            header_64: Some(crate::macos::loader::header::MachHeader64 {
                magic: magic::MH_MAGIC_64,
                cputype: cpu_type::CPU_TYPE_ARM64,
                cpusubtype: 0,
                filetype: file_type::MH_EXECUTE,
                ncmds: 1,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            }),
            header_32: None,
            commands: vec![LoadCommand::Unixthread(thread)],
            segments: vec![],
            entry_point: Some(0),
            is_driver: false,
            segments_data: HashMap::new(),
        };

        let mut loader = MachOLoader::new(binary);
        loader.entry_point = 0x3333;
        loader.stack_sp = 0x10000;

        let mut emu = TestEmulator::with_arch(0x10000, ArchType::Arm64);
        loader.setup_registers(&mut emu).unwrap();

        assert_eq!(emu.read_reg("x0").unwrap(), 1);
        assert_eq!(emu.read_reg("x28").unwrap(), 29);
        assert_eq!(emu.read_reg("fp").unwrap(), 30);
        assert_eq!(emu.read_reg("sp").unwrap(), 0x10000);
        assert_eq!(emu.read_reg("pc").unwrap(), 0x20000);
    }
}
