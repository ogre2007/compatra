//! Mach-O binary parser

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::macos::loader::command::{
    DysymtabCommand, LoadCommand, Section64, SegmentCommand64, SymtabCommand,
};
use crate::macos::loader::consts::*;
use crate::macos::loader::header::{FatArch, FatHeader, MachHeader, MachHeader64, MachOMagic};
use crate::macos::MacOsError;

#[derive(Debug, Clone)]
pub struct RelocationInfo {
    pub address: u64,
    pub symbolnum: u32,
    pub pcrel: bool,
    pub length: u8,
    pub is_extern: bool,
    pub rtype: u8,
}

/// Represents a parsed Mach-O binary
#[derive(Debug, Clone)]
pub struct MachoBinary {
    pub data: Vec<u8>,
    pub magic: MachOMagic,
    pub header_64: Option<MachHeader64>,
    pub header_32: Option<MachHeader>,
    pub commands: Vec<LoadCommand>,
    pub segments: Vec<SegmentCommand64>,
    pub entry_point: Option<u64>,
    pub is_driver: bool,
    pub segments_data: HashMap<String, Vec<u8>>,
}

impl MachoBinary {
    fn symbol_entry_size(&self) -> usize {
        if self.is_64_bit() {
            16
        } else {
            12
        }
    }

    fn get_symtab_cmd(&self) -> Option<&SymtabCommand> {
        self.commands.iter().find_map(|cmd| {
            if let LoadCommand::Symtab(symtab) = cmd {
                Some(symtab)
            } else {
                None
            }
        })
    }

    fn get_dysymtab_cmd(&self) -> Option<&DysymtabCommand> {
        self.commands.iter().find_map(|cmd| {
            if let LoadCommand::Dysymtab(dysymtab) = cmd {
                Some(dysymtab)
            } else {
                None
            }
        })
    }

    fn decode_relocation(&self, offset: usize) -> Option<RelocationInfo> {
        if offset + 8 > self.data.len() {
            return None;
        }

        let r_address = i32::from_le_bytes(self.data[offset..offset + 4].try_into().ok()?) as i64;
        let r_info = u32::from_le_bytes(self.data[offset + 4..offset + 8].try_into().ok()?);

        Some(RelocationInfo {
            address: r_address as u64,
            symbolnum: r_info & 0x00ff_ffff,
            pcrel: ((r_info >> 24) & 0x1) != 0,
            length: ((r_info >> 25) & 0x3) as u8,
            is_extern: ((r_info >> 27) & 0x1) != 0,
            rtype: ((r_info >> 28) & 0xf) as u8,
        })
    }

    fn parse_relocations_at(&self, rel_offset: u32, rel_count: u32) -> Vec<RelocationInfo> {
        let mut out = Vec::new();
        let mut offset = rel_offset as usize;

        for _ in 0..rel_count {
            if let Some(reloc) = self.decode_relocation(offset) {
                out.push(reloc);
            } else {
                break;
            }

            offset = offset.saturating_add(8);
        }

        out
    }

    fn read_symbol_name(&self, strx: u32) -> Option<String> {
        let symtab = self.get_symtab_cmd()?;
        if strx == 0 || strx >= symtab.strsize {
            return None;
        }

        let str_offset = symtab.stroff as usize + strx as usize;
        if str_offset >= self.data.len() {
            return None;
        }

        let end = self.data[str_offset..]
            .iter()
            .position(|&c| c == 0)
            .map(|n| str_offset + n)
            .unwrap_or(self.data.len());

        if end <= str_offset {
            return None;
        }

        Some(String::from_utf8_lossy(&self.data[str_offset..end]).to_string())
    }

    pub fn get_symbol_by_index(&self, index: usize) -> Option<(String, u64, u8)> {
        let symtab = self.get_symtab_cmd()?;
        if index >= symtab.nsyms as usize {
            return None;
        }

        let entry_size = self.symbol_entry_size();
        let offset = symtab.symoff as usize + index * entry_size;
        if offset + entry_size > self.data.len() {
            return None;
        }

        let n_strx = u32::from_le_bytes(self.data[offset..offset + 4].try_into().ok()?);
        let n_type = self.data[offset + 4];

        let n_value = if self.is_64_bit() {
            u64::from_le_bytes(self.data[offset + 8..offset + 16].try_into().ok()?)
        } else {
            u32::from_le_bytes(self.data[offset + 8..offset + 12].try_into().ok()?) as u64
        };

        let name = self.read_symbol_name(n_strx).unwrap_or_default();
        Some((name, n_value, n_type))
    }

    pub fn get_defined_symbols(&self) -> HashMap<String, u64> {
        let mut symbols = HashMap::new();
        let symtab = match self.get_symtab_cmd() {
            Some(s) => s,
            None => return symbols,
        };

        let entry_size = self.symbol_entry_size();

        for i in 0..symtab.nsyms as usize {
            if let Some((name, value, n_type)) = self.get_symbol_by_index(i) {
                // Keep only section-defined symbols and skip empty symbol names.
                if !name.is_empty() && (n_type & 0x0e) == 0x0e {
                    symbols.insert(name, value);
                }
            } else {
                break;
            }

            let next = symtab.symoff as usize + (i + 1) * entry_size;
            if next > self.data.len() {
                break;
            }
        }

        symbols
    }

    pub fn get_dysymtab_relocations(&self) -> (Vec<RelocationInfo>, Vec<RelocationInfo>) {
        let dysymtab = match self.get_dysymtab_cmd() {
            Some(d) => d,
            None => return (Vec::new(), Vec::new()),
        };

        let local = self.parse_relocations_at(dysymtab.locreloff, dysymtab.nlocrel);
        let external = self.parse_relocations_at(dysymtab.extreloff, dysymtab.nextrel);

        (local, external)
    }

    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self, MacOsError> {
        let data = fs::read(path)
            .map_err(|e| MacOsError::LoaderError(format!("Failed to read file: {}", e)))?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self, MacOsError> {
        if data.len() < 4 {
            return Err(MacOsError::LoaderError(
                "File too short for Mach-O header".to_string(),
            ));
        }

        let magic_bytes = [data[0], data[1], data[2], data[3]];
        let magic_le = u32::from_le_bytes(magic_bytes);

        let magic_type = MachOMagic::from_u32(magic_le);

        let is_cigam = MachOMagic::is_cigam(magic_le);

        match magic_type {
            MachOMagic::Fat => {
                return Self::parse_fat(data);
            }
            MachOMagic::Magic32 => {
                let (header, actual_big_endian) = MachHeader::parse_with_auto_detect(data)
                    .map_err(|e| MacOsError::LoaderError(format!("Header parse error: {}", e)))?;
                let commands =
                    Self::parse_commands(data, header.ncmds as usize, 28, actual_big_endian)?;
                return Self::build_binary(data, magic_type, Some(header), None, commands);
            }
            MachOMagic::Magic64 => {
                let (header, actual_big_endian) = MachHeader64::parse_with_auto_detect(data)
                    .map_err(|e| MacOsError::LoaderError(format!("Header parse error: {}", e)))?;

                match Self::parse_commands(data, header.ncmds as usize, 32, actual_big_endian) {
                    Ok(commands) => {
                        return Self::build_binary(data, magic_type, None, Some(header), commands);
                    }
                    Err(_) if is_cigam => {
                        let (header2, _) =
                            MachHeader64::parse_with_auto_detect(data).map_err(|e| {
                                MacOsError::LoaderError(format!("Header parse error: {}", e))
                            })?;
                        let commands2 =
                            Self::parse_commands(data, header2.ncmds as usize, 32, false)?;
                        return Self::build_binary(
                            data,
                            magic_type,
                            None,
                            Some(header2),
                            commands2,
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
            MachOMagic::Unknown => {
                if MachOMagic::is_cigam(magic_le) {
                    let (header, actual_big_endian) = MachHeader64::parse_with_auto_detect(data)
                        .map_err(|e| {
                            MacOsError::LoaderError(format!("Header parse error: {}", e))
                        })?;
                    let commands =
                        Self::parse_commands(data, header.ncmds as usize, 32, actual_big_endian)?;
                    return Self::build_binary(
                        data,
                        MachOMagic::Magic64,
                        None,
                        Some(header),
                        commands,
                    );
                }
                return Err(MacOsError::LoaderError(format!(
                    "Unknown Mach-O magic: 0x{:08x}",
                    magic_le
                )));
            }
        }
    }

    fn parse_fat(data: &[u8]) -> Result<Self, MacOsError> {
        let fat_header = FatHeader::parse(data)?;

        let mut architectures = Vec::new();
        let arch_size = 20;

        for i in 0..fat_header.nfat_arch {
            let offset = 8 + (i as usize * arch_size);
            if offset + arch_size <= data.len() {
                if let Ok(arch) = FatArch::parse(&data[offset..]) {
                    architectures.push(arch);
                }
            }
        }

        let preferred_arch = architectures
            .iter()
            .find(|a| {
                a.cputype == cpu_type::CPU_TYPE_X86_64 || a.cputype == cpu_type::CPU_TYPE_ARM64
            })
            .or(architectures.first());

        if let Some(arch) = preferred_arch {
            if data.len() >= arch.offset as usize + arch.size as usize {
                let slice = &data[arch.offset as usize..][..arch.size as usize];
                return Self::parse(slice);
            }
        }

        Err(MacOsError::LoaderError(
            "Failed to parse FAT binary".to_string(),
        ))
    }

    fn parse_commands(
        data: &[u8],
        ncmds: usize,
        header_size: usize,
        big_endian: bool,
    ) -> Result<Vec<LoadCommand>, MacOsError> {
        let mut commands = Vec::new();
        let mut offset = header_size;

        for _ in 0..ncmds {
            if offset + 8 > data.len() {
                break;
            }

            match LoadCommand::parse(&data[offset..], big_endian) {
                Ok((cmd, cmd_size)) => {
                    commands.push(cmd);
                    offset += cmd_size;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(commands)
    }

    fn build_binary(
        data: &[u8],
        magic: MachOMagic,
        header_32: Option<MachHeader>,
        header_64: Option<MachHeader64>,
        commands: Vec<LoadCommand>,
    ) -> Result<Self, MacOsError> {
        let is_driver = header_64
            .as_ref()
            .map(|h| h.is_driver())
            .or(header_32.as_ref().map(|h| h.is_driver()))
            .unwrap_or(false);

        let mut segments = Vec::new();
        let mut segments_data = HashMap::new();
        let mut entry_point = None;

        for cmd in &commands {
            match cmd {
                LoadCommand::Segment64(seg) => {
                    let seg_name = seg.segname_str();
                    if seg.filesize > 0 && seg.fileoff < data.len() as u64 {
                        let end = (seg.fileoff + seg.filesize) as usize;
                        if end <= data.len() {
                            segments_data
                                .insert(seg_name.clone(), data[seg.fileoff as usize..end].to_vec());
                        }
                    }
                    segments.push(seg.clone());
                }
                LoadCommand::Segment(seg) => {
                    let seg_name = seg.segname_str();
                    if seg.filesize > 0 && seg.fileoff < data.len() as u32 {
                        let end = (seg.fileoff + seg.filesize) as usize;
                        if end <= data.len() {
                            segments_data
                                .insert(seg_name.clone(), data[seg.fileoff as usize..end].to_vec());
                        }
                    }
                }
                LoadCommand::Unixthread(cmd) => {
                    entry_point = Some(cmd.entry);
                }
                LoadCommand::Main(cmd) => {
                    entry_point = Some(cmd.entryoff);
                }
                _ => {}
            }
        }

        Ok(Self {
            data: data.to_vec(),
            magic,
            header_64,
            header_32,
            commands,
            segments,
            entry_point,
            is_driver,
            segments_data,
        })
    }

    pub fn get_segment(&self, name: &str) -> Option<&Vec<u8>> {
        self.segments_data.get(name)
    }

    pub fn get_segment_by_name(&self, name: &str) -> Option<&SegmentCommand64> {
        self.segments.iter().find(|s| s.segname_str() == name)
    }

    pub fn page_zero_size(&self) -> u64 {
        for cmd in &self.commands {
            match cmd {
                LoadCommand::Segment64(seg) if seg.vmaddr == 0 && seg.filesize == 0 => {
                    return seg.vmsize;
                }
                LoadCommand::Segment(seg) if seg.vmaddr == 0 && seg.filesize == 0 => {
                    return seg.vmsize as u64;
                }
                _ => {}
            }
        }
        self.segments
            .iter()
            .find(|s| s.vmaddr == 0 && s.filesize == 0)
            .map(|s| s.vmsize)
            .unwrap_or(0)
    }

    pub fn header_address(&self) -> u64 {
        self.page_zero_size()
    }

    pub fn is_64_bit(&self) -> bool {
        self.magic.is_64_bit()
    }

    pub fn get_text_section(&self) -> Option<&Section64> {
        for seg in &self.segments {
            if seg.segname_str() == "__TEXT" {
                for section in &seg.sections {
                    let section_name = String::from_utf8_lossy(
                        &section.sectname
                            [..section.sectname.iter().position(|&c| c == 0).unwrap_or(16)],
                    )
                    .to_string();
                    if section_name == "__text" {
                        return Some(section);
                    }
                }
            }
        }
        None
    }

    pub fn get_import_symbols(&self) -> HashMap<String, u64> {
        let mut symbols = HashMap::new();

        for cmd in &self.commands {
            if let LoadCommand::Symtab(symtab) = cmd {
                if symtab.nsyms > 0 && symtab.stroff < self.data.len() as u32 {
                    let sym_size = 16;
                    for i in 0..symtab.nsyms {
                        let offset = symtab.symoff as usize + (i as usize * sym_size);
                        if offset + sym_size <= self.data.len() {
                            let n_strx = u32::from_le_bytes([
                                self.data[offset],
                                self.data[offset + 1],
                                self.data[offset + 2],
                                self.data[offset + 3],
                            ]);
                            if n_strx > 0 && n_strx < symtab.strsize {
                                let str_offset = symtab.stroff as usize + n_strx as usize;
                                if str_offset < self.data.len() {
                                    let null_pos = self.data[str_offset..]
                                        .iter()
                                        .position(|&c| c == 0)
                                        .unwrap_or(64);
                                    let name = String::from_utf8_lossy(
                                        &self.data[str_offset..str_offset + null_pos],
                                    )
                                    .to_string();
                                    let n_value = u64::from_le_bytes([
                                        self.data[offset + 8],
                                        self.data[offset + 9],
                                        self.data[offset + 10],
                                        self.data[offset + 11],
                                        self.data[offset + 12],
                                        self.data[offset + 13],
                                        self.data[offset + 14],
                                        self.data[offset + 15],
                                    ]);
                                    if !name.is_empty() {
                                        symbols.insert(name, n_value);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        symbols
    }

    pub fn get_dyld_path(&self) -> Option<String> {
        for cmd in &self.commands {
            if let LoadCommand::Dylinker(dylinker) = cmd {
                return Some(dylinker.name.clone());
            }
        }
        None
    }

    pub fn get_dylib_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();
        for cmd in &self.commands {
            if let LoadCommand::Dylib(dylib) = cmd {
                paths.push(dylib.name.clone());
            }
        }
        paths
    }

    pub fn get_undefined_symbols(&self) -> Vec<(String, u8)> {
        let mut symbols = Vec::new();

        for cmd in &self.commands {
            if let LoadCommand::Symtab(symtab) = cmd {
                if symtab.nsyms == 0 || symtab.stroff >= self.data.len() as u32 {
                    continue;
                }

                let mut dysymtab_cmd = None;
                for c in &self.commands {
                    if let LoadCommand::Dysymtab(d) = c {
                        dysymtab_cmd = Some(d);
                        break;
                    }
                }

                let (undef_start, undef_count) = if let Some(d) = dysymtab_cmd {
                    (d.iundefsym, d.nundefsym)
                } else {
                    (0, 0)
                };

                if undef_count > 0 {
                    let sym_size = 16;
                    let start_offset = symtab.symoff as usize + (undef_start as usize * sym_size);

                    for i in 0..undef_count {
                        let offset = start_offset + (i as usize * sym_size);
                        if offset + sym_size > self.data.len() {
                            break;
                        }

                        let n_strx = u32::from_le_bytes([
                            self.data[offset],
                            self.data[offset + 1],
                            self.data[offset + 2],
                            self.data[offset + 3],
                        ]);

                        if n_strx > 0 && n_strx < symtab.strsize {
                            let str_offset = symtab.stroff as usize + n_strx as usize;
                            if str_offset < self.data.len() {
                                let null_pos = self.data[str_offset..]
                                    .iter()
                                    .position(|&c| c == 0)
                                    .unwrap_or(64);
                                let name = String::from_utf8_lossy(
                                    &self.data[str_offset..str_offset + null_pos],
                                )
                                .to_string();

                                let n_type = self.data[offset + 4];
                                let n_type_static = (n_type & 0x0E) == 0x0E;
                                let n_type_indirect = (n_type & 0x0E) == 0x0A;

                                if !name.is_empty() && !n_type_static && !n_type_indirect {
                                    symbols.push((name, n_type));
                                }
                            }
                        }
                    }
                }
            }
        }

        symbols
    }

    pub fn get_relocations(&self) -> Vec<RelocationInfo> {
        let (local, external) = self.get_dysymtab_relocations();
        let mut relocations = Vec::with_capacity(local.len() + external.len());
        relocations.extend(local);
        relocations.extend(external);
        relocations
    }

    pub fn get_got_relocations(&self) -> Vec<RelocationInfo> {
        self.get_relocations()
            .into_iter()
            .filter(|r| r.rtype == 3 || r.rtype == 4)
            .collect()
    }

    pub fn get_data_segment(&self) -> Option<&SegmentCommand64> {
        self.segments.iter().find(|s| s.segname_str() == "__DATA")
    }

    pub fn get_linkedit_segment(&self) -> Option<&SegmentCommand64> {
        self.segments
            .iter()
            .find(|s| s.segname_str() == "__LINKEDIT")
    }

    pub fn get_section(&self, seg_name: &str, sect_name: &str) -> Option<&Section64> {
        for seg in &self.segments {
            let s = seg.segname_str();

            if s == seg_name {
                for section in &seg.sections {
                    let sname = String::from_utf8_lossy(
                        &section.sectname
                            [..section.sectname.iter().position(|&c| c == 0).unwrap_or(16)],
                    )
                    .to_string();
                    if sname == sect_name {
                        return Some(section);
                    }
                }
            }
        }
        None
    }

    pub fn get_lazy_symbol_ptr_section(&self) -> Option<&Section64> {
        self.get_section("__DATA", "__la_symbol_ptr")
    }

    pub fn get_nl_symbol_ptr_section(&self) -> Option<&Section64> {
        self.get_section("__DATA", "__nl_symbol_ptr")
    }

    pub fn get_eh_section(&self) -> Option<&Section64> {
        self.get_section("__TEXT", "__eh_frame")
    }

    /// Parse binding information from the DyldInfoOnly load command
    pub fn parse_bindings(&self) -> Vec<(String, u64)> {
        let bindings = Vec::new();

        // Find the DyldInfoOnly command
        let mut dyld_info = None;
        for cmd in &self.commands {
            if let LoadCommand::DyldInfoOnly(info) = cmd {
                dyld_info = Some(info);
                break;
            }
        }

        if let Some(info) = dyld_info {
            // Parse binding info if present
            if info.binding_off > 0 && info.binding_size > 0 {
                // For simplicity, we'll just return an empty vector for now
                // A full implementation would parse the bind opcodes
                // This is a placeholder for the actual binding parsing logic
            }

            // Parse lazy binding info if present
            if info.lazy_binding_off > 0 && info.lazy_binding_size > 0 {
                // In a full implementation, we would parse the lazy bind opcodes here
            }
        }

        // For now, return symbols from lazy and non-lazy symbol pointer sections
        // This is a simplified approach - real binding would be more complex
        if let Some(section) = self.get_lazy_symbol_ptr_section() {
            // In a real implementation, we would parse the pointers in this section
            // and resolve them to actual addresses
            let _ = section;
        }

        if let Some(section) = self.get_nl_symbol_ptr_section() {
            // In a real implementation, we would parse the pointers in this section
            // and resolve them to actual addresses
            let _ = section;
        }

        bindings
    }

    /// Resolve an undefined symbol to its address
    pub fn resolve_symbol(&self, symbol_name: &str) -> Option<u64> {
        // First check in import symbols (defined symbols)
        let import_symbols = self.get_import_symbols();
        if let Some(addr) = import_symbols.get(symbol_name) {
            return Some(*addr);
        }

        // Check in undefined symbols (these would need to be resolved externally)
        let undefined_symbols = self.get_undefined_symbols();
        for (name, _) in undefined_symbols {
            if name == symbol_name {
                // Undefined symbols need to be resolved at runtime
                // Return None to indicate it needs external resolution
                return None;
            }
        }

        None
    }
}
