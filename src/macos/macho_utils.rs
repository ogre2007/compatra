//! Small Mach-O helpers shared by runners and import patching code.

use crate::macos::loader::command::{
    DysymtabCommand, LoadCommand, Section32, Section64, SymtabCommand,
};
use crate::{Emulator, MachoBinary};

pub fn get_symtab_cmd(binary: &MachoBinary) -> Option<&SymtabCommand> {
    binary.commands.iter().find_map(|cmd| {
        if let LoadCommand::Symtab(symtab) = cmd {
            Some(symtab)
        } else {
            None
        }
    })
}

pub fn get_dysymtab_cmd(binary: &MachoBinary) -> Option<&DysymtabCommand> {
    binary.commands.iter().find_map(|cmd| {
        if let LoadCommand::Dysymtab(dysymtab) = cmd {
            Some(dysymtab)
        } else {
            None
        }
    })
}

pub fn symbol_name_by_index(binary: &MachoBinary, sym_index: u32) -> Option<String> {
    let symtab = get_symtab_cmd(binary)?;
    if sym_index >= symtab.nsyms {
        return None;
    }
    let base = symtab.symoff as usize + sym_index as usize * 16;
    if base + 16 > binary.data.len() {
        return None;
    }

    let strx = u32::from_le_bytes(binary.data[base..base + 4].try_into().ok()?);
    if strx == 0 || strx >= symtab.strsize {
        return None;
    }
    let str_off = symtab.stroff as usize + strx as usize;
    if str_off >= binary.data.len() {
        return None;
    }
    let end = binary.data[str_off..]
        .iter()
        .position(|&c| c == 0)
        .map(|n| str_off + n)
        .unwrap_or(binary.data.len());
    if end <= str_off {
        return None;
    }
    Some(String::from_utf8_lossy(&binary.data[str_off..end]).to_string())
}

pub fn find_symbol_address(binary: &MachoBinary, wanted: &str) -> Option<u64> {
    let symtab = get_symtab_cmd(binary)?;
    for sym_index in 0..symtab.nsyms {
        let base = symtab.symoff as usize + sym_index as usize * 16;
        if base + 16 > binary.data.len() {
            break;
        }
        let strx = u32::from_le_bytes(binary.data[base..base + 4].try_into().ok()?);
        if strx >= symtab.strsize {
            continue;
        }
        let str_off = symtab.stroff as usize + strx as usize;
        if str_off >= binary.data.len() {
            continue;
        }
        let end = binary.data[str_off..]
            .iter()
            .position(|&c| c == 0)
            .map(|n| str_off + n)
            .unwrap_or(binary.data.len());
        if end <= str_off {
            continue;
        }
        let name = String::from_utf8_lossy(&binary.data[str_off..end]);
        if name == wanted {
            let value_off = base + 8;
            return Some(u64::from_le_bytes(
                binary.data[value_off..value_off + 8].try_into().ok()?,
            ));
        }
    }
    None
}

pub fn file_backed_slice_for_vmaddr(binary: &MachoBinary, addr: u64, size: usize) -> Option<&[u8]> {
    for seg in &binary.segments {
        let file_start = seg.vmaddr;
        let file_end = seg.vmaddr.saturating_add(seg.filesize);
        let end_addr = addr.saturating_add(size as u64);
        if addr >= file_start && end_addr <= file_end {
            let start = seg.fileoff as usize + (addr - seg.vmaddr) as usize;
            let end = start.saturating_add(size);
            if end <= binary.data.len() {
                return Some(&binary.data[start..end]);
            }
        }
    }
    None
}

pub fn reload_file_backed_range(
    emulator: &mut dyn Emulator,
    binary: &MachoBinary,
    addr: u64,
    size: usize,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const CHUNK: usize = 0x1000;
    let mut offset = 0usize;
    while offset < size {
        let chunk_len = (size - offset).min(CHUNK);
        let chunk_addr = addr + offset as u64;
        if let Some(bytes) = file_backed_slice_for_vmaddr(binary, chunk_addr, chunk_len) {
            emulator.write_memory(chunk_addr, bytes)?;
        } else {
            return Err(format!(
                "No file-backed range for {} at 0x{:X} size 0x{:X}",
                label, chunk_addr, chunk_len
            )
            .into());
        }
        offset += chunk_len;
    }
    println!(
        "[PATCH][arm64] Reloaded {} at 0x{:X} (size 0x{:X})",
        label, addr, size
    );
    Ok(())
}

pub fn section_indirect_symbol_name(
    binary: &MachoBinary,
    section: &Section64,
    slot: u64,
) -> Option<String> {
    let dysymtab = get_dysymtab_cmd(binary)?;
    let indirect_index = section.reserved1 as u64 + slot;
    if indirect_index >= dysymtab.nindirectsyms as u64 {
        return None;
    }
    let off = dysymtab.indirectsymoff as usize + indirect_index as usize * 4;
    if off + 4 > binary.data.len() {
        return None;
    }
    let sym_index = u32::from_le_bytes(binary.data[off..off + 4].try_into().ok()?);

    const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
    const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
    if (sym_index & INDIRECT_SYMBOL_LOCAL) != 0 || (sym_index & INDIRECT_SYMBOL_ABS) != 0 {
        return None;
    }

    symbol_name_by_index(binary, sym_index)
}

pub fn section32_indirect_symbol_name(
    binary: &MachoBinary,
    section: &Section32,
    slot: u64,
) -> Option<String> {
    let dysymtab = get_dysymtab_cmd(binary)?;
    let indirect_index = section.reserved1 as u64 + slot;
    if indirect_index >= dysymtab.nindirectsyms as u64 {
        return None;
    }
    let off = dysymtab.indirectsymoff as usize + indirect_index as usize * 4;
    if off + 4 > binary.data.len() {
        return None;
    }
    let sym_index = u32::from_le_bytes(binary.data[off..off + 4].try_into().ok()?);

    const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
    const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
    if (sym_index & INDIRECT_SYMBOL_LOCAL) != 0 || (sym_index & INDIRECT_SYMBOL_ABS) != 0 {
        return None;
    }

    symbol_name_by_index(binary, sym_index)
}

pub fn patch_section64_u64_slots<F>(
    emulator: &mut dyn Emulator,
    binary: &MachoBinary,
    section: &Section64,
    mut value_for_slot: F,
) -> u64
where
    F: FnMut(u64, u64, Option<String>, Option<&[u8]>) -> Option<u64>,
{
    let count = section.size / 8;
    let mut patched = 0;
    for i in 0..count {
        let slot_addr = section.addr + i * 8;
        let sym_name = section_indirect_symbol_name(binary, section, i);
        let current = emulator.read_memory(slot_addr, 8).ok();
        if let Some(value) = value_for_slot(i, slot_addr, sym_name, current.as_deref()) {
            let _ = emulator.write_memory(slot_addr, &value.to_le_bytes());
            patched += 1;
        }
    }
    patched
}

pub fn trim_name(name: &[u8; 16]) -> String {
    String::from_utf8_lossy(&name[..name.iter().position(|&c| c == 0).unwrap_or(16)]).to_string()
}
