//! Guest memory helpers used by Mach-O runners and synthetic imports.

use crate::{Emulator, MacOsError, UnicornEmulator};

pub fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

pub fn alloc_bytes(
    emulator: &mut UnicornEmulator,
    cursor: &mut u64,
    bytes: &[u8],
) -> Result<u64, MacOsError> {
    let addr = *cursor;
    emulator.write_memory(addr, bytes)?;
    *cursor = align_up(addr + bytes.len() as u64, 8);
    Ok(addr)
}

pub fn alloc_cstr(
    emulator: &mut UnicornEmulator,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, MacOsError> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    alloc_bytes(emulator, cursor, &bytes)
}

pub fn stack_push_u64(
    emulator: &mut UnicornEmulator,
    sp: &mut u64,
    value: u64,
) -> Result<u64, MacOsError> {
    *sp -= 8;
    emulator.write_memory(*sp, &value.to_le_bytes())?;
    Ok(*sp)
}

pub fn stack_push_u32(
    emulator: &mut UnicornEmulator,
    sp: &mut u64,
    value: u32,
) -> Result<u64, MacOsError> {
    *sp -= 4;
    emulator.write_memory(*sp, &value.to_le_bytes())?;
    Ok(*sp)
}

pub fn read_cstring(
    emu: &mut dyn Emulator,
    addr: u64,
    max_len: usize,
) -> Result<String, MacOsError> {
    let mut out = Vec::new();
    for i in 0..max_len {
        let b = emu.read_memory(addr + i as u64, 1)?;
        if b.is_empty() || b[0] == 0 {
            break;
        }
        out.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

pub fn read_arm64_argv(
    emu: &mut dyn Emulator,
    argv_ptr: u64,
    max_args: usize,
    max_len: usize,
) -> Vec<String> {
    let mut argv = Vec::new();
    for i in 0..max_args {
        let ptr_addr = argv_ptr + (i as u64) * 8;
        let Ok(bytes) = emu.read_memory(ptr_addr, 8) else {
            break;
        };
        let Some(ptr_bytes) = bytes.get(..8) else {
            break;
        };
        let arg_ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap_or([0; 8]));
        if arg_ptr == 0 {
            break;
        }
        argv.push(read_cstring(emu, arg_ptr, max_len).unwrap_or_default());
    }
    argv
}

pub fn push_recent_trace(
    trace: &std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    entry: String,
) {
    if let Ok(mut items) = trace.lock() {
        if items.len() >= 12 {
            items.pop_front();
        }
        items.push_back(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_rounds_to_next_boundary() {
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x2000, 0x1000), 0x2000);
    }
}
