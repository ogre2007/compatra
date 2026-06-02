//! Guest memory helpers used by Mach-O runners and synthetic imports.

#[cfg(feature = "analysis")]
pub use machina_analysis::guest_model::memory::*;

#[cfg(not(feature = "analysis"))]
pub trait GuestMemoryAccess {
    type Error;

    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, Self::Error>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(not(feature = "analysis"))]
pub fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[cfg(not(feature = "analysis"))]
pub fn alloc_bytes<M: GuestMemoryAccess + ?Sized>(
    emulator: &mut M,
    cursor: &mut u64,
    bytes: &[u8],
) -> Result<u64, M::Error> {
    let addr = *cursor;
    emulator.write_memory(addr, bytes)?;
    *cursor = align_up(addr + bytes.len() as u64, 8);
    Ok(addr)
}

#[cfg(not(feature = "analysis"))]
pub fn alloc_cstr<M: GuestMemoryAccess + ?Sized>(
    emulator: &mut M,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, M::Error> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    alloc_bytes(emulator, cursor, &bytes)
}

#[cfg(not(feature = "analysis"))]
pub fn stack_push_u64<M: GuestMemoryAccess + ?Sized>(
    emulator: &mut M,
    sp: &mut u64,
    value: u64,
) -> Result<u64, M::Error> {
    *sp -= 8;
    emulator.write_memory(*sp, &value.to_le_bytes())?;
    Ok(*sp)
}

#[cfg(not(feature = "analysis"))]
pub fn stack_push_u32<M: GuestMemoryAccess + ?Sized>(
    emulator: &mut M,
    sp: &mut u64,
    value: u32,
) -> Result<u64, M::Error> {
    *sp -= 4;
    emulator.write_memory(*sp, &value.to_le_bytes())?;
    Ok(*sp)
}

#[cfg(not(feature = "analysis"))]
pub fn read_cstring<M: GuestMemoryAccess + ?Sized>(
    emu: &mut M,
    addr: u64,
    max_len: usize,
) -> Result<String, M::Error> {
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

#[cfg(not(feature = "analysis"))]
pub fn read_arm64_argv<M: GuestMemoryAccess + ?Sized>(
    emu: &mut M,
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

#[cfg(not(feature = "analysis"))]
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

use crate::macos::{Emulator, MacOsError};
use crate::unicorn::UnicornEmulator;

impl GuestMemoryAccess for UnicornEmulator {
    type Error = MacOsError;

    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, Self::Error> {
        Emulator::read_memory(self, addr, size)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), Self::Error> {
        Emulator::write_memory(self, addr, data)
    }
}

impl GuestMemoryAccess for dyn Emulator + '_ {
    type Error = MacOsError;

    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, Self::Error> {
        Emulator::read_memory(self, addr, size)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), Self::Error> {
        Emulator::write_memory(self, addr, data)
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
