use crate::macos::{Emulator, MacOsError};
use crate::UnicornEmulator;
use compatra_arch_arm64::stubs::{
    DONE_STUB_OFFSET, IMPORT_STUB_STRIDE, RETURN_STUB_BYTES, STUB_REGION_BASE, STUB_REGION_SIZE,
    THREAD_EXIT_STUB_OFFSET,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubIsa {
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubRegion {
    pub base: u64,
    pub size: u64,
    pub done_addr: u64,
    pub thread_exit_stub: Option<u64>,
}

impl StubIsa {
    fn base(self) -> u64 {
        match self {
            Self::Arm64 => STUB_REGION_BASE,
        }
    }

    fn size(self) -> u64 {
        match self {
            Self::Arm64 => STUB_REGION_SIZE,
        }
    }

    fn done_bytes(self) -> &'static [u8] {
        match self {
            Self::Arm64 => RETURN_STUB_BYTES,
        }
    }
}

impl StubRegion {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.base.saturating_add(self.size)
    }

    pub fn bucket(&self, address: u64) -> u64 {
        self.base + ((address.saturating_sub(self.base)) / IMPORT_STUB_STRIDE) * IMPORT_STUB_STRIDE
    }
}

pub fn install_stub_region(
    emulator: &mut UnicornEmulator,
    isa: StubIsa,
    needs_thread_exit_stub: bool,
) -> Result<StubRegion, MacOsError> {
    let base = isa.base();
    let size = isa.size();
    emulator.map_code_memory(base, size)?;

    let done_addr = base + DONE_STUB_OFFSET;
    emulator.write_memory(done_addr, isa.done_bytes())?;

    let thread_exit_stub = if needs_thread_exit_stub {
        let addr = base + THREAD_EXIT_STUB_OFFSET;
        emulator.write_memory(addr, isa.done_bytes())?;
        Some(addr)
    } else {
        None
    };

    Ok(StubRegion {
        base,
        size,
        done_addr,
        thread_exit_stub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_stub_region_keeps_thread_exit_slot_outside_done_slot() {
        let region = StubRegion {
            base: StubIsa::Arm64.base(),
            size: StubIsa::Arm64.size(),
            done_addr: StubIsa::Arm64.base() + 0x800,
            thread_exit_stub: Some(StubIsa::Arm64.base() + 0x900),
        };

        assert!(region.contains(region.done_addr));
        assert!(region.contains(region.thread_exit_stub.unwrap()));
        assert_ne!(region.done_addr, region.thread_exit_stub.unwrap());
        assert_eq!(region.bucket(region.done_addr + 0x42), region.done_addr);
    }
}
