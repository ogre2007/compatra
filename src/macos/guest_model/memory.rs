//! Compatibility facade for the analysis-owned guest memory helpers.

pub use machina_analysis::guest_model::memory::*;

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
