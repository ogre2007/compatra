//! Compatibility-mode adapter for Machina's emulator trait.
//!
//! Host proxy behavior lives in `machina-compat`. This module only adapts the
//! main crate's `Emulator` trait into the guest-memory trait that the compat
//! crate consumes, keeping compatibility logic out of the analysis runtime.

use crate::macos::{Emulator, RuntimeMode};

pub use machina_compat::{HostCallResult, HostIoResult, HostOpenResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityServices;

struct EmulatorGuestMemory<'a> {
    emulator: &'a mut dyn Emulator,
}

impl machina_compat::GuestMemory for EmulatorGuestMemory<'_> {
    fn read_memory(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<Vec<u8>, machina_compat::GuestMemoryError> {
        self.emulator
            .read_memory(addr, size)
            .map_err(|_| machina_compat::GuestMemoryError)
    }

    fn write_memory(
        &mut self,
        addr: u64,
        data: &[u8],
    ) -> Result<(), machina_compat::GuestMemoryError> {
        self.emulator
            .write_memory(addr, data)
            .map_err(|_| machina_compat::GuestMemoryError)
    }
}

impl CompatibilityServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        machina_compat::CompatibilityServices::for_mode(mode).map(|_| Self)
    }

    pub fn should_proxy_import(&self, symbol: &str) -> bool {
        machina_compat::CompatibilityServices.should_proxy_import(symbol)
    }

    pub fn proxy_cstring_arg0_import(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        arg0_ptr: u64,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_cstring_arg0_import(
            &mut memory,
            symbol,
            arg0_ptr,
        )
    }

    pub fn proxy_arm64_import(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        args: &[u64; 8],
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_arm64_import(&mut memory, symbol, args)
    }

    pub fn proxy_arm64_import_with_stack(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        args: &[u64; 8],
        stack_ptr: Option<u64>,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_arm64_import_with_stack(
            &mut memory,
            symbol,
            args,
            stack_ptr,
        )
    }

    pub fn open_path_arg0(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.open_path_arg0(&mut memory, path_ptr, flags, mode)
    }

    pub fn read_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.read_fd(&mut memory, fd, buf_ptr, count)
    }

    pub fn write_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.write_fd(&mut memory, fd, buf_ptr, count)
    }

    pub fn close_fd(&self, fd: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.close_fd(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_mode_has_no_compat_services() {
        assert_eq!(CompatibilityServices::for_mode(RuntimeMode::Analysis), None);
        assert_eq!(
            CompatibilityServices::for_mode(RuntimeMode::Compat),
            Some(CompatibilityServices)
        );
    }

    #[test]
    fn host_proxy_imports_are_darwin_bound() {
        let compat = CompatibilityServices;
        #[cfg(target_os = "macos")]
        {
            assert!(compat.should_proxy_import("_puts"));
            assert!(compat.should_proxy_import("_printf"));
            assert!(compat.should_proxy_import("_putchar"));
        }
        #[cfg(not(target_os = "macos"))]
        assert!(!compat.should_proxy_import("_puts"));
    }
}
