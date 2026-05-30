//! Compatibility-mode host service boundary.
//!
//! Architecture hooks should translate guest ABI details, then delegate
//! host-backed behavior here. This keeps compat policy separate from both
//! malware-analysis services and arm64 stub plumbing.

#[cfg(target_os = "macos")]
use std::ffi::CString;

#[cfg(target_os = "macos")]
use crate::macos::read_cstring;
use crate::macos::{Emulator, RuntimeMode};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityServices;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCallResult {
    pub return_value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostImportKind {
    #[cfg(target_os = "macos")]
    Puts,
}

impl CompatibilityServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        (!mode.is_analysis()).then_some(Self)
    }

    pub fn should_proxy_import(&self, symbol: &str) -> bool {
        host_import_kind(symbol).is_some()
    }

    pub fn proxy_cstring_arg0_import(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        arg0_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(not(target_os = "macos"))]
        let _ = (&mut *emu, arg0_ptr);

        match host_import_kind(symbol)? {
            #[cfg(target_os = "macos")]
            HostImportKind::Puts => proxy_host_puts(emu, arg0_ptr),
        }
    }
}

fn host_import_kind(symbol: &str) -> Option<HostImportKind> {
    #[cfg(target_os = "macos")]
    {
        match normalize_import_name(symbol) {
            "puts" => Some(HostImportKind::Puts),
            _ => None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = symbol;
        None
    }
}

#[cfg(target_os = "macos")]
fn normalize_import_name(symbol: &str) -> &str {
    symbol.strip_prefix('_').unwrap_or(symbol)
}

#[cfg(target_os = "macos")]
fn proxy_host_puts(emu: &mut dyn Emulator, arg0_ptr: u64) -> Option<HostCallResult> {
    let text = read_cstring(emu, arg0_ptr, 4096).ok()?;
    let host_text = CString::new(text).ok()?;
    let ret = unsafe { libc::puts(host_text.as_ptr()) };
    Some(HostCallResult {
        return_value: ret as u32 as u64,
    })
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
        assert!(compat.should_proxy_import("_puts"));
        #[cfg(not(target_os = "macos"))]
        assert!(!compat.should_proxy_import("_puts"));
    }
}
