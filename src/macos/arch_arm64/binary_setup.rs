//! Binary-specific setup helpers for the legacy arm64 runner.

use std::collections::HashMap;

use crate::macos::{
    process_event, runtime_process_metadata, section_indirect_symbol_name, SharedTraceBus,
};
use crate::{Emulator, MachoBinary, UnicornEmulator};

#[derive(Clone, Copy, Debug, Default)]
pub struct Arm64RuntimeSymbols {
    pub tls_g: Option<u64>,
    pub firstmoduledata: Option<u64>,
    pub libc_close_trampoline: Option<u64>,
    pub libc_dup2_trampoline: Option<u64>,
    pub libc_execve_trampoline: Option<u64>,
}

pub fn find_arm64_runtime_symbols(binary: &MachoBinary) -> Arm64RuntimeSymbols {
    Arm64RuntimeSymbols {
        tls_g: crate::macos::find_symbol_address(binary, "_runtime.tls_g"),
        firstmoduledata: crate::macos::find_symbol_address(binary, "_runtime.firstmoduledata"),
        libc_close_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_close_trampoline",
        ),
        libc_dup2_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_dup2_trampoline",
        ),
        libc_execve_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_execve_trampoline",
        ),
    }
}

pub fn log_arm64_runtime_symbols(
    symbols: Arm64RuntimeSymbols,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) {
    if let Some(addr) = symbols.tls_g {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "runtime-symbol",
            "runtime_symbol",
            &[
                ("Name", "_runtime.tls_g".to_string()),
                ("Address", format!("0x{:X}", addr)),
            ],
        );
    }
    if let Some(addr) = symbols.firstmoduledata {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "runtime-symbol",
            "runtime_symbol",
            &[
                ("Name", "_runtime.firstmoduledata".to_string()),
                ("Address", format!("0x{:X}", addr)),
            ],
        );
    }
}

pub fn patch_arm64_symbol_pointers(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    stub_map: &HashMap<String, u64>,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(la_symbol_ptr) = binary.get_lazy_symbol_ptr_section() {
        let la_addr = la_symbol_ptr.addr;
        let la_size = la_symbol_ptr.size;
        if la_size > 0 {
            let page_size = 0x1000;
            let aligned_size = ((la_size + page_size - 1) / page_size) * page_size;
            let _ = emulator.map_writable_code_memory(la_addr, aligned_size);
            let num_stubs = la_size / 8;
            for i in 0..num_stubs {
                let got_addr = la_addr + (i * 8);
                if let Some(sym_name) = section_indirect_symbol_name(binary, la_symbol_ptr, i) {
                    let target = stub_map.get(&sym_name).copied().unwrap_or(done_addr);
                    let _ = emulator.write_memory(got_addr, &target.to_le_bytes());
                } else {
                    let _ = emulator.write_memory(got_addr, &done_addr.to_le_bytes());
                }
            }
            emit_arm64_binary_event(
                trace_bus,
                process_name,
                "lazy-symbol-ptrs",
                "patch_symbol_pointers",
                &[
                    ("Section", "__la_symbol_ptr".to_string()),
                    ("Address", format!("0x{:X}", la_addr)),
                    ("Count", num_stubs.to_string()),
                ],
            );
        }
    }

    if let Some(nl_symbol_ptr) = binary.get_nl_symbol_ptr_section() {
        let nl_addr = nl_symbol_ptr.addr;
        let nl_size = nl_symbol_ptr.size;
        if nl_size > 0 {
            let page_size = 0x1000;
            let aligned_size = ((nl_size + page_size - 1) / page_size) * page_size;
            let _ = emulator.map_writable_code_memory(nl_addr, aligned_size);
            let count = nl_size / 8;
            let mut patched = 0u64;
            for i in 0..count {
                let slot_addr = nl_addr + i * 8;
                let target = if let Some(sym_name) =
                    section_indirect_symbol_name(binary, nl_symbol_ptr, i)
                {
                    stub_map.get(&sym_name).copied().unwrap_or(done_addr)
                } else {
                    done_addr
                };
                let _ = emulator.write_memory(slot_addr, &target.to_le_bytes());
                patched += 1;
            }
            emit_arm64_binary_event(
                trace_bus,
                process_name,
                "nonlazy-symbol-ptrs",
                "patch_symbol_pointers",
                &[
                    ("Section", "__nl_symbol_ptr".to_string()),
                    ("Address", format!("0x{:X}", nl_addr)),
                    ("Count", patched.to_string()),
                ],
            );
        }
    }

    Ok(())
}

pub fn resolve_arm64_entry(binary: &MachoBinary) -> u64 {
    let entry = binary.entry_point.unwrap_or(0);
    if entry >= 0x100000000 && entry < 0x300000000 {
        entry
    } else if let Some(seg) = binary.segments.iter().find(|s| s.segname_str() == "__TEXT") {
        seg.vmaddr + entry
    } else {
        entry
    }
}

fn emit_arm64_binary_event(
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
    name: impl Into<String>,
    call: impl Into<String>,
    args: &[(&str, String)],
) {
    if let Some(bus) = trace_bus {
        let mut event = process_event(
            &runtime_process_metadata(process_name.to_string()),
            name,
            call,
        );
        for (key, value) in args {
            event = event.arg(*key, value.clone());
        }
        let _ = bus.send(event);
    }
}
