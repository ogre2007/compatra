//! arm64 dynamic import hooks (`dlopen` / `dlsym`).
//!
//! Guest code cannot receive raw host pointers on Intel macOS. `dlsym`
//! therefore returns guest arm64 trampoline addresses backed by Machina's
//! import-stub dispatch table.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::macos::apple_imports::is_apple_import_symbol;
use crate::macos::arm64_import_stubs::{allocate_arm64_dynamic_import_stub, Arm64ImportTracker};
use crate::macos::arm64_runner_support::{
    arm64_process_event, emit_arm64_event, record_arm64_import, Arm64SharedState,
};
use crate::macos::compat::CompatibilityServices;
use crate::macos::{read_cstring, Emulator, RuntimeMode, SharedTraceBus, StubRegion};
use crate::UnicornEmulator;
use machina_arch_arm64::abi::DYNAMIC_IMPORT_HANDLE_BASE;

pub fn install_arm64_dynamic_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    stub_region: StubRegion,
    stub_name_map: Arc<Mutex<HashMap<u64, String>>>,
    next_dynamic_stub_addr: Arc<Mutex<u64>>,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(compat) = CompatibilityServices::for_mode(shared_state.runtime_mode) else {
        return Ok(());
    };
    let handles = Arc::new(Mutex::new(HashMap::<u64, Option<String>>::new()));
    let next_handle = Arc::new(Mutex::new(DYNAMIC_IMPORT_HANDLE_BASE));
    let dynamic_symbols = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
    let unresolved_symbols = Arc::new(Mutex::new(HashSet::<String>::new()));

    if let Some(&addr) = stub_map.get("_dlopen") {
        let handles = handles.clone();
        let next_handle = next_handle.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let flags = emu.read_reg("x1").unwrap_or(0);
                let path = if path_ptr == 0 {
                    None
                } else {
                    Some(read_cstring(emu, path_ptr, 4096).unwrap_or_default())
                };
                let handle = {
                    let mut next = match next_handle.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let handle = *next;
                    *next = (*next).saturating_add(1);
                    if let Ok(mut handles) = handles.lock() {
                        handles.insert(handle, path.clone());
                    }
                    handle
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", handle);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dlopen(path={:?}, flags=0x{:X}) -> 0x{:X}",
                        path, flags, handle
                    ),
                );
                let event = arm64_process_event(1, 1, "dlopen", "dlopen")
                    .arg("HostProxy", "true")
                    .arg("Path", path.unwrap_or_else(|| "<self>".to_string()))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Handle", format!("0x{:X}", handle));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dlsym") {
        let handles = handles.clone();
        let dynamic_symbols = dynamic_symbols.clone();
        let unresolved_symbols = unresolved_symbols.clone();
        let next_dynamic_stub_addr = next_dynamic_stub_addr.clone();
        let stub_name_map = stub_name_map.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let process_name = process_name.to_string();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let symbol_ptr = emu.read_reg("x1").unwrap_or(0);
                let symbol = read_cstring(emu, symbol_ptr, 512).unwrap_or_default();
                let handle_known = handle == 0
                    || handle >= u64::MAX.saturating_sub(8)
                    || handles
                        .lock()
                        .ok()
                        .is_some_and(|handles| handles.contains_key(&handle));
                let result = if handle_known
                    && (compat.should_proxy_import(&symbol) || is_apple_import_symbol(&symbol))
                {
                    if let Some(existing) = dynamic_symbols
                        .lock()
                        .ok()
                        .and_then(|symbols| symbols.get(&symbol).copied())
                    {
                        existing
                    } else {
                        let Some(stub_addr) = allocate_arm64_dynamic_import_stub(
                            emu,
                            stub_region,
                            &next_dynamic_stub_addr,
                            &stub_name_map,
                            &symbol,
                            RuntimeMode::Compat,
                            &trace_bus_for_hook,
                            &process_name,
                        ) else {
                            return;
                        };
                        if let Ok(mut symbols) = dynamic_symbols.lock() {
                            symbols.insert(symbol.clone(), stub_addr);
                        }
                        stub_addr
                    }
                } else {
                    0
                };
                if result == 0 {
                    let reason = if handle_known {
                        "no compat proxy or Apple dynamic dispatcher"
                    } else {
                        "unknown dlopen handle"
                    };
                    let log_key = format!("0x{handle:X}:{symbol}");
                    let should_log = unresolved_symbols
                        .lock()
                        .ok()
                        .is_some_and(|mut seen| seen.insert(log_key));
                    if should_log {
                        compat.log_unresolved_dlsym(handle, &symbol, reason);
                    }
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dlsym(handle=0x{:X}, symbol={:?}) -> 0x{:X}",
                        handle, symbol, result
                    ),
                );
                let event = arm64_process_event(1, 1, "dlsym", "dlsym")
                    .arg("HostProxy", "true")
                    .arg("Handle", format!("0x{:X}", handle))
                    .arg("Symbol", symbol)
                    .arg("Result", format!("0x{:X}", result));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dlclose") {
        let handles = handles.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut handles) = handles.lock() {
                    handles.remove(&handle);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_dlclose(handle=0x{:X}) -> 0", handle),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dlerror") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, "_dlerror() -> NULL");
            },
        )?;
    }

    Ok(())
}
