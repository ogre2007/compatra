//! arm64 import-stub installation and tracking.
//!
//! The no-dyld runner resolves undefined symbols into tiny arm64 stubs. This
//! module owns the stub bytes, import-hit tracking, and arm64 ABI handoff into
//! architecture-neutral compatibility services.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::macos::compat::CompatibilityServices;
use crate::macos::plugin_events::import_event;
use crate::macos::{
    emit_runner_trace_event, process_event, push_recent_trace, runtime_process_metadata, Emulator,
    RuntimeMode, SharedTraceBus, StubRegion, TraceEvent, TraceMetadata,
};
use crate::UnicornEmulator;
use machina_arch_arm64::stubs::{IMPORT_STUB_STRIDE, RETURN_STUB_BYTES, RETURN_ZERO_STUB_BYTES};

#[derive(Clone, Debug)]
pub struct Arm64ImportTracker {
    pub last_stub: Arc<Mutex<Option<String>>>,
    pub import_count: Arc<AtomicUsize>,
    pub recent_imports: Arc<Mutex<VecDeque<String>>>,
}

pub fn initialize_arm64_import_tracker() -> Arm64ImportTracker {
    Arm64ImportTracker {
        last_stub: Arc::new(Mutex::new(None)),
        import_count: Arc::new(AtomicUsize::new(0)),
        recent_imports: Arc::new(Mutex::new(VecDeque::new())),
    }
}

pub fn record_arm64_import(tracker: &Arm64ImportTracker, summary: impl Into<String>) {
    tracker.import_count.fetch_add(1, Ordering::Relaxed);
    push_recent_trace(&tracker.recent_imports, summary.into());
}

fn emit_arm64_event(bus: &Option<SharedTraceBus>, event: TraceEvent) {
    emit_runner_trace_event(bus, &TraceMetadata::new(), event);
}

fn arm64_stub_bytes(symbol: &str, runtime_mode: RuntimeMode) -> &'static [u8] {
    let compat = CompatibilityServices::for_mode(runtime_mode);
    if compat.is_some_and(|compat| compat.should_proxy_import(symbol)) {
        RETURN_STUB_BYTES
    } else {
        RETURN_ZERO_STUB_BYTES
    }
}

fn arm64_proxy_compat_host_import(
    emu: &mut dyn Emulator,
    symbol: &str,
    compat: CompatibilityServices,
) {
    let mut args = [0u64; 8];
    for (idx, arg) in args.iter_mut().enumerate() {
        let Ok(value) = emu.read_reg(&format!("x{idx}")) else {
            return;
        };
        *arg = value;
    }

    if let Some(result) = compat.proxy_arm64_import(emu, symbol, &args) {
        let _ = emu.write_reg("x0", result.return_value);
    };
}

pub fn install_arm64_return_stubs(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    undefs: &[(String, u8)],
    tracker: &Arm64ImportTracker,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
    runtime_mode: RuntimeMode,
) -> Result<
    (
        HashMap<String, u64>,
        Arc<Mutex<HashMap<u64, String>>>,
        Arc<Mutex<u64>>,
    ),
    Box<dyn std::error::Error>,
> {
    let compat = CompatibilityServices::for_mode(runtime_mode);
    let mut stub_addr = stub_region.base;
    let mut stub_map = HashMap::new();
    for (name, _) in undefs {
        while stub_addr == stub_region.done_addr || Some(stub_addr) == stub_region.thread_exit_stub
        {
            stub_addr += IMPORT_STUB_STRIDE;
        }
        let _ = emulator.write_memory(stub_addr, arm64_stub_bytes(name, runtime_mode));
        stub_map.insert(name.clone(), stub_addr);
        emit_arm64_event(
            trace_bus,
            process_event(
                &runtime_process_metadata(process_name.to_string()),
                "import-stub",
                "install_import_stub",
            )
            .arg("Symbol", name.clone())
            .arg("StubAddr", format!("0x{:X}", stub_addr)),
        );
        stub_addr += IMPORT_STUB_STRIDE;
    }

    let next_dynamic_stub_addr = Arc::new(Mutex::new(stub_addr));
    let stub_name_map = Arc::new(Mutex::new(
        stub_map
            .iter()
            .map(|(name, addr)| (*addr, name.clone()))
            .collect::<HashMap<u64, String>>(),
    ));
    let last_stub_for_hook = tracker.last_stub.clone();
    let import_count_for_hook = tracker.import_count.clone();
    let recent_imports_for_hook = tracker.recent_imports.clone();
    let stub_name_map_for_hook = stub_name_map.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let process_name_for_hook = process_name.to_string();
    let compat_for_hook = compat;
    emulator.add_code_hook(
        stub_region.base,
        stub_region.base + stub_region.size,
        move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
            let bucket = stub_region.bucket(address);
            let name = stub_name_map_for_hook
                .lock()
                .ok()
                .and_then(|symbols| symbols.get(&bucket).cloned());
            if let Some(name) = name {
                import_count_for_hook.fetch_add(1, Ordering::Relaxed);
                push_recent_trace(
                    &recent_imports_for_hook,
                    format!("{} @ 0x{:X}", name, address),
                );
                emit_arm64_event(
                    &trace_bus_for_hook,
                    import_event(
                        &runtime_process_metadata(process_name_for_hook.clone()),
                        name.clone(),
                        "import-hit",
                    )
                    .arg("Address", format!("0x{:X}", address))
                    .arg("lr", format!("0x{:X}", emu.read_reg("lr").unwrap())),
                );
                if address == bucket {
                    if let Some(compat) = compat_for_hook {
                        arm64_proxy_compat_host_import(emu, &name, compat);
                    }
                }
                if let Ok(mut slot) = last_stub_for_hook.lock() {
                    *slot = Some(format!("{} @ 0x{:X}", name, address));
                }
            } else {
                emit_arm64_event(
                    &trace_bus_for_hook,
                    process_event(
                        &runtime_process_metadata(process_name_for_hook.clone()),
                        "<unknown>",
                        "import-hit",
                    )
                    .arg("Address", format!("0x{:X}", address))
                    .arg("lr", format!("0x{:X}", emu.read_reg("lr").unwrap())),
                );
            }
        },
    )?;

    Ok((stub_map, stub_name_map, next_dynamic_stub_addr))
}

pub fn allocate_arm64_dynamic_import_stub(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    next_stub_addr: &Arc<Mutex<u64>>,
    stub_name_map: &Arc<Mutex<HashMap<u64, String>>>,
    symbol: &str,
    runtime_mode: RuntimeMode,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Option<u64> {
    let mut next = next_stub_addr.lock().ok()?;
    while *next == stub_region.done_addr || Some(*next) == stub_region.thread_exit_stub {
        *next = (*next).saturating_add(IMPORT_STUB_STRIDE);
    }
    if *next >= stub_region.base.saturating_add(stub_region.size) {
        return None;
    }
    let addr = *next;
    *next = (*next).saturating_add(IMPORT_STUB_STRIDE);
    if emulator
        .write_memory(addr, arm64_stub_bytes(symbol, runtime_mode))
        .is_err()
    {
        return None;
    }
    if let Ok(mut symbols) = stub_name_map.lock() {
        symbols.insert(addr, symbol.to_string());
    }
    emit_arm64_event(
        trace_bus,
        process_event(
            &runtime_process_metadata(process_name.to_string()),
            "dynamic-import-stub",
            "install_dynamic_import_stub",
        )
        .arg("Symbol", symbol.to_string())
        .arg("StubAddr", format!("0x{:X}", addr)),
    );
    Some(addr)
}
