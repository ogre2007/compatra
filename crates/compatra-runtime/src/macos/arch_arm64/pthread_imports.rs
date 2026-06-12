//! Pthread and TLS-related synthetic imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::macos::arm64_runner_support::{
    arm64_metadata, arm64_thread_event, emit_arm64_event, record_arm64_import, Arm64ImportTracker,
    Arm64SharedState,
};
use crate::macos::{
    block_active_arm64_thread_on_cond, block_current_arm64_thread_on_cond,
    dispatch_pending_arm64_thread, dispatch_pending_arm64_thread_by_id_with_exit_action,
    thread_event, yield_active_arm64_thread, Emulator, SharedTraceBus, StubRegion,
    ARM64_SYNTHETIC_THREAD_STACK_SIZE, MAX_SYNTHETIC_THREADS,
};
use crate::UnicornEmulator;
use compatra_threading::GuestThreadExitAction;

const DISPATCH_MAIN_QUEUE_HANDLE: u64 = 0x6D15_1000_0000;
const DISPATCH_GLOBAL_QUEUE_BASE: u64 = 0x6D15_2000_0000;
const DISPATCH_ONCE_DONE_SENTINEL: u64 = u64::MAX;
const PTHREAD_ONCE_DONE_SENTINEL: u64 = 0x4D41_4348_4F4E_4345;
const PTHREAD_ONCE_TRAMPOLINE_ADDR: u64 = 0x6D16_0000_0000;
const PTHREAD_ONCE_TRAMPOLINE_LR_SLOT: u64 = PTHREAD_ONCE_TRAMPOLINE_ADDR + 0x10;

fn normalized_dispatch_symbol(symbol: &str) -> &str {
    symbol.strip_prefix('_').unwrap_or(symbol)
}

fn is_dispatch_import_symbol(symbol: &str) -> bool {
    matches!(
        normalized_dispatch_symbol(symbol),
        "dispatch_get_main_queue"
            | "dispatch_get_global_queue"
            | "dispatch_queue_create"
            | "dispatch_async"
            | "dispatch_async_f"
            | "dispatch_sync"
            | "dispatch_sync_f"
            | "dispatch_once"
            | "dispatch_once_f"
            | "dispatch_release"
            | "dispatch_semaphore_create"
            | "dispatch_semaphore_signal"
            | "dispatch_semaphore_wait"
    )
}

fn read_guest_u64(emu: &mut dyn Emulator, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let bytes = emu.read_memory(addr, 8).ok()?;
    let array = <[u8; 8]>::try_from(bytes.as_slice()).ok()?;
    Some(u64::from_le_bytes(array))
}

fn dispatch_block_invoke(emu: &mut dyn Emulator, block_ptr: u64) -> Option<u64> {
    let invoke = read_guest_u64(emu, block_ptr.saturating_add(16))?;
    (invoke != 0).then_some(invoke)
}

fn current_thread_id(shared_state: &Arm64SharedState) -> u64 {
    shared_state
        .thread_runtime
        .lock()
        .ok()
        .map(|rt| rt.current_thread_id.max(1))
        .unwrap_or(1)
}

fn return_to_dispatch_caller(emu: &mut UnicornEmulator, result: u64) {
    let lr = emu.read_reg("lr").unwrap_or(0);
    let _ = emu.write_reg("x0", result);
    if lr != 0 {
        let _ = emu.write_reg("pc", lr);
    }
}

fn enter_dispatch_callback(emu: &mut UnicornEmulator, callback: u64, arg0: u64) -> bool {
    if callback == 0 {
        return false;
    }
    let lr = emu.read_reg("lr").unwrap_or(0);
    let _ = emu.write_reg("x0", arg0);
    if lr != 0 {
        let _ = emu.write_reg("lr", lr);
    }
    emu.write_reg("pc", callback).is_ok()
}

fn alloc_dispatch_queue(shared_state: &Arm64SharedState, label: impl Into<String>) -> u64 {
    let handle = {
        let mut next = match shared_state.dispatch_queue_next.lock() {
            Ok(next) => next,
            Err(_) => return 0,
        };
        let handle = *next;
        *next = next.saturating_add(0x100);
        handle
    };
    if let Ok(mut queues) = shared_state.dispatch_queues.lock() {
        queues.insert(handle, label.into());
    }
    handle
}

fn dispatch_once_should_call(
    emu: &mut UnicornEmulator,
    shared_state: &Arm64SharedState,
    token_ptr: u64,
) -> bool {
    if token_ptr == 0 {
        return false;
    }

    match read_guest_u64(emu, token_ptr) {
        Some(DISPATCH_ONCE_DONE_SENTINEL) => return false,
        Some(_) => {
            let _ = emu.write_memory(token_ptr, &DISPATCH_ONCE_DONE_SENTINEL.to_le_bytes());
            return true;
        }
        None => {}
    }

    let set_done = shared_state
        .dispatch_once_tokens
        .lock()
        .ok()
        .is_some_and(|tokens| tokens.contains(&token_ptr));
    if set_done {
        return false;
    }

    if let Ok(mut tokens) = shared_state.dispatch_once_tokens.lock() {
        tokens.insert(token_ptr);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::macos::arm64_runner_support::initialize_arm64_shared_state_with_mode;
    use crate::macos::{GuestProcessBootstrap, RuntimeMode};

    fn empty_bootstrap() -> GuestProcessBootstrap {
        GuestProcessBootstrap {
            argc: 0,
            arg0_addr: 0,
            env0_addr: 0,
            apple0_addr: 0,
            argv_addr: 0,
            envp_addr: 0,
            argc_addr: 0,
            ns_argv_ptr_addr: 0,
            ns_envp_ptr_addr: 0,
        }
    }

    #[test]
    fn dispatch_once_rechecks_guest_token_memory_for_reused_stack_addresses() {
        let mut emu = UnicornEmulator::new_arm64().expect("create arm64 emulator");
        emu.map_data_memory(0x1000, 0x1000)
            .expect("map token memory");
        let shared_state = initialize_arm64_shared_state_with_mode(
            std::env::temp_dir(),
            empty_bootstrap(),
            RuntimeMode::Compat,
        );
        let token_ptr = 0x1080;

        emu.write_memory(token_ptr, &0u64.to_le_bytes())
            .expect("initialize token");
        assert!(dispatch_once_should_call(
            &mut emu,
            &shared_state,
            token_ptr
        ));
        assert!(!dispatch_once_should_call(
            &mut emu,
            &shared_state,
            token_ptr
        ));

        emu.write_memory(token_ptr, &0u64.to_le_bytes())
            .expect("reuse stack slot with a fresh token");
        assert!(dispatch_once_should_call(
            &mut emu,
            &shared_state,
            token_ptr
        ));
    }
}

fn handle_dispatch_import(
    emu: &mut UnicornEmulator,
    symbol: &str,
    shared_state: &Arm64SharedState,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
) -> bool {
    let name = normalized_dispatch_symbol(symbol);
    let thread_id = current_thread_id(shared_state);
    match name {
        "dispatch_get_main_queue" => {
            return_to_dispatch_caller(emu, DISPATCH_MAIN_QUEUE_HANDLE);
            record_arm64_import(
                import_tracker,
                format!("_dispatch_get_main_queue() -> 0x{DISPATCH_MAIN_QUEUE_HANDLE:X}"),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-queue",
                "dispatch_get_main_queue",
            )
            .arg("Queue", format!("0x{DISPATCH_MAIN_QUEUE_HANDLE:X}"));
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_get_global_queue" => {
            let identifier = emu.read_reg("x0").unwrap_or(0);
            let flags = emu.read_reg("x1").unwrap_or(0);
            let queue = DISPATCH_GLOBAL_QUEUE_BASE | (identifier & 0xFFFF);
            return_to_dispatch_caller(emu, queue);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_get_global_queue(identifier={}, flags=0x{:X}) -> 0x{:X}",
                    identifier, flags, queue
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-queue",
                "dispatch_get_global_queue",
            )
            .arg("Identifier", identifier.to_string())
            .arg("Flags", format!("0x{flags:X}"))
            .arg("Queue", format!("0x{queue:X}"));
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_queue_create" => {
            let label_ptr = emu.read_reg("x0").unwrap_or(0);
            let attr = emu.read_reg("x1").unwrap_or(0);
            let label = if label_ptr == 0 {
                "dispatch.queue".to_string()
            } else {
                crate::macos::read_cstring(emu, label_ptr, 512)
                    .unwrap_or_else(|_| "dispatch.queue".to_string())
            };
            let queue = alloc_dispatch_queue(shared_state, label.clone());
            return_to_dispatch_caller(emu, queue);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_queue_create(label={:?}, attr=0x{:X}) -> 0x{:X}",
                    label, attr, queue
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-queue",
                "dispatch_queue_create",
            )
            .arg("Label", label)
            .arg("Attr", format!("0x{attr:X}"))
            .arg("Queue", format!("0x{queue:X}"));
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_async" | "dispatch_sync" => {
            let queue = emu.read_reg("x0").unwrap_or(0);
            let block = emu.read_reg("x1").unwrap_or(0);
            let invoke = dispatch_block_invoke(emu, block).unwrap_or(0);
            let entered = enter_dispatch_callback(emu, invoke, block);
            if !entered {
                return_to_dispatch_caller(emu, 0);
            }
            record_arm64_import(
                import_tracker,
                format!(
                    "_{}(queue=0x{:X}, block=0x{:X}, invoke=0x{:X}) -> inline={}",
                    name, queue, block, invoke, entered
                ),
            );
            let event = thread_event(&arm64_metadata(None, thread_id), "dispatch-block", name)
                .arg("Queue", format!("0x{queue:X}"))
                .arg("Block", format!("0x{block:X}"))
                .arg("Invoke", format!("0x{invoke:X}"))
                .arg("Inline", entered.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_async_f" | "dispatch_sync_f" => {
            let queue = emu.read_reg("x0").unwrap_or(0);
            let context = emu.read_reg("x1").unwrap_or(0);
            let work = emu.read_reg("x2").unwrap_or(0);
            let entered = enter_dispatch_callback(emu, work, context);
            if !entered {
                return_to_dispatch_caller(emu, 0);
            }
            record_arm64_import(
                import_tracker,
                format!(
                    "_{}(queue=0x{:X}, context=0x{:X}, work=0x{:X}) -> inline={}",
                    name, queue, context, work, entered
                ),
            );
            let event = thread_event(&arm64_metadata(None, thread_id), "dispatch-function", name)
                .arg("Queue", format!("0x{queue:X}"))
                .arg("Context", format!("0x{context:X}"))
                .arg("Work", format!("0x{work:X}"))
                .arg("Inline", entered.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_once" => {
            let token_ptr = emu.read_reg("x0").unwrap_or(0);
            let block = emu.read_reg("x1").unwrap_or(0);
            let invoke = dispatch_block_invoke(emu, block).unwrap_or(0);
            let should_call = dispatch_once_should_call(emu, shared_state, token_ptr);
            let entered = should_call && enter_dispatch_callback(emu, invoke, block);
            if !entered {
                return_to_dispatch_caller(emu, 0);
            }
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_once(token=0x{:X}, block=0x{:X}, invoke=0x{:X}) -> call={}",
                    token_ptr, block, invoke, entered
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-once",
                "dispatch_once",
            )
            .arg("Token", format!("0x{token_ptr:X}"))
            .arg("Block", format!("0x{block:X}"))
            .arg("Invoke", format!("0x{invoke:X}"))
            .arg("Called", entered.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_once_f" => {
            let token_ptr = emu.read_reg("x0").unwrap_or(0);
            let context = emu.read_reg("x1").unwrap_or(0);
            let function = emu.read_reg("x2").unwrap_or(0);
            let should_call = dispatch_once_should_call(emu, shared_state, token_ptr);
            let entered = should_call && enter_dispatch_callback(emu, function, context);
            if !entered {
                return_to_dispatch_caller(emu, 0);
            }
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_once_f(token=0x{:X}, context=0x{:X}, function=0x{:X}) -> call={}",
                    token_ptr, context, function, entered
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-once",
                "dispatch_once_f",
            )
            .arg("Token", format!("0x{token_ptr:X}"))
            .arg("Context", format!("0x{context:X}"))
            .arg("Function", format!("0x{function:X}"))
            .arg("Called", entered.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_semaphore_create" => {
            let initial = emu.read_reg("x0").unwrap_or(0) as i64;
            let handle = {
                let mut next = match shared_state.dispatch_semaphore_next.lock() {
                    Ok(next) => next,
                    Err(_) => return false,
                };
                let handle = *next;
                *next = next.saturating_add(0x100);
                handle
            };
            if let Ok(mut semaphores) = shared_state.dispatch_semaphores.lock() {
                semaphores.insert(handle, initial);
            }
            return_to_dispatch_caller(emu, handle);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_semaphore_create(value={}) -> 0x{:X}",
                    initial, handle
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-semaphore-create",
                "dispatch_semaphore_create",
            )
            .arg("Initial", initial.to_string())
            .arg("Handle", format!("0x{handle:X}"));
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_semaphore_signal" => {
            let handle = emu.read_reg("x0").unwrap_or(0);
            let value = {
                let mut semaphores = match shared_state.dispatch_semaphores.lock() {
                    Ok(semaphores) => semaphores,
                    Err(_) => return false,
                };
                let slot = semaphores.entry(handle).or_insert(0);
                *slot = slot.saturating_add(1);
                *slot
            };
            return_to_dispatch_caller(emu, 0);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_semaphore_signal(handle=0x{:X}) -> {}",
                    handle, value
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-semaphore-signal",
                "dispatch_semaphore_signal",
            )
            .arg("Handle", format!("0x{handle:X}"))
            .arg("Value", value.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_semaphore_wait" => {
            let handle = emu.read_reg("x0").unwrap_or(0);
            let timeout = emu.read_reg("x1").unwrap_or(0);
            let value = {
                let mut semaphores = match shared_state.dispatch_semaphores.lock() {
                    Ok(semaphores) => semaphores,
                    Err(_) => return false,
                };
                let slot = semaphores.entry(handle).or_insert(0);
                if *slot > 0 {
                    *slot -= 1;
                }
                *slot
            };
            return_to_dispatch_caller(emu, 0);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_semaphore_wait(handle=0x{:X}, timeout=0x{:X}) -> 0 value={}",
                    handle, timeout, value
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-semaphore-wait",
                "dispatch_semaphore_wait",
            )
            .arg("Handle", format!("0x{handle:X}"))
            .arg("Timeout", format!("0x{timeout:X}"))
            .arg("Value", value.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        "dispatch_release" => {
            let handle = emu.read_reg("x0").unwrap_or(0);
            let queue_existed = shared_state
                .dispatch_queues
                .lock()
                .ok()
                .and_then(|mut queues| queues.remove(&handle))
                .is_some();
            let semaphore_existed = shared_state
                .dispatch_semaphores
                .lock()
                .ok()
                .and_then(|mut semaphores| semaphores.remove(&handle))
                .is_some();
            return_to_dispatch_caller(emu, 0);
            record_arm64_import(
                import_tracker,
                format!(
                    "_dispatch_release(handle=0x{:X}) -> queue={} semaphore={}",
                    handle, queue_existed, semaphore_existed
                ),
            );
            let event = thread_event(
                &arm64_metadata(None, thread_id),
                "dispatch-release",
                "dispatch_release",
            )
            .arg("Handle", format!("0x{handle:X}"))
            .arg("Queue", queue_existed.to_string())
            .arg("Semaphore", semaphore_existed.to_string());
            emit_arm64_event(trace_bus, event);
            true
        }
        _ => false,
    }
}

fn install_dispatch_hook(
    emulator: &mut UnicornEmulator,
    addr: u64,
    symbol: String,
    shared_state: Arm64SharedState,
    trace_bus: Option<SharedTraceBus>,
    import_tracker: Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
            let _ =
                handle_dispatch_import(emu, &symbol, &shared_state, &trace_bus, &import_tracker);
        },
    )?;
    Ok(())
}

fn install_dispatch_dynamic_hook(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    stub_name_map: Arc<Mutex<HashMap<u64, String>>>,
    next_dynamic_stub_addr: Arc<Mutex<u64>>,
    shared_state: Arm64SharedState,
    trace_bus: Option<SharedTraceBus>,
    import_tracker: Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let dynamic_start = next_dynamic_stub_addr
        .lock()
        .ok()
        .map(|next| *next)
        .unwrap_or_else(|| stub_region.base.saturating_add(stub_region.size));
    let dynamic_end = stub_region.base.saturating_add(stub_region.size);
    if dynamic_start >= dynamic_end {
        return Ok(());
    }

    emulator.add_code_hook(
        dynamic_start,
        dynamic_end,
        move |emu: &mut compatra_runtime::UnicornEmulator, address: u64, _size: u32| {
            let bucket = stub_region.bucket(address);
            let symbol = stub_name_map
                .lock()
                .ok()
                .and_then(|symbols| symbols.get(&bucket).cloned());
            let Some(symbol) = symbol else {
                return;
            };
            if !is_dispatch_import_symbol(&symbol) {
                return;
            }
            let _ =
                handle_dispatch_import(emu, &symbol, &shared_state, &trace_bus, &import_tracker);
        },
    )?;
    Ok(())
}

fn install_pthread_once_trampoline(
    emulator: &mut UnicornEmulator,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&0xD2800000u32.to_le_bytes()); // mov x0, #0
    bytes.extend_from_slice(&0x58000070u32.to_le_bytes()); // ldr x16, #0xC
    bytes.extend_from_slice(&0xD61F0200u32.to_le_bytes()); // br x16
    bytes.extend_from_slice(&0xD503201Fu32.to_le_bytes()); // nop / align literal
    bytes.extend_from_slice(&0u64.to_le_bytes());
    emulator.map_writable_code_memory(PTHREAD_ONCE_TRAMPOLINE_ADDR, 0x1000)?;
    emulator.write_memory(PTHREAD_ONCE_TRAMPOLINE_ADDR, &bytes)?;
    Ok(PTHREAD_ONCE_TRAMPOLINE_ADDR)
}

pub fn install_arm64_pthread_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    stub_region: StubRegion,
    stub_name_map: Arc<Mutex<HashMap<u64, String>>>,
    next_dynamic_stub_addr: Arc<Mutex<u64>>,
    errno_ptr: u64,
    thread_exit_stub: u64,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let pthread_once_trampoline = if stub_map.contains_key("_pthread_once") {
        Some(install_pthread_once_trampoline(emulator)?)
    } else {
        None
    };

    install_dispatch_dynamic_hook(
        emulator,
        stub_region,
        stub_name_map,
        next_dynamic_stub_addr,
        shared_state.clone(),
        trace_bus.clone(),
        import_tracker.clone(),
    )?;

    for symbol in [
        "_dispatch_get_main_queue",
        "_dispatch_get_global_queue",
        "_dispatch_queue_create",
        "_dispatch_async",
        "_dispatch_async_f",
        "_dispatch_sync",
        "_dispatch_sync_f",
        "_dispatch_once",
        "_dispatch_once_f",
    ] {
        if let Some(&addr) = stub_map.get(symbol) {
            install_dispatch_hook(
                emulator,
                addr,
                symbol.to_string(),
                shared_state.clone(),
                trace_bus.clone(),
                import_tracker.clone(),
            )?;
        }
    }

    if let Some(&addr) = stub_map.get("_pthread_get_stackaddr_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let requested_thread = emu.read_reg("x0").unwrap_or(0);
                let (tid, stackaddr) = {
                    let runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    let tid = if requested_thread == 0 {
                        runtime.current_thread_id.max(1)
                    } else {
                        requested_thread
                    };
                    let stackaddr = if tid == 1 {
                        0x8000_0000_0000
                    } else {
                        runtime
                            .next_stack_base
                            .saturating_sub(crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE)
                            .saturating_add(crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE)
                    };
                    (tid, stackaddr)
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", stackaddr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_get_stackaddr_np(thread={}) -> 0x{:X}",
                        tid, stackaddr
                    ),
                );
                let event =
                    arm64_thread_event(tid, "pthread_get_stackaddr_np", "pthread_get_stackaddr_np")
                        .arg("Thread", tid.to_string())
                        .arg("Result", format!("0x{:X}", stackaddr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_get_stacksize_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let requested_thread = emu.read_reg("x0").unwrap_or(0);
                let tid = {
                    let runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if requested_thread == 0 {
                        runtime.current_thread_id.max(1)
                    } else {
                        requested_thread
                    }
                };
                let stacksize = if tid == 1 {
                    0x20_0000
                } else {
                    crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", stacksize);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_get_stacksize_np(thread={}) -> 0x{:X}",
                        tid, stacksize
                    ),
                );
                let event =
                    arm64_thread_event(tid, "pthread_get_stacksize_np", "pthread_get_stacksize_np")
                        .arg("Thread", tid.to_string())
                        .arg("Result", format!("0x{:X}", stacksize));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__tlv_bootstrap") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let tlv_next_addr = shared_state.tlv_next_addr.clone();
        let tlv_storage = shared_state.tlv_storage.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let descriptor = emu.read_reg("x0").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let value_addr = {
                    let mut storage = match tlv_storage.lock() {
                        Ok(storage) => storage,
                        Err(_) => return,
                    };
                    if let Some(existing) = storage.get(&(thread_id, descriptor)).copied() {
                        existing
                    } else {
                        let addr = {
                            let mut next = match tlv_next_addr.lock() {
                                Ok(next) => next,
                                Err(_) => return,
                            };
                            let addr = *next;
                            *next = next.saturating_add(0x1000);
                            addr
                        };
                        let _ = emu.map_data_memory(addr, 0x1000);
                        // Seed the new thread-local slot with whatever the
                        // main thread (tid=1) already has for the same
                        // descriptor. Rust thread-locals on real macOS are
                        // initialized from the binary's __thread_data
                        // template; since we don't read that template we
                        // fall back to the main thread's already-bootstrapped
                        // page so worker pthreads inherit non-zero defaults
                        // (e.g. the random-state slot the daemon's main
                        // thread populated via getentropy). Without this,
                        // the worker reads all zeros and Rust's "non-zero
                        // sentinel" thread-local invariants trip the
                        // panic-helper at 0x10000AE00.
                        let mut seed = [0u8; 0x1000];
                        if thread_id != 1 {
                            if let Some(&main_addr) = storage.get(&(1, descriptor)) {
                                if let Ok(bytes) = emu.read_memory(main_addr, 0x1000) {
                                    let len = bytes.len().min(seed.len());
                                    seed[..len].copy_from_slice(&bytes[..len]);
                                }
                            }
                        }
                        let _ = emu.write_memory(addr, &seed);
                        storage.insert((thread_id, descriptor), addr);
                        addr
                    }
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x8", value_addr);
                let _ = emu.write_reg("x0", value_addr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "__tlv_bootstrap(desc=0x{:X}, tid={}) -> 0x{:X}",
                        descriptor, thread_id, value_addr
                    ),
                );
                let event = arm64_thread_event(thread_id, "tlv-bootstrap", "__tlv_bootstrap")
                    .arg("Descriptor", format!("0x{:X}", descriptor))
                    .arg("Result", format!("0x{:X}", value_addr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__tlv_atexit") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let dtor = emu.read_reg("x0").unwrap_or(0);
                let object = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "__tlv_atexit(dtor=0x{:X}, object=0x{:X}) -> 0",
                        dtor, object
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "tlv-atexit",
                    "__tlv_atexit",
                )
                .arg("Dtor", format!("0x{:X}", dtor))
                .arg("Object", format!("0x{:X}", object));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_key_create") {
        let tls_next_key = shared_state.tls_next_key.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let key_ptr = emu.read_reg("x0").unwrap_or(0);
                let key = {
                    let mut next = tls_next_key.lock().unwrap();
                    let key = *next;
                    *next = next.saturating_add(1);
                    key
                };
                if key_ptr != 0 {
                    let _ = emu.write_memory(key_ptr, &(key as u32).to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_key_create(key_ptr=0x{:X}) -> key={}",
                        key_ptr, key
                    ),
                );
                println!("[IMPORT][arm64] _pthread_key_create -> key={}", key);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("___error") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", errno_ptr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("___error() -> 0x{:X}", errno_ptr));
                println!("[IMPORT][arm64] ___error -> 0x{:X}", errno_ptr);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_setspecific") {
        let tls_values = shared_state.tls_values.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let key = emu.read_reg("x0").unwrap_or(0);
                let value = emu.read_reg("x1").unwrap_or(0);
                if let Ok(mut map) = tls_values.lock() {
                    map.insert(key, value);
                }
                let tls_base = emu.read_reg("tpidrro_el0").unwrap_or(0);
                if tls_base != 0 {
                    let slot_addr = tls_base.saturating_add(key.saturating_mul(8));
                    let _ = emu.write_memory(slot_addr, &value.to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_setspecific(key={}, value=0x{:X}, tls_slot=0x{:X})",
                        key,
                        value,
                        tls_base.saturating_add(key.saturating_mul(8))
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_setspecific key={} value=0x{:X} tls_slot=0x{:X}",
                    key,
                    value,
                    tls_base.saturating_add(key.saturating_mul(8))
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_getspecific") {
        let tls_values = shared_state.tls_values.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let key = emu.read_reg("x0").unwrap_or(0);
                let value = tls_values
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&key).copied())
                    .unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", value);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_pthread_getspecific(key={}) -> 0x{:X}", key, value),
                );
                println!(
                    "[IMPORT][arm64] _pthread_getspecific key={} -> 0x{:X}",
                    key, value
                );
            },
        )?;
    }

    if let (Some(&addr), Some(trampoline_addr)) =
        (stub_map.get("_pthread_once"), pthread_once_trampoline)
    {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let once_ptr = emu.read_reg("x0").unwrap_or(0);
                let init_routine = emu.read_reg("x1").unwrap_or(0);
                let state = if once_ptr == 0 {
                    PTHREAD_ONCE_DONE_SENTINEL
                } else {
                    emu.read_memory(once_ptr, 8)
                        .ok()
                        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                        .map(u64::from_le_bytes)
                        .unwrap_or(0)
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let should_call =
                    once_ptr != 0 && init_routine != 0 && state != PTHREAD_ONCE_DONE_SENTINEL;
                if once_ptr != 0 && state != PTHREAD_ONCE_DONE_SENTINEL {
                    let _ = emu.write_memory(once_ptr, &PTHREAD_ONCE_DONE_SENTINEL.to_le_bytes());
                }
                let _ = emu.write_reg("x0", 0u64);
                if should_call {
                    let _ = emu.write_memory(PTHREAD_ONCE_TRAMPOLINE_LR_SLOT, &lr.to_le_bytes());
                    let _ = emu.write_reg("lr", trampoline_addr);
                    let _ = emu.write_reg("pc", init_routine);
                } else if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_once(control=0x{:X}, init=0x{:X}) -> 0 call={}",
                        once_ptr, init_routine, should_call
                    ),
                );
                let event = arm64_thread_event(thread_id, "pthread-once", "pthread_once")
                    .arg("Control", format!("0x{:X}", once_ptr))
                    .arg("InitRoutine", format!("0x{:X}", init_routine))
                    .arg("CalledInit", should_call.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_self") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", thread_id);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("_pthread_self() -> {}", thread_id));
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-self",
                    "pthread_self",
                )
                .arg("ThreadId", thread_id.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_threadid_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let requested_thread = emu.read_reg("x0").unwrap_or(0);
                let thread_id_ptr = emu.read_reg("x1").unwrap_or(0);
                let current_thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let thread_id = if requested_thread == 0 {
                    current_thread_id
                } else {
                    requested_thread
                };
                let result = if thread_id_ptr == 0 {
                    libc::EINVAL as u64
                } else if emu
                    .write_memory(thread_id_ptr, &thread_id.to_le_bytes())
                    .is_ok()
                {
                    0
                } else {
                    libc::EFAULT as u64
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_threadid_np(thread=0x{:X}, out=0x{:X}) -> {} tid={}",
                        requested_thread, thread_id_ptr, result, thread_id
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, current_thread_id),
                    "pthread-threadid-np",
                    "pthread_threadid_np",
                )
                .arg("RequestedThread", format!("0x{:X}", requested_thread))
                .arg("ThreadIdPtr", format!("0x{:X}", thread_id_ptr))
                .arg("ThreadId", thread_id.to_string())
                .arg("Result", result.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_setname_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let name_ptr = emu.read_reg("x0").unwrap_or(0);
                let name = if name_ptr != 0 {
                    crate::macos::read_cstring(emu, name_ptr, 256).unwrap_or_default()
                } else {
                    String::new()
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_setname_np(tid={}, name={:?}) -> 0",
                        thread_id, name
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-setname",
                    "pthread_setname_np",
                )
                .arg("ThreadId", thread_id.to_string())
                .arg("Name", name);
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_create") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let next_handle = shared_state.dispatch_semaphore_next.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let initial = emu.read_reg("x0").unwrap_or(0) as i64;
                let handle = {
                    let mut next = match next_handle.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let handle = *next;
                    *next = next.saturating_add(0x100);
                    handle
                };
                if let Ok(mut map) = semaphores.lock() {
                    map.insert(handle, initial);
                }
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", handle);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_create(value={}) -> 0x{:X}",
                        initial, handle
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-create",
                    "dispatch_semaphore_create",
                )
                .arg("Initial", initial.to_string())
                .arg("Handle", format!("0x{:X}", handle));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_signal") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let value = {
                    let mut map = match semaphores.lock() {
                        Ok(map) => map,
                        Err(_) => return,
                    };
                    let slot = map.entry(handle).or_insert(0);
                    *slot = slot.saturating_add(1);
                    *slot
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_signal(handle=0x{:X}) -> {}",
                        handle, value
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-signal",
                    "dispatch_semaphore_signal",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Value", value.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_wait") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let timeout = emu.read_reg("x1").unwrap_or(0);
                let (value, result) = {
                    let mut map = match semaphores.lock() {
                        Ok(map) => map,
                        Err(_) => return,
                    };
                    let slot = map.entry(handle).or_insert(0);
                    if *slot > 0 {
                        *slot -= 1;
                        (*slot, 0u64)
                    } else {
                        (*slot, 0u64)
                    }
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_wait(handle=0x{:X}, timeout=0x{:X}) -> {} value={}",
                        handle, timeout, result, value
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-wait",
                    "dispatch_semaphore_wait",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Timeout", format!("0x{:X}", timeout))
                .arg("Result", result.to_string())
                .arg("Value", value.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_release") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let existed = semaphores
                    .lock()
                    .ok()
                    .and_then(|mut map| map.remove(&handle))
                    .is_some();
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_release(handle=0x{:X}) -> existed={}",
                        handle, existed
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-release",
                    "dispatch_release",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Existed", existed.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_create") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let thread_ptr = emu.read_reg("x0").unwrap_or(0);
                let _attr = emu.read_reg("x1").unwrap_or(0);
                let start_routine = emu.read_reg("x2").unwrap_or(0);
                let arg = emu.read_reg("x3").unwrap_or(0);
                let parent_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let parent_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&parent_tid).copied())
                    .unwrap_or(1);

                let (result, thread_id) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    match runtime.reserve_guest_thread(
                        ARM64_SYNTHETIC_THREAD_STACK_SIZE,
                        MAX_SYNTHETIC_THREADS,
                    ) {
                        Ok(reservation) => {
                            let _ = emu.map_data_memory(
                                reservation.stack_base,
                                ARM64_SYNTHETIC_THREAD_STACK_SIZE,
                            );
                            let thread_id = reservation.thread_id;
                            runtime.enqueue_thread_start(
                                reservation,
                                start_routine,
                                arg,
                                thread_exit_stub,
                            );
                            (0u64, thread_id)
                        }
                        Err(_) => (11u64, 0u64),
                    }
                };
                if result == 0 {
                    if let Ok(mut os) = os_runtime.lock() {
                        os.process_thread_ids.insert(thread_id);
                        os.thread_processes.insert(thread_id, parent_pid);
                    }
                }

                if result == 0 && thread_ptr != 0 {
                    let _ = emu.write_memory(thread_ptr, &thread_id.to_le_bytes());
                }

                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }

                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_create(thread_ptr=0x{:X}, start=0x{:X}, arg=0x{:X}) -> {}",
                        thread_ptr, start_routine, arg, result
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(Some(parent_pid), parent_tid),
                    "pthread-create",
                    "pthread_create",
                )
                .arg("ThreadPtr", format!("0x{:X}", thread_ptr))
                .arg("StartRoutine", format!("0x{:X}", start_routine))
                .arg("Arg", format!("0x{:X}", arg))
                .arg("Result", result.to_string())
                .arg("ChildTid", thread_id.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_join") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let target_thread = emu.read_reg("x0").unwrap_or(0);
                let retval_ptr = emu.read_reg("x1").unwrap_or(0);
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let completed_result;
                let mut dispatched = false;
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    completed_result = runtime.take_thread_completion(target_thread);
                    if completed_result.is_none() {
                        if let Ok(did_dispatch) =
                            dispatch_pending_arm64_thread_by_id_with_exit_action(
                                emu,
                                &mut runtime,
                                target_thread,
                                GuestThreadExitAction::StoreResultAndReturn {
                                    result_addr: retval_ptr,
                                    return_value: 0,
                                },
                            )
                        {
                            dispatched = did_dispatch;
                        }
                    }
                }

                if dispatched {
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_pthread_join(thread={}, retval=0x{:X}, tid={}) -> dispatched",
                            target_thread, retval_ptr, current_tid
                        ),
                    );
                    let event = thread_event(
                        &arm64_metadata(None, current_tid),
                        "pthread-join",
                        "pthread_join",
                    )
                    .arg("Thread", target_thread.to_string())
                    .arg("RetvalPtr", format!("0x{:X}", retval_ptr))
                    .arg("Dispatched", "true");
                    emit_arm64_event(&trace_bus_for_hook, event);
                    return;
                }

                if let Some(result) = completed_result {
                    if retval_ptr != 0 {
                        let _ = emu.write_memory(retval_ptr, &result.to_le_bytes());
                    }
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_join(thread={}, retval=0x{:X}, tid={}, completed={}) -> 0",
                        target_thread,
                        retval_ptr,
                        current_tid,
                        completed_result.is_some()
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, current_tid),
                    "pthread-join",
                    "pthread_join",
                )
                .arg("Thread", target_thread.to_string())
                .arg("RetvalPtr", format!("0x{:X}", retval_ptr))
                .arg("Dispatched", "false")
                .arg("Completed", completed_result.is_some().to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_detach") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let target_thread = emu.read_reg("x0").unwrap_or(0);
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        rt.take_thread_completion(target_thread);
                        rt.current_thread_id.max(1)
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_detach(thread={}, tid={}) -> 0",
                        target_thread, current_tid
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, current_tid),
                    "pthread-detach",
                    "pthread_detach",
                )
                .arg("Thread", target_thread.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_exit") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let retval = emu.read_reg("x0").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let _ = emu.write_reg("x0", retval);
                let _ = emu.write_reg("pc", thread_exit_stub);
                record_arm64_import(
                    &import_tracker,
                    format!("_pthread_exit(retval=0x{:X}, tid={})", retval, thread_id),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-exit",
                    "pthread_exit",
                )
                .arg("Retval", format!("0x{:X}", retval));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_init") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let attr = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        rt.mutex_owners.remove(&mutex);
                        rt.current_thread_id.max(1)
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_init(mutex=0x{:X}, attr=0x{:X}, tid={}) -> 0",
                        mutex, attr, thread_id
                    ),
                );

                println!(
                    "[IMPORT][arm64] _pthread_mutex_init mutex=0x{:X} attr=0x{:X} tid={} -> 0",
                    mutex, attr, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_lock") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, owner_before) = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        let owner = rt.mutex_owners.get(&mutex).copied().unwrap_or(0);
                        rt.mutex_owners.insert(mutex, tid);
                        (tid, owner)
                    })
                    .unwrap_or((1, 0));
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_lock(mutex=0x{:X}, tid={}, prev_owner={}) -> 0",
                        mutex, thread_id, owner_before
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_mutex_lock mutex=0x{:X} tid={} prev_owner={} -> 0",
                    mutex, thread_id, owner_before
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_unlock") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, owner_before) = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        let owner = rt.mutex_owners.remove(&mutex).unwrap_or(0);
                        (tid, owner)
                    })
                    .unwrap_or((1, 0));
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_unlock(mutex=0x{:X}, tid={}, prev_owner={}) -> 0",
                        mutex, thread_id, owner_before
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_mutex_unlock mutex=0x{:X} tid={} prev_owner={} -> 0",
                    mutex, thread_id, owner_before
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_init") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let attr = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        rt.cond_signal_counts.remove(&cond);
                        rt.cond_waiters.remove(&cond);
                        rt.current_thread_id.max(1)
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_init(cond=0x{:X}, attr=0x{:X}, tid={}) -> 0",
                        cond, attr, thread_id
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_init cond=0x{:X} attr=0x{:X} tid={} -> 0",
                    cond, attr, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_wait") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let mutex = emu.read_reg("x1").unwrap_or(0);
                let mut dispatched = false;
                let mut synthetic_wake = false;
                let consumed_signal;
                let mut blocked_to = None;
                let mut blocked_current = false;
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    consumed_signal = runtime.consume_cond_signal(cond, mutex, thread_id);
                    if consumed_signal {
                        runtime.cond_wait_streaks.remove(&(cond, mutex));
                    } else {
                        runtime.mutex_owners.remove(&mutex);
                    }
                    if !consumed_signal
                        && runtime.active_thread.is_none()
                        && !runtime.pending_threads.is_empty()
                    {
                        if let Ok(did_block) = block_current_arm64_thread_on_cond(
                            emu,
                            &mut runtime,
                            cond,
                            mutex,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            blocked_current = did_block;
                        }
                    }
                    if blocked_current {
                        dispatched = true;
                    }
                    if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                        if !blocked_current
                            && did_dispatch
                            && runtime.active_thread.as_ref().map(|a| a.thread_id)
                                != Some(thread_id)
                        {
                            dispatched = true;
                        }
                    }
                    if !consumed_signal
                        && !dispatched
                        && runtime.active_thread.is_some()
                        && !runtime.pending_threads.is_empty()
                    {
                        if let Ok(result) = block_active_arm64_thread_on_cond(
                            emu,
                            &mut runtime,
                            cond,
                            mutex,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            blocked_to = result;
                        }
                    }
                    if !consumed_signal && !dispatched && blocked_to.is_none() {
                        let streak = runtime
                            .cond_wait_streaks
                            .entry((cond, mutex))
                            .and_modify(|v| *v = v.saturating_add(1))
                            .or_insert(1);
                        if *streak >= 8 {
                            *streak = 0;
                            synthetic_wake = true;
                        }
                    }
                }
                if dispatched {
                    println!(
                        "[THREAD][arm64] dispatch from pthread_cond_wait cond=0x{:X} mutex=0x{:X}",
                        cond, mutex
                    );
                    return;
                }
                if let Some((from_tid, to_tid)) = blocked_to {
                    println!(
                        "[THREAD][arm64] cond_wait block tid={} -> tid={} cond=0x{:X} mutex=0x{:X}",
                        from_tid, to_tid, cond, mutex
                    );
                    return;
                }

                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_wait(cond=0x{:X}, mutex=0x{:X}, tid={}, signal={}) -> wake={}",
                        cond,
                        mutex,
                        thread_id,
                        consumed_signal,
                        synthetic_wake || consumed_signal
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-cond-wait",
                    "pthread_cond_wait",
                )
                    .arg("Cond", format!("0x{:X}", cond))
                    .arg("Mutex", format!("0x{:X}", mutex))
                    .arg("Signal", consumed_signal.to_string())
                    .arg("Wake", (synthetic_wake || consumed_signal).to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_timedwait_relative_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let mutex = emu.read_reg("x1").unwrap_or(0);
                let abstime = emu.read_reg("x2").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        rt.consume_cond_signal(cond, mutex, tid);
                        tid
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_timedwait_relative_np(cond=0x{:X}, mutex=0x{:X}, abstime=0x{:X}, tid={}) -> 0",
                        cond, mutex, abstime, thread_id
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_timedwait_relative_np cond=0x{:X} mutex=0x{:X} abstime=0x{:X} tid={} -> 0",
                    cond, mutex, abstime, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_signal") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, pending_signals, woken_thread_id) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    let tid = runtime.current_thread_id.max(1);
                    let signal = runtime.signal_cond(cond);
                    (tid, signal.pending_signals, signal.woken_thread_id)
                };
                let mut yielded_to = None;
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if runtime.active_thread.is_some() && !runtime.pending_threads.is_empty() {
                        if let Ok(result) = yield_active_arm64_thread(
                            emu,
                            &mut runtime,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            yielded_to = result;
                        }
                    }
                }
                if let Some((from_tid, to_tid)) = yielded_to {
                    println!(
                        "[THREAD][arm64] signal yield tid={} -> tid={} cond=0x{:X}",
                        from_tid, to_tid, cond
                    );
                    return;
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_signal(cond=0x{:X}, tid={}, pending_signals={}, woken={:?}) -> 0",
                        cond, thread_id, pending_signals, woken_thread_id
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_signal cond=0x{:X} tid={} pending_signals={} -> 0",
                    cond, thread_id, pending_signals
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-cond-signal",
                    "pthread_cond_signal",
                )
                .arg("Cond", format!("0x{:X}", cond))
                .arg("PendingSignals", pending_signals.to_string())
                .arg(
                    "WokenThread",
                    woken_thread_id
                        .map(|tid| tid.to_string())
                        .unwrap_or_else(|| "0".to_string()),
                );
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_broadcast") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, woken_count) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    let tid = runtime.current_thread_id.max(1);
                    let woken = runtime.broadcast_cond(cond);
                    (tid, woken.len())
                };
                let mut yielded_to = None;
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if runtime.active_thread.is_some() && !runtime.pending_threads.is_empty() {
                        if let Ok(result) = yield_active_arm64_thread(
                            emu,
                            &mut runtime,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            yielded_to = result;
                        }
                    }
                }
                if let Some((from_tid, to_tid)) = yielded_to {
                    println!(
                        "[THREAD][arm64] broadcast yield tid={} -> tid={} cond=0x{:X}",
                        from_tid, to_tid, cond
                    );
                    return;
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_broadcast(cond=0x{:X}, tid={}, woken={}) -> 0",
                        cond, thread_id, woken_count
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_broadcast cond=0x{:X} tid={} woken={} -> 0",
                    cond, thread_id, woken_count
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-cond-broadcast",
                    "pthread_cond_broadcast",
                )
                .arg("Cond", format!("0x{:X}", cond))
                .arg("Woken", woken_count.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    Ok(())
}
