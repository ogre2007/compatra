//! Time and system-query imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::macos::arm64_runner_support::{
    record_arm64_import, Arm64ImportTracker, Arm64SharedState,
};
use crate::macos::{wake_arm64_cond_waiters, yield_active_arm64_thread};
use crate::{Emulator, UnicornEmulator};

fn vec_u64_le(bytes: Vec<u8>) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn read_cstring(emu: &dyn Emulator, addr: u64, max_len: usize) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    for i in 0..max_len {
        let Ok(bytes) = emu.read_memory(addr + i as u64, 1) else {
            break;
        };
        let Some(&byte) = bytes.first() else {
            break;
        };
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn install_arm64_time_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
    usleep_streaks: &Arc<Mutex<HashMap<(u64, u64), u32>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let thread_runtime = shared_state.thread_runtime.clone();
    let mach_absolute_time = Arc::new(AtomicU64::new(1_000_000));

    if let Some(&addr) = stub_map.get("_mach_absolute_time") {
        let mach_absolute_time = mach_absolute_time.clone();
        let import_tracker = import_tracker.clone();
        let thread_runtime = thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let value =
                    mach_absolute_time.fetch_add(1_000, std::sync::atomic::Ordering::Relaxed);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", value);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_mach_absolute_time(tid={}) -> {}", thread_id, value),
                );
                println!(
                    "[IMPORT][arm64] _mach_absolute_time tid={} lr=0x{:X} -> {}",
                    thread_id, lr, value
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_usleep") {
        let import_tracker = import_tracker.clone();
        let thread_runtime = thread_runtime.clone();
        let usleep_streaks = usleep_streaks.clone();
        let mach_absolute_time = mach_absolute_time.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let usec = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let (thread_id, active_thread, pending_threads) = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| {
                        (
                            rt.current_thread_id.max(1),
                            rt.active_thread.is_some(),
                            rt.pending_threads.len(),
                        )
                    })
                    .unwrap_or((1, false, 0));

                let time_advance = usec.saturating_mul(1_000).max(1_000);
                let _ = mach_absolute_time.fetch_add(
                    time_advance,
                    std::sync::atomic::Ordering::Relaxed,
                );

                let streak = {
                    let mut streaks = match usleep_streaks.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    let slot = streaks.entry((thread_id, lr)).or_insert(0);
                    *slot = slot.saturating_add(1);
                    *slot
                };

                let lr_bytes = emu.read_memory(lr, 8).unwrap_or_default();
                let lr_backtrace = lr.saturating_sub(8);
                let caller_bytes = emu.read_memory(lr_backtrace, 16).unwrap_or_default();
                let sp = emu.read_reg("sp").unwrap_or(0);
                let caller_lr = if sp != 0 {
                    emu.read_memory(sp, 8)
                        .ok()
                        .and_then(vec_u64_le)
                        .unwrap_or(0)
                } else {
                    0
                };

                let mut yielded_to = None;
                let mut idle_wake = Vec::new();
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    if let Ok(yield_result) = yield_active_arm64_thread(emu, &mut runtime, 0, lr) {
                        yielded_to = yield_result;
                    }
                    if yielded_to.is_none()
                        && pending_threads == 0
                        && streak >= 50
                        && streak % 25 == 0
                    {
                        idle_wake = wake_arm64_cond_waiters(&mut runtime, 4);
                        if !idle_wake.is_empty() {
                            if let Ok(yield_result) =
                                yield_active_arm64_thread(emu, &mut runtime, 0, lr)
                            {
                                yielded_to = yield_result;
                            }
                        }
                    }
                }

                if let Some((from_tid, to_tid)) = yielded_to {
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_usleep(tid={}, usec={}, caller=0x{:X}, streak={}) -> yield:{}",
                            thread_id, usec, caller_lr, streak, to_tid
                        ),
                    );
                    println!(
                        "[THREAD][arm64] usleep yield tid={} -> tid={} usec={} caller=0x{:X} streak={} pending={} advanced_ns={}",
                        from_tid, to_tid, usec, caller_lr, streak, pending_threads, time_advance
                    );
                    if !idle_wake.is_empty() {
                        let summary = idle_wake
                            .iter()
                            .map(|(cond, waiter_tid)| format!("cond=0x{:X}/tid={}", cond, waiter_tid))
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!(
                            "[THREAD][arm64] idle cond rescue [{}] via usleep tid={}",
                            summary, thread_id
                        );
                    }
                    return;
                }

                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }

                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_usleep(tid={}, usec={}, caller=0x{:X}, streak={}, dt_ns={}) -> 0",
                        thread_id, usec, caller_lr, streak, time_advance
                    ),
                );

                if streak <= 5 || streak % 25 == 0 {
                    println!(
                        "[IMPORT][arm64] _usleep tid={} usec={} lr=0x{:X} caller=0x{:X} streak={} active={} pending={} dt_ns={} lr_code={:02X?} caller_code={:02X?}",
                        thread_id,
                        usec,
                        lr,
                        caller_lr,
                        streak,
                        active_thread,
                        pending_threads,
                        time_advance,
                        lr_bytes,
                        caller_bytes
                    );
                }

                if streak == 50 {
                    println!(
                        "[IDLE][arm64] thread {} appears parked in usleep loop at lr=0x{:X}",
                        thread_id, lr
                    );
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_mach_timebase_info") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let info_ptr = emu.read_reg("x0").unwrap_or(0);
                if info_ptr != 0 {
                    let _ = emu.write_memory(info_ptr, &1u32.to_le_bytes());
                    let _ = emu.write_memory(info_ptr + 4, &1u32.to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_mach_timebase_info(info=0x{:X}) -> numer=1 denom=1",
                        info_ptr
                    ),
                );
                println!(
                    "[IMPORT][arm64] _mach_timebase_info info=0x{:X} numer=1 denom=1",
                    info_ptr
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_sysctl") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let name = emu.read_reg("x0").unwrap_or(0);
                let namelen = emu.read_reg("x1").unwrap_or(0);
                let oldp = emu.read_reg("x2").unwrap_or(0);
                let oldlenp = emu.read_reg("x3").unwrap_or(0);
                let newp = emu.read_reg("x4").unwrap_or(0);
                let newlen = emu.read_reg("x5").unwrap_or(0);
                let mib_bytes = if name != 0 && namelen > 0 {
                    emu.read_memory(name, (namelen as usize).saturating_mul(4))
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let mut mib = Vec::new();
                for chunk in mib_bytes.chunks_exact(4) {
                    mib.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }

                let mut result_value: Option<u32> = None;
                if mib.len() >= 2 {
                    match (mib[0], mib[1]) {
                        (6, 3) | (3, 6) => result_value = Some(4),
                        (6, 7) | (7, 6) => result_value = Some(0x4000),
                        _ => {}
                    }
                }

                if oldlenp != 0 {
                    let result_len = if oldp != 0 && result_value.is_some() {
                        4u64
                    } else {
                        0u64
                    };
                    let _ = emu.write_memory(oldlenp, &result_len.to_le_bytes());
                }
                if oldp != 0 {
                    if let Some(value) = result_value {
                        let _ = emu.write_memory(oldp, &value.to_le_bytes());
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
                        "_sysctl(mib={:?}, oldp=0x{:X}, oldlenp=0x{:X}) -> {:?}",
                        mib, oldp, oldlenp, result_value
                    ),
                );
                println!(
                    "[IMPORT][arm64] _sysctl mib={:?} oldp=0x{:X} oldlenp=0x{:X} newp=0x{:X} newlen={} -> {:?}",
                    mib, oldp, oldlenp, newp, newlen, result_value
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_sysctlbyname") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let name_ptr = emu.read_reg("x0").unwrap_or(0);
                let oldp = emu.read_reg("x1").unwrap_or(0);
                let oldlenp = emu.read_reg("x2").unwrap_or(0);
                let _newp = emu.read_reg("x3").unwrap_or(0);
                let _newlen = emu.read_reg("x4").unwrap_or(0);
                let name = read_cstring(emu, name_ptr, 128);
                if matches!(name.as_str(), "hw.pagesize" | "hw.page_size") {
                    if oldlenp != 0 {
                        let _ = emu.write_memory(oldlenp, &8u64.to_le_bytes());
                    }
                    if oldp != 0 {
                        let _ = emu.write_memory(oldp, &0x4000u64.to_le_bytes());
                    }
                } else if name.starts_with("hw.optional.") {
                    if oldlenp != 0 {
                        let _ = emu.write_memory(oldlenp, &4u64.to_le_bytes());
                    }
                    if oldp != 0 {
                        let _ = emu.write_memory(oldp, &0u32.to_le_bytes());
                    }
                } else {
                    let payload = b"machina\0";
                    if oldlenp != 0 {
                        let _ = emu.write_memory(oldlenp, &(payload.len() as u64).to_le_bytes());
                    }
                    if oldp != 0 {
                        let _ = emu.write_memory(oldp, payload);
                    }
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_sysctlbyname(name={}, oldp=0x{:X}, oldlenp=0x{:X}) -> 0",
                        name, oldp, oldlenp
                    ),
                );
                println!(
                    "[IMPORT][arm64] _sysctlbyname name={} oldp=0x{:X} oldlenp=0x{:X} -> 0",
                    name, oldp, oldlenp
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_notify_is_valid_token") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let token = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_notify_is_valid_token(token=0x{:X}) -> 0", token),
                );
                println!(
                    "[IMPORT][arm64] _notify_is_valid_token token=0x{:X} -> 0",
                    token
                );
            },
        )?;
    }

    Ok(())
}
