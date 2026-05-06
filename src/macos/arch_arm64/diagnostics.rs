//! Diagnostic hooks and stop reporting for the legacy arm64 runner.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};

use crate::macos::{
    detect_event, emit_runner_trace_event, file_backed_slice_for_vmaddr, reload_file_backed_range,
    runtime_process_metadata, SharedTraceBus,
};
use crate::{Emulator, MachoBinary, UnicornEmulator};

fn slice_u64_le(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn debug_stdout_enabled() -> bool {
    std::env::var("MACHINA_DEBUG_STDOUT")
        .ok()
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

pub fn install_arm64_diagnostic_hooks(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    runtime_firstmoduledata: Option<u64>,
    actual_entry: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let interesting_symbols = [
        "_main.main",
        "_main.GrabFirefox",
        "_main.GrabChrome",
        "_main.GrabWallets",
    ];
    let defined_symbols = binary.get_defined_symbols();
    for symbol_name in interesting_symbols {
        if let Some(&symbol_addr) = defined_symbols.get(symbol_name) {
            let symbol_name = symbol_name.to_string();
            let trace_bus = trace_bus.clone();
            let process_name = process_name.to_string();
            emulator.add_code_hook(
                symbol_addr,
                symbol_addr + 4,
                move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                    let sp = emu.read_reg("sp").unwrap_or(0);
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let metadata = runtime_process_metadata(&process_name)
                        .pid(1)
                        .ppid(0)
                        .tid(1);
                    emit_runner_trace_event(
                        &trace_bus,
                        &metadata,
                        detect_event(&metadata, "malware-symbol-hit")
                            .call(symbol_name.clone())
                            .arg("Address", format!("0x{:X}", address))
                            .arg("LR", format!("0x{:X}", lr))
                            .arg("SP", format!("0x{:X}", sp)),
                    );
                },
            )?;
        }
    }

    if let Some(firstmoduledata_addr) = runtime_firstmoduledata {
        let dumped = Arc::new(AtomicBool::new(false));
        let dumped_flag = dumped.clone();
        let binary = binary.clone();
        emulator.add_code_hook(
            0x10006C33C,
            0x10006C340,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                if dumped_flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let read_u64 = |off: u64, emu: &mut machina::UnicornEmulator| -> u64 {
                    emu.read_memory(firstmoduledata_addr + off, 8)
                        .ok()
                        .and_then(|v| v.get(..8).and_then(slice_u64_le))
                        .unwrap_or(0)
                };
                let pc_header = read_u64(0x00, emu);
                let funcnametab = read_u64(0x08, emu);
                let pclntable = read_u64(0x50, emu);
                let ftab = read_u64(0x80, emu);
                let ftab_len = read_u64(0x88, emu);
                let filetab = read_u64(0x38, emu);
                let findfunctab = read_u64(0x98, emu);
                let minpc = read_u64(0xA0, emu);
                let maxpc = read_u64(0xA8, emu);
                let text = read_u64(0xB0, emu);
                let etext = read_u64(0xB8, emu);
                if debug_stdout_enabled() {
                    println!(
                        "[RUNTIME][arm64] firstmoduledata pcHeader=0x{:X} funcnametab=0x{:X} filetab=0x{:X} pclntable=0x{:X} ftab=0x{:X} ftab_len=0x{:X} findfunctab=0x{:X} minpc=0x{:X} maxpc=0x{:X} text=0x{:X} etext=0x{:X}",
                        pc_header, funcnametab, filetab, pclntable, ftab, ftab_len, findfunctab, minpc, maxpc, text, etext
                    );
                }
                if pc_header != 0 {
                    if let Ok(bytes) = emu.read_memory(pc_header, 16) {
                        if debug_stdout_enabled() {
                            println!("[RUNTIME][arm64] pcHeader bytes={:02X?}", bytes);
                        }
                    }
                }
                if ftab != 0 && ftab_len != 0 && ftab_len < 0x20_000 {
                    if let Ok(bytes) = emu.read_memory(ftab, 32) {
                        if debug_stdout_enabled() {
                            println!("[RUNTIME][arm64] ftab mem bytes={:02X?}", bytes);
                        }
                    }
                    if let Some(bytes) = file_backed_slice_for_vmaddr(&binary, ftab, 32) {
                        if debug_stdout_enabled() {
                            println!("[RUNTIME][arm64] ftab file bytes={:02X?}", bytes);
                        }
                    }
                    let _ = reload_file_backed_range(
                        emu,
                        &binary,
                        ftab,
                        (ftab_len as usize).saturating_mul(8),
                        "_runtime.firstmoduledata.ftab",
                    );
                }
            },
        )?;
    }

    let startup_trace_count = Arc::new(AtomicUsize::new(0));
    let startup_trace_counter = startup_trace_count.clone();
    emulator.add_code_hook(
        actual_entry,
        done_addr + 4,
        move |emu: &mut machina::UnicornEmulator, address: u64, size: u32| {
            let seen = startup_trace_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if seen >= 64 {
                return;
            }
            let sp = emu.read_reg("sp").unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);
            let x0 = emu.read_reg("x0").unwrap_or(0);
            let x1 = emu.read_reg("x1").unwrap_or(0);
            let x2 = emu.read_reg("x2").unwrap_or(0);
            let x3 = emu.read_reg("x3").unwrap_or(0);
            let tpidr_el0 = emu.read_reg("tpidr_el0").unwrap_or(0);
            let tpidrro_el0 = emu.read_reg("tpidrro_el0").unwrap_or(0);
            let bytes = emu.read_memory(address, size as usize).unwrap_or_default();
            if debug_stdout_enabled() {
                println!(
                    "[STARTUP][arm64 #{:02}] pc=0x{:X} lr=0x{:X} sp=0x{:X} x0=0x{:X} x1=0x{:X} x2=0x{:X} x3=0x{:X} tpidr_el0=0x{:X} tpidrro_el0=0x{:X} bytes={:02X?}",
                    seen,
                    address,
                    lr,
                    sp,
                    x0,
                    x1,
                    x2,
                    x3,
                    tpidr_el0,
                    tpidrro_el0,
                    bytes
                );
            }
            if address == done_addr {
                if debug_stdout_enabled() {
                    println!("[STARTUP][arm64] reached done_addr");
                }
            }
        },
    )?;

    Ok(())
}

pub struct Arm64RunReport {
    pub actual_entry: u64,
    pub done_addr: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub stub_base: u64,
    pub stub_size: u64,
    pub saw_exit: Arc<AtomicBool>,
    pub syscall_count: Arc<AtomicUsize>,
    pub import_count: Arc<AtomicUsize>,
    pub last_stub: Arc<Mutex<Option<String>>>,
    pub recent_imports: Arc<Mutex<VecDeque<String>>>,
}

pub fn run_arm64_with_diagnostics(
    emulator: &mut UnicornEmulator,
    report: Arm64RunReport,
) -> Result<(), Box<dyn std::error::Error>> {
    match emulator.run_with_limits(report.actual_entry, None, 15_000_000, 10_000_000) {
        Ok(()) => {}
        Err(e) => {
            let pc = emulator.read_reg("pc").unwrap_or(0);
            let x1 = emulator.read_reg("x1").unwrap_or(0);
            let msg = e.to_string();
            let graceful_reason = if (msg.contains("FETCH_UNMAPPED")
                || msg.contains("Invalid memory fetch"))
                && (pc == 0 || pc == 1)
            {
                Some("Treating return from entry as graceful stop")
            } else if report.saw_exit.load(std::sync::atomic::Ordering::Relaxed)
                && (msg.contains("UNMAPPED") || msg.contains("Invalid memory"))
                && pc >= report.stub_base
                && pc < report.stub_base + report.stub_size
            {
                Some("Treating post-exit stub tail as graceful stop")
            } else if report.saw_exit.load(std::sync::atomic::Ordering::Relaxed)
                && (msg.contains("WRITE_UNMAPPED") || msg.contains("Invalid memory write"))
                && x1 == 0x3EA
            {
                Some("Treating post-exit Go fatal tail as graceful stop")
            } else if pc >= report.stack_base
                && pc < report.stack_base + report.stack_size
                && (msg.contains("INSN_INVALID")
                    || msg.contains("Invalid instruction")
                    || msg.contains("FETCH")
                    || msg.contains("Invalid memory fetch"))
            {
                Some("Treating stack-return tail as graceful stop")
            } else {
                None
            };

            if graceful_reason.is_some() {
                return Ok(());
            }

            return Err(format!("Emulation stopped with error: {}", e).into());
        }
    }

    Ok(())
}
