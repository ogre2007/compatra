//! Legacy arm64 Mach-O runner used by the no-dyld binary entrypoint.

use crate::macos::analysis::AnalysisRuntimeHooks;
use crate::macos::analysis_arm64_cpp_imports::{
    install_analysis_arm64_cpp_imports, setup_analysis_arm64_cpp_data_region,
};
use crate::macos::apple_imports::install_apple_imports;
use crate::macos::arm64_dynamic_imports::install_arm64_dynamic_imports;
use crate::macos::binary_bootstrap::{map_binary_segments, setup_bootstrap_state};
use crate::macos::binary_setup::{
    find_runtime_symbols, install_arm64_indirect_branch_hooks, install_arm64_lse_atomic_hooks,
    log_runtime_symbols, patch_symbol_pointers, resolve_entry,
};
use crate::macos::diagnostics::{install_diagnostic_hooks, run_with_diagnostics, RunReport};
use crate::macos::io_imports::install_io_imports;
use crate::macos::process_imports::install_process_imports;
use crate::macos::pthread_imports::install_pthread_imports;
use crate::macos::runner_support::{
    initialize_import_tracker, initialize_shared_state_with_mode, install_return_stubs,
};
use crate::macos::runtime_hooks::install_runtime_hooks;
use crate::macos::time_imports::install_time_imports;
use crate::macos::{
    default_guest_fs_base, ensure_macho_cpu, install_runtime_plugins, process_event,
    runtime_process_metadata, MacosCpu, RuntimeContext, RuntimeMode, SyscallRuntimePlugin,
    TraceMetadata,
};
use crate::{ArchType, Emulator, MachoBinary, UnicornEmulator};

use crate::macos::{memory_event, SharedTraceBus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const INDIRECT_BRANCH_MODE_ENV: &str = "MACHINA_INDIRECT_BRANCH_MODE";

/// Build a synthetic trampoline that invokes each
/// `__mod_init_func` entry in order, then tail-jumps to the real
/// `_main`. Modern Mach-O loaders execute these C++ static
/// initializers as part of dyld startup, and obfuscated samples
/// like the Mach-O Man profiler put meaningful state-setup logic
/// inside them — without it, runtime globals stay zero and
/// `_main` runs against an uninitialized world.
///
/// Returns the trampoline entry point on success, or `Ok(None)`
/// when the binary has no `__mod_init_func` section (so the
/// caller can keep using the original entry).
fn build_mod_init_trampoline(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    main_addr: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    // Locate the __mod_init_func section regardless of which
    // segment claims it — obfuscators rename the parent segment
    // (e.g. ".<71" instead of "__DATA_CONST") so we can't rely
    // on `get_section(seg, "__mod_init_func")`.
    let init_section = binary
        .segments
        .iter()
        .flat_map(|s| s.sections.iter())
        .find(|sec| {
            let name = String::from_utf8_lossy(
                &sec.sectname[..sec
                    .sectname
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(sec.sectname.len())],
            );
            name == "__mod_init_func"
        });
    let Some(sec) = init_section else {
        return Ok(None);
    };
    if sec.size == 0 || sec.size % 8 != 0 {
        return Ok(None);
    }
    let entry_count = (sec.size / 8) as usize;
    if entry_count == 0 {
        return Ok(None);
    }

    // Read every initializer address out of guest memory — the
    // chained-fixups pass has already replaced the on-disk chain
    // entries with resolved absolute addresses.
    let mut init_addrs: Vec<u64> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let slot_addr = sec.addr + (i as u64) * 8;
        let bytes = emulator.read_memory(slot_addr, 8)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| "short read on __mod_init_func slot")?;
        let addr = u64::from_le_bytes(arr);
        if addr == 0 {
            continue;
        }
        init_addrs.push(addr);
    }
    if init_addrs.is_empty() {
        return Ok(None);
    }

    // ARM64 trampoline layout:
    //   sub sp, sp, #32                ; reserve scratch frame
    //   stp x0, x1, [sp]               ; save argc, argv
    //   str x2, [sp, #16]              ; save envp
    //   ; per initializer:
    //   movz x16, #imm0
    //   movk x16, #imm1, lsl #16
    //   movk x16, #imm2, lsl #32
    //   movk x16, #imm3, lsl #48
    //   blr  x16
    //   ; after the last initializer:
    //   ldp x0, x1, [sp]
    //   ldr x2, [sp, #16]
    //   add sp, sp, #32
    //   movz x16, #imm0    ; <main>
    //   movk x16, #imm1, lsl #16
    //   movk x16, #imm2, lsl #32
    //   movk x16, #imm3, lsl #48
    //   br   x16
    //
    // Each init = 6 instructions (24 bytes); prelude/epilogue =
    // 8 instructions (32 bytes); main jump = 5 instructions (20
    // bytes). Add a 4-byte ret guard at the tail for safety.
    let mut code: Vec<u8> = Vec::new();

    // Prelude.
    code.extend_from_slice(&0xD10083FFu32.to_le_bytes()); // sub sp, sp, #32
    code.extend_from_slice(&0xA90007E0u32.to_le_bytes()); // stp x0, x1, [sp]
    code.extend_from_slice(&0xF90008E2u32.to_le_bytes()); // str x2, [sp, #16]

    let emit_load_x16 = |code: &mut Vec<u8>, target: u64| {
        let imm0 = (target & 0xFFFF) as u32;
        let imm1 = ((target >> 16) & 0xFFFF) as u32;
        let imm2 = ((target >> 32) & 0xFFFF) as u32;
        let imm3 = ((target >> 48) & 0xFFFF) as u32;
        // movz x16, #imm0, lsl #0
        code.extend_from_slice(&(0xD2800010u32 | (imm0 << 5)).to_le_bytes());
        // movk x16, #imm1, lsl #16
        code.extend_from_slice(&(0xF2A00010u32 | (imm1 << 5)).to_le_bytes());
        // movk x16, #imm2, lsl #32
        code.extend_from_slice(&(0xF2C00010u32 | (imm2 << 5)).to_le_bytes());
        // movk x16, #imm3, lsl #48
        code.extend_from_slice(&(0xF2E00010u32 | (imm3 << 5)).to_le_bytes());
    };

    for &init_addr in &init_addrs {
        emit_load_x16(&mut code, init_addr);
        // blr x16
        code.extend_from_slice(&0xD63F0200u32.to_le_bytes());
    }

    // Epilogue: restore argc/argv/envp.
    code.extend_from_slice(&0xA94007E0u32.to_le_bytes()); // ldp x0, x1, [sp]
    code.extend_from_slice(&0xF94008E2u32.to_le_bytes()); // ldr x2, [sp, #16]
    code.extend_from_slice(&0x910083FFu32.to_le_bytes()); // add sp, sp, #32

    // Tail-call main via br x16 (LR already points at done_addr).
    emit_load_x16(&mut code, main_addr);
    code.extend_from_slice(&0xD61F0200u32.to_le_bytes()); // br x16
    code.extend_from_slice(&0xD65F03C0u32.to_le_bytes()); // ret (safety net)

    // Allocate guest memory for the trampoline. The arm64 layout
    // pre-maps the mmap arena as data-only (R+W) heap; if we
    // wrote into that region the trampoline bytes would be
    // unfetchable. Carve out a fresh R+W+X page above the
    // existing arena instead.
    let aligned_size = ((code.len() as u64 + 0xFFF) & !0xFFF).max(0x1000);
    let base = mmap_next.fetch_add(aligned_size, Ordering::Relaxed);
    if base.saturating_add(aligned_size) > mmap_end {
        return Err("mmap arena exhausted while allocating __mod_init trampoline".into());
    }
    // Re-protect the trampoline page to R+W+X so the fetch path
    // can read instructions from it. The page is already mapped
    // as part of the heap arena; just upgrade the protection.
    emulator.protect_memory(
        base & !0xFFF,
        aligned_size,
        unicorn_engine::Prot::READ | unicorn_engine::Prot::WRITE | unicorn_engine::Prot::EXEC,
    )?;
    emulator.write_memory(base, &code)?;
    // Read back the first few instructions to confirm the write
    // landed and is visible to the fetch path.
    if let Some(bus) = trace_bus {
        let _ = bus.send(
            memory_event(metadata, "mod-init-trampoline")
                .arg("Base", format!("0x{:X}", base))
                .arg("Size", format!("0x{:X}", code.len()))
                .arg("InitCount", init_addrs.len().to_string())
                .arg("FirstInit", format!("0x{:X}", init_addrs[0]))
                .arg("MainAddr", format!("0x{:X}", main_addr))
                .arg("DoneAddr", format!("0x{:X}", done_addr)),
        );
    }

    Ok(Some(base))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndirectBranchMode {
    Fast,
    Sanitize,
}

impl IndirectBranchMode {
    fn from_env() -> (Self, Option<String>) {
        let Ok(raw) = std::env::var(INDIRECT_BRANCH_MODE_ENV) else {
            return (Self::Fast, None);
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "fast" => (Self::Fast, None),
            "sanitize" => (Self::Sanitize, None),
            _ => (Self::Fast, Some(raw)),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Sanitize => "sanitize",
        }
    }
}

pub fn emulate_macos_arm64_binary(binary_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_mode = RuntimeMode::from_env().unwrap_or_default();
    emulate_macos_arm64_binary_with_mode(binary_path, runtime_mode)
}

pub fn emulate_macos_arm64_binary_with_mode(
    binary_path: &str,
    runtime_mode: RuntimeMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
    let binary = MachoBinary::parse(&raw_data)?;
    let process_name = "main";
    let trace_bus = crate::macos::shared_trace_bus_for_mode_from_env(runtime_mode);
    let metadata = TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name);
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "binary-load", "binary-load")
                .arg("Path", binary_path.to_string())
                .arg("Mode", runtime_mode.as_str())
                .arg("Size", raw_data.len().to_string()),
        );
    }

    if let Some(dyld_path) = binary.get_dyld_path() {
        if let Some(bus) = &trace_bus {
            let _ = bus.send(process_event(&metadata, "dyld", "dyld").arg("Path", dyld_path));
        }
    }
    for lib in binary.get_dylib_paths() {
        if let Some(bus) = &trace_bus {
            let _ = bus.send(process_event(&metadata, "load_dylib", "load_dylib").arg("Path", lib));
        }
    }

    let cputype = ensure_macho_cpu(&binary, MacosCpu::Arm64)
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "cpu-detect", "cpu-detect")
                .arg("CpuType", format!("0x{:X}", cputype))
                .arg("CpuName", "arm64"),
        );
    }

    let mut emulator = UnicornEmulator::new(ArchType::Arm64)?;
    emulator.set_automap_low_page(true);
    let _ = emulator.install_unmapped_memory_debug_hook(&trace_bus);

    let stack_base: u64 = 0x7FFF_FFFC_0000;
    let stack_size: u64 = 0x40000;
    emulator.map_code_memory(stack_base, stack_size)?;
    let sp = (stack_base + stack_size - 16) & !0xF;
    emulator.write_reg("sp", sp)?;

    let max_addr = map_binary_segments(&mut emulator, &binary, &trace_bus, process_name)?;
    let bootstrap_state = setup_bootstrap_state(
        &mut emulator,
        &binary,
        binary_path,
        max_addr,
        sp,
        &trace_bus,
        process_name,
    )?;
    let heap_base = bootstrap_state.heap_base;
    let mmap_base = bootstrap_state.mmap_base;
    let mmap_end = bootstrap_state.mmap_end;
    let mmap_next = bootstrap_state.mmap_next.clone();
    let errno_ptr = bootstrap_state.errno_ptr;
    let stub_region = bootstrap_state.stub_region;
    let process_bootstrap = bootstrap_state.process_bootstrap;
    let stub_base = stub_region.base;
    let stub_size = stub_region.size;
    let done_addr = stub_region.done_addr;
    let thread_exit_stub = stub_region.thread_exit_stub.unwrap_or(done_addr);

    let undefs = binary.get_undefined_symbols();
    if let Some(bus) = &trace_bus {
        let preview = undefs
            .iter()
            .take(10)
            .map(|(name, n_type)| format!("{name}:0x{n_type:X}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = bus.send(
            process_event(&metadata, "undefined-symbols", "undefined-symbols")
                .arg("Count", undefs.len().to_string())
                .arg("Preview", preview),
        );
    }

    let shared_state = initialize_shared_state_with_mode(
        default_guest_fs_base(std::path::Path::new(binary_path), "arm64_ios"),
        process_bootstrap.clone(),
        runtime_mode,
    );

    let import_tracker = initialize_import_tracker();
    let (mut stub_map, stub_name_map, next_dynamic_stub_addr) = install_return_stubs(
        &mut emulator,
        stub_region,
        &undefs,
        &import_tracker,
        &trace_bus,
        &process_name,
        runtime_mode,
        &shared_state,
        errno_ptr,
    )?;
    for (name, addr) in stub_map.clone() {
        let normalized = crate::macos::imports::normalize_import_symbol(name);
        stub_map.entry(normalized).or_insert(addr);
    }

    let analysis_hooks = AnalysisRuntimeHooks::for_mode(runtime_mode);
    let cpp_data_symbols = if analysis_hooks.is_enabled() {
        match setup_analysis_arm64_cpp_data_region(
            &mut emulator,
            &mmap_next,
            mmap_end,
            done_addr,
            &trace_bus,
            &metadata,
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[CPP-DATA-REGION] setup failed: {}", e);
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // Apply LC_DYLD_CHAINED_FIXUPS: walk every chain in the data
    // segments and patch each pointer slot in guest memory. Without
    // this, indirect calls through __nl_symbol_ptr / GOT fetch the
    // raw chain value (`bit63=1 | ordinal`) and the emulator's TBI
    // strip lands PC inside the Mach-O header at offsets like
    // 0x100000065, never executing real imports.
    match crate::macos::imports::process_chained_fixups_with_binary(
        &mut emulator,
        &binary,
        0u64,
        &stub_map,
        Some(&cpp_data_symbols),
        done_addr,
    ) {
        Ok(stats) if stats.bound + stats.rebased + stats.unresolved > 0 => {
            if let Some(bus) = &trace_bus {
                let _ = bus.send(
                    process_event(&metadata, "chained-fixups", "process_chained_fixups")
                        .arg("Bound", stats.bound.to_string())
                        .arg("Rebased", stats.rebased.to_string())
                        .arg("Unresolved", stats.unresolved.to_string()),
                );
            }
        }
        Ok(_) => {}
        Err(err) => {
            if let Some(bus) = &trace_bus {
                let _ = bus.send(
                    process_event(&metadata, "chained-fixups-error", "process_chained_fixups")
                        .arg("Error", format!("{}", err)),
                );
            }
        }
    }
    if analysis_hooks.is_enabled() {
        install_analysis_arm64_cpp_imports(
            &mut emulator,
            &stub_map,
            &mmap_next,
            mmap_end,
            &trace_bus,
            &import_tracker,
            &process_name,
        )?;
    }

    for spec in analysis_hooks.function_entry_specs_from_env() {
        let label_owned = spec.label;
        let addr = spec.addr;
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let x0 = emu.read_reg("x0").unwrap_or(0);
                let x1 = emu.read_reg("x1").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                if let Some(bus) = &trace_bus_for_hook {
                    let _ = bus.send(
                        process_event(
                            &runtime_process_metadata(proc_name.clone()),
                            "function-entry",
                            "function_entry",
                        )
                        .arg("Label", label_owned.clone())
                        .arg("Pc", format!("0x{:X}", addr))
                        .arg("X0", format!("0x{:X}", x0))
                        .arg("X1", format!("0x{:X}", x1))
                        .arg("Lr", format!("0x{:X}", lr)),
                    );
                }
            },
        )?;
    }

    for spec in analysis_hooks.usage_bypass_specs_from_env() {
        let addr = spec.addr;
        let lr_filter = spec.lr_filter;
        let values = spec.values;
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let x0_in = emu.read_reg("x0").unwrap_or(0);
                let x1_in = emu.read_reg("x1").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr_filter.is_some_and(|expected| expected != lr) {
                    return;
                }
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let value = if values.is_empty() {
                    0
                } else if n < values.len() {
                    values[n]
                } else {
                    *values.last().unwrap()
                };
                let _ = emu.write_reg("x0", value);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                if let Some(bus) = &trace_bus_for_hook {
                    let _ = bus.send(
                        process_event(
                            &runtime_process_metadata(proc_name.clone()),
                            "bypass-usage-check",
                            "bypass_usage_check",
                        )
                        .arg("Pc", format!("0x{:X}", addr))
                        .arg("CallIndex", n.to_string())
                        .arg("ReturnValue", format!("0x{:X}", value))
                        .arg("X0In", format!("0x{:X}", x0_in))
                        .arg("X1In", format!("0x{:X}", x1_in))
                        .arg("Lr", format!("0x{:X}", lr))
                        .arg(
                            "LrFilter",
                            lr_filter
                                .map(|expected| format!("0x{:X}", expected))
                                .unwrap_or_else(|| "none".to_string()),
                        ),
                    );
                }
            },
        )?;
    }

    let last_stub = import_tracker.last_stub.clone();
    let import_count = import_tracker.import_count.clone();
    let recent_imports = import_tracker.recent_imports.clone();

    let usleep_streaks = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        (u64, u64),
        u32,
    >::new()));
    let saw_exit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime_symbols = find_runtime_symbols(&binary);
    log_runtime_symbols(runtime_symbols, &trace_bus, &process_name);

    install_runtime_hooks(
        &mut emulator,
        thread_exit_stub,
        done_addr,
        runtime_symbols.libc_close_trampoline,
        runtime_symbols.libc_dup2_trampoline,
        runtime_symbols.libc_execve_trampoline,
        &trace_bus,
        &shared_state,
    )?;

    install_pthread_imports(
        &mut emulator,
        &stub_map,
        errno_ptr,
        thread_exit_stub,
        &trace_bus,
        &shared_state,
        &import_tracker,
    )?;

    install_time_imports(
        &mut emulator,
        &stub_map,
        &trace_bus,
        &shared_state,
        &import_tracker,
        &usleep_streaks,
    )?;

    install_apple_imports(
        &mut emulator,
        &stub_map,
        &trace_bus,
        &shared_state,
        &import_tracker,
        &process_name,
    )?;

    install_arm64_dynamic_imports(
        &mut emulator,
        &stub_map,
        stub_region,
        stub_name_map.clone(),
        next_dynamic_stub_addr.clone(),
        &trace_bus,
        &shared_state,
        &import_tracker,
        &process_name,
    )?;

    install_io_imports(
        &mut emulator,
        &stub_map,
        errno_ptr,
        mmap_end,
        &mmap_next,
        &trace_bus,
        &shared_state,
        &import_tracker,
    )?;

    install_process_imports(
        &mut emulator,
        &stub_map,
        done_addr,
        errno_ptr,
        &trace_bus,
        &saw_exit,
        &shared_state,
        &import_tracker,
    )?;
    patch_symbol_pointers(
        &mut emulator,
        &binary,
        &undefs,
        &stub_map,
        done_addr,
        &trace_bus,
        &process_name,
    )?;
    install_arm64_lse_atomic_hooks(&mut emulator, &binary, &trace_bus, process_name)?;
    let (indirect_branch_mode, invalid_indirect_branch_mode) = IndirectBranchMode::from_env();
    if let Some(bus) = &trace_bus {
        let mut event = process_event(&metadata, "indirect-branch-mode", "indirect_branch_mode")
            .arg("Mode", indirect_branch_mode.as_str())
            .arg("Env", INDIRECT_BRANCH_MODE_ENV);
        if let Some(raw) = invalid_indirect_branch_mode {
            event = event.arg("Requested", raw).arg("Fallback", "fast");
        }
        let _ = bus.send(event);
    }
    if indirect_branch_mode == IndirectBranchMode::Sanitize {
        install_arm64_indirect_branch_hooks(&mut emulator, &binary, &trace_bus, process_name)?;
    } else {
        if let Some(bus) = &trace_bus {
            let _ = bus.send(
                process_event(
                    &metadata,
                    "indirect-branch-hooks-skipped",
                    "install_indirect_branch_hooks",
                )
                .arg("Reason", "mode-fast"),
            );
        }
    }

    let runtime_context = RuntimeContext::new_with_mode(
        process_name,
        binary_path,
        runtime_mode,
        done_addr,
        heap_base,
        mmap_base,
        mmap_end,
        mmap_next.clone(),
        saw_exit.clone(),
        trace_bus.clone(),
    );
    let syscall_count = runtime_context.core.runtime.syscall_count.clone();
    install_runtime_plugins(&mut emulator, &runtime_context, &[&SyscallRuntimePlugin])?;

    let actual_entry = resolve_entry(&binary);

    // Optional: build a synthetic trampoline that calls every
    // __mod_init_func entry before transferring control to _main.
    // Modern Mach-O loaders execute these C++ static
    // initializers as part of dyld startup, and obfuscated
    // samples (notably the Mach-O Man profiler) place
    // meaningful initialization in them — without this, runtime
    // globals stay zero and the binary's argc dispatch always
    // takes the usage-and-exit branch.
    let entry = match build_mod_init_trampoline(
        &mut emulator,
        &binary,
        &mmap_next,
        mmap_end,
        actual_entry,
        done_addr,
        &trace_bus,
        &metadata,
    ) {
        Ok(Some(trampoline_addr)) => trampoline_addr,
        Ok(None) => actual_entry,
        Err(err) => {
            eprintln!(
                "[MOD-INIT] trampoline setup failed, running _main directly: {}",
                err
            );
            actual_entry
        }
    };

    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "entry", "entry")
                .arg("Pc", format!("0x{:X}", entry))
                .arg("DoneAddr", format!("0x{:X}", done_addr))
                .arg("ActualEntry", format!("0x{:X}", actual_entry)),
        );
    }
    emulator.write_reg("pc", entry)?;
    emulator.write_reg("lr", done_addr)?;

    install_diagnostic_hooks(
        &mut emulator,
        &binary,
        runtime_symbols.firstmoduledata,
        actual_entry,
        done_addr,
        &trace_bus,
        process_name,
    )?;

    let result = run_with_diagnostics(
        &mut emulator,
        RunReport {
            // Start emulation at the trampoline (or _main if the
            // trampoline wasn't built) — the diagnostic runner
            // passes this PC to `uc_emu_start` instead of reading
            // PC from the cpu state, so updating PC via
            // `write_reg` earlier is not enough on its own.
            actual_entry: entry,
            done_addr,
            stack_base,
            stack_size,
            stub_base,
            stub_size,
            saw_exit,
            syscall_count,
            import_count,
            last_stub,
            recent_imports,
            synthetic_stop_reason: shared_state.synthetic_stop_reason.clone(),
            trace_bus: trace_bus.clone(),
            process_name: process_name.to_string(),
        },
    );

    if let Some(bus) = &trace_bus {
        let recent_preview = import_tracker
            .recent_imports
            .lock()
            .ok()
            .map(|items| items.iter().cloned().collect::<Vec<_>>().join(" | "))
            .unwrap_or_default();
        let _ = bus.send(
            process_event(&metadata, "trace-summary", "trace-summary")
                .arg(
                    "Syscalls",
                    runtime_context
                        .core
                        .runtime
                        .syscall_count
                        .load(std::sync::atomic::Ordering::Relaxed)
                        .to_string(),
                )
                .arg(
                    "Imports",
                    import_tracker
                        .import_count
                        .load(std::sync::atomic::Ordering::Relaxed)
                        .to_string(),
                )
                .arg("RecentImports", recent_preview),
        );
    }

    result
}
