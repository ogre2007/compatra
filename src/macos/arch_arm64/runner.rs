//! Legacy arm64 Mach-O runner used by the no-dyld binary entrypoint.

use crate::macos::apple_imports::install_apple_imports;
use crate::macos::arm64_cpp_imports::install_arm64_cpp_imports;
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
    initialize_import_tracker, initialize_shared_state, install_return_stubs,
};
use crate::macos::runtime_hooks::install_runtime_hooks;
use crate::macos::time_imports::install_time_imports;
use crate::macos::{
    default_guest_fs_base, ensure_macho_cpu, install_runtime_plugins, process_event,
    shared_trace_bus_from_env, MacosCpu, RuntimeContext, SyscallRuntimePlugin, TraceMetadata,
};
use crate::{ArchType, Emulator, MachoBinary, UnicornEmulator};

use crate::macos::{memory_event, SharedTraceBus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const INDIRECT_BRANCH_MODE_ENV: &str = "MACHINA_INDIRECT_BRANCH_MODE";

/// Size of the fake C++ data region carved out of the mmap arena.
/// Large enough to host a generic ostream object, a small vtable
/// table, and a few extra fake-data symbols (ctype::id, etc.)
/// without bumping into surrounding allocations.
const ARM64_CPP_DATA_REGION_SIZE: u64 = 0x2000;

/// Offsets inside the C++ data region for each kind of fake symbol.
/// Layout is intentionally simple: a single vtable shared by every
/// C++ class import, followed by per-instance objects whose
/// vtable-pointer slot (offset 0) targets that shared vtable. The
/// shared vtable holds far more entries than any individual class
/// would ever index into, so virtual calls fall through to the
/// done_addr return-zero gadget rather than tripping off the end.
const ARM64_CPP_VTABLE_OFFSET: u64 = 0x100; // 32 fake vfn entries
const ARM64_CPP_CERR_OBJECT_OFFSET: u64 = 0x400;
const ARM64_CPP_CIN_OBJECT_OFFSET: u64 = 0x500;
const ARM64_CPP_CTYPE_ID_OFFSET: u64 = 0x600;
const ARM64_CPP_GENERIC_OBJECT_OFFSET: u64 = 0x700;

/// Allocate and initialize a fake C++ data-symbol region.
///
/// Returns a map of known C++ data-symbol names → resolved
/// addresses. Pass it to `process_chained_fixups_with_binary` as
/// `data_symbols` so the chain walker patches data binds (like
/// `__ZNSt3__14cerrE`) into this region instead of a function
/// stub. The fake region survives for the lifetime of the
/// emulator process and is never read by anything else, so the
/// initial layout is locked in here and not rebuilt.
fn setup_arm64_cpp_data_region(
    emulator: &mut UnicornEmulator,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<HashMap<String, u64>, Box<dyn std::error::Error>> {
    let region_size = ARM64_CPP_DATA_REGION_SIZE;
    let base = mmap_next.fetch_add(region_size, Ordering::Relaxed);
    if base.saturating_add(region_size) > mmap_end {
        // The mmap arena is exhausted — extremely unlikely in
        // practice (it's 16 GB), but bail rather than wrap.
        return Err("mmap arena exhausted while allocating C++ data region".into());
    }
    // The mmap arena overlaps the already-mapped heap region in
    // arm64 bootstrap layout (see memory_arena::arm64) so we
    // don't need to (and can't) re-map here. Just zero the slice.
    let zeros = vec![0u8; region_size as usize];
    emulator.write_memory(base, &zeros)?;

    // Populate the shared vtable with done_addr entries. C++ code
    // that reaches a virtual call ends up at done_addr's `ret`
    // (returning 0 in x0), which is the same convention every
    // unhandled libc++ stub already uses.
    let vtable_addr = base + ARM64_CPP_VTABLE_OFFSET;
    for i in 0..32 {
        emulator.write_memory(vtable_addr + i * 8, &done_addr.to_le_bytes())?;
    }

    // Each fake object stores the shared vtable pointer at offset
    // 0. The C++ ABI says `[this]` is the vtable for the most
    // derived class. With every entry pointing at done_addr,
    // any virtual call through this object harmlessly returns 0.
    let cerr_addr = base + ARM64_CPP_CERR_OBJECT_OFFSET;
    emulator.write_memory(cerr_addr, &vtable_addr.to_le_bytes())?;
    let cin_addr = base + ARM64_CPP_CIN_OBJECT_OFFSET;
    emulator.write_memory(cin_addr, &vtable_addr.to_le_bytes())?;
    let ctype_id_addr = base + ARM64_CPP_CTYPE_ID_OFFSET;
    // ctype::id is a small std::locale::id object; a single zeroed
    // page is enough — the C++ runtime only uses it for identity
    // comparisons.

    let mut data_symbols: HashMap<String, u64> = HashMap::new();

    // C++ globals (std::cerr / std::cin) — instances.
    data_symbols.insert("__ZNSt3__14cerrE".to_string(), cerr_addr);
    data_symbols.insert("__ZNSt3__14cinE".to_string(), cin_addr);
    data_symbols.insert("__ZNSt3__15wcerrE".to_string(), cerr_addr);
    data_symbols.insert("__ZNSt3__15wcinE".to_string(), cin_addr);
    data_symbols.insert("__ZNSt3__15ctypeIcE2idE".to_string(), ctype_id_addr);

    // C++ vtable / VTT symbols. The C++ ABI stores typeinfo at
    // [vtable-8] and offset-to-top at [vtable-16]. Our shared
    // vtable starts at vtable_addr, but a bind to `__ZTV*` should
    // resolve to vtable_addr + 16 (i.e., past the metadata slots)
    // so subsequent `ldr xN, [vtable, #0]` reads the first virtual
    // function, not the typeinfo. We currently bind to vtable_addr
    // directly because the metadata slots are already zeros from
    // the initial map and the obfuscated code we observe reads
    // `ldur xN, [xN, #-24]` — i.e., it expects valid memory at
    // (vtable-24) too, which the surrounding zeros provide as long
    // as the vtable lives well inside the region.
    let vtable_names = [
        "__ZTVNSt3__18ios_baseE",
        "__ZTVNSt3__19basic_iosIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__113basic_ostreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__113basic_istreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__115basic_streambufIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTVNSt3__119basic_istringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTVNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTTNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE",
        "__ZTTNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE",
        "__ZTTNSt3__119basic_istringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTTNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    ];
    for name in vtable_names {
        data_symbols.insert(name.to_string(), vtable_addr);
    }

    let _ = ARM64_CPP_GENERIC_OBJECT_OFFSET; // reserved for future symbols

    if let Some(bus) = trace_bus {
        let _ = bus.send(
            memory_event(metadata, "cpp-data-region")
                .arg("Base", format!("0x{:X}", base))
                .arg("Size", format!("0x{:X}", region_size))
                .arg("VTable", format!("0x{:X}", vtable_addr))
                .arg("Cerr", format!("0x{:X}", cerr_addr)),
        );
    }
    Ok(data_symbols)
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
    let raw_data = std::fs::read(binary_path)?;
    let binary = MachoBinary::parse(&raw_data)?;
    let process_name = "main";
    let trace_bus = shared_trace_bus_from_env();
    let metadata = TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name);
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "binary-load", "binary-load")
                .arg("Path", binary_path.to_string())
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

    let import_tracker = initialize_import_tracker();
    let (stub_map, _stub_name_map) = install_return_stubs(
        &mut emulator,
        stub_region,
        &undefs,
        &import_tracker,
        &trace_bus,
        &process_name,
    )?;

    // Build a fake C++ data-symbol region so chained-fixups can
    // bind C++ globals (std::cerr, vtables) to a region that won't
    // crash when the binary dereferences them as ostream/vtable
    // pointers. Without this, the chained-fixups walker binds
    // every C++ data symbol to a function stub address, and the
    // first time the C++ code does `ldr xN, [cerr_slot]` followed
    // by `ldr xN, [xN]` (vtable load) it fetches 8 bytes of stub
    // code (`mov x0,0; ret` = 0xd65f03c0d2800000) as data and the
    // next vtable-relative LDUR faults on the bogus address.
    let cpp_data_symbols = match setup_arm64_cpp_data_region(
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

    // Install C++ ostream stub overrides. Without these, every
    // operator<< call construct/destructs a sentry but never
    // writes — and `basic_ostream::write` silently returns 0
    // instead of producing the actual message bytes. Wire these
    // up after install_return_stubs so the stub addresses are
    // already populated.
    install_arm64_cpp_imports(
        &mut emulator,
        &stub_map,
        &trace_bus,
        &import_tracker,
        &process_name,
    )?;

    let last_stub = import_tracker.last_stub.clone();
    let import_count = import_tracker.import_count.clone();
    let recent_imports = import_tracker.recent_imports.clone();

    let shared_state = initialize_shared_state(
        default_guest_fs_base(std::path::Path::new(binary_path), "arm64_ios"),
        process_bootstrap,
    );
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

    let runtime_context = RuntimeContext::new(
        process_name,
        binary_path,
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
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "entry", "entry")
                .arg("Pc", format!("0x{:X}", actual_entry))
                .arg("DoneAddr", format!("0x{:X}", done_addr)),
        );
    }
    emulator.write_reg("pc", actual_entry)?;
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
            actual_entry,
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
