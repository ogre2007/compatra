//! Legacy arm64 Mach-O runner used by the no-dyld binary entrypoint.

use crate::macos::analysis_arm64_cpp_imports::{
    install_prepared_analysis_arm64_hooks, prepare_analysis_arm64_hooks,
};
use crate::macos::apple_imports::{install_apple_data_symbols, install_apple_imports};
use crate::macos::arm64_dynamic_imports::install_arm64_dynamic_imports;
use crate::macos::arm64_import_stubs::arm64_import_can_resolve_to_guest_library;
use crate::macos::binary_bootstrap::{map_binary_segments, setup_bootstrap_state};
use crate::macos::binary_setup::{
    find_runtime_symbols, install_arm64_indirect_branch_hooks, install_arm64_lse_atomic_hooks,
    log_runtime_symbols, patch_arm64_symbol_pointers_with_data_symbols,
    patch_arm64_symbol_pointers_with_slide_and_data_symbols, resolve_entry,
};
use crate::macos::diagnostics::{install_diagnostic_hooks, run_with_diagnostics, RunReport};
use crate::macos::io_imports::install_io_imports;
use crate::macos::process_imports::install_process_imports;
use crate::macos::pthread_imports::install_pthread_imports;
use crate::macos::runner_support::{
    initialize_import_tracker, initialize_shared_state_with_mode, install_return_stubs,
    Arm64ExitHandler, Arm64ExitHandlerKind,
};
use crate::macos::runtime_hooks::install_runtime_hooks;
use crate::macos::time_imports::install_time_imports;
use crate::macos::{
    align_up, default_guest_fs_base, ensure_macho_cpu, install_runtime_plugins, process_event,
    GuestImageRegistry, GuestLibraryChainedFixupReport, GuestLibraryImage, GuestLibrarySet,
    MacosCpu, RuntimeContext, RuntimeMode, SyscallRuntimePlugin, TraceMetadata,
    COMPATRA_GUEST_LIBS_ENV,
};
use crate::{ArchType, Emulator, MachoBinary, UnicornEmulator};

use crate::macos::{memory_event, SharedTraceBus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const INDIRECT_BRANCH_MODE_ENV: &str = "COMPATRA_INDIRECT_BRANCH_MODE";
const GUEST_LIBRARY_LOAD_GAP: u64 = 0x10000;

fn section_pointer_values(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    section_name: &str,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    section_pointer_values_with_slide(emulator, binary, 0, section_name)
}

fn section_pointer_values_with_slide(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    slide: u64,
    section_name: &str,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let section = binary
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
            name == section_name
        });
    let Some(sec) = section else {
        return Ok(Vec::new());
    };
    if sec.size == 0 || sec.size % 8 != 0 {
        return Ok(Vec::new());
    }

    let mut values = Vec::with_capacity((sec.size / 8) as usize);
    for i in 0..(sec.size / 8) as usize {
        let slot_addr = sec.addr.wrapping_add(slide) + (i as u64) * 8;
        let bytes = emulator.read_memory(slot_addr, 8)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| format!("short read on {section_name} slot"))?;
        let addr = u64::from_le_bytes(arr);
        if addr != 0 {
            values.push(addr);
        }
    }
    Ok(values)
}

fn guest_library_runtime_pointer(image: &GuestLibraryImage, address: u64) -> Option<u64> {
    if address == 0 {
        return None;
    }
    let runtime_address = if address >= image.vm_range.start && address < image.vm_range.end {
        address.wrapping_add(image.slide)
    } else {
        address
    };
    (runtime_address >= image.mapped_range.start && runtime_address < image.mapped_range.end)
        .then_some(runtime_address)
}

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
    pre_main_init_addrs: &[u64],
    main_addr: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    // Read every initializer address out of guest memory — the
    // chained-fixups pass has already replaced the on-disk chain
    // entries with resolved absolute addresses.
    let main_init_addrs = section_pointer_values(emulator, binary, "__mod_init_func")?;
    let mut init_addrs = pre_main_init_addrs.to_vec();
    init_addrs.extend(main_init_addrs.iter().copied());
    if init_addrs.is_empty() {
        return Ok(None);
    }

    // ARM64 trampoline layout:
    //   sub sp, sp, #32                ; reserve scratch frame
    //   stp x0, x1, [sp]               ; save argc, argv
    //   str x2, [sp, #16]              ; save envp
    //   str x30, [sp, #24]             ; save original return target
    //   ; per initializer:
    //   movz x16, #imm0
    //   movk x16, #imm1, lsl #16
    //   movk x16, #imm2, lsl #32
    //   movk x16, #imm3, lsl #48
    //   blr  x16
    //   ; after the last initializer:
    //   ldp x0, x1, [sp]
    //   ldr x2, [sp, #16]
    //   ldr x30, [sp, #24]
    //   add sp, sp, #32
    //   movz x16, #imm0    ; <main>
    //   movk x16, #imm1, lsl #16
    //   movk x16, #imm2, lsl #32
    //   movk x16, #imm3, lsl #48
    //   br   x16
    //
    // Each init = 5 instructions (20 bytes); prelude/epilogue =
    // 8 instructions (32 bytes); main jump = 5 instructions (20
    // bytes). Add a 4-byte ret guard at the tail for safety.
    let mut code: Vec<u8> = Vec::new();

    // Prelude.
    code.extend_from_slice(&0xD10083FFu32.to_le_bytes()); // sub sp, sp, #32
    code.extend_from_slice(&0xA90007E0u32.to_le_bytes()); // stp x0, x1, [sp]
    code.extend_from_slice(&0xF9000BE2u32.to_le_bytes()); // str x2, [sp, #16]
    code.extend_from_slice(&0xF9000FFEu32.to_le_bytes()); // str x30, [sp, #24]

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

    // Epilogue: restore argc/argv/envp and the original LR. The
    // initializer BLR instructions clobber x30; without restoring it, main
    // returns into this trampoline and repeats instead of reaching done_addr.
    code.extend_from_slice(&0xA94007E0u32.to_le_bytes()); // ldp x0, x1, [sp]
    code.extend_from_slice(&0xF9400BE2u32.to_le_bytes()); // ldr x2, [sp, #16]
    code.extend_from_slice(&0xF9400FFEu32.to_le_bytes()); // ldr x30, [sp, #24]
    code.extend_from_slice(&0x910083FFu32.to_le_bytes()); // add sp, sp, #32

    // Tail-call main via br x16 with LR restored to done_addr.
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
                .arg("GuestInitCount", pre_main_init_addrs.len().to_string())
                .arg("MainInitCount", main_init_addrs.len().to_string())
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

fn map_guest_libraries_from_env(
    emulator: &mut UnicornEmulator,
    max_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<GuestLibrarySet, Box<dyn std::error::Error>> {
    let load_base = align_up(
        max_addr.saturating_add(GUEST_LIBRARY_LOAD_GAP),
        GUEST_LIBRARY_LOAD_GAP,
    );
    let guest_libraries = GuestLibrarySet::from_env(load_base)?;
    if guest_libraries.is_empty() {
        return Ok(guest_libraries);
    }

    guest_libraries.map_into(emulator)?;
    if let Some(bus) = trace_bus {
        let _ = bus.send(
            process_event(metadata, "guest-libraries", "guest_libraries")
                .arg("Env", COMPATRA_GUEST_LIBS_ENV)
                .arg("Count", guest_libraries.image_count().to_string())
                .arg("Exports", guest_libraries.export_count().to_string())
                .arg("MappedEnd", format!("0x{:X}", guest_libraries.mapped_end())),
        );
        for image in guest_libraries.images() {
            let _ = bus.send(
                process_event(metadata, "guest-library", "guest_library")
                    .arg("Path", image.path.display().to_string())
                    .arg(
                        "InstallName",
                        image
                            .install_name
                            .clone()
                            .unwrap_or_else(|| "<none>".to_string()),
                    )
                    .arg("LoadBase", format!("0x{:X}", image.load_base))
                    .arg("Slide", format!("0x{:X}", image.slide))
                    .arg("Exports", image.export_count().to_string()),
            );
        }
    }

    Ok(guest_libraries)
}

fn emit_guest_image_registry_trace(
    registry: &GuestImageRegistry,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) {
    let Some(bus) = trace_bus else {
        return;
    };
    let _ = bus.send(
        process_event(metadata, "guest-image-registry", "guest_image_registry")
            .arg("Images", registry.image_count().to_string())
            .arg("Libraries", registry.library_count().to_string())
            .arg(
                "MappedStart",
                registry
                    .mapped_start()
                    .map(|addr| format!("0x{:X}", addr))
                    .unwrap_or_else(|| "0x0".to_string()),
            )
            .arg(
                "MappedEnd",
                registry
                    .mapped_end()
                    .map(|addr| format!("0x{:X}", addr))
                    .unwrap_or_else(|| "0x0".to_string()),
            ),
    );
    for record in registry.records() {
        let _ = bus.send(
            process_event(metadata, "guest-image", "guest_image")
                .arg("Index", record.index.to_string())
                .arg("Kind", record.kind.as_str())
                .arg("Path", record.path.display().to_string())
                .arg(
                    "InstallName",
                    record
                        .install_name
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                )
                .arg("Slide", format!("0x{:X}", record.slide))
                .arg("VmStart", format!("0x{:X}", record.vm_range.start))
                .arg("VmEnd", format!("0x{:X}", record.vm_range.end))
                .arg("MappedStart", format!("0x{:X}", record.mapped_range.start))
                .arg("MappedEnd", format!("0x{:X}", record.mapped_range.end))
                .arg("Exports", record.export_count.to_string()),
        );
    }
}

fn emit_guest_library_chained_fixup_reports(
    reports: &[GuestLibraryChainedFixupReport],
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) {
    let Some(bus) = trace_bus else {
        return;
    };
    for report in reports {
        if let Some(stats) = report.stats {
            if stats.bound + stats.rebased + stats.unresolved == 0 {
                continue;
            }
            let _ = bus.send(
                process_event(
                    metadata,
                    "guest-library-chained-fixups",
                    "guest_library_chained_fixups",
                )
                .arg("Path", report.path.display().to_string())
                .arg(
                    "InstallName",
                    report
                        .install_name
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                )
                .arg("Bound", stats.bound.to_string())
                .arg("Rebased", stats.rebased.to_string())
                .arg("Unresolved", stats.unresolved.to_string()),
            );
        } else if let Some(error) = &report.error {
            let _ = bus.send(
                process_event(
                    metadata,
                    "guest-library-chained-fixups-error",
                    "guest_library_chained_fixups",
                )
                .arg("Path", report.path.display().to_string())
                .arg(
                    "InstallName",
                    report
                        .install_name
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                )
                .arg("Error", error.clone()),
            );
        }
    }
}

fn collect_guest_library_mod_init_entries(
    emulator: &mut UnicornEmulator,
    guest_libraries: &GuestLibrarySet,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Vec<u64> {
    let mut entries = Vec::new();
    for image in guest_libraries.images() {
        match section_pointer_values_with_slide(
            emulator,
            &image.binary,
            image.slide,
            "__mod_init_func",
        ) {
            Ok(raw_addrs) if !raw_addrs.is_empty() => {
                let init_addrs = raw_addrs
                    .into_iter()
                    .filter_map(|addr| guest_library_runtime_pointer(image, addr))
                    .collect::<Vec<_>>();
                if init_addrs.is_empty() {
                    continue;
                }
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        memory_event(metadata, "guest-library-mod-init-handlers")
                            .arg("Path", image.path.display().to_string())
                            .arg(
                                "InstallName",
                                image
                                    .install_name
                                    .clone()
                                    .unwrap_or_else(|| "<none>".to_string()),
                            )
                            .arg("Count", init_addrs.len().to_string())
                            .arg("First", format!("0x{:X}", init_addrs[0])),
                    );
                }
                entries.extend(init_addrs);
            }
            Ok(_) => {}
            Err(err) => {
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        memory_event(metadata, "guest-library-mod-init-error")
                            .arg("Path", image.path.display().to_string())
                            .arg("Error", format!("{}", err)),
                    );
                }
            }
        }
    }
    entries
}

fn register_mod_term_handlers(
    shared_state: &crate::macos::arm64_state::Arm64SharedState,
    functions: &[u64],
) {
    if let Ok(mut handlers) = shared_state.exit_handlers.lock() {
        for function in functions.iter().copied() {
            handlers.push(Arm64ExitHandler {
                function,
                argument: 0,
                dso_handle: 0,
                kind: Arm64ExitHandlerKind::ModTerm,
            });
        }
    }
}

fn register_guest_library_mod_term_handlers(
    emulator: &mut UnicornEmulator,
    guest_libraries: &GuestLibrarySet,
    shared_state: &crate::macos::arm64_state::Arm64SharedState,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) {
    for image in guest_libraries.images() {
        match section_pointer_values_with_slide(
            emulator,
            &image.binary,
            image.slide,
            "__mod_term_func",
        ) {
            Ok(raw_addrs) if !raw_addrs.is_empty() => {
                let term_addrs = raw_addrs
                    .into_iter()
                    .filter_map(|addr| guest_library_runtime_pointer(image, addr))
                    .collect::<Vec<_>>();
                if term_addrs.is_empty() {
                    continue;
                }
                register_mod_term_handlers(shared_state, &term_addrs);
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        memory_event(metadata, "guest-library-mod-term-handlers")
                            .arg("Path", image.path.display().to_string())
                            .arg(
                                "InstallName",
                                image
                                    .install_name
                                    .clone()
                                    .unwrap_or_else(|| "<none>".to_string()),
                            )
                            .arg("Count", term_addrs.len().to_string())
                            .arg("First", format!("0x{:X}", term_addrs[0])),
                    );
                }
            }
            Ok(_) => {}
            Err(err) => {
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        memory_event(metadata, "guest-library-mod-term-error")
                            .arg("Path", image.path.display().to_string())
                            .arg("Error", format!("{}", err)),
                    );
                }
            }
        }
    }
}

fn patch_guest_library_symbol_pointers(
    emulator: &mut UnicornEmulator,
    guest_libraries: &GuestLibrarySet,
    stub_map: &std::collections::HashMap<String, u64>,
    data_symbols: Option<&std::collections::HashMap<String, u64>>,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
    process_name: &str,
) {
    for image in guest_libraries.images() {
        let image_undefs = image.binary.get_undefined_symbols();
        match patch_arm64_symbol_pointers_with_slide_and_data_symbols(
            emulator,
            &image.binary,
            image.slide,
            &image_undefs,
            stub_map,
            data_symbols,
            done_addr,
            trace_bus,
            process_name,
        ) {
            Ok(()) => {
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        process_event(
                            metadata,
                            "guest-library-symbol-pointers",
                            "patch_symbol_pointers",
                        )
                        .arg("Path", image.path.display().to_string())
                        .arg(
                            "InstallName",
                            image
                                .install_name
                                .clone()
                                .unwrap_or_else(|| "<none>".to_string()),
                        )
                        .arg("Slide", format!("0x{:X}", image.slide)),
                    );
                }
            }
            Err(err) => {
                if let Some(bus) = trace_bus {
                    let _ = bus.send(
                        process_event(
                            metadata,
                            "guest-library-symbol-pointers-error",
                            "patch_symbol_pointers",
                        )
                        .arg("Path", image.path.display().to_string())
                        .arg("Error", format!("{}", err)),
                    );
                }
            }
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

    let mut max_addr = map_binary_segments(&mut emulator, &binary, &trace_bus, process_name)?;
    let guest_libraries =
        map_guest_libraries_from_env(&mut emulator, max_addr, &trace_bus, &metadata)?;
    if !guest_libraries.is_empty() {
        max_addr = max_addr.max(guest_libraries.mapped_end());
    }
    let guest_images = GuestImageRegistry::from_loaded_images(
        std::path::Path::new(binary_path),
        &binary,
        0,
        &guest_libraries,
    );
    emit_guest_image_registry_trace(&guest_images, &trace_bus, &metadata);
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
    let mut heap_cursor = bootstrap_state.heap_cursor;
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

    let mut undefs = binary.get_undefined_symbols();
    let symtab_undef_count = undefs.len();
    match crate::macos::imports::chained_fixup_import_symbols(&binary) {
        Ok(chained_imports) => {
            let chained_count = chained_imports.len();
            let mut added = 0usize;
            for name in chained_imports {
                let normalized = crate::macos::imports::normalize_import_symbol(name.clone());
                let already_present = undefs.iter().any(|(existing, _)| {
                    existing == &name
                        || crate::macos::imports::normalize_import_symbol(existing.clone())
                            == normalized
                });
                if !already_present {
                    undefs.push((name, 0));
                    added += 1;
                }
            }
            if let Some(bus) = &trace_bus {
                let _ = bus.send(
                    process_event(&metadata, "static-import-set", "static_import_set")
                        .arg("SymtabUndefined", symtab_undef_count.to_string())
                        .arg("ChainedImports", chained_count.to_string())
                        .arg("Added", added.to_string())
                        .arg("Total", undefs.len().to_string()),
                );
            }
        }
        Err(err) => {
            if let Some(bus) = &trace_bus {
                let _ = bus.send(
                    process_event(&metadata, "static-import-set-error", "static_import_set")
                        .arg("Error", format!("{}", err)),
                );
            }
        }
    }
    let guest_import_report = guest_libraries.extend_undefined_imports(&mut undefs);
    if guest_import_report.added > 0 || !guest_import_report.errors.is_empty() {
        if let Some(bus) = &trace_bus {
            let mut event = process_event(
                &metadata,
                "guest-library-import-set",
                "guest_library_import_set",
            )
            .arg("Added", guest_import_report.added.to_string())
            .arg("Total", guest_import_report.total.to_string());
            if !guest_import_report.errors.is_empty() {
                event = event.arg("Errors", guest_import_report.errors.join("; "));
            }
            let _ = bus.send(event);
        }
    }
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

    let mut shared_state = initialize_shared_state_with_mode(
        default_guest_fs_base(std::path::Path::new(binary_path), "arm64_ios"),
        process_bootstrap.clone(),
        runtime_mode,
    );
    shared_state.main_image_header = binary.header_address();
    shared_state.main_image_slide = 0;

    let apple_data_symbols = install_apple_data_symbols(
        &mut emulator,
        &shared_state.apple_runtime,
        &mut heap_cursor,
        undefs.iter().map(|(name, _)| name.as_str()),
    )?;
    if let Some(bus) = &trace_bus {
        let preview = apple_data_symbols
            .iter()
            .filter(|(name, _)| name.starts_with("_kSec"))
            .take(8)
            .map(|(name, addr)| format!("{name}=0x{addr:X}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = bus.send(
            process_event(&metadata, "apple-data-symbols", "apple_data_symbols")
                .arg("Count", apple_data_symbols.len().to_string())
                .arg("Preview", preview),
        );
    }

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
    let guest_library_bindings =
        guest_libraries.apply_import_bindings(&undefs, &mut stub_map, |name| {
            arm64_import_can_resolve_to_guest_library(name, runtime_mode)
        });
    if !guest_library_bindings.is_empty() {
        if let Some(bus) = &trace_bus {
            let preview = guest_library_bindings
                .iter()
                .take(8)
                .map(|binding| {
                    format!(
                        "{}=0x{:X}({})",
                        binding.import_name,
                        binding.address,
                        binding.install_name.as_deref().unwrap_or_else(|| {
                            binding.library_path.to_str().unwrap_or("<guest-lib>")
                        })
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let _ = bus.send(
                process_event(
                    &metadata,
                    "guest-library-bindings",
                    "guest_library_bindings",
                )
                .arg("Count", guest_library_bindings.len().to_string())
                .arg("Preview", preview),
            );
        }
    }

    let analysis_hook_plan = prepare_analysis_arm64_hooks(
        runtime_mode,
        &mut emulator,
        &mmap_next,
        mmap_end,
        done_addr,
        &trace_bus,
        &metadata,
    );
    let mut data_symbols = apple_data_symbols;
    data_symbols.extend(
        analysis_hook_plan
            .cpp_data_symbols
            .iter()
            .map(|(name, addr)| (name.clone(), *addr)),
    );

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
        Some(&data_symbols),
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
    let guest_library_fixup_reports = guest_libraries.process_chained_fixups(
        &mut emulator,
        &stub_map,
        Some(&data_symbols),
        done_addr,
    );
    emit_guest_library_chained_fixup_reports(&guest_library_fixup_reports, &trace_bus, &metadata);
    install_prepared_analysis_arm64_hooks(
        analysis_hook_plan,
        &mut emulator,
        &stub_map,
        &mmap_next,
        mmap_end,
        &trace_bus,
        &import_tracker,
        &process_name,
    )?;

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
        stub_region,
        stub_name_map.clone(),
        next_dynamic_stub_addr.clone(),
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
        stub_region,
        stub_name_map.clone(),
        next_dynamic_stub_addr.clone(),
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
        &guest_libraries,
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
    patch_arm64_symbol_pointers_with_data_symbols(
        &mut emulator,
        &binary,
        &undefs,
        &stub_map,
        Some(&data_symbols),
        done_addr,
        &trace_bus,
        &process_name,
    )?;
    patch_guest_library_symbol_pointers(
        &mut emulator,
        &guest_libraries,
        &stub_map,
        Some(&data_symbols),
        done_addr,
        &trace_bus,
        &metadata,
        &process_name,
    );
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

    if runtime_mode.is_compat() {
        register_guest_library_mod_term_handlers(
            &mut emulator,
            &guest_libraries,
            &shared_state,
            &trace_bus,
            &metadata,
        );
        match section_pointer_values(&mut emulator, &binary, "__mod_term_func") {
            Ok(term_addrs) if !term_addrs.is_empty() => {
                register_mod_term_handlers(&shared_state, &term_addrs);
                if let Some(bus) = &trace_bus {
                    let _ = bus.send(
                        memory_event(&metadata, "mod-term-handlers")
                            .arg("Count", term_addrs.len().to_string())
                            .arg("First", format!("0x{:X}", term_addrs[0])),
                    );
                }
            }
            Ok(_) => {}
            Err(err) => {
                if let Some(bus) = &trace_bus {
                    let _ = bus.send(
                        memory_event(&metadata, "mod-term-error").arg("Error", format!("{}", err)),
                    );
                }
            }
        }
    }

    let actual_entry = resolve_entry(&binary);
    let guest_init_addrs = collect_guest_library_mod_init_entries(
        &mut emulator,
        &guest_libraries,
        &trace_bus,
        &metadata,
    );

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
        &guest_init_addrs,
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
