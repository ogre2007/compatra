//! arm64 import-stub installation and tracking.
//!
//! The no-dyld runner resolves undefined symbols into tiny arm64 stubs. This
//! module owns the stub bytes, import-hit tracking, and arm64 ABI handoff into
//! architecture-neutral compatibility services.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::macos::apple_imports::is_apple_import_symbol;
use crate::macos::arm64_compat_memory::Arm64CompatGuestMemory;
use crate::macos::arm64_state::Arm64SharedState;
use crate::macos::compat::CompatibilityServices;
use crate::macos::plugin_events::import_event;
use crate::macos::{
    emit_runner_trace_event, process_event, push_recent_trace, runtime_process_metadata, Emulator,
    RuntimeMode, SharedTraceBus, StubRegion, TraceEvent, TraceMetadata,
};
use crate::UnicornEmulator;
use compatra_arch_arm64::stubs::{IMPORT_STUB_STRIDE, RETURN_STUB_BYTES, RETURN_ZERO_STUB_BYTES};

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
    emu: &mut UnicornEmulator,
    symbol: &str,
    shared_state: &Arm64SharedState,
    errno_ptr: u64,
) {
    let mut args = [0u64; 8];
    for (idx, arg) in args.iter_mut().enumerate() {
        let Ok(value) = emu.read_reg(&format!("x{idx}")) else {
            return;
        };
        *arg = value;
    }
    let stack_ptr = emu.read_reg("sp").ok();

    let mut memory = Arm64CompatGuestMemory {
        emulator: emu,
        shared_state,
    };
    if let Some(result) = compatra::CompatibilityServices.proxy_arm64_import_with_stack(
        &mut memory,
        symbol,
        &args,
        stack_ptr,
    ) {
        let _ = emu.write_reg("x0", result.return_value);
        if let Some(errno) = result.errno {
            let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
        }
        if let Some(reason) = compatra::take_pending_stop_reason() {
            if let Ok(mut stop_reason) = shared_state.synthetic_stop_reason.lock() {
                if stop_reason.is_none() {
                    *stop_reason = Some(reason);
                }
            }
            let _ = emu.stop_emulation();
        }
    };
}

fn arm64_import_has_process_stdio_runtime_hook(symbol: &str) -> bool {
    matches!(
        symbol,
        "_clearerr" | "_feof" | "_ferror" | "_fgets" | "_fread"
    )
}

fn arm64_import_has_analysis_process_runtime_hook(symbol: &str) -> bool {
    matches!(symbol, "_pclose" | "_popen")
}

pub(crate) fn arm64_import_has_runtime_hook(symbol: &str, runtime_mode: RuntimeMode) -> bool {
    if arm64_import_has_process_stdio_runtime_hook(symbol) {
        return runtime_mode.is_analysis() || runtime_mode.is_compat();
    }
    if arm64_import_has_analysis_process_runtime_hook(symbol) {
        return runtime_mode.is_analysis();
    }
    if is_apple_import_symbol(symbol) {
        return true;
    }
    matches!(
        symbol,
        "___error"
            | "__NSGetArgc"
            | "__NSGetArgv"
            | "__NSGetEnviron"
            | "__Znwm"
            | "__Znam"
            | "__ZdlPv"
            | "__ZdaPv"
            | "__ZdlPvm"
            | "__ZdaPvm"
            | "__exit"
            | "__tlv_atexit"
            | "__tlv_bootstrap"
            | "_atexit"
            | "___cxa_atexit"
            | "_calloc"
            | "_cmalloc"
            | "_close"
            | "_closedir"
            | "_dispatch_release"
            | "_dispatch_semaphore_create"
            | "_dispatch_semaphore_signal"
            | "_dispatch_semaphore_wait"
            | "_dlclose"
            | "_dlerror"
            | "_dlopen"
            | "_dlsym"
            | "_dup2"
            | "_execve"
            | "_exit"
            | "_fcntl"
            | "_fdopendir"
            | "_fork"
            | "_free"
            | "_fstat"
            | "_getcwd"
            | "_getenv"
            | "_getrlimit"
            | "_kevent"
            | "_kill"
            | "_kqueue"
            | "_lstat"
            | "_mach_absolute_time"
            | "_mach_timebase_info"
            | "_malloc"
            | "_memcpy"
            | "_memmove"
            | "_memset"
            | "_memcmp"
            | "_mmap"
            | "_mprotect"
            | "_munmap"
            | "_notify_is_valid_token"
            | "_open"
            | "_opendir"
            | "_pipe"
            | "_posix_memalign"
            | "_posix_spawn"
            | "_posix_spawn_file_actions_adddup2"
            | "_posix_spawn_file_actions_destroy"
            | "_posix_spawn_file_actions_init"
            | "_posix_spawnp"
            | "_pthread_cond_broadcast"
            | "_pthread_cond_init"
            | "_pthread_cond_signal"
            | "_pthread_cond_timedwait_relative_np"
            | "_pthread_cond_wait"
            | "_pthread_create"
            | "_pthread_detach"
            | "_pthread_exit"
            | "_pthread_get_stackaddr_np"
            | "_pthread_get_stacksize_np"
            | "_pthread_getspecific"
            | "_pthread_join"
            | "_pthread_key_create"
            | "_pthread_mutex_init"
            | "_pthread_mutex_lock"
            | "_pthread_mutex_unlock"
            | "_pthread_once"
            | "_pthread_self"
            | "_pthread_setname_np"
            | "_pthread_setspecific"
            | "_pthread_threadid_np"
            | "_read"
            | "_readdir_r"
            | "_realloc"
            | "_sigaction"
            | "_sigaltstack"
            | "_signal"
            | "_sleep"
            | "_stat"
            | "_strlen"
            | "_sysconf"
            | "_sysctl"
            | "_sysctlbyname"
            | "_usleep"
            | "_wait4"
            | "_waitpid"
            | "_write"
            | "_xpc_date_create_from_current"
            | "_CFArrayAppendValue"
            | "_CFArrayCreate"
            | "_CFArrayCreateMutable"
            | "_CFArrayGetCount"
            | "_CFArrayGetValueAtIndex"
            | "_CFDataCreate"
            | "_CFDataGetBytePtr"
            | "_CFDataGetLength"
            | "_CFDateCreate"
            | "_CFDictionaryCreate"
            | "_CFDictionaryGetValueIfPresent"
            | "_CFErrorCopyDescription"
            | "_CFErrorCreate"
            | "_CFErrorGetCode"
            | "_CFGetTypeID"
            | "_CFNumberGetTypeID"
            | "_CFNumberGetValue"
            | "_CFRelease"
            | "_CFRetain"
            | "_CFStringCreateExternalRepresentation"
            | "_CFStringCreateWithBytes"
            | "_CGMainDisplayID"
            | "_CGDisplayPixelsWide"
            | "_CGDisplayPixelsHigh"
            | "_CGDisplayIsActive"
            | "_CGDisplayIsOnline"
            | "_CGPreflightScreenCaptureAccess"
            | "_CGRequestScreenCaptureAccess"
            | "_CGDisplayCreateImage"
            | "_CGImageGetWidth"
            | "_CGImageGetHeight"
            | "_CGImageGetBitsPerPixel"
            | "_CGImageGetBytesPerRow"
            | "_CGImageGetDataProvider"
            | "_CGImageRelease"
            | "_CGDataProviderCopyData"
            | "_CGEventSourceKeyState"
            | "_CGPreflightListenEventAccess"
            | "_CGRequestListenEventAccess"
            | "_AXIsProcessTrusted"
            | "_AXIsProcessTrustedWithOptions"
            | "_NSApplicationLoad"
            | "_NSApplicationMain"
            | "_SecCertificateCopyData"
            | "_SecCertificateCreateWithData"
            | "_SecItemCopyMatching"
            | "_SecKeychainCopyDefault"
            | "_SecKeychainFindGenericPassword"
            | "_SecKeychainGetPath"
            | "_SecKeychainItemFreeContent"
            | "_SecKeychainOpen"
            | "_SecPolicyCreateSSL"
            | "_SecTrustCreateWithCertificates"
            | "_SecTrustEvaluateWithError"
            | "_SecTrustGetCertificateAtIndex"
            | "_SecTrustGetCertificateCount"
            | "_SecTrustSetVerifyDate"
    )
}

pub(crate) fn arm64_import_can_resolve_to_guest_library(
    symbol: &str,
    runtime_mode: RuntimeMode,
) -> bool {
    if CompatibilityServices::for_mode(runtime_mode)
        .is_some_and(|compat| compat.should_proxy_import(symbol))
    {
        return false;
    }
    !arm64_import_has_runtime_hook(symbol, runtime_mode)
}

fn arm64_stub_bucket_is_reserved(stub_region: StubRegion, bucket: u64) -> bool {
    bucket == stub_region.done_addr || Some(bucket) == stub_region.thread_exit_stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_stat_imports_are_handled_by_exact_hooks() {
        assert!(arm64_import_has_runtime_hook("_stat", RuntimeMode::Compat));
        assert!(arm64_import_has_runtime_hook("_lstat", RuntimeMode::Compat));
        assert!(arm64_import_has_runtime_hook("_fstat", RuntimeMode::Compat));
    }

    #[test]
    fn runtime_hook_classifier_covers_non_generic_import_groups() {
        assert!(arm64_import_has_runtime_hook("_dlsym", RuntimeMode::Compat));
        assert!(arm64_import_has_runtime_hook(
            "_CFStringCreateWithBytes",
            RuntimeMode::Compat
        ));
        assert!(arm64_import_has_runtime_hook(
            "CFStringCreateWithCString",
            RuntimeMode::Compat
        ));
        assert!(arm64_import_has_runtime_hook(
            "_pthread_create",
            RuntimeMode::Compat
        ));
        assert!(arm64_import_has_runtime_hook(
            "_pthread_once",
            RuntimeMode::Compat
        ));
        assert!(arm64_import_has_runtime_hook(
            "_pthread_threadid_np",
            RuntimeMode::Compat
        ));
        assert!(arm64_import_has_runtime_hook("__Znwm", RuntimeMode::Compat));
        assert!(!arm64_import_has_runtime_hook(
            "_future_unhandled_import",
            RuntimeMode::Compat
        ));
    }

    #[test]
    fn guest_library_resolution_only_covers_unhandled_imports() {
        assert!(arm64_import_can_resolve_to_guest_library(
            "__ZN5guest3runEv",
            RuntimeMode::Compat
        ));
        assert!(!arm64_import_can_resolve_to_guest_library(
            "_open",
            RuntimeMode::Compat
        ));
        #[cfg(target_os = "macos")]
        {
            assert!(!arm64_import_can_resolve_to_guest_library(
                "_mkdir",
                RuntimeMode::Compat
            ));
            assert!(!arm64_import_can_resolve_to_guest_library(
                "_system",
                RuntimeMode::Compat
            ));
            for symbol in ["_getpwuid", "_getpwnam", "_getlogin_r", "_getgroups"] {
                assert!(!arm64_import_can_resolve_to_guest_library(
                    symbol,
                    RuntimeMode::Compat
                ));
            }
        }
        assert!(!arm64_import_can_resolve_to_guest_library(
            "_CFStringCreateWithBytes",
            RuntimeMode::Compat
        ));
    }

    #[test]
    fn runtime_hook_classifier_covers_cf_bundle_and_iokit_compat_imports() {
        for symbol in [
            "_CFStringGetCStringPtr",
            "_CFStringCreateCopy",
            "_CFStringCompare",
            "_CFURLCreateWithFileSystemPath",
            "_CFURLCopyFileSystemPath",
            "_CFBundleGetMainBundle",
            "_CFBundleCopyBundleURL",
            "_IONotificationPortDestroy",
            "_IOServiceMatching",
            "_IOServiceGetMatchingService",
            "_IOServiceGetMatchingServices",
            "_IOIteratorNext",
            "_IORegistryEntryCreateCFProperty",
            "_IOObjectRelease",
        ] {
            assert!(
                arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat),
                "{symbol} should be dispatched by the arm64 compat runtime"
            );
        }
    }

    #[test]
    fn runtime_hook_classifier_covers_corefoundation_object_compat_imports() {
        for symbol in [
            "_CFStringCreateWithBytes",
            "_CFStringCreateExternalRepresentation",
            "_CFStringGetTypeID",
            "_CFDataCreate",
            "_CFDataGetLength",
            "_CFDataGetBytePtr",
            "_CFDataGetTypeID",
            "_CFArrayCreateMutable",
            "_CFArrayCreate",
            "_CFArrayAppendValue",
            "_CFArrayGetCount",
            "_CFArrayGetValueAtIndex",
            "_CFArrayGetTypeID",
            "_CFDictionaryCreate",
            "_CFDictionaryGetValueIfPresent",
            "_CFDictionaryGetTypeID",
            "_CFDateCreate",
            "_CFErrorCreate",
            "_CFErrorGetCode",
            "_CFErrorCopyDescription",
            "_CFGetTypeID",
            "_CFNumberGetTypeID",
            "_CFNumberGetValue",
            "_CFBooleanGetTypeID",
            "_CFBooleanGetValue",
            "_xpc_date_create_from_current",
        ] {
            assert!(
                arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat),
                "{symbol} should be dispatched by the arm64 compat runtime"
            );
        }
    }

    #[test]
    fn runtime_hook_classifier_covers_security_object_compat_imports() {
        for symbol in [
            "_SecCertificateCreateWithData",
            "_SecCertificateCopyData",
            "_SecItemCopyMatching",
            "_SecKeychainCopyDefault",
            "_SecKeychainOpen",
            "_SecKeychainGetPath",
            "_SecKeychainFindGenericPassword",
            "_SecKeychainItemFreeContent",
            "_SecPolicyCreateSSL",
            "_SecTrustCreateWithCertificates",
            "_SecTrustEvaluateWithError",
            "_SecTrustGetCertificateCount",
            "_SecTrustGetCertificateAtIndex",
            "_SecTrustSetVerifyDate",
        ] {
            assert!(
                arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat),
                "{symbol} should be dispatched by the arm64 compat runtime"
            );
        }
    }

    #[test]
    fn runtime_hook_classifier_covers_ui_compat_imports() {
        for symbol in [
            "_NSApplicationLoad",
            "_NSApplicationMain",
            "_CGMainDisplayID",
            "_CGDisplayPixelsWide",
            "_CGDisplayPixelsHigh",
            "_CGDisplayIsActive",
            "_CGDisplayIsOnline",
            "_CGPreflightScreenCaptureAccess",
            "_CGRequestScreenCaptureAccess",
            "_CGDisplayCreateImage",
            "_CGImageGetWidth",
            "_CGImageGetHeight",
            "_CGImageGetBitsPerPixel",
            "_CGImageGetBytesPerRow",
            "_CGImageGetDataProvider",
            "_CGImageRelease",
            "_CGDataProviderCopyData",
            "_CGEventSourceKeyState",
            "_CGPreflightListenEventAccess",
            "_CGRequestListenEventAccess",
            "_AXIsProcessTrusted",
            "_AXIsProcessTrustedWithOptions",
        ] {
            assert!(
                arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat),
                "{symbol} should be dispatched by the arm64 UI compat runtime"
            );
        }
    }

    #[test]
    fn runtime_hook_classifier_covers_objc_compat_imports() {
        for symbol in [
            "_objc_getClass",
            "_objc_lookUpClass",
            "_objc_getMetaClass",
            "_object_getClass",
            "_class_getName",
            "_sel_registerName",
            "_sel_getName",
            "_objc_msgSend",
            "_objc_alloc",
            "_objc_alloc_init",
            "_objc_autoreleasePoolPush",
            "_objc_retain",
            "_objc_release",
            "_objc_storeStrong",
            "_objc_loadWeakRetained",
        ] {
            assert!(
                arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat),
                "{symbol} should be dispatched by the arm64 compat runtime"
            );
        }
    }

    #[test]
    fn process_stdio_hooks_cover_analysis_and_compat_modes() {
        for symbol in ["_fgets", "_fread", "_feof", "_ferror", "_clearerr"] {
            assert!(arm64_import_has_runtime_hook(symbol, RuntimeMode::Analysis));
            assert!(arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat));
        }
    }

    #[test]
    fn popen_hooks_are_analysis_only_so_compat_can_host_proxy() {
        for symbol in ["_popen", "_pclose"] {
            assert!(arm64_import_has_runtime_hook(symbol, RuntimeMode::Analysis));
            assert!(!arm64_import_has_runtime_hook(symbol, RuntimeMode::Compat));
            #[cfg(target_os = "macos")]
            assert!(!arm64_import_can_resolve_to_guest_library(
                symbol,
                RuntimeMode::Compat
            ));
        }
    }

    #[test]
    fn reserved_terminal_stub_buckets_are_not_import_misses() {
        let stub_region = StubRegion {
            base: 0x2000_0000,
            size: 0x10000,
            done_addr: 0x2000_0800,
            thread_exit_stub: Some(0x2000_0900),
        };

        assert!(arm64_stub_bucket_is_reserved(
            stub_region,
            stub_region.bucket(stub_region.done_addr)
        ));
        assert!(arm64_stub_bucket_is_reserved(
            stub_region,
            stub_region.bucket(stub_region.done_addr + 4)
        ));
        assert!(arm64_stub_bucket_is_reserved(
            stub_region,
            stub_region.bucket(stub_region.thread_exit_stub.unwrap())
        ));
        assert!(!arm64_stub_bucket_is_reserved(
            stub_region,
            stub_region.bucket(0x2000_0A00)
        ));
    }
}

pub fn install_arm64_return_stubs(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    undefs: &[(String, u8)],
    tracker: &Arm64ImportTracker,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
    runtime_mode: RuntimeMode,
    shared_state: &Arm64SharedState,
    errno_ptr: u64,
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
    let shared_state_for_hook = shared_state.clone();
    let logged_unhandled_imports = Arc::new(Mutex::new(HashSet::<String>::new()));
    emulator.add_code_hook(
        stub_region.base,
        stub_region.base + stub_region.size,
        move |emu: &mut compatra_runtime::UnicornEmulator, address: u64, _size: u32| {
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
                    let has_runtime_hook = arm64_import_has_runtime_hook(&name, runtime_mode);
                    if let Some(compat) = compat_for_hook {
                        let proxied_by_generic_import = compat.should_proxy_import(&name);
                        if proxied_by_generic_import && !has_runtime_hook {
                            arm64_proxy_compat_host_import(
                                emu,
                                &name,
                                &shared_state_for_hook,
                                errno_ptr,
                            );
                        } else if !proxied_by_generic_import && !has_runtime_hook {
                            let lr = emu.read_reg("lr").unwrap_or(0);
                            let log_key = format!("{name}@0x{bucket:X}");
                            let should_log = logged_unhandled_imports
                                .lock()
                                .ok()
                                .is_some_and(|mut seen| seen.insert(log_key));
                            if should_log {
                                compat.log_unhandled_import(
                                    &name,
                                    address,
                                    lr,
                                    "no compat proxy or exact runtime hook",
                                );
                            }
                        }
                    }
                }
                if let Ok(mut slot) = last_stub_for_hook.lock() {
                    *slot = Some(format!("{} @ 0x{:X}", name, address));
                }
            } else {
                if arm64_stub_bucket_is_reserved(stub_region, bucket) {
                    return;
                }
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
                if address == bucket {
                    if let Some(compat) = compat_for_hook {
                        let lr = emu.read_reg("lr").unwrap_or(0);
                        let log_key = format!("<unknown>@0x{bucket:X}");
                        let should_log = logged_unhandled_imports
                            .lock()
                            .ok()
                            .is_some_and(|mut seen| seen.insert(log_key));
                        if should_log {
                            compat.log_unknown_import_address(address, lr);
                        }
                    }
                }
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
