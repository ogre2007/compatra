//! arm64 shared runtime state construction.
//!
//! The fields are still consumed by the arm64 import and runtime hooks, but
//! keeping construction here separates process/thread state wiring from trace
//! helpers and import-stub installation.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use crate::macos::analysis::AnalysisRuntimeHooks;
use crate::macos::{
    AppleRuntime, Arm64SyntheticOsRuntime, Arm64ThreadRuntime, GuestFileTable, GuestPathPolicy,
    GuestProcessBootstrap, RuntimeMode, SyntheticProcess, ARM64_SYNTHETIC_THREAD_STACK_BASE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64ExitHandlerKind {
    Atexit,
    CxaAtexit,
    ModTerm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arm64ExitHandler {
    pub function: u64,
    pub argument: u64,
    pub dso_handle: u64,
    pub kind: Arm64ExitHandlerKind,
}

#[derive(Clone, Debug)]
pub struct Arm64SharedState {
    pub runtime_mode: RuntimeMode,
    pub process_bootstrap: GuestProcessBootstrap,
    pub tls_next_key: Arc<Mutex<u64>>,
    pub tls_values: Arc<Mutex<HashMap<u64, u64>>>,
    pub tlv_next_addr: Arc<Mutex<u64>>,
    pub tlv_storage: Arc<Mutex<HashMap<(u64, u64), u64>>>,
    pub malloc_next_addr: Arc<Mutex<u64>>,
    pub malloc_mapped_until: Arc<Mutex<u64>>,
    pub malloc_allocations: Arc<Mutex<HashMap<u64, u64>>>,
    pub posix_spawn_file_actions: Arc<Mutex<HashMap<u64, Vec<(u64, u64)>>>>,
    pub synthetic_stop_reason: Arc<Mutex<Option<String>>>,
    pub program_name_ptr: Arc<Mutex<u64>>,
    pub main_image_header: u64,
    pub main_image_slide: i64,
    pub dispatch_semaphore_next: Arc<Mutex<u64>>,
    pub dispatch_semaphores: Arc<Mutex<HashMap<u64, i64>>>,
    pub thread_runtime: Arc<Mutex<Arm64ThreadRuntime>>,
    pub os_runtime: Arc<Mutex<Arm64SyntheticOsRuntime>>,
    pub apple_runtime: Arc<Mutex<AppleRuntime>>,
    pub exit_handlers: Arc<Mutex<Vec<Arm64ExitHandler>>>,
    pub analysis: AnalysisRuntimeHooks,
    pub child_trace_budget: Arc<AtomicUsize>,
}

pub fn initialize_arm64_shared_state(
    guest_fs_base: std::path::PathBuf,
    process_bootstrap: GuestProcessBootstrap,
) -> Arm64SharedState {
    initialize_arm64_shared_state_with_mode(guest_fs_base, process_bootstrap, RuntimeMode::Analysis)
}

pub fn initialize_arm64_shared_state_with_mode(
    guest_fs_base: std::path::PathBuf,
    process_bootstrap: GuestProcessBootstrap,
    runtime_mode: RuntimeMode,
) -> Arm64SharedState {
    let policy = if runtime_mode.is_analysis() {
        GuestPathPolicy::analysis()
    } else {
        GuestPathPolicy::compat()
    };
    let guest_files = GuestFileTable::with_policy(guest_fs_base.clone(), policy);
    Arm64SharedState {
        runtime_mode,
        process_bootstrap,
        tls_next_key: Arc::new(Mutex::new(1)),
        tls_values: Arc::new(Mutex::new(HashMap::new())),
        tlv_next_addr: Arc::new(Mutex::new(0x5100_0000)),
        tlv_storage: Arc::new(Mutex::new(HashMap::new())),
        malloc_next_addr: Arc::new(Mutex::new(0x5200_0000)),
        malloc_mapped_until: Arc::new(Mutex::new(0x5200_0000)),
        malloc_allocations: Arc::new(Mutex::new(HashMap::new())),
        posix_spawn_file_actions: Arc::new(Mutex::new(HashMap::new())),
        synthetic_stop_reason: Arc::new(Mutex::new(None)),
        program_name_ptr: Arc::new(Mutex::new(process_bootstrap.arg0_addr)),
        main_image_header: 0,
        main_image_slide: 0,
        dispatch_semaphore_next: Arc::new(Mutex::new(0x6D15_0000_0000)),
        dispatch_semaphores: Arc::new(Mutex::new(HashMap::new())),
        thread_runtime: Arc::new(Mutex::new(Arm64ThreadRuntime {
            next_thread_id: 2,
            current_thread_id: 1,
            next_stack_base: ARM64_SYNTHETIC_THREAD_STACK_BASE,
            ..Default::default()
        })),
        os_runtime: Arc::new(Mutex::new(Arm64SyntheticOsRuntime {
            next_process_id: 2,
            next_fd: 0x10_000,
            next_kqueue_fd: 0x20_000,
            guest_fs_base,
            guest_files,
            processes: HashMap::from([(
                1,
                SyntheticProcess {
                    pid: 1,
                    parent_pid: 0,
                    exit_status: 0,
                    running: true,
                    reaped: false,
                    exec_path: None,
                },
            )]),
            thread_processes: HashMap::from([(1, 1)]),
            process_fds: HashMap::from([(1, HashSet::from([0, 1, 2]))]),
            ..Default::default()
        })),
        apple_runtime: Arc::new(Mutex::new(AppleRuntime::default())),
        exit_handlers: Arc::new(Mutex::new(Vec::new())),
        analysis: AnalysisRuntimeHooks::for_mode(runtime_mode),
        child_trace_budget: Arc::new(AtomicUsize::new(80)),
    }
}
