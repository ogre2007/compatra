extern crate self as compatra_runtime;

pub mod macos;
pub mod unicorn;

pub use compatra::{
    compat_capability_report_enabled, compat_capability_report_json, emit_compat_capability_report,
    reset_compat_capability_report,
};
pub use macos::arm64_runtime::{
    restore_arm64_context, save_arm64_context, wake_arm64_cond_waiters, wake_one_arm64_cond_waiter,
    Arm64SyntheticOsRuntime, Arm64ThreadContext,
};
pub use macos::bootstrap::{setup_arm64_stack_bootstrap, GuestProcessBootstrap};
pub use macos::emulation::{
    collect_targets, cpu_type_name, ensure_macho_cpu, macho_cputype, run_target_batch,
    run_target_batch_with_mode, targets_from_args, BatchSummary, EmulationOptions, EmulationReport,
    EmulationStatus, MacosCpu, MacosEmulator, CPU_TYPE_ARM64, DEFAULT_SAMPLE_PATH,
};
pub use macos::events::MacOsEventManager;
pub use macos::events::MacOsEventType;
pub use macos::guest_memory::{
    align_up, alloc_bytes, alloc_cstr, push_recent_trace, read_arm64_argv, read_cstring,
    stack_push_u32, stack_push_u64,
};
pub use macos::imports::{
    install_synthetic_macho_imports, patch_macho_import_pointer_sections, read_c_string,
    ImportReturnPolicy, ImportThunk, SyntheticImportLayout,
};
pub use macos::loader::{
    guest_library_specs_from_env, guest_library_symbol_lookup_keys, parse_guest_library_specs,
    parser::MachoBinary, GuestImageAddress, GuestImageKind, GuestImageRecord, GuestImageRegistry,
    GuestLibraryBinding, GuestLibraryChainedFixupReport, GuestLibraryImage,
    GuestLibraryImportSetReport, GuestLibrarySet, GuestLibrarySpec, GuestLibrarySymbol,
    MachOLoader, COMPATRA_GUEST_LIBS_ENV,
};
pub use macos::macho_utils::{
    file_backed_slice_for_vmaddr, find_symbol_address, get_dysymtab_cmd, get_symtab_cmd,
    patch_section64_u64_slots, reload_file_backed_range, section32_indirect_symbol_name,
    section_indirect_symbol_name, symbol_name_by_index, trim_name,
};
pub use macos::memory_arena::{setup_guest_memory_arena, GuestMemoryArena, GuestMemoryArenaConfig};
pub use macos::mode::RuntimeMode;
pub use macos::plugin_events::{
    io_event, kqueue_event, memory_event, process_event, syscall_event, thread_event, TraceMetadata,
};
pub use macos::policy::MacOsPolicyManager;
pub use macos::runner::{
    emulate_macos_arm64_binary, emulate_macos_arm64_binary_with_mode, emulate_macos_binary,
    emulate_macos_binary_with_mode,
};
pub use macos::runner_plugins::{
    emit_runner_trace_event, shared_trace_bus_for_mode_from_env, shared_trace_bus_from_env,
    SharedTraceBus,
};
pub use macos::runtime::{
    bind_process_fd_target, block_active_arm64_thread_on_cond, block_current_arm64_thread_on_cond,
    close_directory_stream, close_synthetic_fd, dispatch_pending_arm64_thread,
    dispatch_pending_arm64_thread_by_id, dispatch_pending_arm64_thread_by_id_with_exit_action,
    has_pipe_endpoint_ref, open_directory_stream, read_guest_directory_entry, register_process_fd,
    resolve_directory_stream_fd, resolve_process_fd_target, restore_context, save_context,
    terminate_synthetic_process, wake_cond_waiters, wake_one_cond_waiter,
    yield_active_arm64_thread, ActiveArm64Thread, Arm64ThreadRuntime, ForkParentResume,
    PendingArm64Thread, SyntheticFdTarget, SyntheticKeventRegistration, SyntheticOsRuntime,
    SyntheticPipe, SyntheticPopenStream, SyntheticProcess, ThreadContext, WaitingArm64Thread,
    ARM64_SYNTHETIC_THREAD_STACK_BASE, ARM64_SYNTHETIC_THREAD_STACK_SIZE, MAX_SYNTHETIC_THREADS,
};
pub use macos::runtime_plugins::{
    install_arm64_runtime_plugins, install_runtime_plugins, runtime_process_metadata,
    Arm64RuntimeContext, Arm64RuntimePlugin, Arm64SyscallRuntimePlugin, RuntimeContext,
    RuntimeContextCore, RuntimePlugin, SyscallRuntimePlugin,
};
pub use macos::structs::{KmodInfo, MacPolicyList, Pointer64};
pub use macos::stubs::{install_stub_region, StubIsa, StubRegion};
pub use macos::syscall_plugins::{
    default_guest_fs_base, default_syscall_name, handle_basic_macos_syscall, SyscallInvocation,
    SyscallOutcome, SyscallRuntimeState,
};
pub use macos::trace::{
    CallTracePlugin, PluginRegistry, StdoutTraceSink, StdoutTracer, TraceCategory, TraceConfig,
    TraceEvent, TraceFormat, TracePlugin, TraceSink, Tracer, WriterTraceSink,
};
pub use macos::{AppleObject, AppleRuntime};
pub use macos::{ArchType, Emulator, LogLevel, MacOsError};
pub use unicorn::UnicornEmulator;
