pub use crate::macos::arm64_runner_support::{Arm64ImportTracker, Arm64SharedState, *};

pub type ImportTracker = Arm64ImportTracker;
pub type SharedState = Arm64SharedState;

pub fn initialize_import_tracker() -> ImportTracker {
    crate::macos::arm64_runner_support::initialize_arm64_import_tracker()
}

pub fn initialize_shared_state(
    guest_fs_base: std::path::PathBuf,
    process_bootstrap: crate::macos::GuestProcessBootstrap,
) -> SharedState {
    initialize_shared_state_with_mode(
        guest_fs_base,
        process_bootstrap,
        crate::macos::RuntimeMode::Analysis,
    )
}

pub fn initialize_shared_state_with_mode(
    guest_fs_base: std::path::PathBuf,
    process_bootstrap: crate::macos::GuestProcessBootstrap,
    runtime_mode: crate::macos::RuntimeMode,
) -> SharedState {
    crate::macos::arm64_runner_support::initialize_arm64_shared_state_with_mode(
        guest_fs_base,
        process_bootstrap,
        runtime_mode,
    )
}

pub fn install_return_stubs(
    emulator: &mut crate::UnicornEmulator,
    stub_region: crate::macos::StubRegion,
    undefs: &[(String, u8)],
    tracker: &ImportTracker,
    trace_bus: &Option<crate::macos::SharedTraceBus>,
    process_name: &str,
    runtime_mode: crate::macos::RuntimeMode,
) -> Result<
    (
        std::collections::HashMap<String, u64>,
        std::sync::Arc<std::collections::HashMap<u64, String>>,
    ),
    Box<dyn std::error::Error>,
> {
    crate::macos::arm64_runner_support::install_arm64_return_stubs(
        emulator,
        stub_region,
        undefs,
        tracker,
        trace_bus,
        process_name,
        runtime_mode,
    )
}
