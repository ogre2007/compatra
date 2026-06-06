//! No-analysis arm64 hook adapter used by compat-only builds.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::macos::arm64_runner_support::Arm64ImportTracker;
use crate::macos::{RuntimeMode, SharedTraceBus, TraceMetadata};
use crate::UnicornEmulator;

pub struct Arm64AnalysisHookPlan {
    pub cpp_data_symbols: HashMap<String, u64>,
}

pub fn prepare_analysis_arm64_hooks(
    _runtime_mode: RuntimeMode,
    _emulator: &mut UnicornEmulator,
    _mmap_next: &Arc<AtomicU64>,
    _mmap_end: u64,
    _done_addr: u64,
    _trace_bus: &Option<SharedTraceBus>,
    _metadata: &TraceMetadata,
) -> Arm64AnalysisHookPlan {
    Arm64AnalysisHookPlan {
        cpp_data_symbols: HashMap::new(),
    }
}

pub fn install_prepared_analysis_arm64_hooks(
    _plan: Arm64AnalysisHookPlan,
    _emulator: &mut UnicornEmulator,
    _stub_map: &HashMap<String, u64>,
    _mmap_next: &Arc<AtomicU64>,
    _mmap_end: u64,
    _trace_bus: &Option<SharedTraceBus>,
    _import_tracker: &Arm64ImportTracker,
    _process_name: &str,
) -> Result<(), Box<dyn Error>> {
    Ok(())
}
