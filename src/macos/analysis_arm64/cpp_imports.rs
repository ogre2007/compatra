//! Main-crate adapter for arm64 C++/libc++ analysis hooks.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use machina_analysis::arm64_cpp_hooks::{
    self, AnalysisTraceCategory, AnalysisTraceRecord, AnalysisTraceSink, Arm64AnalysisEmulator,
    Arm64AnalysisImportTracker,
};
use machina_analysis::{FunctionEntryProbeSpec, UsageBypassHookSpec};

use crate::macos::arm64_runner_support::Arm64ImportTracker;
use crate::macos::{
    memory_event, process_event, runtime_process_metadata, Emulator, SharedTraceBus, TraceEvent,
    TraceMetadata,
};
use crate::UnicornEmulator;

#[derive(Clone)]
struct RunnerAnalysisTraceSink {
    bus: Option<SharedTraceBus>,
    metadata: Option<TraceMetadata>,
}

impl AnalysisTraceSink for RunnerAnalysisTraceSink {
    fn emit(&self, record: AnalysisTraceRecord) {
        let Some(bus) = &self.bus else {
            return;
        };
        let metadata = match record.category {
            AnalysisTraceCategory::Memory => self
                .metadata
                .clone()
                .unwrap_or_else(|| runtime_process_metadata(record.process_name.clone())),
            AnalysisTraceCategory::Process => runtime_process_metadata(record.process_name.clone()),
        };
        let mut event: TraceEvent = match record.category {
            AnalysisTraceCategory::Process => {
                process_event(&metadata, record.event_name, record.call_name)
            }
            AnalysisTraceCategory::Memory => memory_event(&metadata, record.call_name),
        };
        for (key, value) in record.args {
            event = event.arg(key, value);
        }
        let _ = bus.send(event);
    }
}

impl Arm64AnalysisEmulator for UnicornEmulator {
    fn read_memory(&mut self, addr: u64, size: usize) -> Option<Vec<u8>> {
        Emulator::read_memory(self, addr, size).ok()
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> bool {
        Emulator::write_memory(self, addr, data).is_ok()
    }

    fn read_reg(&mut self, reg: &str) -> Option<u64> {
        Emulator::read_reg(self, reg).ok()
    }

    fn write_reg(&mut self, reg: &str, value: u64) -> bool {
        Emulator::write_reg(self, reg, value).is_ok()
    }

    fn add_code_hook<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<(), Box<dyn Error>>
    where
        F: Fn(&mut Self, u64, u32) + Send + 'static,
    {
        UnicornEmulator::add_code_hook(self, begin, end, callback)
            .map_err(|err| Box::new(err) as Box<dyn Error>)
    }
}

impl Arm64AnalysisImportTracker for Arm64ImportTracker {
    fn record_import(&self, name: &str, address: u64) {
        self.import_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last_stub.lock() {
            *last = Some(name.to_string());
        }
        if let Ok(mut recent) = self.recent_imports.lock() {
            if recent.len() >= 64 {
                recent.pop_front();
            }
            recent.push_back(format!("{} @ 0x{:X}", name, address));
        }
    }
}

pub fn setup_analysis_arm64_cpp_data_region(
    emulator: &mut UnicornEmulator,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<HashMap<String, u64>, Box<dyn Error>> {
    let process_name = metadata
        .running_process
        .clone()
        .unwrap_or_else(|| "main".to_string());
    arm64_cpp_hooks::setup_analysis_arm64_cpp_data_region(
        emulator,
        mmap_next,
        mmap_end,
        done_addr,
        RunnerAnalysisTraceSink {
            bus: trace_bus.clone(),
            metadata: Some(metadata.clone()),
        },
        &process_name,
    )
}

pub fn install_analysis_arm64_cpp_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn Error>> {
    arm64_cpp_hooks::install_analysis_arm64_cpp_imports(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        RunnerAnalysisTraceSink {
            bus: trace_bus.clone(),
            metadata: None,
        },
        import_tracker.clone(),
        process_name,
    )
}

pub fn install_analysis_arm64_operator_hooks(
    emulator: &mut UnicornEmulator,
    function_entry_specs: Vec<FunctionEntryProbeSpec>,
    usage_bypass_specs: Vec<UsageBypassHookSpec>,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn Error>> {
    arm64_cpp_hooks::install_arm64_operator_hooks(
        emulator,
        function_entry_specs,
        usage_bypass_specs,
        RunnerAnalysisTraceSink {
            bus: trace_bus.clone(),
            metadata: None,
        },
        process_name,
    )
}
