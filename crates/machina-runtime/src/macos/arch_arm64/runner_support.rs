//! Shared setup helpers for the legacy arm64 no-dyld runner.

use crate::macos::{
    emit_runner_trace_event, io_event, kqueue_event, memory_event, process_event,
    runtime_process_metadata, thread_event, SharedTraceBus, TraceEvent, TraceMetadata,
};

pub use crate::macos::arm64_import_stubs::{
    initialize_arm64_import_tracker, record_arm64_import, Arm64ImportTracker,
};
pub use crate::macos::arm64_state::{
    initialize_arm64_shared_state, initialize_arm64_shared_state_with_mode, Arm64SharedState,
};

pub fn arm64_metadata(pid: Option<u64>, tid: u64) -> TraceMetadata {
    let metadata = runtime_process_metadata("arm64-guest").tid(tid);
    if let Some(pid) = pid {
        metadata.pid(pid).ppid(1)
    } else {
        metadata
    }
}

pub fn emit_arm64_event(bus: &Option<SharedTraceBus>, event: TraceEvent) {
    emit_runner_trace_event(bus, &TraceMetadata::new(), event);
}

pub fn arm64_process_event(
    pid: u64,
    tid: u64,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    process_event(&arm64_metadata(Some(pid), tid), name, call)
}

pub fn arm64_thread_event(
    tid: u64,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    thread_event(&arm64_metadata(None, tid), name, call)
}

pub fn arm64_io_event(pid: u64, tid: u64, call: impl Into<String>) -> TraceEvent {
    io_event(&arm64_metadata(Some(pid), tid), call)
}

pub fn arm64_kqueue_event(pid: u64, tid: u64, call: impl Into<String>) -> TraceEvent {
    kqueue_event(&arm64_metadata(Some(pid), tid), call)
}

pub fn arm64_memory_event(call: impl Into<String>) -> TraceEvent {
    memory_event(&TraceMetadata::new(), call)
}
