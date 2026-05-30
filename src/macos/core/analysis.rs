use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::macos::byte_preview::lossy_data_preview;
use crate::macos::emulation::MacosEmulator;
use crate::macos::plugin_events::{capture_event, detect_event, TraceMetadata};
use crate::macos::plugins::register_analysis_plugins;
use crate::macos::trace::{PluginRegistry, TraceSink};
use crate::macos::RuntimeMode;

pub use machina_analysis::{
    parse_function_entry_specs, parse_usage_bypass_specs, AnalysisServices, FilePayloadDump,
    FunctionEntryProbeSpec, PipeStdinCaptureReport, SyntheticLogStream, UsageBypassHookSpec,
    BYPASS_USAGE_CHECK_ENV, TRACE_FN_ENTRY_ENV,
};

pub fn register_trace_plugins_for_mode(registry: &mut PluginRegistry, mode: RuntimeMode) {
    if AnalysisServices::for_mode(mode).is_some() {
        register_analysis_plugins(registry);
    }
}

pub trait AnalysisTraceEmitter {
    fn emit_capture_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
    fn emit_detect_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisRuntimeHooks {
    services: Option<AnalysisServices>,
    pipe_stdin: Arc<Mutex<HashMap<u64, PipeStdinCaptureState>>>,
}

#[derive(Clone, Debug)]
struct PipeStdinCaptureState {
    label: String,
    consumer_pid: Option<u64>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeStdinCaptureProgress {
    pub label: String,
    pub bytes: usize,
    pub preview: String,
}

impl AnalysisRuntimeHooks {
    pub fn for_mode(mode: RuntimeMode) -> Self {
        Self {
            services: AnalysisServices::for_mode(mode),
            pipe_stdin: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.services.is_some()
    }

    pub fn function_entry_specs_from_env(&self) -> Vec<FunctionEntryProbeSpec> {
        if !self.is_enabled() {
            return Vec::new();
        }
        std::env::var(TRACE_FN_ENTRY_ENV)
            .ok()
            .map(|spec| parse_function_entry_specs(&spec))
            .unwrap_or_default()
    }

    pub fn usage_bypass_specs_from_env(&self) -> Vec<UsageBypassHookSpec> {
        if !self.is_enabled() {
            return Vec::new();
        }
        std::env::var(BYPASS_USAGE_CHECK_ENV)
            .ok()
            .map(|spec| parse_usage_bypass_specs(&spec))
            .unwrap_or_default()
    }

    pub fn synthetic_log_stream(&self, path: &str, argv: &[String]) -> Option<SyntheticLogStream> {
        self.services?.synthetic_log_stream(path, argv)
    }

    pub fn write_posix_spawn_argv_capture(
        &self,
        parent_pid: u64,
        child_pid: u64,
        sequence: usize,
        path: &str,
        argv: &[String],
        envp_ptr: u64,
    ) -> Option<PathBuf> {
        self.services?
            .write_posix_spawn_argv_capture(parent_pid, child_pid, sequence, path, argv, envp_ptr)
    }

    pub fn arm_pipe_stdin_capture(
        &self,
        pipe_id: u64,
        consumer_pid: u64,
        path: &str,
        argv: &[String],
    ) -> Option<String> {
        let label = self
            .services?
            .process_stdin_capture_label(consumer_pid, path, argv);
        let mut captures = self.pipe_stdin.lock().ok()?;
        captures.insert(
            pipe_id,
            PipeStdinCaptureState {
                label: label.clone(),
                consumer_pid: Some(consumer_pid),
                data: Vec::new(),
            },
        );
        Some(label)
    }

    pub fn observe_pipe_stdin_write(
        &self,
        pipe_id: u64,
        data: &[u8],
    ) -> Option<PipeStdinCaptureProgress> {
        self.services?;
        let mut captures = self.pipe_stdin.lock().ok()?;
        let capture = captures.get_mut(&pipe_id)?;
        capture.data.extend(data.iter().copied());
        Some(PipeStdinCaptureProgress {
            label: capture.label.clone(),
            bytes: capture.data.len(),
            preview: lossy_data_preview(&capture.data, 256),
        })
    }

    pub fn pipe_stdin_consumer_pid(&self, pipe_id: u64) -> Option<u64> {
        self.pipe_stdin.lock().ok().and_then(|captures| {
            captures
                .get(&pipe_id)
                .and_then(|capture| capture.consumer_pid)
        })
    }

    pub fn complete_pipe_stdin_capture(&self, pipe_id: u64) -> Option<PipeStdinCaptureReport> {
        let services = self.services?;
        let capture = self.pipe_stdin.lock().ok()?.remove(&pipe_id)?;
        Some(services.complete_pipe_stdin_capture(
            pipe_id,
            capture.label,
            capture.consumer_pid,
            &capture.data,
        ))
    }

    pub fn capture_file_write_payload(
        &self,
        pid: u64,
        fd: u64,
        raw_path: String,
        data: &[u8],
    ) -> Option<FilePayloadDump> {
        self.services?
            .capture_file_write_payload(pid, fd, raw_path, data)
    }
}

impl<S: TraceSink> AnalysisTraceEmitter for MacosEmulator<S> {
    fn emit_capture_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>) {
        if AnalysisServices::for_mode(self.options.mode).is_none() {
            return;
        }
        self.emit_trace(capture_event(metadata, name));
    }

    fn emit_detect_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>) {
        if AnalysisServices::for_mode(self.options.mode).is_none() {
            return;
        }
        self.emit_trace(detect_event(metadata, name));
    }
}

#[cfg(test)]
mod tests {
    use crate::macos::emulation::{EmulationOptions, MacosEmulator};
    use crate::macos::plugin_events::TraceMetadata;
    use crate::macos::trace::{TraceConfig, Tracer, WriterTraceSink};
    use crate::macos::RuntimeMode;

    use super::*;

    #[test]
    fn compat_mode_suppresses_analysis_emitter_events() {
        let options = EmulationOptions {
            mode: RuntimeMode::Compat,
            trace: TraceConfig::full_jsonl(),
            ..EmulationOptions::default()
        };
        let tracer = Tracer::new(options.trace.clone(), WriterTraceSink::new(Vec::new()));
        let mut emulator = MacosEmulator::new(options, tracer);
        let meta = TraceMetadata::new()
            .pid(2)
            .ppid(1)
            .tid(3)
            .running_process("sample");

        emulator.emit_detect_event(&meta, "process_execution");
        emulator.emit_capture_event(&meta, "payload");

        let output = String::from_utf8(emulator.into_tracer().into_sink().into_inner()).unwrap();
        assert!(output.is_empty());
    }
}
