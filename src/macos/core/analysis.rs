#[cfg(feature = "analysis")]
use crate::macos::emulation::MacosEmulator;
#[cfg(feature = "analysis")]
use crate::macos::plugin_events::{capture_event, detect_event, TraceMetadata};
#[cfg(feature = "analysis")]
use crate::macos::trace::{CallTracePlugin, PluginRegistry, TraceCategory, TraceSink};
use crate::macos::RuntimeMode;

#[cfg(feature = "analysis")]
pub use machina_analysis::{
    analysis_plugin_specs, parse_function_entry_specs, parse_usage_bypass_specs,
    AnalysisEventCategory, AnalysisPluginSpec, AnalysisRuntimeHooks, AnalysisServices,
    FilePayloadDump, FunctionEntryProbeSpec, PipeStdinCaptureProgress, PipeStdinCaptureReport,
    SyntheticLogStream, SyntheticPopenOutput, UsageBypassHookSpec, BYPASS_USAGE_CHECK_ENV,
    TRACE_FN_ENTRY_ENV,
};

#[cfg(feature = "analysis")]
fn trace_category(category: AnalysisEventCategory) -> TraceCategory {
    match category {
        AnalysisEventCategory::Process => TraceCategory::Process,
        AnalysisEventCategory::Thread => TraceCategory::Thread,
        AnalysisEventCategory::Syscall => TraceCategory::Syscall,
        AnalysisEventCategory::Io => TraceCategory::Io,
        AnalysisEventCategory::Memory => TraceCategory::Memory,
        AnalysisEventCategory::Kqueue => TraceCategory::Kqueue,
        AnalysisEventCategory::Detect => TraceCategory::Detect,
        AnalysisEventCategory::Capture => TraceCategory::Capture,
        AnalysisEventCategory::Loader => TraceCategory::Loader,
        AnalysisEventCategory::Import => TraceCategory::Import,
    }
}

#[cfg(feature = "analysis")]
fn plugin_from_spec(spec: AnalysisPluginSpec) -> CallTracePlugin {
    let mut plugin = CallTracePlugin::new(spec.name);
    for category in spec.categories {
        plugin = plugin.category(trace_category(*category));
    }
    for call in spec.calls {
        plugin = plugin.call(*call);
    }
    plugin
}

#[cfg(feature = "analysis")]
pub fn register_analysis_plugins(registry: &mut PluginRegistry) {
    for spec in analysis_plugin_specs() {
        registry.register(plugin_from_spec(*spec));
    }
}

#[cfg(not(feature = "analysis"))]
pub fn register_analysis_plugins(_registry: &mut crate::macos::trace::PluginRegistry) {}

#[cfg(feature = "analysis")]
pub fn register_trace_plugins_for_mode(registry: &mut PluginRegistry, mode: RuntimeMode) {
    if AnalysisServices::for_mode(mode).is_some() {
        register_analysis_plugins(registry);
    }
}

#[cfg(not(feature = "analysis"))]
pub fn register_trace_plugins_for_mode(
    _registry: &mut crate::macos::trace::PluginRegistry,
    _mode: RuntimeMode,
) {
}

#[cfg(feature = "analysis")]
pub fn materialize_missing_file_for_mode(
    mode: RuntimeMode,
    raw_path: &str,
    size: usize,
) -> Option<Vec<u8>> {
    Some(AnalysisServices::for_mode(mode)?.materialize_synthetic_file_bytes(raw_path, size))
}

#[cfg(not(feature = "analysis"))]
pub fn materialize_missing_file_for_mode(
    _mode: RuntimeMode,
    _raw_path: &str,
    _size: usize,
) -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "analysis")]
pub trait AnalysisTraceEmitter {
    fn emit_capture_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
    fn emit_detect_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
}

#[cfg(feature = "analysis")]
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

#[cfg(not(feature = "analysis"))]
pub trait AnalysisTraceEmitter {
    fn emit_capture_event(
        &mut self,
        _metadata: &crate::macos::plugin_events::TraceMetadata,
        _name: impl Into<String>,
    );
    fn emit_detect_event(
        &mut self,
        _metadata: &crate::macos::plugin_events::TraceMetadata,
        _name: impl Into<String>,
    );
}

#[cfg(not(feature = "analysis"))]
impl<S: crate::macos::trace::TraceSink> AnalysisTraceEmitter
    for crate::macos::emulation::MacosEmulator<S>
{
    fn emit_capture_event(
        &mut self,
        _metadata: &crate::macos::plugin_events::TraceMetadata,
        _name: impl Into<String>,
    ) {
    }

    fn emit_detect_event(
        &mut self,
        _metadata: &crate::macos::plugin_events::TraceMetadata,
        _name: impl Into<String>,
    ) {
    }
}

#[cfg(not(feature = "analysis"))]
pub const TRACE_FN_ENTRY_ENV: &str = "MACHINA_TRACE_FN_ENTRY";
#[cfg(not(feature = "analysis"))]
pub const BYPASS_USAGE_CHECK_ENV: &str = "MACHINA_BYPASS_USAGE_CHECK";

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisEventCategory {
    Process,
    Thread,
    Syscall,
    Io,
    Memory,
    Kqueue,
    Detect,
    Capture,
    Loader,
    Import,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisPluginSpec {
    pub name: &'static str,
    pub categories: &'static [AnalysisEventCategory],
    pub calls: &'static [&'static str],
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnalysisServices;

#[cfg(not(feature = "analysis"))]
impl AnalysisServices {
    pub fn for_mode(_mode: RuntimeMode) -> Option<Self> {
        None
    }

    pub fn materialize_synthetic_file_bytes(&self, _raw_path: &str, _size: usize) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Default)]
pub struct AnalysisRuntimeHooks;

#[cfg(not(feature = "analysis"))]
impl AnalysisRuntimeHooks {
    pub fn for_mode(_mode: RuntimeMode) -> Self {
        Self
    }

    pub fn is_enabled(&self) -> bool {
        false
    }

    pub fn function_entry_specs_from_env(&self) -> Vec<FunctionEntryProbeSpec> {
        Vec::new()
    }

    pub fn usage_bypass_specs_from_env(&self) -> Vec<UsageBypassHookSpec> {
        Vec::new()
    }

    pub fn synthetic_log_stream(
        &self,
        _path: &str,
        _argv: &[String],
    ) -> Option<SyntheticLogStream> {
        None
    }

    pub fn synthetic_popen_output(&self, _command: &str) -> Option<SyntheticPopenOutput> {
        None
    }

    pub fn write_posix_spawn_argv_capture(
        &self,
        _parent_pid: u64,
        _child_pid: u64,
        _sequence: usize,
        _path: &str,
        _argv: &[String],
        _envp_ptr: u64,
    ) -> Option<std::path::PathBuf> {
        None
    }

    pub fn arm_pipe_stdin_capture(
        &self,
        _pipe_id: u64,
        _consumer_pid: u64,
        _path: &str,
        _argv: &[String],
    ) -> Option<String> {
        None
    }

    pub fn observe_pipe_stdin_write(
        &self,
        _pipe_id: u64,
        _data: &[u8],
    ) -> Option<PipeStdinCaptureProgress> {
        None
    }

    pub fn pipe_stdin_consumer_pid(&self, _pipe_id: u64) -> Option<u64> {
        None
    }

    pub fn complete_pipe_stdin_capture(&self, _pipe_id: u64) -> Option<PipeStdinCaptureReport> {
        None
    }

    pub fn capture_file_write_payload(
        &self,
        _pid: u64,
        _fd: u64,
        _raw_path: String,
        _data: &[u8],
    ) -> Option<FilePayloadDump> {
        None
    }
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticLogStream {
    pub messages: Vec<String>,
    pub output: Vec<u8>,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticPopenOutput {
    pub label: String,
    pub output: Vec<u8>,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePayloadDump {
    pub raw_path: String,
    pub dump_path: std::path::PathBuf,
    pub dumped_bytes: usize,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipeStdinCaptureProgress {
    pub label: String,
    pub bytes: usize,
    pub preview: String,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, PartialEq)]
pub struct PipeStdinCaptureReport {
    pub pipe_id: u64,
    pub label: String,
    pub consumer_pid: Option<u64>,
    pub bytes: usize,
    pub raw_hash: String,
    pub raw_entropy: f64,
    pub preview: String,
    pub artifact_summary: String,
    pub analysis_summary: String,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionEntryProbeSpec {
    pub label: String,
    pub addr: u64,
}

#[cfg(not(feature = "analysis"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageBypassHookSpec {
    pub addr: u64,
    pub lr_filter: Option<u64>,
    pub values: Vec<u64>,
}

#[cfg(not(feature = "analysis"))]
pub fn analysis_plugin_specs() -> &'static [AnalysisPluginSpec] {
    &[]
}

#[cfg(not(feature = "analysis"))]
pub fn parse_function_entry_specs(_spec: &str) -> Vec<FunctionEntryProbeSpec> {
    Vec::new()
}

#[cfg(not(feature = "analysis"))]
pub fn parse_usage_bypass_specs(_spec: &str) -> Vec<UsageBypassHookSpec> {
    Vec::new()
}

#[cfg(all(test, feature = "analysis"))]
mod tests {
    use crate::macos::emulation::{EmulationOptions, MacosEmulator};
    use crate::macos::plugin_events::TraceMetadata;
    use crate::macos::trace::{
        PluginRegistry, TraceCategory, TraceConfig, TraceEvent, Tracer, WriterTraceSink,
    };
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

    #[test]
    fn analysis_preset_claims_detection_and_import_events() {
        let mut plugins = PluginRegistry::new();
        register_analysis_plugins(&mut plugins);

        let produced =
            plugins.dispatch(&TraceEvent::new(TraceCategory::Import, "ptrace").call("ptrace"));

        assert!(produced
            .iter()
            .any(|event| event.plugin.as_deref() == Some("imports")));
    }
}
