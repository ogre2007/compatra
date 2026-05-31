use crate::macos::emulation::MacosEmulator;
use crate::macos::plugin_events::{capture_event, detect_event, TraceMetadata};
use crate::macos::trace::{CallTracePlugin, PluginRegistry, TraceCategory, TraceSink};
use crate::macos::RuntimeMode;

pub use machina_analysis::{
    analysis_plugin_specs, parse_function_entry_specs, parse_usage_bypass_specs,
    AnalysisEventCategory, AnalysisPluginSpec, AnalysisRuntimeHooks, AnalysisServices,
    FilePayloadDump, FunctionEntryProbeSpec, PipeStdinCaptureProgress, PipeStdinCaptureReport,
    SyntheticLogStream, UsageBypassHookSpec, BYPASS_USAGE_CHECK_ENV, TRACE_FN_ENTRY_ENV,
};

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

pub fn register_analysis_plugins(registry: &mut PluginRegistry) {
    for spec in analysis_plugin_specs() {
        registry.register(plugin_from_spec(*spec));
    }
}

pub fn register_trace_plugins_for_mode(registry: &mut PluginRegistry, mode: RuntimeMode) {
    if AnalysisServices::for_mode(mode).is_some() {
        register_analysis_plugins(registry);
    }
}

pub fn materialize_missing_file_for_mode(
    mode: RuntimeMode,
    raw_path: &str,
    size: usize,
) -> Option<Vec<u8>> {
    Some(AnalysisServices::for_mode(mode)?.materialize_synthetic_file_bytes(raw_path, size))
}

pub trait AnalysisTraceEmitter {
    fn emit_capture_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
    fn emit_detect_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>);
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
