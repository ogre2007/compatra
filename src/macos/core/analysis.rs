use crate::macos::emulation::MacosEmulator;
use crate::macos::plugin_events::{capture_event, detect_event, TraceMetadata};
use crate::macos::plugins::register_analysis_plugins;
use crate::macos::trace::{PluginRegistry, TraceSink};
use crate::macos::RuntimeMode;

pub use machina_analysis::{
    parse_function_entry_specs, parse_usage_bypass_specs, AnalysisRuntimeHooks, AnalysisServices,
    FilePayloadDump, FunctionEntryProbeSpec, PipeStdinCaptureProgress, PipeStdinCaptureReport,
    SyntheticLogStream, UsageBypassHookSpec, BYPASS_USAGE_CHECK_ENV, TRACE_FN_ENTRY_ENV,
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
