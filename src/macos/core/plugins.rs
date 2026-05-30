//! Trace plugin adapters for analysis presets owned by `machina-analysis`.

use crate::macos::trace::{CallTracePlugin, PluginRegistry, TraceCategory};
use machina_analysis::{analysis_plugin_specs, AnalysisEventCategory, AnalysisPluginSpec};

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

pub fn register_plugins(registry: &mut PluginRegistry) {
    register_analysis_plugins(registry);
}

#[cfg(test)]
mod tests {
    use crate::macos::trace::{PluginRegistry, TraceCategory, TraceEvent};

    use super::*;

    #[test]
    fn analysis_preset_claims_detection_and_import_events() {
        let mut plugins = PluginRegistry::new();
        register_plugins(&mut plugins);

        let produced =
            plugins.dispatch(&TraceEvent::new(TraceCategory::Import, "ptrace").call("ptrace"));

        assert!(produced
            .iter()
            .any(|event| event.plugin.as_deref() == Some("imports")));
    }
}
