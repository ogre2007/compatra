#![forbid(unsafe_code)]

pub mod arm64_cpp_hooks;
pub mod capture;
pub mod guest_artifacts;
pub mod libcpp;
pub mod operator_hooks;
pub mod plugin_preset;
pub mod runtime_hooks;
mod service;

pub use guest_artifacts::{
    materialize_synthetic_file_bytes, path_looks_like_directory, should_materialize_missing_path,
    synthetic_directory_entries, synthetic_path_size, SyntheticDirectoryEntry,
};
pub use operator_hooks::{
    function_entry_specs_from_env, parse_function_entry_specs, parse_usage_bypass_specs,
    usage_bypass_specs_from_env, FunctionEntryProbeSpec, UsageBypassHookSpec,
    BYPASS_USAGE_CHECK_ENV, TRACE_FN_ENTRY_ENV,
};
pub use plugin_preset::{analysis_plugin_specs, AnalysisEventCategory, AnalysisPluginSpec};
pub use runtime_hooks::{AnalysisRuntimeHooks, PipeStdinCaptureProgress};
pub use service::{AnalysisServices, FilePayloadDump, PipeStdinCaptureReport, SyntheticLogStream};
