#![forbid(unsafe_code)]

pub mod capture;
pub mod guest_artifacts;
pub mod plugin_preset;
mod service;

pub use guest_artifacts::{
    materialize_synthetic_file_bytes, path_looks_like_directory, should_materialize_missing_path,
    synthetic_directory_entries, synthetic_path_size, SyntheticDirectoryEntry,
};
pub use plugin_preset::{analysis_plugin_specs, AnalysisEventCategory, AnalysisPluginSpec};
pub use service::{AnalysisServices, FilePayloadDump, PipeStdinCaptureReport, SyntheticLogStream};
