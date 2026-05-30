#![forbid(unsafe_code)]

pub mod capture;
pub mod guest_artifacts;
mod service;

pub use guest_artifacts::{
    materialize_synthetic_file_bytes, path_looks_like_directory, should_materialize_missing_path,
    synthetic_directory_entries, synthetic_path_size, SyntheticDirectoryEntry,
};
pub use service::{AnalysisServices, FilePayloadDump, PipeStdinCaptureReport, SyntheticLogStream};
