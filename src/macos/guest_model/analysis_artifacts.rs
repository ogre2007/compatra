//! Analysis-mode synthetic guest artifact adapter.
//!
//! The artifact policy itself lives in `machina-analysis`. This module only
//! converts crate-neutral artifact entries into the guest filesystem's local
//! directory-entry type.

use crate::macos::guest_files::{GuestDirectoryEntry, GuestPathPolicy};

pub use machina_analysis::{
    materialize_synthetic_file_bytes, path_looks_like_directory, should_materialize_missing_path,
};

pub fn synthetic_directory_entries(raw_path: &str) -> Vec<GuestDirectoryEntry> {
    machina_analysis::synthetic_directory_entries(raw_path)
        .into_iter()
        .map(|entry| GuestDirectoryEntry {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
        })
        .collect()
}

pub fn synthetic_path_size(raw_path: &str, policy: &GuestPathPolicy) -> u64 {
    machina_analysis::synthetic_path_size(raw_path, policy.synthetic_file_size)
}
