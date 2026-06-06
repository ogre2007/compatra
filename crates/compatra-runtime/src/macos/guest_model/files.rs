//! Guest-visible file and directory model.

#[cfg(feature = "analysis")]
pub use machoscope_analysis::guest_model::files::*;

#[cfg(not(feature = "analysis"))]
mod compat_only {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Debug)]
    pub enum GuestOpenTarget {
        File(u64),
        Directory(u64),
    }

    #[derive(Clone, Debug)]
    pub enum SyntheticGuestFileKind {
        HostBytes(Vec<u8>),
        Urandom,
    }

    #[derive(Clone, Debug)]
    pub struct SyntheticGuestFile {
        pub raw_path: String,
        pub resolved_path: PathBuf,
        pub kind: SyntheticGuestFileKind,
    }

    #[derive(Clone, Debug)]
    pub struct SyntheticGuestDirectory {
        pub raw_path: String,
        pub resolved_path: PathBuf,
        pub entries: Vec<GuestDirectoryEntry>,
    }

    #[derive(Clone, Debug)]
    pub struct GuestDirectoryEntry {
        pub name: String,
        pub is_dir: bool,
        pub size: u64,
    }

    #[derive(Clone, Debug)]
    pub struct GuestPathPolicy {
        pub materialize_missing_paths: bool,
        pub create_missing_files: bool,
        pub synthetic_file_size: usize,
    }

    impl GuestPathPolicy {
        pub fn analysis() -> Self {
            Self {
                materialize_missing_paths: false,
                create_missing_files: true,
                synthetic_file_size: 0,
            }
        }

        pub fn compat() -> Self {
            Self {
                materialize_missing_paths: false,
                create_missing_files: true,
                synthetic_file_size: 0,
            }
        }
    }

    impl Default for GuestPathPolicy {
        fn default() -> Self {
            Self::analysis()
        }
    }

    #[derive(Debug, Default)]
    pub struct GuestFileTable {
        pub next_file_id: u64,
        pub next_dir_id: u64,
        pub guest_fs_base: PathBuf,
        pub policy: GuestPathPolicy,
        pub files: HashMap<u64, SyntheticGuestFile>,
        pub directories: HashMap<u64, SyntheticGuestDirectory>,
        pub file_offsets: HashMap<(u64, u64), usize>,
        pub directory_offsets: HashMap<(u64, u64), usize>,
    }

    impl GuestFileTable {
        pub fn new(guest_fs_base: PathBuf) -> Self {
            Self::with_policy(guest_fs_base, GuestPathPolicy::default())
        }

        pub fn with_policy(guest_fs_base: PathBuf, policy: GuestPathPolicy) -> Self {
            Self {
                next_file_id: 1,
                next_dir_id: 1,
                guest_fs_base,
                policy,
                ..Default::default()
            }
        }
    }

    pub const GUEST_OPEN_CREATE: u64 = 0x200;

    pub fn resolve_guest_path(guest_fs_base: &Path, raw_path: &str) -> PathBuf {
        if raw_path.starts_with('/') {
            guest_fs_base.join(raw_path.trim_start_matches('/'))
        } else {
            guest_fs_base.join(raw_path)
        }
    }

    fn create_missing_file_target(
        table: &mut GuestFileTable,
        pid: u64,
        fd: u64,
        raw_path: &str,
        resolved: &Path,
    ) -> (GuestOpenTarget, PathBuf) {
        let file_id = table.next_file_id.max(1);
        table.next_file_id = file_id.saturating_add(1);
        table.files.insert(
            file_id,
            SyntheticGuestFile {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.to_path_buf(),
                kind: SyntheticGuestFileKind::HostBytes(Vec::new()),
            },
        );
        table.file_offsets.insert((pid, fd), 0);
        (GuestOpenTarget::File(file_id), resolved.to_path_buf())
    }

    fn read_directory_entries(resolved: &Path) -> Result<Vec<GuestDirectoryEntry>, u32> {
        let mut entries = vec![
            GuestDirectoryEntry {
                name: ".".to_string(),
                is_dir: true,
                size: 0,
            },
            GuestDirectoryEntry {
                name: "..".to_string(),
                is_dir: true,
                size: 0,
            },
        ];
        let read_dir = std::fs::read_dir(resolved).map_err(|_| 2u32)?;
        for entry in read_dir.flatten() {
            let Ok(file_name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            entries.push(GuestDirectoryEntry {
                name: file_name,
                is_dir: meta.is_dir(),
                size: meta.len(),
            });
        }
        entries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        Ok(entries)
    }

    pub fn open_guest_path(
        table: &mut GuestFileTable,
        pid: u64,
        fd: u64,
        raw_path: &str,
    ) -> Result<(GuestOpenTarget, PathBuf), u32> {
        open_guest_path_with_flags(table, pid, fd, raw_path, 0)
    }

    pub fn open_guest_path_with_flags(
        table: &mut GuestFileTable,
        pid: u64,
        fd: u64,
        raw_path: &str,
        flags: u64,
    ) -> Result<(GuestOpenTarget, PathBuf), u32> {
        let resolved = resolve_guest_path(&table.guest_fs_base, raw_path);
        if raw_path == "/dev/urandom" {
            let file_id = table.next_file_id.max(1);
            table.next_file_id = file_id.saturating_add(1);
            table.files.insert(
                file_id,
                SyntheticGuestFile {
                    raw_path: raw_path.to_string(),
                    resolved_path: resolved.clone(),
                    kind: SyntheticGuestFileKind::Urandom,
                },
            );
            table.file_offsets.insert((pid, fd), 0);
            return Ok((GuestOpenTarget::File(file_id), resolved));
        }

        let creating = (flags & GUEST_OPEN_CREATE) != 0;
        let allow_create = creating && table.policy.create_missing_files;
        let meta = match std::fs::metadata(&resolved) {
            Ok(meta) => meta,
            Err(_) if allow_create => {
                return Ok(create_missing_file_target(
                    table, pid, fd, raw_path, &resolved,
                ));
            }
            Err(_) => return Err(2u32),
        };
        if meta.is_dir() {
            let dir_id = table.next_dir_id.max(1);
            table.next_dir_id = dir_id.saturating_add(1);
            table.directories.insert(
                dir_id,
                SyntheticGuestDirectory {
                    raw_path: raw_path.to_string(),
                    resolved_path: resolved.clone(),
                    entries: read_directory_entries(&resolved)?,
                },
            );
            table.directory_offsets.insert((pid, fd), 0);
            Ok((GuestOpenTarget::Directory(dir_id), resolved))
        } else {
            let data = std::fs::read(&resolved).map_err(|_| 2u32)?;
            let file_id = table.next_file_id.max(1);
            table.next_file_id = file_id.saturating_add(1);
            table.files.insert(
                file_id,
                SyntheticGuestFile {
                    raw_path: raw_path.to_string(),
                    resolved_path: resolved.clone(),
                    kind: SyntheticGuestFileKind::HostBytes(data),
                },
            );
            table.file_offsets.insert((pid, fd), 0);
            Ok((GuestOpenTarget::File(file_id), resolved))
        }
    }

    pub fn read_guest_file(
        table: &mut GuestFileTable,
        pid: u64,
        fd: u64,
        file_id: u64,
        count: usize,
    ) -> Option<(Vec<u8>, bool)> {
        let current_offset = table.file_offsets.get(&(pid, fd)).copied().unwrap_or(0);
        let (chunk, next_offset, eof) = match table.files.get(&file_id)? {
            SyntheticGuestFile {
                kind: SyntheticGuestFileKind::HostBytes(data),
                ..
            } => {
                let start = current_offset.min(data.len());
                let end = start.saturating_add(count).min(data.len());
                (data[start..end].to_vec(), end, end >= data.len())
            }
            SyntheticGuestFile {
                kind: SyntheticGuestFileKind::Urandom,
                ..
            } => {
                let mut out = Vec::with_capacity(count);
                let mut state = (current_offset as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0xA5A5_5A5A_C3C3_3C3C);
                for _ in 0..count {
                    state ^= state >> 12;
                    state ^= state << 25;
                    state ^= state >> 27;
                    out.push(state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8);
                }
                (out, current_offset.saturating_add(count), false)
            }
        };
        table.file_offsets.insert((pid, fd), next_offset);
        Some((chunk, eof))
    }

    pub fn stat_guest_path(table: &GuestFileTable, raw_path: &str) -> Result<(u64, PathBuf), u32> {
        let resolved = resolve_guest_path(&table.guest_fs_base, raw_path);
        if let Some(file) = table.files.values().find(|file| file.raw_path == raw_path) {
            let size = match &file.kind {
                SyntheticGuestFileKind::HostBytes(data) => data.len() as u64,
                SyntheticGuestFileKind::Urandom => 0,
            };
            return Ok((size, file.resolved_path.clone()));
        }
        if let Some(dir) = table
            .directories
            .values()
            .find(|dir| dir.raw_path == raw_path)
        {
            return Ok((0, dir.resolved_path.clone()));
        }
        match raw_path {
            "/dev/urandom" => Ok((0, resolved)),
            _ => match std::fs::metadata(&resolved) {
                Ok(meta) => Ok((meta.len(), resolved)),
                Err(_) => Err(2),
            },
        }
    }

    pub fn fstat_guest_file(table: &GuestFileTable, file_id: u64) -> Result<u64, u32> {
        match table.files.get(&file_id) {
            Some(SyntheticGuestFile {
                kind: SyntheticGuestFileKind::HostBytes(data),
                ..
            }) => Ok(data.len() as u64),
            Some(SyntheticGuestFile {
                kind: SyntheticGuestFileKind::Urandom,
                ..
            }) => Ok(0),
            None => Err(9),
        }
    }

    pub fn read_guest_directory_entry(
        table: &mut GuestFileTable,
        pid: u64,
        fd: u64,
        dir_id: u64,
    ) -> Option<GuestDirectoryEntry> {
        let current_offset = table
            .directory_offsets
            .get(&(pid, fd))
            .copied()
            .unwrap_or(0);
        let dir = table.directories.get(&dir_id)?;
        let entry = dir.entries.get(current_offset)?.clone();
        table
            .directory_offsets
            .insert((pid, fd), current_offset.saturating_add(1));
        Some(entry)
    }
}

#[cfg(not(feature = "analysis"))]
pub use compat_only::*;
