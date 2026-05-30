#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticDirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

fn pseudo_random_bytes(seed: &str, size: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for byte in seed.as_bytes() {
        state = state.rotate_left(7) ^ (*byte as u64);
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
    }
    let mut out = Vec::with_capacity(size);
    for idx in 0..size {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let mut byte = state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8;
        if idx % 97 == 0 {
            byte = b'{';
        } else if idx % 97 == 1 {
            byte = b'}';
        } else if idx % 53 == 0 {
            byte = b'\n';
        } else if !byte.is_ascii_graphic() && byte != b' ' {
            byte = b'a' + (byte % 26);
        }
        out.push(byte);
    }
    out
}

pub fn materialize_synthetic_file_bytes(raw_path: &str, size: usize) -> Vec<u8> {
    let lower = raw_path.to_ascii_lowercase();
    if lower.ends_with("local state") {
        return br#"{"profile":{"info_cache":{"Default":{"name":"Default"}}},"os_crypt":{"encrypted_key":"QUJDREVGR0g="}}"#
            .to_vec();
    }
    if lower.ends_with("cookies") || lower.ends_with("login data") {
        return pseudo_random_bytes(raw_path, size.max(2048));
    }
    if lower.ends_with(".json")
        || lower.ends_with(".sqlite")
        || lower.ends_with(".ldb")
        || lower.ends_with(".log")
        || lower.ends_with(".txt")
    {
        return pseudo_random_bytes(raw_path, size.clamp(256, 1024));
    }
    if lower.contains("wallet") || lower.contains("seed") || lower.contains("key") {
        return pseudo_random_bytes(raw_path, size.clamp(512, 1024));
    }
    pseudo_random_bytes(raw_path, size)
}

pub fn path_looks_like_directory(raw_path: &str) -> bool {
    if raw_path.ends_with('/') || raw_path.ends_with('\\') {
        return true;
    }
    let Some(last) = raw_path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
    else {
        return true;
    };
    if last.is_empty() {
        return true;
    }
    let lower = last.to_ascii_lowercase();
    if lower == "default"
        || lower.starts_with("profile")
        || lower == "wallets"
        || lower == "profiles"
        || lower == "chrome"
        || lower == "firefox"
        || lower == "exodus"
        || lower == "coinomi"
        || lower == "leveldb"
    {
        return true;
    }
    !last.contains('.')
}

pub fn synthetic_directory_entries(raw_path: &str) -> Vec<SyntheticDirectoryEntry> {
    fn push_dir(entries: &mut Vec<SyntheticDirectoryEntry>, name: &str) {
        entries.push(SyntheticDirectoryEntry {
            name: name.to_string(),
            is_dir: true,
            size: 0,
        });
    }

    fn push_file(entries: &mut Vec<SyntheticDirectoryEntry>, name: &str, size: u64) {
        entries.push(SyntheticDirectoryEntry {
            name: name.to_string(),
            is_dir: false,
            size,
        });
    }

    let lower = raw_path.to_ascii_lowercase();
    let mut entries = vec![
        SyntheticDirectoryEntry {
            name: ".".to_string(),
            is_dir: true,
            size: 0,
        },
        SyntheticDirectoryEntry {
            name: "..".to_string(),
            is_dir: true,
            size: 0,
        },
    ];

    if lower.contains("firefox/profiles") {
        push_dir(&mut entries, "default-release");
        push_dir(&mut entries, "dev-edition-default");
    } else if lower.contains("google/chrome")
        || lower.contains("brave-browser")
        || lower.contains("microsoft edge")
    {
        push_dir(&mut entries, "Default");
        push_dir(&mut entries, "Profile 1");
        push_file(&mut entries, "Local State", 512);
    } else if lower.contains("leveldb") {
        push_file(&mut entries, "000003.ldb", 8192);
        push_file(&mut entries, "CURRENT", 16);
        push_file(&mut entries, "MANIFEST-000001", 2048);
    } else if lower.contains("wallet") || lower.contains("exodus") || lower.contains("coinomi") {
        push_file(&mut entries, "wallet.dat", 512);
        push_file(&mut entries, "seed.seco", 512);
        push_file(&mut entries, "config.json", 512);
    } else if lower.ends_with("/default") || lower.ends_with("\\default") {
        push_file(&mut entries, "Cookies", 8192);
        push_file(&mut entries, "Login Data", 12288);
        push_file(&mut entries, "History", 4096);
        push_dir(&mut entries, "Local Storage");
    } else {
        push_dir(&mut entries, "Default");
        push_dir(&mut entries, "Profile 1");
        push_file(&mut entries, "manifest.json", 512);
        push_file(&mut entries, "data.bin", 2048);
    }
    entries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    entries
}

pub fn synthetic_path_size(raw_path: &str, synthetic_file_size: usize) -> u64 {
    materialize_synthetic_file_bytes(raw_path, synthetic_file_size).len() as u64
}

pub fn should_materialize_missing_path(raw_path: &str) -> bool {
    let Some(name) = raw_path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
    else {
        return true;
    };
    if name.starts_with(".inj_") {
        return false;
    }
    if raw_path == "/tmp/com.apple.lock" || raw_path.starts_with("/tmp/com.apple.lock.") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_profile_artifacts_are_analysis_fixtures() {
        let entries =
            synthetic_directory_entries("/Users/analyst/Library/Application Support/Google/Chrome");
        assert!(entries.iter().any(|entry| entry.name == "Default"));
        assert!(entries.iter().any(|entry| entry.name == "Local State"));
    }

    #[test]
    fn rustdoor_lock_files_are_not_materialized_as_bait() {
        assert!(!should_materialize_missing_path("/tmp/com.apple.lock"));
        assert!(!should_materialize_missing_path("/tmp/com.apple.lock.123"));
        assert!(!should_materialize_missing_path(
            "/Users/analyst/.docks/.inj_rc_chr"
        ));
    }
}
