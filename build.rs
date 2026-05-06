use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_UNICORN_BIN_DIR");
    println!("cargo:rerun-if-env-changed=DEP_UNICORN_BUILD_BIN_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    if let Some(profile_dir) = resolve_profile_dir(&out_dir) {
        if let Some(dll_path) = unicorn_dll_path(&profile_dir) {
            println!("cargo:rerun-if-changed={}", dll_path.display());
            copy_if_needed(&dll_path, &profile_dir.join("unicorn.dll"));
        }
    }
}

fn unicorn_dll_path(profile_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        env::var_os("DEP_UNICORN_BIN_DIR")
            .map(PathBuf::from)
            .map(|dir| dir.join("unicorn.dll")),
        env::var_os("DEP_UNICORN_BUILD_BIN_DIR")
            .map(PathBuf::from)
            .map(|dir| dir.join("unicorn.dll")),
    ];

    if let Some(found) = candidates.into_iter().flatten().find(|path| path.is_file()) {
        return Some(found);
    }

    let build_root = profile_dir.join("build");
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;

    if let Ok(entries) = fs::read_dir(build_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.starts_with("unicorn-engine-sys-") {
                continue;
            }

            for candidate in [
                path.join("out").join("bin").join("unicorn.dll"),
                path.join("out").join("build").join("unicorn.dll"),
            ] {
                if !candidate.is_file() {
                    continue;
                }
                let modified = fs::metadata(&candidate)
                    .and_then(|meta| meta.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                match &best {
                    Some((best_time, _)) if &modified <= best_time => {}
                    _ => best = Some((modified, candidate)),
                }
            }
        }
    }

    best.map(|(_, path)| path)
}

fn resolve_profile_dir(out_dir: &Path) -> Option<PathBuf> {
    let mut path = Some(out_dir);
    while let Some(current) = path {
        if current.file_name().and_then(|name| name.to_str()) == Some("build") {
            return current.parent().map(Path::to_path_buf);
        }
        path = current.parent();
    }
    None
}

fn copy_if_needed(src: &Path, dst: &Path) {
    if let Some(parent) = dst.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let should_copy = match (fs::metadata(src), fs::metadata(dst)) {
        (Ok(src_meta), Ok(dst_meta)) => {
            src_meta.len() != dst_meta.len() || src_meta.modified().ok() != dst_meta.modified().ok()
        }
        (Ok(_), Err(_)) => true,
        _ => false,
    };

    if should_copy {
        let _ = fs::copy(src, dst);
    }
}
