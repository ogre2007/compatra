//! Integration test for the AMOS stealer private-file access milestones.
//!
//! Spawns the `machoscope` binary against
//! `fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`
//! (the arm64 AMOS stealer fixture used as the CI regression target)
//! and asserts that the JSONL trace contains the wallet/browser probes
//! the Python check in `scripts/ci/check_amos_trace.py` used to assert
//! out-of-band:
//!
//! 1. The trace carries some JSONL output at all (sanity).
//! 2. `_open` of `Binance/app-store.json`.
//! 3. At least one `filemon` `read` event.
//! 4. `_open` of `Firefox/Profiles/` (the profile root).
//! 5. `_open` of `.electrum/wallets/`.
//! 6. `_open` of `Coinomi/wallets/`.
//! 7. `_lstat` of the Chrome profile root.
//!
//! These are the same milestones the legacy Python/PowerShell scripts
//! pinned, lifted into pure-Rust integration tests so `cargo test`
//! covers the AMOS regression on every platform without an external
//! Python or PowerShell dependency.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const AMOS_FIXTURE: &str =
    "fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_path() -> PathBuf {
    workspace_root().join(AMOS_FIXTURE)
}

fn machoscope_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_machoscope"))
}

/// Match a JSONL event line that pairs a specific `plugin`, `Call`,
/// and a substring inside the `Path` field. Mirrors the Python
/// `has_event(plugin=..., call=..., path_contains=...)` helper.
fn has_filemon_path_event(trace: &str, call: &str, path_contains: &str) -> bool {
    let call_token = format!("\"Call\":\"{}\"", call);
    trace.lines().any(|line| {
        line.contains("\"plugin\":\"filemon\"")
            && line.contains(&call_token)
            && line.contains(path_contains)
    })
}

#[test]
fn amos_reaches_private_file_access_paths() {
    let fixture = fixture_path();
    if !fixture.is_file() {
        eprintln!(
            "skipping AMOS integration test: fixture not present at {}",
            fixture.display()
        );
        return;
    }

    let output = Command::new(machoscope_binary())
        .arg(&fixture)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machoscope binary");

    assert!(
        output.status.success(),
        "machoscope exited with non-zero status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let trace = String::from_utf8(output.stdout).expect("machoscope stdout was not UTF-8");

    // Sanity: the JSONL stream must at least carry the run-target prologue.
    assert!(
        trace.contains("\"Call\":\"run_target\""),
        "trace did not contain a run_target event — emulator probably did not start"
    );

    assert!(
        has_filemon_path_event(
            &trace,
            "open",
            "/Users/analyst/Library/Application Support/Binance/app-store.json",
        ),
        "sample did not attempt to open Binance wallet data"
    );

    let any_read_seen = trace
        .lines()
        .any(|line| line.contains("\"plugin\":\"filemon\"") && line.contains("\"Call\":\"read\""));
    assert!(any_read_seen, "sample did not perform any file reads");

    assert!(
        has_filemon_path_event(
            &trace,
            "open",
            "/Users/analyst/Library/Application Support/Firefox/Profiles/",
        ),
        "sample did not attempt to open Firefox profile data"
    );

    assert!(
        has_filemon_path_event(&trace, "open", "/Users/analyst/.electrum/wallets/"),
        "sample did not attempt to open Electrum wallet data"
    );

    assert!(
        has_filemon_path_event(
            &trace,
            "open",
            "/Users/analyst/Library/Application Support/Coinomi/wallets/",
        ),
        "sample did not attempt to open Coinomi wallet data"
    );

    assert!(
        has_filemon_path_event(
            &trace,
            "_lstat",
            "/Users/analyst/Library/Application Support/Google/Chrome/",
        ),
        "sample did not probe Chrome profile roots"
    );
}
