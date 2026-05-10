//! Integration test for the RustDoor fast-mode milestones.
//!
//! Spawns the `machina` binary against
//! `fixtures/macos/bin/rustdoor/76f96a35*.macho` (the arm64 RustDoor stage-1
//! `.zsh_env` dropper from the Unit42 Contagious Interview campaign) and
//! asserts that the JSONL trace contains the events that mark the current
//! emulator coverage:
//!
//! 1. The parent process probes Chrome — `_stat /Applications/Google
//!    Chrome.app/Contents/MacOS/Google Chrome` succeeds.
//! 2. The daemon child opens `~/.zshrc` read-write for the shell-startup
//!    persistence injection (synthetic fd `65539`).
//! 3. The `_write` payload-dump path fires for `~/.zshrc` (filemon `write`
//!    event with a `PayloadPath` ending in `.zshrc` and a non-empty
//!    `PayloadDumpFile`).
//! 4. The malware retries `/tmp/com.apple.lock.<timestamp>` as
//!    `O_CREAT|O_RDWR|O_TRUNC` (Darwin flags `0x1000601`) and our
//!    O_CREAT-aware open synthesizes the file successfully.
//! 5. `posix_spawnp` is observed for `log stream --predicate ...
//!    restartInitiated/shutdownInitiated --info` — the first
//!    malware-interesting command from Unit42's Table 1.
//!
//! These are the milestones the emulator currently reaches in the default
//! "fast" indirect-branch mode (`MACHINA_INDIRECT_BRANCH_MODE` unset). If
//! a future change regresses the path that takes RustDoor from bootstrap
//! all the way to the `log stream` `posix_spawnp`, this test fails before
//! the JSONL contract drifts further.
//!
//! The test is run-once: it spawns one `machina` subprocess, captures its
//! full stdout, and asserts the milestones from the captured bytes. No
//! Python tooling, no shelling out beyond launching the emulator binary
//! itself.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const RUSTDOOR_FIXTURE: &str =
    "fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path() -> PathBuf {
    workspace_root().join(RUSTDOOR_FIXTURE)
}

fn machina_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_machina"))
}

#[test]
fn rustdoor_fast_mode_reaches_log_stream_posix_spawnp() {
    let fixture = fixture_path();
    if !fixture.is_file() {
        eprintln!(
            "skipping rustdoor integration test: fixture not present at {}",
            fixture.display()
        );
        return;
    }

    let output = Command::new(machina_binary())
        .arg(&fixture)
        // Force the default "fast" indirect-branch mode regardless of host env.
        .env("MACHINA_INDIRECT_BRANCH_MODE", "fast")
        // Default profile (60 s / 50 M instructions) is enough on a
        // dev machine to reach the log-stream spawn; bumping to `long`
        // costs more wall-time without changing the milestone set.
        .env("MACHINA_PROFILE", "default")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    assert!(
        output.status.success(),
        "machina exited with non-zero status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let trace = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");

    // Sanity: the JSONL stream must at least carry the run-target prologue.
    assert!(
        trace.contains("\"Call\":\"run_target\""),
        "trace did not contain a run_target event — emulator probably did not start"
    );

    let chrome_probe_seen = trace.lines().any(|line| {
        line.contains("\"plugin\":\"filemon\"")
            && line.contains("\"Call\":\"_stat\"")
            && line.contains("/Applications/Google Chrome.app/")
            && line.contains("\"Errno\":\"0\"")
    });
    assert!(
        chrome_probe_seen,
        "fast-mode trace did not contain the parent's Chrome.app probe — \
         either we regressed past Chrome detection or the parent panicked early"
    );

    let zshrc_rw_open_seen = trace.lines().any(|line| {
        line.contains("\"plugin\":\"filemon\"")
            && line.contains("\"Call\":\"open\"")
            && line.contains("/Users/unknown/.zshrc")
            // Mode-byte 0x9 = O_RDWR | O_APPEND — combined with O_CLOEXEC this
            // is the second `.zshrc` open the daemon does for the persistence
            // injection. Only the read-write open delivers fd 65539, which the
            // subsequent payload-dump asserts depend on.
            && line.contains("\"Flags\":\"0x1000009\"")
            && line.contains("\"Result\":\"65539\"")
    });
    assert!(
        zshrc_rw_open_seen,
        "fast-mode trace did not contain the daemon's read-write open of ~/.zshrc"
    );

    let zshrc_payload_dump_seen = trace.lines().any(|line| {
        line.contains("\"plugin\":\"filemon\"")
            && line.contains("\"Call\":\"write\"")
            && line.contains("\"PayloadPath\":\"/Users/unknown/.zshrc\"")
            && line.contains("\"PayloadDumpFile\":")
    });
    assert!(
        zshrc_payload_dump_seen,
        "fast-mode trace did not record a payload dump for the ~/.zshrc \
         injection — the _write hook may have stopped resolving tagged \
         buffers or the write itself never happened"
    );

    let lock_create_seen = trace.lines().any(|line| {
        line.contains("\"plugin\":\"filemon\"")
            && line.contains("\"Call\":\"open\"")
            && line.contains("/tmp/com.apple.lock.")
            // 0x1000601 = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC. The
            // O_CREAT bit (0x200) is the one that exercises our new
            // open_guest_path_with_flags codepath; without it we would
            // come back as ENOENT and the daemon panics before spawning.
            && line.contains("\"Flags\":\"0x1000601\"")
            && line.contains("\"Errno\":\"0\"")
    });
    assert!(
        lock_create_seen,
        "fast-mode trace did not contain a successful O_CREAT open of \
         /tmp/com.apple.lock.<timestamp> — the malware never reached the \
         install path that leads to the log-stream spawn"
    );

    // The Argv field is itself a JSON-encoded string, so the inner
    // `"log"` / `"stream"` tokens appear in the JSONL line as
    // `\"log\"` / `\"stream\"`. Match the bytes that survive that
    // double-encoding instead of the source-form quotes.
    let log_stream_spawn_seen = trace.lines().any(|line| {
        line.contains("\"Call\":\"posix_spawnp\"")
            && line.contains("\"Path\":\"log\"")
            && line.contains("--predicate")
            && line.contains("restartInitiated")
            && line.contains("shutdownInitiated")
            && line.contains("\"SyntheticLogStream\":\"true\"")
            && line.contains("\"Result\":\"0\"")
    });
    if !log_stream_spawn_seen {
        // Build an actionable failure: include the stop event and any
        // posix_spawn-related lines that did appear, so a regression
        // report tells the maintainer how far the emulator got before
        // missing the spawn.
        let spawn_lines: Vec<&str> = trace
            .lines()
            .filter(|line| line.contains("posix_spawn") || line.contains("brk_trap"))
            .collect();
        let stop_line = trace
            .lines()
            .find(|line| line.contains("\"Call\":\"emulation-stop\""))
            .unwrap_or("<no emulation-stop event>");
        panic!(
            "fast-mode trace did not contain the log-stream posix_spawnp — \
             the malware did not reach the Unit42 Table-1 shutdown-monitor \
             command. Make sure the latest /tmp/com.apple.lock prefix and \
             O_CREAT honoring fixes are in place.\n\
             trace bytes: {}\n\
             stop event: {}\n\
             posix_spawn / brk_trap lines:\n{}",
            trace.len(),
            stop_line,
            spawn_lines.join("\n")
        );
    }
}
