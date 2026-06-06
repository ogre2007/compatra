//! Integration test for Mach-O Man profiler system commands.
//!
//! This test intentionally asserts command strings surfaced by the normal
//! arm64 `_popen` OS-call hook rather than libc++ string-building hooks. The
//! goal is to pin the generic tracing surface that tells analysts which
//! system commands the profiler attempted to execute.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const MACHOMAN_FIXTURE: &str = "fixtures/macos/bin/machoman/D1yCPUyk.bin.macho";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_path() -> PathBuf {
    workspace_root().join(MACHOMAN_FIXTURE)
}

fn machoscope_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_machoscope"))
}

fn has_line_with(trace: &str, parts: &[&str]) -> bool {
    trace
        .lines()
        .any(|line| parts.iter().all(|part| line.contains(part)))
}

fn assert_line_with(trace: &str, parts: &[&str], description: &str) {
    assert!(
        has_line_with(trace, parts),
        "Mach-O Man trace did not contain {}.\nrequired fragments: {:?}",
        description,
        parts
    );
}

fn assert_popen_command(trace: &str, command: &str) {
    assert_line_with(
        trace,
        &[
            "\"Call\":\"popen\"",
            "\"Command\":\"",
            command,
            "\"Mode\":\"r\"",
        ],
        &format!("_popen command {command:?}"),
    );
}

#[test]
fn machoman_profiler_system_commands_are_visible_on_popen_hooks() {
    let fixture = fixture_path();
    if !fixture.is_file() {
        eprintln!(
            "skipping Mach-O Man integration test: fixture not present at {}",
            fixture.display()
        );
        return;
    }

    let output = Command::new(machoscope_binary())
        .arg(&fixture)
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env(
            "COMPATRA_BYPASS_USAGE_CHECK",
            "0x10022AE68@0x10022812C=0;\
             0x10022AE68@0x100225548=0;\
             0x10022AE68@0x100225ADC=0",
        )
        .env("COMPATRA_ARGV_APPEND", "http://127.0.0.1:8888")
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

    assert!(
        trace.contains("\"Call\":\"run_target\""),
        "trace did not contain a run_target event - emulator probably did not start"
    );

    assert_line_with(
        &trace,
        &[
            "\"Event\":\"bypass-usage-check\"",
            "\"LrFilter\":\"0x10022812C\"",
        ],
        "the LR-filtered usage-check bypass event",
    );

    for command in [
        "uname -s 2>/dev/null",
        "uname -m 2>/dev/null",
        "uname -r 2>/dev/null",
        "stat -f %SB / 2>/dev/null | head -1",
        "sysctl -n kern.boottime 2>/dev/null | grep -oE '[0-9]+' | head -1",
        "date +%Z 2>/dev/null",
        "sysctl -n machdep.cpu.brand_string 2>/dev/null",
        "ifconfig en0 2>/dev/null | awk '/ether/{print $2}'",
        "ifconfig en0 2>/dev/null | awk '/inet /{print $2}'",
        "ps -eo pid,sess,command 2>/dev/null",
    ] {
        assert_popen_command(&trace, command);
    }

    assert_line_with(
        &trace,
        &[
            "\"Call\":\"popen\"",
            "\"Command\":\"uname -s 2>/dev/null\"",
            "\"SyntheticOutput\":\"true\"",
            "\"SyntheticLabel\":\"uname-kernel\"",
            "\"OutputBytes\":\"7\"",
        ],
        "synthetic stdout metadata for uname -s",
    );

    assert_line_with(
        &trace,
        &[
            "\"Call\":\"fgets\"",
            "\"SyntheticPopen\":\"true\"",
            "\"SyntheticLabel\":\"uname-kernel\"",
            "\"Preview\":\"Darwin\\\\n\"",
            "\"Result\":\"0x",
        ],
        "guest fgets reading synthetic uname output",
    );

    assert_line_with(
        &trace,
        &[
            "\"Call\":\"fgets\"",
            "\"SyntheticPopen\":\"true\"",
            "\"SyntheticLabel\":\"process-list\"",
            "Google Chrome",
        ],
        "guest fgets reading synthetic process-list output",
    );

    assert_line_with(
        &trace,
        &[
            "\"Call\":\"emulation-stop\"",
            "idle_sleep_loop(seconds=1, caller=0x100228950, sleeps=3)",
        ],
        "the clean profiler idle-loop stop reason",
    );
}
