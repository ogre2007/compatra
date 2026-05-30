//! macOS-only compatibility-mode smoke test.
//!
//! The future host-bridged compatibility layer depends on Darwin host
//! behavior, so CI runs this test on an explicit Intel macOS runner. Other
//! hosts keep the test target present but skip the host-specific check.

#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
const HELLO_FIXTURE: &str = "fixtures/macos/bin/arm64_hello";

#[cfg(target_os = "macos")]
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(target_os = "macos")]
fn fixture_path() -> PathBuf {
    workspace_root().join(HELLO_FIXTURE)
}

#[cfg(target_os = "macos")]
fn machina_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_machina"))
}

#[cfg(not(target_os = "macos"))]
#[test]
fn compat_mode_smoke_is_macos_only() {
    eprintln!(
        "skipping macOS compat-mode integration test on {}",
        std::env::consts::OS
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_executes_arm64_hello_without_analysis_trace_plugins() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode integration test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = fixture_path();
    if !fixture.is_file() {
        eprintln!(
            "skipping compat-mode integration test: fixture not present at {}",
            fixture.display()
        );
        return;
    }

    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        // The compat trace bus intentionally has no analysis plugin preset,
        // so enable legacy startup diagnostics only for this smoke test. These
        // markers prove Unicorn entered guest arm64 code and returned through
        // the synthetic done address instead of merely accepting the CLI input.
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let startup_marker = stdout
        .lines()
        .find(|line| line.contains("[STARTUP][arm64 #00] pc="))
        .unwrap_or("<missing startup marker>");
    let done_marker = stdout
        .lines()
        .find(|line| {
            line.contains("[THREAD][arm64] reached done_addr")
                || line.contains("[STARTUP][arm64] reached done_addr")
        })
        .unwrap_or("<missing done marker>");

    eprintln!(
        "compat proof: host={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    eprintln!(
        "compat proof: command={} --mode compat {}",
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof: status={status}");
    eprintln!("compat proof: guest stdout={guest_stdout:?}");
    eprintln!("compat proof: startup marker={startup_marker}");
    eprintln!("compat proof: done marker={done_marker}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof: stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstderr:\n{}",
        status,
        stderr
    );

    assert!(
        stdout.contains("Hello World"),
        "compat smoke did not proxy guest stdout from the arm64 fixture; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[STARTUP][arm64 #00] pc="),
        "compat smoke did not show the first guest instruction; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[THREAD][arm64] reached done_addr")
            || stdout.contains("[STARTUP][arm64] reached done_addr"),
        "compat smoke did not prove guest execution reached the synthetic done address; stdout:\n{stdout}"
    );
    for forbidden in [
        "\"plugin\":\"procmon\"",
        "\"plugin\":\"syscalls\"",
        "\"plugin\":\"filemon\"",
        "\"plugin\":\"memmon\"",
        "\"plugin\":\"detect\"",
        "\"plugin\":\"capture\"",
        "\"PayloadDumpFile\"",
        "\"SyntheticLogStream\"",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "compat mode emitted analysis trace fragment {forbidden:?}\nstdout:\n{stdout}"
        );
    }
}
