//! macOS-only compatibility-mode smoke test.
//!
//! The future host-bridged compatibility layer depends on Darwin host
//! behavior, so CI runs this test on an explicit Intel macOS runner. Other
//! hosts keep the test target present but skip the host-specific check.

#[cfg(target_os = "macos")]
use std::fs;
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

#[cfg(target_os = "macos")]
fn generated_fixture_dir() -> PathBuf {
    workspace_root()
        .join("target")
        .join("machina-compat-fixtures")
}

#[cfg(target_os = "macos")]
fn compile_arm64_write_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_write_hello.c");
    let binary = out_dir.join("arm64_write_hello");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*printf_fn)(const char *, ...);

int main(void) {
    printf("compat %s path\n", "printf");
    void *self = dlopen(NULL, RTLD_NOW);
    printf_fn dyn_printf = (printf_fn)dlsym(self, "printf");
    if (dyn_printf == 0) {
        return 2;
    }
    dyn_printf("compat %s path\n", "dlsym");
    dlclose(self);
    return write(1, "compat write path\n", sizeof("compat write path\n") - 1) < 0;
}
"#,
    )
    .expect("failed to write generated arm64 C fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
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

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_fresh_arm64_write_program() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode integration test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_write_fixture();
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
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

    eprintln!(
        "compat proof(write+dlsym): command={} --mode compat {}",
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(write+dlsym): status={status}");
    eprintln!("compat proof(write+dlsym): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(write+dlsym): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstderr:\n{}",
        status,
        stderr
    );
    assert!(
        stdout.contains("compat printf path"),
        "fresh arm64 fixture did not reach host-proxied _printf; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dlsym path"),
        "fresh arm64 fixture did not call a dlsym-returned guest trampoline; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat write path"),
        "fresh arm64 write fixture did not reach host-proxied _write; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[STARTUP][arm64 #00] pc="),
        "fresh arm64 write fixture did not show the first guest instruction; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[THREAD][arm64] reached done_addr")
            || stdout.contains("[STARTUP][arm64] reached done_addr"),
        "fresh arm64 write fixture did not prove guest execution reached done_addr; stdout:\n{stdout}"
    );
}
