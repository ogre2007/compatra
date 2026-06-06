use compatra_runtime::macos::{
    cpu_type_name, emulate_macos_binary_with_mode, macho_cputype, run_target_batch_with_mode,
    targets_from_args, MacosCpu, RuntimeMode,
};
#[cfg(target_os = "macos")]
use compatra_runtime::macos::{
    loader::consts::cpu_type, process_event, shared_trace_bus_for_mode_from_env,
};
use compatra_runtime::MachoBinary;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CompatLogOptions {
    level: Option<String>,
    filter: Option<String>,
    preview_bytes: Option<String>,
}

impl CompatLogOptions {
    fn apply_env(&self) {
        if let Some(level) = &self.level {
            std::env::set_var("COMPATRA_COMPAT_LOG", level);
        }
        if let Some(filter) = &self.filter {
            std::env::set_var("COMPATRA_COMPAT_LOG_FILTER", filter);
        }
        if let Some(preview_bytes) = &self.preview_bytes {
            std::env::set_var("COMPATRA_COMPAT_LOG_PREVIEW_BYTES", preview_bytes);
        }
    }
}

#[cfg(target_os = "macos")]
fn native_host_macho_cpu() -> Option<u32> {
    match std::env::consts::ARCH {
        "x86_64" => Some(cpu_type::CPU_TYPE_X86_64),
        "aarch64" => Some(cpu_type::CPU_TYPE_ARM64),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn file_has_execute_bit(binary_path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(binary_path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn native_fat_slice_is_runnable(raw_data: &[u8], binary_path: &str) -> bool {
    let Some(cputype) = native_host_macho_cpu() else {
        return false;
    };
    MachoBinary::is_fat(raw_data)
        && MachoBinary::fat_contains_cpu(raw_data, cputype)
        && file_has_execute_bit(binary_path)
}

#[cfg(target_os = "macos")]
fn run_native_compatible_fat(binary_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trace_bus = shared_trace_bus_for_mode_from_env(RuntimeMode::Compat);
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(
                &compatra_runtime::macos::TraceMetadata::new(),
                "native-fat",
                "exec",
            )
            .arg("Path", binary_path.to_string())
            .arg("HostArch", std::env::consts::ARCH.to_string()),
        );
    }
    let status = std::process::Command::new(binary_path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("native FAT slice exited with status {status}").into())
    }
}

fn emulate_macos_binary_with_stub_resolver(
    binary_path: &str,
    runtime_mode: RuntimeMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
    #[cfg(target_os = "macos")]
    {
        if runtime_mode.is_compat() && native_fat_slice_is_runnable(&raw_data, binary_path) {
            return run_native_compatible_fat(binary_path);
        }
    }
    let binary = MachoBinary::parse(&raw_data)?;
    let cputype = macho_cputype(&binary);

    if cputype == MacosCpu::Arm64.cputype() {
        emulate_macos_binary_with_mode(binary_path, runtime_mode)
    } else {
        Err(format!(
            "Unsupported Mach-O CPU type 0x{:X} ({}) in runner",
            cputype,
            cpu_type_name(cputype)
        )
        .into())
    }
}

fn usage() -> &'static str {
    "Usage: machoscope [--mode analysis|compat] [--compat-log off|summary|calls|verbose] [--compat-log-filter calls] [--compat-log-preview-bytes n] [targets...]\n\nModes:\n  analysis  malware-analysis defaults with JSONL plugins and synthetic artifacts\n  compat    compatibility defaults without analysis bait data or detections; prefer compatra for compatibility-only builds\n\nCompat logs are JSONL lines written to stderr. Any non-off level reports unhandled imports and unresolved dlsym requests. Filters limit host-call logs to normalized call names such as write,open,getaddrinfo."
}

fn parse_compat_log_level(value: String) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" | "none" => Ok("off".to_string()),
        "1" | "true" | "yes" | "summary" => Ok("summary".to_string()),
        "call" | "calls" | "full" | "jsonl" | "on" => Ok("calls".to_string()),
        "verbose" | "debug" => Ok("verbose".to_string()),
        _ => Err(format!(
            "--compat-log expects off, summary, calls, or verbose; got {value:?}"
        )),
    }
}

fn parse_preview_bytes(value: String) -> Result<String, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("--compat-log-preview-bytes expects an integer; got {value:?}"))?;
    if parsed > 4096 {
        return Err("--compat-log-preview-bytes must be <= 4096".to_string());
    }
    Ok(parsed.to_string())
}

fn parse_args(args: Vec<String>) -> Result<(RuntimeMode, CompatLogOptions, Vec<String>), String> {
    let mut mode = RuntimeMode::from_env()?;
    let mut targets = Vec::new();
    let mut compat_log = CompatLogOptions::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            println!("{}", usage());
            std::process::exit(0);
        } else if arg == "--compat" {
            mode = RuntimeMode::Compat;
        } else if arg == "--analysis" {
            mode = RuntimeMode::Analysis;
        } else if arg == "--mode" {
            let value = iter
                .next()
                .ok_or_else(|| "--mode requires 'analysis' or 'compat'".to_string())?;
            mode = value.parse()?;
        } else if let Some(value) = arg.strip_prefix("--mode=") {
            mode = value.parse()?;
        } else if arg == "--compat-log" {
            let value = iter
                .next()
                .ok_or_else(|| "--compat-log requires a value".to_string())?;
            compat_log.level = Some(parse_compat_log_level(value)?);
        } else if let Some(value) = arg.strip_prefix("--compat-log=") {
            compat_log.level = Some(parse_compat_log_level(value.to_string())?);
        } else if arg == "--compat-log-filter" {
            compat_log.filter = Some(iter.next().ok_or_else(|| {
                "--compat-log-filter requires a comma-separated value".to_string()
            })?);
        } else if let Some(value) = arg.strip_prefix("--compat-log-filter=") {
            compat_log.filter = Some(value.to_string());
        } else if arg == "--compat-log-preview-bytes" {
            let value = iter
                .next()
                .ok_or_else(|| "--compat-log-preview-bytes requires a value".to_string())?;
            compat_log.preview_bytes = Some(parse_preview_bytes(value)?);
        } else if let Some(value) = arg.strip_prefix("--compat-log-preview-bytes=") {
            compat_log.preview_bytes = Some(parse_preview_bytes(value.to_string())?);
        } else {
            targets.push(arg);
        }
    }
    Ok((mode, compat_log, targets))
}

pub fn run_from_env() {
    let (runtime_mode, compat_log, target_args) = parse_args(std::env::args().skip(1).collect())
        .unwrap_or_else(|msg| {
            eprintln!("{}", msg);
            eprintln!("{}", usage());
            std::process::exit(2);
        });
    compat_log.apply_env();
    let targets = targets_from_args(&target_args).unwrap_or_else(|msg| {
        eprintln!("{}", msg);
        std::process::exit(2);
    });

    let summary = run_target_batch_with_mode(targets, runtime_mode, |path| {
        emulate_macos_binary_with_stub_resolver(path, runtime_mode)
    });
    if summary.failed > 0 {
        std::process::exit(1);
    }
}
