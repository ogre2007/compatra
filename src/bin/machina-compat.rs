use machina::macos::{
    cpu_type_name, emulate_macos_binary_with_mode, macho_cputype, run_target_batch_with_mode,
    targets_from_args, MacosCpu, RuntimeMode,
};
use machina::MachoBinary;

fn emulate_macos_binary_with_stub_resolver(
    binary_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
    let binary = MachoBinary::parse(&raw_data)?;
    let cputype = macho_cputype(&binary);

    if cputype == MacosCpu::Arm64.cputype() {
        emulate_macos_binary_with_mode(binary_path, RuntimeMode::Compat)
    } else {
        Err(format!(
            "Unsupported Mach-O CPU type 0x{:X} ({}) in compat runner",
            cputype,
            cpu_type_name(cputype)
        )
        .into())
    }
}

fn usage() -> &'static str {
    "Usage: machina-compat [--compat|--mode compat] [targets...]\n\nRuns the macOS arm64 compatibility layer without analysis mode."
}

fn parse_args(args: Vec<String>) -> Result<Vec<String>, String> {
    let mut targets = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            println!("{}", usage());
            std::process::exit(0);
        } else if arg == "--compat" {
            continue;
        } else if arg == "--analysis" {
            return Err("machina-compat cannot run analysis mode".to_string());
        } else if arg == "--mode" {
            let value = iter
                .next()
                .ok_or_else(|| "--mode requires 'compat' for machina-compat".to_string())?;
            let mode: RuntimeMode = value.parse()?;
            if mode != RuntimeMode::Compat {
                return Err("machina-compat only accepts '--mode compat'".to_string());
            }
        } else if let Some(value) = arg.strip_prefix("--mode=") {
            let mode: RuntimeMode = value.parse()?;
            if mode != RuntimeMode::Compat {
                return Err("machina-compat only accepts '--mode=compat'".to_string());
            }
        } else {
            targets.push(arg);
        }
    }
    Ok(targets)
}

fn main() {
    let target_args = parse_args(std::env::args().skip(1).collect()).unwrap_or_else(|msg| {
        eprintln!("{}", msg);
        eprintln!("{}", usage());
        std::process::exit(2);
    });
    let targets = targets_from_args(&target_args).unwrap_or_else(|msg| {
        eprintln!("{}", msg);
        std::process::exit(2);
    });

    let summary = run_target_batch_with_mode(targets, RuntimeMode::Compat, |path| {
        emulate_macos_binary_with_stub_resolver(path)
    });
    if summary.failed > 0 {
        std::process::exit(1);
    }
}
