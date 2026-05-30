use machina::macos::{
    cpu_type_name, emulate_macos_binary_with_mode, macho_cputype, run_target_batch_with_mode,
    targets_from_args, MacosCpu, RuntimeMode,
};
use machina::MachoBinary;

fn emulate_macos_binary_with_stub_resolver(
    binary_path: &str,
    runtime_mode: RuntimeMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
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
    "Usage: machina [--mode analysis|compat] [targets...]\n\nModes:\n  analysis  malware-analysis defaults with JSONL plugins and synthetic artifacts\n  compat    compatibility defaults without analysis bait data or detections"
}

fn parse_args(args: Vec<String>) -> Result<(RuntimeMode, Vec<String>), String> {
    let mut mode = RuntimeMode::from_env()?;
    let mut targets = Vec::new();
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
        } else {
            targets.push(arg);
        }
    }
    Ok((mode, targets))
}

fn main() {
    let (runtime_mode, target_args) = parse_args(std::env::args().skip(1).collect())
        .unwrap_or_else(|msg| {
            eprintln!("{}", msg);
            eprintln!("{}", usage());
            std::process::exit(2);
        });
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
