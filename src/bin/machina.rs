use machina::macos::{
    cpu_type_name, emulate_macos_binary, macho_cputype, run_target_batch, targets_from_args,
    MacosCpu,
};
use machina::MachoBinary;

fn emulate_macos_binary_with_stub_resolver(
    binary_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
    let binary = MachoBinary::parse(&raw_data)?;
    let cputype = macho_cputype(&binary);

    if cputype == MacosCpu::Arm64.cputype() {
        emulate_macos_binary(binary_path)
    } else {
        Err(format!(
            "Unsupported Mach-O CPU type 0x{:X} ({}) in runner",
            cputype,
            cpu_type_name(cputype)
        )
        .into())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let targets = targets_from_args(&args).unwrap_or_else(|msg| {
        eprintln!("{}", msg);
        std::process::exit(2);
    });

    let summary = run_target_batch(targets, emulate_macos_binary_with_stub_resolver);
    if summary.failed > 0 {
        std::process::exit(1);
    }
}
