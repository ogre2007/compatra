# Machina

`Machina` is a Rust project for emulating macOS `arm64` Mach-O binaries with a
malware-analysis and userland compatibility focus.

The project is intentionally no longer a generic Qiling port. Its current scope
is:

- `arm64` macOS userland binaries
- Unicorn-backed CPU emulation
- synthetic macOS runtime services
- two runtime modes: `analysis` for malware-analysis workflows and `compat`
  for host-backed userland compatibility work
- JSONL-first tracing in analysis mode
- fixture-driven progress against real samples, including stealers

## Repository layout

- [src/bin/machina.rs](D:/dev/quiling/qiling/src/bin/machina.rs): analysis-capable CLI entrypoint
- [src/bin/machina-compat.rs](D:/dev/quiling/qiling/src/bin/machina-compat.rs): compatibility-only CLI entrypoint for no-analysis builds
- [crates/machina-mode](D:/dev/quiling/qiling/crates/machina-mode): shared `RuntimeMode` parsing and predicates
- [crates/machina-analysis](D:/dev/quiling/qiling/crates/machina-analysis): analysis-only services, synthetic analysis artifacts, capture helpers, and built-in plugin preset specs
- [crates/machina-compat](D:/dev/quiling/qiling/crates/machina-compat): compatibility-only host proxy services behind a guest-memory trait
- [src/macos](D:/dev/quiling/qiling/src/macos): macOS emulation code
- [src/macos/core/mod.rs](D:/dev/quiling/qiling/src/macos/core/mod.rs): architecture-neutral emulation pipeline, tracing, and runtime façades
- [src/macos/arch_arm64/mod.rs](D:/dev/quiling/qiling/src/macos/arch_arm64/mod.rs): grouped view of arm64-specific modules
- [src/macos/platform_apple/mod.rs](D:/dev/quiling/qiling/src/macos/platform_apple/mod.rs): grouped view of Apple compatibility layers
- [src/macos/guest_model/mod.rs](D:/dev/quiling/qiling/src/macos/guest_model/mod.rs): grouped view of guest filesystem and memory helpers
- [fixtures](D:/dev/quiling/qiling/fixtures): development sample corpus and analysis notes
- [docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md): current fixture status and observed behavior

## Unicorn dependency

Machina uses the published `unicorn-engine` / `unicorn-engine-sys` crates as
normal Cargo dependencies.

There is no vendored Unicorn source tree in the repository anymore, and Unicorn
is not managed as a git submodule. [build.rs](D:/dev/quiling/qiling/build.rs)
only handles Windows-side `unicorn.dll` placement after Cargo builds the crate.

## Runtime modes

Machina has two runtime modes. The mode is selected by `--mode`, the shorthand
flags `--analysis` / `--compat`, or `MACHINA_MODE`.

| Mode | Entrypoint | Purpose | Behavior |
| --- | --- | --- | --- |
| `analysis` | `machina` | Malware-analysis runs against samples | Enables analysis services, synthetic analyst-visible guest data, capture/detection events, and built-in JSONL trace plugin presets. This is the default mode and the default Cargo feature set. |
| `compat` | `machina` or `machina-compat` | Running arm64 macOS userland code with fewer analysis assumptions | Disables analysis-only synthetic artifacts, captures, detections, and built-in analysis plugin presets. Host-backed Darwin/libSystem import and raw syscall proxies are used where implemented. |

Runtime mode and Cargo features are related but not identical:

- `cargo build --bin machina` builds the full analysis-capable binary. It can
  still run `--mode compat`, but the analysis crate is present in the build.
- `cargo build --no-default-features --bin machina-compat` builds the dedicated
  compatibility utility. It always runs compat mode and does not link
  `machina-analysis`.
- Compatibility mode is not a security boundary and does not add defensive
  isolation. It is a userland compatibility path that tries to proxy supported
  guest operations into host-backed helpers.

## Logging

Default runtime output is expected to be structured JSONL through the trace bus.
Human-readable `println!` diagnostics are legacy-only and should be treated as
debug output to be removed or gated over time.

Useful knobs:

- `MACHINA_MODE=analysis`: select analysis mode, the default
- `MACHINA_MODE=compat`: select compatibility mode for the `machina` binary
- `MACHINA_PLUGIN_TRACE=1`: enable plugin trace bus
- `MACHINA_TRACE_FORMAT=jsonl`: force JSONL output
- `MACHINA_TRACE_FORMAT=human`: legacy human-readable sink for debugging
- `MACHINA_INDIRECT_BRANCH_MODE=fast`: default; skip expensive indirect-branch sanitizers
- `MACHINA_INDIRECT_BRANCH_MODE=sanitize`: enable indirect-branch sanitizers for debugging signed or tagged branch targets
- `MACHINA_PROFILE=default`: default; 60s timeout, 50M instruction budget (suitable for most samples and CI)
- `MACHINA_PROFILE=short`: legacy 15s / 10M-instruction budget (for tight smoke runs)
- `MACHINA_PROFILE=long`: 120s / 200M-instruction budget (recommended for RustDoor and other Rust binaries with large startup graphs)
- `MACHINA_PROFILE=extended`: 300s / 1B-instruction budget (deep analysis runs)
- `MACHINA_TIMEOUT_USECS` / `MACHINA_MAX_INSTRUCTIONS`: explicit overrides; always win over the active profile
- `MACHINA_BYPASS_USAGE_CHECK`: sample-analysis helper for forcing selected arm64 call sites to return fixed values; supports `0xADDR=VAL0,VAL1` and optional LR filters such as `0xADDR@0xLR=VAL`

## Build

```powershell
cargo build --bin machina
```

The compatibility utility can be built without the default `analysis` feature:

```powershell
cargo build --no-default-features --bin machina-compat
```

## Run

```powershell
cargo run --bin machina -- fixtures\macos\bin\arm64_hello
```

Compatibility mode keeps the same arm64 loader and execution path but uses
non-analysis runtime services. Selected Darwin/libSystem imports and raw
`svc #0x80` syscall traps are proxied into host-backed helpers so small arm64
programs can make observable progress under an Intel macOS host.

```powershell
cargo run --bin machina -- --mode compat fixtures\macos\bin\arm64_hello
```

For compatibility-only runs prefer the dedicated binary:

```powershell
cargo run --no-default-features --bin machina-compat -- fixtures\macos\bin\arm64_hello
```

## Local compat smoke check

Compatibility mode is pinned by `tests/compat_mode_macos.rs`. The test is
intended for Intel macOS, where host-library compatibility work can be
validated:

```
cargo test --release --no-default-features --test compat_mode_macos -- --nocapture
```

Use `-- --nocapture` when debugging CI or a local Intel macOS machine. The test
prints `compat ...` proof lines with real guest-observed return values and
outputs, including:

- arm64 guest stdout from the emulated program
- static imports and `dlsym` imports for file descriptors, positioned I/O,
  path metadata and mutation, directory iteration, environment, time, resource,
  and entropy calls
- raw Darwin syscall traps and imported syscall thunks for process, time,
  resource, sysctl, and file descriptor calls

On non-macOS hosts the test is a skip guard; the AMOS and RustDoor regression
tests remain the portable analysis checks.

## Local AMOS integration check

The AMOS private-file access milestones (Binance / Firefox / Electrum
/ Coinomi / Chrome) are pinned by `tests/amos_private_access.rs`. Run
it with:

```
cargo test --test amos_private_access
```

The test spawns the `machina` binary against the AMOS fixture and
asserts the milestones from its JSONL stdout, so it works the same way
on Windows, macOS, and Linux without a separate Python or PowerShell
checker.

## Sample corpus

The project keeps a small local corpus in
[fixtures/macos/bin](D:/dev/quiling/qiling/fixtures/macos/bin).

Two important analysis targets today:

- `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`
  AMOS stealer sample used to drive browser/wallet compatibility work
- `0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho`
  large arm64 sample used for deeper runtime and synthetic API coverage work

See [fixtures/README.md](D:/dev/quiling/qiling/fixtures/README.md) and
[docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md).

## Project status

Working today:

- arm64 Mach-O loading and execution
- synthetic imports, syscall shims, guest filesystem model
- host-backed compatibility shims for selected Darwin/libSystem imports and
  raw arm64 Darwin syscall traps in compat mode
- JSONL plugin events
- real sample progression into malware logic for AMOS-style paths

Still in progress:

- deeper normalization of all remaining legacy stdout diagnostics
- broader synthetic macOS API coverage
- broader host-backed static/dynamic import and syscall coverage for compat
- directory-heavy profile emulation and richer artifact capture for analysis
- publication cleanup of remaining legacy compatibility layers inherited from the Qiling-era codebase

## License

GPL-2.0
