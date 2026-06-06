# Compatra

`Compatra` is a Rust compatibility runner for macOS `arm64` Mach-O userland
binaries on Intel macOS hosts. The workspace also includes `Machoscope`, an
analysis-capable runner for malware-analysis workflows over the same runtime.

Its current scope is:

- `arm64` macOS userland binaries
- Unicorn-backed CPU emulation
- synthetic macOS runtime services
- `compatra` as the compatibility-only CLI
- `machoscope` as the analysis-capable CLI
- JSONL-first tracing in analysis mode
- fixture-driven progress against real samples, including stealers

## Repository layout

- [Cargo.toml](D:/dev/quiling/qiling/Cargo.toml): virtual workspace root
- [crates/machoscope](D:/dev/quiling/qiling/crates/machoscope): analysis-capable `machoscope` CLI/library and portable analysis regression tests
- [crates/machoscope-analysis](D:/dev/quiling/qiling/crates/machoscope-analysis): analysis-only services, synthetic analysis artifacts, capture helpers, and built-in plugin preset specs
- [crates/compatra](D:/dev/quiling/qiling/crates/compatra): compatibility-only host proxy services behind a guest-memory trait
- [crates/compatra-cli](D:/dev/quiling/qiling/crates/compatra-cli): dedicated `compatra` CLI and Intel macOS compatibility tests
- [crates/compatra-runtime](D:/dev/quiling/qiling/crates/compatra-runtime): macOS emulation runtime, loader, Unicorn wrapper, trace pipeline, and arm64 execution flow
- [crates/compatra-runtime/src/macos/core/mod.rs](D:/dev/quiling/qiling/crates/compatra-runtime/src/macos/core/mod.rs): architecture-neutral emulation pipeline, tracing, and runtime façades
- [crates/compatra-runtime/src/macos/arch_arm64/mod.rs](D:/dev/quiling/qiling/crates/compatra-runtime/src/macos/arch_arm64/mod.rs): grouped view of arm64-specific modules
- [crates/compatra-runtime/src/macos/platform_apple/mod.rs](D:/dev/quiling/qiling/crates/compatra-runtime/src/macos/platform_apple/mod.rs): grouped view of Apple compatibility layers
- [crates/compatra-runtime/src/macos/guest_model/mod.rs](D:/dev/quiling/qiling/crates/compatra-runtime/src/macos/guest_model/mod.rs): grouped view of guest filesystem and memory helpers
- [fixtures](D:/dev/quiling/qiling/fixtures): development sample corpus and analysis notes
- [docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md): current fixture status and observed behavior

## Unicorn dependency

The runtime uses the published `unicorn-engine` / `unicorn-engine-sys` crates as
normal Cargo dependencies.

There is no vendored Unicorn source tree in the repository anymore, and Unicorn
is not managed as a git submodule.
[crates/compatra-runtime/build.rs](D:/dev/quiling/qiling/crates/compatra-runtime/build.rs)
only handles Windows-side `unicorn.dll` placement after Cargo builds the runtime
crate.

## Runtime modes

The runtime has two modes. `compatra` always runs compatibility mode and is
built without the analysis crate. `machoscope` is the analysis-capable runner;
it still accepts `--mode` for development and legacy workflows.

| Mode | Entrypoint | Purpose | Behavior |
| --- | --- | --- | --- |
| `analysis` | `machoscope` | Malware-analysis runs against samples | Enables analysis services, synthetic analyst-visible guest data, capture/detection events, and built-in JSONL trace plugin presets. This is the default mode and the default Cargo feature set. |
| `compat` | `compatra` | Running arm64 macOS userland code with fewer analysis assumptions | Disables analysis-only synthetic artifacts, captures, detections, and built-in analysis plugin presets. Host-backed Darwin/libSystem import and raw syscall proxies are used where implemented. |

Runtime mode and Cargo features are related but not identical:

- `cargo build -p machoscope --bin machoscope` builds the full
  analysis-capable binary. It can still run `--mode compat`, but the analysis
  crate is present in the build.
- `cargo build -p compatra-cli --no-default-features --bin compatra` builds
  the dedicated compatibility utility. It always runs compat mode and does not
  link `machoscope-analysis`.
- Compatibility mode is not a security boundary and does not add defensive
  isolation. It is a userland compatibility path that tries to proxy supported
  guest operations into host-backed helpers.
- On macOS, compat mode treats FAT/universal binaries specially: if the file
  contains a slice that the host can run natively, Compatra runs that native
  slice through the OS instead of emulating the arm64 slice. If no native slice
  is available, the loader prefers the arm64 slice for emulation.

## Logging

Default runtime output is expected to be structured JSONL through the trace bus.
Human-readable `println!` diagnostics are legacy-only and should be treated as
debug output to be removed or gated over time.

Useful knobs:

- `COMPATRA_MODE=analysis`: select analysis mode, the default
- `COMPATRA_MODE=compat`: select compatibility mode for analysis-capable development runs; `compatra` always runs compat mode
- `COMPATRA_PLUGIN_TRACE=1`: enable plugin trace bus
- `COMPATRA_TRACE_FORMAT=jsonl`: force JSONL output
- `COMPATRA_TRACE_FORMAT=human`: legacy human-readable sink for debugging
- `COMPATRA_COMPAT_LOG=off|summary|calls|verbose`: emit compatibility-layer JSONL logs to stderr; default is `off`. Any non-`off` level also reports unhandled import-stub hits and unresolved `dlsym` requests.
- `COMPATRA_COMPAT_LOG_FILTER=write,open,getaddrinfo`: limit compat host-call logs to comma-separated normalized call names; missing-import diagnostics still emit at any non-`off` log level
- `COMPATRA_COMPAT_LOG_PREVIEW_BYTES=96`: cap escaped text/hex previews for host-proxied I/O payloads
- `COMPATRA_GUEST_LIBS=/path/libhelper.dylib`: opt in guest-side arm64 Mach-O dylibs for the no-dyld runner. Values use the host path-list separator, may include comma-separated entries, and may point at dylib files, directories of dylibs, or `.framework` directories. Guest-library exports are mapped into guest memory and used for otherwise unhandled static/chained imports and `dlsym` lookups. The loader also records a guest image registry and emits `guest-image-registry` / `guest-image` trace events with image ranges, slides, and export counts.
- `COMPATRA_INDIRECT_BRANCH_MODE=fast`: default; skip expensive indirect-branch sanitizers
- `COMPATRA_INDIRECT_BRANCH_MODE=sanitize`: enable indirect-branch sanitizers for debugging signed or tagged branch targets
- `COMPATRA_PROFILE=default`: default; 60s timeout, 50M instruction budget (suitable for most samples and CI)
- `COMPATRA_PROFILE=short`: legacy 15s / 10M-instruction budget (for tight smoke runs)
- `COMPATRA_PROFILE=long`: 120s / 200M-instruction budget (recommended for RustDoor and other Rust binaries with large startup graphs)
- `COMPATRA_PROFILE=extended`: 300s / 1B-instruction budget (deep analysis runs)
- `COMPATRA_TIMEOUT_USECS` / `COMPATRA_MAX_INSTRUCTIONS`: explicit overrides; always win over the active profile
- `COMPATRA_BYPASS_USAGE_CHECK`: sample-analysis helper for forcing selected arm64 call sites to return fixed values; supports `0xADDR=VAL0,VAL1` and optional LR filters such as `0xADDR@0xLR=VAL`

## Build

```powershell
cargo build -p machoscope --bin machoscope
```

The compatibility utility can be built without the default `analysis` feature:

```powershell
cargo build -p compatra-cli --no-default-features --bin compatra
```

## Run

```powershell
cargo run -p machoscope --bin machoscope -- fixtures\macos\bin\arm64_hello
```

Compatibility mode keeps the same arm64 loader and execution path but uses
non-analysis runtime services. Selected Darwin/libSystem imports and raw
`svc #0x80` syscall traps are proxied into host-backed helpers so small arm64
programs can make observable progress under an Intel macOS host. For helper
code that must run as arm64 guest code, set `COMPATRA_GUEST_LIBS` to one or more
arm64 dylibs; this is an explicit no-dyld import-resolution aid, not a full
dyld replacement. These guest images are tracked in a loader-level registry so
future lazy-resolution and translated-address mapping can share one image model.

```powershell
cargo run -p machoscope --bin machoscope -- --mode compat fixtures\macos\bin\arm64_hello
```

For compatibility-only runs prefer the dedicated binary:

```powershell
cargo run -p compatra-cli --no-default-features --bin compatra -- fixtures\macos\bin\arm64_hello
```

Compat runs can also emit focused host-proxy logs without enabling analysis
plugins. Use `summary` when you mainly want stderr diagnostics for missing
compat imports, or `calls`/`verbose` when you also want successful host-proxy
calls:

```powershell
cargo run -p compatra-cli --no-default-features --bin compatra -- --compat-log calls --compat-log-filter write,getaddrinfo --compat-log-preview-bytes 96 fixtures\macos\bin\arm64_hello
```

## Local compat smoke check

Compatibility mode is pinned by
`crates/compatra-cli/tests/compat_mode_macos.rs`. The test is intended
for Intel macOS, where host-library compatibility work can be validated:

```
cargo test -p compatra-cli --release --no-default-features --test compat_mode_macos -- --nocapture
```

Use `-- --nocapture` when debugging CI or a local Intel macOS machine. The test
prints `compat ...` proof lines with real guest-observed return values and
outputs, including:

- arm64 guest stdout from the emulated program
- arm64 `printf` varargs that spill past register arguments onto the guest
  stack, for both static imports and `dlsym` trampolines
- lifecycle glue diagnostics for `__mod_init_func` constructors, `atexit`
  handlers, and destructor/finalizer stages
- static imports and `dlsym` imports for file descriptors, positioned I/O,
  path metadata and mutation, directory iteration, environment, time, resource,
  and entropy calls
- raw Darwin syscall traps and imported syscall thunks for process, time,
  resource, sysctl, and file descriptor calls

On non-macOS hosts the test is a skip guard; the AMOS and RustDoor regression
tests remain the portable analysis checks.

## Local AMOS integration check

The AMOS private-file access milestones (Binance / Firefox / Electrum
/ Coinomi / Chrome) are pinned by
`crates/machoscope/tests/amos_private_access.rs`. Run
it with:

```
cargo test -p machoscope --test amos_private_access
```

The test spawns the `machoscope` binary against the AMOS fixture and
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
- opt-in guest-side arm64 dylib export mapping for otherwise unhandled imports
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
