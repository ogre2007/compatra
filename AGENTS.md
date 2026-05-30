# AGENTS

These rules are for agents (codex, Claude, future contributors) working on this
repo. The intent is to keep direction stable across short, automated sessions.

## Project identity

- Project name: `Machina` (Cargo package `machina`, lib `machina`, bin `machina`).
- Language: Rust, edition 2021.
- Workspace architecture crates:
  - `crates/machina-arch` — architecture-neutral identifiers and traits.
  - `crates/machina-arch-arm64` — pure arm64 ABI, stub-layout,
    instruction-decoder, and pointer-sanitizer primitives with no dependency
    on the main `machina` crate.
- Workspace runtime-mode crates:
  - `crates/machina-mode` — `RuntimeMode` parsing/defaults and mode
    predicates.
  - `crates/machina-analysis` — analysis-only services: capture artifact
    writing, payload summaries, synthetic analyst fixtures such as log-stream
    output, synthetic guest artifact/bait data, and built-in analysis plugin
    preset specifications and operator hook env parsing.
  - `crates/machina-compat` — compatibility-only host proxy services behind a
    guest-memory trait; it must not depend on analysis services or the main
    `machina` crate.
- Scope: macOS `arm64` Mach-O userland emulation for malware analysis.
- CPU backend: published `unicorn-engine` / `unicorn-engine-sys` crates (no
  vendored source, no submodule).
- Non-goals: reviving broad Qiling compatibility or maintaining `x86`,
  `x86_64`, or `arm32` execution paths.

## Code organization rules

`src/macos/mod.rs` is intentionally flat: each leaf file is declared once via
`#[path = ".../foo.rs"] pub mod foo;` and then the grouped façades re-export
the same modules under shorter names. When you add a new file:

1. Decide which group it belongs to (see below).
2. Add the `#[path]` declaration in `src/macos/mod.rs`.
3. Re-export it from the matching group's `mod.rs` (`core`, `arch_arm64`,
   `analysis_arm64`, `platform_apple`, `guest_model`) using `pub use` so
   callers can keep importing through the façade.
4. If the new symbol is part of the public surface, add a `pub use` entry to
   `src/lib.rs` as well.

Group ownership:

- `src/macos/core` — architecture-neutral orchestration, analysis-service
  boundary (`analysis.rs`), compatibility-service boundary (`compat.rs`),
  tracing, plugin and runtime façades, batch
  emulation driver (`emulation.rs`), JSONL trace pipeline (`trace.rs`,
  `plugin_events.rs`, `runner_plugins.rs`).
- `src/macos/arch_arm64` — arm64-only runner, binary setup, diagnostics,
  shared arm64 runtime state (`state.rs`), import-stub plumbing
  (`import_stubs.rs`), dynamic import trampolines (`dynamic_imports.rs`),
  LSE atomic / indirect-branch hooks, and arm64 `*_imports.rs` thunk groups
  that are required by both runtime modes.
- `src/macos/analysis_arm64` — arm64-only analysis hooks and diagnostic shims
  that are not part of the compatibility runtime. C++/libc++ synthetic hook
  models, fake analysis data symbols, and other operator-facing arm64 analysis
  glue belong here behind `AnalysisRuntimeHooks`/analysis-mode gating.
- `src/macos/platform_apple` — CoreFoundation, Security, XPC, libobjc and
  other Apple-facing synthetic runtime services.
- `src/macos/guest_model` — guest filesystem (`files.rs`), guest memory
  (`memory.rs`), and synthetic OS-visible resources.
- `src/macos/loader` — Mach-O parser, command/header decoding, and the
  no-dyld vs dyld load-path switch (`MACHINA_USE_DYLD`).

Architecture-neutral logic should not live in `arch_arm64`. Prefer reusable
services or plugins over one-off hook-local hacks.

Pure architecture facts should not live in the main `machina` crate. Put
arm64 instruction masks/decoders, ABI constants, register naming/layout, and
stub-layout constants in `crates/machina-arch-arm64`. Keep emulator lifecycle,
Unicorn hooks, trace events, guest filesystem, and Apple/Darwin service
modeling in the main crate until their runtime dependencies are split cleanly.

Analysis and compatibility behavior should not live in the same implementation
module. `src/macos/core/analysis.rs`, `compat.rs`, `capture.rs`, `mode.rs`, and
`src/macos/guest_model/analysis_artifacts.rs` are facades/adapters only; real
behavior belongs in `crates/machina-analysis`, `crates/machina-compat`, or
`crates/machina-mode`. Compatibility code must not emit detections, write
captures, synthesize analyst bait data, or depend on the analysis crate.
If arm64 code needs analysis behavior, route it through
`AnalysisRuntimeHooks` or an `analysis_arm64` module instead of storing
capture state or parsing analysis-only env knobs directly in
`src/macos/arch_arm64`.

## Logging rules

- Default observable output is structured JSONL through the trace/plugin
  pipeline. New feature work should emit `TraceEvent`s first.
- Raw `println!` / `eprintln!` output is legacy debug output and should not
  be the primary logging surface.
- If a hook needs extra debug-only text, gate it (typically via
  `MACHINA_DEBUG_STDOUT`) so it does not pollute the default analysis stream.

Environment knobs the code currently honors (keep this list in sync if you
add new ones):

- `MACHINA_PLUGIN_TRACE` — enable/disable the plugin trace bus (default on).
- `MACHINA_MODE` — `analysis` (default) or `compat`. Analysis mode keeps
  malware-analysis defaults; compat mode disables analysis-only synthetic
  artifacts, captures, detections, and built-in trace plugin presets.
- `MACHINA_TRACE_FORMAT` — `jsonl` (default) or `human`.
- `MACHINA_TRACE_PROFILE` — `compact` (default), `full`, or `debug`.
- `MACHINA_TRACE_WINDOW_START` / `_END` / `_HITS` — bounded instruction trace
  window for arm64 diagnostics.
- `MACHINA_INDIRECT_BRANCH_MODE` — `fast` (default) or `sanitize`.
- `MACHINA_AUTH_DISPATCH_DIAG` / `_HITS` — pointer-auth dispatch diagnostics.
- `MACHINA_PROFILE` — pre-set budget bundle: `default` (60 s / 50 M instr,
  current behavior), `short` (15 s / 10 M, legacy cap), `long`
  (120 s / 200 M, recommended for RustDoor and other Rust binaries with
  heavy startup graphs), `extended` (300 s / 1 B, deep analysis runs).
  The runner emits a `run-profile` trace event with the resolved values.
- `MACHINA_TIMEOUT_USECS` / `MACHINA_MAX_INSTRUCTIONS` — explicit emulation
  budgets; always override the active `MACHINA_PROFILE`.
- `MACHINA_ARGV_APPEND` — extra guest argv tokens appended at bootstrap.
- `MACHINA_BYPASS_USAGE_CHECK` — analysis helper for selected arm64 call
  sites; tokens are `0xADDR`, `0xADDR=VAL0,VAL1`, or
  `0xADDR@0xLR=VAL` to apply a return override only when LR matches.
- `MACHINA_TRACE_FN_ENTRY` — comma-separated `<label>:<hex addr>` hooks that
  emit structured `function-entry` trace events without changing execution.
- `MACHINA_USE_DYLD` — opt-in to dyld load path; default is the no-dyld
  fallback.
- `MACHINA_DEBUG_STDOUT` — gate legacy human-readable debug prints.

## Dependency rules

- Unicorn stays a normal Cargo dependency. If future Unicorn work requires
  patching, justify it explicitly before reintroducing repository-local
  source copies.
- Do not introduce new architecture features into `unicorn-engine` unless
  the project scope changes explicitly.
- `build.rs` is intentionally minimal: it only locates and copies
  `unicorn.dll` on Windows builds. Do not extend it with project-specific
  build logic.

## Sample corpus rules

- `fixtures/macos/bin` is the local development corpus.
- `fixtures/README.md` documents what is in the corpus.
- `docs/sample-status.md` records current execution/analysis status.
- Tracked sample families today:
  - `arm64_hello` — smoke fixture.
  - AMOS stealer
    (`2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`)
    — drives browser/wallet compatibility work and is the CI regression
    target.
  - RustDoor
    (`fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho`)
    — drives daemon-lifecycle, lock-file, and `posix_spawnp` log-stream
    coverage.
  - `0393e898…macho` — large arm64 reference target.
- If a sample meaningfully changes emulator direction, update
  `docs/sample-status.md` with the result, not just the code change.
- `docs/rustdoor.mhtml` is a checked-in offline analysis reference for the
  RustDoor family. Do not delete it casually — the corpus has no other
  external reference for that family.

## CI and local validation

- CI (`.github/workflows/rust.yml`) runs the full `cargo test` suite on
  Ubuntu and a focused compatibility-mode smoke test on Intel macOS
  (`macos-15-intel`). The AMOS regression contract lives in
  `tests/amos_private_access.rs`, the RustDoor fast-mode contract lives in
  `tests/rustdoor_fast_mode.rs`, and the Intel macOS compatibility smoke
  lives in `tests/compat_mode_macos.rs`.
- Canonical local smoke flow:
  - `cargo build --bin machina`
  - `cargo run --bin machina -- fixtures/macos/bin/arm64_hello`
  - `cargo test --test amos_private_access` for the AMOS regression
  - `cargo test --test rustdoor_fast_mode` for the RustDoor milestones
  - `cargo test --test compat_mode_macos` on Intel macOS for compat mode

## Repo hygiene

- `*.jsonl`, `*.txt`, `*.log`, `*.dmp`, and similar capture artifacts are
  gitignored on purpose. Do not stage them — they exist as scratch traces.
- `target/` and `target_codex/` are gitignored. Do not check in build
  artifacts.
- The repo is on `master`. Local working trees frequently show whole-file
  diffs because of CRLF↔LF line-ending churn; verify with
  `git diff -w --stat` before assuming code actually changed.

## Review checklist for changes

- Is the new behavior arm64-only for a good reason, or should it live in a
  shared service in `core` / `platform_apple` / `guest_model`?
- Does the change keep default logs structured (JSONL via the trace bus)?
- Does it improve behavior on a real fixture, and is that reflected in
  `docs/sample-status.md`?
- Does it add tech debt by hardcoding one sample, or does it improve a
  reusable emulator layer?
- Is any new env knob documented here and in `README.md`?
- Are CI and local AMOS checkers still in agreement after the change?
