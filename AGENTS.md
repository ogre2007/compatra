# AGENTS

## Project identity

- Project name: `Machina`
- Language: Rust
- Scope: macOS `arm64` Mach-O emulation for malware analysis
- Non-goals: reviving broad Qiling compatibility or maintaining `x86`, `x86_64`, or `arm32` execution paths

## Code organization rules

- Keep architecture-neutral logic outside arm64-specific files when possible.
- `src/macos/core` is for architecture-neutral orchestration, tracing, and runtime/plugin façades.
- `src/macos/arch_arm64` is the grouped entrypoint for arm64-only implementation details.
- `src/macos/platform_apple` is for CoreFoundation, Security, XPC, and other Apple-facing synthetic runtime services.
- `src/macos/guest_model` is for guest filesystem, guest memory, and synthetic OS-visible resources.
- New compatibility behavior should prefer reusable services or plugins over one-off hook-local hacks.

## Logging rules

- Default observable output should be structured JSONL through the trace/plugin pipeline.
- New feature work should emit `TraceEvent`s first.
- Raw `println!` / `eprintln!` output is legacy debug output and should not be the primary logging surface.
- If a hook needs extra debug-only text, gate it so it does not pollute the default analysis stream.

## Dependency rules

- Unicorn is treated as a normal Cargo dependency, not a vendored source tree and not a git submodule.
- If future Unicorn work requires patching, justify it explicitly before reintroducing repository-local source copies.
- Do not introduce new architecture features in `unicorn-engine` unless the project scope changes explicitly.

## Sample corpus rules

- `fixtures/macos/bin` is the local development corpus.
- `fixtures/README.md` documents what is in the corpus.
- `docs/sample-status.md` records current execution/analysis status for important samples.
- If a sample meaningfully changes emulator direction, document the result, not just the code change.

## Review checklist for changes

- Is the new behavior arm64-only for a good reason, or should it live in a shared service?
- Does the change keep default logs structured?
- Does it improve behavior on a real fixture, and is that reflected in docs?
- Does it add tech debt by hardcoding one sample, or does it improve a reusable emulator layer?
