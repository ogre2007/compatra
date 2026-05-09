# Sample Status

This file tracks the current state of the local sample corpus as it relates to
emulator behavior.

## `arm64_hello`

- Path: [fixtures/macos/bin/arm64_hello](D:/dev/quiling/qiling/fixtures/macos/bin/arm64_hello)
- Role: smoke-test fixture
- Expected status: should execute successfully
- Current note: used as the primary quick validation sample for `cargo build --bin machina` and basic runtime checks

## `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`

- Path: [fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho](D:/dev/quiling/qiling/fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho)
- Family: AMOS stealer
- Architecture: arm64
- Current observed status:
  - probes browser and wallet paths
  - probes browser profile roots such as Chrome, Brave, Edge, and Firefox
  - attempts to open wallet/private data such as Binance, Electrum, Coinomi, and Exodus paths
  - reads synthetic fallback content from guest filesystem policy
  - CI regression guard verifies these milestones from JSONL trace output on Ubuntu
- Important implication:
  - emulator is already past bootstrap/runtime-only execution and into real stealer logic
  - next compatibility work should focus on richer profile traversal and artifact semantics rather than simple `ENOENT` fixes

## `0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho`

- Path: [fixtures/macos/bin/0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho](D:/dev/quiling/qiling/fixtures/macos/bin/0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho)
- Current observed status:
  - retained as a large arm64 analysis target
- Important implication:
  - this sample is both an execution target and a reverse-engineering reference set

## `rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho`

- Path: [fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho](D:/dev/quiling/qiling/fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho)
- Family: RustDoor
- Architecture: arm64
- Current observed status:
  - parses, maps, and loads Foundation/AppKit/CoreFoundation/Security/libobjc dependencies
  - reaches real runtime/import activity instead of stopping at initial unresolved bindings
  - exercises TLV bootstrap, signal/bootstrap imports, heap growth, `memcmp`, `memmove`, `memcpy`, `malloc`, `realloc`, and `free`
  - now synthetically handles arm64 LSE `ldadd`, `ldapr`, and `cas` runtime atomics that previously consumed the execution budget
  - resolves bootstrap environment lookups such as `getenv("HOME")` from the synthetic guest envp
  - resolves high/tagged literal pointers in libc memory imports, including the path build for `/Users/analyst/.docks`
  - uses chunked synthetic heap mapping so Rust runtime allocation churn no longer exhausts Unicorn memory sections
  - records `posix_spawnp` for `log stream --predicate ... restartInitiated/shutdownInitiated ... --info` and can feed synthetic matching log events into the redirected pipe
  - treats hidden `.inj_*` marker files as absent by default, so RustDoor does not falsely assume Chrome injection already happened
  - progresses through the daemonization path (`fork`, `chdir`, `setsid`, second `fork`) and the grandchild becomes the active daemon
  - tagged-PC FETCH faults now redirect PC to the canonical address, so execution no longer accumulates additional tagged pages for each `bl`/`adrp` from a tagged page
  - the daemon-singleton check on `/tmp/com.apple.lock` now reports `ENOENT`, so the freshly emulated daemon "wins" the lock instead of immediately exiting on the assumption another daemon is already present
  - daemon child PID=3 now reaches persistence/setup activity:
    - opens `~/.zshrc` (read-only then read-write) for shell-startup persistence injection
    - opens `~/.docks/cron` for cron-style persistence
    - creates `/tmp/com.apple.lock.<timestamp>` IPC/marker files
  - the LSE atomic hook now also handles `SWP[A][L]` and the rest of the `LDADD`/`LDCLR`/`LDEOR`/`LDSET`/`LDSMAX`/`LDSMIN`/`LDUMAX`/`LDUMIN` family, not just `CAS`/`LDADD`/`LDAPR`. The OnceLock release `SWPAL x8, x8, [x19]` at `0x10018242C` previously hung because Unicorn did not advance PC for it; with the explicit emulator that path now completes.
  - the synthetic `_waitpid` import now reports `ECHILD` for `WNOHANG` polls when no reapable child is left, mirroring `_wait4`. Without that, the post-OnceLock daemon spun forever in `waitpid(-1, &status, WNOHANG) == 0`.
  - the parent process (`PID=1`, after the daemon detached) now reaches Chrome-injection probing:
    - `_stat /Applications/Google Chrome.app/Contents/MacOS/Google Chrome` (Chrome detection)
    - `_stat /Users/analyst/.docks/.inj_rc_chr` → `ENOENT` (Chrome rc-injection marker)
    - `_stat /Users/analyst/.docks/.inj_launch_chr` → `ENOENT` (Chrome launch-injection marker)
  - the LSE atomic SWP `0x10018242C` now correctly transitions `0x10026D450`/`0x10026D1D8` from `RUNNING` (2) to `COMPLETE` (3), so the OnceLock release returns instead of looping
  - the `_exit` libc symbol is now hooked in addition to the BSD `__exit` syscall wrapper, so the daemon's clean shutdown actually terminates
  - the `done_addr` cleanup hook now honors `stop_now` even when an `exited_pid` is also reported — the previous `else if` chain meant the runner kept running the dead caller's tail after the daemon exit
  - off-canvas data pages (e.g. `0xA00000000`) are now synthesized for tagged data writes that fall outside the canonical heap/mmap arena, so the post-`waitpid` `WaitStatus` store at `[x19, #8]` succeeds
  - the daemon now runs all the way through its persistence-and-Chrome-probing path and **terminates cleanly with `_exit(0)`**:
    - opens `~/.zshrc`, reads it in 32→2048-byte windows, then re-opens it `read_write` and writes injected lines
    - opens `~/.docks/cron` and `/tmp/com.apple.lock.<timestamp>` for cron-style and lock persistence
    - `_stat`s the `~/.local` and `~/.zshrc` parents during persistence prep
    - Stops with `Detail:"done_addr"` and `SawExit:true` (`Imports:10592`), no error
- Important implication:
  - all of the in-process compatibility blockers (TLV bootstrap, LSE atomics, daemonization, lock-file singleton, parking_lot mutex/condvar, `waitpid` poll, exit dispatch) are resolved
  - what RustDoor doesn't do in-process is the actual remote command list (`curl`, `chflags hidden npm`, `zsh -c zip -r ...`, `mdfind -name .pem`, reverse-shell `back.sh`/`sh.sh`); per the Unit42 article those run later via the cron and `~/.zshrc` persistence we now write, not from the originally executed binary
  - next compatibility work for this family should focus on simulating the second-stage execution paths (e.g. driving a fake shell login that re-reads `~/.zshrc`, or executing the cron entry) rather than coaxing more behavior out of the first-stage binary, which is now reaching `_exit(0)` cleanly

## Corpus hygiene

- New samples should be added with a short status note here.
