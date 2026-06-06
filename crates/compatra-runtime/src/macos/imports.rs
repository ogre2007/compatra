macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::macos::loader::command::{DysymtabCommand, LoadCommand, Section64, SymtabCommand};
use crate::macos::loader::MachOLoader;
use crate::macos::os::{Emulator, MacOsError};
use crate::macos::ArchType;
use crate::UnicornEmulator;

#[derive(Clone, Debug)]
pub enum ImportReturnPolicy {
    Zero,
    One,
    NegOne,
    Fd3,
    IntArg0,
    StaticPtr(u64),
    Strlen,
    StrCmp,
    StrNCmp,
    StrChr,
    StrRChr,
    StrStr,
    MemCpy,
    MemSet,
    PutChar,
    ZeroMemoryArg1(usize),
    ZeroMemoryArg0(usize),
    PipePair,
    SyntheticFd,
    Fcntl,
    Kevent,
    Fork,
    WaitPidStub,
    SysConfStub(u64),
    WriteCStringToArg0(&'static [u8]),
    SleepUsecArg0,
    MachAbsoluteTime,
    ClockGetTime,
    MachTimebaseInfo,
    SysctlByName(u64),
    PthreadCreate,
    PthreadSelf,
    PthreadCondWait,
    PthreadCondTimedWait,
    PthreadCondSignal,
    PthreadKeyCreate,
    PthreadSetSpecific,
    PthreadGetSpecific,
    MbrTowc,
    MbrLen,
    LogCString0Zero,
    LogCString0One,
    LogCString1Zero,
    FtsOpen(u64),
    FtsChildren,
    FtsRead,
    FtsClose,
    FtsSet,
    GetEnv(u64),
    Exit,
}

#[derive(Clone, Debug)]
pub struct ImportThunk {
    pub symbol: String,
    pub policy: ImportReturnPolicy,
}

#[derive(Debug)]
pub struct SyntheticImportLayout {
    pub zero_stub_addr: u64,
    pub syscall_stubs: HashMap<u64, u64>,
    pub symbol_stubs: HashMap<String, u64>,
    pub data_symbols: HashMap<String, u64>,
}

#[derive(Clone, Debug)]
struct FakeFtsSession {
    handle_addr: u64,
    errno_addr: u64,
    entry_addr: u64,
    stat_addr: u64,
    path_addr: u64,
    child_base_addr: u64,
    root_path: String,
    child_names: Vec<String>,
    current_path: String,
    yielded_root: bool,
    child_index: usize,
    skipped_path: Option<String>,
}

#[derive(Debug, Default)]
struct FakeFtsState {
    next_slot: u64,
    sessions: HashMap<u64, FakeFtsSession>,
}

#[derive(Debug, Default)]
struct ImportIoState {
    stdout_buffer: Vec<u8>,
}

#[derive(Debug, Default)]
struct ImportThreadState {
    next_key: u64,
    next_thread_id: u64,
    next_process_id: u64,
    next_synthetic_fd: u64,
    current_thread_id: u64,
    synthetic_time_ns: u64,
    last_resume_pc: u64,
    last_resume_streak: u32,
    defer_same_resume: bool,
    last_cond_wait_key: (u64, u64),
    last_cond_wait_streak: u32,
    next_stack_base: u64,
    pending_arm64_threads: VecDeque<PendingArm64Thread>,
    active_arm64_thread: Option<ActiveArm64Thread>,
    synthetic_processes: HashMap<u64, SyntheticProcess>,
    synthetic_fds: HashSet<u64>,
    synthetic_fd_kinds: HashMap<u64, SyntheticFdKind>,
    pipe_keys: HashMap<u64, u64>,
    pipes: HashMap<u64, SyntheticPipeState>,
    fd_flags: HashMap<u64, u64>,
    kqueues: HashMap<u64, SyntheticKqueue>,
    tls_values: HashMap<u64, u64>,
}

#[derive(Debug, Default)]
struct SyntheticSignalBus {
    pending: VecDeque<SyntheticFdSignal>,
}

#[derive(Clone, Debug)]
struct SyntheticProcess {
    pid: u64,
    parent_pid: u64,
    exit_status: i32,
    running: bool,
    reaped: bool,
}

#[derive(Clone, Debug)]
enum SyntheticFdKind {
    PipeRead { peer: u64 },
    PipeWrite { peer: u64 },
    Kqueue,
}

#[derive(Clone, Debug)]
struct SyntheticPipeState {
    read_fd: u64,
    write_fd: u64,
    buffered_bytes: u64,
    read_closed: bool,
    write_closed: bool,
}

#[derive(Clone, Debug)]
struct SyntheticKeventRegistration {
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: i64,
    udata: u64,
    enabled: bool,
}

#[derive(Clone, Debug)]
struct SyntheticKeventEvent {
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: i64,
    udata: u64,
}

#[derive(Clone, Debug)]
enum SyntheticFdSignal {
    Write { fd: u64, count: u64 },
    Read { fd: u64, count: u64 },
    Close { fd: u64 },
}

#[derive(Clone, Debug, Default)]
struct SyntheticKqueue {
    registrations: HashMap<(u64, i16), SyntheticKeventRegistration>,
    pending: VecDeque<SyntheticKeventEvent>,
}

#[derive(Clone, Debug)]
struct PendingArm64Thread {
    thread_id: u64,
    entry: u64,
    arg: u64,
    stack_top: u64,
    resume: Option<Arm64SavedContext>,
}

#[derive(Clone, Debug)]
struct ActiveArm64Thread {
    thread_id: u64,
    parent_thread_id: u64,
    parent: Arm64SavedContext,
}

#[derive(Clone, Debug)]
struct Arm64SavedContext {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

const SYNTHETIC_IMPORT_REGION_SIZE: u64 = 0x40000;
const FTS_SESSION_STRIDE: u64 = 0x20000;
const MAX_GUEST_THREADS: u64 = 6;
const DARWIN_EAGAIN: u64 = 35;
const DARWIN_ETIMEDOUT: u64 = 60;
const ARM64_RESUME_STREAK_LIMIT: u32 = 32;
const ARM64_COND_WAIT_STREAK_LIMIT: u32 = 64;
const ARM64_HELPER_EXIT_STUB: u64 = 0x3200_0000;
const ARM64_HELPER_STACK_BASE: u64 = 0x3300_0000;
const ARM64_HELPER_STACK_SIZE: u64 = 0x20_000;
const SYNTHETIC_PARENT_PID: u64 = 1;
const SYNTHETIC_FD_BASE: u64 = 0x1_0000;
const KEVENT64_SIZE: u64 = 32;
const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
const EV_EOF: u16 = 0x8000;
const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;

fn trim_name(name: &[u8; 16]) -> String {
    String::from_utf8_lossy(&name[..name.iter().position(|&c| c == 0).unwrap_or(16)]).to_string()
}

fn synthetic_signal_bus() -> &'static Mutex<SyntheticSignalBus> {
    static BUS: OnceLock<Mutex<SyntheticSignalBus>> = OnceLock::new();
    BUS.get_or_init(|| Mutex::new(SyntheticSignalBus::default()))
}

fn push_synthetic_fd_signal(signal: SyntheticFdSignal) {
    let mut bus = synthetic_signal_bus().lock().unwrap();
    bus.pending.push_back(signal);
}

pub fn notify_synthetic_fd_write(fd: u64, count: u64) {
    push_synthetic_fd_signal(SyntheticFdSignal::Write { fd, count });
}

pub fn notify_synthetic_fd_read(fd: u64, count: u64) {
    push_synthetic_fd_signal(SyntheticFdSignal::Read { fd, count });
}

pub fn notify_synthetic_fd_close(fd: u64) {
    push_synthetic_fd_signal(SyntheticFdSignal::Close { fd });
}

fn flush_program_stdout(io_state: &mut ImportIoState) {
    if io_state.stdout_buffer.is_empty() {
        return;
    }
    let rendered = String::from_utf8_lossy(&io_state.stdout_buffer);
    println!("[PROGRAM][stdout] {}", rendered);
    io_state.stdout_buffer.clear();
}

fn record_program_byte(io_state: &mut ImportIoState, byte: u8) {
    if byte == b'\r' {
        return;
    }
    if byte == b'\n' {
        flush_program_stdout(io_state);
        return;
    }
    io_state.stdout_buffer.push(byte);
    if io_state.stdout_buffer.len() >= 240 {
        flush_program_stdout(io_state);
    }
}

fn should_emit_import_trace(symbol: &str, policy: &ImportReturnPolicy) -> bool {
    match policy {
        ImportReturnPolicy::PutChar | ImportReturnPolicy::MbrTowc | ImportReturnPolicy::MbrLen => {
            false
        }
        _ => !matches!(symbol, "putchar" | "mbrtowc" | "mbrlen" | "mblen"),
    }
}

pub fn normalize_import_symbol(mut s: String) -> String {
    if let Some(stripped) = s.strip_prefix('_') {
        s = stripped.to_string();
    }
    if let Some((base, _)) = s.split_once('$') {
        return base.to_string();
    }
    s
}

fn get_symtab_cmd(loader: &MachOLoader) -> Option<&SymtabCommand> {
    loader.binary.commands.iter().find_map(|cmd| {
        if let LoadCommand::Symtab(sym) = cmd {
            Some(sym)
        } else {
            None
        }
    })
}

fn get_dysymtab_cmd(loader: &MachOLoader) -> Option<&DysymtabCommand> {
    loader.binary.commands.iter().find_map(|cmd| {
        if let LoadCommand::Dysymtab(sym) = cmd {
            Some(sym)
        } else {
            None
        }
    })
}

fn symbol_name_by_index(loader: &MachOLoader, sym_index: u32) -> Option<String> {
    let symtab = get_symtab_cmd(loader)?;
    if sym_index >= symtab.nsyms {
        return None;
    }
    let entry_size = if loader.binary.is_64_bit() {
        16usize
    } else {
        12usize
    };
    let base = symtab.symoff as usize + sym_index as usize * entry_size;
    if base + entry_size > loader.binary.data.len() {
        return None;
    }

    let strx = u32::from_le_bytes(loader.binary.data[base..base + 4].try_into().ok()?);
    if strx == 0 || strx >= symtab.strsize {
        return None;
    }
    let str_off = symtab.stroff as usize + strx as usize;
    if str_off >= loader.binary.data.len() {
        return None;
    }
    let end = loader.binary.data[str_off..]
        .iter()
        .position(|&c| c == 0)
        .map(|n| str_off + n)
        .unwrap_or(loader.binary.data.len());
    if end <= str_off {
        return None;
    }
    Some(String::from_utf8_lossy(&loader.binary.data[str_off..end]).to_string())
}

fn section64_indirect_symbol_name(
    loader: &MachOLoader,
    section: &Section64,
    slot: u64,
) -> Option<String> {
    let dysymtab = get_dysymtab_cmd(loader)?;
    let indirect_index = section.reserved1 as u64 + slot;
    if indirect_index >= dysymtab.nindirectsyms as u64 {
        return None;
    }
    let off = dysymtab.indirectsymoff as usize + indirect_index as usize * 4;
    if off + 4 > loader.binary.data.len() {
        return None;
    }
    let sym_index = u32::from_le_bytes(loader.binary.data[off..off + 4].try_into().ok()?);

    const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
    const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
    if (sym_index & INDIRECT_SYMBOL_LOCAL) != 0 || (sym_index & INDIRECT_SYMBOL_ABS) != 0 {
        return None;
    }
    symbol_name_by_index(loader, sym_index)
}

pub fn initialize_fake_x64_import_data(
    emulator: &mut dyn Emulator,
    fake_data_addr: u64,
) -> Result<HashMap<String, u64>, MacOsError> {
    emulator.write_memory(fake_data_addr, &[0u8; 0x400])?;
    emulator.write_memory(fake_data_addr + 0x50, &1u32.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x58, &0x1234_5678_u64.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x60, &fake_data_addr.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x80, b"QILING_FAKE_HANDLE\0")?;
    emulator.write_memory(fake_data_addr + 0xA0, b"QILING_FAKE_ENV\0")?;
    emulator.write_memory(fake_data_addr + 0x100, b" \t\n\"'><=;|&(:\0")?;
    emulator.write_memory(fake_data_addr + 0x120, b" \t\n\"'><=;|&(:/\0")?;
    emulator.write_memory(fake_data_addr + 0x140, &0u32.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x148, &0u32.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x150, &0u32.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x158, &0u32.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x160, &0u64.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x168, &0u64.to_le_bytes())?;
    emulator.write_memory(fake_data_addr + 0x170, &0u64.to_le_bytes())?;
    emulator.write_memory(
        fake_data_addr + 0x178,
        &(fake_data_addr + 0x100).to_le_bytes(),
    )?;
    emulator.write_memory(
        fake_data_addr + 0x180,
        &(fake_data_addr + 0x120).to_le_bytes(),
    )?;
    emulator.write_memory(fake_data_addr + 0x190, b"compatra-host\0")?;
    emulator.write_memory(fake_data_addr + 0x1b0, b"/dev/tty\0")?;
    emulator.write_memory(fake_data_addr + 0x1d0, b"dlerror: synthetic loader\0")?;
    emulator.write_memory(fake_data_addr + 0x200, b"/bin:/usr/bin\0")?;
    emulator.write_memory(fake_data_addr + 0x220, b"\0")?;

    let mut by_data_symbol = HashMap::new();

    let mut insert_symbol = |name: &str, addr: u64| {
        by_data_symbol.insert(name.to_string(), addr);
        by_data_symbol.insert(normalize_import_symbol(name.to_string()), addr);
    };

    insert_symbol("__DefaultRuneLocale", fake_data_addr);
    insert_symbol("__stack_chk_guard", fake_data_addr + 0x20);
    insert_symbol("__stderrp", fake_data_addr + 0x40);
    insert_symbol("__stdoutp", fake_data_addr + 0x48);
    insert_symbol("__stdinp", fake_data_addr + 0x60);
    insert_symbol("__mb_cur_max", fake_data_addr + 0x50);
    insert_symbol("optind", fake_data_addr + 0x50);
    insert_symbol("tilde_additional_suffixes", fake_data_addr + 0x160);
    insert_symbol("tilde_expansion_preexpansion_hook", fake_data_addr + 0x168);
    insert_symbol("tilde_additional_prefixes", fake_data_addr + 0x170);
    insert_symbol("rl_basic_word_break_characters", fake_data_addr + 0x178);
    insert_symbol("history_comment_char", fake_data_addr + 0x140);
    insert_symbol("history_subst_char", fake_data_addr + 0x148);
    insert_symbol("history_expansion_char", fake_data_addr + 0x150);
    insert_symbol("history_write_timestamps", fake_data_addr + 0x158);
    insert_symbol("rl_completer_word_break_characters", fake_data_addr + 0x180);
    insert_symbol("hostname", fake_data_addr + 0x190);
    insert_symbol("ttyname", fake_data_addr + 0x1b0);
    insert_symbol("dlerror", fake_data_addr + 0x1d0);
    insert_symbol("confstr_value", fake_data_addr + 0x200);
    insert_symbol("empty_string", fake_data_addr + 0x220);

    Ok(by_data_symbol)
}

pub fn default_x64_import_policies(fake_data_addr: u64) -> Vec<(String, ImportReturnPolicy)> {
    let mut policies = Vec::new();

    for symbol in [
        "__error",
        "malloc",
        "realloc",
        "strdup",
        "strerror",
        "localtime",
        "setlocale",
        "nl_langinfo",
        "tgetstr",
        "tgoto",
        "mbr_uuid_to_string",
        "memchr",
        "__stdoutp",
        "__stderrp",
        "__stdinp",
        "__mb_cur_max",
    ] {
        policies.push((
            symbol.to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr),
        ));
    }

    policies.extend([
        ("strlen".to_string(), ImportReturnPolicy::Strlen),
        ("putchar".to_string(), ImportReturnPolicy::PutChar),
        ("getopt".to_string(), ImportReturnPolicy::NegOne),
        ("isatty".to_string(), ImportReturnPolicy::Zero),
        ("ioctl".to_string(), ImportReturnPolicy::NegOne),
        ("dup".to_string(), ImportReturnPolicy::IntArg0),
        ("dup2".to_string(), ImportReturnPolicy::IntArg0),
        ("fcntl".to_string(), ImportReturnPolicy::Fcntl),
        (
            "getdtablesize".to_string(),
            ImportReturnPolicy::SysConfStub(256),
        ),
        ("sysconf".to_string(), ImportReturnPolicy::SysConfStub(256)),
        ("getppid".to_string(), ImportReturnPolicy::One),
        ("getpgrp".to_string(), ImportReturnPolicy::One),
        ("setpgid".to_string(), ImportReturnPolicy::Zero),
        ("killpg".to_string(), ImportReturnPolicy::Zero),
        ("kill".to_string(), ImportReturnPolicy::Zero),
        ("sleep".to_string(), ImportReturnPolicy::Zero),
        ("alarm".to_string(), ImportReturnPolicy::Zero),
        ("umask".to_string(), ImportReturnPolicy::Zero),
        ("setuid".to_string(), ImportReturnPolicy::Zero),
        ("setgid".to_string(), ImportReturnPolicy::Zero),
        ("unlink".to_string(), ImportReturnPolicy::Zero),
        ("mkfifo".to_string(), ImportReturnPolicy::Zero),
        ("chdir".to_string(), ImportReturnPolicy::Zero),
        (
            "ttyname".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x1b0),
        ),
        (
            "dlerror".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x1d0),
        ),
        ("fputs".to_string(), ImportReturnPolicy::LogCString0One),
        ("fprintf".to_string(), ImportReturnPolicy::LogCString1Zero),
        ("printf".to_string(), ImportReturnPolicy::LogCString0Zero),
        ("err".to_string(), ImportReturnPolicy::LogCString1Zero),
        ("warn".to_string(), ImportReturnPolicy::LogCString0Zero),
        ("warnx".to_string(), ImportReturnPolicy::LogCString0Zero),
        (
            "fopen".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        (
            "fdopen".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        (
            "freopen".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        (
            "popen".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        ("fclose".to_string(), ImportReturnPolicy::Zero),
        ("fflush".to_string(), ImportReturnPolicy::Zero),
        ("ferror".to_string(), ImportReturnPolicy::Zero),
        ("clearerr".to_string(), ImportReturnPolicy::Zero),
        ("setvbuf".to_string(), ImportReturnPolicy::Zero),
        ("fileno".to_string(), ImportReturnPolicy::One),
        ("fread".to_string(), ImportReturnPolicy::Zero),
        ("fwrite".to_string(), ImportReturnPolicy::One),
        ("fputc".to_string(), ImportReturnPolicy::PutChar),
        ("putc".to_string(), ImportReturnPolicy::PutChar),
        (
            "getenv".to_string(),
            ImportReturnPolicy::GetEnv(fake_data_addr),
        ),
        (
            "fts_open".to_string(),
            ImportReturnPolicy::FtsOpen(fake_data_addr + 0x400),
        ),
        ("fts_close".to_string(), ImportReturnPolicy::FtsClose),
        ("fts_read".to_string(), ImportReturnPolicy::FtsRead),
        ("fts_children".to_string(), ImportReturnPolicy::FtsChildren),
        ("fts_set".to_string(), ImportReturnPolicy::FtsSet),
        ("tgetent".to_string(), ImportReturnPolicy::LogCString1Zero),
        ("tputs".to_string(), ImportReturnPolicy::LogCString0Zero),
        ("mbrtowc".to_string(), ImportReturnPolicy::MbrTowc),
        ("mbrlen".to_string(), ImportReturnPolicy::MbrLen),
        ("mblen".to_string(), ImportReturnPolicy::MbrLen),
        ("wcwidth".to_string(), ImportReturnPolicy::One),
        ("atoi".to_string(), ImportReturnPolicy::Zero),
        ("humanize_number".to_string(), ImportReturnPolicy::NegOne),
        (
            "time".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x58),
        ),
        ("compat_mode".to_string(), ImportReturnPolicy::Zero),
        ("__tolower".to_string(), ImportReturnPolicy::IntArg0),
        ("__maskrune".to_string(), ImportReturnPolicy::Zero),
        (
            "strmode".to_string(),
            ImportReturnPolicy::WriteCStringToArg0(b"----------\0"),
        ),
        ("strcmp".to_string(), ImportReturnPolicy::StrCmp),
        ("strncmp".to_string(), ImportReturnPolicy::StrNCmp),
        ("strchr".to_string(), ImportReturnPolicy::StrChr),
        ("strrchr".to_string(), ImportReturnPolicy::StrRChr),
        ("strstr".to_string(), ImportReturnPolicy::StrStr),
        ("strcpy".to_string(), ImportReturnPolicy::IntArg0),
        ("strncpy".to_string(), ImportReturnPolicy::IntArg0),
        ("strcat".to_string(), ImportReturnPolicy::IntArg0),
        ("strncat".to_string(), ImportReturnPolicy::IntArg0),
        ("memcpy".to_string(), ImportReturnPolicy::MemCpy),
        ("memmove".to_string(), ImportReturnPolicy::MemCpy),
        ("memset".to_string(), ImportReturnPolicy::MemSet),
        ("stat".to_string(), ImportReturnPolicy::ZeroMemoryArg1(0x80)),
        (
            "lstat".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(0x80),
        ),
        (
            "fstat".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(0x80),
        ),
        (
            "tcgetattr".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(0x40),
        ),
        ("tcsetattr".to_string(), ImportReturnPolicy::Zero),
        ("tcgetpgrp".to_string(), ImportReturnPolicy::One),
        ("tcsetpgrp".to_string(), ImportReturnPolicy::Zero),
        (
            "gettimeofday".to_string(),
            ImportReturnPolicy::ZeroMemoryArg0(0x10),
        ),
        (
            "getrusage".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(0x80),
        ),
        (
            "getrlimit".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(0x10),
        ),
        ("setrlimit".to_string(), ImportReturnPolicy::Zero),
        ("pipe".to_string(), ImportReturnPolicy::PipePair),
        ("waitpid".to_string(), ImportReturnPolicy::WaitPidStub),
        ("wait4".to_string(), ImportReturnPolicy::WaitPidStub),
        (
            "sigemptyset".to_string(),
            ImportReturnPolicy::ZeroMemoryArg0(8),
        ),
        ("sigaddset".to_string(), ImportReturnPolicy::Zero),
        ("sigaction".to_string(), ImportReturnPolicy::Zero),
        ("sigprocmask".to_string(), ImportReturnPolicy::Zero),
        ("sigaltstack".to_string(), ImportReturnPolicy::Zero),
        ("sigsetjmp".to_string(), ImportReturnPolicy::Zero),
        ("siglongjmp".to_string(), ImportReturnPolicy::Zero),
        (
            "confstr".to_string(),
            ImportReturnPolicy::WriteCStringToArg0(b"/bin:/usr/bin\0"),
        ),
        (
            "gethostname".to_string(),
            ImportReturnPolicy::WriteCStringToArg0(b"compatra-host\0"),
        ),
        (
            "clock_gettime".to_string(),
            ImportReturnPolicy::ClockGetTime,
        ),
        (
            "mach_absolute_time".to_string(),
            ImportReturnPolicy::MachAbsoluteTime,
        ),
        (
            "mach_timebase_info".to_string(),
            ImportReturnPolicy::MachTimebaseInfo,
        ),
        (
            "sysctlbyname".to_string(),
            ImportReturnPolicy::SysctlByName(fake_data_addr),
        ),
        ("pthread_self".to_string(), ImportReturnPolicy::PthreadSelf),
        ("pthread_sigmask".to_string(), ImportReturnPolicy::Zero),
        ("pthread_attr_init".to_string(), ImportReturnPolicy::Zero),
        (
            "pthread_attr_getstacksize".to_string(),
            ImportReturnPolicy::ZeroMemoryArg1(8),
        ),
        (
            "pthread_attr_setdetachstate".to_string(),
            ImportReturnPolicy::Zero,
        ),
        (
            "pthread_create".to_string(),
            ImportReturnPolicy::PthreadCreate,
        ),
        ("pthread_mutex_init".to_string(), ImportReturnPolicy::Zero),
        ("pthread_mutex_lock".to_string(), ImportReturnPolicy::Zero),
        ("pthread_mutex_unlock".to_string(), ImportReturnPolicy::Zero),
        ("pthread_cond_init".to_string(), ImportReturnPolicy::Zero),
        (
            "pthread_cond_wait".to_string(),
            ImportReturnPolicy::PthreadCondWait,
        ),
        (
            "pthread_cond_timedwait_relative_np".to_string(),
            ImportReturnPolicy::PthreadCondTimedWait,
        ),
        (
            "pthread_cond_signal".to_string(),
            ImportReturnPolicy::PthreadCondSignal,
        ),
        ("pthread_kill".to_string(), ImportReturnPolicy::Zero),
        (
            "pthread_key_create".to_string(),
            ImportReturnPolicy::PthreadKeyCreate,
        ),
        (
            "pthread_setspecific".to_string(),
            ImportReturnPolicy::PthreadSetSpecific,
        ),
        (
            "pthread_getspecific".to_string(),
            ImportReturnPolicy::PthreadGetSpecific,
        ),
        ("usleep".to_string(), ImportReturnPolicy::SleepUsecArg0),
        ("madvise".to_string(), ImportReturnPolicy::Zero),
        ("mlock".to_string(), ImportReturnPolicy::Zero),
        ("kqueue".to_string(), ImportReturnPolicy::SyntheticFd),
        ("kevent".to_string(), ImportReturnPolicy::Kevent),
        ("setsid".to_string(), ImportReturnPolicy::One),
        ("fork".to_string(), ImportReturnPolicy::Fork),
        ("execve".to_string(), ImportReturnPolicy::NegOne),
        (
            "getcwd".to_string(),
            ImportReturnPolicy::WriteCStringToArg0(b".\0"),
        ),
        ("closedir".to_string(), ImportReturnPolicy::Zero),
        ("chmod".to_string(), ImportReturnPolicy::Zero),
        ("chroot".to_string(), ImportReturnPolicy::NegOne),
        ("ptrace".to_string(), ImportReturnPolicy::NegOne),
        ("faccessat".to_string(), ImportReturnPolicy::Zero),
        ("issetugid".to_string(), ImportReturnPolicy::Zero),
        ("setgroups".to_string(), ImportReturnPolicy::Zero),
        ("raise".to_string(), ImportReturnPolicy::Zero),
        ("notify_is_valid_token".to_string(), ImportReturnPolicy::One),
        (
            "xpc_date_create_from_current".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        (
            "dlopen".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x80),
        ),
        ("dlsym".to_string(), ImportReturnPolicy::Zero),
        ("dlclose".to_string(), ImportReturnPolicy::Zero),
        (
            "readline".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x220),
        ),
        (
            "tilde_expand".to_string(),
            ImportReturnPolicy::StaticPtr(fake_data_addr + 0x220),
        ),
        ("using_history".to_string(), ImportReturnPolicy::Zero),
        ("previous_history".to_string(), ImportReturnPolicy::Zero),
        ("add_history".to_string(), ImportReturnPolicy::Zero),
        (
            "replace_history_entry".to_string(),
            ImportReturnPolicy::Zero,
        ),
        ("free_history_entry".to_string(), ImportReturnPolicy::Zero),
        ("remove_history".to_string(), ImportReturnPolicy::Zero),
        ("history_expand".to_string(), ImportReturnPolicy::Zero),
        (
            "history_truncate_file".to_string(),
            ImportReturnPolicy::Zero,
        ),
        ("unstifle_history".to_string(), ImportReturnPolicy::Zero),
        ("stifle_history".to_string(), ImportReturnPolicy::Zero),
        ("where_history".to_string(), ImportReturnPolicy::Zero),
        ("read_history_range".to_string(), ImportReturnPolicy::Zero),
        ("history_get_time".to_string(), ImportReturnPolicy::Zero),
        ("rl_complete_internal".to_string(), ImportReturnPolicy::Zero),
        ("rl_reset_terminal".to_string(), ImportReturnPolicy::Zero),
        ("rl_list_funmap_names".to_string(), ImportReturnPolicy::Zero),
        ("rl_function_dumper".to_string(), ImportReturnPolicy::Zero),
        ("rl_macro_dumper".to_string(), ImportReturnPolicy::Zero),
        ("rl_variable_dumper".to_string(), ImportReturnPolicy::Zero),
        ("rl_read_init_file".to_string(), ImportReturnPolicy::Zero),
        ("rl_named_function".to_string(), ImportReturnPolicy::Zero),
        ("rl_invoking_keyseqs".to_string(), ImportReturnPolicy::Zero),
        (
            "rl_unbind_function_in_map".to_string(),
            ImportReturnPolicy::Zero,
        ),
        ("rl_parse_and_bind".to_string(), ImportReturnPolicy::Zero),
        ("rl_set_key".to_string(), ImportReturnPolicy::Zero),
        ("puts".to_string(), ImportReturnPolicy::LogCString0Zero),
        ("sprintf".to_string(), ImportReturnPolicy::Zero),
        ("snprintf".to_string(), ImportReturnPolicy::Zero),
        ("vsnprintf".to_string(), ImportReturnPolicy::Zero),
        ("vfprintf".to_string(), ImportReturnPolicy::LogCString1Zero),
        ("abort".to_string(), ImportReturnPolicy::Exit),
        ("free".to_string(), ImportReturnPolicy::Zero),
        ("getgrgid".to_string(), ImportReturnPolicy::Zero),
        ("getpwuid".to_string(), ImportReturnPolicy::Zero),
        ("group_from_gid".to_string(), ImportReturnPolicy::Zero),
        ("user_from_uid".to_string(), ImportReturnPolicy::Zero),
        ("fflagstostr".to_string(), ImportReturnPolicy::Zero),
        ("getbsize".to_string(), ImportReturnPolicy::Zero),
        ("exit".to_string(), ImportReturnPolicy::Exit),
    ]);

    policies
}

pub fn read_c_string(emu: &dyn Emulator, addr: u64, limit: usize) -> String {
    if addr == 0 {
        return "<null>".to_string();
    }

    let mut out = Vec::new();
    for i in 0..limit {
        let Ok(byte) = emu.read_memory(addr + i as u64, 1) else {
            break;
        };
        if byte.is_empty() || byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }

    String::from_utf8_lossy(&out).to_string()
}

fn read_c_string_bytes(emu: &dyn Emulator, addr: u64, limit: usize) -> Vec<u8> {
    if addr == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    for i in 0..limit {
        let Ok(byte) = emu.read_memory(addr + i as u64, 1) else {
            break;
        };
        if byte.is_empty() || byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }

    out
}

fn compare_c_strings(emu: &dyn Emulator, lhs: u64, rhs: u64, limit: Option<usize>) -> u64 {
    let max_len = limit.unwrap_or(0x1000);
    let lhs_bytes = read_c_string_bytes(emu, lhs, max_len);
    let rhs_bytes = read_c_string_bytes(emu, rhs, max_len);
    let lhs_slice = if let Some(n) = limit {
        &lhs_bytes[..lhs_bytes.len().min(n)]
    } else {
        lhs_bytes.as_slice()
    };
    let rhs_slice = if let Some(n) = limit {
        &rhs_bytes[..rhs_bytes.len().min(n)]
    } else {
        rhs_bytes.as_slice()
    };

    use std::cmp::Ordering;
    match lhs_slice.cmp(rhs_slice) {
        Ordering::Less => u64::MAX,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn find_char_ptr(emu: &dyn Emulator, haystack: u64, needle: u8, reverse: bool) -> u64 {
    let bytes = read_c_string_bytes(emu, haystack, 0x1000);
    let found = if reverse {
        bytes.iter().rposition(|&b| b == needle)
    } else {
        bytes.iter().position(|&b| b == needle)
    };
    found.map(|idx| haystack + idx as u64).unwrap_or(0)
}

fn find_substr_ptr(emu: &dyn Emulator, haystack: u64, needle: u64) -> u64 {
    let haystack_bytes = read_c_string_bytes(emu, haystack, 0x1000);
    let needle_bytes = read_c_string_bytes(emu, needle, 0x1000);
    if needle_bytes.is_empty() {
        return haystack;
    }

    haystack_bytes
        .windows(needle_bytes.len())
        .position(|window| window == needle_bytes.as_slice())
        .map(|idx| haystack + idx as u64)
        .unwrap_or(0)
}

fn emulate_memcpy(emu: &mut UnicornEmulator, dst: u64, src: u64, len: u64) -> u64 {
    if dst == 0 || src == 0 || len == 0 {
        return dst;
    }
    if let Ok(bytes) = emu.read_memory(src, len as usize) {
        let _ = emu.write_memory(dst, &bytes);
    }
    dst
}

fn emulate_memset(emu: &mut UnicornEmulator, dst: u64, value: u64, len: u64) -> u64 {
    if dst == 0 || len == 0 {
        return dst;
    }
    let buf = vec![(value & 0xff) as u8; len as usize];
    let _ = emu.write_memory(dst, &buf);
    dst
}

fn zero_memory(emu: &mut UnicornEmulator, addr: u64, len: usize) {
    if addr == 0 || len == 0 {
        return;
    }
    let _ = emu.write_memory(addr, &vec![0u8; len]);
}

fn read_pointer_sized(emu: &dyn Emulator, addr: u64, width: usize) -> u64 {
    match width {
        4 => emu
            .read_memory(addr, 4)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
            .unwrap_or(0),
        8 => emu
            .read_memory(addr, 8)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0),
        _ => 0,
    }
}

fn write_u16(emu: &mut UnicornEmulator, addr: u64, value: u16) {
    let _ = emu.write_memory(addr, &value.to_le_bytes());
}

fn write_i16(emu: &mut UnicornEmulator, addr: u64, value: i16) {
    let _ = emu.write_memory(addr, &value.to_le_bytes());
}

fn write_i64(emu: &mut UnicornEmulator, addr: u64, value: i64) {
    let _ = emu.write_memory(addr, &value.to_le_bytes());
}

fn write_u32(emu: &mut UnicornEmulator, addr: u64, value: u32) {
    let _ = emu.write_memory(addr, &value.to_le_bytes());
}

fn write_u64(emu: &mut UnicornEmulator, addr: u64, value: u64) {
    let _ = emu.write_memory(addr, &value.to_le_bytes());
}

fn read_u16(emu: &dyn Emulator, addr: u64) -> Option<u16> {
    let data = emu.read_memory(addr, 2).ok()?;
    let bytes: [u8; 2] = data.as_slice().try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_i16(emu: &dyn Emulator, addr: u64) -> Option<i16> {
    let data = emu.read_memory(addr, 2).ok()?;
    let bytes: [u8; 2] = data.as_slice().try_into().ok()?;
    Some(i16::from_le_bytes(bytes))
}

fn read_u32_guest(emu: &dyn Emulator, addr: u64) -> Option<u32> {
    let data = emu.read_memory(addr, 4).ok()?;
    let bytes: [u8; 4] = data.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i64(emu: &dyn Emulator, addr: u64) -> Option<i64> {
    let data = emu.read_memory(addr, 8).ok()?;
    let bytes: [u8; 8] = data.as_slice().try_into().ok()?;
    Some(i64::from_le_bytes(bytes))
}

fn ascii_multibyte_step(emu: &mut UnicornEmulator, dst_wchar_addr: u64, src_addr: u64) -> u64 {
    if src_addr == 0 {
        return 0;
    }
    let byte = emu
        .read_memory(src_addr, 1)
        .ok()
        .and_then(|bytes| bytes.first().copied())
        .unwrap_or(0);
    if dst_wchar_addr != 0 {
        write_u32(emu, dst_wchar_addr, byte as u32);
    }
    if byte == 0 {
        0
    } else {
        1
    }
}

fn ascii_multibyte_len(emu: &mut UnicornEmulator, src_addr: u64) -> u64 {
    if src_addr == 0 {
        return 0;
    }
    let byte = emu
        .read_memory(src_addr, 1)
        .ok()
        .and_then(|bytes| bytes.first().copied())
        .unwrap_or(0);
    if byte == 0 {
        0
    } else {
        1
    }
}

fn normalize_fts_input_path(path: String) -> String {
    if path.trim().is_empty() {
        ".".to_string()
    } else {
        path
    }
}

fn emulate_getenv(emu: &mut UnicornEmulator, name_ptr: u64, fake_data_addr: u64) -> u64 {
    let name = read_c_string(emu, name_ptr, 128);
    match name.as_str() {
        "PATH" => fake_data_addr + 0x200,
        "TERM" => fake_data_addr + 0x220,
        "TERMINFO" | "LS_COLORS" | "CLICOLOR" | "CLICOLOR_FORCE" | "COLORTERM" => 0,
        "<null>" | "" => 0,
        _ => 0,
    }
}

fn synthetic_clock_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn ensure_synthetic_time(state: &mut ImportThreadState) -> u64 {
    if state.synthetic_time_ns == 0 {
        state.synthetic_time_ns = synthetic_clock_seed();
    }
    state.synthetic_time_ns
}

fn advance_synthetic_time_ns(state: &mut ImportThreadState, delta_ns: u64) -> u64 {
    let current = ensure_synthetic_time(state);
    let next = current.saturating_add(delta_ns.max(1));
    state.synthetic_time_ns = next;
    next
}

fn synthetic_time_to_timespec_parts(time_ns: u64) -> (u64, u64) {
    (time_ns / 1_000_000_000, time_ns % 1_000_000_000)
}

fn write_synthetic_timespec(emu: &mut UnicornEmulator, addr: u64, time_ns: u64) {
    if addr == 0 {
        return;
    }
    let (secs, nanos) = synthetic_time_to_timespec_parts(time_ns);
    write_u64(emu, addr, secs);
    write_u64(emu, addr + 8, nanos);
}

fn read_timespec_duration_ns(emu: &dyn Emulator, addr: u64, width: usize) -> u64 {
    if addr == 0 {
        return 0;
    }
    let secs = read_pointer_sized(emu, addr, width);
    let nanos = read_pointer_sized(emu, addr + width as u64, width);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

fn write_mach_timebase_info(emu: &mut UnicornEmulator, addr: u64) {
    if addr == 0 {
        return;
    }
    write_u32(emu, addr, 1);
    write_u32(emu, addr + 4, 1);
}

fn emulate_sysctlbyname(
    emu: &mut UnicornEmulator,
    name_ptr: u64,
    oldp: u64,
    oldlenp: u64,
    fake_data_addr: u64,
) -> u64 {
    let name = read_c_string(emu, name_ptr, 128);
    if matches!(name.as_str(), "hw.pagesize" | "hw.page_size") {
        if oldlenp != 0 {
            write_u64(emu, oldlenp, 8);
        }
        if oldp != 0 {
            let _ = emu.write_memory(oldp, &0x4000u64.to_le_bytes());
        }
    } else if name.starts_with("hw.optional.") {
        // Go probes these as integer feature flags. Returning the fallback
        // string payload here makes the first byte non-zero, which incorrectly
        // enables unsupported ARMv8.1/LSE paths and traps the runtime in
        // atomics it cannot execute under our current Unicorn setup.
        if oldlenp != 0 {
            write_u64(emu, oldlenp, 4);
        }
        if oldp != 0 {
            let _ = emu.write_memory(oldp, &0u32.to_le_bytes());
        }
    } else {
        let payload = b"compatra\0";
        if oldlenp != 0 {
            write_u64(emu, oldlenp, payload.len() as u64);
        }
        if oldp != 0 {
            let _ = emu.write_memory(oldp, payload);
        } else {
            let _ = emu.write_memory(fake_data_addr + 0x240, payload);
        }
    }
    0
}

fn path_child_names(path: &Path) -> Vec<String> {
    let mut names = match fs::read_dir(path) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

fn classify_fts_info(path: &Path) -> u16 {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => 1,
        Ok(meta) if meta.file_type().is_symlink() => 12,
        Ok(_) => 8,
        Err(_) => 11,
    }
}

fn unix_timestamp_parts(time: SystemTime) -> (u64, u64) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs(), duration.subsec_nanos() as u64),
        Err(_) => (0, 0),
    }
}

fn synthetic_mode_bits(path: &Path, meta: &fs::Metadata) -> u16 {
    let file_type = meta.file_type();
    let type_bits = if file_type.is_dir() {
        0o040000
    } else if file_type.is_symlink() {
        0o120000
    } else {
        0o100000
    };

    let mut perm_bits = if file_type.is_dir() { 0o755 } else { 0o644 };
    let is_executable = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "exe" | "sh" | "py" | "pl" | "rb"))
        .unwrap_or(false);
    if is_executable {
        perm_bits = 0o755;
    }

    (type_bits | perm_bits) as u16
}

fn write_fake_stat_x64(emu: &mut UnicornEmulator, stat_addr: u64, path: &Path) {
    zero_memory(emu, stat_addr, 0x90);

    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };

    let size = meta.len();
    let blocks = size.div_ceil(512);
    let mode = synthetic_mode_bits(path, &meta);
    let nlink = if meta.file_type().is_dir() {
        2_u16
    } else {
        1_u16
    };
    let blksize = if meta.file_type().is_dir() {
        4096_u32
    } else {
        512_u32
    };
    let (atime_sec, atime_nsec) = meta.accessed().map(unix_timestamp_parts).unwrap_or((0, 0));
    let (mtime_sec, mtime_nsec) = meta.modified().map(unix_timestamp_parts).unwrap_or((0, 0));
    let (ctime_sec, ctime_nsec) = meta
        .created()
        .map(unix_timestamp_parts)
        .unwrap_or((mtime_sec, mtime_nsec));

    write_u32(emu, stat_addr + 0x00, 0);
    write_u16(emu, stat_addr + 0x04, mode);
    write_u16(emu, stat_addr + 0x06, nlink);
    write_u64(emu, stat_addr + 0x08, size ^ ((mode as u64) << 32));
    write_u32(emu, stat_addr + 0x10, 0);
    write_u32(emu, stat_addr + 0x14, 0);
    write_u32(emu, stat_addr + 0x18, 0);
    write_u64(emu, stat_addr + 0x20, atime_sec);
    write_u64(emu, stat_addr + 0x28, atime_nsec);
    write_u64(emu, stat_addr + 0x30, mtime_sec);
    write_u64(emu, stat_addr + 0x38, mtime_nsec);
    write_u64(emu, stat_addr + 0x40, ctime_sec);
    write_u64(emu, stat_addr + 0x48, ctime_nsec);
    write_u64(emu, stat_addr + 0x50, ctime_sec);
    write_u64(emu, stat_addr + 0x58, ctime_nsec);
    write_u64(emu, stat_addr + 0x60, size);
    write_u64(emu, stat_addr + 0x68, blocks);
    write_u32(emu, stat_addr + 0x70, blksize);
    write_u32(emu, stat_addr + 0x74, 0);
    write_u32(emu, stat_addr + 0x78, 0);
}

fn write_fake_ftsent_x64(
    emu: &mut UnicornEmulator,
    entry_addr: u64,
    stat_addr: u64,
    path_addr: u64,
    path: &str,
    name: &str,
    level: i16,
    parent_addr: u64,
    next_addr: u64,
) -> u64 {
    zero_memory(emu, entry_addr, 0x120);
    zero_memory(emu, path_addr, 0x200);
    write_fake_stat_x64(emu, stat_addr, Path::new(path));

    let path_bytes = path.as_bytes();
    let name_bytes = name.as_bytes();
    let path_len = path_bytes.len().min(0x1ff);
    let name_len = name_bytes.len().min(0xb7);
    let _ = emu.write_memory(path_addr, &path_bytes[..path_len]);
    let _ = emu.write_memory(path_addr + path_len as u64, &[0]);
    let _ = emu.write_memory(entry_addr + 0x68, &name_bytes[..name_len]);
    let _ = emu.write_memory(entry_addr + 0x68 + name_len as u64, &[0]);

    write_u64(emu, entry_addr + 0x00, next_addr);
    write_u64(emu, entry_addr + 0x08, parent_addr);
    write_u64(emu, entry_addr + 0x10, next_addr);
    write_u64(emu, entry_addr + 0x20, path_addr);
    write_u64(emu, entry_addr + 0x28, path_addr);
    write_u64(emu, entry_addr + 0x30, path_addr);
    write_u32(emu, entry_addr + 0x38, 0);
    write_u32(emu, entry_addr + 0x3c, u32::MAX);
    write_u16(
        emu,
        entry_addr + 0x40,
        path_len.min(u16::MAX as usize) as u16,
    );
    write_u16(
        emu,
        entry_addr + 0x42,
        name_len.min(u16::MAX as usize) as u16,
    );
    write_u64(emu, entry_addr + 0x48, 1);
    write_u64(emu, entry_addr + 0x50, 1);
    write_i16(emu, entry_addr + 0x56, level);
    write_u16(emu, entry_addr + 0x58, classify_fts_info(Path::new(path)));
    write_u16(emu, entry_addr + 0x5a, 0);
    write_u16(emu, entry_addr + 0x5c, 0);
    write_u64(emu, entry_addr + 0x60, stat_addr);
    entry_addr
}

fn build_fake_fts_children_x64(emu: &mut UnicornEmulator, session: &FakeFtsSession) -> u64 {
    let current_path = PathBuf::from(&session.current_path);
    let child_names = path_child_names(&current_path);
    if child_names.is_empty() {
        return 0;
    }
    let mut head = 0;
    let mut next = 0;
    for (index, name) in child_names.iter().enumerate().rev() {
        let chunk = session.child_base_addr + index as u64 * 0x400;
        let child_path = current_path.join(name);
        let entry_addr = chunk;
        let stat_addr = chunk + 0x100;
        let path_addr = chunk + 0x180;
        write_fake_ftsent_x64(
            emu,
            entry_addr,
            stat_addr,
            path_addr,
            &child_path.to_string_lossy(),
            name,
            1,
            session.entry_addr,
            next,
        );
        head = entry_addr;
        next = entry_addr;
    }
    head
}

fn save_arm64_context(emu: &mut UnicornEmulator) -> Arm64SavedContext {
    let mut x = [0_u64; 29];
    for (index, slot) in x.iter_mut().enumerate() {
        *slot = emu.read_reg(&format!("x{}", index)).unwrap_or(0);
    }
    Arm64SavedContext {
        x,
        fp: emu.read_reg("x29").unwrap_or(0),
        lr: emu.read_reg("lr").unwrap_or(0),
        sp: emu.read_reg("sp").unwrap_or(0),
        pc: emu.read_reg("pc").unwrap_or(0),
    }
}

fn restore_arm64_context(
    emu: &mut UnicornEmulator,
    ctx: &Arm64SavedContext,
    retval: u64,
    resume_pc: u64,
) {
    for (index, value) in ctx.x.iter().enumerate() {
        let _ = emu.write_reg(&format!("x{}", index), *value);
    }
    let _ = emu.write_reg("x29", ctx.fp);
    let _ = emu.write_reg("lr", ctx.lr);
    let _ = emu.write_reg("sp", ctx.sp);
    let _ = emu.write_reg("x0", retval);
    let _ = emu.write_reg("pc", if resume_pc != 0 { resume_pc } else { ctx.pc });
}

fn dispatch_pending_arm64_thread(emu: &mut UnicornEmulator, state: &mut ImportThreadState) -> bool {
    if state.active_arm64_thread.is_some() {
        return false;
    }
    if state.defer_same_resume {
        state.defer_same_resume = false;
        return false;
    }
    let Some(pending) = state.pending_arm64_threads.pop_front() else {
        return false;
    };
    let parent = save_arm64_context(emu);
    let parent_thread_id = state.current_thread_id.max(1);
    state.active_arm64_thread = Some(ActiveArm64Thread {
        thread_id: pending.thread_id,
        parent_thread_id,
        parent,
    });
    state.current_thread_id = pending.thread_id;
    if let Some(ctx) = pending.resume.as_ref() {
        if ctx.pc == state.last_resume_pc {
            state.last_resume_streak = state.last_resume_streak.saturating_add(1);
        } else {
            state.last_resume_pc = ctx.pc;
            state.last_resume_streak = 1;
        }
        if state.last_resume_streak > ARM64_RESUME_STREAK_LIMIT {
            state.defer_same_resume = true;
            state.pending_arm64_threads.push_back(pending);
            println!(
                "[THREAD][arm64] defer child resume at pc=0x{:x} after {} repeats",
                state.last_resume_pc, state.last_resume_streak
            );
            return false;
        }
        restore_arm64_context(emu, ctx, ctx.x[0], ctx.pc);
        println!(
            "[THREAD][arm64] resume parent {} -> child {} pc=0x{:x}",
            parent_thread_id, pending.thread_id, ctx.pc
        );
    } else {
        state.last_resume_pc = pending.entry;
        state.last_resume_streak = 0;
        for reg in 0..29 {
            let _ = emu.write_reg(&format!("x{}", reg), 0);
        }
        let _ = emu.write_reg("x29", 0);
        let _ = emu.write_reg("x0", pending.arg);
        let _ = emu.write_reg("sp", pending.stack_top);
        let _ = emu.write_reg("lr", ARM64_HELPER_EXIT_STUB);
        let _ = emu.write_reg("pc", pending.entry);
        println!(
            "[THREAD][arm64] switch parent {} -> child {} entry=0x{:x} arg=0x{:x}",
            parent_thread_id, pending.thread_id, pending.entry, pending.arg
        );
    }
    true
}

fn record_cond_wait_and_maybe_wake(state: &mut ImportThreadState, cond: u64, mutex: u64) -> bool {
    let key = (cond, mutex);
    if state.last_cond_wait_key == key {
        state.last_cond_wait_streak = state.last_cond_wait_streak.saturating_add(1);
    } else {
        state.last_cond_wait_key = key;
        state.last_cond_wait_streak = 1;
    }
    if state.last_cond_wait_streak > ARM64_COND_WAIT_STREAK_LIMIT {
        state.last_cond_wait_streak = 0;
        true
    } else {
        false
    }
}

fn emulate_synthetic_fork(state: &mut ImportThreadState) -> u64 {
    if state.next_process_id == 0 {
        state.next_process_id = 2;
    }
    let pid = state.next_process_id;
    state.next_process_id = state.next_process_id.saturating_add(1);
    state.synthetic_processes.insert(
        pid,
        SyntheticProcess {
            pid,
            parent_pid: SYNTHETIC_PARENT_PID,
            exit_status: 0,
            running: true,
            reaped: false,
        },
    );
    println!(
        "[PROC] synthetic fork parent_pid={} child_pid={} state=exited",
        SYNTHETIC_PARENT_PID, pid
    );
    pid
}

fn emulate_synthetic_wait(
    state: &mut ImportThreadState,
    requested_pid: u64,
    status_ptr: u64,
    options: u64,
    emu: &mut UnicornEmulator,
) -> u64 {
    let requested = requested_pid as i64;
    let chosen = if requested <= 0 {
        state
            .synthetic_processes
            .values_mut()
            .find(|proc| !proc.reaped && !proc.running)
    } else {
        state
            .synthetic_processes
            .get_mut(&(requested as u64))
            .filter(|proc| !proc.reaped && !proc.running)
    };

    let Some(proc) = chosen else {
        if status_ptr != 0 {
            let _ = emu.write_memory(status_ptr, &0u32.to_le_bytes());
        }
        if (options & 0x1) != 0 {
            println!(
                "[PROC] synthetic wait request pid={} options=0x{:x} -> no child ready",
                requested, options
            );
            return 0;
        }
        println!(
            "[PROC] synthetic wait request pid={} options=0x{:x} -> no child",
            requested, options
        );
        return u64::MAX;
    };

    proc.reaped = true;
    let status = ((proc.exit_status & 0xff) << 8) as u32;
    if status_ptr != 0 {
        let _ = emu.write_memory(status_ptr, &status.to_le_bytes());
    }
    println!(
        "[PROC] synthetic wait reaped child_pid={} parent_pid={} status=0x{:x}",
        proc.pid, proc.parent_pid, status
    );
    proc.pid
}

fn mark_synthetic_process_exit(state: &mut ImportThreadState, pid: u64, exit_status: i32) {
    if let Some(proc) = state.synthetic_processes.get_mut(&pid) {
        proc.exit_status = exit_status;
        proc.running = false;
        println!(
            "[PROC] synthetic child pid={} parent_pid={} exited status={}",
            proc.pid, proc.parent_pid, proc.exit_status
        );
    }
}

fn schedule_arm64_fork_child(
    emu: &mut UnicornEmulator,
    state: &mut ImportThreadState,
    child_pid: u64,
    resume_pc: u64,
) {
    let mut child_ctx = save_arm64_context(emu);
    child_ctx.x[0] = 0;
    child_ctx.pc = resume_pc;
    child_ctx.lr = ARM64_HELPER_EXIT_STUB;
    state.pending_arm64_threads.push_front(PendingArm64Thread {
        thread_id: child_pid,
        entry: 0,
        arg: 0,
        stack_top: child_ctx.sp,
        resume: Some(child_ctx),
    });
    println!(
        "[PROC][arm64] scheduled synthetic fork child pid={} resume_pc=0x{:x}",
        child_pid, resume_pc
    );
}

fn allocate_synthetic_fd_with_kind(state: &mut ImportThreadState, kind: SyntheticFdKind) -> u64 {
    if state.next_synthetic_fd < SYNTHETIC_FD_BASE {
        state.next_synthetic_fd = SYNTHETIC_FD_BASE;
    }
    let fd = state.next_synthetic_fd;
    state.next_synthetic_fd = state.next_synthetic_fd.saturating_add(1);
    state.synthetic_fds.insert(fd);
    state.synthetic_fd_kinds.insert(fd, kind.clone());
    if matches!(kind, SyntheticFdKind::Kqueue) {
        state.kqueues.insert(fd, SyntheticKqueue::default());
    }
    fd
}

fn emulate_import_fcntl(state: &mut ImportThreadState, fd: u64, cmd: u64, arg: u64) -> u64 {
    match cmd {
        // F_GETFD / F_SETFD
        1 => state.fd_flags.get(&fd).copied().unwrap_or(0),
        2 => {
            state.fd_flags.insert(fd, arg);
            0
        }
        // F_GETFL / F_SETFL
        3 => 0,
        4 => 0,
        _ => 0,
    }
}

fn pipe_state_for_fd<'a>(state: &'a ImportThreadState, fd: u64) -> Option<&'a SyntheticPipeState> {
    let key = *state.pipe_keys.get(&fd)?;
    state.pipes.get(&key)
}

fn pipe_state_for_fd_mut<'a>(
    state: &'a mut ImportThreadState,
    fd: u64,
) -> Option<&'a mut SyntheticPipeState> {
    let key = *state.pipe_keys.get(&fd)?;
    state.pipes.get_mut(&key)
}

fn read_kevent64_registration(
    emu: &dyn Emulator,
    addr: u64,
) -> Option<SyntheticKeventRegistration> {
    Some(SyntheticKeventRegistration {
        ident: read_pointer_sized(emu, addr, 8),
        filter: read_i16(emu, addr + 8)?,
        flags: read_u16(emu, addr + 10)?,
        fflags: read_u32_guest(emu, addr + 12)?,
        data: read_i64(emu, addr + 16)?,
        udata: read_pointer_sized(emu, addr + 24, 8),
        enabled: true,
    })
}

fn write_kevent64_entry(emu: &mut UnicornEmulator, addr: u64, event: &SyntheticKeventEvent) {
    write_u64(emu, addr, event.ident);
    write_i16(emu, addr + 8, event.filter);
    write_u16(emu, addr + 10, event.flags);
    write_u32(emu, addr + 12, event.fflags);
    write_i64(emu, addr + 16, event.data);
    write_u64(emu, addr + 24, event.udata);
}

fn kevent_result_flags(reg: &SyntheticKeventRegistration, extra_flags: u16) -> u16 {
    extra_flags | (reg.flags & (EV_ADD | EV_ENABLE | EV_CLEAR | EV_ONESHOT))
}

fn event_from_registration(
    reg: &SyntheticKeventRegistration,
    extra_flags: u16,
    data: i64,
) -> SyntheticKeventEvent {
    SyntheticKeventEvent {
        ident: reg.ident,
        filter: reg.filter,
        flags: kevent_result_flags(reg, extra_flags),
        fflags: reg.fflags,
        data,
        udata: reg.udata,
    }
}

fn registration_ready_event(
    state: &ImportThreadState,
    reg: &SyntheticKeventRegistration,
) -> Option<SyntheticKeventEvent> {
    if !reg.enabled {
        return None;
    }
    let kind = state.synthetic_fd_kinds.get(&reg.ident);
    match reg.filter {
        EVFILT_WRITE => match kind {
            Some(SyntheticFdKind::PipeWrite { .. }) => {
                let pipe = pipe_state_for_fd(state, reg.ident)?;
                if pipe.read_closed {
                    Some(event_from_registration(reg, EV_EOF, 0))
                } else {
                    Some(event_from_registration(reg, 0, reg.data.max(1)))
                }
            }
            Some(SyntheticFdKind::PipeRead { .. }) | Some(SyntheticFdKind::Kqueue) | None => None,
        },
        EVFILT_READ => match kind {
            Some(SyntheticFdKind::PipeRead { .. }) => {
                let pipe = pipe_state_for_fd(state, reg.ident)?;
                if pipe.buffered_bytes != 0 {
                    Some(event_from_registration(
                        reg,
                        0,
                        pipe.buffered_bytes.min(i64::MAX as u64) as i64,
                    ))
                } else if pipe.write_closed {
                    Some(event_from_registration(reg, EV_EOF, 0))
                } else {
                    None
                }
            }
            Some(SyntheticFdKind::PipeWrite { .. }) | Some(SyntheticFdKind::Kqueue) | None => None,
        },
        _ => None,
    }
}

fn queue_kevent_event(kq: &mut SyntheticKqueue, event: SyntheticKeventEvent) {
    let duplicate = kq
        .pending
        .iter()
        .any(|queued| queued.ident == event.ident && queued.filter == event.filter);
    if !duplicate {
        kq.pending.push_back(event);
    }
}

fn seed_kqueue_readiness(state: &ImportThreadState, kq: &mut SyntheticKqueue) {
    let registrations: Vec<SyntheticKeventRegistration> =
        kq.registrations.values().cloned().collect();
    for reg in registrations {
        if let Some(event) = registration_ready_event(state, &reg) {
            queue_kevent_event(kq, event);
        }
    }
}

fn queue_registration_event(
    kq: &mut SyntheticKqueue,
    reg: &SyntheticKeventRegistration,
    extra_flags: u16,
    data: i64,
) {
    queue_kevent_event(kq, event_from_registration(reg, extra_flags, data));
}

fn apply_signal_to_kqueue(
    state: &mut ImportThreadState,
    kq: &mut SyntheticKqueue,
    signal: SyntheticFdSignal,
) {
    match signal {
        SyntheticFdSignal::Write { fd, count } => {
            if let Some(pipe) = pipe_state_for_fd_mut(state, fd) {
                if fd == pipe.write_fd && !pipe.write_closed {
                    pipe.buffered_bytes = pipe.buffered_bytes.saturating_add(count);
                    if let Some(reg) = kq.registrations.get(&(pipe.read_fd, EVFILT_READ)).cloned() {
                        queue_registration_event(
                            kq,
                            &reg,
                            0,
                            pipe.buffered_bytes.min(i64::MAX as u64) as i64,
                        );
                    }
                }
            }
            if let Some(reg) = kq.registrations.get(&(fd, EVFILT_WRITE)).cloned() {
                queue_registration_event(kq, &reg, 0, count.max(1) as i64);
            }
        }
        SyntheticFdSignal::Read { fd, count } => {
            if let Some(pipe) = pipe_state_for_fd_mut(state, fd) {
                if fd == pipe.read_fd {
                    pipe.buffered_bytes = pipe.buffered_bytes.saturating_sub(count);
                    if let Some(reg) = kq
                        .registrations
                        .get(&(pipe.write_fd, EVFILT_WRITE))
                        .cloned()
                    {
                        queue_registration_event(kq, &reg, 0, count.max(1) as i64);
                    }
                    if pipe.buffered_bytes != 0 {
                        if let Some(reg) =
                            kq.registrations.get(&(pipe.read_fd, EVFILT_READ)).cloned()
                        {
                            queue_registration_event(
                                kq,
                                &reg,
                                0,
                                pipe.buffered_bytes.min(i64::MAX as u64) as i64,
                            );
                        }
                    } else if pipe.write_closed {
                        if let Some(reg) =
                            kq.registrations.get(&(pipe.read_fd, EVFILT_READ)).cloned()
                        {
                            queue_registration_event(kq, &reg, EV_EOF, 0);
                        }
                    }
                }
            } else if let Some(SyntheticFdKind::PipeRead { peer }) =
                state.synthetic_fd_kinds.get(&fd)
            {
                if let Some(reg) = kq.registrations.get(&(*peer, EVFILT_WRITE)).cloned() {
                    queue_registration_event(kq, &reg, 0, count.max(1) as i64);
                }
            }
        }
        SyntheticFdSignal::Close { fd } => {
            if let Some(pipe) = pipe_state_for_fd_mut(state, fd) {
                if fd == pipe.write_fd {
                    pipe.write_closed = true;
                    if let Some(reg) = kq.registrations.get(&(pipe.read_fd, EVFILT_READ)).cloned() {
                        let flags = if pipe.buffered_bytes == 0 { EV_EOF } else { 0 };
                        let data = pipe.buffered_bytes.min(i64::MAX as u64) as i64;
                        queue_registration_event(kq, &reg, flags, data);
                    }
                }
                if fd == pipe.read_fd {
                    pipe.read_closed = true;
                    if let Some(reg) = kq
                        .registrations
                        .get(&(pipe.write_fd, EVFILT_WRITE))
                        .cloned()
                    {
                        queue_registration_event(kq, &reg, EV_EOF, 0);
                    }
                }
            } else {
                match state.synthetic_fd_kinds.get(&fd) {
                    Some(SyntheticFdKind::PipeWrite { peer }) => {
                        if let Some(reg) = kq.registrations.get(&(*peer, EVFILT_READ)).cloned() {
                            queue_registration_event(kq, &reg, EV_EOF, 0);
                        }
                    }
                    Some(SyntheticFdKind::PipeRead { peer }) => {
                        if let Some(reg) = kq.registrations.get(&(*peer, EVFILT_WRITE)).cloned() {
                            queue_registration_event(kq, &reg, EV_EOF, 0);
                        }
                    }
                    Some(SyntheticFdKind::Kqueue) | None => {}
                }
            }
        }
    }
}

fn drain_synthetic_fd_signals(state: &mut ImportThreadState, kq: &mut SyntheticKqueue) {
    let signals: Vec<SyntheticFdSignal> = {
        let mut bus = synthetic_signal_bus().lock().unwrap();
        bus.pending.drain(..).collect()
    };
    for signal in signals {
        apply_signal_to_kqueue(state, kq, signal);
    }
}

fn apply_kevent_changes(
    state: &ImportThreadState,
    changelist: u64,
    nchanges: u64,
    emu: &dyn Emulator,
    kq_fd: u64,
    kq: &mut SyntheticKqueue,
) {
    for index in 0..nchanges {
        let addr = changelist + index * KEVENT64_SIZE;
        let Some(mut reg) = read_kevent64_registration(emu, addr) else {
            continue;
        };
        let key = (reg.ident, reg.filter);
        println!(
            "[KQUEUE] kq_fd=0x{:x} change ident=0x{:x} filter={} flags=0x{:x} data={} udata=0x{:x}",
            kq_fd, reg.ident, reg.filter, reg.flags, reg.data, reg.udata
        );
        if (reg.flags & EV_DELETE) != 0 {
            kq.registrations.remove(&key);
            kq.pending
                .retain(|queued| !(queued.ident == reg.ident && queued.filter == reg.filter));
            continue;
        }
        if let Some(existing) = kq.registrations.get(&key) {
            reg.udata = if reg.udata == 0 {
                existing.udata
            } else {
                reg.udata
            };
        }
        reg.enabled = (reg.flags & EV_DISABLE) == 0;
        kq.registrations.insert(key, reg);
        if let Some(inserted) = kq.registrations.get(&key).cloned() {
            if let Some(event) = registration_ready_event(state, &inserted) {
                queue_kevent_event(kq, event);
            }
        }
    }
}

fn emulate_import_kevent(
    state: &mut ImportThreadState,
    kq_fd: u64,
    changelist: u64,
    nchanges: u64,
    eventlist: u64,
    nevents: u64,
    _timeout: u64,
    emu: &mut UnicornEmulator,
) -> u64 {
    let Some(mut kq) = state.kqueues.remove(&kq_fd) else {
        return u64::MAX;
    };

    if changelist != 0 && nchanges != 0 {
        apply_kevent_changes(state, changelist, nchanges, emu, kq_fd, &mut kq);
    }
    drain_synthetic_fd_signals(state, &mut kq);

    let mut emitted = 0u64;
    if eventlist != 0 && nevents != 0 {
        if kq.pending.is_empty() {
            seed_kqueue_readiness(state, &mut kq);
        }
        let mut next_pending = VecDeque::new();
        let mut oneshot_to_remove = HashSet::new();
        while let Some(event) = kq.pending.pop_front() {
            if emitted >= nevents {
                next_pending.push_back(event);
                continue;
            }
            let key = (event.ident, event.filter);
            let Some(reg) = kq.registrations.get(&key) else {
                continue;
            };
            if !reg.enabled {
                continue;
            }
            let out_addr = eventlist + emitted * KEVENT64_SIZE;
            write_kevent64_entry(emu, out_addr, &event);
            emitted += 1;
            println!(
                "[KQUEUE] kq_fd=0x{:x} emit ident=0x{:x} filter={} flags=0x{:x} data={} udata=0x{:x}",
                kq_fd, event.ident, event.filter, event.flags, event.data, event.udata
            );
            if (reg.flags & EV_ONESHOT) != 0 {
                oneshot_to_remove.insert(key);
            } else if (reg.flags & EV_CLEAR) == 0 {
                next_pending.push_back(event);
            }
        }
        kq.pending.extend(next_pending);
        for key in oneshot_to_remove {
            kq.registrations.remove(&key);
            kq.pending
                .retain(|queued| !(queued.ident == key.0 && queued.filter == key.1));
        }
    }

    state.kqueues.insert(kq_fd, kq);
    emitted
}

pub fn install_x64_import_dispatcher(
    emulator: &mut UnicornEmulator,
    import_thunks: HashMap<u64, ImportThunk>,
) -> Result<(), MacOsError> {
    let fts_state = Arc::new(Mutex::new(FakeFtsState::default()));
    let io_state = Arc::new(Mutex::new(ImportIoState::default()));
    let thread_state = Arc::new(Mutex::new(ImportThreadState {
        next_key: 1,
        ..ImportThreadState::default()
    }));
    for (addr, thunk) in import_thunks {
        let fts_state = Arc::clone(&fts_state);
        let io_state = Arc::clone(&io_state);
        let thread_state = Arc::clone(&thread_state);
        emulator.add_code_hook(addr, addr + 1, move |emu, _addr, _size| {
            let rsp = emu.read_reg("rsp").unwrap_or(0);
            let ret_addr = emu
                .read_memory(rsp, 8)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);

            let rdi = emu.read_reg("rdi").unwrap_or(0);
            let rsi = emu.read_reg("rsi").unwrap_or(0);
            let rdx = emu.read_reg("rdx").unwrap_or(0);
            let rcx = emu.read_reg("rcx").unwrap_or(0);
            let r8 = emu.read_reg("r8").unwrap_or(0);
            let r9 = emu.read_reg("r9").unwrap_or(0);

            let result = match &thunk.policy {
                ImportReturnPolicy::Zero => 0_u64,
                ImportReturnPolicy::One => 1_u64,
                ImportReturnPolicy::NegOne => u64::MAX,
                ImportReturnPolicy::Fd3 => 3_u64,
                ImportReturnPolicy::IntArg0 => rdi,
                ImportReturnPolicy::StaticPtr(ptr) => *ptr,
                ImportReturnPolicy::Strlen => read_c_string(emu, rdi, 0x1000).len() as u64,
                ImportReturnPolicy::StrCmp => compare_c_strings(emu, rdi, rsi, None),
                ImportReturnPolicy::StrNCmp => compare_c_strings(emu, rdi, rsi, Some(rdx as usize)),
                ImportReturnPolicy::StrChr => find_char_ptr(emu, rdi, (rsi & 0xff) as u8, false),
                ImportReturnPolicy::StrRChr => find_char_ptr(emu, rdi, (rsi & 0xff) as u8, true),
                ImportReturnPolicy::StrStr => find_substr_ptr(emu, rdi, rsi),
                ImportReturnPolicy::MemCpy => emulate_memcpy(emu, rdi, rsi, rdx),
                ImportReturnPolicy::MemSet => emulate_memset(emu, rdi, rsi, rdx),
                ImportReturnPolicy::ZeroMemoryArg1(len) => {
                    zero_memory(emu, rsi, *len);
                    0
                }
                ImportReturnPolicy::ZeroMemoryArg0(len) => {
                    zero_memory(emu, rdi, *len);
                    0
                }
                ImportReturnPolicy::PipePair => {
                    let mut state = thread_state.lock().unwrap();
                    let fd0 = allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::PipeRead { peer: 0 });
                    let fd1 = allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::PipeWrite { peer: fd0 });
                    state.synthetic_fd_kinds.insert(fd0, SyntheticFdKind::PipeRead { peer: fd1 });
                    state.pipe_keys.insert(fd0, fd0);
                    state.pipe_keys.insert(fd1, fd0);
                    state.pipes.insert(
                        fd0,
                        SyntheticPipeState {
                            read_fd: fd0,
                            write_fd: fd1,
                            buffered_bytes: 0,
                            read_closed: false,
                            write_closed: false,
                        },
                    );
                    if rdi != 0 {
                        let _ = emu.write_memory(rdi, &(fd0 as u32).to_le_bytes());
                        let _ = emu.write_memory(rdi + 4, &(fd1 as u32).to_le_bytes());
                    }
                    0
                }
                ImportReturnPolicy::SyntheticFd => {
                    let mut state = thread_state.lock().unwrap();
                    allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::Kqueue)
                }
                ImportReturnPolicy::Fcntl => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_import_fcntl(&mut state, rdi, rsi, rdx)
                }
                ImportReturnPolicy::Kevent => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_import_kevent(&mut state, rdi, rsi, rdx, rcx, r8, r9, emu)
                }
                ImportReturnPolicy::Fork => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_synthetic_fork(&mut state)
                }
                ImportReturnPolicy::WaitPidStub => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_synthetic_wait(&mut state, rdi, rsi, rdx, emu)
                }
                ImportReturnPolicy::SysConfStub(value) => *value,
                ImportReturnPolicy::PutChar => rdi & 0xff,
                ImportReturnPolicy::SleepUsecArg0 => {
                    let mut state = thread_state.lock().unwrap();
                    advance_synthetic_time_ns(&mut state, rdi.saturating_mul(1_000));
                    0
                }
                ImportReturnPolicy::MachAbsoluteTime => {
                    let mut state = thread_state.lock().unwrap();
                    ensure_synthetic_time(&mut state)
                }
                ImportReturnPolicy::WriteCStringToArg0(bytes) => {
                    if rdi != 0 {
                        let _ = emu.write_memory(rdi, bytes);
                    }
                    rdi
                }
                ImportReturnPolicy::ClockGetTime => {
                    let mut state = thread_state.lock().unwrap();
                    let now_ns = advance_synthetic_time_ns(&mut state, 1);
                    write_synthetic_timespec(emu, rsi, now_ns);
                    0
                }
                ImportReturnPolicy::MachTimebaseInfo => {
                    write_mach_timebase_info(emu, rdi);
                    0
                }
                ImportReturnPolicy::SysctlByName(fake_data_addr) => {
                    emulate_sysctlbyname(emu, rdi, rsi, rdx, *fake_data_addr)
                }
                ImportReturnPolicy::PthreadCreate => {
                    let mut state = thread_state.lock().unwrap();
                    if state.next_thread_id > MAX_GUEST_THREADS {
                        println!(
                            "[IMPORT][x64] pthread_create denied: thread flood (active_limit={})",
                            MAX_GUEST_THREADS
                        );
                        DARWIN_EAGAIN
                    } else {
                        let thread_id = if state.next_thread_id == 0 {
                        state.current_thread_id = 1;
                        state.next_thread_id = 2;
                        2
                        } else {
                            let id = state.next_thread_id;
                            state.next_thread_id += 1;
                            id
                        };
                        if rdi != 0 {
                            write_u64(emu, rdi, thread_id);
                        }
                        0
                    }
                }
                ImportReturnPolicy::PthreadSelf => {
                    let mut state = thread_state.lock().unwrap();
                    if state.current_thread_id == 0 {
                        state.current_thread_id = 1;
                        if state.next_thread_id == 0 {
                            state.next_thread_id = 2;
                        }
                    }
                    state.current_thread_id
                }
                ImportReturnPolicy::PthreadCondWait
                | ImportReturnPolicy::PthreadCondTimedWait
                | ImportReturnPolicy::PthreadCondSignal => 0,
                ImportReturnPolicy::PthreadKeyCreate => {
                    let mut state = thread_state.lock().unwrap();
                    let key = state.next_key;
                    state.next_key += 1;
                    if rdi != 0 {
                        write_u64(emu, rdi, key);
                    }
                    0
                }
                ImportReturnPolicy::PthreadSetSpecific => {
                    let mut state = thread_state.lock().unwrap();
                    state.tls_values.insert(rdi, rsi);
                    0
                }
                ImportReturnPolicy::PthreadGetSpecific => {
                    let state = thread_state.lock().unwrap();
                    state.tls_values.get(&rdi).copied().unwrap_or(0)
                }
                ImportReturnPolicy::MbrTowc => ascii_multibyte_step(emu, rdi, rsi),
                ImportReturnPolicy::MbrLen => ascii_multibyte_len(emu, rdi),
                ImportReturnPolicy::FtsOpen(base) => {
                    let root_ptr = read_pointer_sized(emu, rdi, 8);
                    let root_path = if root_ptr == 0 {
                        ".".to_string()
                    } else {
                        let path = read_c_string(emu, root_ptr, 0x200);
                        if path == "<null>" {
                            ".".to_string()
                        } else {
                            normalize_fts_input_path(path)
                        }
                    };
                    let root_fs_path = PathBuf::from(&root_path);
                    let child_names = path_child_names(&root_fs_path);
                    let mut state = fts_state.lock().unwrap();
                    let slot = state.next_slot;
                    state.next_slot += 1;
                    let session_base = base + slot * FTS_SESSION_STRIDE;
                    let session = FakeFtsSession {
                        handle_addr: session_base,
                        errno_addr: base - 0x400,
                        entry_addr: session_base + 0x100,
                        stat_addr: session_base + 0x300,
                        path_addr: session_base + 0x400,
                        child_base_addr: session_base + 0x800,
                        root_path,
                        child_names,
                        current_path: ".".to_string(),
                        yielded_root: false,
                        child_index: 0,
                        skipped_path: None,
                    };
                    write_u32(emu, session.errno_addr, 0);
                    let handle = session.handle_addr;
                    state.sessions.insert(handle, session);
                    handle
                }
                ImportReturnPolicy::FtsChildren => {
                    let mut state = fts_state.lock().unwrap();
                    if let Some(session) = state.sessions.get_mut(&rdi) {
                        if session
                            .skipped_path
                            .as_ref()
                            .is_some_and(|path| path == &session.current_path)
                        {
                            0
                        } else {
                            build_fake_fts_children_x64(emu, session)
                        }
                    } else {
                        0
                    }
                }
                ImportReturnPolicy::FtsRead => {
                    let mut state = fts_state.lock().unwrap();
                    if let Some(session) = state.sessions.get_mut(&rdi) {
                        write_u32(emu, session.errno_addr, 0);
                        if !session.yielded_root {
                            session.yielded_root = true;
                            session.current_path = session.root_path.clone();
                            session.skipped_path = None;
                            write_fake_ftsent_x64(
                                emu,
                                session.entry_addr,
                                session.stat_addr,
                                session.path_addr,
                                &session.root_path,
                                &session.root_path,
                                0,
                                0,
                                0,
                            )
                        } else if let Some(name) = session.child_names.get(session.child_index).cloned() {
                            session.child_index += 1;
                            let child_path = Path::new(&session.root_path).join(&name);
                            session.current_path = child_path.to_string_lossy().to_string();
                            session.skipped_path = None;
                            write_fake_ftsent_x64(
                                emu,
                                session.entry_addr,
                                session.stat_addr,
                                session.path_addr,
                                &child_path.to_string_lossy(),
                                &name,
                                1,
                                session.entry_addr,
                                0,
                            )
                        } else {
                            write_u32(emu, session.errno_addr, 0);
                            0
                        }
                    } else {
                        0
                    }
                }
                ImportReturnPolicy::FtsClose => {
                    let mut state = fts_state.lock().unwrap();
                    if let Some(session) = state.sessions.remove(&rdi) {
                        write_u32(emu, session.errno_addr, 0);
                    }
                    0
                }
                ImportReturnPolicy::FtsSet => {
                    let mut state = fts_state.lock().unwrap();
                    if let Some(session) = state.sessions.get_mut(&rdi) {
                        session.skipped_path = (rdx == 0x4).then(|| session.current_path.clone());
                        write_u32(emu, session.errno_addr, 0);
                    }
                    0
                }
                ImportReturnPolicy::GetEnv(fake_data_addr) => emulate_getenv(emu, rdi, *fake_data_addr),
                ImportReturnPolicy::LogCString0Zero => 0_u64,
                ImportReturnPolicy::LogCString0One => 1_u64,
                ImportReturnPolicy::LogCString1Zero => 0_u64,
                ImportReturnPolicy::Exit => {
                    let mut io_state = io_state.lock().unwrap();
                    flush_program_stdout(&mut io_state);
                    println!(
                        "[IMPORT][x64] {}(code={}) -> stop emulation",
                        thunk.symbol, rdi
                    );
                    let _ = emu.write_reg("rax", 0);
                    let _ = emu.stop_emulation();
                    return;
                }
            };

            let extra = match &thunk.policy {
                ImportReturnPolicy::Strlen => {
                    format!(" string=\"{}\"", read_c_string(emu, rdi, 128))
                }
                ImportReturnPolicy::StrCmp | ImportReturnPolicy::StrNCmp => {
                    format!(
                        " lhs=\"{}\" rhs=\"{}\"",
                        read_c_string(emu, rdi, 128),
                        read_c_string(emu, rsi, 128)
                    )
                }
                ImportReturnPolicy::StrChr | ImportReturnPolicy::StrRChr => {
                    format!(" haystack=\"{}\" needle=0x{:x}", read_c_string(emu, rdi, 128), rsi & 0xff)
                }
                ImportReturnPolicy::StrStr => {
                    format!(
                        " haystack=\"{}\" needle=\"{}\"",
                        read_c_string(emu, rdi, 128),
                        read_c_string(emu, rsi, 128)
                    )
                }
                ImportReturnPolicy::MemCpy => {
                    format!(" dst=0x{:x} src=0x{:x} len=0x{:x}", rdi, rsi, rdx)
                }
                ImportReturnPolicy::MemSet => {
                    format!(" dst=0x{:x} value=0x{:x} len=0x{:x}", rdi, rsi & 0xff, rdx)
                }
                ImportReturnPolicy::ZeroMemoryArg1(len) => {
                    format!(" zeroed=0x{:x} len=0x{:x}", rsi, len)
                }
                ImportReturnPolicy::ZeroMemoryArg0(len) => {
                    format!(" zeroed=0x{:x} len=0x{:x}", rdi, len)
                }
                ImportReturnPolicy::PipePair => format!(" pipefd=0x{:x}", rdi),
                ImportReturnPolicy::SyntheticFd => String::new(),
                ImportReturnPolicy::Fcntl => format!(" fd=0x{:x} cmd=0x{:x} arg=0x{:x}", rdi, rsi, rdx),
                ImportReturnPolicy::Kevent => format!(
                    " changelist=0x{:x} nchanges=0x{:x} eventlist=0x{:x} nevents=0x{:x} timeout=0x{:x}",
                    rsi, rdx, rcx, r8, r9
                ),
                ImportReturnPolicy::Fork => String::new(),
                ImportReturnPolicy::WaitPidStub => format!(" status=0x{:x}", rsi),
                ImportReturnPolicy::SysConfStub(value) => format!(" value=0x{:x}", value),
                ImportReturnPolicy::WriteCStringToArg0(bytes) => {
                    format!(" wrote=\"{}\"", String::from_utf8_lossy(bytes))
                }
                ImportReturnPolicy::ClockGetTime => format!(" tp=0x{:x}", rsi),
                ImportReturnPolicy::MachAbsoluteTime => String::new(),
                ImportReturnPolicy::SleepUsecArg0 => format!(" usec=0x{:x}", rdi),
                ImportReturnPolicy::MachTimebaseInfo => format!(" info=0x{:x}", rdi),
                ImportReturnPolicy::SysctlByName(_) => {
                    format!(" name=\"{}\" oldp=0x{:x} oldlenp=0x{:x}", read_c_string(emu, rdi, 128), rsi, rdx)
                }
                ImportReturnPolicy::PthreadKeyCreate => format!(" key_ptr=0x{:x}", rdi),
                ImportReturnPolicy::PthreadSetSpecific => format!(" key=0x{:x} value=0x{:x}", rdi, rsi),
                ImportReturnPolicy::PthreadGetSpecific => format!(" key=0x{:x}", rdi),
                ImportReturnPolicy::MbrTowc | ImportReturnPolicy::MbrLen => {
                    format!(" bytes=\"{}\"", read_c_string(emu, rsi, 32))
                }
                ImportReturnPolicy::FtsOpen(_) => {
                    let root_ptr = read_pointer_sized(emu, rdi, 8);
                    format!(" root=\"{}\"", read_c_string(emu, root_ptr, 256))
                }
                ImportReturnPolicy::FtsChildren => format!(" fts=0x{:x}", rdi),
                ImportReturnPolicy::FtsRead => format!(" fts=0x{:x}", rdi),
                ImportReturnPolicy::FtsClose => format!(" fts=0x{:x}", rdi),
                ImportReturnPolicy::FtsSet => format!(" fts=0x{:x} instr=0x{:x}", rdi, rdx),
                ImportReturnPolicy::GetEnv(_) => format!(" name=\"{}\"", read_c_string(emu, rdi, 128)),
                ImportReturnPolicy::LogCString0Zero | ImportReturnPolicy::LogCString0One => {
                    format!(" string=\"{}\"", read_c_string(emu, rdi, 256))
                }
                ImportReturnPolicy::LogCString1Zero => {
                    format!(" string=\"{}\"", read_c_string(emu, rsi, 256))
                }
                _ => String::new(),
            };
            if matches!(&thunk.policy, ImportReturnPolicy::PutChar) {
                let mut io_state = io_state.lock().unwrap();
                record_program_byte(&mut io_state, (result & 0xff) as u8);
            }
            if should_emit_import_trace(&thunk.symbol, &thunk.policy) {
                println!(
                    "[IMPORT][x64] {}(rdi=0x{:x}, rsi=0x{:x}, rdx=0x{:x}, rcx=0x{:x}) -> 0x{:x}{}",
                    thunk.symbol, rdi, rsi, rdx, rcx, result, extra
                );
            }
            let _ = emu.write_reg("rax", result);
            if rsp != 0 {
                let _ = emu.write_reg("rsp", rsp + 8);
            }
            if ret_addr != 0 {
                let _ = emu.write_reg("rip", ret_addr);
            }
        })?;
    }

    Ok(())
}

fn install_arm64_import_dispatcher(
    emulator: &mut UnicornEmulator,
    import_thunks: HashMap<u64, ImportThunk>,
) -> Result<(), MacOsError> {
    let thread_state = Arc::new(Mutex::new(ImportThreadState {
        next_key: 1,
        ..ImportThreadState::default()
    }));
    let _ = emulator.map_writable_code_memory(ARM64_HELPER_EXIT_STUB, 0x1000);
    let _ = emulator.write_memory(ARM64_HELPER_EXIT_STUB, &[0xc0, 0x03, 0x5f, 0xd6]);
    {
        let thread_state = Arc::clone(&thread_state);
        emulator.add_code_hook(
            ARM64_HELPER_EXIT_STUB,
            ARM64_HELPER_EXIT_STUB + 4,
            move |emu, _addr, _size| {
                let mut state = thread_state.lock().unwrap();
                if let Some(active) = state.active_arm64_thread.take() {
                    mark_synthetic_process_exit(&mut state, active.thread_id, 0);
                    state.current_thread_id = active.parent_thread_id;
                    println!(
                        "[THREAD][arm64] thread {} returned to parent {}",
                        active.thread_id, active.parent_thread_id
                    );
                    restore_arm64_context(emu, &active.parent, 0, active.parent.lr);
                }
            },
        )?;
    }
    for (addr, thunk) in import_thunks {
        let thread_state = Arc::clone(&thread_state);
        emulator.add_code_hook(addr, addr + 4, move |emu, _addr, _size| {
            let x0 = emu.read_reg("x0").unwrap_or(0);
            let x1 = emu.read_reg("x1").unwrap_or(0);
            let x2 = emu.read_reg("x2").unwrap_or(0);
            let x3 = emu.read_reg("x3").unwrap_or(0);
            let x4 = emu.read_reg("x4").unwrap_or(0);
            let x5 = emu.read_reg("x5").unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);

            let result = match &thunk.policy {
                ImportReturnPolicy::Zero => 0_u64,
                ImportReturnPolicy::One => 1_u64,
                ImportReturnPolicy::NegOne => u64::MAX,
                ImportReturnPolicy::Fd3 => 3_u64,
                ImportReturnPolicy::IntArg0 => x0,
                ImportReturnPolicy::StaticPtr(ptr) => *ptr,
                ImportReturnPolicy::Strlen => read_c_string(emu, x0, 0x1000).len() as u64,
                ImportReturnPolicy::StrCmp => compare_c_strings(emu, x0, x1, None),
                ImportReturnPolicy::StrNCmp => compare_c_strings(emu, x0, x1, Some(x2 as usize)),
                ImportReturnPolicy::StrChr => find_char_ptr(emu, x0, (x1 & 0xff) as u8, false),
                ImportReturnPolicy::StrRChr => find_char_ptr(emu, x0, (x1 & 0xff) as u8, true),
                ImportReturnPolicy::StrStr => find_substr_ptr(emu, x0, x1),
                ImportReturnPolicy::MemCpy => emulate_memcpy(emu, x0, x1, x2),
                ImportReturnPolicy::MemSet => emulate_memset(emu, x0, x1, x2),
                ImportReturnPolicy::ZeroMemoryArg1(len) => {
                    zero_memory(emu, x1, *len);
                    0
                }
                ImportReturnPolicy::ZeroMemoryArg0(len) => {
                    zero_memory(emu, x0, *len);
                    0
                }
                ImportReturnPolicy::PipePair => {
                    let mut state = thread_state.lock().unwrap();
                    let fd0 = allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::PipeRead { peer: 0 });
                    let fd1 = allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::PipeWrite { peer: fd0 });
                    state.synthetic_fd_kinds.insert(fd0, SyntheticFdKind::PipeRead { peer: fd1 });
                    state.pipe_keys.insert(fd0, fd0);
                    state.pipe_keys.insert(fd1, fd0);
                    state.pipes.insert(
                        fd0,
                        SyntheticPipeState {
                            read_fd: fd0,
                            write_fd: fd1,
                            buffered_bytes: 0,
                            read_closed: false,
                            write_closed: false,
                        },
                    );
                    if x0 != 0 {
                        let _ = emu.write_memory(x0, &(fd0 as u32).to_le_bytes());
                        let _ = emu.write_memory(x0 + 4, &(fd1 as u32).to_le_bytes());
                    }
                    0
                }
                ImportReturnPolicy::SyntheticFd => {
                    let mut state = thread_state.lock().unwrap();
                    allocate_synthetic_fd_with_kind(&mut state, SyntheticFdKind::Kqueue)
                }
                ImportReturnPolicy::Fcntl => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_import_fcntl(&mut state, x0, x1, x2)
                }
                ImportReturnPolicy::Kevent => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_import_kevent(&mut state, x0, x1, x2, x3, x4, x5, emu)
                }
                ImportReturnPolicy::Fork => {
                    let mut state = thread_state.lock().unwrap();
                    let child_pid = emulate_synthetic_fork(&mut state);
                    schedule_arm64_fork_child(emu, &mut state, child_pid, lr);
                    child_pid
                }
                ImportReturnPolicy::WaitPidStub => {
                    let mut state = thread_state.lock().unwrap();
                    emulate_synthetic_wait(&mut state, x0, x1, x2, emu)
                }
                ImportReturnPolicy::SysConfStub(value) => *value,
                ImportReturnPolicy::PutChar => x0 & 0xff,
                ImportReturnPolicy::SleepUsecArg0 => {
                    let mut state = thread_state.lock().unwrap();
                    advance_synthetic_time_ns(&mut state, x0.saturating_mul(1_000));
                    if let Some(active) = state.active_arm64_thread.take() {
                        let child_ctx = save_arm64_context(emu);
                        state.pending_arm64_threads.push_back(PendingArm64Thread {
                            thread_id: active.thread_id,
                            entry: 0,
                            arg: 0,
                            stack_top: child_ctx.sp,
                            resume: Some(child_ctx),
                        });
                        state.current_thread_id = active.parent_thread_id;
                        println!(
                            "[THREAD][arm64] child {} yielded on usleep to parent {}",
                            active.thread_id, active.parent_thread_id
                        );
                        restore_arm64_context(emu, &active.parent, 0, active.parent.lr);
                        return;
                    }
                    0
                }
                ImportReturnPolicy::MachAbsoluteTime => {
                    let mut state = thread_state.lock().unwrap();
                    ensure_synthetic_time(&mut state)
                }
                ImportReturnPolicy::WriteCStringToArg0(bytes) => {
                    if x0 != 0 {
                        let _ = emu.write_memory(x0, bytes);
                    }
                    x0
                }
                ImportReturnPolicy::ClockGetTime => {
                    let mut state = thread_state.lock().unwrap();
                    let now_ns = advance_synthetic_time_ns(&mut state, 1);
                    write_synthetic_timespec(emu, x1, now_ns);
                    0
                }
                ImportReturnPolicy::MachTimebaseInfo => {
                    write_mach_timebase_info(emu, x0);
                    0
                }
                ImportReturnPolicy::SysctlByName(fake_data_addr) => {
                    emulate_sysctlbyname(emu, x0, x1, x2, *fake_data_addr)
                }
                ImportReturnPolicy::PthreadCreate => {
                    let mut state = thread_state.lock().unwrap();
                    if state.next_thread_id > MAX_GUEST_THREADS {
                        println!(
                            "[IMPORT][arm64] pthread_create denied: thread flood (active_limit={})",
                            MAX_GUEST_THREADS
                        );
                        DARWIN_EAGAIN
                    } else {
                        let thread_id = if state.next_thread_id == 0 {
                            state.current_thread_id = 1;
                            state.next_thread_id = 2;
                            2
                        } else {
                            let id = state.next_thread_id;
                            state.next_thread_id += 1;
                            id
                        };
                        if state.next_stack_base == 0 {
                            state.next_stack_base = ARM64_HELPER_STACK_BASE;
                        }
                        let stack_base = state.next_stack_base;
                        state.next_stack_base += ARM64_HELPER_STACK_SIZE;
                        let _ = emu.map_data_memory(stack_base, ARM64_HELPER_STACK_SIZE);
                        state.pending_arm64_threads.push_back(PendingArm64Thread {
                            thread_id,
                            entry: x2,
                            arg: x3,
                            stack_top: stack_base + ARM64_HELPER_STACK_SIZE - 0x100,
                            resume: None,
                        });
                        if x0 != 0 {
                            write_u64(emu, x0, thread_id);
                        }
                        0
                    }
                }
                ImportReturnPolicy::PthreadSelf => {
                    let mut state = thread_state.lock().unwrap();
                    if state.current_thread_id == 0 {
                        state.current_thread_id = 1;
                        if state.next_thread_id == 0 {
                            state.next_thread_id = 2;
                        }
                    }
                    state.current_thread_id
                }
                ImportReturnPolicy::PthreadCondWait => {
                    let mut state = thread_state.lock().unwrap();
                    if dispatch_pending_arm64_thread(emu, &mut state) {
                        return;
                    }
                    if record_cond_wait_and_maybe_wake(&mut state, x0, x1) {
                        advance_synthetic_time_ns(&mut state, 50_000);
                        println!(
                            "[THREAD][arm64] synthetic wake after repeated pthread_cond_wait cond=0x{:x} mutex=0x{:x}",
                            x0, x1
                        );
                        return;
                    }
                    0
                }
                ImportReturnPolicy::PthreadCondTimedWait => {
                    let mut state = thread_state.lock().unwrap();
                    if dispatch_pending_arm64_thread(emu, &mut state) {
                        return;
                    }
                    let timeout_ns = read_timespec_duration_ns(emu, x2, 8);
                    advance_synthetic_time_ns(&mut state, timeout_ns.max(1));
                    DARWIN_ETIMEDOUT
                }
                ImportReturnPolicy::PthreadCondSignal => {
                    let mut state = thread_state.lock().unwrap();
                    if let Some(active) = state.active_arm64_thread.take() {
                        state.current_thread_id = active.parent_thread_id;
                        println!(
                            "[THREAD][arm64] signal resumes parent {} from child {}",
                            active.parent_thread_id, active.thread_id
                        );
                        restore_arm64_context(emu, &active.parent, 0, active.parent.lr);
                        return;
                    }
                    0
                }
                ImportReturnPolicy::PthreadKeyCreate => {
                    let mut state = thread_state.lock().unwrap();
                    let key = state.next_key;
                    state.next_key += 1;
                    if x0 != 0 {
                        write_u64(emu, x0, key);
                    }
                    0
                }
                ImportReturnPolicy::PthreadSetSpecific => {
                    let mut state = thread_state.lock().unwrap();
                    state.tls_values.insert(x0, x1);
                    0
                }
                ImportReturnPolicy::PthreadGetSpecific => {
                    let state = thread_state.lock().unwrap();
                    state.tls_values.get(&x0).copied().unwrap_or(0)
                }
                ImportReturnPolicy::MbrTowc => ascii_multibyte_step(emu, x0, x1),
                ImportReturnPolicy::MbrLen => ascii_multibyte_len(emu, x0),
                ImportReturnPolicy::FtsOpen(_)
                | ImportReturnPolicy::FtsChildren
                | ImportReturnPolicy::FtsRead
                | ImportReturnPolicy::FtsClose
                | ImportReturnPolicy::FtsSet
                | ImportReturnPolicy::GetEnv(_) => 0_u64,
                ImportReturnPolicy::LogCString0Zero => 0_u64,
                ImportReturnPolicy::LogCString0One => 1_u64,
                ImportReturnPolicy::LogCString1Zero => 0_u64,
                ImportReturnPolicy::Exit => {
                    let mut state = thread_state.lock().unwrap();
                    if let Some(active) = state.active_arm64_thread.take() {
                        mark_synthetic_process_exit(&mut state, active.thread_id, x0 as i32);
                        state.current_thread_id = active.parent_thread_id;
                        println!(
                            "[IMPORT][arm64] {}(code={}) -> child {} resumes parent {}",
                            thunk.symbol, x0, active.thread_id, active.parent_thread_id
                        );
                        restore_arm64_context(emu, &active.parent, 0, active.parent.lr);
                        return;
                    }
                    println!("[IMPORT][arm64] {}(code={}) -> stop emulation", thunk.symbol, x0);
                    let _ = emu.write_reg("x0", 0);
                    let _ = emu.stop_emulation();
                    return;
                }
            };

            let extra = match &thunk.policy {
                ImportReturnPolicy::Strlen => {
                    format!(" string=\"{}\"", read_c_string(emu, x0, 128))
                }
                ImportReturnPolicy::StrCmp | ImportReturnPolicy::StrNCmp => {
                    format!(
                        " lhs=\"{}\" rhs=\"{}\"",
                        read_c_string(emu, x0, 128),
                        read_c_string(emu, x1, 128)
                    )
                }
                ImportReturnPolicy::StrChr | ImportReturnPolicy::StrRChr => {
                    format!(" haystack=\"{}\" needle=0x{:x}", read_c_string(emu, x0, 128), x1 & 0xff)
                }
                ImportReturnPolicy::StrStr => {
                    format!(
                        " haystack=\"{}\" needle=\"{}\"",
                        read_c_string(emu, x0, 128),
                        read_c_string(emu, x1, 128)
                    )
                }
                ImportReturnPolicy::MemCpy => {
                    format!(" dst=0x{:x} src=0x{:x} len=0x{:x}", x0, x1, x2)
                }
                ImportReturnPolicy::MemSet => {
                    format!(" dst=0x{:x} value=0x{:x} len=0x{:x}", x0, x1 & 0xff, x2)
                }
                ImportReturnPolicy::ZeroMemoryArg1(len) => {
                    format!(" zeroed=0x{:x} len=0x{:x}", x1, len)
                }
                ImportReturnPolicy::ZeroMemoryArg0(len) => {
                    format!(" zeroed=0x{:x} len=0x{:x}", x0, len)
                }
                ImportReturnPolicy::PipePair => format!(" pipefd=0x{:x}", x0),
                ImportReturnPolicy::SyntheticFd => String::new(),
                ImportReturnPolicy::Fcntl => format!(" fd=0x{:x} cmd=0x{:x} arg=0x{:x}", x0, x1, x2),
                ImportReturnPolicy::Kevent => format!(
                    " changelist=0x{:x} nchanges=0x{:x} eventlist=0x{:x} nevents=0x{:x} timeout=0x{:x}",
                    x1, x2, x3, x4, x5
                ),
                ImportReturnPolicy::Fork => String::new(),
                ImportReturnPolicy::WaitPidStub => format!(" status=0x{:x}", x1),
                ImportReturnPolicy::SysConfStub(value) => format!(" value=0x{:x}", value),
                ImportReturnPolicy::WriteCStringToArg0(bytes) => {
                    format!(" wrote=\"{}\"", String::from_utf8_lossy(bytes))
                }
                ImportReturnPolicy::ClockGetTime => format!(" tp=0x{:x}", x1),
                ImportReturnPolicy::MachAbsoluteTime => String::new(),
                ImportReturnPolicy::SleepUsecArg0 => format!(" usec=0x{:x}", x0),
                ImportReturnPolicy::MachTimebaseInfo => format!(" info=0x{:x}", x0),
                ImportReturnPolicy::SysctlByName(_) => {
                    format!(" name=\"{}\" oldp=0x{:x} oldlenp=0x{:x}", read_c_string(emu, x0, 128), x1, x2)
                }
                ImportReturnPolicy::PthreadCondWait => format!(" cond=0x{:x} mutex=0x{:x}", x0, x1),
                ImportReturnPolicy::PthreadCondTimedWait => {
                    let timeout_ns = read_timespec_duration_ns(emu, x2, 8);
                    format!(" cond=0x{:x} mutex=0x{:x} timeout_ns=0x{:x}", x0, x1, timeout_ns)
                }
                ImportReturnPolicy::PthreadCondSignal => format!(" cond=0x{:x}", x0),
                ImportReturnPolicy::PthreadKeyCreate => format!(" key_ptr=0x{:x}", x0),
                ImportReturnPolicy::PthreadSetSpecific => format!(" key=0x{:x} value=0x{:x}", x0, x1),
                ImportReturnPolicy::PthreadGetSpecific => format!(" key=0x{:x}", x0),
                ImportReturnPolicy::MbrTowc => {
                    format!(" bytes=\"{}\"", read_c_string(emu, x1, 32))
                }
                ImportReturnPolicy::MbrLen => {
                    format!(" bytes=\"{}\"", read_c_string(emu, x0, 32))
                }
                ImportReturnPolicy::FtsOpen(_)
                | ImportReturnPolicy::FtsChildren
                | ImportReturnPolicy::FtsRead
                | ImportReturnPolicy::FtsClose
                | ImportReturnPolicy::FtsSet
                | ImportReturnPolicy::GetEnv(_) => String::new(),
                ImportReturnPolicy::LogCString0Zero | ImportReturnPolicy::LogCString0One => {
                    format!(" string=\"{}\"", read_c_string(emu, x0, 256))
                }
                ImportReturnPolicy::LogCString1Zero => {
                    format!(" string=\"{}\"", read_c_string(emu, x1, 256))
                }
                _ => String::new(),
            };
            println!(
                "[IMPORT][arm64] {}(x0=0x{:x}, x1=0x{:x}, x2=0x{:x}, x3=0x{:x}) -> 0x{:x}{}",
                thunk.symbol, x0, x1, x2, x3, result, extra
            );
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            if matches!(&thunk.policy, ImportReturnPolicy::Fork) {
                let mut state = thread_state.lock().unwrap();
                if dispatch_pending_arm64_thread(emu, &mut state) {
                    return;
                }
            }
        })?;
    }

    Ok(())
}

pub fn install_import_dispatcher(
    emulator: &mut UnicornEmulator,
    arch: ArchType,
    import_thunks: HashMap<u64, ImportThunk>,
) -> Result<(), MacOsError> {
    match arch {
        ArchType::Arm64 => install_arm64_import_dispatcher(emulator, import_thunks),
    }
}

pub fn install_synthetic_macho_imports(
    emulator: &mut dyn Emulator,
    arch: ArchType,
    base: u64,
) -> Result<SyntheticImportLayout, MacOsError> {
    let fake_data_addr = base + 0x2000;
    let data_symbols = initialize_fake_x64_import_data(emulator, fake_data_addr)?;
    let mut cursor = base;
    let mut syscall_stubs = HashMap::new();
    let mut symbol_stubs = HashMap::new();
    let mut import_thunks = HashMap::new();

    let mut write_blob = |blob: &[u8]| -> Result<u64, MacOsError> {
        let addr = cursor;
        emulator.write_memory(addr, blob)?;
        cursor += align_up(blob.len() as u64, 4);
        Ok(addr)
    };

    let zero_stub_addr = match arch {
        ArchType::Arm64 => write_blob(&[0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6])?,
    };

    let mut register_import =
        |symbol: &str, policy: ImportReturnPolicy| -> Result<(), MacOsError> {
            let addr = match arch {
                ArchType::Arm64 => write_blob(&[0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6])?,
            };
            symbol_stubs.insert(symbol.to_string(), addr);
            import_thunks.insert(
                addr,
                ImportThunk {
                    symbol: symbol.to_string(),
                    policy,
                },
            );
            Ok(())
        };

    for (symbol, policy) in default_x64_import_policies(fake_data_addr) {
        register_import(&symbol, policy)?;
    }

    let compact_syscalls = [
        0x1_u64, 0x3, 0x4, 0x5, 0x6, 0x17, 0x18, 0x1B, 0x1C, 0x20, 0x49, 0x68, 0x87, 0xA2, 0xC5,
        0xC7,
    ];
    for num in compact_syscalls {
        let addr = match arch {
            ArchType::Arm64 => {
                let movz = 0xD2800000u32 | ((num as u32 & 0xFFFF) << 5) | 16;
                let mut blob = Vec::with_capacity(12);
                blob.extend_from_slice(&movz.to_le_bytes());
                blob.extend_from_slice(&0xD4000001u32.to_le_bytes());
                blob.extend_from_slice(&0xD65F03C0u32.to_le_bytes());
                write_blob(&blob)?
            }
        };
        syscall_stubs.insert(num, addr);
    }

    let unicorn = emulator
        .as_any_mut()
        .downcast_mut::<UnicornEmulator>()
        .ok_or_else(|| {
            MacOsError::InvalidArgument(
                "synthetic imports require UnicornEmulator-compatible backend".to_string(),
            )
        })?;
    install_import_dispatcher(unicorn, arch, import_thunks)?;

    let pad_blob: &[u8] = match arch {
        ArchType::Arm64 => &[0xC0, 0x03, 0x5F, 0xD6],
    };
    let mut pad_addr = align_up(cursor, 0x1000);
    let pad_limit = base + SYNTHETIC_IMPORT_REGION_SIZE;
    while pad_addr < pad_limit {
        emulator.write_memory(pad_addr, pad_blob)?;
        pad_addr += pad_blob.len() as u64;
    }

    Ok(SyntheticImportLayout {
        zero_stub_addr,
        syscall_stubs,
        symbol_stubs,
        data_symbols,
    })
}

/// Result of resolving every bind in an `LC_DYLD_CHAINED_FIXUPS` blob.
///
/// Reported counts are the number of bind chain entries patched, the
/// number of rebase entries rewritten, and the number of binds that
/// fell back to the "unresolved" stub address because the named
/// symbol had no synthetic stub.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChainedFixupStats {
    pub bound: usize,
    pub rebased: usize,
    pub unresolved: usize,
}

/// Walk every chain described by `LC_DYLD_CHAINED_FIXUPS` and patch
/// each pointer slot in guest memory.
///
/// Modern macOS Mach-O binaries (and obfuscated samples like the
/// Lazarus "Mach-O Man" profiler) use chained fixups instead of the
/// legacy `LC_DYLD_INFO_ONLY` bind opcodes. Each pointer slot in a
/// data segment is initialized in the file to a self-describing
/// chain entry: bit 63 selects bind vs. rebase, bits 51-62 give the
/// stride to the next slot (in 4-byte units, or 0 to end the chain),
/// and the remaining bits encode either an import-table ordinal or
/// an image-base-relative target offset. dyld walks every chain at
/// load time and rewrites every slot to the resolved address.
///
/// Without this pass the slots remain as raw chain values, so any
/// indirect call through `__nl_symbol_ptr` (or any C++ vtable / GOT
/// load) jumps to the chain encoding itself — which strips through
/// the TBI tag handler and lands inside the Mach-O header at offsets
/// like `0x100000065`, exhausting the instruction budget without ever
/// executing real import code.
pub fn process_macho_chained_fixups(
    emulator: &mut dyn Emulator,
    loader: &MachOLoader,
    _arch: ArchType,
    zero_stub_addr: u64,
    syscall_stubs: &HashMap<u64, u64>,
    symbol_stubs: &HashMap<String, u64>,
    data_symbols: &HashMap<String, u64>,
) -> Result<ChainedFixupStats, MacOsError> {
    let unresolved_mode = std::env::var("QILING_IMPORT_FALLBACK")
        .unwrap_or_else(|_| "getpid".to_string())
        .to_ascii_lowercase();
    let fallback_addr = if unresolved_mode == "zero" {
        zero_stub_addr
    } else {
        *syscall_stubs.get(&0x20).unwrap_or(&zero_stub_addr)
    };
    process_chained_fixups_with_binary(
        emulator,
        &loader.binary,
        loader.slide,
        symbol_stubs,
        Some(data_symbols),
        fallback_addr,
    )
}

/// Loader-independent chained-fixups walker.
///
/// Decouples chain processing from `MachOLoader` so the arm64 runner
/// (which loads the binary through its own segment-mapping path,
/// then resolves imports via `install_return_stubs`) can patch
/// chained-fixup binds against the runner's `stub_map`.
pub fn process_chained_fixups_with_binary(
    emulator: &mut dyn Emulator,
    binary: &crate::macos::loader::parser::MachoBinary,
    slide: u64,
    symbol_stubs: &HashMap<String, u64>,
    data_symbols: Option<&HashMap<String, u64>>,
    fallback_addr: u64,
) -> Result<ChainedFixupStats, MacOsError> {
    use crate::macos::loader::consts::dyld_chained_fixups::*;

    let mut stats = ChainedFixupStats::default();

    // Locate the LC_DYLD_CHAINED_FIXUPS payload. If the binary uses
    // the legacy bind opcodes there is nothing to do here.
    let (blob_off, blob_size) = match binary.commands.iter().find_map(|c| match c {
        LoadCommand::DyldChainedFixups(cf) => {
            Some((cf.data_offset as usize, cf.data_size as usize))
        }
        _ => None,
    }) {
        Some(pair) => pair,
        None => return Ok(stats),
    };
    let raw = &binary.data;
    if blob_off
        .checked_add(blob_size)
        .map(|end| end > raw.len())
        .unwrap_or(true)
    {
        return Err(MacOsError::LoaderError(
            "chained-fixups blob extends past binary EOF".to_string(),
        ));
    }
    let blob = &raw[blob_off..blob_off + blob_size];
    if blob.len() < 28 {
        return Err(MacOsError::LoaderError(
            "chained-fixups header truncated".to_string(),
        ));
    }

    let starts_offset = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
    let imports_offset = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
    let symbols_offset = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let imports_count = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
    let imports_format = u32::from_le_bytes(blob[20..24].try_into().unwrap());
    let symbols_format = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    if symbols_format != 0 {
        return Err(MacOsError::LoaderError(format!(
            "chained-fixups symbols_format={} (only uncompressed=0 is supported)",
            symbols_format
        )));
    }

    let imports = parse_chained_fixup_imports(
        blob,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
    )?;
    let defined_symbols = binary.get_defined_symbols();

    // Resolve each import once up front so the chain walk is a
    // straight lookup. Look up by the literal symbol name first
    // (matching how install_return_stubs registers them — with the
    // leading underscore preserved) and fall back to the normalized
    // form for the synthetic-imports path.
    let resolved: Vec<u64> = imports
        .iter()
        .enumerate()
        .map(|(_, (_, _, name))| {
            // Prefer data-symbol bindings whenever both maps have an
            // entry: install_return_stubs builds a function stub for
            // every undefined symbol regardless of type, including
            // C++ globals like `__ZNSt3__14cerrE`. Without checking
            // data_symbols first, a load through cerr fetches stub
            // code bytes as if they were the ostream object's
            // vtable, and the next `ldur xN, [xN, #-N]` faults.
            if let Some(d) = data_symbols {
                if let Some(&addr) = d.get(name) {
                    return addr;
                }
                let normalized = normalize_import_symbol(name.clone());
                if let Some(&addr) = d.get(&normalized) {
                    return addr;
                }
            }
            if let Some(&addr) = defined_symbols.get(name) {
                return addr.wrapping_add(slide);
            }
            let normalized = normalize_import_symbol(name.clone());
            if let Some(&addr) = defined_symbols.get(&normalized) {
                return addr.wrapping_add(slide);
            }
            if let Some(&addr) = symbol_stubs.get(name) {
                return addr;
            }
            if let Some(&addr) = symbol_stubs.get(&normalized) {
                return addr;
            }
            stats.unresolved += 1;
            fallback_addr
        })
        .collect();

    // Parse starts_in_image and walk each segment's chains.
    let starts = &blob[starts_offset..];
    if starts.len() < 4 {
        return Err(MacOsError::LoaderError(
            "chained-fixups starts_in_image truncated".to_string(),
        ));
    }
    let seg_count = u32::from_le_bytes(starts[0..4].try_into().unwrap()) as usize;
    if starts.len() < 4 + seg_count * 4 {
        return Err(MacOsError::LoaderError(
            "chained-fixups seg_info_offset table truncated".to_string(),
        ));
    }
    let image_base = binary.header_address();

    // Collect which segments the chain table actually covers so we
    // can detect duplicate chain tables that other segments hold
    // (some obfuscated samples mirror the chain bytes in
    // __DATA_CONST without registering a starts entry; calls that
    // resolve through that mirror would otherwise still see raw
    // chain values).
    let mut chain_format: Option<u16> = None;
    let mut covered_segments: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut canonical_chain_starts: Vec<(u16, u64)> = Vec::new();
    for seg_idx in 0..seg_count {
        let v = u32::from_le_bytes(
            starts[4 + seg_idx * 4..4 + seg_idx * 4 + 4]
                .try_into()
                .unwrap(),
        );
        if v != 0 {
            covered_segments.insert(seg_idx);
            if chain_format.is_none() {
                let sio = &blob[starts_offset + v as usize..];
                if sio.len() >= 8 {
                    chain_format = Some(u16::from_le_bytes(sio[6..8].try_into().unwrap()));
                }
            }
        }
    }

    for seg_idx in 0..seg_count {
        let seg_info_off = u32::from_le_bytes(
            starts[4 + seg_idx * 4..4 + seg_idx * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if seg_info_off == 0 {
            continue;
        }
        let sio = &blob[starts_offset + seg_info_off..];
        if sio.len() < 22 {
            continue;
        }
        let page_size = u16::from_le_bytes(sio[4..6].try_into().unwrap()) as u64;
        let pointer_format = u16::from_le_bytes(sio[6..8].try_into().unwrap());
        let segment_offset = u64::from_le_bytes(sio[8..16].try_into().unwrap());
        let page_count = u16::from_le_bytes(sio[20..22].try_into().unwrap()) as usize;
        if sio.len() < 22 + page_count * 2 {
            continue;
        }

        for page_idx in 0..page_count {
            let ps = u16::from_le_bytes(
                sio[22 + page_idx * 2..22 + page_idx * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            if ps == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            // DYLD_CHAINED_PTR_START_MULTI introduces a second header
            // word giving multiple chain starts within one page; the
            // obfuscated profiler does not use it, but unfamiliar
            // pointer formats reach the same branch — skip cleanly
            // rather than misinterpret.
            if ps & DYLD_CHAINED_PTR_START_MULTI != 0 {
                continue;
            }
            let chain_start_va =
                image_base + segment_offset + page_idx as u64 * page_size + ps as u64 + slide;
            canonical_chain_starts.push((pointer_format, chain_start_va));
            walk_chain_64(
                emulator,
                chain_start_va,
                pointer_format,
                image_base + slide,
                &resolved,
                fallback_addr,
                &mut stats,
            )?;
        }
    }

    // Fallback: detect duplicate chain tables in segments that
    // weren't registered as having a chain start. Treat any
    // r/w-writable segment whose first slot looks like a chain bind
    // entry (top byte 0x80 — the sentinel that marks bit 63 set in
    // chain-encoded binds) as a synthetic chain starting at offset
    // 0, using the same pointer format the real chain used.
    if let Some(fmt) = chain_format {
        let segments_clone: Vec<crate::macos::loader::command::SegmentCommand64> = binary
            .commands
            .iter()
            .filter_map(|c| match c {
                LoadCommand::Segment64(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        for (idx, seg) in segments_clone.iter().enumerate() {
            if covered_segments.contains(&idx) {
                continue;
            }
            if seg.filesize == 0 || seg.vmsize == 0 {
                continue;
            }
            // PAGEZERO / TEXT / LINKEDIT are not GOT-like.
            let segname = seg.segname_str();
            if segname == "__PAGEZERO" || segname == "__TEXT" || segname == "__LINKEDIT" {
                continue;
            }
            let probe_file_off = seg.fileoff as usize;
            if probe_file_off
                .checked_add(8)
                .map(|end| end > binary.data.len())
                .unwrap_or(true)
            {
                continue;
            }
            let probe_arr: [u8; 8] =
                match binary.data[probe_file_off..probe_file_off + 8].try_into() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
            let raw = u64::from_le_bytes(probe_arr);
            // Bind sentinel: bit 63 set AND ordinal in range AND
            // next field non-zero. Without all three this is just
            // ordinary data and we leave it alone.
            let bind = (raw >> 63) & 1 == 1;
            let nxt = (raw >> 51) & 0xFFF;
            let ord = (raw & 0x00FF_FFFF) as usize;
            if !(bind && nxt != 0 && ord < resolved.len()) {
                continue;
            }
            if let Some((_, canonical_start)) = canonical_chain_starts
                .iter()
                .find(|(source_fmt, _)| *source_fmt == fmt)
            {
                copy_patched_chain_from_canonical(
                    emulator,
                    &binary.data,
                    seg.fileoff,
                    seg.vmaddr + slide,
                    *canonical_start,
                    fmt,
                    &resolved,
                    &mut stats,
                )?;
            } else {
                walk_chain_64_from_file_mirror(
                    emulator,
                    &binary.data,
                    seg.fileoff,
                    seg.vmaddr + slide,
                    fmt,
                    image_base + slide,
                    &resolved,
                    fallback_addr,
                    &mut stats,
                )?;
            }
        }
    }

    Ok(stats)
}

pub fn chained_fixup_import_symbols(
    binary: &crate::macos::loader::parser::MachoBinary,
) -> Result<Vec<String>, MacOsError> {
    let (blob_off, blob_size) = match binary.commands.iter().find_map(|c| match c {
        LoadCommand::DyldChainedFixups(cf) => {
            Some((cf.data_offset as usize, cf.data_size as usize))
        }
        _ => None,
    }) {
        Some(pair) => pair,
        None => return Ok(Vec::new()),
    };
    let raw = &binary.data;
    if blob_off
        .checked_add(blob_size)
        .map(|end| end > raw.len())
        .unwrap_or(true)
    {
        return Err(MacOsError::LoaderError(
            "chained-fixups blob extends past binary EOF".to_string(),
        ));
    }
    let blob = &raw[blob_off..blob_off + blob_size];
    if blob.len() < 28 {
        return Err(MacOsError::LoaderError(
            "chained-fixups header truncated".to_string(),
        ));
    }

    let imports_offset = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
    let symbols_offset = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let imports_count = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
    let imports_format = u32::from_le_bytes(blob[20..24].try_into().unwrap());
    let symbols_format = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    if symbols_format != 0 {
        return Err(MacOsError::LoaderError(format!(
            "chained-fixups symbols_format={} (only uncompressed=0 is supported)",
            symbols_format
        )));
    }

    let imports = parse_chained_fixup_imports(
        blob,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
    )?;
    Ok(imports.into_iter().map(|(_, _, name)| name).collect())
}

/// Decode the chained-fixup imports table into `(lib_ordinal, weak, name)` triples.
fn parse_chained_fixup_imports(
    blob: &[u8],
    imports_offset: usize,
    symbols_offset: usize,
    imports_count: usize,
    imports_format: u32,
) -> Result<Vec<(u8, bool, String)>, MacOsError> {
    use crate::macos::loader::consts::dyld_chained_fixups::*;
    let entry_size = match imports_format {
        DYLD_CHAINED_IMPORT => 4,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        other => {
            return Err(MacOsError::LoaderError(format!(
                "chained-fixups imports_format={} not supported",
                other
            )));
        }
    };
    if imports_offset + imports_count * entry_size > blob.len() {
        return Err(MacOsError::LoaderError(
            "chained-fixups imports table truncated".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(imports_count);
    for i in 0..imports_count {
        let off = imports_offset + i * entry_size;
        // All three formats share the same first u32 layout for
        // lib_ordinal / weak_import / name_offset.
        let raw = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        let lib_ord = (raw & 0xFF) as u8;
        let weak = ((raw >> 8) & 0x1) != 0;
        let name_off = ((raw >> 9) & 0x007F_FFFF) as usize;
        let nm_start = symbols_offset + name_off;
        if nm_start >= blob.len() {
            return Err(MacOsError::LoaderError(format!(
                "chained-fixups import #{} name_offset 0x{:x} out of range",
                i, name_off
            )));
        }
        let nm_end = blob[nm_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| nm_start + p)
            .unwrap_or(blob.len());
        let name = String::from_utf8_lossy(&blob[nm_start..nm_end]).into_owned();
        out.push((lib_ord, weak, name));
    }
    Ok(out)
}

fn copy_patched_chain_from_canonical(
    emulator: &mut dyn Emulator,
    raw_file: &[u8],
    file_start: u64,
    vm_start: u64,
    canonical_start: u64,
    pointer_format: u16,
    resolved_imports: &[u64],
    stats: &mut ChainedFixupStats,
) -> Result<(), MacOsError> {
    use crate::macos::loader::consts::dyld_chained_fixups::*;
    if !matches!(
        pointer_format,
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET
    ) {
        return Ok(());
    }
    let mut chain_off = 0u64;
    for _ in 0..0x10_0000 {
        let file_off = file_start.saturating_add(chain_off) as usize;
        if file_off
            .checked_add(8)
            .map(|end| end > raw_file.len())
            .unwrap_or(true)
        {
            break;
        }
        let raw_bytes: [u8; 8] = raw_file[file_off..file_off + 8]
            .try_into()
            .map_err(|_| MacOsError::LoaderError("short mirror chain read".to_string()))?;
        let raw = u64::from_le_bytes(raw_bytes);
        let bind = (raw >> 63) & 1 == 1;
        let next = ((raw >> 51) & 0xFFF) as u64;
        if bind {
            let ordinal = (raw & 0x00FF_FFFF) as usize;
            if ordinal < resolved_imports.len() {
                stats.bound += 1;
            } else {
                stats.unresolved += 1;
            }
        } else {
            stats.rebased += 1;
        }
        let patched = emulator.read_memory(canonical_start + chain_off, 8)?;
        emulator.write_memory(vm_start + chain_off, &patched)?;
        if next == 0 {
            break;
        }
        chain_off = chain_off.wrapping_add(next * 4);
    }
    Ok(())
}

/// Walk a duplicate chained-fixup table from the original file bytes
/// while writing resolved pointers to guest memory. Obfuscated samples
/// can mirror the real chain into an unregistered segment; using the
/// raw on-disk entries here keeps `next` and `ordinal` decoding stable
/// even if guest memory for a previous slot was already patched.
fn walk_chain_64_from_file_mirror(
    emulator: &mut dyn Emulator,
    raw_file: &[u8],
    file_start: u64,
    vm_start: u64,
    pointer_format: u16,
    image_base_with_slide: u64,
    resolved_imports: &[u64],
    fallback_addr: u64,
    stats: &mut ChainedFixupStats,
) -> Result<(), MacOsError> {
    use crate::macos::loader::consts::dyld_chained_fixups::*;
    if !matches!(
        pointer_format,
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET
    ) {
        return Ok(());
    }
    let mut chain_off = 0u64;
    for _ in 0..0x10_0000 {
        let file_off = file_start.saturating_add(chain_off) as usize;
        if file_off
            .checked_add(8)
            .map(|end| end > raw_file.len())
            .unwrap_or(true)
        {
            break;
        }
        let raw_bytes: [u8; 8] = raw_file[file_off..file_off + 8]
            .try_into()
            .map_err(|_| MacOsError::LoaderError("short mirror chain read".to_string()))?;
        let raw = u64::from_le_bytes(raw_bytes);
        let bind = (raw >> 63) & 1 == 1;
        let next = ((raw >> 51) & 0xFFF) as u64;
        let new_value = if bind {
            let ordinal = (raw & 0x00FF_FFFF) as usize;
            if ordinal < resolved_imports.len() {
                stats.bound += 1;
                resolved_imports[ordinal]
            } else {
                stats.unresolved += 1;
                fallback_addr
            }
        } else {
            let target_off = raw & 0x0000_000F_FFFF_FFFF;
            let high8 = if pointer_format == DYLD_CHAINED_PTR_64 {
                (raw >> 56) & 0xFF
            } else {
                0
            };
            stats.rebased += 1;
            (high8 << 56) | image_base_with_slide.wrapping_add(target_off)
        };
        emulator.write_memory(vm_start + chain_off, &new_value.to_le_bytes())?;
        if next == 0 {
            break;
        }
        chain_off = chain_off.wrapping_add(next * 4);
    }
    Ok(())
}

/// Walk a single chain starting at `chain_start_va` for one of the
/// 64-bit `DYLD_CHAINED_PTR_*` formats and patch each slot in place.
fn walk_chain_64(
    emulator: &mut dyn Emulator,
    chain_start_va: u64,
    pointer_format: u16,
    image_base_with_slide: u64,
    resolved_imports: &[u64],
    fallback_addr: u64,
    stats: &mut ChainedFixupStats,
) -> Result<(), MacOsError> {
    use crate::macos::loader::consts::dyld_chained_fixups::*;
    if !matches!(
        pointer_format,
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET
    ) {
        return Ok(());
    }
    let mut va = chain_start_va;
    // Sanity bound to avoid runaway chains in malformed blobs.
    for _ in 0..0x10_0000 {
        let bytes_vec = emulator.read_memory(va, 8)?;
        let bytes: [u8; 8] = bytes_vec
            .try_into()
            .map_err(|_| MacOsError::LoaderError(format!("short read at chain slot 0x{:x}", va)))?;
        let raw = u64::from_le_bytes(bytes);
        let bind = (raw >> 63) & 1 == 1;
        let next = ((raw >> 51) & 0xFFF) as u64;
        let new_value: u64 = if bind {
            let ordinal = (raw & 0x00FF_FFFF) as usize;
            if ordinal < resolved_imports.len() {
                stats.bound += 1;
                resolved_imports[ordinal]
            } else {
                stats.unresolved += 1;
                fallback_addr
            }
        } else {
            // Rebase: bits 0-35 are the target offset. For format
            // DYLD_CHAINED_PTR_64 bits 56-63 give the top byte of
            // the final VA; for DYLD_CHAINED_PTR_64_OFFSET that
            // field is reserved and must be zero.
            let target_off = raw & 0x0000_000F_FFFF_FFFF;
            let high8 = if pointer_format == DYLD_CHAINED_PTR_64 {
                (raw >> 56) & 0xFF
            } else {
                0
            };
            stats.rebased += 1;
            (high8 << 56) | (image_base_with_slide.wrapping_add(target_off))
        };
        emulator.write_memory(va, &new_value.to_le_bytes())?;
        if next == 0 {
            break;
        }
        va = va.wrapping_add(next * 4);
    }
    Ok(())
}

pub fn patch_macho_import_pointer_sections(
    emulator: &mut dyn Emulator,
    loader: &MachOLoader,
    arch: ArchType,
    zero_stub_addr: u64,
    syscall_stubs: &HashMap<u64, u64>,
    symbol_stubs: &HashMap<String, u64>,
    data_symbols: &HashMap<String, u64>,
) -> Result<(usize, usize, usize), MacOsError> {
    let mut patched = 0usize;
    let mut mapped_to_syscall = 0usize;
    let mut unresolved_fallback = 0usize;
    let verbose_imports = std::env::var("QILING_VERBOSE_IMPORTS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut import_log_budget = std::env::var("QILING_IMPORT_LOG_BUDGET")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(40);

    let unresolved_mode = std::env::var("QILING_IMPORT_FALLBACK")
        .unwrap_or_else(|_| "getpid".to_string())
        .to_ascii_lowercase();
    let unresolved_addr = if unresolved_mode == "zero" {
        zero_stub_addr
    } else {
        *syscall_stubs.get(&0x20).unwrap_or(&zero_stub_addr)
    };

    let sym_to_sysno = |sym: &str| -> Option<u64> {
        match normalize_import_symbol(sym.to_string()).as_str() {
            "exit" => Some(0x1),
            "getpid" => Some(0x20),
            "getuid" => Some(0x17),
            "getgid" => Some(0x18),
            "geteuid" => Some(0x1B),
            "getegid" => Some(0x1C),
            "read" => Some(0x3),
            "write" => Some(0x4),
            "open" => Some(0x5),
            "close" => Some(0x6),
            "munmap" => Some(0x49),
            "brk" => Some(0x68),
            "sysctl" => Some(0x87),
            "nanosleep" => Some(0xA2),
            "mmap" => Some(0xC5),
            "lseek" => Some(0xC7),
            _ => None,
        }
    };

    let addr_for_symbol = |name: Option<String>| -> (u64, bool, bool, Option<String>) {
        if let Some(sym) = name {
            if let Some(&addr) = symbol_stubs.get(&sym) {
                return (addr, false, false, Some(sym));
            }
            let normalized = normalize_import_symbol(sym.clone());
            if let Some(&addr) = symbol_stubs.get(&normalized) {
                return (addr, false, false, Some(sym));
            }
            if let Some(num) = sym_to_sysno(&sym) {
                if let Some(&addr) = syscall_stubs.get(&num) {
                    return (addr, true, false, Some(sym));
                }
            }
            return (unresolved_addr, false, true, Some(sym));
        }
        (unresolved_addr, false, true, None)
    };

    debug_assert!(matches!(arch, ArchType::Arm64));
    if let Some(sec) = loader.binary.get_lazy_symbol_ptr_section() {
        let count = (sec.size / 8) as usize;
        for i in 0..count {
            let name = section64_indirect_symbol_name(loader, sec, i as u64);
            let (target, is_sys, is_unresolved, sym_name) = match name.clone() {
                Some(sym) => {
                    let normalized = normalize_import_symbol(sym.clone());
                    if let Some(&addr) = data_symbols
                        .get(&sym)
                        .or_else(|| data_symbols.get(&normalized))
                    {
                        (addr, false, false, Some(sym))
                    } else {
                        addr_for_symbol(Some(sym))
                    }
                }
                None => addr_for_symbol(None),
            };
            emulator.write_memory(sec.addr + i as u64 * 8, &target.to_le_bytes())?;
            patched += 1;
            if verbose_imports && import_log_budget > 0 {
                println!(
                    "[IMPORT][{}] slot=0x{:x} symbol={} target=0x{:x} kind={}",
                    trim_name(&sec.sectname),
                    sec.addr + i as u64 * 8,
                    sym_name.unwrap_or_else(|| "<none>".to_string()),
                    target,
                    if is_sys { "syscall" } else { "fallback" }
                );
                import_log_budget -= 1;
            }
            if is_sys {
                mapped_to_syscall += 1;
            }
            if is_unresolved {
                unresolved_fallback += 1;
            }
        }
    }
    if let Some(sec) = loader.binary.get_nl_symbol_ptr_section() {
        let count = (sec.size / 8) as usize;
        for i in 0..count {
            let (target, is_sys, is_unresolved, sym_name) =
                addr_for_symbol(section64_indirect_symbol_name(loader, sec, i as u64));
            emulator.write_memory(sec.addr + i as u64 * 8, &target.to_le_bytes())?;
            patched += 1;
            if verbose_imports && import_log_budget > 0 {
                println!(
                    "[IMPORT][{}] slot=0x{:x} symbol={} target=0x{:x} kind={}",
                    trim_name(&sec.sectname),
                    sec.addr + i as u64 * 8,
                    sym_name.unwrap_or_else(|| "<none>".to_string()),
                    target,
                    if is_sys { "syscall" } else { "fallback" }
                );
                import_log_budget -= 1;
            }
            if is_sys {
                mapped_to_syscall += 1;
            }
            if is_unresolved {
                unresolved_fallback += 1;
            }
        }
    }
    if let Some(sec) = loader.binary.get_section("__DATA", "__got") {
        let count = (sec.size / 8) as usize;
        for i in 0..count {
            let name = section64_indirect_symbol_name(loader, sec, i as u64);
            let (target, is_sys, is_unresolved, sym_name) = match name.clone() {
                Some(sym) => {
                    let normalized = normalize_import_symbol(sym.clone());
                    if let Some(&addr) = data_symbols
                        .get(&sym)
                        .or_else(|| data_symbols.get(&normalized))
                    {
                        (addr, false, false, Some(sym))
                    } else {
                        addr_for_symbol(Some(sym))
                    }
                }
                None => addr_for_symbol(None),
            };
            emulator.write_memory(sec.addr + i as u64 * 8, &target.to_le_bytes())?;
            patched += 1;
            if verbose_imports && import_log_budget > 0 {
                println!(
                    "[IMPORT][{}] slot=0x{:x} symbol={} target=0x{:x} kind={}",
                    trim_name(&sec.sectname),
                    sec.addr + i as u64 * 8,
                    sym_name.unwrap_or_else(|| "<none>".to_string()),
                    target,
                    if is_sys { "syscall" } else { "fallback" }
                );
                import_log_budget -= 1;
            }
            if is_sys {
                mapped_to_syscall += 1;
            }
            if is_unresolved {
                unresolved_fallback += 1;
            }
        }
    }

    Ok((patched, mapped_to_syscall, unresolved_fallback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::loader::command::{DyldChainedFixupsCommand, LoadCommand};
    use crate::macos::loader::header::MachOMagic;
    use crate::macos::loader::parser::MachoBinary;
    use std::collections::HashMap;

    #[test]
    fn chained_fixup_import_symbols_reads_static_dyld_import_table() {
        use crate::macos::loader::consts::dyld_chained_fixups::DYLD_CHAINED_IMPORT;

        let mut blob = Vec::new();
        blob.extend_from_slice(&0u32.to_le_bytes()); // fixups_version
        blob.extend_from_slice(&0u32.to_le_bytes()); // starts_offset
        blob.extend_from_slice(&28u32.to_le_bytes()); // imports_offset
        blob.extend_from_slice(&36u32.to_le_bytes()); // symbols_offset
        blob.extend_from_slice(&2u32.to_le_bytes()); // imports_count
        blob.extend_from_slice(&DYLD_CHAINED_IMPORT.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // symbols_format

        let first_import = 1u32;
        let second_import = 1u32 | (7u32 << 9);
        blob.extend_from_slice(&first_import.to_le_bytes());
        blob.extend_from_slice(&second_import.to_le_bytes());
        blob.extend_from_slice(b"_write\0_gettimeofday\0");

        let data_size = blob.len() as u32;
        let binary = MachoBinary {
            data: blob,
            magic: MachOMagic::Magic64,
            header_64: None,
            header_32: None,
            commands: vec![LoadCommand::DyldChainedFixups(DyldChainedFixupsCommand {
                data_offset: 0,
                data_size,
            })],
            segments: Vec::new(),
            entry_point: None,
            is_driver: false,
            segments_data: HashMap::new(),
        };

        let symbols = chained_fixup_import_symbols(&binary).unwrap();
        assert_eq!(symbols, vec!["_write", "_gettimeofday"]);
    }
}
