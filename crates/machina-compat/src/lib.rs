//! Compatibility-mode host service boundary.

mod cxx;

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use cxx::CxxImportKind;

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::mem::{self, MaybeUninit};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::ptr;
#[cfg(target_os = "macos")]
use std::sync::Mutex;

pub use machina_mode::RuntimeMode;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityServices;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestMemoryError;

pub trait GuestMemory {
    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError>;

    fn allocate_memory(
        &mut self,
        _size: usize,
        _alignment: usize,
    ) -> Result<u64, GuestMemoryError> {
        Err(GuestMemoryError)
    }

    fn free_memory(&mut self, _addr: u64) -> Result<(), GuestMemoryError> {
        Ok(())
    }

    fn allocation_size(&mut self, _addr: u64) -> Option<usize> {
        None
    }

    fn guest_executable_path(&mut self) -> Option<String> {
        None
    }

    fn guest_executable_path_ptr(&mut self) -> Option<u64> {
        None
    }

    fn guest_program_name_ptr(&mut self) -> Option<u64> {
        None
    }

    fn set_guest_program_name_ptr(&mut self, _addr: u64) -> Result<(), GuestMemoryError> {
        Ok(())
    }

    fn guest_main_image_header(&mut self) -> Option<u64> {
        None
    }

    fn guest_main_image_slide(&mut self) -> i64 {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCallResult {
    pub return_value: u64,
    pub errno: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOpenResult {
    pub path: String,
    pub return_value: u64,
    pub errno: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIoResult {
    pub return_value: u64,
    pub errno: u32,
    pub transferred: usize,
    pub preview: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostPipeResult {
    pub read_fd: u64,
    pub write_fd: u64,
    pub errno: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompatLogLevel {
    #[default]
    Off,
    Summary,
    Calls,
    Verbose,
}

impl CompatLogLevel {
    fn parse(value: Option<&str>) -> Self {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Self::Off;
        };
        match value.to_ascii_lowercase().as_str() {
            "0" | "false" | "no" | "off" | "none" => Self::Off,
            "1" | "true" | "yes" | "summary" => Self::Summary,
            "call" | "calls" | "full" | "jsonl" | "on" => Self::Calls,
            "verbose" | "debug" => Self::Verbose,
            _ => Self::Calls,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Summary => "summary",
            Self::Calls => "calls",
            Self::Verbose => "verbose",
        }
    }
}

#[derive(Clone, Debug)]
struct CompatLogConfig {
    level: CompatLogLevel,
    filter: HashSet<String>,
    preview_bytes: usize,
}

impl CompatLogConfig {
    fn from_env() -> Self {
        Self::from_env_values(
            std::env::var("MACHINA_COMPAT_LOG").ok().as_deref(),
            std::env::var("MACHINA_COMPAT_LOG_FILTER").ok().as_deref(),
            std::env::var("MACHINA_COMPAT_LOG_PREVIEW_BYTES")
                .ok()
                .as_deref(),
        )
    }

    fn from_env_values(
        level: Option<&str>,
        filter: Option<&str>,
        preview_bytes: Option<&str>,
    ) -> Self {
        let filter = filter
            .unwrap_or("")
            .split(',')
            .map(normalize_log_call_name)
            .filter(|entry| !entry.is_empty())
            .collect::<HashSet<_>>();
        let preview_bytes = preview_bytes
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64)
            .min(4096);
        Self {
            level: CompatLogLevel::parse(level),
            filter,
            preview_bytes,
        }
    }

    fn should_emit(&self, call: &str, error: bool) -> bool {
        if self.level == CompatLogLevel::Off {
            return false;
        }
        let normalized = normalize_log_call_name(call);
        if !self.filter.is_empty() && !self.filter.contains(&normalized) {
            return false;
        }
        if self.level == CompatLogLevel::Summary {
            return error || summary_log_call(&normalized);
        }
        true
    }

    fn include_preview(&self, error: bool) -> bool {
        matches!(self.level, CompatLogLevel::Calls | CompatLogLevel::Verbose)
            || (self.level == CompatLogLevel::Summary && error)
    }
}

thread_local! {
    static COMPAT_LOG_DEPTH: Cell<usize> = Cell::new(0);
    static COMPAT_PENDING_STOP_REASON: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn take_pending_stop_reason() -> Option<String> {
    COMPAT_PENDING_STOP_REASON.with(|reason| reason.borrow_mut().take())
}

#[cfg(target_os = "macos")]
fn set_pending_stop_reason(reason: impl Into<String>) {
    COMPAT_PENDING_STOP_REASON.with(|slot| {
        *slot.borrow_mut() = Some(reason.into());
    });
}

#[derive(Debug)]
struct CompatLogScope {
    outermost: bool,
}

impl CompatLogScope {
    fn enter() -> Self {
        let outermost = COMPAT_LOG_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_add(1));
            current == 0
        });
        Self { outermost }
    }

    fn call_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostCallResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno.unwrap_or(0) != 0 || result.return_value == u64::MAX
        });
        if !self.outermost || !compat_log_config().should_emit(call, error) {
            return;
        }
        let mut fields = vec![
            (
                "return",
                result
                    .as_ref()
                    .map(|result| format_return(result.return_value)),
            ),
            (
                "return_hex",
                result
                    .as_ref()
                    .map(|result| format!("0x{:X}", result.return_value)),
            ),
            (
                "errno",
                result
                    .as_ref()
                    .and_then(|result| result.errno)
                    .map(|errno| errno.to_string()),
            ),
            ("status", result.is_none().then(|| "unhandled".to_string())),
        ];
        emit_compat_log_line(kind, call, args, &mut fields, None);
    }

    fn io_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostIoResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno != 0 || result.return_value == u64::MAX
        });
        if !self.outermost || !compat_log_config().should_emit(call, error) {
            return;
        }
        let mut fields = vec![
            (
                "return",
                result
                    .as_ref()
                    .map(|result| format_return(result.return_value)),
            ),
            (
                "return_hex",
                result
                    .as_ref()
                    .map(|result| format!("0x{:X}", result.return_value)),
            ),
            (
                "errno",
                result.as_ref().map(|result| result.errno.to_string()),
            ),
            (
                "transferred",
                result.as_ref().map(|result| result.transferred.to_string()),
            ),
            ("status", result.is_none().then(|| "unhandled".to_string())),
        ];
        let preview = result.as_ref().and_then(|result| {
            compat_log_config()
                .include_preview(error)
                .then_some(result.preview.as_slice())
        });
        emit_compat_log_line(kind, call, args, &mut fields, preview);
    }

    fn open_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostOpenResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno != 0 || result.return_value == u64::MAX
        });
        if !self.outermost || !compat_log_config().should_emit(call, error) {
            return;
        }
        let mut fields = vec![
            (
                "return",
                result
                    .as_ref()
                    .map(|result| format_return(result.return_value)),
            ),
            (
                "return_hex",
                result
                    .as_ref()
                    .map(|result| format!("0x{:X}", result.return_value)),
            ),
            (
                "errno",
                result.as_ref().map(|result| result.errno.to_string()),
            ),
            ("path", result.as_ref().map(|result| result.path.clone())),
            ("status", result.is_none().then(|| "unhandled".to_string())),
        ];
        emit_compat_log_line(kind, call, args, &mut fields, None);
    }

    fn pipe_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostPipeResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| result.errno != 0);
        if !self.outermost || !compat_log_config().should_emit(call, error) {
            return;
        }
        let mut fields = vec![
            (
                "read_fd",
                result.as_ref().map(|result| result.read_fd.to_string()),
            ),
            (
                "write_fd",
                result.as_ref().map(|result| result.write_fd.to_string()),
            ),
            (
                "errno",
                result.as_ref().map(|result| result.errno.to_string()),
            ),
            ("status", result.is_none().then(|| "unhandled".to_string())),
        ];
        emit_compat_log_line(kind, call, args, &mut fields, None);
    }
}

impl Drop for CompatLogScope {
    fn drop(&mut self) {
        COMPAT_LOG_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

fn compat_log_config() -> &'static CompatLogConfig {
    static CONFIG: OnceLock<CompatLogConfig> = OnceLock::new();
    CONFIG.get_or_init(CompatLogConfig::from_env)
}

fn normalize_log_call_name(call: &str) -> String {
    let mut normalized = call.trim();
    while let Some(rest) = normalized.strip_prefix('_') {
        normalized = rest;
    }
    if let Some((base, _suffix)) = normalized.split_once('$') {
        normalized = base;
    }
    normalized.to_ascii_lowercase()
}

fn summary_log_call(call: &str) -> bool {
    matches!(
        call,
        "open"
            | "openat"
            | "read"
            | "write"
            | "close"
            | "socket"
            | "connect"
            | "bind"
            | "listen"
            | "accept"
            | "send"
            | "recv"
            | "sendto"
            | "recvfrom"
            | "sendmsg"
            | "recvmsg"
            | "shutdown"
            | "getaddrinfo"
            | "getnameinfo"
            | "stat"
            | "lstat"
            | "fstat"
            | "rename"
            | "unlink"
            | "mkdir"
            | "rmdir"
            | "symlink"
            | "readlink"
            | "getentropy"
    )
}

fn format_return(value: u64) -> String {
    if value == u64::MAX {
        "-1".to_string()
    } else {
        value.to_string()
    }
}

fn hex_arg(value: u64) -> String {
    format!("0x{value:X}")
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn compat_log_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn compat_preview_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match *byte {
            b'\n' => "\\n".to_string(),
            b'\r' => "\\r".to_string(),
            b'\t' => "\\t".to_string(),
            0x20..=0x7e => (*byte as char).to_string(),
            _ => ".".to_string(),
        })
        .collect::<String>()
}

fn compat_preview_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

fn push_json_field(out: &mut String, key: &str, value: &str) {
    out.push(',');
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":\"");
    out.push_str(&json_escape(value));
    out.push('"');
}

fn emit_compat_log_line(
    kind: &str,
    call: &str,
    args: &[(&str, String)],
    fields: &mut [(&str, Option<String>)],
    preview: Option<&[u8]>,
) {
    let config = compat_log_config();
    if config.level == CompatLogLevel::Off {
        return;
    }

    let mut out = String::new();
    out.push('{');
    out.push_str("\"plugin\":\"compat\"");
    push_json_field(
        &mut out,
        "TimeStamp",
        &compat_log_timestamp_us().to_string(),
    );
    push_json_field(&mut out, "Level", config.level.as_str());
    push_json_field(&mut out, "Kind", kind);
    push_json_field(&mut out, "Call", &normalize_log_call_name(call));
    push_json_field(&mut out, "Symbol", call);
    for (name, value) in args {
        push_json_field(&mut out, name, value);
    }
    for (name, value) in fields.iter_mut() {
        if let Some(value) = value.take() {
            push_json_field(&mut out, name, &value);
        }
    }
    if let Some(preview) = preview {
        let preview_len = preview.len().min(config.preview_bytes);
        let preview = &preview[..preview_len];
        push_json_field(&mut out, "PreviewText", &compat_preview_text(preview));
        push_json_field(&mut out, "PreviewHex", &compat_preview_hex(preview));
        push_json_field(&mut out, "PreviewBytes", &preview_len.to_string());
    }
    out.push('}');

    let _ = writeln!(std::io::stderr(), "{out}");
}

#[cfg(target_os = "macos")]
fn emit_verbose_compat_payload(
    kind: &str,
    call: &str,
    args: &[(&str, String)],
    fields: &mut [(&str, Option<String>)],
    preview: Option<&[u8]>,
) {
    let config = compat_log_config();
    if config.level != CompatLogLevel::Verbose || !config.should_emit(call, false) {
        return;
    }
    emit_compat_log_line(kind, call, args, fields, preview);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostImportKind {
    #[cfg(target_os = "macos")]
    Puts,
    #[cfg(target_os = "macos")]
    Printf,
    #[cfg(target_os = "macos")]
    SnPrintf,
    #[cfg(target_os = "macos")]
    SnPrintfChk,
    #[cfg(target_os = "macos")]
    Putchar,
    #[cfg(target_os = "macos")]
    Open,
    #[cfg(target_os = "macos")]
    OpenAt,
    #[cfg(target_os = "macos")]
    Read,
    #[cfg(target_os = "macos")]
    Write,
    #[cfg(target_os = "macos")]
    Close,
    #[cfg(target_os = "macos")]
    Socket,
    #[cfg(target_os = "macos")]
    Connect,
    #[cfg(target_os = "macos")]
    Bind,
    #[cfg(target_os = "macos")]
    Listen,
    #[cfg(target_os = "macos")]
    Send,
    #[cfg(target_os = "macos")]
    Recv,
    #[cfg(target_os = "macos")]
    SendTo,
    #[cfg(target_os = "macos")]
    RecvFrom,
    #[cfg(target_os = "macos")]
    SendMsg,
    #[cfg(target_os = "macos")]
    RecvMsg,
    #[cfg(target_os = "macos")]
    Shutdown,
    #[cfg(target_os = "macos")]
    SetSockOpt,
    #[cfg(target_os = "macos")]
    GetSockOpt,
    #[cfg(target_os = "macos")]
    Accept,
    #[cfg(target_os = "macos")]
    GetPeerName,
    #[cfg(target_os = "macos")]
    GetSockName,
    #[cfg(target_os = "macos")]
    SocketPair,
    #[cfg(target_os = "macos")]
    Fcntl,
    #[cfg(target_os = "macos")]
    Ioctl,
    #[cfg(target_os = "macos")]
    Fsync,
    #[cfg(target_os = "macos")]
    Poll,
    #[cfg(target_os = "macos")]
    Readv,
    #[cfg(target_os = "macos")]
    Writev,
    #[cfg(target_os = "macos")]
    Pread,
    #[cfg(target_os = "macos")]
    Pwrite,
    #[cfg(target_os = "macos")]
    Lseek,
    #[cfg(target_os = "macos")]
    Dup,
    #[cfg(target_os = "macos")]
    Dup2,
    #[cfg(target_os = "macos")]
    Pipe,
    #[cfg(target_os = "macos")]
    Select,
    #[cfg(target_os = "macos")]
    DarwinCheckFdSetOverflow,
    #[cfg(target_os = "macos")]
    DarwinChkstk,
    #[cfg(target_os = "macos")]
    Access,
    #[cfg(target_os = "macos")]
    FAccessAt,
    #[cfg(target_os = "macos")]
    Chmod,
    #[cfg(target_os = "macos")]
    Fchmod,
    #[cfg(target_os = "macos")]
    FchmodAt,
    #[cfg(target_os = "macos")]
    Chdir,
    #[cfg(target_os = "macos")]
    Fchdir,
    #[cfg(target_os = "macos")]
    GetCwd,
    #[cfg(target_os = "macos")]
    Stat,
    #[cfg(target_os = "macos")]
    LStat,
    #[cfg(target_os = "macos")]
    FStat,
    #[cfg(target_os = "macos")]
    FStatAt,
    #[cfg(target_os = "macos")]
    StatFs,
    #[cfg(target_os = "macos")]
    FStatFs,
    #[cfg(target_os = "macos")]
    Truncate,
    #[cfg(target_os = "macos")]
    Ftruncate,
    #[cfg(target_os = "macos")]
    Mkdir,
    #[cfg(target_os = "macos")]
    MkdirAt,
    #[cfg(target_os = "macos")]
    Rmdir,
    #[cfg(target_os = "macos")]
    Unlink,
    #[cfg(target_os = "macos")]
    UnlinkAt,
    #[cfg(target_os = "macos")]
    Rename,
    #[cfg(target_os = "macos")]
    RenameAt,
    #[cfg(target_os = "macos")]
    Readlink,
    #[cfg(target_os = "macos")]
    ReadlinkAt,
    #[cfg(target_os = "macos")]
    Symlink,
    #[cfg(target_os = "macos")]
    Realpath,
    #[cfg(target_os = "macos")]
    GetAddrInfo,
    #[cfg(target_os = "macos")]
    FreeAddrInfo,
    #[cfg(target_os = "macos")]
    GaiStrError,
    #[cfg(target_os = "macos")]
    GetNameInfo,
    #[cfg(target_os = "macos")]
    InetPton,
    #[cfg(target_os = "macos")]
    InetNtop,
    #[cfg(target_os = "macos")]
    InetAddr,
    #[cfg(target_os = "macos")]
    InetAton,
    #[cfg(target_os = "macos")]
    Htonl,
    #[cfg(target_os = "macos")]
    Htons,
    #[cfg(target_os = "macos")]
    Ntohl,
    #[cfg(target_os = "macos")]
    Ntohs,
    #[cfg(target_os = "macos")]
    GetEnv,
    #[cfg(target_os = "macos")]
    SetEnv,
    #[cfg(target_os = "macos")]
    UnsetEnv,
    #[cfg(target_os = "macos")]
    GetPid,
    #[cfg(target_os = "macos")]
    GetPpid,
    #[cfg(target_os = "macos")]
    GetUid,
    #[cfg(target_os = "macos")]
    GetEuid,
    #[cfg(target_os = "macos")]
    GetGid,
    #[cfg(target_os = "macos")]
    GetEgid,
    #[cfg(target_os = "macos")]
    SysConf,
    #[cfg(target_os = "macos")]
    GetPageSize,
    #[cfg(target_os = "macos")]
    GetHostName,
    #[cfg(target_os = "macos")]
    Uname,
    #[cfg(target_os = "macos")]
    GetTimeOfDay,
    #[cfg(target_os = "macos")]
    ClockGetTime,
    #[cfg(target_os = "macos")]
    NanoSleep,
    #[cfg(target_os = "macos")]
    Sleep,
    #[cfg(target_os = "macos")]
    USleep,
    #[cfg(target_os = "macos")]
    MachAbsoluteTime,
    #[cfg(target_os = "macos")]
    MachTimebaseInfo,
    #[cfg(target_os = "macos")]
    GetRLimit,
    #[cfg(target_os = "macos")]
    SetRLimit,
    #[cfg(target_os = "macos")]
    Sysctl,
    #[cfg(target_os = "macos")]
    SysctlByName,
    #[cfg(target_os = "macos")]
    Mlock,
    #[cfg(target_os = "macos")]
    Munlock,
    #[cfg(target_os = "macos")]
    Madvise,
    #[cfg(target_os = "macos")]
    Umask,
    #[cfg(target_os = "macos")]
    FOpen,
    #[cfg(target_os = "macos")]
    FdOpen,
    #[cfg(target_os = "macos")]
    FClose,
    #[cfg(target_os = "macos")]
    FRead,
    #[cfg(target_os = "macos")]
    FWrite,
    #[cfg(target_os = "macos")]
    FFlush,
    #[cfg(target_os = "macos")]
    FSeek,
    #[cfg(target_os = "macos")]
    FTell,
    #[cfg(target_os = "macos")]
    FGetS,
    #[cfg(target_os = "macos")]
    FPutS,
    #[cfg(target_os = "macos")]
    FEOF,
    #[cfg(target_os = "macos")]
    FError,
    #[cfg(target_os = "macos")]
    ClearErr,
    #[cfg(target_os = "macos")]
    Fileno,
    #[cfg(target_os = "macos")]
    Malloc,
    #[cfg(target_os = "macos")]
    Calloc,
    #[cfg(target_os = "macos")]
    Realloc,
    #[cfg(target_os = "macos")]
    Free,
    #[cfg(target_os = "macos")]
    PosixMemalign,
    #[cfg(target_os = "macos")]
    Memcpy,
    #[cfg(target_os = "macos")]
    Memmove,
    #[cfg(target_os = "macos")]
    Memset,
    #[cfg(target_os = "macos")]
    BZero,
    #[cfg(target_os = "macos")]
    Memcmp,
    #[cfg(target_os = "macos")]
    Strlen,
    #[cfg(target_os = "macos")]
    Strcmp,
    #[cfg(target_os = "macos")]
    Strncmp,
    #[cfg(target_os = "macos")]
    Strcpy,
    #[cfg(target_os = "macos")]
    Strncpy,
    #[cfg(target_os = "macos")]
    Strcat,
    #[cfg(target_os = "macos")]
    Strchr,
    #[cfg(target_os = "macos")]
    Strrchr,
    #[cfg(target_os = "macos")]
    Strdup,
    #[cfg(target_os = "macos")]
    Cxx(CxxImportKind),
    #[cfg(target_os = "macos")]
    OpenDir,
    #[cfg(target_os = "macos")]
    FdOpenDir,
    #[cfg(target_os = "macos")]
    ReadDir,
    #[cfg(target_os = "macos")]
    ReadDirR,
    #[cfg(target_os = "macos")]
    CloseDir,
    #[cfg(target_os = "macos")]
    DirFd,
    #[cfg(target_os = "macos")]
    RewindDir,
    #[cfg(target_os = "macos")]
    Telldir,
    #[cfg(target_os = "macos")]
    Seekdir,
    #[cfg(target_os = "macos")]
    GetEntropy,
    #[cfg(target_os = "macos")]
    PthreadThreadingNp,
    #[cfg(target_os = "macos")]
    PthreadSigmask,
    #[cfg(target_os = "macos")]
    NSGetExecutablePath,
    #[cfg(target_os = "macos")]
    IsSetUGid,
    #[cfg(target_os = "macos")]
    Execl,
    #[cfg(target_os = "macos")]
    Execlp,
    #[cfg(target_os = "macos")]
    Execv,
    #[cfg(target_os = "macos")]
    Execve,
    #[cfg(target_os = "macos")]
    Execvp,
    #[cfg(target_os = "macos")]
    GetProgName,
    #[cfg(target_os = "macos")]
    SetProgName,
    #[cfg(target_os = "macos")]
    DyldImageCount,
    #[cfg(target_os = "macos")]
    DyldGetImageName,
    #[cfg(target_os = "macos")]
    DyldGetImageHeader,
    #[cfg(target_os = "macos")]
    DyldGetImageVmaddrSlide,
    #[cfg(target_os = "macos")]
    Dladdr,
    #[cfg(target_os = "macos")]
    PthreadOnce,
    #[cfg(target_os = "macos")]
    PthreadMutexAttrInit,
    #[cfg(target_os = "macos")]
    PthreadMutexAttrSetType,
    #[cfg(target_os = "macos")]
    PthreadMutexAttrDestroy,
    #[cfg(target_os = "macos")]
    PthreadAttrInit,
    #[cfg(target_os = "macos")]
    PthreadAttrDestroy,
    #[cfg(target_os = "macos")]
    PthreadAttrGetStackSize,
    #[cfg(target_os = "macos")]
    PthreadAttrSetStackSize,
    #[cfg(target_os = "macos")]
    PthreadAttrSetDetachState,
    #[cfg(target_os = "macos")]
    OsUnfairLockLock,
    #[cfg(target_os = "macos")]
    OsUnfairLockTryLock,
    #[cfg(target_os = "macos")]
    OsUnfairLockUnlock,
    #[cfg(target_os = "macos")]
    OsUnfairLockAssertOwner,
    #[cfg(target_os = "macos")]
    OsUnfairLockAssertNotOwner,
}

impl CompatibilityServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        mode.is_compat().then_some(Self)
    }

    pub fn log_unhandled_import(&self, symbol: &str, address: u64, lr: u64, reason: &str) {
        let args = [
            ("ImportSymbol", symbol.to_string()),
            ("Address", hex_arg(address)),
            ("Lr", hex_arg(lr)),
        ];
        let mut fields = vec![
            ("status", Some("unhandled".to_string())),
            ("reason", Some(reason.to_string())),
        ];
        if let Some(diagnostic) = cxx::diagnose_symbol(symbol) {
            fields.push(("CxxCategory", Some(diagnostic.category.to_string())));
            fields.push(("CxxStrategy", Some(diagnostic.strategy.to_string())));
        }
        emit_compat_log_line("diagnostic", "unhandled-import", &args, &mut fields, None);
    }

    pub fn log_unknown_import_address(&self, address: u64, lr: u64) {
        let args = [("Address", hex_arg(address)), ("Lr", hex_arg(lr))];
        let mut fields = [
            ("status", Some("unhandled".to_string())),
            (
                "reason",
                Some("no import stub symbol for address".to_string()),
            ),
        ];
        emit_compat_log_line(
            "diagnostic",
            "unknown-import-address",
            &args,
            &mut fields,
            None,
        );
    }

    pub fn log_unresolved_dlsym(&self, handle: u64, symbol: &str, reason: &str) {
        let args = [
            ("Handle", hex_arg(handle)),
            ("ImportSymbol", symbol.to_string()),
        ];
        let mut fields = vec![
            ("status", Some("unhandled".to_string())),
            ("reason", Some(reason.to_string())),
        ];
        if let Some(diagnostic) = cxx::diagnose_symbol(symbol) {
            fields.push(("CxxCategory", Some(diagnostic.category.to_string())));
            fields.push(("CxxStrategy", Some(diagnostic.strategy.to_string())));
        }
        emit_compat_log_line("diagnostic", "unresolved-dlsym", &args, &mut fields, None);
    }

    pub fn should_proxy_import(&self, symbol: &str) -> bool {
        host_import_kind(symbol).is_some()
    }

    pub fn proxy_cstring_arg0_import<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        arg0_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            let log_scope = CompatLogScope::enter();
            let kind = host_import_kind(symbol)?;
            let result = match kind {
                HostImportKind::Puts => proxy_host_puts(memory, arg0_ptr),
                HostImportKind::Printf => {
                    proxy_host_printf(memory, &[arg0_ptr, 0, 0, 0, 0, 0, 0, 0], None)
                }
                HostImportKind::Putchar => proxy_host_putchar(arg0_ptr),
                _ => None,
            };
            let log_args = [("arg0", hex_arg(arg0_ptr))];
            log_scope.call_result("import", symbol, &log_args, &result);
            result
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, symbol, arg0_ptr);
            None
        }
    }

    pub fn proxy_arm64_import<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        args: &[u64; 8],
    ) -> Option<HostCallResult> {
        self.proxy_arm64_import_with_stack(memory, symbol, args, None)
    }

    pub fn proxy_arm64_import_with_stack<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        args: &[u64; 8],
        stack_ptr: Option<u64>,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            let log_scope = CompatLogScope::enter();
            let kind = host_import_kind(symbol)?;
            let result = match kind {
                HostImportKind::Puts => proxy_host_puts(memory, args[0]),
                HostImportKind::Printf => {
                    let stack_args = stack_ptr.map(|sp| read_stack_u64_args(memory, sp, 64));
                    proxy_host_printf(memory, args, stack_args.as_deref())
                }
                HostImportKind::SnPrintf => {
                    let stack_args = stack_ptr.map(|sp| read_stack_u64_args(memory, sp, 64));
                    proxy_host_snprintf(memory, args, stack_args.as_deref())
                }
                HostImportKind::SnPrintfChk => {
                    let stack_args = stack_ptr.map(|sp| read_stack_u64_args(memory, sp, 64));
                    proxy_host_snprintf_chk(memory, args, stack_args.as_deref())
                }
                HostImportKind::Putchar => proxy_host_putchar(args[0]),
                HostImportKind::Open => {
                    let result =
                        self.open_path_arm64(memory, args[0], args[1], args[2], stack_ptr)?;
                    Some(HostCallResult {
                        return_value: result.return_value,
                        errno: Some(result.errno),
                    })
                }
                HostImportKind::OpenAt => {
                    let mode = arm64_variadic_open_mode(memory, args[2], args[3], stack_ptr);
                    let result = self.openat_path(memory, args[0], args[1], args[2], mode)?;
                    Some(HostCallResult {
                        return_value: result.return_value,
                        errno: Some(result.errno),
                    })
                }
                HostImportKind::Read => Some(
                    self.read_fd(memory, args[0], args[1], args[2] as usize)?
                        .into(),
                ),
                HostImportKind::Write => Some(
                    self.write_fd(memory, args[0], args[1], args[2] as usize)?
                        .into(),
                ),
                HostImportKind::Close => Some(self.close_fd(args[0])?.into()),
                HostImportKind::Socket => Some(self.socket(args[0], args[1], args[2])?.into()),
                HostImportKind::Connect => Some(
                    self.connect_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::Bind => {
                    Some(self.bind_socket(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::Listen => Some(self.listen_socket(args[0], args[1])?.into()),
                HostImportKind::Send => Some(
                    self.send_socket(memory, args[0], args[1], args[2] as usize, args[3])?
                        .into(),
                ),
                HostImportKind::Recv => Some(
                    self.recv_socket(memory, args[0], args[1], args[2] as usize, args[3])?
                        .into(),
                ),
                HostImportKind::SendTo => Some(
                    self.sendto_socket(
                        memory,
                        args[0],
                        args[1],
                        args[2] as usize,
                        args[3],
                        args[4],
                        args[5],
                    )?
                    .into(),
                ),
                HostImportKind::RecvFrom => Some(
                    self.recvfrom_socket(
                        memory,
                        args[0],
                        args[1],
                        args[2] as usize,
                        args[3],
                        args[4],
                        args[5],
                    )?
                    .into(),
                ),
                HostImportKind::SendMsg => Some(
                    self.sendmsg_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::RecvMsg => Some(
                    self.recvmsg_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::Shutdown => Some(self.shutdown_socket(args[0], args[1])?.into()),
                HostImportKind::SetSockOpt => Some(
                    self.setsockopt_socket(memory, args[0], args[1], args[2], args[3], args[4])?
                        .into(),
                ),
                HostImportKind::GetSockOpt => Some(
                    self.getsockopt_socket(memory, args[0], args[1], args[2], args[3], args[4])?
                        .into(),
                ),
                HostImportKind::Accept => Some(
                    self.accept_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::GetPeerName => Some(
                    self.getpeername_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::GetSockName => Some(
                    self.getsockname_socket(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::SocketPair => Some(
                    self.socketpair(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::Fcntl => {
                    let arg = arm64_variadic_stack_arg(memory, args[2], stack_ptr, 0);
                    Some(self.fcntl_fd(args[0], args[1], arg)?.into())
                }
                HostImportKind::Ioctl => {
                    let data_ptr = arm64_variadic_stack_arg(memory, args[2], stack_ptr, 0);
                    Some(self.ioctl_fd(memory, args[0], args[1], data_ptr)?.into())
                }
                HostImportKind::Fsync => Some(self.fsync_fd(args[0])?.into()),
                HostImportKind::Poll => {
                    Some(self.poll_fds(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::Readv => {
                    Some(self.readv_fd(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::Writev => {
                    Some(self.writev_fd(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::Pread => Some(
                    self.pread_fd(memory, args[0], args[1], args[2] as usize, args[3])?
                        .into(),
                ),
                HostImportKind::Pwrite => Some(
                    self.pwrite_fd(memory, args[0], args[1], args[2] as usize, args[3])?
                        .into(),
                ),
                HostImportKind::Lseek => Some(self.lseek_fd(args[0], args[1], args[2])?.into()),
                HostImportKind::Dup => Some(self.dup_fd(args[0])?.into()),
                HostImportKind::Dup2 => Some(self.dup2_fd(args[0], args[1])?.into()),
                HostImportKind::Pipe => Some(self.pipe_fds(memory, args[0])?.into()),
                HostImportKind::Select => Some(
                    self.select_fds(memory, args[0], args[1], args[2], args[3], args[4])?
                        .into(),
                ),
                HostImportKind::DarwinCheckFdSetOverflow => Some(HostCallResult {
                    return_value: 1,
                    errno: Some(0),
                }),
                HostImportKind::DarwinChkstk => Some(host_call_value(args[0])),
                HostImportKind::Access => Some(self.access_path(memory, args[0], args[1])?.into()),
                HostImportKind::FAccessAt => Some(
                    self.faccessat_path(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::Chmod => Some(self.chmod_path(memory, args[0], args[1])?.into()),
                HostImportKind::Fchmod => Some(self.fchmod_fd(args[0], args[1])?.into()),
                HostImportKind::FchmodAt => Some(
                    self.fchmodat_path(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::Chdir => Some(self.chdir_path(memory, args[0])?.into()),
                HostImportKind::Fchdir => Some(self.fchdir_fd(args[0])?.into()),
                HostImportKind::GetCwd => Some(self.getcwd_path(memory, args[0], args[1])?),
                HostImportKind::Stat => Some(self.stat_path(memory, args[0], args[1])?.into()),
                HostImportKind::LStat => Some(self.lstat_path(memory, args[0], args[1])?.into()),
                HostImportKind::FStat => Some(self.fstat_fd(memory, args[0], args[1])?.into()),
                HostImportKind::FStatAt => Some(
                    self.fstatat_path(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::StatFs => Some(self.statfs_path(memory, args[0], args[1])?.into()),
                HostImportKind::FStatFs => Some(self.fstatfs_fd(memory, args[0], args[1])?.into()),
                HostImportKind::Truncate => {
                    Some(self.truncate_path(memory, args[0], args[1])?.into())
                }
                HostImportKind::Ftruncate => Some(self.ftruncate_fd(args[0], args[1])?.into()),
                HostImportKind::Mkdir => Some(self.mkdir_path(memory, args[0], args[1])?.into()),
                HostImportKind::MkdirAt => {
                    Some(self.mkdirat_path(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::Rmdir => Some(self.rmdir_path(memory, args[0])?.into()),
                HostImportKind::Unlink => Some(self.unlink_path(memory, args[0])?.into()),
                HostImportKind::UnlinkAt => Some(
                    self.unlinkat_path(memory, args[0], args[1], args[2])?
                        .into(),
                ),
                HostImportKind::Rename => Some(self.rename_path(memory, args[0], args[1])?.into()),
                HostImportKind::RenameAt => Some(
                    self.renameat_path(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::Readlink => Some(
                    self.readlink_path(memory, args[0], args[1], args[2] as usize)?
                        .into(),
                ),
                HostImportKind::ReadlinkAt => Some(
                    self.readlinkat_path(memory, args[0], args[1], args[2], args[3] as usize)?
                        .into(),
                ),
                HostImportKind::Symlink => {
                    Some(self.symlink_path(memory, args[0], args[1])?.into())
                }
                HostImportKind::Realpath => Some(self.realpath_path(memory, args[0], args[1])?),
                HostImportKind::GetAddrInfo => {
                    Some(self.getaddrinfo(memory, args[0], args[1], args[2], args[3])?)
                }
                HostImportKind::FreeAddrInfo => Some(self.freeaddrinfo(memory, args[0])?),
                HostImportKind::GaiStrError => Some(self.gai_strerror(memory, args[0])?),
                HostImportKind::GetNameInfo => Some(self.getnameinfo(
                    memory, args[0], args[1], args[2], args[3], args[4], args[5], args[6],
                )?),
                HostImportKind::InetPton => {
                    Some(self.inet_pton(memory, args[0], args[1], args[2])?)
                }
                HostImportKind::InetNtop => {
                    Some(self.inet_ntop(memory, args[0], args[1], args[2], args[3])?)
                }
                HostImportKind::InetAddr => Some(self.inet_addr(memory, args[0])?),
                HostImportKind::InetAton => Some(self.inet_aton(memory, args[0], args[1])?),
                HostImportKind::Htonl => Some(HostCallResult {
                    return_value: (args[0] as u32).to_be() as u64,
                    errno: None,
                }),
                HostImportKind::Htons => Some(HostCallResult {
                    return_value: (args[0] as u16).to_be() as u64,
                    errno: None,
                }),
                HostImportKind::Ntohl => Some(HostCallResult {
                    return_value: u32::from_be(args[0] as u32) as u64,
                    errno: None,
                }),
                HostImportKind::Ntohs => Some(HostCallResult {
                    return_value: u16::from_be(args[0] as u16) as u64,
                    errno: None,
                }),
                HostImportKind::GetEnv => Some(self.getenv(memory, args[0])?),
                HostImportKind::SetEnv => {
                    Some(self.setenv_var(memory, args[0], args[1], args[2])?.into())
                }
                HostImportKind::UnsetEnv => Some(self.unsetenv_var(memory, args[0])?.into()),
                HostImportKind::GetPid => Some(self.getpid()?),
                HostImportKind::GetPpid => Some(self.getppid()?),
                HostImportKind::GetUid => Some(self.getuid()?),
                HostImportKind::GetEuid => Some(self.geteuid()?),
                HostImportKind::GetGid => Some(self.getgid()?),
                HostImportKind::GetEgid => Some(self.getegid()?),
                HostImportKind::SysConf => Some(self.sysconf(args[0])?),
                HostImportKind::GetPageSize => Some(self.getpagesize()?),
                HostImportKind::GetHostName => {
                    Some(self.gethostname(memory, args[0], args[1])?.into())
                }
                HostImportKind::Uname => Some(self.uname(memory, args[0])?.into()),
                HostImportKind::GetTimeOfDay => {
                    Some(self.gettimeofday(memory, args[0], args[1], 0)?.into())
                }
                HostImportKind::ClockGetTime => {
                    Some(self.clock_gettime(memory, args[0], args[1])?.into())
                }
                HostImportKind::NanoSleep => Some(self.nanosleep(memory, args[0], args[1])?.into()),
                HostImportKind::Sleep => Some(self.sleep_seconds(args[0])?),
                HostImportKind::USleep => Some(self.usleep_usecs(args[0])?.into()),
                HostImportKind::MachAbsoluteTime => Some(self.mach_absolute_time()?),
                HostImportKind::MachTimebaseInfo => Some(self.mach_timebase_info(memory, args[0])?),
                HostImportKind::GetRLimit => Some(self.getrlimit(memory, args[0], args[1])?.into()),
                HostImportKind::SetRLimit => Some(self.setrlimit(memory, args[0], args[1])?.into()),
                HostImportKind::Sysctl => Some(
                    self.sysctl(memory, args[0], args[1], args[2], args[3], args[4], args[5])?
                        .into(),
                ),
                HostImportKind::SysctlByName => Some(
                    self.sysctlbyname(memory, args[0], args[1], args[2], args[3], args[4])?
                        .into(),
                ),
                HostImportKind::Mlock => Some(proxy_guest_memory_lock("mlock", args[0], args[1])),
                HostImportKind::Munlock => {
                    Some(proxy_guest_memory_lock("munlock", args[0], args[1]))
                }
                HostImportKind::Madvise => Some(proxy_guest_madvise(args[0], args[1], args[2])),
                HostImportKind::Umask => Some(self.umask(args[0])?),
                HostImportKind::FOpen => Some(self.fopen_path(memory, args[0], args[1])?),
                HostImportKind::FdOpen => Some(self.fdopen_fd(memory, args[0], args[1])?),
                HostImportKind::FClose => Some(self.fclose_stream(memory, args[0])?.into()),
                HostImportKind::FRead => Some(
                    self.fread_stream(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::FWrite => Some(
                    self.fwrite_stream(memory, args[0], args[1], args[2], args[3])?
                        .into(),
                ),
                HostImportKind::FFlush => Some(self.fflush_stream(args[0])?.into()),
                HostImportKind::FSeek => Some(self.fseek_stream(args[0], args[1], args[2])?.into()),
                HostImportKind::FTell => Some(self.ftell_stream(args[0])?),
                HostImportKind::FGetS => {
                    Some(self.fgets_stream(memory, args[0], args[1], args[2])?)
                }
                HostImportKind::FPutS => Some(self.fputs_stream(memory, args[0], args[1])?.into()),
                HostImportKind::FEOF => Some(self.feof_stream(args[0])?),
                HostImportKind::FError => Some(self.ferror_stream(args[0])?),
                HostImportKind::ClearErr => Some(self.clearerr_stream(args[0])?),
                HostImportKind::Fileno => Some(self.fileno_stream(args[0])?.into()),
                HostImportKind::Malloc => Some(self.malloc(memory, args[0])?),
                HostImportKind::Calloc => Some(self.calloc(memory, args[0], args[1])?),
                HostImportKind::Realloc => Some(self.realloc(memory, args[0], args[1])?),
                HostImportKind::Free => Some(self.free(memory, args[0])?),
                HostImportKind::PosixMemalign => {
                    Some(self.posix_memalign(memory, args[0], args[1], args[2])?)
                }
                HostImportKind::Memcpy => Some(self.memcpy(memory, args[0], args[1], args[2])?),
                HostImportKind::Memmove => Some(self.memmove(memory, args[0], args[1], args[2])?),
                HostImportKind::Memset => Some(self.memset(memory, args[0], args[1], args[2])?),
                HostImportKind::BZero => Some(self.memset(memory, args[0], 0, args[1])?),
                HostImportKind::Memcmp => Some(self.memcmp(memory, args[0], args[1], args[2])?),
                HostImportKind::Strlen => Some(self.strlen(memory, args[0])?),
                HostImportKind::Strcmp => Some(self.strcmp(memory, args[0], args[1])?),
                HostImportKind::Strncmp => Some(self.strncmp(memory, args[0], args[1], args[2])?),
                HostImportKind::Strcpy => Some(self.strcpy(memory, args[0], args[1])?),
                HostImportKind::Strncpy => Some(self.strncpy(memory, args[0], args[1], args[2])?),
                HostImportKind::Strcat => Some(self.strcat(memory, args[0], args[1])?),
                HostImportKind::Strchr => Some(self.strchr(memory, args[0], args[1])?),
                HostImportKind::Strrchr => Some(self.strrchr(memory, args[0], args[1])?),
                HostImportKind::Strdup => Some(self.strdup(memory, args[0])?),
                HostImportKind::Cxx(kind) => proxy_cxx_import(kind, memory, args),
                HostImportKind::OpenDir => Some(self.opendir_path(memory, args[0])?),
                HostImportKind::FdOpenDir => Some(self.fdopendir_fd(memory, args[0])?),
                HostImportKind::ReadDir => Some(self.readdir_handle(memory, args[0])?),
                HostImportKind::ReadDirR => {
                    Some(self.readdir_r_handle(memory, args[0], args[1], args[2])?)
                }
                HostImportKind::CloseDir => Some(self.closedir_handle(memory, args[0])?.into()),
                HostImportKind::DirFd => Some(self.dirfd_handle(args[0])?.into()),
                HostImportKind::RewindDir => Some(self.rewinddir_handle(args[0])?),
                HostImportKind::Telldir => Some(self.telldir_handle(args[0])?),
                HostImportKind::Seekdir => Some(self.seekdir_handle(args[0], args[1])?),
                HostImportKind::GetEntropy => {
                    Some(self.getentropy(memory, args[0], args[1] as usize)?.into())
                }
                HostImportKind::PthreadThreadingNp => Some(proxy_host_pthread_threading_np()),
                HostImportKind::PthreadSigmask => Some(proxy_guest_pthread_sigmask(
                    memory, args[0], args[1], args[2],
                )?),
                HostImportKind::NSGetExecutablePath => Some(proxy_guest_ns_get_executable_path(
                    memory, args[0], args[1],
                )?),
                HostImportKind::IsSetUGid => Some(host_call_value(0)),
                HostImportKind::Execl => {
                    Some(proxy_guest_execl(memory, "execl", args, stack_ptr, false)?)
                }
                HostImportKind::Execlp => {
                    Some(proxy_guest_execl(memory, "execlp", args, stack_ptr, true)?)
                }
                HostImportKind::Execv => Some(proxy_guest_execv(
                    memory, "execv", args[0], args[1], 0, false,
                )?),
                HostImportKind::Execve => Some(proxy_guest_execv(
                    memory, "execve", args[0], args[1], args[2], false,
                )?),
                HostImportKind::Execvp => Some(proxy_guest_execv(
                    memory, "execvp", args[0], args[1], 0, true,
                )?),
                HostImportKind::GetProgName => Some(host_call_value(
                    memory
                        .guest_program_name_ptr()
                        .or_else(|| memory.guest_executable_path_ptr())
                        .unwrap_or(0),
                )),
                HostImportKind::SetProgName => {
                    let _ = memory.set_guest_program_name_ptr(args[0]);
                    Some(host_call_value(0))
                }
                HostImportKind::DyldImageCount => Some(host_call_value(1)),
                HostImportKind::DyldGetImageName => {
                    Some(proxy_guest_dyld_get_image_name(memory, args[0]))
                }
                HostImportKind::DyldGetImageHeader => {
                    Some(proxy_guest_dyld_get_image_header(memory, args[0]))
                }
                HostImportKind::DyldGetImageVmaddrSlide => {
                    Some(proxy_guest_dyld_get_image_vmaddr_slide(memory, args[0]))
                }
                HostImportKind::Dladdr => Some(proxy_guest_dladdr(memory, args[0], args[1])?),
                HostImportKind::PthreadOnce => {
                    Some(proxy_guest_pthread_once(memory, args[0], args[1])?)
                }
                HostImportKind::PthreadMutexAttrInit => {
                    Some(proxy_guest_pthread_attr_init(memory, args[0], 16)?)
                }
                HostImportKind::PthreadMutexAttrSetType => Some(host_call_value(0)),
                HostImportKind::PthreadMutexAttrDestroy => {
                    Some(proxy_guest_pthread_attr_destroy(memory, args[0], 16)?)
                }
                HostImportKind::PthreadAttrInit => {
                    Some(proxy_guest_pthread_attr_init(memory, args[0], 64)?)
                }
                HostImportKind::PthreadAttrDestroy => {
                    Some(proxy_guest_pthread_attr_destroy(memory, args[0], 64)?)
                }
                HostImportKind::PthreadAttrGetStackSize => {
                    Some(proxy_guest_pthread_attr_getstacksize(memory, args[1])?)
                }
                HostImportKind::PthreadAttrSetStackSize => Some(host_call_value(0)),
                HostImportKind::PthreadAttrSetDetachState => Some(host_call_value(0)),
                HostImportKind::OsUnfairLockLock => {
                    Some(proxy_guest_os_unfair_lock_lock(memory, args[0], false)?)
                }
                HostImportKind::OsUnfairLockTryLock => {
                    Some(proxy_guest_os_unfair_lock_lock(memory, args[0], true)?)
                }
                HostImportKind::OsUnfairLockUnlock => {
                    Some(proxy_guest_os_unfair_lock_unlock(memory, args[0])?)
                }
                HostImportKind::OsUnfairLockAssertOwner
                | HostImportKind::OsUnfairLockAssertNotOwner => Some(host_call_value(0)),
            };
            let mut log_arg_pairs = args
                .iter()
                .enumerate()
                .map(|(idx, value)| (format!("x{idx}"), hex_arg(*value)))
                .collect::<Vec<_>>();
            if let Some(stack_ptr) = stack_ptr {
                log_arg_pairs.push(("sp".to_string(), hex_arg(stack_ptr)));
            }
            if matches!(kind, HostImportKind::Connect) {
                for (name, value) in sockaddr_log_fields(memory, args[1], args[2]) {
                    log_arg_pairs.push((name.to_string(), value));
                }
            }
            let log_args = log_arg_pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.clone()))
                .collect::<Vec<_>>();
            log_scope.call_result("import", symbol, &log_args, &result);
            result
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, symbol, args, stack_ptr);
            None
        }
    }

    pub fn open_path_arg0<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_open_arg0(memory, path_ptr, flags, mode);
            let log_args = [
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "open", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, flags, mode);
            let result = None;
            let log_args = [
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "open", &log_args, &result);
            result
        }
    }

    pub fn open_path_arm64<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        flags: u64,
        register_mode: u64,
        stack_ptr: Option<u64>,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let mode = arm64_variadic_open_mode(memory, flags, register_mode, stack_ptr);
            let result = proxy_host_open_arg0(memory, path_ptr, flags, mode);
            let mut log_args = vec![
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
                ("register_mode", hex_arg(register_mode)),
            ];
            if let Some(stack_ptr) = stack_ptr {
                log_args.push(("sp", hex_arg(stack_ptr)));
            }
            log_scope.open_result("direct", "open", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, flags, register_mode, stack_ptr);
            let result = None;
            let mut log_args = vec![
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("register_mode", hex_arg(register_mode)),
            ];
            if let Some(stack_ptr) = stack_ptr {
                log_args.push(("sp", hex_arg(stack_ptr)));
            }
            log_scope.open_result("direct", "open", &log_args, &result);
            result
        }
    }

    pub fn openat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_openat(memory, dirfd, path_ptr, flags, mode);
            let log_args = [
                ("dirfd", dirfd.to_string()),
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "openat", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, flags, mode);
            let result = None;
            let log_args = [
                ("dirfd", dirfd.to_string()),
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "openat", &log_args, &result);
            result
        }
    }

    pub fn read_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_read(memory, fd, buf_ptr, count);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "read", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "read", &log_args, &result);
            result
        }
    }

    pub fn write_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_write(memory, fd, buf_ptr, count);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "write", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "write", &log_args, &result);
            result
        }
    }

    pub fn close_fd(&self, fd: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_close(fd);
            let log_args = [("fd", fd.to_string())];
            log_scope.io_result("direct", "close", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            let result = None;
            let log_args = [("fd", fd.to_string())];
            log_scope.io_result("direct", "close", &log_args, &result);
            result
        }
    }

    pub fn socket(&self, domain: u64, kind: u64, protocol: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_socket(domain, kind, protocol);
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
            ];
            log_scope.io_result("direct", "socket", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (domain, kind, protocol);
            let result = None;
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
            ];
            log_scope.io_result("direct", "socket", &log_args, &result);
            result
        }
    }

    pub fn connect_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_connect(memory, fd, sockaddr_ptr, sockaddr_len);
            let mut log_args = vec![
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_args.extend(sockaddr_log_fields(memory, sockaddr_ptr, sockaddr_len));
            log_scope.io_result("direct", "connect", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "connect", &log_args, &result);
            result
        }
    }

    pub fn bind_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_bind(memory, fd, sockaddr_ptr, sockaddr_len);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "bind", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "bind", &log_args, &result);
            result
        }
    }

    pub fn listen_socket(&self, fd: u64, backlog: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_listen(fd, backlog);
            let log_args = [("fd", fd.to_string()), ("backlog", backlog.to_string())];
            log_scope.io_result("direct", "listen", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, backlog);
            let result = None;
            let log_args = [("fd", fd.to_string()), ("backlog", backlog.to_string())];
            log_scope.io_result("direct", "listen", &log_args, &result);
            result
        }
    }

    pub fn send_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_send(memory, fd, buf_ptr, count, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "send", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "send", &log_args, &result);
            result
        }
    }

    pub fn recv_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recv(memory, fd, buf_ptr, count, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recv", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recv", &log_args, &result);
            result
        }
    }

    pub fn sendto_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_sendto(
                memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "sendto", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "sendto", &log_args, &result);
            result
        }
    }

    pub fn recvfrom_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recvfrom(
                memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len_ptr,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "recvfrom", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len_ptr,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "recvfrom", &log_args, &result);
            result
        }
    }

    pub fn sendmsg_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_sendmsg(memory, fd, msg_ptr, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "sendmsg", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, msg_ptr, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "sendmsg", &log_args, &result);
            result
        }
    }

    pub fn recvmsg_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recvmsg(memory, fd, msg_ptr, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recvmsg", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, msg_ptr, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recvmsg", &log_args, &result);
            result
        }
    }

    pub fn shutdown_socket(&self, fd: u64, how: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_shutdown(fd, how);
            let log_args = [("fd", fd.to_string()), ("how", how.to_string())];
            log_scope.io_result("direct", "shutdown", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, how);
            let result = None;
            let log_args = [("fd", fd.to_string()), ("how", how.to_string())];
            log_scope.io_result("direct", "shutdown", &log_args, &result);
            result
        }
    }

    pub fn setsockopt_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result =
                proxy_host_setsockopt(memory, fd, level, option_name, option_value_ptr, option_len);
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len", option_len.to_string()),
            ];
            log_scope.io_result("direct", "setsockopt", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len", option_len.to_string()),
            ];
            log_scope.io_result("direct", "setsockopt", &log_args, &result);
            result
        }
    }

    pub fn getsockopt_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getsockopt(
                memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len_ptr,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len_ptr", hex_arg(option_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockopt", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len_ptr,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len_ptr", hex_arg(option_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockopt", &log_args, &result);
            result
        }
    }

    pub fn accept_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_accept(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "accept", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "accept", &log_args, &result);
            result
        }
    }

    pub fn getpeername_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getpeername(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getpeername", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getpeername", &log_args, &result);
            result
        }
    }

    pub fn getsockname_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getsockname(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockname", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockname", &log_args, &result);
            result
        }
    }

    pub fn socketpair<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        domain: u64,
        kind: u64,
        protocol: u64,
        sv_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_socketpair(memory, domain, kind, protocol, sv_ptr);
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
                ("sv", hex_arg(sv_ptr)),
            ];
            log_scope.io_result("direct", "socketpair", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, domain, kind, protocol, sv_ptr);
            let result = None;
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
                ("sv", hex_arg(sv_ptr)),
            ];
            log_scope.io_result("direct", "socketpair", &log_args, &result);
            result
        }
    }

    pub fn fcntl_fd(&self, fd: u64, cmd: u64, arg: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fcntl(fd, cmd, arg);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, cmd, arg);
            None
        }
    }

    pub fn ioctl_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        request: u64,
        data_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ioctl(memory, fd, request, data_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, request, data_ptr);
            None
        }
    }

    pub fn fsync_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fsync(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn poll_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fds_ptr: u64,
        nfds: u64,
        timeout: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_poll(memory, fds_ptr, nfds, timeout);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fds_ptr, nfds, timeout);
            None
        }
    }

    pub fn readv_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readv(memory, fd, iov_ptr, iovcnt);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, iov_ptr, iovcnt);
            None
        }
    }

    pub fn writev_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_writev(memory, fd, iov_ptr, iovcnt);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, iov_ptr, iovcnt);
            None
        }
    }

    pub fn pread_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_pread(memory, fd, buf_ptr, count, offset);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, offset);
            None
        }
    }

    pub fn pwrite_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_pwrite(memory, fd, buf_ptr, count, offset);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, offset);
            None
        }
    }

    pub fn lseek_fd(&self, fd: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_lseek(fd, offset, whence);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, offset, whence);
            None
        }
    }

    pub fn dup_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dup(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn dup2_fd(&self, from: u64, to: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dup2(from, to);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (from, to);
            None
        }
    }

    pub fn pipe_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fds_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_pipe(memory, fds_ptr);
            let log_args = [("fds_ptr", hex_arg(fds_ptr))];
            log_scope.io_result("direct", "pipe", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fds_ptr);
            let result = None;
            let log_args = [("fds_ptr", hex_arg(fds_ptr))];
            log_scope.io_result("direct", "pipe", &log_args, &result);
            result
        }
    }

    pub fn pipe_pair(&self) -> Option<HostPipeResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_pipe_pair();
            log_scope.pipe_result("direct", "pipe_pair", &[], &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let result = None;
            log_scope.pipe_result("direct", "pipe_pair", &[], &result);
            result
        }
    }

    pub fn select_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        nfds: u64,
        readfds_ptr: u64,
        writefds_ptr: u64,
        exceptfds_ptr: u64,
        timeout_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_select(
                memory,
                nfds,
                readfds_ptr,
                writefds_ptr,
                exceptfds_ptr,
                timeout_ptr,
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                nfds,
                readfds_ptr,
                writefds_ptr,
                exceptfds_ptr,
                timeout_ptr,
            );
            None
        }
    }

    pub fn access_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_access(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn faccessat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_faccessat(memory, dirfd, path_ptr, mode, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode, flags);
            None
        }
    }

    pub fn chmod_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_chmod(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn fchmod_fd(&self, fd: u64, mode: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchmod(fd, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, mode);
            None
        }
    }

    pub fn fchmodat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchmodat(memory, dirfd, path_ptr, mode, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode, flags);
            None
        }
    }

    pub fn chdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_chdir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn fchdir_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchdir(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn getcwd_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getcwd(memory, buf_ptr, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size);
            None
        }
    }

    pub fn stat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_stat(memory, path_ptr, stat_ptr, true);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, stat_ptr);
            None
        }
    }

    pub fn lstat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_stat(memory, path_ptr, stat_ptr, false);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, stat_ptr);
            None
        }
    }

    pub fn fstat_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstat(memory, fd, stat_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, stat_ptr);
            None
        }
    }

    pub fn fstatat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        stat_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstatat(memory, dirfd, path_ptr, stat_ptr, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, stat_ptr, flags);
            None
        }
    }

    pub fn statfs_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        buf_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_statfs(memory, path_ptr, buf_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, buf_ptr);
            None
        }
    }

    pub fn fstatfs_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstatfs(memory, fd, buf_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr);
            None
        }
    }

    pub fn truncate_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        length: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_truncate(memory, path_ptr, length);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, length);
            None
        }
    }

    pub fn ftruncate_fd(&self, fd: u64, length: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ftruncate(fd, length);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, length);
            None
        }
    }

    pub fn mkdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_mkdir(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn mkdirat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_mkdirat(memory, dirfd, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode);
            None
        }
    }

    pub fn rmdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rmdir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn unlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_unlink(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn unlinkat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_unlinkat(memory, dirfd, path_ptr, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, flags);
            None
        }
    }

    pub fn rename_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        from_ptr: u64,
        to_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rename(memory, from_ptr, to_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, from_ptr, to_ptr);
            None
        }
    }

    pub fn renameat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fromfd: u64,
        from_ptr: u64,
        tofd: u64,
        to_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_renameat(memory, fromfd, from_ptr, tofd, to_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fromfd, from_ptr, tofd, to_ptr);
            None
        }
    }

    pub fn readlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readlink(memory, path_ptr, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, buf_ptr, count);
            None
        }
    }

    pub fn readlinkat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readlinkat(memory, dirfd, path_ptr, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, buf_ptr, count);
            None
        }
    }

    pub fn symlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        target_ptr: u64,
        link_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_symlink(memory, target_ptr, link_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, target_ptr, link_ptr);
            None
        }
    }

    pub fn realpath_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        resolved_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_realpath(memory, path_ptr, resolved_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, resolved_ptr);
            None
        }
    }

    pub fn getaddrinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        node_ptr: u64,
        service_ptr: u64,
        hints_ptr: u64,
        result_ptr: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result =
                proxy_host_getaddrinfo(memory, node_ptr, service_ptr, hints_ptr, result_ptr);
            let log_args = [
                ("node", hex_arg(node_ptr)),
                ("service", hex_arg(service_ptr)),
                ("hints", hex_arg(hints_ptr)),
                ("result_ptr", hex_arg(result_ptr)),
            ];
            log_scope.call_result("direct", "getaddrinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, node_ptr, service_ptr, hints_ptr, result_ptr);
            let result = None;
            let log_args = [
                ("node", hex_arg(node_ptr)),
                ("service", hex_arg(service_ptr)),
                ("hints", hex_arg(hints_ptr)),
                ("result_ptr", hex_arg(result_ptr)),
            ];
            log_scope.call_result("direct", "getaddrinfo", &log_args, &result);
            result
        }
    }

    pub fn freeaddrinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        addrinfo_ptr: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_freeaddrinfo(memory, addrinfo_ptr);
            let log_args = [("addrinfo", hex_arg(addrinfo_ptr))];
            log_scope.call_result("direct", "freeaddrinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, addrinfo_ptr);
            let result = None;
            let log_args = [("addrinfo", hex_arg(addrinfo_ptr))];
            log_scope.call_result("direct", "freeaddrinfo", &log_args, &result);
            result
        }
    }

    pub fn gai_strerror<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        errcode: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_gai_strerror(memory, errcode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, errcode);
            None
        }
    }

    pub fn getnameinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
        host_ptr: u64,
        host_len: u64,
        service_ptr: u64,
        service_len: u64,
        flags: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getnameinfo(
                memory,
                sockaddr_ptr,
                sockaddr_len,
                host_ptr,
                host_len,
                service_ptr,
                service_len,
                flags,
            );
            let log_args = [
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
                ("host", hex_arg(host_ptr)),
                ("host_len", host_len.to_string()),
                ("service", hex_arg(service_ptr)),
                ("service_len", service_len.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.call_result("direct", "getnameinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                sockaddr_ptr,
                sockaddr_len,
                host_ptr,
                host_len,
                service_ptr,
                service_len,
                flags,
            );
            let result = None;
            let log_args = [
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
                ("host", hex_arg(host_ptr)),
                ("host_len", host_len.to_string()),
                ("service", hex_arg(service_ptr)),
                ("service_len", service_len.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.call_result("direct", "getnameinfo", &log_args, &result);
            result
        }
    }

    pub fn inet_pton<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        family: u64,
        src_ptr: u64,
        dst_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_pton(memory, family, src_ptr, dst_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, family, src_ptr, dst_ptr);
            None
        }
    }

    pub fn inet_ntop<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        family: u64,
        src_ptr: u64,
        dst_ptr: u64,
        dst_len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_ntop(memory, family, src_ptr, dst_ptr, dst_len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, family, src_ptr, dst_ptr, dst_len);
            None
        }
    }

    pub fn inet_addr<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        src_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_addr(memory, src_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, src_ptr);
            None
        }
    }

    pub fn inet_aton<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        src_ptr: u64,
        dst_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_aton(memory, src_ptr, dst_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, src_ptr, dst_ptr);
            None
        }
    }

    pub fn getenv<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getenv(memory, name_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr);
            None
        }
    }

    pub fn setenv_var<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
        value_ptr: u64,
        overwrite: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_setenv(memory, name_ptr, value_ptr, overwrite);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr, value_ptr, overwrite);
            None
        }
    }

    pub fn unsetenv_var<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_unsetenv(memory, name_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr);
            None
        }
    }

    pub fn getpid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::getpid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn getppid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::getppid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn getuid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::getuid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn geteuid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::geteuid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn getgid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::getgid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn getegid(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return Some(host_call_value(unsafe { libc::getegid() } as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn sysconf(&self, name: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_sysconf(name);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = name;
            None
        }
    }

    pub fn getpagesize(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_sysconf(libc::_SC_PAGESIZE as u64);
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn gethostname<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
        len: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_gethostname(memory, name_ptr, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr, len);
            None
        }
    }

    pub fn uname<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        uts_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_uname(memory, uts_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, uts_ptr);
            None
        }
    }

    pub fn gettimeofday<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        tv_ptr: u64,
        tz_ptr: u64,
        mach_absolute_time_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_gettimeofday(memory, tv_ptr, tz_ptr, mach_absolute_time_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, tv_ptr, tz_ptr, mach_absolute_time_ptr);
            None
        }
    }

    pub fn clock_gettime<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        clock_id: u64,
        tp_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_clock_gettime(memory, clock_id, tp_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, clock_id, tp_ptr);
            None
        }
    }

    pub fn nanosleep<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        req_ptr: u64,
        rem_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_nanosleep(memory, req_ptr, rem_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, req_ptr, rem_ptr);
            None
        }
    }

    pub fn sleep_seconds(&self, seconds: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            clear_errno();
            let ret = unsafe { libc::sleep(seconds as libc::c_uint) };
            return Some(host_call_value(ret as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = seconds;
            None
        }
    }

    pub fn usleep_usecs(&self, usecs: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            clear_errno();
            let ret = unsafe { libc::usleep(usecs as libc::useconds_t) };
            return Some(host_io_result(ret as isize, Vec::new()));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = usecs;
            None
        }
    }

    pub fn mach_absolute_time(&self) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            #[allow(deprecated)]
            let value = unsafe { libc::mach_absolute_time() };
            return Some(host_call_value(value));
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn mach_timebase_info<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        info_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_mach_timebase_info(memory, info_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, info_ptr);
            None
        }
    }

    pub fn getrlimit<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        resource: u64,
        rlp_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getrlimit(memory, resource, rlp_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, resource, rlp_ptr);
            None
        }
    }

    pub fn setrlimit<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        resource: u64,
        rlp_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_setrlimit(memory, resource, rlp_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, resource, rlp_ptr);
            None
        }
    }

    pub fn sysctl<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
        namelen: u64,
        oldp: u64,
        oldlenp: u64,
        newp: u64,
        newlen: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_sysctl(memory, name_ptr, namelen, oldp, oldlenp, newp, newlen);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr, namelen, oldp, oldlenp, newp, newlen);
            None
        }
    }

    pub fn sysctlbyname<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
        oldp: u64,
        oldlenp: u64,
        newp: u64,
        newlen: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_sysctlbyname(memory, name_ptr, oldp, oldlenp, newp, newlen);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr, oldp, oldlenp, newp, newlen);
            None
        }
    }

    pub fn umask(&self, mask: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            let ret = unsafe { libc::umask(mask as libc::mode_t) };
            return Some(host_call_value(ret as u64));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = mask;
            None
        }
    }

    pub fn fopen_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fopen(memory, path_ptr, mode_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode_ptr);
            None
        }
    }

    pub fn fdopen_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        mode_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fdopen(memory, fd, mode_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, mode_ptr);
            None
        }
    }

    pub fn fclose_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fclose(memory, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, stream);
            None
        }
    }

    pub fn fread_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        nmemb: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fread(memory, buf_ptr, size, nmemb, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, nmemb, stream);
            None
        }
    }

    pub fn fwrite_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        nmemb: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fwrite(memory, buf_ptr, size, nmemb, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, nmemb, stream);
            None
        }
    }

    pub fn fflush_stream(&self, stream: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fflush(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fseek_stream(&self, stream: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fseek(stream, offset, whence);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (stream, offset, whence);
            None
        }
    }

    pub fn ftell_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ftell(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fgets_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        stream: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fgets(memory, buf_ptr, size, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, stream);
            None
        }
    }

    pub fn fputs_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        text_ptr: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fputs(memory, text_ptr, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, text_ptr, stream);
            None
        }
    }

    pub fn feof_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_feof(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn ferror_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ferror(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn clearerr_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_clearerr(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fileno_stream(&self, stream: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fileno(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn malloc<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_malloc(memory, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, size);
            None
        }
    }

    pub fn calloc<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        nmemb: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_calloc(memory, nmemb, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, nmemb, size);
            None
        }
    }

    pub fn realloc<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        ptr: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_realloc(memory, ptr, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, ptr, size);
            None
        }
    }

    pub fn free<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_free(memory, ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, ptr);
            None
        }
    }

    pub fn posix_memalign<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        memptr_ptr: u64,
        alignment: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_posix_memalign(memory, memptr_ptr, alignment, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, memptr_ptr, alignment, size);
            None
        }
    }

    pub fn memcpy<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        src: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_memcpy(memory, dst, src, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, src, len);
            None
        }
    }

    pub fn memmove<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        src: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_memcpy(memory, dst, src, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, src, len);
            None
        }
    }

    pub fn memset<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        value: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_memset(memory, dst, value, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, value, len);
            None
        }
    }

    pub fn memcmp<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        left: u64,
        right: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_memcmp(memory, left, right, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, left, right, len);
            None
        }
    }

    pub fn strlen<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        str_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strlen(memory, str_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, str_ptr);
            None
        }
    }

    pub fn strcmp<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        left: u64,
        right: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strcmp(memory, left, right);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, left, right);
            None
        }
    }

    pub fn strncmp<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        left: u64,
        right: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strncmp(memory, left, right, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, left, right, len);
            None
        }
    }

    pub fn strcpy<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        src: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strcpy(memory, dst, src);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, src);
            None
        }
    }

    pub fn strncpy<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        src: u64,
        len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strncpy(memory, dst, src, len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, src, len);
            None
        }
    }

    pub fn strcat<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dst: u64,
        src: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strcat(memory, dst, src);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dst, src);
            None
        }
    }

    pub fn strchr<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        str_ptr: u64,
        needle: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strchr(memory, str_ptr, needle, false);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, str_ptr, needle);
            None
        }
    }

    pub fn strrchr<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        str_ptr: u64,
        needle: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strchr(memory, str_ptr, needle, true);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, str_ptr, needle);
            None
        }
    }

    pub fn strdup<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        str_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_guest_strdup(memory, str_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, str_ptr);
            None
        }
    }

    pub fn opendir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_opendir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn fdopendir_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fdopendir(memory, fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd);
            None
        }
    }

    pub fn readdir_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readdir(memory, dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp);
            None
        }
    }

    pub fn readdir_r_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
        entry_ptr: u64,
        result_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readdir_r(memory, dirp, entry_ptr, result_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp, entry_ptr, result_ptr);
            None
        }
    }

    pub fn closedir_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_closedir(memory, dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp);
            None
        }
    }

    pub fn dirfd_handle(&self, dirp: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dirfd(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn rewinddir_handle(&self, dirp: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rewinddir(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn telldir_handle(&self, dirp: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_telldir(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn seekdir_handle(&self, dirp: u64, loc: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_seekdir(dirp, loc);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (dirp, loc);
            None
        }
    }

    pub fn getentropy<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getentropy(memory, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, count);
            None
        }
    }
}

#[cfg(target_os = "macos")]
impl From<HostIoResult> for HostCallResult {
    fn from(value: HostIoResult) -> Self {
        Self {
            return_value: value.return_value,
            errno: Some(value.errno),
        }
    }
}

#[cfg(target_os = "macos")]
type PthreadThreadingNpFn = unsafe extern "C" fn() -> libc::c_int;

#[cfg(target_os = "macos")]
fn host_pthread_threading_np_fn() -> Option<PthreadThreadingNpFn> {
    static SYMBOL: OnceLock<Option<PthreadThreadingNpFn>> = OnceLock::new();
    *SYMBOL.get_or_init(|| {
        let symbol = CString::new("pthread_threading_np").ok()?;
        let ptr = unsafe { libc::dlsym((-2isize) as *mut libc::c_void, symbol.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { mem::transmute::<*mut libc::c_void, PthreadThreadingNpFn>(ptr) })
        }
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_pthread_threading_np() -> HostCallResult {
    let return_value = host_pthread_threading_np_fn()
        .map(|func| unsafe { func() as i64 as u64 })
        .unwrap_or(1);
    HostCallResult {
        return_value,
        errno: None,
    }
}

#[cfg(target_os = "macos")]
fn proxy_cxx_import<M: GuestMemory + ?Sized>(
    kind: CxxImportKind,
    memory: &mut M,
    args: &[u64; 8],
) -> Option<HostCallResult> {
    match kind {
        CxxImportKind::LibcppNextPrime => Some(proxy_libcpp_next_prime(args[0])),
        CxxImportKind::CxaGuardAcquire => Some(proxy_guest_cxa_guard_acquire(memory, args[0])?),
        CxxImportKind::CxaGuardRelease => Some(proxy_guest_cxa_guard_release(memory, args[0])?),
        CxxImportKind::CxaGuardAbort => Some(proxy_guest_cxa_guard_abort(memory, args[0])?),
        _ => cxx::proxy_import(kind, memory, args),
    }
}

#[cfg(target_os = "macos")]
type LibcppNextPrimeFn = unsafe extern "C" fn(libc::c_ulong) -> libc::c_ulong;

#[cfg(target_os = "macos")]
fn host_libcpp_next_prime_fn() -> Option<LibcppNextPrimeFn> {
    static SYMBOL: OnceLock<Option<LibcppNextPrimeFn>> = OnceLock::new();
    *SYMBOL.get_or_init(|| {
        let symbol_names = [
            CString::new("_ZNSt3__112__next_primeEm").ok()?,
            CString::new("__ZNSt3__112__next_primeEm").ok()?,
        ];
        let default_handle = (-2isize) as *mut libc::c_void;
        for symbol in &symbol_names {
            let ptr = unsafe { libc::dlsym(default_handle, symbol.as_ptr()) };
            if !ptr.is_null() {
                return Some(unsafe {
                    mem::transmute::<*mut libc::c_void, LibcppNextPrimeFn>(ptr)
                });
            }
        }

        let path = CString::new("/usr/lib/libc++.1.dylib").ok()?;
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return None;
        }
        for symbol in &symbol_names {
            let ptr = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
            if !ptr.is_null() {
                return Some(unsafe {
                    mem::transmute::<*mut libc::c_void, LibcppNextPrimeFn>(ptr)
                });
            }
        }
        None
    })
}

#[cfg(target_os = "macos")]
fn proxy_libcpp_next_prime(value: u64) -> HostCallResult {
    let host_value = libc::c_ulong::try_from(value)
        .ok()
        .and_then(|value| host_libcpp_next_prime_fn().map(|func| unsafe { func(value) as u64 }));
    let (return_value, source) = host_value
        .map(|value| (value, "host-libc++"))
        .unwrap_or_else(|| (compat_next_prime(value), "compat-fallback"));
    let mut fields = [
        ("Source", Some(source.to_string())),
        ("Result", Some(return_value.to_string())),
    ];
    emit_verbose_compat_payload(
        "cxx",
        "__next_prime",
        &[("Value", value.to_string())],
        &mut fields,
        None,
    );
    host_call_value(return_value)
}

#[cfg(any(target_os = "macos", test))]
fn compat_next_prime(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    if value <= 2 {
        return 2;
    }
    let mut candidate = value;
    if candidate % 2 == 0 {
        candidate = candidate.saturating_add(1);
    }
    while !compat_is_prime(candidate) {
        let Some(next) = candidate.checked_add(2) else {
            return u64::MAX;
        };
        candidate = next;
    }
    candidate
}

#[cfg(any(target_os = "macos", test))]
fn compat_is_prime(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    if value % 2 == 0 {
        return value == 2;
    }
    let mut divisor = 3u64;
    while divisor <= value / divisor {
        if value % divisor == 0 {
            return false;
        }
        divisor += 2;
    }
    true
}

#[cfg(target_os = "macos")]
const CXA_GUARD_SIZE: usize = 8;
#[cfg(target_os = "macos")]
const CXA_GUARD_INITIALIZED_BYTE: usize = 0;
#[cfg(target_os = "macos")]
const CXA_GUARD_IN_USE_BYTE: usize = 1;

#[cfg(target_os = "macos")]
fn read_guest_cxa_guard<M: GuestMemory + ?Sized>(
    memory: &mut M,
    guard_ptr: u64,
) -> Result<[u8; CXA_GUARD_SIZE], GuestMemoryError> {
    let bytes = memory.read_memory(guard_ptr, CXA_GUARD_SIZE)?;
    <[u8; CXA_GUARD_SIZE]>::try_from(bytes.as_slice()).map_err(|_| GuestMemoryError)
}

#[cfg(target_os = "macos")]
fn emit_verbose_cxa_guard(
    call: &str,
    guard_ptr: u64,
    before: &[u8; CXA_GUARD_SIZE],
    after: &[u8; CXA_GUARD_SIZE],
    return_value: u64,
) {
    let mut fields = [
        ("BeforeHex", Some(compat_preview_hex(before))),
        ("AfterHex", Some(compat_preview_hex(after))),
        ("Result", Some(return_value.to_string())),
    ];
    emit_verbose_compat_payload(
        "cxx",
        call,
        &[("guard", hex_arg(guard_ptr))],
        &mut fields,
        None,
    );
}

#[cfg(target_os = "macos")]
fn proxy_guest_cxa_guard_acquire<M: GuestMemory + ?Sized>(
    memory: &mut M,
    guard_ptr: u64,
) -> Option<HostCallResult> {
    if guard_ptr == 0 {
        return Some(host_call_value(0));
    }
    let Ok(before) = read_guest_cxa_guard(memory, guard_ptr) else {
        return Some(host_call_value(0));
    };
    let mut after = before;
    let return_value = if before[CXA_GUARD_INITIALIZED_BYTE] & 1 != 0 {
        0
    } else if before[CXA_GUARD_IN_USE_BYTE] != 0 {
        0
    } else {
        after[CXA_GUARD_IN_USE_BYTE] = 1;
        if memory.write_memory(guard_ptr, &after).is_err() {
            return Some(host_call_value(0));
        }
        1
    };
    emit_verbose_cxa_guard(
        "__cxa_guard_acquire",
        guard_ptr,
        &before,
        &after,
        return_value,
    );
    Some(host_call_value(return_value))
}

#[cfg(target_os = "macos")]
fn proxy_guest_cxa_guard_release<M: GuestMemory + ?Sized>(
    memory: &mut M,
    guard_ptr: u64,
) -> Option<HostCallResult> {
    if guard_ptr == 0 {
        return Some(host_call_value(0));
    }
    let before = read_guest_cxa_guard(memory, guard_ptr).unwrap_or([0u8; CXA_GUARD_SIZE]);
    let mut after = before;
    after[CXA_GUARD_INITIALIZED_BYTE] = 1;
    after[CXA_GUARD_IN_USE_BYTE] = 0;
    let _ = memory.write_memory(guard_ptr, &after);
    emit_verbose_cxa_guard("__cxa_guard_release", guard_ptr, &before, &after, 0);
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_cxa_guard_abort<M: GuestMemory + ?Sized>(
    memory: &mut M,
    guard_ptr: u64,
) -> Option<HostCallResult> {
    if guard_ptr == 0 {
        return Some(host_call_value(0));
    }
    let before = read_guest_cxa_guard(memory, guard_ptr).unwrap_or([0u8; CXA_GUARD_SIZE]);
    let mut after = before;
    after[CXA_GUARD_IN_USE_BYTE] = 0;
    let _ = memory.write_memory(guard_ptr, &after);
    emit_verbose_cxa_guard("__cxa_guard_abort", guard_ptr, &before, &after, 0);
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
const DARWIN_SIGSET_T_SIZE: usize = 4;

#[cfg(target_os = "macos")]
fn proxy_guest_pthread_sigmask<M: GuestMemory + ?Sized>(
    memory: &mut M,
    how: u64,
    set_ptr: u64,
    oldset_ptr: u64,
) -> Option<HostCallResult> {
    if oldset_ptr != 0
        && memory
            .write_memory(oldset_ptr, &[0u8; DARWIN_SIGSET_T_SIZE])
            .is_err()
    {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    let mut fields = [
        ("Model", Some("guest-empty-mask".to_string())),
        ("OldSetBytes", Some(DARWIN_SIGSET_T_SIZE.to_string())),
    ];
    emit_verbose_compat_payload(
        "thread",
        "pthread_sigmask",
        &[
            ("how", how.to_string()),
            ("set", hex_arg(set_ptr)),
            ("oldset", hex_arg(oldset_ptr)),
        ],
        &mut fields,
        None,
    );
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_memory_lock(call: &str, addr: u64, len: u64) -> HostCallResult {
    let mut fields = [("Model", Some("guest-pointer-noop".to_string()))];
    emit_verbose_compat_payload(
        "memory",
        call,
        &[("addr", hex_arg(addr)), ("len", len.to_string())],
        &mut fields,
        None,
    );
    host_call_value(0)
}

#[cfg(target_os = "macos")]
fn proxy_guest_madvise(addr: u64, len: u64, advice: u64) -> HostCallResult {
    let mut fields = [("Model", Some("guest-pointer-noop".to_string()))];
    emit_verbose_compat_payload(
        "memory",
        "madvise",
        &[
            ("addr", hex_arg(addr)),
            ("len", len.to_string()),
            ("advice", advice.to_string()),
        ],
        &mut fields,
        None,
    );
    host_call_value(0)
}

#[cfg(target_os = "macos")]
fn proxy_guest_execl<M: GuestMemory + ?Sized>(
    memory: &mut M,
    call: &'static str,
    args: &[u64; 8],
    stack_ptr: Option<u64>,
    search_path: bool,
) -> Option<HostCallResult> {
    let path_ptr = args[0];
    let path = match read_cstring(memory, path_ptr, 4096) {
        Ok(path) => path,
        Err(_) => {
            emit_exec_model_log(
                call,
                vec![("path", hex_arg(path_ptr))],
                vec![
                    ("Path", Some(format!("<invalid:0x{path_ptr:X}>"))),
                    ("Model", Some("guest-read-error".to_string())),
                    ("Reason", Some("path pointer could not be read".to_string())),
                ],
                &host_call_error(libc::EFAULT as u32),
            );
            return Some(host_call_error(libc::EFAULT as u32));
        }
    };
    let argv = match read_execl_argv(memory, args, stack_ptr) {
        Ok(argv) => argv,
        Err(errno) => {
            emit_exec_model_log(
                call,
                vec![("path", hex_arg(path_ptr))],
                vec![
                    ("Path", Some(path)),
                    ("Model", Some("guest-read-error".to_string())),
                    ("Reason", Some("argv pointer could not be read".to_string())),
                ],
                &host_call_error(errno),
            );
            return Some(host_call_error(errno));
        }
    };
    let mut log_args = vec![("path", hex_arg(path_ptr))];
    if let Some(stack_ptr) = stack_ptr {
        log_args.push(("sp", hex_arg(stack_ptr)));
    }
    Some(proxy_guest_exec_request(
        call,
        log_args,
        path,
        argv,
        None,
        search_path,
    ))
}

#[cfg(target_os = "macos")]
fn proxy_guest_execv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    call: &'static str,
    path_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
    search_path: bool,
) -> Option<HostCallResult> {
    let path = match read_cstring(memory, path_ptr, 4096) {
        Ok(path) => path,
        Err(_) => {
            let result = host_call_error(libc::EFAULT as u32);
            emit_exec_model_log(
                call,
                vec![("path", hex_arg(path_ptr)), ("argv", hex_arg(argv_ptr))],
                vec![
                    ("Path", Some(format!("<invalid:0x{path_ptr:X}>"))),
                    ("Model", Some("guest-read-error".to_string())),
                    ("Reason", Some("path pointer could not be read".to_string())),
                ],
                &result,
            );
            return Some(result);
        }
    };
    let argv = match read_guest_cstring_array(memory, argv_ptr, 128) {
        Ok(argv) => argv,
        Err(errno) => {
            let result = host_call_error(errno);
            emit_exec_model_log(
                call,
                vec![("path", hex_arg(path_ptr)), ("argv", hex_arg(argv_ptr))],
                vec![
                    ("Path", Some(path)),
                    ("Model", Some("guest-read-error".to_string())),
                    ("Reason", Some("argv vector could not be read".to_string())),
                ],
                &result,
            );
            return Some(result);
        }
    };
    let env = if envp_ptr == 0 {
        None
    } else {
        match read_guest_env_array(memory, envp_ptr, 256) {
            Ok(env) => Some(env),
            Err(errno) => {
                let result = host_call_error(errno);
                emit_exec_model_log(
                    call,
                    vec![
                        ("path", hex_arg(path_ptr)),
                        ("argv", hex_arg(argv_ptr)),
                        ("envp", hex_arg(envp_ptr)),
                    ],
                    vec![
                        ("Path", Some(path)),
                        ("Model", Some("guest-read-error".to_string())),
                        ("Reason", Some("envp vector could not be read".to_string())),
                    ],
                    &result,
                );
                return Some(result);
            }
        }
    };
    let mut log_args = vec![("path", hex_arg(path_ptr)), ("argv", hex_arg(argv_ptr))];
    if envp_ptr != 0 {
        log_args.push(("envp", hex_arg(envp_ptr)));
    }
    Some(proxy_guest_exec_request(
        call,
        log_args,
        path,
        argv,
        env,
        search_path,
    ))
}

#[cfg(target_os = "macos")]
fn proxy_guest_exec_request(
    call: &'static str,
    log_args: Vec<(&'static str, String)>,
    path: String,
    mut argv: Vec<String>,
    env: Option<Vec<(String, String)>>,
    search_path: bool,
) -> HostCallResult {
    if argv.is_empty() {
        argv.push(path.clone());
    }
    let resolved_path = resolve_exec_path(&path, env.as_deref(), search_path);
    let mut fields = vec![
        ("Path", Some(path.clone())),
        ("ResolvedPath", Some(resolved_path.display().to_string())),
        ("Argc", Some(argv.len().to_string())),
        ("Argv", Some(argv.join("\u{1f}"))),
        (
            "EnvCount",
            env.as_ref()
                .map(|env| env.len().to_string())
                .or_else(|| (!matches!(call, "execve")).then(|| "inherit".to_string())),
        ),
        (
            "PathSearch",
            Some(if search_path { "1" } else { "0" }.to_string()),
        ),
    ];

    let result = match fs::metadata(&resolved_path) {
        Ok(metadata) if metadata.is_dir() => {
            fields.push(("Model", Some("path-error".to_string())));
            fields.push(("Reason", Some("target is a directory".to_string())));
            host_call_error(libc::EACCES as u32)
        }
        Ok(metadata) if metadata.mode() & 0o111 == 0 => {
            fields.push(("Model", Some("path-error".to_string())));
            fields.push(("Reason", Some("target is not executable".to_string())));
            host_call_error(libc::EACCES as u32)
        }
        Ok(_) => match spawn_exec_child(&resolved_path, &argv, env.as_deref()) {
            Ok(exit_status) => {
                fields.push(("Model", Some("spawn-wait-stop".to_string())));
                fields.push(("ExitStatus", Some(exit_status.to_string())));
                set_pending_stop_reason(format!(
                    "compat exec replaced guest image call={call} path={} status={exit_status}",
                    resolved_path.display()
                ));
                host_call_value(0)
            }
            Err((errno, reason)) => {
                fields.push(("Model", Some("spawn-error".to_string())));
                fields.push(("Reason", Some(reason)));
                host_call_error(errno)
            }
        },
        Err(error) => {
            let errno = io_error_errno(&error);
            fields.push(("Model", Some("path-error".to_string())));
            fields.push(("Reason", Some(error.to_string())));
            host_call_error(errno)
        }
    };
    emit_exec_model_log(call, log_args, fields, &result);
    result
}

#[cfg(target_os = "macos")]
fn emit_exec_model_log(
    call: &str,
    log_args: Vec<(&str, String)>,
    mut fields: Vec<(&str, Option<String>)>,
    result: &HostCallResult,
) {
    fields.push(("return", Some(format_return(result.return_value))));
    fields.push(("return_hex", Some(format!("0x{:X}", result.return_value))));
    fields.push(("errno", result.errno.map(|errno| errno.to_string())));
    emit_verbose_compat_payload("process", call, &log_args, &mut fields, None);
}

#[cfg(target_os = "macos")]
fn read_execl_argv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    args: &[u64; 8],
    stack_ptr: Option<u64>,
) -> Result<Vec<String>, u32> {
    let mut ptrs = args[1..].to_vec();
    if let Some(stack_ptr) = stack_ptr {
        ptrs.extend(read_stack_u64_args(memory, stack_ptr, 128));
    }
    read_cstring_pointer_list(memory, ptrs.into_iter(), 128)
}

#[cfg(target_os = "macos")]
fn read_guest_cstring_array<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    max_entries: usize,
) -> Result<Vec<String>, u32> {
    if ptr == 0 {
        return Err(libc::EFAULT as u32);
    }
    let mut ptrs = Vec::new();
    for index in 0..max_entries {
        let addr = ptr.saturating_add((index * 8) as u64);
        let bytes = memory
            .read_memory(addr, 8)
            .map_err(|_| libc::EFAULT as u32)?;
        let value = read_u64_at(&bytes, 0).ok_or(libc::EFAULT as u32)?;
        ptrs.push(value);
        if value == 0 {
            return read_cstring_pointer_list(memory, ptrs.into_iter(), max_entries);
        }
    }
    Err(libc::E2BIG as u32)
}

#[cfg(target_os = "macos")]
fn read_cstring_pointer_list<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptrs: impl Iterator<Item = u64>,
    max_entries: usize,
) -> Result<Vec<String>, u32> {
    let mut out = Vec::new();
    for ptr in ptrs.take(max_entries + 1) {
        if ptr == 0 {
            return Ok(out);
        }
        if out.len() >= max_entries {
            return Err(libc::E2BIG as u32);
        }
        out.push(read_cstring(memory, ptr, 4096).map_err(|_| libc::EFAULT as u32)?);
    }
    Err(libc::E2BIG as u32)
}

#[cfg(target_os = "macos")]
fn read_guest_env_array<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    max_entries: usize,
) -> Result<Vec<(String, String)>, u32> {
    let entries = read_guest_cstring_array(memory, ptr, max_entries)?;
    Ok(entries
        .into_iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(name, value)| (name.to_string(), value.to_string()))
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn resolve_exec_path(
    path: &str,
    env: Option<&[(String, String)]>,
    search_path: bool,
) -> std::path::PathBuf {
    if !search_path || path.contains('/') {
        return std::path::PathBuf::from(path);
    }
    let path_value = env
        .and_then(|env| {
            env.iter()
                .find(|(name, _)| name == "PATH")
                .map(|(_, value)| std::ffi::OsString::from(value))
        })
        .or_else(|| std::env::var_os("PATH"));
    if let Some(path_value) = path_value {
        for base in std::env::split_paths(&path_value) {
            let candidate = base.join(path);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    std::path::PathBuf::from(path)
}

#[cfg(target_os = "macos")]
fn spawn_exec_child(
    path: &std::path::Path,
    argv: &[String],
    env: Option<&[(String, String)]>,
) -> Result<i32, (u32, String)> {
    let mut command = Command::new(path);
    if let Some(arg0) = argv.first() {
        command.arg0(arg0);
    }
    command.args(argv.iter().skip(1));
    if let Some(env) = env {
        command.env_clear();
        for (name, value) in env {
            command.env(name, value);
        }
    }
    match command.status() {
        Ok(status) => Ok(status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(0)),
        Err(error) => Err((io_error_errno(&error), error.to_string())),
    }
}

#[cfg(target_os = "macos")]
const DEFAULT_GUEST_PTHREAD_STACK_SIZE: u64 = 0x20_0000;

#[cfg(target_os = "macos")]
fn host_call_minus_one() -> HostCallResult {
    HostCallResult {
        return_value: u64::MAX,
        errno: None,
    }
}

#[cfg(target_os = "macos")]
fn write_guest_cstring_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    bytes: &[u8],
) -> Result<(), GuestMemoryError> {
    let mut out = Vec::with_capacity(bytes.len().saturating_add(1));
    out.extend_from_slice(bytes);
    out.push(0);
    memory.write_memory(addr, &out)
}

#[cfg(target_os = "macos")]
fn allocate_guest_cstring<M: GuestMemory + ?Sized>(memory: &mut M, text: &str) -> Option<u64> {
    let len = text.len().saturating_add(1).max(1);
    let addr = memory.allocate_memory(len, 1).ok()?;
    write_guest_cstring_bytes(memory, addr, text.as_bytes()).ok()?;
    Some(addr)
}

#[cfg(target_os = "macos")]
fn guest_executable_path_ptr_or_alloc<M: GuestMemory + ?Sized>(memory: &mut M) -> Option<u64> {
    if let Some(ptr) = memory.guest_executable_path_ptr().filter(|ptr| *ptr != 0) {
        return Some(ptr);
    }
    let path = memory
        .guest_executable_path()
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "program".to_string());
    allocate_guest_cstring(memory, &path)
}

#[cfg(target_os = "macos")]
fn proxy_guest_ns_get_executable_path<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size_ptr: u64,
) -> Option<HostCallResult> {
    if size_ptr == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    let path = memory
        .guest_executable_path()
        .filter(|path| !path.is_empty())
        .or_else(|| {
            memory
                .guest_program_name_ptr()
                .and_then(|ptr| read_cstring(memory, ptr, 4096).ok())
        })
        .unwrap_or_else(|| "program".to_string());
    let required = path.len().saturating_add(1).min(u32::MAX as usize) as u32;
    let size_bytes = memory.read_memory(size_ptr, 4).ok()?;
    let capacity = read_u32_at(&size_bytes, 0)?;
    write_guest_u32(memory, size_ptr, required).ok()?;
    if buf_ptr == 0 || capacity < required {
        return Some(host_call_minus_one());
    }
    write_guest_cstring_bytes(memory, buf_ptr, path.as_bytes()).ok()?;
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_dyld_get_image_name<M: GuestMemory + ?Sized>(
    memory: &mut M,
    index: u64,
) -> HostCallResult {
    if index == 0 {
        host_call_value(guest_executable_path_ptr_or_alloc(memory).unwrap_or(0))
    } else {
        host_call_value(0)
    }
}

#[cfg(target_os = "macos")]
fn proxy_guest_dyld_get_image_header<M: GuestMemory + ?Sized>(
    memory: &mut M,
    index: u64,
) -> HostCallResult {
    host_call_value(
        (index == 0)
            .then(|| memory.guest_main_image_header())
            .flatten()
            .unwrap_or(0),
    )
}

#[cfg(target_os = "macos")]
fn proxy_guest_dyld_get_image_vmaddr_slide<M: GuestMemory + ?Sized>(
    memory: &mut M,
    index: u64,
) -> HostCallResult {
    if index == 0 {
        HostCallResult {
            return_value: memory.guest_main_image_slide() as u64,
            errno: None,
        }
    } else {
        host_call_value(0)
    }
}

#[cfg(target_os = "macos")]
fn proxy_guest_dladdr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    info_ptr: u64,
) -> Option<HostCallResult> {
    if addr == 0 || info_ptr == 0 {
        return Some(host_call_value(0));
    }
    let fname = guest_executable_path_ptr_or_alloc(memory).unwrap_or(0);
    let fbase = memory.guest_main_image_header().unwrap_or(0);
    if fname == 0 || fbase == 0 {
        return Some(host_call_value(0));
    }
    write_guest_u64(memory, info_ptr, fname).ok()?;
    write_guest_u64(memory, info_ptr + 8, fbase).ok()?;
    write_guest_u64(memory, info_ptr + 16, 0).ok()?;
    write_guest_u64(memory, info_ptr + 24, 0).ok()?;
    Some(host_call_value(1))
}

#[cfg(target_os = "macos")]
fn proxy_guest_pthread_once<M: GuestMemory + ?Sized>(
    memory: &mut M,
    once_ptr: u64,
    init_routine: u64,
) -> Option<HostCallResult> {
    if once_ptr == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    let state = memory
        .read_memory(once_ptr, 8)
        .ok()
        .and_then(|bytes| read_u64_at(&bytes, 0))
        .unwrap_or(0);
    if state == 0 {
        write_guest_u64(memory, once_ptr, 1).ok()?;
    }
    let _ = init_routine;
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_pthread_attr_init<M: GuestMemory + ?Sized>(
    memory: &mut M,
    attr_ptr: u64,
    size: usize,
) -> Option<HostCallResult> {
    if attr_ptr == 0 {
        return Some(host_call_error(libc::EINVAL as u32));
    }
    memory.write_memory(attr_ptr, &vec![0u8; size]).ok()?;
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_pthread_attr_destroy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    attr_ptr: u64,
    size: usize,
) -> Option<HostCallResult> {
    if attr_ptr != 0 {
        let _ = memory.write_memory(attr_ptr, &vec![0u8; size]);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_pthread_attr_getstacksize<M: GuestMemory + ?Sized>(
    memory: &mut M,
    size_ptr: u64,
) -> Option<HostCallResult> {
    if size_ptr == 0 {
        return Some(host_call_error(libc::EINVAL as u32));
    }
    write_guest_u64(memory, size_ptr, DEFAULT_GUEST_PTHREAD_STACK_SIZE).ok()?;
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_os_unfair_lock_lock<M: GuestMemory + ?Sized>(
    memory: &mut M,
    lock_ptr: u64,
    try_only: bool,
) -> Option<HostCallResult> {
    if lock_ptr == 0 {
        return Some(host_call_error(libc::EINVAL as u32));
    }
    let state = memory
        .read_memory(lock_ptr, 4)
        .ok()
        .and_then(|bytes| read_u32_at(&bytes, 0))
        .unwrap_or(0);
    if try_only && state != 0 {
        return Some(host_call_value(0));
    }
    write_guest_u32(memory, lock_ptr, 1).ok()?;
    Some(host_call_value(if try_only { 1 } else { 0 }))
}

#[cfg(target_os = "macos")]
fn proxy_guest_os_unfair_lock_unlock<M: GuestMemory + ?Sized>(
    memory: &mut M,
    lock_ptr: u64,
) -> Option<HostCallResult> {
    if lock_ptr == 0 {
        return Some(host_call_error(libc::EINVAL as u32));
    }
    write_guest_u32(memory, lock_ptr, 0).ok()?;
    Some(host_call_value(0))
}

fn host_import_kind(symbol: &str) -> Option<HostImportKind> {
    #[cfg(target_os = "macos")]
    {
        let symbol = normalize_import_name(symbol);
        if let Some(kind) = cxx::classify_import(symbol) {
            return Some(HostImportKind::Cxx(kind));
        }
        match symbol {
            "puts" => Some(HostImportKind::Puts),
            "printf" => Some(HostImportKind::Printf),
            "snprintf" => Some(HostImportKind::SnPrintf),
            "__snprintf_chk" => Some(HostImportKind::SnPrintfChk),
            "putchar" => Some(HostImportKind::Putchar),
            "open" | "open$NOCANCEL" => Some(HostImportKind::Open),
            "openat" => Some(HostImportKind::OpenAt),
            "read" | "read$NOCANCEL" => Some(HostImportKind::Read),
            "write" | "write$NOCANCEL" => Some(HostImportKind::Write),
            "close" | "close$NOCANCEL" => Some(HostImportKind::Close),
            "socket" => Some(HostImportKind::Socket),
            "connect" | "connect$NOCANCEL" => Some(HostImportKind::Connect),
            "bind" => Some(HostImportKind::Bind),
            "listen" => Some(HostImportKind::Listen),
            "send" | "send$NOCANCEL" => Some(HostImportKind::Send),
            "recv" | "recv$NOCANCEL" => Some(HostImportKind::Recv),
            "sendto" | "sendto$NOCANCEL" => Some(HostImportKind::SendTo),
            "recvfrom" | "recvfrom$NOCANCEL" => Some(HostImportKind::RecvFrom),
            "sendmsg" | "sendmsg$NOCANCEL" => Some(HostImportKind::SendMsg),
            "recvmsg" | "recvmsg$NOCANCEL" => Some(HostImportKind::RecvMsg),
            "shutdown" => Some(HostImportKind::Shutdown),
            "setsockopt" => Some(HostImportKind::SetSockOpt),
            "getsockopt" => Some(HostImportKind::GetSockOpt),
            "accept" | "accept$NOCANCEL" => Some(HostImportKind::Accept),
            "getpeername" => Some(HostImportKind::GetPeerName),
            "getsockname" => Some(HostImportKind::GetSockName),
            "socketpair" => Some(HostImportKind::SocketPair),
            "fcntl" => Some(HostImportKind::Fcntl),
            "ioctl" => Some(HostImportKind::Ioctl),
            "fsync" => Some(HostImportKind::Fsync),
            "poll" | "poll$NOCANCEL" => Some(HostImportKind::Poll),
            "readv" | "readv$NOCANCEL" => Some(HostImportKind::Readv),
            "writev" | "writev$NOCANCEL" => Some(HostImportKind::Writev),
            "pread" | "pread$NOCANCEL" => Some(HostImportKind::Pread),
            "pwrite" | "pwrite$NOCANCEL" => Some(HostImportKind::Pwrite),
            "lseek" => Some(HostImportKind::Lseek),
            "dup" => Some(HostImportKind::Dup),
            "dup2" => Some(HostImportKind::Dup2),
            "pipe" => Some(HostImportKind::Pipe),
            "select" | "select$NOCANCEL" => Some(HostImportKind::Select),
            "__darwin_check_fd_set_overflow" => Some(HostImportKind::DarwinCheckFdSetOverflow),
            "__chkstk_darwin" | "_chkstk_darwin" | "chkstk_darwin" => {
                Some(HostImportKind::DarwinChkstk)
            }
            "access" => Some(HostImportKind::Access),
            "faccessat" => Some(HostImportKind::FAccessAt),
            "chmod" => Some(HostImportKind::Chmod),
            "fchmod" => Some(HostImportKind::Fchmod),
            "fchmodat" => Some(HostImportKind::FchmodAt),
            "chdir" => Some(HostImportKind::Chdir),
            "fchdir" => Some(HostImportKind::Fchdir),
            "getcwd" => Some(HostImportKind::GetCwd),
            "stat" | "stat64" | "stat$INODE64" => Some(HostImportKind::Stat),
            "lstat" | "lstat64" | "lstat$INODE64" => Some(HostImportKind::LStat),
            "fstat" | "fstat64" | "fstat$INODE64" => Some(HostImportKind::FStat),
            "fstatat" | "fstatat64" | "fstatat$INODE64" => Some(HostImportKind::FStatAt),
            "statfs" | "statfs64" | "statfs$INODE64" => Some(HostImportKind::StatFs),
            "fstatfs" | "fstatfs64" | "fstatfs$INODE64" => Some(HostImportKind::FStatFs),
            "truncate" => Some(HostImportKind::Truncate),
            "ftruncate" => Some(HostImportKind::Ftruncate),
            "mkdir" => Some(HostImportKind::Mkdir),
            "mkdirat" => Some(HostImportKind::MkdirAt),
            "rmdir" => Some(HostImportKind::Rmdir),
            "unlink" => Some(HostImportKind::Unlink),
            "unlinkat" => Some(HostImportKind::UnlinkAt),
            "rename" => Some(HostImportKind::Rename),
            "renameat" => Some(HostImportKind::RenameAt),
            "readlink" => Some(HostImportKind::Readlink),
            "readlinkat" => Some(HostImportKind::ReadlinkAt),
            "symlink" => Some(HostImportKind::Symlink),
            "realpath" => Some(HostImportKind::Realpath),
            "getaddrinfo" => Some(HostImportKind::GetAddrInfo),
            "freeaddrinfo" => Some(HostImportKind::FreeAddrInfo),
            "gai_strerror" => Some(HostImportKind::GaiStrError),
            "getnameinfo" => Some(HostImportKind::GetNameInfo),
            "inet_pton" => Some(HostImportKind::InetPton),
            "inet_ntop" => Some(HostImportKind::InetNtop),
            "inet_addr" => Some(HostImportKind::InetAddr),
            "inet_aton" => Some(HostImportKind::InetAton),
            "htonl" => Some(HostImportKind::Htonl),
            "htons" => Some(HostImportKind::Htons),
            "ntohl" => Some(HostImportKind::Ntohl),
            "ntohs" => Some(HostImportKind::Ntohs),
            "getenv" => Some(HostImportKind::GetEnv),
            "setenv" => Some(HostImportKind::SetEnv),
            "unsetenv" => Some(HostImportKind::UnsetEnv),
            "getpid" => Some(HostImportKind::GetPid),
            "getppid" => Some(HostImportKind::GetPpid),
            "getuid" => Some(HostImportKind::GetUid),
            "geteuid" => Some(HostImportKind::GetEuid),
            "getgid" => Some(HostImportKind::GetGid),
            "getegid" => Some(HostImportKind::GetEgid),
            "sysconf" => Some(HostImportKind::SysConf),
            "getpagesize" => Some(HostImportKind::GetPageSize),
            "gethostname" => Some(HostImportKind::GetHostName),
            "uname" => Some(HostImportKind::Uname),
            "gettimeofday" => Some(HostImportKind::GetTimeOfDay),
            "clock_gettime" => Some(HostImportKind::ClockGetTime),
            "nanosleep" => Some(HostImportKind::NanoSleep),
            "sleep" => Some(HostImportKind::Sleep),
            "usleep" => Some(HostImportKind::USleep),
            "mach_absolute_time" => Some(HostImportKind::MachAbsoluteTime),
            "mach_timebase_info" => Some(HostImportKind::MachTimebaseInfo),
            "getrlimit" => Some(HostImportKind::GetRLimit),
            "setrlimit" => Some(HostImportKind::SetRLimit),
            "sysctl" => Some(HostImportKind::Sysctl),
            "sysctlbyname" => Some(HostImportKind::SysctlByName),
            "mlock" => Some(HostImportKind::Mlock),
            "munlock" => Some(HostImportKind::Munlock),
            "madvise" => Some(HostImportKind::Madvise),
            "umask" => Some(HostImportKind::Umask),
            "fopen" | "fopen$UNIX2003" => Some(HostImportKind::FOpen),
            "fdopen" | "fdopen$UNIX2003" => Some(HostImportKind::FdOpen),
            "fclose" => Some(HostImportKind::FClose),
            "fread" => Some(HostImportKind::FRead),
            "fwrite" => Some(HostImportKind::FWrite),
            "fflush" => Some(HostImportKind::FFlush),
            "fseek" | "fseek$UNIX2003" => Some(HostImportKind::FSeek),
            "ftell" | "ftell$UNIX2003" => Some(HostImportKind::FTell),
            "fgets" => Some(HostImportKind::FGetS),
            "fputs" => Some(HostImportKind::FPutS),
            "feof" => Some(HostImportKind::FEOF),
            "ferror" => Some(HostImportKind::FError),
            "clearerr" => Some(HostImportKind::ClearErr),
            "fileno" => Some(HostImportKind::Fileno),
            "malloc" => Some(HostImportKind::Malloc),
            "calloc" | "cmalloc" => Some(HostImportKind::Calloc),
            "realloc" => Some(HostImportKind::Realloc),
            "free" => Some(HostImportKind::Free),
            "posix_memalign" => Some(HostImportKind::PosixMemalign),
            "memcpy" | "__memcpy_chk" => Some(HostImportKind::Memcpy),
            "memmove" | "__memmove_chk" => Some(HostImportKind::Memmove),
            "memset" | "__memset_chk" => Some(HostImportKind::Memset),
            "bzero" => Some(HostImportKind::BZero),
            "memcmp" => Some(HostImportKind::Memcmp),
            "strlen" => Some(HostImportKind::Strlen),
            "strcmp" => Some(HostImportKind::Strcmp),
            "strncmp" => Some(HostImportKind::Strncmp),
            "strcpy" | "__strcpy_chk" => Some(HostImportKind::Strcpy),
            "strncpy" | "__strncpy_chk" => Some(HostImportKind::Strncpy),
            "strcat" | "__strcat_chk" => Some(HostImportKind::Strcat),
            "strchr" => Some(HostImportKind::Strchr),
            "strrchr" => Some(HostImportKind::Strrchr),
            "strdup" => Some(HostImportKind::Strdup),
            "opendir" => Some(HostImportKind::OpenDir),
            "fdopendir" => Some(HostImportKind::FdOpenDir),
            "readdir" => Some(HostImportKind::ReadDir),
            "readdir_r" => Some(HostImportKind::ReadDirR),
            "closedir" => Some(HostImportKind::CloseDir),
            "dirfd" => Some(HostImportKind::DirFd),
            "rewinddir" => Some(HostImportKind::RewindDir),
            "telldir" => Some(HostImportKind::Telldir),
            "seekdir" => Some(HostImportKind::Seekdir),
            "getentropy" => Some(HostImportKind::GetEntropy),
            "pthread_threading_np" => Some(HostImportKind::PthreadThreadingNp),
            "pthread_sigmask" => Some(HostImportKind::PthreadSigmask),
            "_NSGetExecutablePath" | "NSGetExecutablePath" => {
                Some(HostImportKind::NSGetExecutablePath)
            }
            "issetugid" | "issetguid" => Some(HostImportKind::IsSetUGid),
            "execl" => Some(HostImportKind::Execl),
            "execlp" => Some(HostImportKind::Execlp),
            "execv" => Some(HostImportKind::Execv),
            "execve" => Some(HostImportKind::Execve),
            "execvp" => Some(HostImportKind::Execvp),
            "getprogname" => Some(HostImportKind::GetProgName),
            "setprogname" => Some(HostImportKind::SetProgName),
            "_dyld_image_count" | "dyld_image_count" => Some(HostImportKind::DyldImageCount),
            "_dyld_get_image_name" | "dyld_get_image_name" => {
                Some(HostImportKind::DyldGetImageName)
            }
            "_dyld_get_image_header" | "dyld_get_image_header" => {
                Some(HostImportKind::DyldGetImageHeader)
            }
            "_dyld_get_image_vmaddr_slide" | "dyld_get_image_vmaddr_slide" => {
                Some(HostImportKind::DyldGetImageVmaddrSlide)
            }
            "dladdr" => Some(HostImportKind::Dladdr),
            "pthread_once" => Some(HostImportKind::PthreadOnce),
            "pthread_mutexattr_init" => Some(HostImportKind::PthreadMutexAttrInit),
            "pthread_mutexattr_settype" => Some(HostImportKind::PthreadMutexAttrSetType),
            "pthread_mutexattr_destroy" => Some(HostImportKind::PthreadMutexAttrDestroy),
            "pthread_attr_init" => Some(HostImportKind::PthreadAttrInit),
            "pthread_attr_destroy" => Some(HostImportKind::PthreadAttrDestroy),
            "pthread_attr_getstacksize" => Some(HostImportKind::PthreadAttrGetStackSize),
            "pthread_attr_setstacksize" => Some(HostImportKind::PthreadAttrSetStackSize),
            "pthread_attr_setdetachstate" => Some(HostImportKind::PthreadAttrSetDetachState),
            "os_unfair_lock_lock" => Some(HostImportKind::OsUnfairLockLock),
            "os_unfair_lock_trylock" => Some(HostImportKind::OsUnfairLockTryLock),
            "os_unfair_lock_unlock" => Some(HostImportKind::OsUnfairLockUnlock),
            "os_unfair_lock_assert_owner" => Some(HostImportKind::OsUnfairLockAssertOwner),
            "os_unfair_lock_assert_not_owner" => Some(HostImportKind::OsUnfairLockAssertNotOwner),
            _ => None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = symbol;
        None
    }
}

#[cfg(target_os = "macos")]
fn normalize_import_name(symbol: &str) -> &str {
    let symbol = symbol.strip_prefix('_').unwrap_or(symbol);
    symbol
        .split_once('$')
        .map(|(base, _suffix)| base)
        .unwrap_or(symbol)
}

#[cfg(target_os = "macos")]
fn read_cstring<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    max_len: usize,
) -> Result<String, GuestMemoryError> {
    let bytes = read_cstring_bytes(memory, addr, max_len)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "macos")]
fn read_cstring_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    max_len: usize,
) -> Result<Vec<u8>, GuestMemoryError> {
    let mut bytes = Vec::new();
    for offset in 0..max_len {
        let byte = memory
            .read_memory(addr.saturating_add(offset as u64), 1)?
            .first()
            .copied()
            .ok_or(GuestMemoryError)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn read_stack_u64_args<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stack_ptr: u64,
    max_args: usize,
) -> Vec<u64> {
    let mut args = Vec::new();
    for idx in 0..max_args {
        let addr = stack_ptr.saturating_add((idx * 8) as u64);
        let Ok(bytes) = memory.read_memory(addr, 8) else {
            break;
        };
        let Ok(raw) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            break;
        };
        args.push(u64::from_le_bytes(raw));
    }
    args
}

#[cfg(target_os = "macos")]
fn arm64_variadic_stack_arg<M: GuestMemory + ?Sized>(
    memory: &mut M,
    register_arg: u64,
    stack_ptr: Option<u64>,
    index: usize,
) -> u64 {
    stack_ptr
        .and_then(|sp| {
            read_stack_u64_args(memory, sp, index.saturating_add(1))
                .get(index)
                .copied()
        })
        .unwrap_or(register_arg)
}

#[cfg(target_os = "macos")]
fn arm64_variadic_open_mode<M: GuestMemory + ?Sized>(
    memory: &mut M,
    flags: u64,
    register_mode: u64,
    stack_ptr: Option<u64>,
) -> u64 {
    if (flags & libc::O_CREAT as u64) == 0 {
        return register_mode;
    }

    arm64_variadic_stack_arg(memory, register_mode, stack_ptr, 0)
}

#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_SIZE: usize = 48;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_FLAGS: usize = 0;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_FAMILY: usize = 4;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_SOCKTYPE: usize = 8;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_PROTOCOL: usize = 12;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_ADDRLEN: usize = 16;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_CANONNAME: usize = 24;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_ADDR: usize = 32;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_NEXT: usize = 40;
#[cfg(target_os = "macos")]
const MAX_ADDRINFO_RESULTS: usize = 64;
#[cfg(target_os = "macos")]
const MAX_GUEST_POLL_FDS: usize = 4096;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_SIZE: usize = 16;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_BASE: usize = 0;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_LEN: usize = 8;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_SIZE: usize = 48;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_NAME: usize = 0;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_NAMELEN: usize = 8;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_IOV: usize = 16;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_IOVLEN: usize = 24;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_CONTROL: usize = 32;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_CONTROLLEN: usize = 40;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_FLAGS: usize = 44;
#[cfg(target_os = "macos")]
const DARWIN_STAT_SIZE_OFFSET: usize = 96;
#[cfg(target_os = "macos")]
const MAX_GUEST_IOV: usize = 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_IOV_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_MSG_SIDE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "macos")]
const HOST_PATH_BUFFER_SIZE: usize = 4096;
#[cfg(target_os = "macos")]
const MAX_GUEST_SYSCTL_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_STDIO_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_MEMORY_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_STRING_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "macos")]
const HOST_FILE_HANDLE_SIZE: usize = 8;
#[cfg(target_os = "macos")]
const HOST_DIRENT_SIZE: usize = mem::size_of::<libc::dirent>();

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct HostFileHandle {
    file_ptr: usize,
}

#[cfg(target_os = "macos")]
fn host_file_handles() -> &'static Mutex<std::collections::HashMap<u64, HostFileHandle>> {
    static HANDLES: OnceLock<Mutex<std::collections::HashMap<u64, HostFileHandle>>> =
        OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "macos")]
fn host_file_ptr(stream: u64) -> Option<*mut libc::FILE> {
    let handles = host_file_handles().lock().ok()?;
    let handle = handles.get(&stream)?;
    Some(handle.file_ptr as *mut libc::FILE)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct HostDirHandle {
    dir_ptr: usize,
    dirent_guest_ptr: u64,
}

#[cfg(target_os = "macos")]
fn host_dir_handles() -> &'static Mutex<std::collections::HashMap<u64, HostDirHandle>> {
    static HANDLES: OnceLock<Mutex<std::collections::HashMap<u64, HostDirHandle>>> =
        OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct HostFdReadiness {
    pipe_write_to_read: HashMap<libc::c_int, libc::c_int>,
    pending_read_bytes: HashMap<libc::c_int, usize>,
}

#[cfg(target_os = "macos")]
fn host_fd_readiness() -> &'static Mutex<HostFdReadiness> {
    static READINESS: OnceLock<Mutex<HostFdReadiness>> = OnceLock::new();
    READINESS.get_or_init(|| Mutex::new(HostFdReadiness::default()))
}

#[cfg(target_os = "macos")]
fn note_host_pipe(read_fd: libc::c_int, write_fd: libc::c_int) {
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        readiness.pipe_write_to_read.insert(write_fd, read_fd);
        readiness.pending_read_bytes.entry(read_fd).or_default();
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_write(fd: u64, ret: isize) {
    if ret <= 0 {
        return;
    }
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        let Some(read_fd) = readiness.pipe_write_to_read.get(&fd).copied() else {
            return;
        };
        let pending = readiness.pending_read_bytes.entry(read_fd).or_default();
        *pending = pending.saturating_add(ret as usize);
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_read(fd: u64, ret: isize) {
    if ret <= 0 {
        return;
    }
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        if let Some(pending) = readiness.pending_read_bytes.get_mut(&fd) {
            *pending = pending.saturating_sub(ret as usize);
        }
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_dup(from: u64, to: libc::c_int) {
    if to < 0 {
        return;
    }
    let from = from as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        if let Some(read_fd) = readiness.pipe_write_to_read.get(&from).copied() {
            readiness.pipe_write_to_read.insert(to, read_fd);
        }
        if let Some(pending) = readiness.pending_read_bytes.get(&from).copied() {
            readiness.pending_read_bytes.insert(to, pending);
        }
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_close(fd: u64) {
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        readiness.pipe_write_to_read.remove(&fd);
        readiness
            .pipe_write_to_read
            .retain(|_write_fd, read_fd| *read_fd != fd);
        readiness.pending_read_bytes.remove(&fd);
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn inet_addr(cp: *const libc::c_char) -> libc::in_addr_t;
    fn inet_aton(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
    fn inet_ntop(
        af: libc::c_int,
        src: *const libc::c_void,
        dst: *mut libc::c_char,
        size: libc::socklen_t,
    ) -> *const libc::c_char;
}

#[cfg(any(target_os = "macos", test))]
fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = <[u8; 4]>::try_from(bytes.get(offset..offset + 4)?).ok()?;
    Some(u32::from_le_bytes(raw))
}

#[cfg(any(target_os = "macos", test))]
fn read_i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(read_u32_at(bytes, offset)? as i32)
}

#[cfg(target_os = "macos")]
fn read_i16_at(bytes: &[u8], offset: usize) -> Option<i16> {
    let raw = <[u8; 2]>::try_from(bytes.get(offset..offset + 2)?).ok()?;
    Some(i16::from_le_bytes(raw))
}

#[cfg(any(target_os = "macos", test))]
fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = <[u8; 8]>::try_from(bytes.get(offset..offset + 8)?).ok()?;
    Some(u64::from_le_bytes(raw))
}

#[cfg(target_os = "macos")]
fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    bytes
        .get_mut(offset..offset + 4)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

#[cfg(target_os = "macos")]
fn write_i32_at(bytes: &mut [u8], offset: usize, value: i32) -> Option<()> {
    write_u32_at(bytes, offset, value as u32)
}

#[cfg(target_os = "macos")]
fn write_i16_at(bytes: &mut [u8], offset: usize, value: i16) -> Option<()> {
    bytes
        .get_mut(offset..offset + 2)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

#[cfg(target_os = "macos")]
fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) -> Option<()> {
    bytes
        .get_mut(offset..offset + 8)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

#[cfg(target_os = "macos")]
fn write_guest_u64<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    value: u64,
) -> Result<(), GuestMemoryError> {
    memory.write_memory(addr, &value.to_le_bytes())
}

#[cfg(target_os = "macos")]
fn write_guest_u32<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    value: u32,
) -> Result<(), GuestMemoryError> {
    memory.write_memory(addr, &value.to_le_bytes())
}

#[cfg(target_os = "macos")]
fn read_guest_i32<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
) -> Result<i32, GuestMemoryError> {
    let bytes = memory.read_memory(addr, 4)?;
    let raw = <[u8; 4]>::try_from(bytes.as_slice()).map_err(|_| GuestMemoryError)?;
    Ok(i32::from_le_bytes(raw))
}

#[cfg(target_os = "macos")]
fn write_guest_i32<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    value: i32,
) -> Result<(), GuestMemoryError> {
    memory.write_memory(addr, &(value as u32).to_le_bytes())
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(target_os = "macos")]
fn host_errno() -> u32 {
    unsafe { *libc::__error() as u32 }
}

#[cfg(target_os = "macos")]
fn signed_return_value(ret: isize) -> u64 {
    ret as i64 as u64
}

#[cfg(target_os = "macos")]
fn host_io_result(ret: isize, preview: Vec<u8>) -> HostIoResult {
    HostIoResult {
        return_value: signed_return_value(ret),
        errno: if ret < 0 { host_errno() } else { 0 },
        transferred: ret.max(0) as usize,
        preview,
    }
}

#[cfg(target_os = "macos")]
fn host_io_error(errno: u32) -> HostIoResult {
    HostIoResult {
        return_value: u64::MAX,
        errno,
        transferred: 0,
        preview: Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn io_error_errno(error: &io::Error) -> u32 {
    error
        .raw_os_error()
        .filter(|errno| *errno > 0)
        .unwrap_or(libc::EIO) as u32
}

#[cfg(target_os = "macos")]
fn host_call_result(ret: isize) -> HostCallResult {
    HostCallResult {
        return_value: signed_return_value(ret),
        errno: (ret < 0).then(host_errno),
    }
}

#[cfg(target_os = "macos")]
fn host_call_value(value: u64) -> HostCallResult {
    HostCallResult {
        return_value: value,
        errno: None,
    }
}

#[cfg(target_os = "macos")]
fn host_call_error(errno: u32) -> HostCallResult {
    HostCallResult {
        return_value: u64::MAX,
        errno: Some(errno),
    }
}

#[cfg(target_os = "macos")]
fn host_null_error(errno: u32) -> HostCallResult {
    HostCallResult {
        return_value: 0,
        errno: Some(errno),
    }
}

#[cfg(target_os = "macos")]
fn gai_call_result(ret: libc::c_int) -> HostCallResult {
    HostCallResult {
        return_value: signed_return_value(ret as isize),
        errno: None,
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_puts<M: GuestMemory + ?Sized>(
    memory: &mut M,
    arg0_ptr: u64,
) -> Option<HostCallResult> {
    let text = read_cstring(memory, arg0_ptr, 4096).ok()?;
    let host_text = CString::new(text).ok()?;
    clear_errno();
    let ret = unsafe { libc::puts(host_text.as_ptr()) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_putchar(ch: u64) -> Option<HostCallResult> {
    clear_errno();
    let ret = unsafe { libc::putchar(ch as libc::c_int) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_printf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    args: &[u64; 8],
    stack_args: Option<&[u64]>,
) -> Option<HostCallResult> {
    let format = read_cstring(memory, args[0], 4096).ok()?;
    let rendered = render_arm64_printf(memory, &format, &args[1..], stack_args);
    let host_text = CString::new(rendered).ok()?;
    clear_errno();
    let ret = unsafe { libc::printf(b"%s\0".as_ptr().cast(), host_text.as_ptr()) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_snprintf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    args: &[u64; 8],
    stack_args: Option<&[u64]>,
) -> Option<HostCallResult> {
    let format = read_cstring(memory, args[2], 4096).ok()?;
    proxy_host_rendered_snprintf(memory, args[0], args[1], &format, &args[3..], stack_args)
}

#[cfg(target_os = "macos")]
fn proxy_host_snprintf_chk<M: GuestMemory + ?Sized>(
    memory: &mut M,
    args: &[u64; 8],
    stack_args: Option<&[u64]>,
) -> Option<HostCallResult> {
    let format = read_cstring(memory, args[4], 4096).ok()?;
    proxy_host_rendered_snprintf(memory, args[0], args[1], &format, &args[5..], stack_args)
}

#[cfg(target_os = "macos")]
fn proxy_host_rendered_snprintf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst_ptr: u64,
    size: u64,
    format: &str,
    register_args: &[u64],
    stack_args: Option<&[u64]>,
) -> Option<HostCallResult> {
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let rendered = render_arm64_printf(memory, format, register_args, stack_args);
    if size > 0 {
        if dst_ptr == 0 {
            return Some(host_call_error(libc::EFAULT as u32));
        }
        let bytes = rendered.as_bytes();
        let copy_len = bytes.len().min(size.saturating_sub(1));
        let mut out = Vec::with_capacity(copy_len.saturating_add(1));
        out.extend_from_slice(&bytes[..copy_len]);
        out.push(0);
        if memory.write_memory(dst_ptr, &out).is_err() {
            return Some(host_call_error(libc::EFAULT as u32));
        }
    }

    Some(host_call_value(rendered.len() as u64))
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct PrintfField {
    alternate: bool,
    zero_pad: bool,
    left_align: bool,
    show_sign: bool,
    leading_space: bool,
    width: Option<usize>,
    precision: Option<usize>,
}

#[cfg(target_os = "macos")]
fn apply_printf_width(value: String, field: &PrintfField, zero_padding_allowed: bool) -> String {
    let Some(width) = field.width else {
        return value;
    };
    let len = value.chars().count();
    if len >= width {
        return value;
    }

    let pad_len = width - len;
    if field.left_align {
        return format!("{value}{}", " ".repeat(pad_len));
    }

    if field.zero_pad && zero_padding_allowed && field.precision.is_none() {
        let prefix_len =
            if value.starts_with('-') || value.starts_with('+') || value.starts_with(' ') {
                1
            } else if value.starts_with("0x") || value.starts_with("0X") {
                2
            } else {
                0
            };
        if prefix_len > 0 {
            let (prefix, rest) = value.split_at(prefix_len);
            return format!("{prefix}{}{rest}", "0".repeat(pad_len));
        }
        return format!("{}{value}", "0".repeat(pad_len));
    }

    format!("{}{value}", " ".repeat(pad_len))
}

#[cfg(target_os = "macos")]
fn apply_integer_precision(value: String, field: &PrintfField) -> String {
    let Some(precision) = field.precision else {
        return value;
    };

    let prefix_len = if value.starts_with('-') || value.starts_with('+') || value.starts_with(' ') {
        1
    } else if value.starts_with("0x") || value.starts_with("0X") {
        2
    } else {
        0
    };
    let digit_len = value.len().saturating_sub(prefix_len);
    if digit_len >= precision {
        return value;
    }

    let (prefix, rest) = value.split_at(prefix_len);
    format!("{prefix}{}{rest}", "0".repeat(precision - digit_len))
}

#[cfg(target_os = "macos")]
fn render_printf_signed(arg: u64, long_count: usize, field: &PrintfField) -> String {
    let value = if long_count > 0 {
        arg as i64
    } else {
        arg as i32 as i64
    };
    let mut rendered = value.to_string();
    if value >= 0 {
        if field.show_sign {
            rendered = format!("+{rendered}");
        } else if field.leading_space {
            rendered = format!(" {rendered}");
        }
    }
    let rendered = apply_integer_precision(rendered, field);
    apply_printf_width(rendered, field, true)
}

#[cfg(target_os = "macos")]
fn render_printf_unsigned(arg: u64, long_count: usize, field: &PrintfField) -> String {
    let rendered = if long_count > 0 {
        arg.to_string()
    } else {
        (arg as u32).to_string()
    };
    let rendered = apply_integer_precision(rendered, field);
    apply_printf_width(rendered, field, true)
}

#[cfg(target_os = "macos")]
fn render_printf_hex(arg: u64, long_count: usize, upper: bool, field: &PrintfField) -> String {
    let value = if long_count > 0 {
        arg
    } else {
        arg as u32 as u64
    };
    let mut rendered = if upper {
        format!("{value:X}")
    } else {
        format!("{value:x}")
    };
    if field.alternate && value != 0 {
        rendered = if upper {
            format!("0X{rendered}")
        } else {
            format!("0x{rendered}")
        };
    }
    let rendered = apply_integer_precision(rendered, field);
    apply_printf_width(rendered, field, true)
}

#[cfg(target_os = "macos")]
fn printf_arg_sources(
    register_args: &[u64],
    stack_args: Option<&[u64]>,
    index: usize,
) -> (u64, Option<u64>, Option<u64>) {
    let stack_arg = stack_args.and_then(|args| args.get(index).copied());
    let register_arg = register_args.get(index).copied();
    (
        stack_arg.or(register_arg).unwrap_or(0),
        stack_arg,
        register_arg,
    )
}

#[cfg(target_os = "macos")]
fn take_printf_arg(
    register_args: &[u64],
    stack_args: Option<&[u64]>,
    arg_index: &mut usize,
) -> (u64, Option<u64>, Option<u64>) {
    let arg = printf_arg_sources(register_args, stack_args, *arg_index);
    *arg_index = (*arg_index).saturating_add(1);
    arg
}

#[cfg(target_os = "macos")]
fn apply_printf_dynamic_width(field: &mut PrintfField, raw: u64) {
    let width = raw as i32 as i64;
    if width < 0 {
        field.left_align = true;
        field.width = Some(width.unsigned_abs() as usize);
    } else {
        field.width = Some(width as usize);
    }
}

#[cfg(target_os = "macos")]
fn render_arm64_printf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    format: &str,
    register_args: &[u64],
    stack_args: Option<&[u64]>,
) -> String {
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_index = 0usize;
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            out.push('%');
            continue;
        }

        let mut field = PrintfField::default();
        loop {
            match chars.peek().copied() {
                Some('#') => field.alternate = true,
                Some('0') => field.zero_pad = true,
                Some('-') => field.left_align = true,
                Some('+') => field.show_sign = true,
                Some(' ') => field.leading_space = true,
                _ => break,
            }
            chars.next();
        }
        if chars.peek() == Some(&'*') {
            chars.next();
            let (width_arg, _, _) = take_printf_arg(register_args, stack_args, &mut arg_index);
            apply_printf_dynamic_width(&mut field, width_arg);
        } else {
            let mut width = 0usize;
            let mut has_width = false;
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                has_width = true;
                width = width.saturating_mul(10).saturating_add(
                    chars.peek().and_then(|ch| ch.to_digit(10)).unwrap_or(0) as usize,
                );
                chars.next();
            }
            if has_width {
                field.width = Some(width);
            }
        }
        if chars.peek() == Some(&'.') {
            chars.next();
            if chars.peek() == Some(&'*') {
                chars.next();
                let (precision_arg, _, _) =
                    take_printf_arg(register_args, stack_args, &mut arg_index);
                let precision = precision_arg as i32;
                if precision >= 0 {
                    field.precision = Some(precision as usize);
                }
            } else {
                let mut precision = 0usize;
                let mut has_precision = false;
                while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                    has_precision = true;
                    precision = precision.saturating_mul(10).saturating_add(
                        chars.peek().and_then(|ch| ch.to_digit(10)).unwrap_or(0) as usize,
                    );
                    chars.next();
                }
                field.precision = Some(if has_precision { precision } else { 0 });
            }
        }
        let mut long_count = 0usize;
        while chars.peek() == Some(&'l') {
            chars.next();
            long_count += 1;
        }
        let spec = chars.next().unwrap_or('%');
        let (arg, stack_arg, register_arg) = if matches!(spec, '%') {
            (0, None, None)
        } else {
            take_printf_arg(register_args, stack_args, &mut arg_index)
        };
        if matches!(spec, '%') {
            out.push('%');
            continue;
        }
        match spec {
            's' => {
                let mut value = String::new();
                let mut rendered = false;
                for candidate in stack_arg.into_iter().chain(register_arg) {
                    if candidate == 0 {
                        value.push_str("(null)");
                        rendered = true;
                        break;
                    }
                    if let Ok(value) = read_cstring(memory, candidate, 4096) {
                        let precision_limited = match field.precision {
                            Some(limit) => value.chars().take(limit).collect::<String>(),
                            None => value,
                        };
                        out.push_str(&apply_printf_width(precision_limited, &field, false));
                        rendered = true;
                        break;
                    }
                }
                if !value.is_empty() {
                    out.push_str(&apply_printf_width(value, &field, false));
                }
                if !rendered {
                    // Leave unreadable string arguments empty, matching the
                    // previous permissive renderer behavior.
                }
            }
            'c' => {
                let value = char::from_u32((arg as u8) as u32)
                    .unwrap_or('\u{FFFD}')
                    .to_string();
                out.push_str(&apply_printf_width(value, &field, false));
            }
            'd' | 'i' => out.push_str(&render_printf_signed(arg, long_count, &field)),
            'u' => out.push_str(&render_printf_unsigned(arg, long_count, &field)),
            'x' => out.push_str(&render_printf_hex(arg, long_count, false, &field)),
            'X' => out.push_str(&render_printf_hex(arg, long_count, true, &field)),
            'p' => out.push_str(&apply_printf_width(format!("0x{:x}", arg), &field, true)),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn proxy_host_open_arg0<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> Option<HostOpenResult> {
    let path = read_cstring(memory, path_ptr, 4096).ok()?;
    let host_path = CString::new(path.clone()).ok()?;
    clear_errno();
    let ret = unsafe {
        libc::open(
            host_path.as_ptr(),
            flags as libc::c_int,
            mode as libc::mode_t as libc::c_uint,
        )
    };
    Some(HostOpenResult {
        path,
        return_value: signed_return_value(ret as isize),
        errno: if ret < 0 { host_errno() } else { 0 },
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_openat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> Option<HostOpenResult> {
    let path = read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).ok()?;
    let host_path = CString::new(path.clone()).ok()?;
    clear_errno();
    let ret = unsafe {
        libc::openat(
            dirfd as libc::c_int,
            host_path.as_ptr(),
            flags as libc::c_int,
            mode as libc::mode_t as libc::c_uint,
        )
    };
    Some(HostOpenResult {
        path,
        return_value: signed_return_value(ret as isize),
        errno: if ret < 0 { host_errno() } else { 0 },
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_read<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::read(fd as libc::c_int, data.as_mut_ptr().cast(), count) };
    if ret > 0 {
        let read_len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..read_len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        data.truncate(read_len.min(128));
        note_host_fd_read(fd, ret);
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_write<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => {
                return Some(HostIoResult {
                    return_value: u64::MAX,
                    errno: libc::EFAULT as u32,
                    transferred: 0,
                    preview: Vec::new(),
                });
            }
        }
    };
    clear_errno();
    let ret = unsafe { libc::write(fd as libc::c_int, data.as_ptr().cast(), data.len()) };
    note_host_fd_write(fd, ret);
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_close(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::close(fd as libc::c_int) };
    if ret == 0 {
        note_host_fd_close(fd);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_host_path<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Result<(String, CString), u32> {
    let path =
        read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).map_err(|_| libc::EFAULT as u32)?;
    let host_path = CString::new(path.clone()).map_err(|_| libc::EINVAL as u32)?;
    Ok((path, host_path))
}

#[cfg(target_os = "macos")]
fn proxy_host_access<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::access(path.as_ptr(), mode as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_faccessat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::faccessat(
            dirfd as libc::c_int,
            path.as_ptr(),
            mode as libc::c_int,
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_chmod<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchmod(fd: u64, mode: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fchmod(fd as libc::c_int, mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchmodat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::fchmodat(
            dirfd as libc::c_int,
            path.as_ptr(),
            mode as libc::mode_t,
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_chdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::chdir(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchdir(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fchdir(fd as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_getcwd<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
) -> Option<HostCallResult> {
    if buf_ptr != 0 && size == 0 {
        return Some(host_null_error(libc::EINVAL as u32));
    }
    let host_size = if size == 0 {
        HOST_PATH_BUFFER_SIZE
    } else {
        usize::try_from(size).unwrap_or(HOST_PATH_BUFFER_SIZE)
    };
    let mut host_buf = vec![0u8; host_size.max(1)];
    clear_errno();
    let ret = unsafe { libc::getcwd(host_buf.as_mut_ptr().cast::<libc::c_char>(), host_buf.len()) };
    if ret.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let bytes = unsafe { CStr::from_ptr(host_buf.as_ptr().cast()).to_bytes_with_nul() };
    let dest = if buf_ptr == 0 {
        match allocate_guest_bytes(memory, bytes) {
            Some(addr) => addr,
            None => return Some(host_null_error(libc::ENOMEM as u32)),
        }
    } else {
        if bytes.len() > host_size || memory.write_memory(buf_ptr, bytes).is_err() {
            return Some(host_null_error(libc::ERANGE as u32));
        }
        buf_ptr
    };
    Some(HostCallResult {
        return_value: dest,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn write_darwin_stat_from_metadata<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stat_ptr: u64,
    metadata: &fs::Metadata,
) -> Result<(), u32> {
    write_darwin_minimal_stat(memory, stat_ptr, metadata.size())
}

#[cfg(target_os = "macos")]
fn write_darwin_minimal_stat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stat_ptr: u64,
    size: u64,
) -> Result<(), u32> {
    // Small compatibility fixtures and real guests may allocate a Darwin
    // `struct stat` shape that is smaller than the host Rust libc view. The
    // size field is the contract used by current compat callers, so write it
    // directly instead of treating an oversized full-struct write as EFAULT.
    memory
        .write_memory(
            stat_ptr + DARWIN_STAT_SIZE_OFFSET as u64,
            &size.to_le_bytes(),
        )
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn proxy_host_stat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    stat_ptr: u64,
    follow: bool,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (path, _) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let metadata = if follow {
        fs::metadata(&path)
    } else {
        fs::symlink_metadata(&path)
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(error) => return Some(host_io_error(io_error_errno(&error))),
    };
    if write_darwin_stat_from_metadata(memory, stat_ptr, &metadata).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(0, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    stat_ptr: u64,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    clear_errno();
    let ret = unsafe { libc::fstat(fd as libc::c_int, stat.as_mut_ptr()) };
    if ret == 0 {
        let size = unsafe { (*stat.as_ptr()).st_size }.max(0) as u64;
        if write_darwin_minimal_stat(memory, stat_ptr, size).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstatat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    stat_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    clear_errno();
    let ret = unsafe {
        libc::fstatat(
            dirfd as libc::c_int,
            path.as_ptr(),
            stat.as_mut_ptr(),
            flags as libc::c_int,
        )
    };
    if ret == 0 {
        let size = unsafe { (*stat.as_ptr()).st_size }.max(0) as u64;
        if write_darwin_minimal_stat(memory, stat_ptr, size).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_statfs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    buf_ptr: u64,
) -> Option<HostIoResult> {
    if buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut statfs = MaybeUninit::<libc::statfs>::zeroed();
    clear_errno();
    let ret = unsafe { libc::statfs(path.as_ptr(), statfs.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, buf_ptr, &statfs).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstatfs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
) -> Option<HostIoResult> {
    if buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut statfs = MaybeUninit::<libc::statfs>::zeroed();
    clear_errno();
    let ret = unsafe { libc::fstatfs(fd as libc::c_int, statfs.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, buf_ptr, &statfs).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_truncate<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    length: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::truncate(path.as_ptr(), length as libc::off_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ftruncate(fd: u64, length: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::ftruncate(fd as libc::c_int, length as libc::off_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_mkdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::mkdir(path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_mkdirat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::mkdirat(dirfd as libc::c_int, path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rmdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::rmdir(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_unlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::unlink(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_unlinkat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::unlinkat(dirfd as libc::c_int, path.as_ptr(), flags as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rename<M: GuestMemory + ?Sized>(
    memory: &mut M,
    from_ptr: u64,
    to_ptr: u64,
) -> Option<HostIoResult> {
    let (_, from) = match read_host_path(memory, from_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, to) = match read_host_path(memory, to_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::rename(from.as_ptr(), to.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_renameat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fromfd: u64,
    from_ptr: u64,
    tofd: u64,
    to_ptr: u64,
) -> Option<HostIoResult> {
    let (_, from) = match read_host_path(memory, from_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, to) = match read_host_path(memory, to_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::renameat(
            fromfd as libc::c_int,
            from.as_ptr(),
            tofd as libc::c_int,
            to.as_ptr(),
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_readlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::readlink(path.as_ptr(), data.as_mut_ptr().cast(), data.len()) };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_readlinkat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::readlinkat(
            dirfd as libc::c_int,
            path.as_ptr(),
            data.as_mut_ptr().cast(),
            data.len(),
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_symlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    target_ptr: u64,
    link_ptr: u64,
) -> Option<HostIoResult> {
    let (_, target) = match read_host_path(memory, target_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, link) = match read_host_path(memory, link_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::symlink(target.as_ptr(), link.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_realpath<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    resolved_ptr: u64,
) -> Option<HostCallResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_null_error(errno)),
    };
    let mut resolved = vec![0u8; HOST_PATH_BUFFER_SIZE];
    clear_errno();
    let ret = unsafe { libc::realpath(path.as_ptr(), resolved.as_mut_ptr().cast()) };
    if ret.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let bytes = unsafe { CStr::from_ptr(resolved.as_ptr().cast()).to_bytes_with_nul() };
    let dest = if resolved_ptr == 0 {
        match allocate_guest_bytes(memory, bytes) {
            Some(addr) => addr,
            None => return Some(host_null_error(libc::ENOMEM as u32)),
        }
    } else {
        if memory.write_memory(resolved_ptr, bytes).is_err() {
            return Some(host_null_error(libc::EFAULT as u32));
        }
        resolved_ptr
    };
    Some(HostCallResult {
        return_value: dest,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn read_socklen<M: GuestMemory + ?Sized>(memory: &mut M, addr: u64) -> Option<libc::socklen_t> {
    let bytes = memory
        .read_memory(addr, mem::size_of::<libc::socklen_t>())
        .ok()?;
    let raw = <[u8; 4]>::try_from(bytes.as_slice()).ok()?;
    Some(u32::from_le_bytes(raw) as libc::socklen_t)
}

#[cfg(target_os = "macos")]
fn write_socklen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    value: libc::socklen_t,
) -> Result<(), GuestMemoryError> {
    memory.write_memory(addr, &(value as u32).to_le_bytes())
}

#[cfg(target_os = "macos")]
fn read_sockaddr_storage<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    len: u64,
) -> Option<(MaybeUninit<libc::sockaddr_storage>, libc::socklen_t)> {
    if addr == 0 || len == 0 {
        return None;
    }
    let copy_len = (len as usize).min(mem::size_of::<libc::sockaddr_storage>());
    let bytes = memory.read_memory(addr, copy_len).ok()?;
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast::<u8>(), copy_len);
    }
    Some((storage, copy_len as libc::socklen_t))
}

#[cfg(target_os = "macos")]
fn sockaddr_log_fields<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    len: u64,
) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if addr == 0 || len < 2 {
        fields.push(("SockaddrDecode", "unavailable".to_string()));
        return fields;
    }
    let Ok(bytes) = memory.read_memory(addr, (len as usize).min(256)) else {
        fields.push(("SockaddrDecode", "read-error".to_string()));
        return fields;
    };
    if bytes.len() < 2 {
        fields.push(("SockaddrDecode", "short".to_string()));
        return fields;
    }

    let family = bytes[1] as i32;
    fields.push(("Family", sockaddr_family_name(family).to_string()));
    match family {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let address = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            fields.push(("Address", address.to_string()));
            fields.push(("Port", port.to_string()));
            fields.push(("Endpoint", format!("{address}:{port}")));
        }
        libc::AF_INET6 if bytes.len() >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[8..24]);
            let address = std::net::Ipv6Addr::from(raw);
            let scope = read_u32_at(&bytes, 24).unwrap_or(0);
            fields.push(("Address", address.to_string()));
            fields.push(("Port", port.to_string()));
            if scope != 0 {
                fields.push(("ScopeId", scope.to_string()));
                fields.push(("Endpoint", format!("[{address}%{scope}]:{port}")));
            } else {
                fields.push(("Endpoint", format!("[{address}]:{port}")));
            }
        }
        libc::AF_UNIX if bytes.len() > 2 => {
            let path = bytes[2..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|end| &bytes[2..2 + end])
                .unwrap_or(&bytes[2..]);
            fields.push(("Address", String::from_utf8_lossy(path).into_owned()));
        }
        _ => {
            fields.push(("SockaddrDecode", "unsupported-family".to_string()));
        }
    }
    fields
}

#[cfg(target_os = "macos")]
fn sockaddr_family_name(family: i32) -> &'static str {
    match family {
        libc::AF_UNIX => "AF_UNIX",
        libc::AF_INET => "AF_INET",
        libc::AF_INET6 => "AF_INET6",
        _ => "unknown",
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_socket(domain: u64, kind: u64, protocol: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe {
        libc::socket(
            domain as libc::c_int,
            kind as libc::c_int,
            protocol as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_connect<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::connect(
            fd as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_bind<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::bind(
            fd as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_listen(fd: u64, backlog: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::listen(fd as libc::c_int, backlog as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_send<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
) -> Option<HostIoResult> {
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => {
                return Some(HostIoResult {
                    return_value: u64::MAX,
                    errno: libc::EFAULT as u32,
                    transferred: 0,
                    preview: Vec::new(),
                });
            }
        }
    };
    clear_errno();
    let ret = unsafe {
        libc::send(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_recv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::recv(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            flags as libc::c_int,
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_sendto<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len == 0 {
        return proxy_host_send(memory, fd, buf_ptr, count, flags);
    }
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => {
                return Some(HostIoResult {
                    return_value: u64::MAX,
                    errno: libc::EFAULT as u32,
                    transferred: 0,
                    preview: Vec::new(),
                });
            }
        }
    };
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::sendto(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            flags as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_recvfrom<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
        return proxy_host_recv(memory, fd, buf_ptr, count, flags);
    }
    let requested_len = read_socklen(memory, sockaddr_len_ptr)
        .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
        .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t);
    let mut data = vec![0u8; count];
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        libc::recvfrom(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            flags as libc::c_int,
            storage.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut addr_len,
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        let sockaddr_copy_len = (addr_len as usize)
            .min(requested_len as usize)
            .min(mem::size_of::<libc::sockaddr_storage>());
        let sockaddr_bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), sockaddr_copy_len) };
        if sockaddr_copy_len > 0 && memory.write_memory(sockaddr_ptr, sockaddr_bytes).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if write_socklen(memory, sockaddr_len_ptr, addr_len).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestMsghdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: i32,
    control: u64,
    controllen: u32,
    flags: i32,
}

#[cfg(any(target_os = "macos", test))]
fn parse_darwin_msghdr(bytes: &[u8]) -> Option<GuestMsghdr> {
    Some(GuestMsghdr {
        name: read_u64_at(bytes, DARWIN_MSGHDR_NAME)?,
        namelen: read_u32_at(bytes, DARWIN_MSGHDR_NAMELEN)?,
        iov: read_u64_at(bytes, DARWIN_MSGHDR_IOV)?,
        iovlen: read_i32_at(bytes, DARWIN_MSGHDR_IOVLEN)?,
        control: read_u64_at(bytes, DARWIN_MSGHDR_CONTROL)?,
        controllen: read_u32_at(bytes, DARWIN_MSGHDR_CONTROLLEN)?,
        flags: read_i32_at(bytes, DARWIN_MSGHDR_FLAGS)?,
    })
}

#[cfg(target_os = "macos")]
fn read_guest_msghdr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    msg_ptr: u64,
) -> Result<GuestMsghdr, u32> {
    if msg_ptr == 0 {
        return Err(libc::EFAULT as u32);
    }
    let bytes = memory
        .read_memory(msg_ptr, DARWIN_MSGHDR_SIZE)
        .map_err(|_| libc::EFAULT as u32)?;
    parse_darwin_msghdr(&bytes).ok_or(libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn write_guest_msghdr_outputs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    msg_ptr: u64,
    msg: &GuestMsghdr,
) -> Result<(), u32> {
    write_guest_u32(memory, msg_ptr + DARWIN_MSGHDR_NAMELEN as u64, msg.namelen)
        .map_err(|_| libc::EFAULT as u32)?;
    write_guest_u32(
        memory,
        msg_ptr + DARWIN_MSGHDR_CONTROLLEN as u64,
        msg.controllen,
    )
    .map_err(|_| libc::EFAULT as u32)?;
    write_guest_i32(memory, msg_ptr + DARWIN_MSGHDR_FLAGS as u64, msg.flags)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn read_guest_side_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    len: usize,
) -> Result<Vec<u8>, u32> {
    if len > MAX_GUEST_MSG_SIDE_BYTES {
        return Err(libc::EINVAL as u32);
    }
    if ptr == 0 || len == 0 {
        return Ok(Vec::new());
    }
    memory
        .read_memory(ptr, len)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn zeroed_guest_side_bytes(ptr: u64, len: usize) -> Result<Vec<u8>, u32> {
    if len > MAX_GUEST_MSG_SIDE_BYTES {
        return Err(libc::EINVAL as u32);
    }
    if ptr == 0 || len == 0 {
        Ok(Vec::new())
    } else {
        Ok(vec![0u8; len])
    }
}

#[cfg(target_os = "macos")]
fn optional_vec_mut_ptr(data: &mut Vec<u8>) -> *mut libc::c_void {
    if data.is_empty() {
        ptr::null_mut()
    } else {
        data.as_mut_ptr().cast()
    }
}

#[cfg(target_os = "macos")]
fn msg_iovcnt(iovlen: libc::c_int) -> Result<u64, u32> {
    u64::try_from(iovlen).map_err(|_| libc::EINVAL as u32)
}

#[cfg(target_os = "macos")]
fn proxy_host_sendmsg<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    msg_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let guest_msg = match read_guest_msghdr(memory, msg_ptr) {
        Ok(msg) => msg,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovcnt = match msg_iovcnt(guest_msg.iovlen) {
        Ok(iovcnt) => iovcnt,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovecs = match read_guest_iovecs(memory, guest_msg.iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let buffers = match read_guest_iovec_bytes(memory, &iovecs) {
        Ok(buffers) => buffers,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut host_iovecs = buffers
        .iter()
        .map(host_iovec_from_buffer)
        .collect::<Vec<_>>();
    let mut name = match read_guest_side_bytes(memory, guest_msg.name, guest_msg.namelen as usize) {
        Ok(name) => name,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut control =
        match read_guest_side_bytes(memory, guest_msg.control, guest_msg.controllen as usize) {
            Ok(control) => control,
            Err(errno) => return Some(host_io_error(errno)),
        };
    let preview = preview_iovec_bytes(&buffers);
    let host_msg = libc::msghdr {
        msg_name: optional_vec_mut_ptr(&mut name),
        msg_namelen: if name.is_empty() {
            0
        } else {
            guest_msg.namelen as libc::socklen_t
        },
        msg_iov: host_iovecs.as_mut_ptr(),
        msg_iovlen: host_iovecs.len() as libc::c_int,
        msg_control: optional_vec_mut_ptr(&mut control),
        msg_controllen: if control.is_empty() {
            0
        } else {
            guest_msg.controllen as libc::socklen_t
        },
        msg_flags: guest_msg.flags,
    };
    clear_errno();
    let ret = unsafe { libc::sendmsg(fd as libc::c_int, &host_msg, flags as libc::c_int) };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_recvmsg<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    msg_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let mut guest_msg = match read_guest_msghdr(memory, msg_ptr) {
        Ok(msg) => msg,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovcnt = match msg_iovcnt(guest_msg.iovlen) {
        Ok(iovcnt) => iovcnt,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovecs = match read_guest_iovecs(memory, guest_msg.iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut buffers = iovecs
        .iter()
        .map(|iov| vec![0u8; iov.len])
        .collect::<Vec<_>>();
    let mut host_iovecs = buffers
        .iter_mut()
        .map(host_iovec_from_mut_buffer)
        .collect::<Vec<_>>();
    let mut name = match zeroed_guest_side_bytes(guest_msg.name, guest_msg.namelen as usize) {
        Ok(name) => name,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut control =
        match zeroed_guest_side_bytes(guest_msg.control, guest_msg.controllen as usize) {
            Ok(control) => control,
            Err(errno) => return Some(host_io_error(errno)),
        };
    let mut host_msg = libc::msghdr {
        msg_name: optional_vec_mut_ptr(&mut name),
        msg_namelen: if name.is_empty() {
            0
        } else {
            guest_msg.namelen as libc::socklen_t
        },
        msg_iov: host_iovecs.as_mut_ptr(),
        msg_iovlen: host_iovecs.len() as libc::c_int,
        msg_control: optional_vec_mut_ptr(&mut control),
        msg_controllen: if control.is_empty() {
            0
        } else {
            guest_msg.controllen as libc::socklen_t
        },
        msg_flags: guest_msg.flags,
    };
    clear_errno();
    let ret = unsafe { libc::recvmsg(fd as libc::c_int, &mut host_msg, flags as libc::c_int) };
    if ret >= 0 {
        if ret > 0 {
            let read_len = ret as usize;
            if let Err(errno) = write_guest_iovec_bytes(memory, &iovecs, &buffers, read_len) {
                return Some(host_io_error(errno));
            }
        }
        if guest_msg.name != 0 && !name.is_empty() {
            let name_len = (host_msg.msg_namelen as usize).min(name.len());
            if memory
                .write_memory(guest_msg.name, &name[..name_len])
                .is_err()
            {
                return Some(host_io_error(libc::EFAULT as u32));
            }
        }
        if guest_msg.control != 0 && !control.is_empty() {
            let control_len = (host_msg.msg_controllen as usize).min(control.len());
            if memory
                .write_memory(guest_msg.control, &control[..control_len])
                .is_err()
            {
                return Some(host_io_error(libc::EFAULT as u32));
            }
        }
        guest_msg.namelen = host_msg.msg_namelen as u32;
        guest_msg.controllen = host_msg.msg_controllen as u32;
        guest_msg.flags = host_msg.msg_flags;
        if let Err(errno) = write_guest_msghdr_outputs(memory, msg_ptr, &guest_msg) {
            return Some(host_io_error(errno));
        }
    }
    let preview = if ret > 0 {
        preview_iovec_bytes(&buffers)
    } else {
        Vec::new()
    };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_shutdown(fd: u64, how: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::shutdown(fd as libc::c_int, how as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_setsockopt<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    level: u64,
    option_name: u64,
    option_value_ptr: u64,
    option_len: u64,
) -> Option<HostIoResult> {
    let option_data = if option_len == 0 {
        Vec::new()
    } else {
        match memory.read_memory(option_value_ptr, option_len as usize) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let ret = unsafe {
        libc::setsockopt(
            fd as libc::c_int,
            level as libc::c_int,
            option_name as libc::c_int,
            option_data.as_ptr().cast(),
            option_data.len() as libc::socklen_t,
        )
    };
    Some(host_io_result(
        ret as isize,
        option_data[..option_data.len().min(128)].to_vec(),
    ))
}

#[cfg(target_os = "macos")]
fn proxy_host_getsockopt<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    level: u64,
    option_name: u64,
    option_value_ptr: u64,
    option_len_ptr: u64,
) -> Option<HostIoResult> {
    let requested_len = match read_socklen(memory, option_len_ptr) {
        Some(value) => value as usize,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    if option_value_ptr == 0 && requested_len > 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut option_data = vec![0u8; requested_len];
    let mut option_len = requested_len as libc::socklen_t;
    clear_errno();
    let ret = unsafe {
        libc::getsockopt(
            fd as libc::c_int,
            level as libc::c_int,
            option_name as libc::c_int,
            option_data.as_mut_ptr().cast(),
            &mut option_len,
        )
    };
    if ret == 0 {
        let write_len = (option_len as usize).min(option_data.len());
        if write_len > 0
            && memory
                .write_memory(option_value_ptr, &option_data[..write_len])
                .is_err()
        {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if write_socklen(memory, option_len_ptr, option_len).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        option_data.truncate(write_len.min(128));
    } else {
        option_data.clear();
    }
    Some(host_io_result(ret as isize, option_data))
}

#[cfg(target_os = "macos")]
fn copy_sockaddr_to_guest<M: GuestMemory + ?Sized>(
    memory: &mut M,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
    storage: &MaybeUninit<libc::sockaddr_storage>,
    requested_len: libc::socklen_t,
    actual_len: libc::socklen_t,
) {
    if sockaddr_ptr != 0 && requested_len > 0 {
        let copy_len = (actual_len as usize)
            .min(requested_len as usize)
            .min(mem::size_of::<libc::sockaddr_storage>());
        let sockaddr_bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), copy_len) };
        let _ = memory.write_memory(sockaddr_ptr, sockaddr_bytes);
    }
    if sockaddr_len_ptr != 0 {
        let _ = write_socklen(memory, sockaddr_len_ptr, actual_len);
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_accept<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let requested_len = if sockaddr_ptr != 0 && sockaddr_len_ptr != 0 {
        read_socklen(memory, sockaddr_len_ptr)
            .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
            .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
    } else {
        0
    };
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        libc::accept(
            fd as libc::c_int,
            if sockaddr_ptr == 0 {
                ptr::null_mut()
            } else {
                storage.as_mut_ptr().cast::<libc::sockaddr>()
            },
            if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
                ptr::null_mut()
            } else {
                &mut addr_len
            },
        )
    };
    if ret >= 0 && sockaddr_ptr != 0 && sockaddr_len_ptr != 0 {
        copy_sockaddr_to_guest(
            memory,
            sockaddr_ptr,
            sockaddr_len_ptr,
            &storage,
            requested_len,
            addr_len,
        );
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_getpeername<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    proxy_host_socket_name(
        memory,
        fd,
        sockaddr_ptr,
        sockaddr_len_ptr,
        libc::getpeername,
    )
}

#[cfg(target_os = "macos")]
fn proxy_host_getsockname<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    proxy_host_socket_name(
        memory,
        fd,
        sockaddr_ptr,
        sockaddr_len_ptr,
        libc::getsockname,
    )
}

#[cfg(target_os = "macos")]
fn proxy_host_socket_name<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
    call: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EFAULT as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let requested_len = read_socklen(memory, sockaddr_len_ptr)
        .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
        .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t);
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        call(
            fd as libc::c_int,
            storage.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut addr_len,
        )
    };
    if ret == 0 {
        copy_sockaddr_to_guest(
            memory,
            sockaddr_ptr,
            sockaddr_len_ptr,
            &storage,
            requested_len,
            addr_len,
        );
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_socketpair<M: GuestMemory + ?Sized>(
    memory: &mut M,
    domain: u64,
    kind: u64,
    protocol: u64,
    sv_ptr: u64,
) -> Option<HostIoResult> {
    if sv_ptr == 0 {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EFAULT as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let mut sv = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe {
        libc::socketpair(
            domain as libc::c_int,
            kind as libc::c_int,
            protocol as libc::c_int,
            sv.as_mut_ptr(),
        )
    };
    if ret == 0 {
        let _ = write_guest_i32(memory, sv_ptr, sv[0]);
        let _ = write_guest_i32(memory, sv_ptr + 4, sv[1]);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fcntl(fd: u64, cmd: u64, arg: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fcntl(fd as libc::c_int, cmd as libc::c_int, arg as libc::c_long) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ioctl<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    request: u64,
    data_ptr: u64,
) -> Option<HostIoResult> {
    match request {
        value if value == libc::FIONREAD as u64 => {
            if data_ptr == 0 {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let mut available: libc::c_int = 0;
            clear_errno();
            let ret = unsafe {
                libc::ioctl(
                    fd as libc::c_int,
                    libc::FIONREAD,
                    &mut available as *mut libc::c_int,
                )
            };
            if ret == 0 && write_guest_i32(memory, data_ptr, available).is_err() {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let preview = if ret == 0 {
                available.to_le_bytes().to_vec()
            } else {
                Vec::new()
            };
            Some(host_io_result(ret as isize, preview))
        }
        value if value == libc::FIONBIO as u64 => {
            if data_ptr == 0 {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let mut enable = match read_guest_i32(memory, data_ptr) {
                Ok(value) => value,
                Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
            };
            clear_errno();
            let ret = unsafe {
                libc::ioctl(
                    fd as libc::c_int,
                    libc::FIONBIO,
                    &mut enable as *mut libc::c_int,
                )
            };
            Some(host_io_result(ret as isize, Vec::new()))
        }
        _ => Some(host_io_result(0, Vec::new())),
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_fsync(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fsync(fd as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_poll<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fds_ptr: u64,
    nfds: u64,
    timeout: u64,
) -> Option<HostIoResult> {
    if nfds as usize > MAX_GUEST_POLL_FDS {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EINVAL as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let entry_size = mem::size_of::<libc::pollfd>();
    let bytes_len = (nfds as usize).saturating_mul(entry_size);
    let bytes = if bytes_len == 0 {
        Vec::new()
    } else {
        memory.read_memory(fds_ptr, bytes_len).ok()?
    };
    let mut fds = vec![
        libc::pollfd {
            fd: 0,
            events: 0,
            revents: 0,
        };
        nfds as usize
    ];
    for (idx, pollfd) in fds.iter_mut().enumerate() {
        let offset = idx * entry_size;
        pollfd.fd = read_i32_at(&bytes, offset)? as libc::c_int;
        pollfd.events = read_i16_at(&bytes, offset + 4)?;
        pollfd.revents = 0;
    }
    clear_errno();
    let ret = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            nfds as libc::nfds_t,
            timeout as libc::c_int,
        )
    };
    if ret >= 0 && bytes_len > 0 {
        let mut out = bytes;
        for (idx, pollfd) in fds.iter().enumerate() {
            let offset = idx * entry_size;
            let _ = write_i32_at(&mut out, offset, pollfd.fd);
            let _ = write_i16_at(&mut out, offset + 4, pollfd.events);
            let _ = write_i16_at(&mut out, offset + 6, pollfd.revents);
        }
        let _ = memory.write_memory(fds_ptr, &out);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestIovec {
    base: u64,
    len: usize,
}

#[cfg(target_os = "macos")]
fn read_guest_iovecs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iov_ptr: u64,
    iovcnt: u64,
) -> Result<Vec<GuestIovec>, u32> {
    let iovcnt = usize::try_from(iovcnt).map_err(|_| libc::EINVAL as u32)?;
    if iovcnt > MAX_GUEST_IOV {
        return Err(libc::EINVAL as u32);
    }
    if iovcnt == 0 {
        return Ok(Vec::new());
    }
    if iov_ptr == 0 {
        return Err(libc::EFAULT as u32);
    }
    let bytes_len = iovcnt
        .checked_mul(DARWIN_IOVEC_SIZE)
        .ok_or(libc::EINVAL as u32)?;
    let bytes = memory
        .read_memory(iov_ptr, bytes_len)
        .map_err(|_| libc::EFAULT as u32)?;
    let mut iovecs = Vec::with_capacity(iovcnt);
    let mut total = 0usize;
    for idx in 0..iovcnt {
        let offset = idx * DARWIN_IOVEC_SIZE;
        let base = read_u64_at(&bytes, offset + DARWIN_IOVEC_BASE).ok_or(libc::EFAULT as u32)?;
        let len = usize::try_from(
            read_u64_at(&bytes, offset + DARWIN_IOVEC_LEN).ok_or(libc::EFAULT as u32)?,
        )
        .map_err(|_| libc::EINVAL as u32)?;
        total = total.checked_add(len).ok_or(libc::EINVAL as u32)?;
        if total > MAX_GUEST_IOV_BYTES {
            return Err(libc::EINVAL as u32);
        }
        iovecs.push(GuestIovec { base, len });
    }
    Ok(iovecs)
}

#[cfg(target_os = "macos")]
fn read_guest_iovec_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iovecs: &[GuestIovec],
) -> Result<Vec<Vec<u8>>, u32> {
    let mut buffers = Vec::with_capacity(iovecs.len());
    for iov in iovecs {
        if iov.len == 0 {
            buffers.push(Vec::new());
            continue;
        }
        if iov.base == 0 {
            return Err(libc::EFAULT as u32);
        }
        let data = memory
            .read_memory(iov.base, iov.len)
            .map_err(|_| libc::EFAULT as u32)?;
        buffers.push(data);
    }
    Ok(buffers)
}

#[cfg(target_os = "macos")]
fn write_guest_iovec_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iovecs: &[GuestIovec],
    buffers: &[Vec<u8>],
    count: usize,
) -> Result<(), u32> {
    let mut remaining = count;
    for (iov, buffer) in iovecs.iter().zip(buffers.iter()) {
        if remaining == 0 {
            break;
        }
        let write_len = remaining.min(iov.len);
        if write_len == 0 {
            continue;
        }
        if iov.base == 0 {
            return Err(libc::EFAULT as u32);
        }
        memory
            .write_memory(iov.base, &buffer[..write_len])
            .map_err(|_| libc::EFAULT as u32)?;
        remaining -= write_len;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn preview_iovec_bytes(buffers: &[Vec<u8>]) -> Vec<u8> {
    let mut preview = Vec::new();
    for buffer in buffers {
        if preview.len() >= 128 {
            break;
        }
        let remaining = 128 - preview.len();
        preview.extend_from_slice(&buffer[..buffer.len().min(remaining)]);
    }
    preview
}

#[cfg(target_os = "macos")]
fn host_iovec_from_mut_buffer(buffer: &mut Vec<u8>) -> libc::iovec {
    libc::iovec {
        iov_base: if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        },
        iov_len: buffer.len(),
    }
}

#[cfg(target_os = "macos")]
fn host_iovec_from_buffer(buffer: &Vec<u8>) -> libc::iovec {
    libc::iovec {
        iov_base: if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_ptr().cast::<libc::c_void>().cast_mut()
        },
        iov_len: buffer.len(),
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_readv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    iov_ptr: u64,
    iovcnt: u64,
) -> Option<HostIoResult> {
    let iovecs = match read_guest_iovecs(memory, iov_ptr, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut buffers = iovecs
        .iter()
        .map(|iov| vec![0u8; iov.len])
        .collect::<Vec<_>>();
    let host_iovecs = buffers
        .iter_mut()
        .map(host_iovec_from_mut_buffer)
        .collect::<Vec<_>>();
    clear_errno();
    let ret = unsafe {
        libc::readv(
            fd as libc::c_int,
            host_iovecs.as_ptr(),
            host_iovecs.len() as libc::c_int,
        )
    };
    if ret > 0 {
        let read_len = ret as usize;
        if let Err(errno) = write_guest_iovec_bytes(memory, &iovecs, &buffers, read_len) {
            return Some(host_io_error(errno));
        }
        note_host_fd_read(fd, ret);
    }
    let preview = if ret > 0 {
        preview_iovec_bytes(&buffers)
    } else {
        Vec::new()
    };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_writev<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    iov_ptr: u64,
    iovcnt: u64,
) -> Option<HostIoResult> {
    let iovecs = match read_guest_iovecs(memory, iov_ptr, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let buffers = match read_guest_iovec_bytes(memory, &iovecs) {
        Ok(buffers) => buffers,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let host_iovecs = buffers
        .iter()
        .map(host_iovec_from_buffer)
        .collect::<Vec<_>>();
    let preview = preview_iovec_bytes(&buffers);
    clear_errno();
    let ret = unsafe {
        libc::writev(
            fd as libc::c_int,
            host_iovecs.as_ptr(),
            host_iovecs.len() as libc::c_int,
        )
    };
    note_host_fd_write(fd, ret);
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_pread<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    offset: u64,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::pread(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            offset as libc::off_t,
        )
    };
    if ret > 0 {
        let read_len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..read_len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(read_len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_pwrite<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    offset: u64,
) -> Option<HostIoResult> {
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let ret = unsafe {
        libc::pwrite(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            offset as libc::off_t,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_lseek(fd: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe {
        libc::lseek(
            fd as libc::c_int,
            offset as libc::off_t,
            whence as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dup(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::dup(fd as libc::c_int) };
    if ret >= 0 {
        note_host_fd_dup(fd, ret);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dup2(from: u64, to: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::dup2(from as libc::c_int, to as libc::c_int) };
    if ret >= 0 {
        note_host_fd_dup(from, ret);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_pipe<M: GuestMemory + ?Sized>(memory: &mut M, fds_ptr: u64) -> Option<HostIoResult> {
    if fds_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut fds = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret == 0 {
        if write_guest_i32(memory, fds_ptr, fds[0]).is_err()
            || write_guest_i32(memory, fds_ptr + 4, fds[1]).is_err()
        {
            let _ = unsafe { libc::close(fds[0]) };
            let _ = unsafe { libc::close(fds[1]) };
            return Some(host_io_error(libc::EFAULT as u32));
        }
        note_host_pipe(fds[0], fds[1]);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_pipe_pair() -> Option<HostPipeResult> {
    let mut fds = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret == 0 {
        note_host_pipe(fds[0], fds[1]);
        Some(HostPipeResult {
            read_fd: fds[0] as u64,
            write_fd: fds[1] as u64,
            errno: 0,
        })
    } else {
        Some(HostPipeResult {
            read_fd: u64::MAX,
            write_fd: 0,
            errno: host_errno(),
        })
    }
}

#[cfg(target_os = "macos")]
fn read_guest_host_struct<M: GuestMemory + ?Sized, T>(
    memory: &mut M,
    addr: u64,
) -> Result<MaybeUninit<T>, u32> {
    let bytes = memory
        .read_memory(addr, mem::size_of::<T>())
        .map_err(|_| libc::EFAULT as u32)?;
    let mut value = MaybeUninit::<T>::zeroed();
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr().cast::<u8>(), bytes.len());
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn write_guest_host_struct<M: GuestMemory + ?Sized, T>(
    memory: &mut M,
    addr: u64,
    value: &MaybeUninit<T>,
) -> Result<(), u32> {
    let bytes =
        unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), mem::size_of::<T>()) };
    memory
        .write_memory(addr, bytes)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn proxy_host_select<M: GuestMemory + ?Sized>(
    memory: &mut M,
    nfds: u64,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
) -> Option<HostIoResult> {
    if nfds > libc::c_int::MAX as u64 {
        return Some(host_io_error(libc::EINVAL as u32));
    }
    let readfds = match read_darwin_fd_set(memory, readfds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let writefds = match read_darwin_fd_set(memory, writefds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let exceptfds = match read_darwin_fd_set(memory, exceptfds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut timeout = match read_darwin_timeval(memory, timeout_ptr) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };

    let mut read_host = match build_host_fd_set(readfds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut write_host = match build_host_fd_set(writefds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut except_host = match build_host_fd_set(exceptfds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };

    clear_errno();
    let mut ret = unsafe {
        libc::select(
            nfds as libc::c_int,
            read_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            write_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            except_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            timeout
                .as_mut()
                .map(|timeout| timeout as *mut libc::timeval)
                .unwrap_or(ptr::null_mut()),
        )
    };
    if ret < 0 {
        return Some(host_io_result(ret as isize, Vec::new()));
    }

    let mut ready_read = collect_ready_host_fd_set(readfds.as_ref(), read_host.as_ref());
    let ready_write = collect_ready_host_fd_set(writefds.as_ref(), write_host.as_ref());
    let ready_except = collect_ready_host_fd_set(exceptfds.as_ref(), except_host.as_ref());
    let inferred_readfds = infer_single_read_fd(readfds.as_ref(), readfds_ptr, nfds);
    let fallback_readfds = inferred_readfds.as_ref().or(readfds.as_ref());
    if ready_read.is_empty() {
        ready_read = collect_tracked_read_ready(readfds.as_ref());
        if ready_read.is_empty() {
            ready_read = collect_fionread_ready(readfds.as_ref());
        }
        if ready_read.is_empty() {
            ready_read = collect_poll_ready(readfds.as_ref());
        }
        if ready_read.is_empty() && inferred_readfds.is_some() {
            ready_read = collect_tracked_read_ready(fallback_readfds);
            if ready_read.is_empty() {
                ready_read = collect_fionread_ready(fallback_readfds);
            }
            if ready_read.is_empty() {
                ready_read = collect_poll_ready(fallback_readfds);
            }
        }
        if !ready_read.is_empty() {
            ret = ret.max(ready_read.len() as libc::c_int);
        } else if ret > 0 {
            if let Some(original) = readfds.as_ref() {
                ready_read = original.iter().copied().take(ret as usize).collect();
            }
        }
    }

    if let Err(errno) = write_darwin_fd_set(memory, readfds_ptr, fallback_readfds, &ready_read)
        .and_then(|_| write_darwin_fd_set(memory, writefds_ptr, writefds.as_ref(), &ready_write))
        .and_then(|_| write_darwin_fd_set(memory, exceptfds_ptr, exceptfds.as_ref(), &ready_except))
    {
        return Some(host_io_error(errno));
    }

    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_darwin_fd_set<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    nfds: u64,
) -> Result<Option<HashSet<libc::c_int>>, u32> {
    if addr == 0 {
        return Ok(None);
    }
    const DARWIN_FD_SET_BYTES: usize = 128;
    const DARWIN_NFDBITS: usize = 32;
    let bytes = memory
        .read_memory(addr, DARWIN_FD_SET_BYTES)
        .map_err(|_| libc::EFAULT as u32)?;
    let mut fds = HashSet::new();
    for fd in 0..(nfds as usize).min(DARWIN_FD_SET_BYTES * 8) {
        let bit = fd % DARWIN_NFDBITS;
        let word_start = (fd / DARWIN_NFDBITS) * 4;
        if word_start + 4 > bytes.len() {
            break;
        }
        let word = u32::from_le_bytes([
            bytes[word_start],
            bytes[word_start + 1],
            bytes[word_start + 2],
            bytes[word_start + 3],
        ]);
        if (word & (1u32 << bit)) != 0 {
            fds.insert(fd as libc::c_int);
        }
    }
    Ok(Some(fds))
}

#[cfg(target_os = "macos")]
fn write_darwin_fd_set<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    original: Option<&HashSet<libc::c_int>>,
    ready: &HashSet<libc::c_int>,
) -> Result<(), u32> {
    if addr == 0 || original.is_none() {
        return Ok(());
    }
    const DARWIN_FD_SET_BYTES: usize = 128;
    const DARWIN_NFDBITS: usize = 32;
    let mut bytes = vec![0u8; DARWIN_FD_SET_BYTES];
    for fd in ready {
        if *fd < 0 {
            continue;
        }
        let fd = *fd as usize;
        let word_start = (fd / DARWIN_NFDBITS) * 4;
        if word_start + 4 > bytes.len() {
            continue;
        }
        let bit = fd % DARWIN_NFDBITS;
        let mut word = u32::from_le_bytes([
            bytes[word_start],
            bytes[word_start + 1],
            bytes[word_start + 2],
            bytes[word_start + 3],
        ]);
        word |= 1u32 << bit;
        bytes[word_start..word_start + 4].copy_from_slice(&word.to_le_bytes());
    }
    memory
        .write_memory(addr, &bytes)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn build_host_fd_set(
    fds: Option<&HashSet<libc::c_int>>,
) -> Result<Option<MaybeUninit<libc::fd_set>>, u32> {
    let Some(fds) = fds else {
        return Ok(None);
    };
    let mut set = MaybeUninit::<libc::fd_set>::zeroed();
    unsafe {
        libc::FD_ZERO(set.as_mut_ptr());
    }
    for fd in fds {
        if *fd < 0 || *fd as usize >= libc::FD_SETSIZE {
            return Err(libc::EINVAL as u32);
        }
        unsafe {
            libc::FD_SET(*fd, set.as_mut_ptr());
        }
    }
    Ok(Some(set))
}

#[cfg(target_os = "macos")]
fn collect_ready_host_fd_set(
    original: Option<&HashSet<libc::c_int>>,
    host: Option<&MaybeUninit<libc::fd_set>>,
) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let (Some(original), Some(host)) = (original, host) else {
        return ready;
    };
    for fd in original {
        let is_ready = unsafe { libc::FD_ISSET(*fd, host.as_ptr()) };
        if is_ready {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn infer_single_read_fd(
    original: Option<&HashSet<libc::c_int>>,
    readfds_ptr: u64,
    nfds: u64,
) -> Option<HashSet<libc::c_int>> {
    if readfds_ptr == 0 || !original.is_some_and(HashSet::is_empty) || nfds == 0 {
        return None;
    }
    let fd = nfds.checked_sub(1)? as libc::c_int;
    if fd < 0 || fd as usize >= libc::FD_SETSIZE {
        return None;
    }
    Some(HashSet::from([fd]))
}

#[cfg(target_os = "macos")]
fn collect_tracked_read_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    let Ok(readiness) = host_fd_readiness().lock() else {
        return ready;
    };
    for fd in original {
        if readiness
            .pending_read_bytes
            .get(fd)
            .copied()
            .unwrap_or_default()
            > 0
        {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn collect_fionread_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    for fd in original {
        let mut available: libc::c_int = 0;
        let ret = unsafe { libc::ioctl(*fd, libc::FIONREAD, &mut available as *mut libc::c_int) };
        if ret == 0 && available > 0 {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn collect_poll_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    let mut fds = original
        .iter()
        .copied()
        .filter(|fd| *fd >= 0)
        .map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect::<Vec<_>>();
    if fds.is_empty() {
        return ready;
    }
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
    if ret <= 0 {
        return ready;
    }
    for fd in fds {
        if (fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            ready.insert(fd.fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn read_darwin_timeval<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
) -> Result<Option<libc::timeval>, u32> {
    if addr == 0 {
        return Ok(None);
    }
    let bytes = memory
        .read_memory(addr, 16)
        .map_err(|_| libc::EFAULT as u32)?;
    let sec = i64::from_le_bytes(bytes[0..8].try_into().map_err(|_| libc::EFAULT as u32)?);
    let usec = i32::from_le_bytes(bytes[8..12].try_into().map_err(|_| libc::EFAULT as u32)?);
    Ok(Some(libc::timeval {
        tv_sec: sec as _,
        tv_usec: usec.max(0) as _,
    }))
}

#[cfg(target_os = "macos")]
fn read_guest_addrinfo_hint<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
) -> Option<libc::addrinfo> {
    if addr == 0 {
        return None;
    }
    let bytes = memory.read_memory(addr, DARWIN_ADDRINFO_SIZE).ok()?;
    let mut hint: libc::addrinfo = unsafe { mem::zeroed() };
    hint.ai_flags = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_FLAGS)? as libc::c_int;
    hint.ai_family = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_FAMILY)? as libc::c_int;
    hint.ai_socktype = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_SOCKTYPE)? as libc::c_int;
    hint.ai_protocol = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_PROTOCOL)? as libc::c_int;
    hint.ai_addrlen = read_u32_at(&bytes, DARWIN_ADDRINFO_AI_ADDRLEN)? as libc::socklen_t;
    Some(hint)
}

#[cfg(target_os = "macos")]
fn write_guest_addrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    ai: &libc::addrinfo,
    canonname: u64,
    sockaddr: u64,
    next: u64,
) -> Result<(), GuestMemoryError> {
    let mut bytes = vec![0u8; DARWIN_ADDRINFO_SIZE];
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_FLAGS, ai.ai_flags).ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_FAMILY, ai.ai_family).ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_SOCKTYPE, ai.ai_socktype)
        .ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_PROTOCOL, ai.ai_protocol)
        .ok_or(GuestMemoryError)?;
    write_u32_at(&mut bytes, DARWIN_ADDRINFO_AI_ADDRLEN, ai.ai_addrlen as u32)
        .ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_CANONNAME, canonname).ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_ADDR, sockaddr).ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_NEXT, next).ok_or(GuestMemoryError)?;
    memory.write_memory(addr, &bytes)
}

#[cfg(target_os = "macos")]
fn read_optional_guest_cstring<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    max_len: usize,
) -> Option<Option<CString>> {
    if addr == 0 {
        return Some(None);
    }
    let text = read_cstring(memory, addr, max_len).ok()?;
    Some(Some(CString::new(text).ok()?))
}

#[cfg(target_os = "macos")]
fn allocate_guest_bytes<M: GuestMemory + ?Sized>(memory: &mut M, bytes: &[u8]) -> Option<u64> {
    let addr = memory.allocate_memory(bytes.len(), 8).ok()?;
    memory.write_memory(addr, bytes).ok()?;
    Some(addr)
}

#[cfg(target_os = "macos")]
fn proxy_host_getaddrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    node_ptr: u64,
    service_ptr: u64,
    hints_ptr: u64,
    result_ptr: u64,
) -> Option<HostCallResult> {
    if result_ptr == 0 {
        return Some(gai_call_result(libc::EAI_FAIL));
    }
    let node = read_optional_guest_cstring(memory, node_ptr, 4096)?;
    let service = read_optional_guest_cstring(memory, service_ptr, 4096)?;
    let hints = read_guest_addrinfo_hint(memory, hints_ptr);
    let mut host_result: *mut libc::addrinfo = ptr::null_mut();
    clear_errno();
    let ret = unsafe {
        libc::getaddrinfo(
            node.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            service.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            hints
                .as_ref()
                .map_or(ptr::null(), |value| value as *const libc::addrinfo),
            &mut host_result,
        )
    };
    if ret != 0 {
        let _ = write_guest_u64(memory, result_ptr, 0);
        return Some(gai_call_result(ret));
    }

    let mut first_guest = 0u64;
    let mut previous_guest = 0u64;
    let mut current = host_result;
    let mut copied = 0usize;
    while !current.is_null() && copied < MAX_ADDRINFO_RESULTS {
        let ai = unsafe { &*current };
        let guest_ai = match memory.allocate_memory(DARWIN_ADDRINFO_SIZE, 8) {
            Ok(addr) => addr,
            Err(_) => {
                unsafe { libc::freeaddrinfo(host_result) };
                let _ = write_guest_u64(memory, result_ptr, 0);
                return Some(gai_call_result(libc::EAI_MEMORY));
            }
        };
        let guest_sockaddr = if ai.ai_addr.is_null() || ai.ai_addrlen == 0 {
            0
        } else {
            let sockaddr_bytes = unsafe {
                std::slice::from_raw_parts(ai.ai_addr.cast::<u8>(), ai.ai_addrlen as usize)
            };
            match allocate_guest_bytes(memory, sockaddr_bytes) {
                Some(addr) => addr,
                None => {
                    unsafe { libc::freeaddrinfo(host_result) };
                    let _ = write_guest_u64(memory, result_ptr, 0);
                    return Some(gai_call_result(libc::EAI_MEMORY));
                }
            }
        };
        let guest_canonname = if ai.ai_canonname.is_null() {
            0
        } else {
            let canon = unsafe { CStr::from_ptr(ai.ai_canonname).to_bytes_with_nul() };
            match allocate_guest_bytes(memory, canon) {
                Some(addr) => addr,
                None => {
                    unsafe { libc::freeaddrinfo(host_result) };
                    let _ = write_guest_u64(memory, result_ptr, 0);
                    return Some(gai_call_result(libc::EAI_MEMORY));
                }
            }
        };
        if write_guest_addrinfo(memory, guest_ai, ai, guest_canonname, guest_sockaddr, 0).is_err() {
            unsafe { libc::freeaddrinfo(host_result) };
            let _ = write_guest_u64(memory, result_ptr, 0);
            return Some(gai_call_result(libc::EAI_MEMORY));
        }
        if previous_guest != 0 {
            let _ = write_guest_u64(
                memory,
                previous_guest + DARWIN_ADDRINFO_AI_NEXT as u64,
                guest_ai,
            );
        } else {
            first_guest = guest_ai;
        }
        previous_guest = guest_ai;
        current = ai.ai_next;
        copied += 1;
    }
    unsafe { libc::freeaddrinfo(host_result) };
    if write_guest_u64(memory, result_ptr, first_guest).is_err() {
        return Some(gai_call_result(libc::EAI_MEMORY));
    }
    Some(gai_call_result(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_freeaddrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addrinfo_ptr: u64,
) -> Option<HostCallResult> {
    let mut current = addrinfo_ptr;
    let mut seen = HashSet::new();
    for _ in 0..MAX_ADDRINFO_RESULTS {
        if current == 0 || !seen.insert(current) {
            break;
        }
        let Ok(bytes) = memory.read_memory(current, DARWIN_ADDRINFO_SIZE) else {
            break;
        };
        let canonname = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_CANONNAME).unwrap_or(0);
        let sockaddr = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_ADDR).unwrap_or(0);
        let next = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_NEXT).unwrap_or(0);
        if canonname != 0 {
            let _ = memory.free_memory(canonname);
        }
        if sockaddr != 0 {
            let _ = memory.free_memory(sockaddr);
        }
        let _ = memory.free_memory(current);
        current = next;
    }
    Some(HostCallResult {
        return_value: 0,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_gai_strerror<M: GuestMemory + ?Sized>(
    memory: &mut M,
    errcode: u64,
) -> Option<HostCallResult> {
    let message = unsafe { libc::gai_strerror(errcode as libc::c_int) };
    if message.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: None,
        });
    }
    let bytes = unsafe { CStr::from_ptr(message).to_bytes_with_nul() };
    let addr = allocate_guest_bytes(memory, bytes).unwrap_or(0);
    Some(HostCallResult {
        return_value: addr,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_getnameinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
    host_ptr: u64,
    host_len: u64,
    service_ptr: u64,
    service_len: u64,
    flags: u64,
) -> Option<HostCallResult> {
    let (storage, len) = read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len)?;
    let mut host = vec![0u8; host_len as usize];
    let mut service = vec![0u8; service_len as usize];
    clear_errno();
    let ret = unsafe {
        libc::getnameinfo(
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
            if host_ptr == 0 || host.is_empty() {
                ptr::null_mut()
            } else {
                host.as_mut_ptr().cast::<libc::c_char>()
            },
            host_len as libc::socklen_t,
            if service_ptr == 0 || service.is_empty() {
                ptr::null_mut()
            } else {
                service.as_mut_ptr().cast::<libc::c_char>()
            },
            service_len as libc::socklen_t,
            flags as libc::c_int,
        )
    };
    if ret == 0 {
        if host_ptr != 0 && !host.is_empty() {
            let _ = memory.write_memory(host_ptr, &host);
        }
        if service_ptr != 0 && !service.is_empty() {
            let _ = memory.write_memory(service_ptr, &service);
        }
    }
    Some(gai_call_result(ret))
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_pton<M: GuestMemory + ?Sized>(
    memory: &mut M,
    family: u64,
    src_ptr: u64,
    dst_ptr: u64,
) -> Option<HostCallResult> {
    let src = read_cstring(memory, src_ptr, 4096).ok()?;
    let host_src = CString::new(src).ok()?;
    let mut storage = [0u8; 16];
    clear_errno();
    let ret = unsafe {
        inet_pton(
            family as libc::c_int,
            host_src.as_ptr(),
            storage.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    if ret == 1 {
        let len = match family as libc::c_int {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        if len > 0 && memory.write_memory(dst_ptr, &storage[..len]).is_err() {
            return Some(host_call_error(libc::EFAULT as u32));
        }
    }
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_ntop<M: GuestMemory + ?Sized>(
    memory: &mut M,
    family: u64,
    src_ptr: u64,
    dst_ptr: u64,
    dst_len: u64,
) -> Option<HostCallResult> {
    let src_len = match family as libc::c_int {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => 16,
    };
    let src = memory.read_memory(src_ptr, src_len).ok()?;
    let mut dst = vec![0u8; dst_len as usize];
    clear_errno();
    let ret = unsafe {
        inet_ntop(
            family as libc::c_int,
            src.as_ptr().cast::<libc::c_void>(),
            dst.as_mut_ptr().cast::<libc::c_char>(),
            dst_len as libc::socklen_t,
        )
    };
    if !ret.is_null() {
        if memory.write_memory(dst_ptr, &dst).is_err() {
            return Some(host_call_error(libc::EFAULT as u32));
        }
        return Some(HostCallResult {
            return_value: dst_ptr,
            errno: None,
        });
    }
    Some(HostCallResult {
        return_value: 0,
        errno: Some(host_errno()),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_addr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    src_ptr: u64,
) -> Option<HostCallResult> {
    let host_src = match read_cstring(memory, src_ptr, 4096)
        .ok()
        .and_then(|src| CString::new(src).ok())
    {
        Some(value) => value,
        None => {
            return Some(HostCallResult {
                return_value: libc::INADDR_NONE as u64,
                errno: Some(libc::EFAULT as u32),
            });
        }
    };
    clear_errno();
    let ret = unsafe { inet_addr(host_src.as_ptr()) };
    Some(HostCallResult {
        return_value: ret as u64,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_aton<M: GuestMemory + ?Sized>(
    memory: &mut M,
    src_ptr: u64,
    dst_ptr: u64,
) -> Option<HostCallResult> {
    if dst_ptr == 0 {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(libc::EFAULT as u32),
        });
    }

    let host_src = match read_cstring(memory, src_ptr, 4096)
        .ok()
        .and_then(|src| CString::new(src).ok())
    {
        Some(value) => value,
        None => {
            return Some(HostCallResult {
                return_value: 0,
                errno: Some(libc::EFAULT as u32),
            });
        }
    };
    let mut addr = libc::in_addr { s_addr: 0 };
    clear_errno();
    let ret = unsafe { inet_aton(host_src.as_ptr(), &mut addr) };
    if ret != 0 {
        if memory
            .write_memory(dst_ptr, &addr.s_addr.to_le_bytes())
            .is_err()
        {
            return Some(HostCallResult {
                return_value: 0,
                errno: Some(libc::EFAULT as u32),
            });
        }
    }
    Some(HostCallResult {
        return_value: ret as u64,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_getenv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
) -> Option<HostCallResult> {
    if name_ptr == 0 {
        return Some(host_null_error(libc::EFAULT as u32));
    }
    let name = read_cstring(memory, name_ptr, 4096).ok()?;
    let host_name = CString::new(name).ok()?;
    clear_errno();
    let value = unsafe { libc::getenv(host_name.as_ptr()) };
    if value.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: None,
        });
    }
    let bytes = unsafe { CStr::from_ptr(value).to_bytes_with_nul() };
    let Some(addr) = allocate_guest_bytes(memory, bytes) else {
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(HostCallResult {
        return_value: addr,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_setenv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
    value_ptr: u64,
    overwrite: u64,
) -> Option<HostIoResult> {
    let name = read_cstring(memory, name_ptr, 4096).ok()?;
    let value = read_cstring(memory, value_ptr, 4096).ok()?;
    let host_name = CString::new(name).ok()?;
    let host_value = CString::new(value).ok()?;
    clear_errno();
    let ret = unsafe {
        libc::setenv(
            host_name.as_ptr(),
            host_value.as_ptr(),
            overwrite as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_unsetenv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
) -> Option<HostIoResult> {
    let name = read_cstring(memory, name_ptr, 4096).ok()?;
    let host_name = CString::new(name).ok()?;
    clear_errno();
    let ret = unsafe { libc::unsetenv(host_name.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
const COMPAT_GUEST_MACHINE: &str = "arm64";
#[cfg(target_os = "macos")]
const COMPAT_GUEST_MODEL: &str = "VirtualMac2,1";
#[cfg(target_os = "macos")]
const DARWIN_CTL_HW: libc::c_int = 6;
#[cfg(target_os = "macos")]
const DARWIN_HW_MACHINE: libc::c_int = 1;
#[cfg(target_os = "macos")]
const DARWIN_HW_MODEL: libc::c_int = 2;
#[cfg(target_os = "macos")]
const DARWIN_HW_MACHINE_ARCH: libc::c_int = 12;
#[cfg(target_os = "macos")]
const DARWIN_CPU_TYPE_ARM64: i32 = 0x0100_000C;
#[cfg(target_os = "macos")]
const DARWIN_CPU_SUBTYPE_ARM64_ALL: i32 = 0;

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct CompatIdentitySysctl {
    label: String,
    value_kind: &'static str,
    value: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn sysctl_cstring_value(value: &str) -> Vec<u8> {
    let mut out = value.as_bytes().to_vec();
    out.push(0);
    out
}

#[cfg(target_os = "macos")]
fn sysctl_i32_value(value: i32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

#[cfg(target_os = "macos")]
fn compat_identity_sysctl_by_name(name: &str) -> Option<CompatIdentitySysctl> {
    let (value_kind, value) = match name {
        "hw.machine" | "hw.machinearch" => ("cstring", sysctl_cstring_value(COMPAT_GUEST_MACHINE)),
        "hw.model" => ("cstring", sysctl_cstring_value(COMPAT_GUEST_MODEL)),
        "hw.cputype" => ("i32", sysctl_i32_value(DARWIN_CPU_TYPE_ARM64)),
        "hw.cpusubtype" => ("i32", sysctl_i32_value(DARWIN_CPU_SUBTYPE_ARM64_ALL)),
        "hw.optional.arm64" => ("i32", sysctl_i32_value(1)),
        name if name.starts_with("hw.optional.arm64.")
            || name.starts_with("hw.optional.armv")
            || name.starts_with("hw.optional.arm.") =>
        {
            ("i32", sysctl_i32_value(0))
        }
        _ => return None,
    };
    Some(CompatIdentitySysctl {
        label: name.to_string(),
        value_kind,
        value,
    })
}

#[cfg(target_os = "macos")]
fn compat_identity_sysctl_by_mib(mib: &[libc::c_int]) -> Option<CompatIdentitySysctl> {
    if mib.len() < 2 || mib[0] != DARWIN_CTL_HW {
        return None;
    }
    let (label, value_kind, value) = match mib[1] {
        DARWIN_HW_MACHINE => (
            "CTL_HW.HW_MACHINE",
            "cstring",
            sysctl_cstring_value(COMPAT_GUEST_MACHINE),
        ),
        DARWIN_HW_MODEL => (
            "CTL_HW.HW_MODEL",
            "cstring",
            sysctl_cstring_value(COMPAT_GUEST_MODEL),
        ),
        DARWIN_HW_MACHINE_ARCH => (
            "CTL_HW.HW_MACHINE_ARCH",
            "cstring",
            sysctl_cstring_value(COMPAT_GUEST_MACHINE),
        ),
        _ => return None,
    };
    Some(CompatIdentitySysctl {
        label: label.to_string(),
        value_kind,
        value,
    })
}

#[cfg(target_os = "macos")]
fn preview_text_field(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(compat_log_config().preview_bytes);
    compat_preview_text(&bytes[..preview_len])
}

#[cfg(target_os = "macos")]
fn preview_hex_field(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(compat_log_config().preview_bytes);
    compat_preview_hex(&bytes[..preview_len])
}

#[cfg(target_os = "macos")]
fn c_char_array_to_string<const N: usize>(value: &[libc::c_char; N]) -> String {
    unsafe { CStr::from_ptr(value.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(target_os = "macos")]
fn write_c_char_array<const N: usize>(dst: &mut [libc::c_char; N], value: &str) {
    for byte in dst.iter_mut() {
        *byte = 0;
    }
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(N.saturating_sub(1));
    for (idx, byte) in bytes.iter().take(copy_len).enumerate() {
        dst[idx] = *byte as libc::c_char;
    }
}

#[cfg(target_os = "macos")]
fn emit_verbose_identity(
    call: &str,
    args: &[(&str, String)],
    fields: &mut [(&str, Option<String>)],
    preview: Option<&[u8]>,
) {
    emit_verbose_compat_payload("identity", call, args, fields, preview);
}

#[cfg(target_os = "macos")]
fn proxy_host_sysconf(name: u64) -> Option<HostCallResult> {
    clear_errno();
    let ret = unsafe { libc::sysconf(name as libc::c_int) };
    let errno = host_errno();
    Some(HostCallResult {
        return_value: signed_return_value(ret as isize),
        errno: (ret < 0 && errno != 0).then_some(errno),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_gethostname<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
    len: u64,
) -> Option<HostIoResult> {
    if len as usize > MAX_GUEST_SYSCTL_BYTES {
        return Some(host_io_error(libc::ENOMEM as u32));
    }
    let mut host = vec![0u8; len as usize];
    clear_errno();
    let ret = unsafe {
        libc::gethostname(
            if name_ptr == 0 || host.is_empty() {
                ptr::null_mut()
            } else {
                host.as_mut_ptr().cast::<libc::c_char>()
            },
            host.len(),
        )
    };
    if ret == 0
        && name_ptr != 0
        && !host.is_empty()
        && memory.write_memory(name_ptr, &host).is_err()
    {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    if ret == 0 {
        let returned_name = host
            .split(|byte| *byte == 0)
            .next()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        let args = [("name_ptr", hex_arg(name_ptr)), ("len", len.to_string())];
        let mut fields = [
            ("Source", Some("host".to_string())),
            ("HostName", Some(returned_name.clone())),
            ("GuestName", Some(returned_name)),
        ];
        emit_verbose_identity("gethostname", &args, &mut fields, Some(&host));
    }
    Some(host_io_result(ret as isize, host))
}

#[cfg(target_os = "macos")]
fn proxy_host_uname<M: GuestMemory + ?Sized>(memory: &mut M, uts_ptr: u64) -> Option<HostIoResult> {
    if uts_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    clear_errno();
    let ret = unsafe { libc::uname(uts.as_mut_ptr()) };
    if ret == 0 {
        let mut uts = unsafe { uts.assume_init() };
        let host_sysname = c_char_array_to_string(&uts.sysname);
        let host_nodename = c_char_array_to_string(&uts.nodename);
        let host_release = c_char_array_to_string(&uts.release);
        let host_version = c_char_array_to_string(&uts.version);
        let host_machine = c_char_array_to_string(&uts.machine);
        write_c_char_array(&mut uts.machine, COMPAT_GUEST_MACHINE);
        let out = MaybeUninit::new(uts);
        if write_guest_host_struct(memory, uts_ptr, &out).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        let args = [("uts_ptr", hex_arg(uts_ptr))];
        let mut fields = [
            ("Source", Some("host+compat-identity".to_string())),
            ("HostSysName", Some(host_sysname.clone())),
            ("HostNodeName", Some(host_nodename.clone())),
            ("HostRelease", Some(host_release.clone())),
            ("HostVersion", Some(host_version.clone())),
            ("HostMachine", Some(host_machine)),
            ("GuestSysName", Some(host_sysname)),
            ("GuestNodeName", Some(host_nodename)),
            ("GuestRelease", Some(host_release)),
            ("GuestVersion", Some(host_version)),
            ("GuestMachine", Some(COMPAT_GUEST_MACHINE.to_string())),
        ];
        emit_verbose_identity("uname", &args, &mut fields, None);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_gettimeofday<M: GuestMemory + ?Sized>(
    memory: &mut M,
    tv_ptr: u64,
    tz_ptr: u64,
    mach_absolute_time_ptr: u64,
) -> Option<HostIoResult> {
    let mut tv = MaybeUninit::<libc::timeval>::zeroed();
    clear_errno();
    let ret = unsafe {
        libc::gettimeofday(
            if tv_ptr == 0 {
                ptr::null_mut()
            } else {
                tv.as_mut_ptr()
            },
            ptr::null_mut(),
        )
    };
    if ret == 0 {
        if tv_ptr != 0 && write_guest_host_struct(memory, tv_ptr, &tv).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if tz_ptr != 0 && memory.write_memory(tz_ptr, &[0u8; 8]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if mach_absolute_time_ptr != 0 {
            #[allow(deprecated)]
            let now = unsafe { libc::mach_absolute_time() };
            if write_guest_u64(memory, mach_absolute_time_ptr, now).is_err() {
                return Some(host_io_error(libc::EFAULT as u32));
            }
        }
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_clock_gettime<M: GuestMemory + ?Sized>(
    memory: &mut M,
    clock_id: u64,
    tp_ptr: u64,
) -> Option<HostIoResult> {
    let mut tp = MaybeUninit::<libc::timespec>::zeroed();
    clear_errno();
    let ret = unsafe {
        libc::clock_gettime(
            clock_id as libc::clockid_t,
            if tp_ptr == 0 {
                ptr::null_mut()
            } else {
                tp.as_mut_ptr()
            },
        )
    };
    if ret == 0 && tp_ptr != 0 && write_guest_host_struct(memory, tp_ptr, &tp).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_nanosleep<M: GuestMemory + ?Sized>(
    memory: &mut M,
    req_ptr: u64,
    rem_ptr: u64,
) -> Option<HostIoResult> {
    if req_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let req = match read_guest_host_struct::<_, libc::timespec>(memory, req_ptr) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut rem = MaybeUninit::<libc::timespec>::zeroed();
    clear_errno();
    let ret = unsafe {
        libc::nanosleep(
            req.as_ptr(),
            if rem_ptr == 0 {
                ptr::null_mut()
            } else {
                rem.as_mut_ptr()
            },
        )
    };
    if ret != 0 && rem_ptr != 0 && write_guest_host_struct(memory, rem_ptr, &rem).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn proxy_host_mach_timebase_info<M: GuestMemory + ?Sized>(
    memory: &mut M,
    info_ptr: u64,
) -> Option<HostCallResult> {
    if info_ptr == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    let mut info = MaybeUninit::<libc::mach_timebase_info>::zeroed();
    #[allow(deprecated)]
    let ret = unsafe { libc::mach_timebase_info(info.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, info_ptr, &info).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    if ret != 0 {
        if write_guest_u32(memory, info_ptr, 1).is_err()
            || write_guest_u32(memory, info_ptr + 4, 1).is_err()
        {
            return Some(host_call_error(libc::EFAULT as u32));
        }
        return Some(HostCallResult {
            return_value: 0,
            errno: None,
        });
    }
    Some(HostCallResult {
        return_value: ret as u64,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_getrlimit<M: GuestMemory + ?Sized>(
    memory: &mut M,
    resource: u64,
    rlp_ptr: u64,
) -> Option<HostIoResult> {
    if rlp_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut rlimit = MaybeUninit::<libc::rlimit>::zeroed();
    clear_errno();
    let ret = unsafe { libc::getrlimit(resource as libc::c_int, rlimit.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, rlp_ptr, &rlimit).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_setrlimit<M: GuestMemory + ?Sized>(
    memory: &mut M,
    resource: u64,
    rlp_ptr: u64,
) -> Option<HostIoResult> {
    if rlp_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let rlimit = match read_guest_host_struct::<_, libc::rlimit>(memory, rlp_ptr) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::setrlimit(resource as libc::c_int, rlimit.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_guest_u64_value<M: GuestMemory + ?Sized>(memory: &mut M, addr: u64) -> Result<u64, u32> {
    let bytes = memory
        .read_memory(addr, 8)
        .map_err(|_| libc::EFAULT as u32)?;
    let raw = <[u8; 8]>::try_from(bytes.as_slice()).map_err(|_| libc::EFAULT as u32)?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(target_os = "macos")]
fn read_guest_sysctl_buffer<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr_addr: u64,
    len: u64,
) -> Result<Vec<u8>, u32> {
    if ptr_addr == 0 || len == 0 {
        return Ok(Vec::new());
    }
    if len as usize > MAX_GUEST_SYSCTL_BYTES {
        return Err(libc::ENOMEM as u32);
    }
    memory
        .read_memory(ptr_addr, len as usize)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn write_guest_sysctl_output<M: GuestMemory + ?Sized>(
    memory: &mut M,
    oldp: u64,
    oldlenp: u64,
    old_len: usize,
    old_buffer: &[u8],
) -> Result<(), u32> {
    if oldlenp != 0 {
        write_guest_u64(memory, oldlenp, old_len as u64).map_err(|_| libc::EFAULT as u32)?;
    }
    if oldp != 0 && old_len > 0 {
        let write_len = old_len.min(old_buffer.len());
        memory
            .write_memory(oldp, &old_buffer[..write_len])
            .map_err(|_| libc::EFAULT as u32)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn proxy_host_sysctl<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
    namelen: u64,
    oldp: u64,
    oldlenp: u64,
    newp: u64,
    newlen: u64,
) -> Option<HostIoResult> {
    if name_ptr == 0 || namelen > 1024 {
        return Some(host_io_error(libc::EINVAL as u32));
    }
    let name_bytes = match memory.read_memory(name_ptr, namelen.saturating_mul(4) as usize) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
    };
    let mut name = Vec::with_capacity(namelen as usize);
    for chunk in name_bytes.chunks_exact(4) {
        name.push(i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as libc::c_int);
    }
    proxy_host_sysctl_common(memory, Some(&mut name), None, oldp, oldlenp, newp, newlen)
}

#[cfg(target_os = "macos")]
fn proxy_host_sysctlbyname<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
    oldp: u64,
    oldlenp: u64,
    newp: u64,
    newlen: u64,
) -> Option<HostIoResult> {
    let name = read_cstring(memory, name_ptr, 4096).ok()?;
    let host_name = CString::new(name).ok()?;
    proxy_host_sysctl_common(memory, None, Some(&host_name), oldp, oldlenp, newp, newlen)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct HostSysctlSnapshot {
    ret: libc::c_int,
    errno: u32,
    value: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn host_sysctlbyname_snapshot(name: &str) -> Option<HostSysctlSnapshot> {
    let host_name = CString::new(name).ok()?;
    let mut old_len = 0usize;
    clear_errno();
    let len_ret = unsafe {
        libc::sysctlbyname(
            host_name.as_ptr(),
            ptr::null_mut(),
            &mut old_len,
            ptr::null_mut(),
            0,
        )
    };
    let len_errno = if len_ret < 0 { host_errno() } else { 0 };
    if len_ret != 0 || old_len == 0 || old_len > MAX_GUEST_SYSCTL_BYTES {
        return Some(HostSysctlSnapshot {
            ret: len_ret,
            errno: len_errno,
            value: Vec::new(),
        });
    }
    let mut value = vec![0u8; old_len];
    clear_errno();
    let ret = unsafe {
        libc::sysctlbyname(
            host_name.as_ptr(),
            value.as_mut_ptr().cast::<libc::c_void>(),
            &mut old_len,
            ptr::null_mut(),
            0,
        )
    };
    value.truncate(old_len.min(value.len()));
    Some(HostSysctlSnapshot {
        ret,
        errno: if ret < 0 { host_errno() } else { 0 },
        value,
    })
}

#[cfg(target_os = "macos")]
fn host_sysctl_mib_snapshot(mib: &[libc::c_int]) -> Option<HostSysctlSnapshot> {
    if mib.is_empty() {
        return None;
    }
    let mut name = mib.to_vec();
    let mut old_len = 0usize;
    clear_errno();
    let len_ret = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            name.len() as libc::c_uint,
            ptr::null_mut(),
            &mut old_len,
            ptr::null_mut(),
            0,
        )
    };
    let len_errno = if len_ret < 0 { host_errno() } else { 0 };
    if len_ret != 0 || old_len == 0 || old_len > MAX_GUEST_SYSCTL_BYTES {
        return Some(HostSysctlSnapshot {
            ret: len_ret,
            errno: len_errno,
            value: Vec::new(),
        });
    }
    let mut value = vec![0u8; old_len];
    clear_errno();
    let ret = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            name.len() as libc::c_uint,
            value.as_mut_ptr().cast::<libc::c_void>(),
            &mut old_len,
            ptr::null_mut(),
            0,
        )
    };
    value.truncate(old_len.min(value.len()));
    Some(HostSysctlSnapshot {
        ret,
        errno: if ret < 0 { host_errno() } else { 0 },
        value,
    })
}

#[cfg(target_os = "macos")]
fn emit_verbose_sysctl_payload(
    call: &str,
    query: &str,
    source: &str,
    ret: u64,
    errno: u32,
    oldp: u64,
    oldlenp: u64,
    value_kind: &str,
    guest_value: &[u8],
    host_snapshot: Option<&HostSysctlSnapshot>,
) {
    let args = [
        ("Query", query.to_string()),
        ("oldp", hex_arg(oldp)),
        ("oldlenp", hex_arg(oldlenp)),
    ];
    let mut fields = vec![
        ("Source", Some(source.to_string())),
        ("return", Some(format_return(ret))),
        ("return_hex", Some(format!("0x{ret:X}"))),
        ("errno", Some(errno.to_string())),
        ("ValueKind", Some(value_kind.to_string())),
        ("GuestValueText", Some(preview_text_field(guest_value))),
        ("GuestValueHex", Some(preview_hex_field(guest_value))),
        ("GuestValueBytes", Some(guest_value.len().to_string())),
    ];
    if let Some(host) = host_snapshot {
        fields.push((
            "HostReturn",
            Some(format_return(signed_return_value(host.ret as isize))),
        ));
        fields.push(("HostErrno", Some(host.errno.to_string())));
        fields.push(("HostValueText", Some(preview_text_field(&host.value))));
        fields.push(("HostValueHex", Some(preview_hex_field(&host.value))));
        fields.push(("HostValueBytes", Some(host.value.len().to_string())));
    }
    emit_verbose_identity(call, &args, &mut fields, Some(guest_value));
}

#[cfg(target_os = "macos")]
fn proxy_host_sysctl_common<M: GuestMemory + ?Sized>(
    memory: &mut M,
    mut name: Option<&mut Vec<libc::c_int>>,
    name_by_string: Option<&CString>,
    oldp: u64,
    oldlenp: u64,
    newp: u64,
    newlen: u64,
) -> Option<HostIoResult> {
    if oldp != 0 && oldlenp == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let query_name = name_by_string
        .and_then(|name| name.to_str().ok())
        .map(str::to_string);
    let query_mib = name.as_deref().map(|mib| mib.to_vec());
    let mut old_len = if oldp != 0 && oldlenp != 0 {
        match read_guest_u64_value(memory, oldlenp) {
            Ok(value) => value as usize,
            Err(errno) => return Some(host_io_error(errno)),
        }
    } else {
        0
    };
    if old_len > MAX_GUEST_SYSCTL_BYTES {
        return Some(host_io_error(libc::ENOMEM as u32));
    }
    let mut old_buffer = if oldp != 0 {
        vec![0u8; old_len]
    } else {
        Vec::new()
    };
    let mut new_buffer = match read_guest_sysctl_buffer(memory, newp, newlen) {
        Ok(buffer) => buffer,
        Err(errno) => return Some(host_io_error(errno)),
    };
    if newp == 0 && newlen == 0 {
        let identity = query_name
            .as_deref()
            .and_then(compat_identity_sysctl_by_name)
            .or_else(|| query_mib.as_deref().and_then(compat_identity_sysctl_by_mib));
        if let Some(identity) = identity {
            if let Err(errno) = write_guest_sysctl_output(
                memory,
                oldp,
                oldlenp,
                identity.value.len(),
                &identity.value,
            ) {
                return Some(host_io_error(errno));
            }
            let host_snapshot = if compat_log_config().level == CompatLogLevel::Verbose {
                query_name
                    .as_deref()
                    .and_then(host_sysctlbyname_snapshot)
                    .or_else(|| query_mib.as_deref().and_then(host_sysctl_mib_snapshot))
            } else {
                None
            };
            let call = if query_name.is_some() {
                "sysctlbyname"
            } else {
                "sysctl"
            };
            emit_verbose_sysctl_payload(
                call,
                &identity.label,
                "compat-identity",
                0,
                0,
                oldp,
                oldlenp,
                identity.value_kind,
                &identity.value,
                host_snapshot.as_ref(),
            );
            return Some(host_io_result(0, identity.value));
        }
    }
    clear_errno();
    let ret = unsafe {
        if let Some(host_name) = name_by_string {
            libc::sysctlbyname(
                host_name.as_ptr(),
                if oldp == 0 {
                    ptr::null_mut()
                } else {
                    old_buffer.as_mut_ptr().cast::<libc::c_void>()
                },
                if oldlenp == 0 {
                    ptr::null_mut()
                } else {
                    &mut old_len
                },
                if newp == 0 || new_buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    new_buffer.as_mut_ptr().cast::<libc::c_void>()
                },
                new_buffer.len(),
            )
        } else {
            let name = name.as_deref_mut()?;
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                if oldp == 0 {
                    ptr::null_mut()
                } else {
                    old_buffer.as_mut_ptr().cast::<libc::c_void>()
                },
                if oldlenp == 0 {
                    ptr::null_mut()
                } else {
                    &mut old_len
                },
                if newp == 0 || new_buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    new_buffer.as_mut_ptr().cast::<libc::c_void>()
                },
                new_buffer.len(),
            )
        }
    };
    if let Err(errno) = write_guest_sysctl_output(memory, oldp, oldlenp, old_len, &old_buffer) {
        return Some(host_io_error(errno));
    }
    let preview = old_buffer[..old_len.min(old_buffer.len())].to_vec();
    let query = query_name.unwrap_or_else(|| {
        query_mib
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    });
    emit_verbose_sysctl_payload(
        if name_by_string.is_some() {
            "sysctlbyname"
        } else {
            "sysctl"
        },
        &query,
        "host",
        signed_return_value(ret as isize),
        if ret < 0 { host_errno() } else { 0 },
        oldp,
        oldlenp,
        "host-bytes",
        &preview,
        None,
    );
    Some(host_io_result(ret as isize, preview))
}

#[cfg(target_os = "macos")]
fn checked_guest_len(len: u64) -> Result<usize, u32> {
    let len = usize::try_from(len).map_err(|_| libc::ENOMEM as u32)?;
    if len > MAX_GUEST_MEMORY_BYTES {
        return Err(libc::ENOMEM as u32);
    }
    Ok(len)
}

#[cfg(target_os = "macos")]
fn proxy_guest_malloc<M: GuestMemory + ?Sized>(
    memory: &mut M,
    size: u64,
) -> Option<HostCallResult> {
    let size = match checked_guest_len(size.max(1)) {
        Ok(size) => size,
        Err(errno) => return Some(host_null_error(errno)),
    };
    let addr = match memory.allocate_memory(size, 0x10) {
        Ok(addr) => addr,
        Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
    };
    Some(host_call_value(addr))
}

#[cfg(target_os = "macos")]
fn proxy_guest_calloc<M: GuestMemory + ?Sized>(
    memory: &mut M,
    nmemb: u64,
    size: u64,
) -> Option<HostCallResult> {
    let Some(total) = nmemb.checked_mul(size) else {
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    let total = match checked_guest_len(total.max(1)) {
        Ok(total) => total,
        Err(errno) => return Some(host_null_error(errno)),
    };
    let addr = match memory.allocate_memory(total, 0x10) {
        Ok(addr) => addr,
        Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
    };
    if memory.write_memory(addr, &vec![0u8; total]).is_err() {
        let _ = memory.free_memory(addr);
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(host_call_value(addr))
}

#[cfg(target_os = "macos")]
fn proxy_guest_realloc<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    size: u64,
) -> Option<HostCallResult> {
    if ptr == 0 {
        return proxy_guest_malloc(memory, size);
    }
    if size == 0 {
        let _ = memory.free_memory(ptr);
        return Some(host_call_value(0));
    }
    let new_size = match checked_guest_len(size) {
        Ok(new_size) => new_size,
        Err(errno) => return Some(host_null_error(errno)),
    };
    let new_ptr = match memory.allocate_memory(new_size, 0x10) {
        Ok(new_ptr) => new_ptr,
        Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
    };
    let old_size = memory.allocation_size(ptr).unwrap_or(0);
    let copy_size = old_size.min(new_size);
    if copy_size > 0 {
        if let Ok(bytes) = memory.read_memory(ptr, copy_size) {
            let _ = memory.write_memory(new_ptr, &bytes);
        }
    }
    let _ = memory.free_memory(ptr);
    Some(host_call_value(new_ptr))
}

#[cfg(target_os = "macos")]
fn proxy_guest_free<M: GuestMemory + ?Sized>(memory: &mut M, ptr: u64) -> Option<HostCallResult> {
    if ptr != 0 {
        let _ = memory.free_memory(ptr);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_posix_memalign<M: GuestMemory + ?Sized>(
    memory: &mut M,
    memptr_ptr: u64,
    alignment: u64,
    size: u64,
) -> Option<HostCallResult> {
    if memptr_ptr == 0 || alignment < 8 || !alignment.is_power_of_two() || alignment % 8 != 0 {
        return Some(host_call_value(libc::EINVAL as u64));
    }
    let size = match checked_guest_len(size.max(1)) {
        Ok(size) => size,
        Err(_) => return Some(host_call_value(libc::ENOMEM as u64)),
    };
    let Ok(alignment) = usize::try_from(alignment) else {
        return Some(host_call_value(libc::ENOMEM as u64));
    };
    let addr = match memory.allocate_memory(size, alignment) {
        Ok(addr) => addr,
        Err(_) => return Some(host_call_value(libc::ENOMEM as u64)),
    };
    if memory
        .write_memory(memptr_ptr, &addr.to_le_bytes())
        .is_err()
    {
        let _ = memory.free_memory(addr);
        return Some(host_call_value(libc::EINVAL as u64));
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_guest_memcpy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst: u64,
    src: u64,
    len: u64,
) -> Option<HostCallResult> {
    let len = match checked_guest_len(len) {
        Ok(len) => len,
        Err(errno) => return Some(host_call_error(errno)),
    };
    if len == 0 {
        return Some(host_call_value(dst));
    }
    if dst == 0 || src == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    let bytes = match memory.read_memory(src, len) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_call_error(libc::EFAULT as u32)),
    };
    if memory.write_memory(dst, &bytes).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    Some(host_call_value(dst))
}

#[cfg(target_os = "macos")]
fn proxy_guest_memset<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst: u64,
    value: u64,
    len: u64,
) -> Option<HostCallResult> {
    let len = match checked_guest_len(len) {
        Ok(len) => len,
        Err(errno) => return Some(host_call_error(errno)),
    };
    if len == 0 {
        return Some(host_call_value(dst));
    }
    if dst == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    if memory.write_memory(dst, &vec![value as u8; len]).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    Some(host_call_value(dst))
}

#[cfg(target_os = "macos")]
fn proxy_guest_memcmp<M: GuestMemory + ?Sized>(
    memory: &mut M,
    left: u64,
    right: u64,
    len: u64,
) -> Option<HostCallResult> {
    let len = match checked_guest_len(len) {
        Ok(len) => len,
        Err(errno) => return Some(host_call_error(errno)),
    };
    if len == 0 {
        return Some(host_call_value(0));
    }
    if left == 0 || right == 0 {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    let left = match memory.read_memory(left, len) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_call_error(libc::EFAULT as u32)),
    };
    let right = match memory.read_memory(right, len) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_call_error(libc::EFAULT as u32)),
    };
    let cmp = compare_bytes(&left, &right, len);
    Some(host_call_value(cmp as i64 as u64))
}

#[cfg(target_os = "macos")]
fn compare_bytes(left: &[u8], right: &[u8], len: usize) -> i32 {
    for idx in 0..len {
        let lhs = left.get(idx).copied().unwrap_or(0);
        let rhs = right.get(idx).copied().unwrap_or(0);
        if lhs != rhs {
            return lhs as i32 - rhs as i32;
        }
    }
    0
}

#[cfg(target_os = "macos")]
fn compare_cstring_bytes(left: &[u8], right: &[u8], limit: Option<usize>) -> i32 {
    let len = limit.unwrap_or_else(|| left.len().max(right.len()).saturating_add(1));
    for idx in 0..len {
        let lhs = left.get(idx).copied().unwrap_or(0);
        let rhs = right.get(idx).copied().unwrap_or(0);
        if lhs != rhs {
            return lhs as i32 - rhs as i32;
        }
        if lhs == 0 {
            return 0;
        }
    }
    0
}

#[cfg(target_os = "macos")]
fn proxy_guest_strlen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    str_ptr: u64,
) -> Option<HostCallResult> {
    let bytes = read_cstring_bytes(memory, str_ptr, MAX_GUEST_STRING_BYTES).ok()?;
    Some(host_call_value(bytes.len() as u64))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strcmp<M: GuestMemory + ?Sized>(
    memory: &mut M,
    left: u64,
    right: u64,
) -> Option<HostCallResult> {
    let left = read_cstring_bytes(memory, left, MAX_GUEST_STRING_BYTES).ok()?;
    let right = read_cstring_bytes(memory, right, MAX_GUEST_STRING_BYTES).ok()?;
    let cmp = compare_cstring_bytes(&left, &right, None);
    Some(host_call_value(cmp as i64 as u64))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strncmp<M: GuestMemory + ?Sized>(
    memory: &mut M,
    left: u64,
    right: u64,
    len: u64,
) -> Option<HostCallResult> {
    let len = match checked_guest_len(len) {
        Ok(len) => len,
        Err(errno) => return Some(host_call_error(errno)),
    };
    let left = read_cstring_bytes(memory, left, len.min(MAX_GUEST_STRING_BYTES)).ok()?;
    let right = read_cstring_bytes(memory, right, len.min(MAX_GUEST_STRING_BYTES)).ok()?;
    let cmp = compare_cstring_bytes(&left, &right, Some(len));
    Some(host_call_value(cmp as i64 as u64))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strcpy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst: u64,
    src: u64,
) -> Option<HostCallResult> {
    let mut bytes = read_cstring_bytes(memory, src, MAX_GUEST_STRING_BYTES).ok()?;
    bytes.push(0);
    if memory.write_memory(dst, &bytes).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    Some(host_call_value(dst))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strncpy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst: u64,
    src: u64,
    len: u64,
) -> Option<HostCallResult> {
    let len = match checked_guest_len(len) {
        Ok(len) => len,
        Err(errno) => return Some(host_call_error(errno)),
    };
    let mut bytes = read_cstring_bytes(memory, src, len.min(MAX_GUEST_STRING_BYTES)).ok()?;
    bytes.truncate(len);
    if bytes.len() < len {
        bytes.resize(len, 0);
    }
    if len > 0 && memory.write_memory(dst, &bytes).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    Some(host_call_value(dst))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strcat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dst: u64,
    src: u64,
) -> Option<HostCallResult> {
    let dst_bytes = read_cstring_bytes(memory, dst, MAX_GUEST_STRING_BYTES).ok()?;
    let mut src_bytes = read_cstring_bytes(memory, src, MAX_GUEST_STRING_BYTES).ok()?;
    src_bytes.push(0);
    let write_addr = dst.saturating_add(dst_bytes.len() as u64);
    if memory.write_memory(write_addr, &src_bytes).is_err() {
        return Some(host_call_error(libc::EFAULT as u32));
    }
    Some(host_call_value(dst))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strchr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    str_ptr: u64,
    needle: u64,
    last: bool,
) -> Option<HostCallResult> {
    let bytes = read_cstring_bytes(memory, str_ptr, MAX_GUEST_STRING_BYTES).ok()?;
    let needle = needle as u8;
    let found = if needle == 0 {
        Some(bytes.len())
    } else if last {
        bytes.iter().rposition(|byte| *byte == needle)
    } else {
        bytes.iter().position(|byte| *byte == needle)
    };
    Some(host_call_value(
        found
            .map(|idx| str_ptr.saturating_add(idx as u64))
            .unwrap_or(0),
    ))
}

#[cfg(target_os = "macos")]
fn proxy_guest_strdup<M: GuestMemory + ?Sized>(
    memory: &mut M,
    str_ptr: u64,
) -> Option<HostCallResult> {
    let mut bytes = read_cstring_bytes(memory, str_ptr, MAX_GUEST_STRING_BYTES).ok()?;
    bytes.push(0);
    let addr = match memory.allocate_memory(bytes.len(), 0x10) {
        Ok(addr) => addr,
        Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
    };
    if memory.write_memory(addr, &bytes).is_err() {
        let _ = memory.free_memory(addr);
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(host_call_value(addr))
}

#[cfg(target_os = "macos")]
fn allocate_guest_file_handle<M: GuestMemory + ?Sized>(
    memory: &mut M,
    file_ptr: *mut libc::FILE,
) -> Option<u64> {
    let guest_handle = memory.allocate_memory(HOST_FILE_HANDLE_SIZE, 8).ok()?;
    memory
        .write_memory(guest_handle, &0u64.to_le_bytes())
        .ok()?;
    host_file_handles().lock().ok()?.insert(
        guest_handle,
        HostFileHandle {
            file_ptr: file_ptr as usize,
        },
    );
    Some(guest_handle)
}

#[cfg(target_os = "macos")]
fn proxy_host_fopen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode_ptr: u64,
) -> Option<HostCallResult> {
    let path = read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).ok()?;
    let mode = read_cstring(memory, mode_ptr, 64).ok()?;
    let host_path = CString::new(path).ok()?;
    let host_mode = CString::new(mode).ok()?;
    clear_errno();
    let file = unsafe { libc::fopen(host_path.as_ptr(), host_mode.as_ptr()) };
    if file.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let Some(guest_handle) = allocate_guest_file_handle(memory, file) else {
        unsafe {
            libc::fclose(file);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(host_call_value(guest_handle))
}

#[cfg(target_os = "macos")]
fn proxy_host_fdopen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    mode_ptr: u64,
) -> Option<HostCallResult> {
    let mode = read_cstring(memory, mode_ptr, 64).ok()?;
    let host_mode = CString::new(mode).ok()?;
    clear_errno();
    let file = unsafe { libc::fdopen(fd as libc::c_int, host_mode.as_ptr()) };
    if file.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let Some(guest_handle) = allocate_guest_file_handle(memory, file) else {
        unsafe {
            libc::fclose(file);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(host_call_value(guest_handle))
}

#[cfg(target_os = "macos")]
fn proxy_host_fclose<M: GuestMemory + ?Sized>(memory: &mut M, stream: u64) -> Option<HostIoResult> {
    let handle = match host_file_handles().lock().ok()?.remove(&stream) {
        Some(handle) => handle,
        None => return Some(host_io_error(libc::EBADF as u32)),
    };
    clear_errno();
    let ret = unsafe { libc::fclose(handle.file_ptr as *mut libc::FILE) };
    let _ = memory.free_memory(stream);
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn guest_stdio_size(size: u64, nmemb: u64) -> Option<(usize, usize, usize)> {
    let item_size = usize::try_from(size).ok()?;
    let item_count = usize::try_from(nmemb).ok()?;
    let byte_count = item_size.checked_mul(item_count)?;
    (byte_count <= MAX_GUEST_STDIO_BYTES).then_some((item_size, item_count, byte_count))
}

#[cfg(target_os = "macos")]
fn proxy_host_fread<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    nmemb: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let (item_size, item_count, byte_count) = match guest_stdio_size(size, nmemb) {
        Some(sizes) => sizes,
        None => return Some(host_io_error(libc::EINVAL as u32)),
    };
    if byte_count > 0 && buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    if byte_count == 0 {
        return Some(HostIoResult {
            return_value: 0,
            errno: 0,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let mut data = vec![0u8; byte_count];
    clear_errno();
    let items = unsafe {
        libc::fread(
            data.as_mut_ptr().cast::<libc::c_void>(),
            item_size,
            item_count,
            file,
        )
    };
    let transferred = items.saturating_mul(item_size).min(data.len());
    if transferred > 0 && memory.write_memory(buf_ptr, &data[..transferred]).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let errno = if items < item_count && unsafe { libc::ferror(file) } != 0 {
        host_errno()
    } else {
        0
    };
    Some(HostIoResult {
        return_value: items as u64,
        errno,
        transferred,
        preview: data[..transferred.min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fwrite<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    nmemb: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let (item_size, item_count, byte_count) = match guest_stdio_size(size, nmemb) {
        Some(sizes) => sizes,
        None => return Some(host_io_error(libc::EINVAL as u32)),
    };
    if byte_count > 0 && buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    let data = if byte_count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, byte_count) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let items = unsafe {
        libc::fwrite(
            data.as_ptr().cast::<libc::c_void>(),
            item_size,
            item_count,
            file,
        )
    };
    let transferred = items.saturating_mul(item_size).min(data.len());
    let errno = if items < item_count && unsafe { libc::ferror(file) } != 0 {
        host_errno()
    } else {
        0
    };
    Some(HostIoResult {
        return_value: items as u64,
        errno,
        transferred,
        preview: data[..transferred.min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fflush(stream: u64) -> Option<HostIoResult> {
    let file = if stream == 0 {
        ptr::null_mut()
    } else {
        let Some(file) = host_file_ptr(stream) else {
            return Some(host_io_error(libc::EBADF as u32));
        };
        file
    };
    clear_errno();
    let ret = unsafe { libc::fflush(file) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fseek(stream: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fseek(file, offset as i64 as libc::c_long, whence as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ftell(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::ftell(file) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_fgets<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    stream: u64,
) -> Option<HostCallResult> {
    if buf_ptr == 0 || size == 0 || size > libc::c_int::MAX as u64 {
        return Some(host_null_error(libc::EINVAL as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_null_error(libc::EBADF as u32));
    };
    let mut data = vec![0u8; size as usize];
    clear_errno();
    let ret = unsafe {
        libc::fgets(
            data.as_mut_ptr().cast::<libc::c_char>(),
            size as libc::c_int,
            file,
        )
    };
    if ret.is_null() {
        let errno = if unsafe { libc::ferror(file) } != 0 {
            Some(host_errno())
        } else {
            None
        };
        return Some(HostCallResult {
            return_value: 0,
            errno,
        });
    }
    let write_len = data
        .iter()
        .position(|byte| *byte == 0)
        .map(|idx| idx + 1)
        .unwrap_or(data.len());
    if memory.write_memory(buf_ptr, &data[..write_len]).is_err() {
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(host_call_value(buf_ptr))
}

#[cfg(target_os = "macos")]
fn proxy_host_fputs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    text_ptr: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let text = read_cstring(memory, text_ptr, MAX_GUEST_STDIO_BYTES).ok()?;
    let bytes = text.as_bytes().to_vec();
    let host_text = CString::new(text).ok()?;
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fputs(host_text.as_ptr(), file) };
    Some(HostIoResult {
        return_value: signed_return_value(ret as isize),
        errno: if ret < 0 { host_errno() } else { 0 },
        transferred: if ret < 0 { 0 } else { bytes.len() },
        preview: bytes[..bytes.len().min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_feof(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    let ret = unsafe { libc::feof(file) };
    Some(host_call_value(ret as u64))
}

#[cfg(target_os = "macos")]
fn proxy_host_ferror(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    let ret = unsafe { libc::ferror(file) };
    Some(host_call_value(ret as u64))
}

#[cfg(target_os = "macos")]
fn proxy_host_clearerr(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::clearerr(file);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_fileno(stream: u64) -> Option<HostIoResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fileno(file) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn allocate_guest_dir_handle<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dir_ptr: *mut libc::DIR,
) -> Option<u64> {
    let guest_handle = memory.allocate_memory(8, 8).ok()?;
    memory
        .write_memory(guest_handle, &0u64.to_le_bytes())
        .ok()?;
    host_dir_handles().lock().ok()?.insert(
        guest_handle,
        HostDirHandle {
            dir_ptr: dir_ptr as usize,
            dirent_guest_ptr: 0,
        },
    );
    Some(guest_handle)
}

#[cfg(target_os = "macos")]
fn proxy_host_opendir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostCallResult> {
    let path = read_cstring(memory, path_ptr, 4096).ok()?;
    let host_path = CString::new(path).ok()?;
    clear_errno();
    let dir = unsafe { libc::opendir(host_path.as_ptr()) };
    if dir.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(host_errno()),
        });
    }
    let Some(guest_handle) = allocate_guest_dir_handle(memory, dir) else {
        unsafe {
            libc::closedir(dir);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(HostCallResult {
        return_value: guest_handle,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fdopendir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
) -> Option<HostCallResult> {
    clear_errno();
    let dir = unsafe { libc::fdopendir(fd as libc::c_int) };
    if dir.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(host_errno()),
        });
    }
    let Some(guest_handle) = allocate_guest_dir_handle(memory, dir) else {
        unsafe {
            libc::closedir(dir);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(HostCallResult {
        return_value: guest_handle,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_readdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirp: u64,
) -> Option<HostCallResult> {
    let mut handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get_mut(&dirp) else {
        return Some(host_null_error(libc::EBADF as u32));
    };
    clear_errno();
    let entry = unsafe { libc::readdir(handle.dir_ptr as *mut libc::DIR) };
    if entry.is_null() {
        let errno = host_errno();
        return Some(HostCallResult {
            return_value: 0,
            errno: (errno != 0).then_some(errno),
        });
    }
    if handle.dirent_guest_ptr == 0 {
        handle.dirent_guest_ptr = match memory.allocate_memory(HOST_DIRENT_SIZE, 8) {
            Ok(addr) => addr,
            Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
        };
    }
    let bytes = unsafe { std::slice::from_raw_parts(entry.cast::<u8>(), HOST_DIRENT_SIZE) };
    if memory.write_memory(handle.dirent_guest_ptr, bytes).is_err() {
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(HostCallResult {
        return_value: handle.dirent_guest_ptr,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_readdir_r<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirp: u64,
    entry_ptr: u64,
    result_ptr: u64,
) -> Option<HostCallResult> {
    if entry_ptr == 0 || result_ptr == 0 {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    let result = proxy_host_readdir(memory, dirp)?;
    if result.return_value == 0 {
        let _ = write_guest_u64(memory, result_ptr, 0);
        return Some(host_call_value(result.errno.unwrap_or(0) as u64));
    }
    let bytes = match memory.read_memory(result.return_value, HOST_DIRENT_SIZE) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_call_value(libc::EFAULT as u64)),
    };
    if memory.write_memory(entry_ptr, &bytes).is_err()
        || write_guest_u64(memory, result_ptr, entry_ptr).is_err()
    {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_closedir<M: GuestMemory + ?Sized>(memory: &mut M, dirp: u64) -> Option<HostIoResult> {
    let handle = match host_dir_handles().lock().ok()?.remove(&dirp) {
        Some(handle) => handle,
        None => return Some(host_io_error(libc::EBADF as u32)),
    };
    clear_errno();
    let ret = unsafe { libc::closedir(handle.dir_ptr as *mut libc::DIR) };
    let _ = memory.free_memory(dirp);
    if handle.dirent_guest_ptr != 0 {
        let _ = memory.free_memory(handle.dirent_guest_ptr);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dirfd(dirp: u64) -> Option<HostIoResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::dirfd(handle.dir_ptr as *mut libc::DIR) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rewinddir(dirp: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::rewinddir(handle.dir_ptr as *mut libc::DIR);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_telldir(dirp: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::telldir(handle.dir_ptr as *mut libc::DIR) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_seekdir(dirp: u64, loc: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::seekdir(handle.dir_ptr as *mut libc::DIR, loc as libc::c_long);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_getentropy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    if count > 256 {
        return Some(host_io_error(libc::EIO as u32));
    }
    if buf_ptr == 0 && count > 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::getentropy(data.as_mut_ptr().cast::<libc::c_void>(), data.len()) };
    if ret == 0 && count > 0 && memory.write_memory(buf_ptr, &data).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_mode_has_no_compat_services() {
        assert_eq!(CompatibilityServices::for_mode(RuntimeMode::Analysis), None);
        assert_eq!(
            CompatibilityServices::for_mode(RuntimeMode::Compat),
            Some(CompatibilityServices)
        );
    }

    #[test]
    fn host_proxy_imports_are_darwin_bound() {
        let compat = CompatibilityServices;
        #[cfg(target_os = "macos")]
        {
            assert!(compat.should_proxy_import("_puts"));
            assert!(compat.should_proxy_import("_printf"));
            assert!(compat.should_proxy_import("_snprintf"));
            assert!(compat.should_proxy_import("___snprintf_chk"));
            assert!(compat.should_proxy_import("_putchar"));
            assert!(compat.should_proxy_import("_open"));
            assert!(compat.should_proxy_import("_openat"));
            assert!(compat.should_proxy_import("_read"));
            assert!(compat.should_proxy_import("_write"));
            assert!(compat.should_proxy_import("_close"));
            assert!(compat.should_proxy_import("_socket"));
            assert!(compat.should_proxy_import("_connect"));
            assert!(compat.should_proxy_import("_send"));
            assert!(compat.should_proxy_import("_recv"));
            assert!(compat.should_proxy_import("_sendto"));
            assert!(compat.should_proxy_import("_recvfrom"));
            assert!(compat.should_proxy_import("_sendmsg"));
            assert!(compat.should_proxy_import("_recvmsg$NOCANCEL"));
            assert!(compat.should_proxy_import("_setsockopt"));
            assert!(compat.should_proxy_import("_getsockopt"));
            assert!(compat.should_proxy_import("_socketpair"));
            assert!(compat.should_proxy_import("_ioctl"));
            assert!(compat.should_proxy_import("_fsync"));
            assert!(compat.should_proxy_import("_getaddrinfo"));
            assert!(compat.should_proxy_import("_freeaddrinfo"));
            assert!(compat.should_proxy_import("_gai_strerror"));
            assert!(compat.should_proxy_import("_getnameinfo"));
            assert!(compat.should_proxy_import("_inet_pton"));
            assert!(compat.should_proxy_import("_inet_ntop"));
            assert!(compat.should_proxy_import("_inet_addr"));
            assert!(compat.should_proxy_import("_inet_aton"));
            assert!(compat.should_proxy_import("_htonl"));
            assert!(compat.should_proxy_import("_htons"));
            assert!(compat.should_proxy_import("_ntohl"));
            assert!(compat.should_proxy_import("_ntohs"));
            assert!(compat.should_proxy_import("_poll"));
            assert!(compat.should_proxy_import("_readv"));
            assert!(compat.should_proxy_import("_writev$NOCANCEL"));
            assert!(compat.should_proxy_import("_pread"));
            assert!(compat.should_proxy_import("_pwrite$NOCANCEL"));
            assert!(compat.should_proxy_import("_lseek"));
            assert!(compat.should_proxy_import("_dup"));
            assert!(compat.should_proxy_import("_dup2"));
            assert!(compat.should_proxy_import("_pipe"));
            assert!(compat.should_proxy_import("_select$NOCANCEL"));
            assert!(compat.should_proxy_import("_select$1050"));
            assert!(compat.should_proxy_import("___darwin_check_fd_set_overflow"));
            assert!(compat.should_proxy_import("___chkstk_darwin"));
            assert!(compat.should_proxy_import("_access"));
            assert!(compat.should_proxy_import("_access$UNIX2003"));
            assert!(compat.should_proxy_import("_faccessat"));
            assert!(compat.should_proxy_import("_chmod"));
            assert!(compat.should_proxy_import("_fchmod"));
            assert!(compat.should_proxy_import("_fchmodat"));
            assert!(compat.should_proxy_import("_chdir"));
            assert!(compat.should_proxy_import("_fchdir"));
            assert!(compat.should_proxy_import("_getcwd"));
            assert!(compat.should_proxy_import("_stat$INODE64"));
            assert!(compat.should_proxy_import("_lstat64"));
            assert!(compat.should_proxy_import("_fstat"));
            assert!(compat.should_proxy_import("_fstatat$INODE64"));
            assert!(compat.should_proxy_import("_statfs"));
            assert!(compat.should_proxy_import("_fstatfs64"));
            assert!(compat.should_proxy_import("_truncate"));
            assert!(compat.should_proxy_import("_ftruncate"));
            assert!(compat.should_proxy_import("_mkdir"));
            assert!(compat.should_proxy_import("_mkdirat"));
            assert!(compat.should_proxy_import("_rmdir"));
            assert!(compat.should_proxy_import("_unlink"));
            assert!(compat.should_proxy_import("_unlinkat"));
            assert!(compat.should_proxy_import("_rename"));
            assert!(compat.should_proxy_import("_renameat"));
            assert!(compat.should_proxy_import("_readlink"));
            assert!(compat.should_proxy_import("_readlinkat"));
            assert!(compat.should_proxy_import("_symlink"));
            assert!(compat.should_proxy_import("_realpath"));
            assert!(compat.should_proxy_import("_getenv"));
            assert!(compat.should_proxy_import("_setenv"));
            assert!(compat.should_proxy_import("_unsetenv"));
            assert!(compat.should_proxy_import("_getpid"));
            assert!(compat.should_proxy_import("_getppid"));
            assert!(compat.should_proxy_import("_getuid"));
            assert!(compat.should_proxy_import("_geteuid"));
            assert!(compat.should_proxy_import("_getgid"));
            assert!(compat.should_proxy_import("_getegid"));
            assert!(compat.should_proxy_import("_sysconf"));
            assert!(compat.should_proxy_import("_gethostname"));
            assert!(compat.should_proxy_import("_uname"));
            assert!(compat.should_proxy_import("_gettimeofday"));
            assert!(compat.should_proxy_import("_clock_gettime"));
            assert!(compat.should_proxy_import("_nanosleep"));
            assert!(compat.should_proxy_import("_sleep"));
            assert!(compat.should_proxy_import("_usleep"));
            assert!(compat.should_proxy_import("_mach_absolute_time"));
            assert!(compat.should_proxy_import("_mach_timebase_info"));
            assert!(compat.should_proxy_import("_getrlimit"));
            assert!(compat.should_proxy_import("_setrlimit"));
            assert!(compat.should_proxy_import("_sysctl"));
            assert!(compat.should_proxy_import("_sysctlbyname"));
            assert!(compat.should_proxy_import("_mlock"));
            assert!(compat.should_proxy_import("_munlock"));
            assert!(compat.should_proxy_import("_madvise"));
            assert!(compat.should_proxy_import("_umask"));
            assert!(compat.should_proxy_import("_fopen"));
            assert!(compat.should_proxy_import("_fdopen"));
            assert!(compat.should_proxy_import("_fclose"));
            assert!(compat.should_proxy_import("_fread"));
            assert!(compat.should_proxy_import("_fwrite"));
            assert!(compat.should_proxy_import("_fflush"));
            assert!(compat.should_proxy_import("_fseek"));
            assert!(compat.should_proxy_import("_ftell"));
            assert!(compat.should_proxy_import("_fgets"));
            assert!(compat.should_proxy_import("_fputs"));
            assert!(compat.should_proxy_import("_feof"));
            assert!(compat.should_proxy_import("_ferror"));
            assert!(compat.should_proxy_import("_clearerr"));
            assert!(compat.should_proxy_import("_fileno"));
            assert!(compat.should_proxy_import("_malloc"));
            assert!(compat.should_proxy_import("_calloc"));
            assert!(compat.should_proxy_import("_realloc"));
            assert!(compat.should_proxy_import("_free"));
            assert!(compat.should_proxy_import("_posix_memalign"));
            assert!(compat.should_proxy_import("_memcpy"));
            assert!(compat.should_proxy_import("_memmove"));
            assert!(compat.should_proxy_import("_memset"));
            assert!(compat.should_proxy_import("_bzero"));
            assert!(compat.should_proxy_import("_memcmp"));
            assert!(compat.should_proxy_import("_strlen"));
            assert!(compat.should_proxy_import("_strcmp"));
            assert!(compat.should_proxy_import("_strncmp"));
            assert!(compat.should_proxy_import("_strcpy"));
            assert!(compat.should_proxy_import("_strncpy"));
            assert!(compat.should_proxy_import("_strcat"));
            assert!(compat.should_proxy_import("_strchr"));
            assert!(compat.should_proxy_import("_strrchr"));
            assert!(compat.should_proxy_import("_strdup"));
            assert!(compat.should_proxy_import("__ZNSt3__112__next_primeEm"));
            assert!(compat.should_proxy_import("_ZNSt3__112__next_primeEm"));
            assert!(compat.should_proxy_import("___cxa_guard_acquire"));
            assert!(compat.should_proxy_import("__cxa_guard_acquire"));
            assert!(compat.should_proxy_import("___cxa_guard_release"));
            assert!(compat.should_proxy_import("___cxa_guard_abort"));
            assert!(compat.should_proxy_import(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc"
            ));
            assert!(compat.should_proxy_import(
                "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm"
            ));
            assert!(compat.should_proxy_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm"
            ));
            assert!(compat.should_proxy_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm"
            ));
            assert!(compat.should_proxy_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv"
            ));
            assert!(compat.should_proxy_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv"
            ));
            assert!(compat.should_proxy_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE8capacityEv"
            ));
            assert!(compat.should_proxy_import(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEm"
            ));
            assert!(compat.should_proxy_import(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev"
            ));
            assert!(compat.should_proxy_import(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_"
            ));
            assert!(compat.should_proxy_import("__ZNKSt3__16vectorIcNS_9allocatorIcEEE4sizeEv"));
            assert!(compat.should_proxy_import("__ZNKSt3__16vectorIhNS_9allocatorIhEEE4dataEv"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEE7reserveEm"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEE6resizeEmRKc"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEE5beginEv"));
            assert!(compat.should_proxy_import("__ZNKSt3__16vectorIcNS_9allocatorIcEEE3endEv"));
            assert!(compat.should_proxy_import("__ZNKSt3__16vectorIcNS_9allocatorIcEEEixEm"));
            assert!(compat.should_proxy_import("__ZNKSt3__16vectorIcNS_9allocatorIcEEE5frontEv"));
            assert!(
                compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEE9push_backERKc")
            );
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEE8pop_backEv"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEEC1Ev"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEEC1ERKS3_"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEEaSERKS3_"));
            assert!(compat.should_proxy_import("__ZNSt3__16vectorIcNS_9allocatorIcEEED1Ev"));
            assert!(compat.should_proxy_import("_opendir"));
            assert!(compat.should_proxy_import("_fdopendir"));
            assert!(compat.should_proxy_import("_readdir"));
            assert!(compat.should_proxy_import("_readdir_r"));
            assert!(compat.should_proxy_import("_closedir"));
            assert!(compat.should_proxy_import("_dirfd"));
            assert!(compat.should_proxy_import("_rewinddir"));
            assert!(compat.should_proxy_import("_telldir"));
            assert!(compat.should_proxy_import("_seekdir"));
            assert!(compat.should_proxy_import("_getentropy"));
            assert!(compat.should_proxy_import("_pthread_threading_np"));
            assert!(compat.should_proxy_import("_pthread_sigmask"));
            assert!(compat.should_proxy_import("__NSGetExecutablePath"));
            assert!(compat.should_proxy_import("_NSGetExecutablePath"));
            assert!(compat.should_proxy_import("_issetugid"));
            assert!(compat.should_proxy_import("_issetguid"));
            assert!(compat.should_proxy_import("_execl"));
            assert!(compat.should_proxy_import("_execlp"));
            assert!(compat.should_proxy_import("_execv"));
            assert!(compat.should_proxy_import("_execve"));
            assert!(compat.should_proxy_import("_execvp"));
            assert!(compat.should_proxy_import("_getprogname"));
            assert!(compat.should_proxy_import("_setprogname"));
            assert!(compat.should_proxy_import("__dyld_image_count"));
            assert!(compat.should_proxy_import("_dyld_image_count"));
            assert!(compat.should_proxy_import("__dyld_get_image_name"));
            assert!(compat.should_proxy_import("_dyld_get_image_name"));
            assert!(compat.should_proxy_import("__dyld_get_image_header"));
            assert!(compat.should_proxy_import("_dyld_get_image_header"));
            assert!(compat.should_proxy_import("__dyld_get_image_vmaddr_slide"));
            assert!(compat.should_proxy_import("_dyld_get_image_vmaddr_slide"));
            assert!(compat.should_proxy_import("_dladdr"));
            assert!(compat.should_proxy_import("_pthread_once"));
            assert!(compat.should_proxy_import("_pthread_mutexattr_init"));
            assert!(compat.should_proxy_import("_pthread_mutexattr_settype"));
            assert!(compat.should_proxy_import("_pthread_mutexattr_destroy"));
            assert!(compat.should_proxy_import("_pthread_attr_init"));
            assert!(compat.should_proxy_import("_pthread_attr_destroy"));
            assert!(compat.should_proxy_import("_pthread_attr_getstacksize"));
            assert!(compat.should_proxy_import("_pthread_attr_setstacksize"));
            assert!(compat.should_proxy_import("_pthread_attr_setdetachstate"));
            assert!(compat.should_proxy_import("_os_unfair_lock_lock"));
            assert!(compat.should_proxy_import("_os_unfair_lock_trylock"));
            assert!(compat.should_proxy_import("_os_unfair_lock_unlock"));
            assert!(compat.should_proxy_import("_os_unfair_lock_assert_owner"));
            assert!(compat.should_proxy_import("_os_unfair_lock_assert_not_owner"));
        }
        #[cfg(not(target_os = "macos"))]
        assert!(!compat.should_proxy_import("_puts"));
    }

    #[test]
    fn libcxx_next_prime_fallback_matches_common_bucket_growth_values() {
        assert_eq!(compat_next_prime(0), 0);
        assert_eq!(compat_next_prime(1), 2);
        assert_eq!(compat_next_prime(2), 2);
        assert_eq!(compat_next_prime(3), 3);
        assert_eq!(compat_next_prime(4), 5);
        assert_eq!(compat_next_prime(31), 31);
        assert_eq!(compat_next_prime(32), 37);
        assert_eq!(compat_next_prime(1000), 1009);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cxa_guard_proxy_models_local_static_lifecycle() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, &[0u8; CXA_GUARD_SIZE]);

        let first = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_acquire",
                &[0x1000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("___cxa_guard_acquire should be proxied");
        assert_eq!(first.return_value, 1);
        assert_eq!(memory.read_memory(0x1000, 2).unwrap(), vec![0, 1]);

        let recursive = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "__cxa_guard_acquire",
                &[0x1000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("__cxa_guard_acquire should be proxied");
        assert_eq!(recursive.return_value, 0);

        let release = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_release",
                &[0x1000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("___cxa_guard_release should be proxied");
        assert_eq!(release.return_value, 0);
        assert_eq!(memory.read_memory(0x1000, 2).unwrap(), vec![1, 0]);

        let after_release = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_acquire",
                &[0x1000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("released guard acquire should be proxied");
        assert_eq!(after_release.return_value, 0);

        memory.write_guest(0x2000, &[0u8; CXA_GUARD_SIZE]);
        let pending = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_acquire",
                &[0x2000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("second guard acquire should be proxied");
        assert_eq!(pending.return_value, 1);

        let abort = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_abort",
                &[0x2000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("___cxa_guard_abort should be proxied");
        assert_eq!(abort.return_value, 0);
        assert_eq!(memory.read_memory(0x2000, 2).unwrap(), vec![0, 0]);

        let after_abort = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___cxa_guard_acquire",
                &[0x2000, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("aborted guard acquire should be proxied again");
        assert_eq!(after_abort.return_value, 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bzero_proxy_zeros_guest_memory() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"abcdef");
        let result = CompatibilityServices
            .proxy_arm64_import(&mut memory, "_bzero", &[0x1001, 3, 0, 0, 0, 0, 0, 0])
            .expect("_bzero should be proxied");

        assert_eq!(result.return_value, 0x1001);
        assert_eq!(result.errno, None);
        assert_eq!(
            memory.read_memory(0x1000, 6).unwrap(),
            vec![b'a', 0, 0, 0, b'e', b'f']
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn chkstk_darwin_proxy_is_non_mutating_noop() {
        #[derive(Default)]
        struct TestMemory;

        impl GuestMemory for TestMemory {
            fn read_memory(
                &mut self,
                _addr: u64,
                _size: usize,
            ) -> Result<Vec<u8>, GuestMemoryError> {
                Err(GuestMemoryError)
            }

            fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), GuestMemoryError> {
                Err(GuestMemoryError)
            }
        }

        let mut memory = TestMemory;
        let result = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "___chkstk_darwin",
                &[0x1234, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("___chkstk_darwin should be proxied");

        assert_eq!(result.return_value, 0x1234);
        assert_eq!(result.errno, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn printf_renderer_prefers_darwin_stack_varargs() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"dlsym\0");
        memory.write_guest(0x2000, &0x1000u64.to_le_bytes());
        memory.write_guest(0x3000, b"register\0");

        let stack_args = read_stack_u64_args(&mut memory, 0x2000, 1);
        assert_eq!(
            render_arm64_printf(
                &mut memory,
                "compat %s path\n",
                &[0x3000],
                Some(&stack_args)
            ),
            "compat dlsym path\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn printf_renderer_honors_width_and_zero_padding() {
        #[derive(Default)]
        struct TestMemory;

        impl GuestMemory for TestMemory {
            fn read_memory(
                &mut self,
                _addr: u64,
                _size: usize,
            ) -> Result<Vec<u8>, GuestMemoryError> {
                Err(GuestMemoryError)
            }

            fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), GuestMemoryError> {
                Ok(())
            }
        }

        let mut memory = TestMemory;
        assert_eq!(
            render_arm64_printf(
                &mut memory,
                "addr=0x%08x short=0x%04x ptr=%018p count=%5u left=%-4u\n",
                &[0x0100007f, 0x5713, 0xabc, 7, 7],
                None
            ),
            "addr=0x0100007f short=0x5713 ptr=0x0000000000000abc count=    7 left=7   \n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn printf_renderer_consumes_dynamic_width_and_precision_args() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"glue-cxx!\0");
        for (index, value) in [4u64, 0x1000, 77, 12, 0x1000].iter().enumerate() {
            memory.write_guest(0x2000 + (index as u64 * 8), &value.to_le_bytes());
        }
        let stack_args = read_stack_u64_args(&mut memory, 0x2000, 5);

        assert_eq!(
            render_arm64_printf(
                &mut memory,
                "text=%.*s next=%d width=%*s\n",
                &[99, 0x3000, 11, 2, 0x3000],
                Some(&stack_args)
            ),
            "text=glue next=77 width=   glue-cxx!\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn snprintf_proxy_writes_truncated_guest_string() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"%s/%s\0");
        memory.write_guest(0x2000, b"base\0");
        memory.write_guest(0x3000, b"file\0");

        let result = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "_snprintf",
                &[0x4000, 8, 0x1000, 0x2000, 0x3000, 0, 0, 0],
            )
            .expect("_snprintf should be proxied");

        assert_eq!(result.return_value, 9);
        assert_eq!(result.errno, None);
        assert_eq!(
            memory.read_memory(0x4000, 8).unwrap(),
            b"base/fi\0".to_vec()
        );

        let zero_size = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "_snprintf",
                &[0, 0, 0x1000, 0x2000, 0x3000, 0, 0, 0],
            )
            .expect("_snprintf size-zero call should be proxied");
        assert_eq!(zero_size.return_value, 9);
        assert_eq!(zero_size.errno, None);

        let null_dst = CompatibilityServices
            .proxy_arm64_import(
                &mut memory,
                "_snprintf",
                &[0, 8, 0x1000, 0x2000, 0x3000, 0, 0, 0],
            )
            .expect("_snprintf null destination should return an errno result");
        assert_eq!(null_dst.return_value, u64::MAX);
        assert_eq!(null_dst.errno, Some(libc::EFAULT as u32));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn snprintf_chk_proxy_uses_darwin_stack_varargs() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"%s/%s\0");
        memory.write_guest(0x2000, b"root\0");
        memory.write_guest(0x3000, b"leaf\0");
        memory.write_guest(0x5000, &0x2000u64.to_le_bytes());
        memory.write_guest(0x5008, &0x3000u64.to_le_bytes());

        let result = CompatibilityServices
            .proxy_arm64_import_with_stack(
                &mut memory,
                "___snprintf_chk",
                &[0x4000, 32, 0, 32, 0x1000, 0, 0, 0],
                Some(0x5000),
            )
            .expect("___snprintf_chk should be proxied");

        assert_eq!(result.return_value, 9);
        assert_eq!(result.errno, None);
        assert_eq!(
            memory.read_memory(0x4000, 10).unwrap(),
            b"root/leaf\0".to_vec()
        );
    }

    fn darwin_msghdr_fixture_bytes() -> Vec<u8> {
        fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
            put_u32(bytes, offset, value as u32);
        }

        fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let mut raw = vec![0u8; DARWIN_MSGHDR_SIZE];
        put_u64(&mut raw, DARWIN_MSGHDR_NAME, 0x1111);
        put_u32(&mut raw, DARWIN_MSGHDR_NAMELEN, 12);
        put_u64(&mut raw, DARWIN_MSGHDR_IOV, 0x2222);
        put_i32(&mut raw, DARWIN_MSGHDR_IOVLEN, 2);
        put_u64(&mut raw, DARWIN_MSGHDR_CONTROL, 0x3333);
        put_u32(&mut raw, DARWIN_MSGHDR_CONTROLLEN, 24);
        put_i32(&mut raw, DARWIN_MSGHDR_FLAGS, 0x40);
        raw
    }

    fn expected_darwin_msghdr() -> GuestMsghdr {
        GuestMsghdr {
            name: 0x1111,
            namelen: 12,
            iov: 0x2222,
            iovlen: 2,
            control: 0x3333,
            controllen: 24,
            flags: 0x40,
        }
    }

    #[test]
    fn msghdr_parser_uses_darwin_guest_layout() {
        let raw = darwin_msghdr_fixture_bytes();
        assert_eq!(parse_darwin_msghdr(&raw), Some(expected_darwin_msghdr()));
        assert_eq!(parse_darwin_msghdr(&raw[..DARWIN_MSGHDR_SIZE - 1]), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn msghdr_output_write_preserves_darwin_pointer_fields() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        let raw = darwin_msghdr_fixture_bytes();
        memory.write_guest(0x1000, &raw);

        let mut msg = read_guest_msghdr(&mut memory, 0x1000).unwrap();
        assert_eq!(msg, expected_darwin_msghdr());

        msg.namelen = 8;
        msg.controllen = 16;
        msg.flags = 0x80;
        write_guest_msghdr_outputs(&mut memory, 0x1000, &msg).unwrap();

        let updated = memory.read_memory(0x1000, DARWIN_MSGHDR_SIZE).unwrap();
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_NAME), Some(0x1111));
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_IOV), Some(0x2222));
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_CONTROL), Some(0x3333));
        assert_eq!(read_u32_at(&updated, DARWIN_MSGHDR_NAMELEN), Some(8));
        assert_eq!(read_u32_at(&updated, DARWIN_MSGHDR_CONTROLLEN), Some(16));
        assert_eq!(read_i32_at(&updated, DARWIN_MSGHDR_FLAGS), Some(0x80));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pipe_readiness_cache_marks_read_end_ready() {
        let read_fd = 700;
        let write_fd = 701;
        note_host_fd_close(read_fd as u64);
        note_host_fd_close(write_fd as u64);

        note_host_pipe(read_fd, write_fd);
        let read_set = HashSet::from([read_fd]);
        assert!(collect_tracked_read_ready(Some(&read_set)).is_empty());

        note_host_fd_write(write_fd as u64, 1);
        assert_eq!(collect_tracked_read_ready(Some(&read_set)), read_set);

        note_host_fd_read(read_fd as u64, 1);
        assert!(collect_tracked_read_ready(Some(&read_set)).is_empty());

        note_host_fd_close(read_fd as u64);
        note_host_fd_close(write_fd as u64);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn select_fallback_can_infer_single_requested_read_fd() {
        let empty = HashSet::new();
        let inferred = infer_single_read_fd(Some(&empty), 0x1000, 4)
            .expect("empty read fd_set with nfds should infer the highest fd");
        assert_eq!(inferred, HashSet::from([3]));

        let non_empty = HashSet::from([2]);
        assert!(infer_single_read_fd(Some(&non_empty), 0x1000, 4).is_none());
        assert!(infer_single_read_fd(Some(&empty), 0, 4).is_none());
        assert!(infer_single_read_fd(Some(&empty), 0x1000, 0).is_none());
    }
}
