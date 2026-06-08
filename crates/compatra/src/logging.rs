use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::report::record_compat_call_result;
use crate::{HostCallResult, HostIoResult, HostOpenResult, HostPipeResult};

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

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Summary => "summary",
            Self::Calls => "calls",
            Self::Verbose => "verbose",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CompatLogConfig {
    pub(crate) level: CompatLogLevel,
    filter: HashSet<String>,
    pub(crate) preview_bytes: usize,
}

impl CompatLogConfig {
    fn from_env() -> Self {
        Self::from_env_values(
            std::env::var("COMPATRA_COMPAT_LOG").ok().as_deref(),
            std::env::var("COMPATRA_COMPAT_LOG_FILTER").ok().as_deref(),
            std::env::var("COMPATRA_COMPAT_LOG_PREVIEW_BYTES")
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
    static COMPAT_LOG_DEPTH: Cell<usize> = const { Cell::new(0) };
    static COMPAT_PENDING_STOP_REASON: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn take_pending_stop_reason() -> Option<String> {
    COMPAT_PENDING_STOP_REASON.with(|reason| reason.borrow_mut().take())
}

#[cfg(target_os = "macos")]
pub(crate) fn set_pending_stop_reason(reason: impl Into<String>) {
    COMPAT_PENDING_STOP_REASON.with(|slot| {
        *slot.borrow_mut() = Some(reason.into());
    });
}

#[derive(Debug)]
pub(crate) struct CompatLogScope {
    outermost: bool,
}

impl CompatLogScope {
    pub(crate) fn enter() -> Self {
        let outermost = COMPAT_LOG_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_add(1));
            current == 0
        });
        Self { outermost }
    }

    pub(crate) fn call_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostCallResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno.unwrap_or(0) != 0 || result.return_value == u64::MAX
        });
        if self.outermost {
            record_compat_call_result(kind, call, result.is_some(), error);
        }
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

    pub(crate) fn io_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostIoResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno != 0 || result.return_value == u64::MAX
        });
        if self.outermost {
            record_compat_call_result(kind, call, result.is_some(), error);
        }
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

    pub(crate) fn open_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostOpenResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| {
            result.errno != 0 || result.return_value == u64::MAX
        });
        if self.outermost {
            record_compat_call_result(kind, call, result.is_some(), error);
        }
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

    pub(crate) fn pipe_result(
        &self,
        kind: &str,
        call: &str,
        args: &[(&str, String)],
        result: &Option<HostPipeResult>,
    ) {
        let error = result.as_ref().map_or(true, |result| result.errno != 0);
        if self.outermost {
            record_compat_call_result(kind, call, result.is_some(), error);
        }
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

pub(crate) fn compat_log_config() -> &'static CompatLogConfig {
    static CONFIG: OnceLock<CompatLogConfig> = OnceLock::new();
    CONFIG.get_or_init(CompatLogConfig::from_env)
}

pub(crate) fn normalize_log_call_name(call: &str) -> String {
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
            | "system"
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

pub(crate) fn format_return(value: u64) -> String {
    if value == u64::MAX {
        "-1".to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn hex_arg(value: u64) -> String {
    format!("0x{value:X}")
}

#[cfg(target_os = "macos")]
pub(crate) fn json_string_array(values: &[String]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(value));
        out.push('"');
    }
    out.push(']');
    out
}

pub(crate) fn json_escape(input: &str) -> String {
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

pub(crate) fn compat_log_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn compat_preview_text(bytes: &[u8]) -> String {
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

pub(crate) fn compat_preview_hex(bytes: &[u8]) -> String {
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

pub(crate) fn emit_compat_log_line(
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
pub(crate) fn emit_verbose_compat_payload(
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn json_string_array_formats_argv_text() {
        let argv = vec![
            "/bin/zsh".to_string(),
            "-s".to_string(),
            "quote\"backslash\\".to_string(),
        ];

        assert_eq!(
            super::json_string_array(&argv),
            r#"["/bin/zsh","-s","quote\"backslash\\"]"#
        );
    }
}
