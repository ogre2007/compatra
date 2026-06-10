use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use crate::logging::{
    compat_log_config, compat_log_timestamp_us, json_escape, normalize_log_call_name,
    CompatLogLevel,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatCapabilityStatus {
    Proxied,
    Failed,
    Unhandled,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CompatCallStats {
    kind: String,
    call: String,
    family: String,
    count: u64,
    proxied: u64,
    failed: u64,
    unhandled: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CompatFamilyStats {
    count: u64,
    failed: u64,
    unhandled: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CompatCapabilityStats {
    total_calls: u64,
    proxied_calls: u64,
    failed_calls: u64,
    unhandled_calls: u64,
    unhandled_imports: u64,
    unknown_import_addresses: u64,
    unresolved_dlsym: u64,
    calls: BTreeMap<String, CompatCallStats>,
    families: BTreeMap<String, CompatFamilyStats>,
    missing_symbols: BTreeMap<String, u64>,
}

fn capability_stats() -> &'static Mutex<CompatCapabilityStats> {
    static STATS: OnceLock<Mutex<CompatCapabilityStats>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(CompatCapabilityStats::default()))
}

fn compat_capability_report_env() -> Option<bool> {
    let value = std::env::var("COMPATRA_COMPAT_REPORT").ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(match value.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" | "none" => false,
        "1" | "true" | "yes" | "on" | "summary" | "report" => true,
        _ => true,
    })
}

pub fn compat_capability_report_enabled() -> bool {
    compat_capability_report_env()
        .unwrap_or_else(|| compat_log_config().level != CompatLogLevel::Off)
}

pub(crate) fn record_compat_call_result(kind: &str, call: &str, handled: bool, error: bool) {
    let status = if !handled {
        CompatCapabilityStatus::Unhandled
    } else if error {
        CompatCapabilityStatus::Failed
    } else {
        CompatCapabilityStatus::Proxied
    };
    let normalized = normalize_log_call_name(call);
    let family = compat_call_family(call, &normalized).to_string();
    let key = format!("{kind}:{normalized}");
    let Ok(mut stats) = capability_stats().lock() else {
        return;
    };

    stats.total_calls = stats.total_calls.saturating_add(1);
    match status {
        CompatCapabilityStatus::Proxied => {
            stats.proxied_calls = stats.proxied_calls.saturating_add(1);
        }
        CompatCapabilityStatus::Failed => {
            stats.proxied_calls = stats.proxied_calls.saturating_add(1);
            stats.failed_calls = stats.failed_calls.saturating_add(1);
        }
        CompatCapabilityStatus::Unhandled => {
            stats.unhandled_calls = stats.unhandled_calls.saturating_add(1);
        }
    }

    let call_stats = stats.calls.entry(key).or_insert_with(|| CompatCallStats {
        kind: kind.to_string(),
        call: normalized,
        family: family.clone(),
        ..CompatCallStats::default()
    });
    call_stats.count = call_stats.count.saturating_add(1);
    match status {
        CompatCapabilityStatus::Proxied => {
            call_stats.proxied = call_stats.proxied.saturating_add(1);
        }
        CompatCapabilityStatus::Failed => {
            call_stats.proxied = call_stats.proxied.saturating_add(1);
            call_stats.failed = call_stats.failed.saturating_add(1);
        }
        CompatCapabilityStatus::Unhandled => {
            call_stats.unhandled = call_stats.unhandled.saturating_add(1);
        }
    }

    let family_stats = stats.families.entry(family).or_default();
    family_stats.count = family_stats.count.saturating_add(1);
    if status == CompatCapabilityStatus::Failed {
        family_stats.failed = family_stats.failed.saturating_add(1);
    } else if status == CompatCapabilityStatus::Unhandled {
        family_stats.unhandled = family_stats.unhandled.saturating_add(1);
    }
}

pub(crate) fn record_unhandled_import(symbol: &str) {
    record_missing_symbol(symbol);
    if let Ok(mut stats) = capability_stats().lock() {
        stats.unhandled_imports = stats.unhandled_imports.saturating_add(1);
    }
}

pub(crate) fn record_unknown_import_address() {
    if let Ok(mut stats) = capability_stats().lock() {
        stats.unknown_import_addresses = stats.unknown_import_addresses.saturating_add(1);
    }
}

pub(crate) fn record_unresolved_dlsym(symbol: &str) {
    record_missing_symbol(symbol);
    if let Ok(mut stats) = capability_stats().lock() {
        stats.unresolved_dlsym = stats.unresolved_dlsym.saturating_add(1);
    }
}

fn record_missing_symbol(symbol: &str) {
    let symbol = symbol.trim();
    if symbol.is_empty() {
        return;
    }
    let normalized = symbol.to_string();
    if let Ok(mut stats) = capability_stats().lock() {
        *stats.missing_symbols.entry(normalized).or_insert(0) += 1;
    }
}

pub fn reset_compat_capability_report() {
    if let Ok(mut stats) = capability_stats().lock() {
        *stats = CompatCapabilityStats::default();
    }
}

pub fn compat_capability_report_json() -> String {
    let snapshot = capability_stats()
        .lock()
        .map(|stats| stats.clone())
        .unwrap_or_default();

    let mut out = String::new();
    out.push('{');
    out.push_str("\"plugin\":\"compat\"");
    push_json_field(
        &mut out,
        "TimeStamp",
        &compat_log_timestamp_us().to_string(),
    );
    let level = match compat_log_config().level {
        CompatLogLevel::Off => "summary",
        level => level.as_str(),
    };
    push_json_field(&mut out, "Level", level);
    push_json_field(&mut out, "Kind", "capability-report");
    push_json_field(&mut out, "Call", "capability-report");
    push_json_number(&mut out, "TotalCalls", snapshot.total_calls);
    push_json_number(&mut out, "ProxiedCalls", snapshot.proxied_calls);
    push_json_number(&mut out, "FailedProxies", snapshot.failed_calls);
    push_json_number(&mut out, "UnhandledCalls", snapshot.unhandled_calls);
    push_json_number(&mut out, "UnhandledImports", snapshot.unhandled_imports);
    push_json_number(
        &mut out,
        "UnknownImportAddresses",
        snapshot.unknown_import_addresses,
    );
    push_json_number(&mut out, "UnresolvedDlsym", snapshot.unresolved_dlsym);
    push_json_number(&mut out, "UniqueCalls", snapshot.calls.len() as u64);
    push_json_number(
        &mut out,
        "UniqueMissingSymbols",
        snapshot.missing_symbols.len() as u64,
    );
    push_json_raw(&mut out, "Families", &render_family_stats(&snapshot));
    push_json_raw(&mut out, "TopCalls", &render_call_stats(&snapshot));
    push_json_raw(
        &mut out,
        "MissingSymbols",
        &render_missing_symbols(&snapshot),
    );
    out.push('}');
    out
}

pub fn emit_compat_capability_report() {
    if !compat_capability_report_enabled() {
        return;
    }
    let _ = writeln!(std::io::stderr(), "{}", compat_capability_report_json());
}

fn render_family_stats(snapshot: &CompatCapabilityStats) -> String {
    let mut families = snapshot.families.iter().collect::<Vec<_>>();
    families.sort_by(|(left_name, left), (right_name, right)| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left_name.cmp(right_name))
    });

    let mut out = String::from("[");
    for (index, (family, stats)) in families.into_iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('{');
        let mut first = true;
        push_object_string_field(&mut out, &mut first, "Family", family);
        push_object_number_field(&mut out, &mut first, "Count", stats.count);
        push_object_number_field(&mut out, &mut first, "Failed", stats.failed);
        push_object_number_field(&mut out, &mut first, "Unhandled", stats.unhandled);
        out.push('}');
    }
    out.push(']');
    out
}

fn render_call_stats(snapshot: &CompatCapabilityStats) -> String {
    let mut calls = snapshot.calls.values().collect::<Vec<_>>();
    calls.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.call.cmp(&right.call))
            .then_with(|| left.kind.cmp(&right.kind))
    });

    let mut out = String::from("[");
    for (index, stats) in calls.into_iter().take(20).enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('{');
        let mut first = true;
        push_object_string_field(&mut out, &mut first, "Kind", &stats.kind);
        push_object_string_field(&mut out, &mut first, "Call", &stats.call);
        push_object_string_field(&mut out, &mut first, "Family", &stats.family);
        push_object_number_field(&mut out, &mut first, "Count", stats.count);
        push_object_number_field(&mut out, &mut first, "Proxied", stats.proxied);
        push_object_number_field(&mut out, &mut first, "Failed", stats.failed);
        push_object_number_field(&mut out, &mut first, "Unhandled", stats.unhandled);
        out.push('}');
    }
    out.push(']');
    out
}

fn render_missing_symbols(snapshot: &CompatCapabilityStats) -> String {
    let mut symbols = snapshot.missing_symbols.iter().collect::<Vec<_>>();
    symbols.sort_by(|(left_symbol, left_count), (right_symbol, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_symbol.cmp(right_symbol))
    });

    let mut out = String::from("[");
    for (index, (symbol, count)) in symbols.into_iter().take(40).enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('{');
        let mut first = true;
        push_object_string_field(&mut out, &mut first, "Symbol", symbol);
        push_object_string_field(
            &mut out,
            &mut first,
            "Family",
            compat_call_family(symbol, &normalize_log_call_name(symbol)),
        );
        push_object_number_field(&mut out, &mut first, "Count", *count);
        out.push('}');
    }
    out.push(']');
    out
}

fn compat_call_family(raw_call: &str, normalized: &str) -> &'static str {
    if is_cxx_symbol(raw_call) || is_cxx_symbol(normalized) {
        return "cxx";
    }
    if normalized.starts_with("cf")
        || normalized.starts_with("ns")
        || normalized.starts_with("sec")
        || normalized.starts_with("objc")
        || normalized.starts_with("xpc")
        || normalized.starts_with("dispatch")
        || raw_call.starts_with("_IO")
        || raw_call.starts_with("IO")
    {
        return "apple-framework";
    }
    if matches!(
        normalized,
        "socket"
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
            | "setsockopt"
            | "getsockopt"
            | "getpeername"
            | "getsockname"
            | "socketpair"
            | "getaddrinfo"
            | "freeaddrinfo"
            | "getnameinfo"
    ) {
        return "network";
    }
    if matches!(
        normalized,
        "open"
            | "openat"
            | "read"
            | "write"
            | "close"
            | "fcntl"
            | "ioctl"
            | "fsync"
            | "poll"
            | "select"
            | "readv"
            | "writev"
            | "pread"
            | "pwrite"
            | "lseek"
            | "dup"
            | "dup2"
            | "pipe"
            | "pipe_pair"
            | "access"
            | "faccessat"
            | "chmod"
            | "fchmod"
            | "fchmodat"
            | "chdir"
            | "fchdir"
            | "getcwd"
            | "stat"
            | "lstat"
            | "fstat"
            | "fstatat"
            | "statfs"
            | "fstatfs"
            | "truncate"
            | "ftruncate"
            | "mkdir"
            | "mkdirat"
            | "rmdir"
            | "unlink"
            | "unlinkat"
            | "rename"
            | "renameat"
            | "readlink"
            | "readlinkat"
            | "symlink"
            | "realpath"
            | "getattrlist"
            | "fgetattrlist"
            | "opendir"
            | "closedir"
            | "fdopendir"
            | "readdir"
            | "readdir_r"
            | "scandir"
            | "alphasort"
            | "glob"
            | "globfree"
    ) {
        return "filesystem";
    }
    if matches!(
        normalized,
        "malloc"
            | "calloc"
            | "cmalloc"
            | "realloc"
            | "free"
            | "posix_memalign"
            | "mmap"
            | "munmap"
            | "mprotect"
            | "madvise"
            | "mlock"
            | "munlock"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "memmem"
            | "bzero"
            | "strlen"
            | "strcmp"
            | "strncmp"
            | "strcasecmp"
            | "strncasecmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strlcpy"
            | "strlcat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strcasestr"
            | "strdup"
            | "atoi"
            | "atol"
            | "atoll"
            | "strtol"
            | "strtoll"
            | "strtoul"
            | "strtoull"
    ) {
        return "memory-string";
    }
    if normalized.starts_with("pthread") || normalized.starts_with("os_unfair_lock") {
        return "threading";
    }
    if matches!(
        normalized,
        "fork"
            | "exec"
            | "execve"
            | "execl"
            | "posix_spawn"
            | "posix_spawnp"
            | "system"
            | "popen"
            | "pclose"
            | "wait4"
            | "waitpid"
            | "kill"
            | "exit"
            | "atexit"
            | "cxa_atexit"
            | "tlv_atexit"
    ) {
        return "process";
    }
    if matches!(
        normalized,
        "dlopen"
            | "dlsym"
            | "dlclose"
            | "dlerror"
            | "dladdr"
            | "dyld_get_image_header"
            | "dyld_get_image_name"
            | "dyld_get_image_vmaddr_slide"
            | "dyld_image_count"
    ) {
        return "dynamic-linking";
    }
    if matches!(
        normalized,
        "getpid"
            | "getppid"
            | "getuid"
            | "geteuid"
            | "getgid"
            | "getegid"
            | "getlogin"
            | "getlogin_r"
            | "getpwuid"
            | "getpwnam"
            | "getgroups"
            | "issetugid"
            | "sysconf"
            | "getpagesize"
            | "gethostname"
            | "uname"
            | "getrlimit"
            | "setrlimit"
            | "sysctl"
            | "sysctlbyname"
            | "umask"
            | "getenv"
            | "setenv"
            | "unsetenv"
            | "getentropy"
    ) {
        return "identity";
    }
    if matches!(
        normalized,
        "gettimeofday"
            | "clock_gettime"
            | "nanosleep"
            | "sleep"
            | "usleep"
            | "mach_absolute_time"
            | "mach_timebase_info"
    ) {
        return "time";
    }
    "misc"
}

fn is_cxx_symbol(symbol: &str) -> bool {
    let symbol = symbol.trim_start_matches('_');
    symbol.starts_with("Z")
        || symbol.starts_with("ZN")
        || symbol.starts_with("ZK")
        || symbol.starts_with("cxa_")
        || symbol.starts_with("_Z")
        || symbol.contains("basic_string")
        || symbol.contains("St3__1")
}

fn push_json_field(out: &mut String, key: &str, value: &str) {
    out.push(',');
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":\"");
    out.push_str(&json_escape(value));
    out.push('"');
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    out.push(',');
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":");
    out.push_str(&value.to_string());
}

fn push_json_raw(out: &mut String, key: &str, value: &str) {
    out.push(',');
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":");
    out.push_str(value);
}

fn push_object_separator(out: &mut String, first: &mut bool) {
    if *first {
        *first = false;
    } else {
        out.push(',');
    }
}

fn push_object_string_field(out: &mut String, first: &mut bool, key: &str, value: &str) {
    push_object_separator(out, first);
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":\"");
    out.push_str(&json_escape(value));
    out.push('"');
}

fn push_object_number_field(out: &mut String, first: &mut bool, key: &str, value: u64) {
    push_object_separator(out, first);
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":");
    out.push_str(&value.to_string());
}

#[cfg(test)]
mod tests {
    #[test]
    fn capability_report_tracks_calls_and_missing_symbols() {
        super::reset_compat_capability_report();
        super::record_compat_call_result("direct", "connect", true, false);
        super::record_compat_call_result("direct", "connect", true, true);
        super::record_compat_call_result("import", "_future_symbol", false, true);
        super::record_unhandled_import("__ZNSt3__112basic_stringIcE6appendEPKcm");
        super::record_unresolved_dlsym("_SecItemCopyMatching");

        let report = super::compat_capability_report_json();

        assert!(report.contains(r#""Kind":"capability-report""#));
        assert!(report.contains(r#""TotalCalls":3"#));
        assert!(report.contains(r#""ProxiedCalls":2"#));
        assert!(report.contains(r#""FailedProxies":1"#));
        assert!(report.contains(r#""UnhandledCalls":1"#));
        assert!(report.contains(r#""UnhandledImports":1"#));
        assert!(report.contains(r#""UnresolvedDlsym":1"#));
        assert!(report.contains(r#""Call":"connect""#));
        assert!(report.contains(r#""Family":"network""#));
        assert!(report.contains(r#""Family":"cxx""#));
        assert!(report.contains(r#""Symbol":"_SecItemCopyMatching""#));

        super::reset_compat_capability_report();
    }
}
