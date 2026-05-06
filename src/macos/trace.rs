//! Structured trace events for macOS emulation.
//!
//! JSONL output follows the DRAKVUF shape: each emitted line is a single JSON
//! object with a `plugin` field and stable process metadata. Plugins decide
//! which intercepted events are written to the log.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TraceCategory {
    Loader,
    Import,
    Syscall,
    Process,
    Thread,
    Memory,
    Io,
    Capture,
    Detect,
    Kqueue,
}

impl TraceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Import => "import",
            Self::Syscall => "syscall",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Memory => "memory",
            Self::Io => "io",
            Self::Capture => "capture",
            Self::Detect => "detect",
            Self::Kqueue => "kqueue",
        }
    }
}

impl fmt::Display for TraceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    Human,
    Jsonl,
}

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub format: TraceFormat,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            format: TraceFormat::Human,
        }
    }
}

impl TraceConfig {
    pub fn human() -> Self {
        Self::default()
    }

    pub fn jsonl() -> Self {
        Self {
            format: TraceFormat::Jsonl,
        }
    }

    pub fn only_jsonl() -> Self {
        Self::jsonl()
    }

    pub fn only_human() -> Self {
        Self::human()
    }

    pub fn enable_category(self, _category: TraceCategory) -> Self {
        self
    }

    pub fn enable_call(self, _call: impl Into<String>) -> Self {
        self
    }

    pub fn is_enabled(&self, event: &TraceEvent) -> bool {
        event.plugin.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub plugin: Option<String>,
    pub timestamp_us: u64,
    pub category: TraceCategory,
    pub name: String,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub tid: Option<u64>,
    pub running_process: Option<String>,
    pub call: Option<String>,
    pub args: BTreeMap<String, String>,
    pub result: Option<String>,
    pub message: Option<String>,
}

impl TraceEvent {
    pub fn new(category: TraceCategory, name: impl Into<String>) -> Self {
        Self {
            plugin: None,
            timestamp_us: unix_timestamp_us(),
            category,
            name: name.into(),
            pid: None,
            ppid: None,
            tid: None,
            running_process: None,
            call: None,
            args: BTreeMap::new(),
            result: None,
            message: None,
        }
    }

    pub fn plugin(mut self, plugin: impl Into<String>) -> Self {
        self.plugin = Some(plugin.into());
        self
    }
    pub fn pid(mut self, pid: u64) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn ppid(mut self, ppid: u64) -> Self {
        self.ppid = Some(ppid);
        self
    }

    pub fn tid(mut self, tid: u64) -> Self {
        self.tid = Some(tid);
        self
    }

    pub fn running_process(mut self, process: impl Into<String>) -> Self {
        self.running_process = Some(process.into());
        self
    }

    pub fn call(mut self, call: impl Into<String>) -> Self {
        self.call = Some(call.into());
        self
    }

    pub fn arg(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(name.into(), value.into());
        self
    }

    pub fn result(mut self, result: impl Into<String>) -> Self {
        self.result = Some(result.into());
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn render(&self, format: TraceFormat) -> String {
        match format {
            TraceFormat::Human => self.render_human(),
            TraceFormat::Jsonl => self.render_jsonl(),
        }
    }

    pub fn render_human(&self) -> String {
        let plugin = self.plugin.as_deref().unwrap_or(self.category.as_str());
        let mut line = format!("[{}] {}", plugin.to_ascii_uppercase(), self.name);

        if let Some(pid) = self.pid {
            line.push_str(&format!(" pid={}", pid));
        }
        if let Some(ppid) = self.ppid {
            line.push_str(&format!(" ppid={}", ppid));
        }
        if let Some(tid) = self.tid {
            line.push_str(&format!(" tid={}", tid));
        }
        if let Some(process) = &self.running_process {
            line.push_str(&format!(" process={}", process));
        }
        if let Some(call) = &self.call {
            line.push_str(&format!(" call={}", call));
        }
        for (name, value) in &self.args {
            line.push_str(&format!(" {}={}", name, value));
        }
        if let Some(result) = &self.result {
            line.push_str(&format!(" -> {}", result));
        }
        if let Some(message) = &self.message {
            line.push_str(&format!(" {}", message));
        }

        line
    }

    pub fn render_jsonl(&self) -> String {
        let mut out = String::new();
        out.push('{');

        let plugin = self.plugin.as_deref().unwrap_or(self.category.as_str());
        push_json_string(&mut out, "plugin", plugin, true);
        push_json_string(
            &mut out,
            "TimeStamp",
            &format_timestamp(self.timestamp_us),
            false,
        );
        if let Some(pid) = self.pid {
            push_json_number(&mut out, "PID", pid, false);
        }
        if let Some(ppid) = self.ppid {
            push_json_number(&mut out, "PPID", ppid, false);
        }
        if let Some(tid) = self.tid {
            push_json_number(&mut out, "TID", tid, false);
        }
        if let Some(process) = &self.running_process {
            push_json_string(&mut out, "RunningProcess", process, false);
        }

        push_json_string(&mut out, "Event", &self.name, false);
        push_json_string(&mut out, "Category", self.category.as_str(), false);

        if let Some(call) = &self.call {
            push_json_string(&mut out, "Call", call, false);
        }
        for (name, value) in &self.args {
            push_json_string(&mut out, name, value, false);
        }
        if let Some(result) = &self.result {
            push_json_string(&mut out, "Result", result, false);
        }
        if let Some(message) = &self.message {
            push_json_string(&mut out, "Message", message, false);
        }

        out.push('}');
        out
    }
}

pub trait TraceSink {
    fn emit_line(&mut self, line: &str);
}

#[derive(Debug, Default)]
pub struct StdoutTraceSink;

impl TraceSink for StdoutTraceSink {
    fn emit_line(&mut self, line: &str) {
        println!("{}", line);
    }
}

#[derive(Debug)]
pub struct WriterTraceSink<W: Write> {
    writer: W,
}

impl<W: Write> WriterTraceSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> TraceSink for WriterTraceSink<W> {
    fn emit_line(&mut self, line: &str) {
        let _ = writeln!(self.writer, "{}", line);
    }
}

pub type StdoutTracer = Tracer<StdoutTraceSink>;

#[derive(Debug)]
pub struct Tracer<S: TraceSink = StdoutTraceSink> {
    config: TraceConfig,
    sink: S,
}

impl StdoutTracer {
    pub fn stdout(config: TraceConfig) -> Self {
        Self::new(config, StdoutTraceSink)
    }
}

impl<S: TraceSink> Tracer<S> {
    pub fn new(config: TraceConfig, sink: S) -> Self {
        Self { config, sink }
    }

    pub fn config(&self) -> &TraceConfig {
        &self.config
    }

    pub fn emit(&mut self, event: TraceEvent) {
        if self.config.is_enabled(&event) {
            self.sink.emit_line(&event.render(self.config.format));
        }
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}

pub trait TracePlugin {
    fn name(&self) -> &'static str;
    fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent>;
}

#[derive(Debug, Clone)]
pub struct CallTracePlugin {
    name: &'static str,
    categories: HashSet<TraceCategory>,
    calls: HashSet<String>,
}

impl CallTracePlugin {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            categories: HashSet::new(),
            calls: HashSet::new(),
        }
    }

    pub fn category(mut self, category: TraceCategory) -> Self {
        self.categories.insert(category);
        self
    }

    pub fn call(mut self, call: impl Into<String>) -> Self {
        self.calls.insert(call.into());
        self
    }

    fn matches(&self, event: &TraceEvent) -> bool {
        self.categories.contains(&event.category)
            || event
                .call
                .as_ref()
                .is_some_and(|call| self.calls.contains(call))
            || self.calls.contains(&event.name)
    }
}

impl TracePlugin for CallTracePlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent> {
        if self.matches(event) {
            Some(event.clone().plugin(self.name))
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn TracePlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P: TracePlugin + 'static>(&mut self, plugin: P) {
        self.plugins.push(Box::new(plugin));
    }

    pub fn dispatch(&mut self, event: &TraceEvent) -> Vec<TraceEvent> {
        let mut produced = Vec::new();
        for plugin in &mut self.plugins {
            if let Some(event) = plugin.on_event(event) {
                produced.push(event);
            }
        }
        produced
    }

    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|plugin| plugin.name()).collect()
    }
}

pub fn json_escape(input: &str) -> String {
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

fn unix_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn format_timestamp(timestamp_us: u64) -> String {
    format!(
        "{}.{:06}",
        timestamp_us / 1_000_000,
        timestamp_us % 1_000_000
    )
}

fn push_json_string(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":\"");
    out.push_str(&json_escape(value));
    out.push('"');
}

fn push_json_number(out: &mut String, key: &str, value: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":");
    out.push_str(&value.to_string());
}

pub fn memory_writer() -> (
    Tracer<WriterTraceSink<Vec<u8>>>,
    impl FnOnce(Tracer<WriterTraceSink<Vec<u8>>>) -> io::Result<String>,
) {
    let tracer = Tracer::new(TraceConfig::jsonl(), WriterTraceSink::new(Vec::new()));
    let finish = |tracer: Tracer<WriterTraceSink<Vec<u8>>>| {
        String::from_utf8(tracer.into_sink().into_inner())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    };
    (tracer, finish)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n\t"), "a\\\"b\\\\c\\n\\t");
    }

    #[test]
    fn jsonl_event_uses_drakvuf_style_fields() {
        let event = TraceEvent::new(TraceCategory::Process, "execve")
            .plugin("procmon")
            .pid(2)
            .ppid(1)
            .tid(6)
            .running_process("sample")
            .call("execve")
            .arg("Path", "/bin/sh")
            .arg("Argv", "[\"/bin/sh\"]")
            .result("0")
            .message("synthetic process consumed");

        let json = event.render_jsonl();

        assert!(json.contains("\"plugin\":\"procmon\""));
        assert!(json.contains("\"TimeStamp\":\""));
        assert!(json.contains("\"PID\":2"));
        assert!(json.contains("\"PPID\":1"));
        assert!(json.contains("\"RunningProcess\":\"sample\""));
        assert!(json.contains("\"Call\":\"execve\""));
        assert!(json.contains("\"Path\":\"/bin/sh\""));
    }

    #[test]
    fn tracer_does_not_emit_unclaimed_events() {
        let (mut tracer, finish) = memory_writer();
        tracer.emit(TraceEvent::new(TraceCategory::Import, "write").call("write"));

        assert_eq!(finish(tracer).unwrap(), "");
    }

    #[test]
    fn call_plugin_claims_enabled_calls() {
        let mut plugin = CallTracePlugin::new("syscalls").call("write");
        let write = TraceEvent::new(TraceCategory::Syscall, "syscall").call("write");
        let open = TraceEvent::new(TraceCategory::Syscall, "syscall").call("open");

        assert_eq!(
            plugin.on_event(&write).unwrap().plugin.as_deref(),
            Some("syscalls")
        );
        assert!(plugin.on_event(&open).is_none());
    }

    struct ExecPlugin;

    impl TracePlugin for ExecPlugin {
        fn name(&self) -> &'static str {
            "procmon"
        }

        fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent> {
            if event.call.as_deref() == Some("execve") {
                Some(event.clone().plugin(self.name()))
            } else {
                None
            }
        }
    }

    #[test]
    fn plugin_registry_only_emits_plugin_selected_events() {
        let mut plugins = PluginRegistry::new();
        plugins.register(ExecPlugin);

        let produced =
            plugins.dispatch(&TraceEvent::new(TraceCategory::Process, "exec").call("execve"));

        assert_eq!(plugins.plugin_names(), vec!["procmon"]);
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].plugin.as_deref(), Some("procmon"));
    }
}
