//! Lightweight plugin-oriented tracing bridge for standalone runners.
//!
//! Legacy runner entrypoints still print directly today. This module lets them
//! begin emitting architecture-independent `TraceEvent`s without being fully
//! rewritten around `MacosEmulator`.

use crate::macos::plugin_events::TraceMetadata;
use crate::macos::trace::{StdoutTraceSink, TraceConfig, TraceEvent};
use crate::macos::{EmulationOptions, MacosEmulator, RuntimeMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct SharedTraceBus {
    tx: mpsc::Sender<TraceEvent>,
    pending: Arc<AtomicUsize>,
}

impl SharedTraceBus {
    pub fn send(&self, event: TraceEvent) -> Result<(), mpsc::SendError<TraceEvent>> {
        self.pending.fetch_add(1, Ordering::Relaxed);
        match self.tx.send(event) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.pending.fetch_sub(1, Ordering::Release);
                Err(err)
            }
        }
    }

    fn mark_delivered(&self) {
        self.pending.fetch_sub(1, Ordering::Release);
    }

    fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
}

pub fn shared_trace_bus_from_env() -> Option<SharedTraceBus> {
    let mode = RuntimeMode::from_env().unwrap_or_default();
    shared_trace_bus_for_mode_from_env(mode)
}

pub fn shared_trace_bus_for_mode_from_env(mode: RuntimeMode) -> Option<SharedTraceBus> {
    let enabled = std::env::var("COMPATRA_PLUGIN_TRACE")
        .ok()
        .map(|value| {
            let value = value.trim();
            if value.eq_ignore_ascii_case("0")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no")
                || value.eq_ignore_ascii_case("off")
            {
                return false;
            }
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
        .unwrap_or(true);
    if !enabled {
        return None;
    }

    let mut options = EmulationOptions::default();
    options.mode = mode;
    let format = std::env::var("COMPATRA_TRACE_FORMAT")
        .unwrap_or_else(|_| "jsonl".to_string())
        .to_ascii_lowercase();
    let profile = std::env::var("COMPATRA_TRACE_PROFILE")
        .unwrap_or_else(|_| "compact".to_string())
        .to_ascii_lowercase();
    options.trace = match (format.as_str(), profile.as_str()) {
        ("human", "debug") => {
            let mut config = TraceConfig::human();
            config.profile = crate::macos::TraceProfile::Debug;
            config
        }
        ("human", _) => {
            let mut config = TraceConfig::human();
            config.profile = crate::macos::TraceProfile::Full;
            config
        }
        (_, "full") => TraceConfig::full_jsonl(),
        (_, "debug") => TraceConfig::debug_jsonl(),
        _ => TraceConfig::compact_jsonl(),
    };

    let (tx, rx) = mpsc::channel::<TraceEvent>();
    let bus = SharedTraceBus {
        tx,
        pending: Arc::new(AtomicUsize::new(0)),
    };
    let worker_bus = bus.clone();
    std::thread::spawn(move || {
        let mut emulator = MacosEmulator::<StdoutTraceSink>::stdout(options);
        while let Ok(event) = rx.recv() {
            emulator.emit_trace(event);
            worker_bus.mark_delivered();
        }
    });

    Some(bus)
}

pub fn flush_shared_trace_bus(bus: &Option<SharedTraceBus>) {
    let Some(bus) = bus else {
        return;
    };
    let deadline = Instant::now() + Duration::from_millis(250);
    while bus.pending_count() != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn emit_event(bus: &Option<SharedTraceBus>, metadata: &TraceMetadata, event: TraceEvent) {
    if let Some(bus) = bus {
        let _ = bus.send(metadata.apply_to(event));
    }
}

pub use emit_event as emit_runner_trace_event;
