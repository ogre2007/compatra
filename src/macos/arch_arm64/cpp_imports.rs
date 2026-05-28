//! C++ libc++ import hooks for arm64.
//!
//! Obfuscated C++ samples (e.g., Lazarus "Mach-O Man" profiler at
//! fixtures/macos/bin/machoman/) bind every libc++ symbol through
//! LC_DYLD_CHAINED_FIXUPS to a return-zero function stub. The
//! default stubs are enough for syscall-flavored libc symbols
//! (`_open`, `_strlen`, etc.) but break the C++ stream pipeline:
//!
//! - `std::__1::basic_ostream<char>::sentry::sentry(ostream&)` is
//!   the RAII guard that operator<< constructs on entry. Its
//!   `__ok_` byte (offset 0 of the sentry) decides whether the
//!   write actually fires; a no-op stub leaves whatever the stack
//!   had there, which is zero, so operator<< takes the
//!   write-skipped path and never emits the usage message.
//!
//! - `std::__1::basic_ostream<char>::write(const char*, streamsize)`
//!   is the actual byte sink. With a return-zero stub the message
//!   is silently dropped on the floor even when the sentry path
//!   does try to write.
//!
//! Install code hooks at the stub addresses for these two imports
//! so that:
//!
//!  1. sentry::sentry sets `this->__ok_ = 1`, marking the sentry
//!     good so the operator<< body runs.
//!
//!  2. basic_ostream::write reads x1 (char*) / x2 (length) out of
//!     the guest, copies the bytes into a host buffer, prints them
//!     via the procmon plugin, and returns `this` so chained
//!     operator<< calls keep working.
//!
//! Both hooks also record themselves in the import tracker the
//! same way `install_arm64_return_stubs`-installed stubs would,
//! so the existing import-count / recent-imports telemetry stays
//! consistent.

use std::collections::HashMap;

use crate::macos::arm64_runner_support::Arm64ImportTracker;
use crate::macos::{process_event, runtime_process_metadata, SharedTraceBus};
use crate::{Emulator, UnicornEmulator};

const SENTRY_C1_SYMBOL: &str =
    "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
const ISTREAM_SENTRY_C1_SYMBOL: &str =
    "__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b";
const OSTREAM_WRITE_SYMBOL: &str =
    "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5writeEPKcl";

fn record_import(
    tracker: &Arm64ImportTracker,
    name: &str,
    address: u64,
) {
    tracker
        .import_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut last) = tracker.last_stub.lock() {
        *last = Some(name.to_string());
    }
    if let Ok(mut recent) = tracker.recent_imports.lock() {
        if recent.len() >= 64 {
            recent.pop_front();
        }
        recent.push_back(format!("{} @ 0x{:X}", name, address));
    }
}

/// Install custom hooks for C++ ostream stubs.
///
/// `stub_map` is the symbol-name → stub-address map produced by
/// `install_arm64_return_stubs`. Symbols that aren't present in
/// the binary's undefined-symbol set won't have a stub address
/// here; we silently skip those hooks.
pub fn install_arm64_cpp_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // ostream::sentry::sentry(stream): set this->__ok_ = 1 and
    // return. Without this every operator<< takes the
    // "stream-not-good" path and skips its actual write.
    if let Some(&addr) = stub_map.get(SENTRY_C1_SYMBOL) {
        let tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let this = emu.read_reg("x0").unwrap_or(0);
                let stream = emu.read_reg("x1").unwrap_or(0);
                if this != 0 {
                    let _ = emu.write_memory(this, &[1u8]);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, SENTRY_C1_SYMBOL, addr);
                if let Some(bus) = &trace_bus_for_hook {
                    let _ = bus.send(
                        process_event(
                            &runtime_process_metadata(proc_name.clone()),
                            "ostream-sentry",
                            "ostream_sentry_C1",
                        )
                        .arg("This", format!("0x{:X}", this))
                        .arg("Stream", format!("0x{:X}", stream)),
                    );
                }
            },
        )?;
    }

    // istream::sentry::sentry(stream, bool noskipws): same idea —
    // mark the sentry good so the istream read path runs.
    if let Some(&addr) = stub_map.get(ISTREAM_SENTRY_C1_SYMBOL) {
        let tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let this = emu.read_reg("x0").unwrap_or(0);
                if this != 0 {
                    let _ = emu.write_memory(this, &[1u8]);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, ISTREAM_SENTRY_C1_SYMBOL, addr);
            },
        )?;
    }

    // ostream::write(const char* s, streamsize n): copy the bytes
    // out of guest memory and emit them as an `ostream-write`
    // event so the captured trace records the actual message.
    // Return `this` (x0) so chained operator<< calls keep
    // returning the stream.
    if let Some(&addr) = stub_map.get(OSTREAM_WRITE_SYMBOL) {
        let tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let this = emu.read_reg("x0").unwrap_or(0);
                let buf_ptr = emu.read_reg("x1").unwrap_or(0);
                let n = emu.read_reg("x2").unwrap_or(0);
                let capped_len = n.min(0x1000) as usize;
                let bytes = if buf_ptr != 0 && capped_len > 0 {
                    emu.read_memory(buf_ptr, capped_len).unwrap_or_default()
                } else {
                    Vec::new()
                };
                // Replace control characters so the JSONL line stays
                // single-row; raw bytes also dumped as hex for
                // unambiguous decoding downstream.
                let text: String = bytes
                    .iter()
                    .map(|&b| match b {
                        0x20..=0x7e => b as char,
                        b'\n' => '\u{240A}',
                        b'\r' => '\u{240D}',
                        b'\t' => '\u{2409}',
                        _ => '.',
                    })
                    .collect();
                let hex: String = bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                let lr = emu.read_reg("lr").unwrap_or(0);
                // Return `this` for chained operator<<.
                let _ = emu.write_reg("x0", this);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, OSTREAM_WRITE_SYMBOL, addr);
                if let Some(bus) = &trace_bus_for_hook {
                    let _ = bus.send(
                        process_event(
                            &runtime_process_metadata(proc_name.clone()),
                            "ostream-write",
                            "ostream_write",
                        )
                        .arg("Stream", format!("0x{:X}", this))
                        .arg("BufPtr", format!("0x{:X}", buf_ptr))
                        .arg("Len", format!("0x{:X}", n))
                        .arg("Text", text)
                        .arg("Hex", hex),
                    );
                }
            },
        )?;
    }

    Ok(())
}

