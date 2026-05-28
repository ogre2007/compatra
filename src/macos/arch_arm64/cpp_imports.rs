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

/// `basic_string::compare(pos, n, s)` — the three-argument form
/// the Lazarus profiler uses to check argv[1] against fixed
/// substrings ("http://", "https://", etc.). The default return-
/// zero stub means every comparison reports "equal", which makes
/// the obfuscated dispatch run the wrong branch and short-circuit
/// the profile pipeline. Implement the actual byte comparison.
const STRING_COMPARE_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc";
/// Four-argument variant: `compare(pos, n1, s, n2)`.
const STRING_COMPARE_N_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm";

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

    // _kill(pid, sig): the Mach-O Man profiler calls this with
    // pid=parent / sibling process ID and sig=0 as an existence
    // check (kill(pid, 0) returns 0 if the process exists, -1
    // with errno=ESRCH otherwise). Default return-zero stub
    // satisfies the existence check, but log the args so we can
    // see which pid the binary is probing.
    if let Some(&addr) = stub_map.get("_kill") {
        let tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let pid = emu.read_reg("x0").unwrap_or(0);
                let sig = emu.read_reg("x1").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, "_kill", addr);
                if let Some(bus) = &trace_bus_for_hook {
                    let _ = bus.send(
                        process_event(
                            &runtime_process_metadata(proc_name.clone()),
                            "kill",
                            "kill",
                        )
                        .arg("Pid", pid.to_string())
                        .arg("Sig", sig.to_string())
                        .arg("Result", "0"),
                    );
                }
            },
        )?;
    }

    // basic_string::compare(pos, n, const char* s):
    //   x0 = this (the std::string)
    //   x1 = pos (start offset)
    //   x2 = n (count of bytes to compare)
    //   x3 = s (other C-string)
    //
    // libc++ std::string short-form layout (no-SSO short string):
    //   offset 0: bytes (the chars)
    //   offset 0x17: length (1 byte, last byte of inline buffer)
    // libc++ long-form (SSO long string):
    //   offset 0: capacity (with flag bit)
    //   offset 8: size
    //   offset 16: data pointer
    // We don't know which layout the binary uses without analysis,
    // so use a heuristic: try the short-string layout first and
    // fall back to reading the data-pointer slot if the first
    // byte doesn't look like ASCII.
    install_compare_hook(emulator, stub_map, STRING_COMPARE_SYMBOL, trace_bus, import_tracker, process_name, false)?;
    install_compare_hook(emulator, stub_map, STRING_COMPARE_N_SYMBOL, trace_bus, import_tracker, process_name, true)?;

    Ok(())
}

fn install_compare_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
    has_n2: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let pos = emu.read_reg("x1").unwrap_or(0);
            let n = emu.read_reg("x2").unwrap_or(0);
            let s_ptr = emu.read_reg("x3").unwrap_or(0);
            let n2 = if has_n2 { emu.read_reg("x4").unwrap_or(0) } else { 0 };

            // Read up to 256 bytes from x3 as the comparison string.
            let cap = (if has_n2 { n2 } else { n }).min(256) as usize;
            let s_bytes = if s_ptr != 0 && cap > 0 {
                emu.read_memory(s_ptr, cap).unwrap_or_default()
            } else {
                Vec::new()
            };

            // Decode the libc++ std::string at `this`. The libc++
            // flag bit location varies across versions and this
            // sample's string layout is non-standard (the libc++
            // long-form size slot holds a code address, not a
            // length), so we probe multiple possible layouts and
            // accept the first one whose data points at a plausible
            // ASCII region.
            let header = emu.read_memory(this, 32).unwrap_or_else(|_| vec![0u8; 32]);
            let try_layout = |data_ptr: u64, _hinted_size: u64| -> Option<(Vec<u8>, u64)> {
                if !(0x100000000..0x200000000).contains(&data_ptr) {
                    return None;
                }
                // Don't trust the hinted size — the binary's
                // custom std::string layout puts a code address in
                // the size slot. Just read `pos + n + 1` bytes
                // from the data pointer (enough to satisfy any
                // compare call), and let the caller slice with
                // `pos`/`n`.
                let read_n = (pos + n + 1).min(0x2000) as usize;
                let buf = emu.read_memory(data_ptr, read_n).ok()?;
                if !buf.first().map(|&b| b != 0).unwrap_or(false) {
                    return None;
                }
                // Synthesize a "length" from the null terminator
                // (or the read size if no null is found) — only
                // used for the trace event.
                let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                Some((buf[..nul_pos].to_vec(), nul_pos as u64))
            };

            let lhs_long_data = u64::from_le_bytes(header[16..24].try_into().unwrap_or([0; 8]));
            let lhs_long_size = u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8]));
            let lhs_alt_data = u64::from_le_bytes(header[0..8].try_into().unwrap_or([0; 8]));
            let lhs_alt_size = u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8]));

            // For samples whose first slot is the data pointer (older libc++
            // layout, or a custom string class that stores `{data,size,cap}`)
            // we fall back to reading at offset 0.
            let (full_lhs, lhs_total_len, is_long) = if let Some((b, sz)) =
                try_layout(lhs_long_data, lhs_long_size)
            {
                (b, sz, true)
            } else if let Some((b, sz)) = try_layout(lhs_alt_data, lhs_alt_size) {
                (b, sz, true)
            } else {
                // Last-resort short-string fallback.
                let short_len = (header.first().copied().unwrap_or(0) >> 1) as u64;
                let read_n = short_len.min(22) as usize;
                let buf = header
                    .get(1..1 + read_n)
                    .map(|s| s.to_vec())
                    .unwrap_or_default();
                (buf, short_len, false)
            };

            // Apply `pos` once we have the full string in hand so
            // we don't double-clip.
            let lhs_bytes: Vec<u8> = full_lhs
                .iter()
                .skip(pos as usize)
                .take(n as usize)
                .copied()
                .collect();

            let lhs_slice: &[u8] = &lhs_bytes;
            let rhs_slice = if has_n2 {
                s_bytes.get(..n2 as usize).unwrap_or(&s_bytes)
            } else {
                s_bytes.as_slice()
            };

            let result: i64 = match lhs_slice.cmp(rhs_slice) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };

            let lhs_preview: String = lhs_slice
                .iter()
                .take(64)
                .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
                .collect();
            let raw_header: String = header
                .iter()
                .take(24)
                .map(|b| format!("{:02x}", b))
                .collect();
            let rhs_preview: String = rhs_slice
                .iter()
                .take(64)
                .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
                .collect();

            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result as u64);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            if let Some(bus) = &trace_bus_for_hook {
                let _ = bus.send(
                    process_event(
                        &runtime_process_metadata(proc_name.clone()),
                        "string-compare",
                        "string_compare",
                    )
                    .arg("This", format!("0x{:X}", this))
                    .arg("Pos", pos.to_string())
                    .arg("N", n.to_string())
                    .arg("N2", n2.to_string())
                    .arg("SPtr", format!("0x{:X}", s_ptr))
                    .arg("Lhs", lhs_preview)
                    .arg("Rhs", rhs_preview)
                    .arg("Result", result.to_string())
                    .arg("RawHeader", raw_header)
                    .arg("IsLong", is_long.to_string())
                    .arg("LhsTotalLen", lhs_total_len.to_string()),
                );
            }
        },
    )?;
    Ok(())
}

