//! arm64 C++/libc++ hooks used by analysis mode.
//!
//! These hooks cover small, well-defined libc++ functions that commonly appear
//! as imported symbols in no-dyld Mach-O runs. They intentionally model function
//! semantics and libc++'s documented string object layouts rather than
//! sample-specific object offsets.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::macos::arm64_runner_support::Arm64ImportTracker;
use crate::macos::{
    memory_event, process_event, runtime_process_metadata, SharedTraceBus, TraceMetadata,
};
use crate::{Emulator, UnicornEmulator};

/// Size of the fake C++ data region carved out of the mmap arena.
/// Large enough to host a generic ostream object, a small vtable
/// table, and a few extra fake-data symbols (ctype::id, etc.)
/// without bumping into surrounding allocations.
const ARM64_CPP_DATA_REGION_SIZE: u64 = 0x2000;

/// Offsets inside the C++ data region for each kind of fake symbol.
/// The region only supplies imported data symbols with stable data-shaped
/// addresses; libc++ behavior belongs in the hooks below.
const ARM64_CPP_VTABLE_STORAGE_OFFSET: u64 = 0x100;
const ARM64_CPP_VTT_OFFSET: u64 = 0x300;
const ARM64_CPP_CERR_OBJECT_OFFSET: u64 = 0x400;
const ARM64_CPP_CIN_OBJECT_OFFSET: u64 = 0x500;
const ARM64_CPP_CTYPE_ID_OFFSET: u64 = 0x600;

const SENTRY_C1_SYMBOL: &str = "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
const ISTREAM_SENTRY_C1_SYMBOL: &str =
    "__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b";
const OSTREAM_WRITE_SYMBOL: &str = "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5writeEPKcl";

const STRING_INIT_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm";
const STRING_COPY_C1_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_";
const STRING_COPY_C2_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_";
const STRING_D1_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev";
const STRING_D2_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev";
const STRING_ASSIGN_CSTR_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc";
const STRING_ASSIGN_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKcm";
const STRING_APPEND_CSTR_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc";
const STRING_APPEND_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm";
const STRING_APPEND_STRING_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendERKS5_";
const STRING_ERASE_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm";
const STRING_PUSH_BACK_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc";
const STRING_FIND_CHAR_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm";
const STRING_RFIND_CHAR_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm";
const TO_STRING_U32_SYMBOL: &str = "__ZNSt3__19to_stringEj";
const STRING_PLUS_CSTR_STRING_SYMBOL: &str =
    "__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_";
const STRING_PLUS_STRING_CSTR_SYMBOL: &str =
    "__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EERKS9_PKS6_";
const STRING_COMPARE_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc";
const STRING_COMPARE_N_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm";

const LIBCPP_STRING_OBJECT_SIZE: usize = 24;
const LIBCPP_SHORT_MAX: usize = 22;
const MAX_SYNTHETIC_STRING_LEN: usize = 0x10_000;
const ALT_LONG_FLAG: u64 = 1u64 << 63;
const NPOS: usize = usize::MAX;

/// Allocate and initialize a fake C++ data-symbol region.
///
/// Returns a map of known C++ data-symbol names -> resolved
/// addresses. Pass it to `process_chained_fixups_with_binary` as
/// `data_symbols` so the chain walker patches data binds (like
/// `__ZNSt3__14cerrE`) into this region instead of a function
/// stub.
pub fn setup_analysis_arm64_cpp_data_region(
    emulator: &mut UnicornEmulator,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    metadata: &TraceMetadata,
) -> Result<HashMap<String, u64>, Box<dyn std::error::Error>> {
    let region_size = ARM64_CPP_DATA_REGION_SIZE;
    let base = mmap_next.fetch_add(region_size, Ordering::Relaxed);
    if base.saturating_add(region_size) > mmap_end {
        return Err("mmap arena exhausted while allocating C++ data region".into());
    }

    let zeros = vec![0u8; region_size as usize];
    emulator.write_memory(base, &zeros)?;

    let vtable_storage_addr = base + ARM64_CPP_VTABLE_STORAGE_OFFSET;
    let vtable_addr = vtable_storage_addr + 16;
    emulator.write_memory(vtable_storage_addr, &0u64.to_le_bytes())?;
    emulator.write_memory(vtable_storage_addr + 8, &0u64.to_le_bytes())?;
    for i in 0..32 {
        emulator.write_memory(vtable_addr + i * 8, &done_addr.to_le_bytes())?;
    }

    let cerr_addr = base + ARM64_CPP_CERR_OBJECT_OFFSET;
    emulator.write_memory(cerr_addr, &vtable_addr.to_le_bytes())?;
    let cin_addr = base + ARM64_CPP_CIN_OBJECT_OFFSET;
    emulator.write_memory(cin_addr, &vtable_addr.to_le_bytes())?;
    let ctype_id_addr = base + ARM64_CPP_CTYPE_ID_OFFSET;

    let mut data_symbols: HashMap<String, u64> = HashMap::new();

    data_symbols.insert("__ZNSt3__14cerrE".to_string(), cerr_addr);
    data_symbols.insert("__ZNSt3__14cinE".to_string(), cin_addr);
    data_symbols.insert("__ZNSt3__15wcerrE".to_string(), cerr_addr);
    data_symbols.insert("__ZNSt3__15wcinE".to_string(), cin_addr);
    data_symbols.insert("__ZNSt3__15ctypeIcE2idE".to_string(), ctype_id_addr);

    let vtable_names = [
        "__ZTVNSt3__18ios_baseE",
        "__ZTVNSt3__19basic_iosIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__113basic_ostreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__113basic_istreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__115basic_streambufIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE",
        "__ZTVNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTVNSt3__119basic_istringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTVNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    ];
    for name in vtable_names {
        data_symbols.insert(name.to_string(), vtable_addr);
    }

    let vtt_addr = base + ARM64_CPP_VTT_OFFSET;
    for i in 0..8 {
        emulator.write_memory(vtt_addr + i * 8, &vtable_addr.to_le_bytes())?;
    }
    for name in [
        "__ZTTNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE",
        "__ZTTNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE",
        "__ZTTNSt3__119basic_istringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
        "__ZTTNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    ] {
        data_symbols.insert(name.to_string(), vtt_addr);
    }

    if let Some(bus) = trace_bus {
        let _ = bus.send(
            memory_event(metadata, "cpp-data-region")
                .arg("Base", format!("0x{:X}", base))
                .arg("Size", format!("0x{:X}", region_size))
                .arg("VTable", format!("0x{:X}", vtable_addr))
                .arg("Vtt", format!("0x{:X}", vtt_addr))
                .arg("Cerr", format!("0x{:X}", cerr_addr)),
        );
    }
    Ok(data_symbols)
}

#[derive(Clone)]
struct DecodedString {
    bytes: Vec<u8>,
    layout: &'static str,
    raw_header: String,
}

#[derive(Clone, Copy)]
enum ByteArg {
    Cstr,
    CstrLen,
    StringRef,
}

fn text_preview(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|&b| match b {
            0x20..=0x7e => b as char,
            b'\n' => '\u{240A}',
            b'\r' => '\u{240D}',
            b'\t' => '\u{2409}',
            _ => '.',
        })
        .collect()
}

fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn read_u64(bytes: &[u8], range: std::ops::Range<usize>) -> u64 {
    bytes
        .get(range)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn read_guest_bytes(emu: &mut dyn Emulator, ptr: u64, len: usize) -> Option<Vec<u8>> {
    if ptr < 0x1000 || len > MAX_SYNTHETIC_STRING_LEN {
        return None;
    }
    if len == 0 {
        return Some(Vec::new());
    }
    emu.read_memory(ptr, len).ok()
}

fn read_capped_guest_bytes(emu: &mut dyn Emulator, ptr: u64, len: usize) -> Vec<u8> {
    read_guest_bytes(emu, ptr, len.min(MAX_SYNTHETIC_STRING_LEN)).unwrap_or_default()
}

fn read_capped_cstring(emu: &mut dyn Emulator, ptr: u64, max_len: usize) -> Vec<u8> {
    if ptr < 0x1000 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for idx in 0..max_len.min(MAX_SYNTHETIC_STRING_LEN) {
        let Ok(bytes) = emu.read_memory(ptr + idx as u64, 1) else {
            break;
        };
        let Some(&byte) = bytes.first() else {
            break;
        };
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    out
}

fn decode_long_string(
    emu: &mut dyn Emulator,
    data_ptr: u64,
    len: u64,
    layout: &'static str,
    raw_header: &str,
) -> Option<DecodedString> {
    if len > MAX_SYNTHETIC_STRING_LEN as u64 {
        return None;
    }
    let bytes = read_guest_bytes(emu, data_ptr, len as usize)?;
    Some(DecodedString {
        bytes,
        layout,
        raw_header: raw_header.to_string(),
    })
}

fn decode_basic_string(emu: &mut dyn Emulator, this: u64) -> DecodedString {
    let header = emu
        .read_memory(this, LIBCPP_STRING_OBJECT_SIZE)
        .unwrap_or_else(|_| vec![0u8; LIBCPP_STRING_OBJECT_SIZE]);
    let raw_header = hex_preview(&header, LIBCPP_STRING_OBJECT_SIZE);

    let word0 = read_u64(&header, 0..8);
    let word1 = read_u64(&header, 8..16);
    let word2 = read_u64(&header, 16..24);

    // Apple arm64 libc++ uses the alternate layout: long strings store
    // {data, size, capacity|long-bit}, short strings store bytes at +0 and
    // size in the low seven bits of byte 23. Decode it first because this
    // emulator targets macOS arm64.
    if (word2 & ALT_LONG_FLAG) != 0 {
        if let Some(decoded) =
            decode_long_string(emu, word0, word1, "libc++-alternate-long", &raw_header)
        {
            return decoded;
        }
    }

    // Non-alternate libc++ layout: long strings store
    // {capacity|long-bit, size, data}.
    if (word0 & 1) != 0 {
        if let Some(decoded) =
            decode_long_string(emu, word2, word1, "libc++-default-long", &raw_header)
        {
            return decoded;
        }
    }

    let alt_short_len = (header.get(23).copied().unwrap_or(0) & 0x7F) as usize;
    let alt_short_is_long = (header.get(23).copied().unwrap_or(0) & 0x80) != 0;
    if !alt_short_is_long && alt_short_len <= LIBCPP_SHORT_MAX {
        let bytes = header
            .get(0..alt_short_len)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        return DecodedString {
            bytes,
            layout: "libc++-alternate-short",
            raw_header,
        };
    }

    let default_short_tag = header.first().copied().unwrap_or(0);
    let default_short_len = (default_short_tag >> 1) as usize;
    if (default_short_tag & 1) == 0 && default_short_len <= LIBCPP_SHORT_MAX {
        let bytes = header
            .get(1..1 + default_short_len)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        return DecodedString {
            bytes,
            layout: "libc++-default-short",
            raw_header,
        };
    }

    DecodedString {
        bytes: Vec::new(),
        layout: "unknown",
        raw_header,
    }
}

fn allocate_guest_bytes(
    emu: &mut dyn Emulator,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    bytes: &[u8],
) -> Option<(u64, u64)> {
    let len = bytes.len().min(MAX_SYNTHETIC_STRING_LEN);
    let alloc_len = ((len as u64 + 1 + 0xF) & !0xF).max(0x10);
    let data_ptr = mmap_next.fetch_add(alloc_len, Ordering::Relaxed);
    if data_ptr.saturating_add(alloc_len) > mmap_end {
        return None;
    }
    let mut payload = Vec::with_capacity(len + 1);
    payload.extend_from_slice(&bytes[..len]);
    payload.push(0);
    if emu.write_memory(data_ptr, &payload).is_err() {
        return None;
    }
    Some((data_ptr, alloc_len))
}

fn write_basic_string(
    emu: &mut dyn Emulator,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    this: u64,
    bytes: &[u8],
) -> Option<(u64, &'static str)> {
    if this < 0x1000 {
        return None;
    }

    let len = bytes.len().min(MAX_SYNTHETIC_STRING_LEN);
    let mut object = [0u8; LIBCPP_STRING_OBJECT_SIZE];
    if len <= LIBCPP_SHORT_MAX {
        object[0..len].copy_from_slice(&bytes[..len]);
        object[23] = len as u8;
        if emu.write_memory(this, &object).is_err() {
            return None;
        }
        return Some((this, "libc++-alternate-short"));
    }

    let (data_ptr, allocation_count) =
        allocate_guest_bytes(emu, mmap_next, mmap_end, &bytes[..len])?;
    object[0..8].copy_from_slice(&data_ptr.to_le_bytes());
    object[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    object[16..24].copy_from_slice(&(allocation_count | ALT_LONG_FLAG).to_le_bytes());
    if emu.write_memory(this, &object).is_err() {
        return None;
    }
    Some((data_ptr, "libc++-alternate-long"))
}

fn record_import(tracker: &Arm64ImportTracker, name: &str, address: u64) {
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

pub fn install_analysis_arm64_cpp_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    install_ostream_sentry_hook(
        emulator,
        stub_map,
        SENTRY_C1_SYMBOL,
        "ostream-sentry",
        "ostream_sentry_C1",
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_ostream_sentry_hook(
        emulator,
        stub_map,
        ISTREAM_SENTRY_C1_SYMBOL,
        "istream-sentry",
        "istream_sentry_C1",
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_ostream_write_hook(emulator, stub_map, trace_bus, import_tracker, process_name)?;
    install_string_init_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_string_copy_hooks(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_string_destructor_hooks(emulator, stub_map, import_tracker)?;
    install_string_assign_hook(
        emulator,
        stub_map,
        STRING_ASSIGN_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        ByteArg::Cstr,
    )?;
    install_string_assign_hook(
        emulator,
        stub_map,
        STRING_ASSIGN_CSTR_LEN_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        ByteArg::CstrLen,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        ByteArg::Cstr,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_CSTR_LEN_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        ByteArg::CstrLen,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_STRING_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        ByteArg::StringRef,
    )?;
    install_string_erase_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_string_push_back_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_find_char_hook(
        emulator,
        stub_map,
        STRING_FIND_CHAR_SYMBOL,
        trace_bus,
        import_tracker,
        process_name,
        false,
    )?;
    install_find_char_hook(
        emulator,
        stub_map,
        STRING_RFIND_CHAR_SYMBOL,
        trace_bus,
        import_tracker,
        process_name,
        true,
    )?;
    install_to_string_u32_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
    )?;
    install_string_plus_hook(
        emulator,
        stub_map,
        STRING_PLUS_CSTR_STRING_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        true,
    )?;
    install_string_plus_hook(
        emulator,
        stub_map,
        STRING_PLUS_STRING_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        trace_bus,
        import_tracker,
        process_name,
        false,
    )?;
    install_compare_hook(
        emulator,
        stub_map,
        STRING_COMPARE_SYMBOL,
        trace_bus,
        import_tracker,
        process_name,
        false,
    )?;
    install_compare_hook(
        emulator,
        stub_map,
        STRING_COMPARE_N_SYMBOL,
        trace_bus,
        import_tracker,
        process_name,
        true,
    )?;

    Ok(())
}

fn install_ostream_sentry_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    event_name: &'static str,
    call_name: &'static str,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
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
            let stream = emu.read_reg("x1").unwrap_or(0);
            if this >= 0x1000 {
                let _ = emu.write_memory(this, &[1u8]);
            }
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            if let Some(bus) = &trace_bus_for_hook {
                let _ = bus.send(
                    process_event(
                        &runtime_process_metadata(proc_name.clone()),
                        event_name,
                        call_name,
                    )
                    .arg("This", format!("0x{:X}", this))
                    .arg("Stream", format!("0x{:X}", stream)),
                );
            }
        },
    )?;
    Ok(())
}

fn install_ostream_write_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(OSTREAM_WRITE_SYMBOL) else {
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
            let buf_ptr = emu.read_reg("x1").unwrap_or(0);
            let n = emu.read_reg("x2").unwrap_or(0);
            let bytes = read_capped_guest_bytes(emu, buf_ptr, n.min(0x1000) as usize);
            let lr = emu.read_reg("lr").unwrap_or(0);
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
                    .arg("Text", text_preview(&bytes, bytes.len()))
                    .arg("Hex", hex_preview(&bytes, bytes.len())),
                );
            }
        },
    )?;
    Ok(())
}

fn install_string_init_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(STRING_INIT_CSTR_LEN_SYMBOL) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let src = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0);
            let bytes = read_capped_guest_bytes(emu, src, len as usize);
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &bytes)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, STRING_INIT_CSTR_LEN_SYMBOL, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-init",
                "basic_string_init",
                this,
                data_ptr,
                layout,
                &bytes,
                |event| {
                    event
                        .arg("Src", format!("0x{:X}", src))
                        .arg("Len", len.to_string())
                },
            );
        },
    )?;
    Ok(())
}

fn install_string_copy_hooks(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for symbol in [STRING_COPY_C1_SYMBOL, STRING_COPY_C2_SYMBOL] {
        let Some(&addr) = stub_map.get(symbol) else {
            continue;
        };
        let tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let proc_name = process_name.to_string();
        let mmap_next_for_hook = mmap_next.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let this = emu.read_reg("x0").unwrap_or(0);
                let src = emu.read_reg("x1").unwrap_or(0);
                let decoded = decode_basic_string(emu, src);
                let (data_ptr, out_layout) =
                    write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &decoded.bytes)
                        .unwrap_or((0, "write-failed"));
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", this);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, symbol, addr);
                emit_string_event(
                    &trace_bus_for_hook,
                    &proc_name,
                    "string-copy",
                    "basic_string_copy",
                    this,
                    data_ptr,
                    out_layout,
                    &decoded.bytes,
                    |event| {
                        event
                            .arg("Src", format!("0x{:X}", src))
                            .arg("SrcLayout", decoded.layout)
                            .arg("RawHeader", decoded.raw_header)
                    },
                );
            },
        )?;
    }
    Ok(())
}

fn install_string_destructor_hooks(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    for symbol in [STRING_D1_SYMBOL, STRING_D2_SYMBOL] {
        let Some(&addr) = stub_map.get(symbol) else {
            continue;
        };
        let tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let this = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", this);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_import(&tracker, symbol, addr);
            },
        )?;
    }
    Ok(())
}

fn read_byte_arg(emu: &mut dyn Emulator, ptr: u64, len: u64, kind: ByteArg) -> Vec<u8> {
    match kind {
        ByteArg::Cstr => read_capped_cstring(emu, ptr, MAX_SYNTHETIC_STRING_LEN),
        ByteArg::CstrLen => {
            read_capped_guest_bytes(emu, ptr, len.min(MAX_SYNTHETIC_STRING_LEN as u64) as usize)
        }
        ByteArg::StringRef => decode_basic_string(emu, ptr).bytes,
    }
}

fn install_string_assign_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
    arg_kind: ByteArg,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let arg = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0);
            let bytes = read_byte_arg(emu, arg, len, arg_kind);
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &bytes)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-assign",
                "string_assign",
                this,
                data_ptr,
                layout,
                &bytes,
                |event| {
                    event
                        .arg("Arg", format!("0x{:X}", arg))
                        .arg("LenArg", len.to_string())
                },
            );
        },
    )?;
    Ok(())
}

fn install_string_append_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
    arg_kind: ByteArg,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let arg = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0);
            let decoded = decode_basic_string(emu, this);
            let appended = read_byte_arg(emu, arg, len, arg_kind);
            let mut bytes = decoded.bytes;
            let old_len = bytes.len();
            let remaining = MAX_SYNTHETIC_STRING_LEN.saturating_sub(bytes.len());
            bytes.extend_from_slice(&appended[..appended.len().min(remaining)]);
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &bytes)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-append",
                "string_append",
                this,
                data_ptr,
                layout,
                &bytes,
                |event| {
                    event
                        .arg("Arg", format!("0x{:X}", arg))
                        .arg("LenArg", len.to_string())
                        .arg("OldLen", old_len.to_string())
                        .arg("AppendLen", appended.len().to_string())
                },
            );
        },
    )?;
    Ok(())
}

fn install_string_erase_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(STRING_ERASE_SYMBOL) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let pos = emu.read_reg("x1").unwrap_or(0) as usize;
            let count = emu.read_reg("x2").unwrap_or(0) as usize;
            let decoded = decode_basic_string(emu, this);
            let mut bytes = decoded.bytes;
            let old_len = bytes.len();
            if pos < bytes.len() {
                let erase_len = if count == NPOS {
                    bytes.len() - pos
                } else {
                    count.min(bytes.len() - pos)
                };
                bytes.drain(pos..pos + erase_len);
            }
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &bytes)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, STRING_ERASE_SYMBOL, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-erase",
                "string_erase",
                this,
                data_ptr,
                layout,
                &bytes,
                |event| {
                    event
                        .arg("Pos", pos.to_string())
                        .arg("Count", count.to_string())
                        .arg("OldLen", old_len.to_string())
                },
            );
        },
    )?;
    Ok(())
}

fn install_string_push_back_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(STRING_PUSH_BACK_SYMBOL) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let this = emu.read_reg("x0").unwrap_or(0);
            let ch = (emu.read_reg("x1").unwrap_or(0) & 0xFF) as u8;
            let decoded = decode_basic_string(emu, this);
            let mut bytes = decoded.bytes;
            if bytes.len() < MAX_SYNTHETIC_STRING_LEN {
                bytes.push(ch);
            }
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, this, &bytes)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", this);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, STRING_PUSH_BACK_SYMBOL, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-push-back",
                "string_push_back",
                this,
                data_ptr,
                layout,
                &bytes,
                |event| event.arg("Char", format!("0x{:02X}", ch)),
            );
        },
    )?;
    Ok(())
}

fn install_to_string_u32_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(TO_STRING_U32_SYMBOL) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let value = emu.read_reg("x0").unwrap_or(0) as u32;
            let out = emu.read_reg("x8").unwrap_or(0);
            let rendered = value.to_string();
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, out, rendered.as_bytes())
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", out);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, TO_STRING_U32_SYMBOL, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-to-string",
                "to_string_u32",
                out,
                data_ptr,
                layout,
                rendered.as_bytes(),
                |event| event.arg("Value", value.to_string()),
            );
        },
    )?;
    Ok(())
}

fn install_string_plus_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
    cstr_first: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let out = emu.read_reg("x8").unwrap_or(0);
            let x0 = emu.read_reg("x0").unwrap_or(0);
            let x1 = emu.read_reg("x1").unwrap_or(0);
            let (left, right) = if cstr_first {
                (
                    read_capped_cstring(emu, x0, MAX_SYNTHETIC_STRING_LEN),
                    decode_basic_string(emu, x1).bytes,
                )
            } else {
                (
                    decode_basic_string(emu, x0).bytes,
                    read_capped_cstring(emu, x1, MAX_SYNTHETIC_STRING_LEN),
                )
            };
            let mut combined = Vec::with_capacity(left.len().saturating_add(right.len()));
            combined.extend_from_slice(&left);
            combined.extend_from_slice(&right);
            combined.truncate(MAX_SYNTHETIC_STRING_LEN);
            let (data_ptr, layout) =
                write_basic_string(emu, &mmap_next_for_hook, mmap_end, out, &combined)
                    .unwrap_or((0, "write-failed"));
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", out);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            emit_string_event(
                &trace_bus_for_hook,
                &proc_name,
                "string-plus",
                "string_plus",
                out,
                data_ptr,
                layout,
                &combined,
                |event| {
                    event
                        .arg("X0", format!("0x{:X}", x0))
                        .arg("X1", format!("0x{:X}", x1))
                        .arg("Left", text_preview(&left, 80))
                        .arg("Right", text_preview(&right, 80))
                },
            );
        },
    )?;
    Ok(())
}

fn install_find_char_hook(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    trace_bus: &Option<SharedTraceBus>,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
    reverse: bool,
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
            let needle = (emu.read_reg("x1").unwrap_or(0) & 0xFF) as u8;
            let pos = emu.read_reg("x2").unwrap_or(0) as usize;
            let decoded = decode_basic_string(emu, this);
            let result = if reverse {
                if decoded.bytes.is_empty() {
                    u64::MAX
                } else {
                    let end = if pos == NPOS || pos >= decoded.bytes.len() {
                        decoded.bytes.len() - 1
                    } else {
                        pos
                    };
                    decoded
                        .bytes
                        .get(..=end)
                        .and_then(|slice| slice.iter().rposition(|&b| b == needle))
                        .map(|idx| idx as u64)
                        .unwrap_or(u64::MAX)
                }
            } else if pos > decoded.bytes.len() {
                u64::MAX
            } else {
                decoded
                    .bytes
                    .iter()
                    .enumerate()
                    .skip(pos)
                    .find_map(|(idx, &b)| (b == needle).then_some(idx as u64))
                    .unwrap_or(u64::MAX)
            };
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_import(&tracker, symbol, addr);
            if let Some(bus) = &trace_bus_for_hook {
                let _ = bus.send(
                    process_event(
                        &runtime_process_metadata(proc_name.clone()),
                        if reverse {
                            "string-rfind"
                        } else {
                            "string-find"
                        },
                        if reverse {
                            "string_rfind"
                        } else {
                            "string_find"
                        },
                    )
                    .arg("This", format!("0x{:X}", this))
                    .arg("Needle", format!("0x{:02X}", needle))
                    .arg("Pos", pos.to_string())
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Layout", decoded.layout)
                    .arg("Text", text_preview(&decoded.bytes, 96))
                    .arg("RawHeader", decoded.raw_header),
                );
            }
        },
    )?;
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
            let pos = emu.read_reg("x1").unwrap_or(0) as usize;
            let n = emu.read_reg("x2").unwrap_or(0) as usize;
            let s_ptr = emu.read_reg("x3").unwrap_or(0);
            let n2 = if has_n2 {
                emu.read_reg("x4").unwrap_or(0) as usize
            } else {
                n
            };
            let rhs_len = if has_n2 { n2 } else { n };
            let s_bytes = read_capped_guest_bytes(emu, s_ptr, rhs_len.min(256));
            let decoded = decode_basic_string(emu, this);
            let lhs_slice = decoded
                .bytes
                .get(pos..pos.saturating_add(n).min(decoded.bytes.len()))
                .unwrap_or(&[]);
            let rhs_slice = s_bytes
                .get(..rhs_len.min(s_bytes.len()))
                .unwrap_or(&s_bytes);
            let result = match lhs_slice.cmp(rhs_slice) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };

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
                    .arg(
                        "N2",
                        if has_n2 {
                            n2.to_string()
                        } else {
                            "none".to_string()
                        },
                    )
                    .arg("SPtr", format!("0x{:X}", s_ptr))
                    .arg("Lhs", text_preview(lhs_slice, 64))
                    .arg("Rhs", text_preview(rhs_slice, 64))
                    .arg("Result", result.to_string())
                    .arg("RawHeader", decoded.raw_header)
                    .arg("Layout", decoded.layout)
                    .arg("LhsTotalLen", decoded.bytes.len().to_string()),
                );
            }
        },
    )?;
    Ok(())
}

fn emit_string_event<F>(
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
    event_name: &'static str,
    call_name: &'static str,
    this: u64,
    data_ptr: u64,
    layout: &'static str,
    bytes: &[u8],
    add_args: F,
) where
    F: FnOnce(crate::macos::TraceEvent) -> crate::macos::TraceEvent,
{
    let Some(bus) = trace_bus else {
        return;
    };
    let event = process_event(
        &runtime_process_metadata(process_name.to_string()),
        event_name,
        call_name,
    )
    .arg("This", format!("0x{:X}", this))
    .arg("Data", format!("0x{:X}", data_ptr))
    .arg("Layout", layout)
    .arg("Len", bytes.len().to_string())
    .arg("Text", text_preview(bytes, 160))
    .arg("Hex", hex_preview(bytes, 96));
    let _ = bus.send(add_args(event));
}
