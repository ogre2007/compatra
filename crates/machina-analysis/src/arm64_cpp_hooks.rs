//! arm64 C++/libc++ hooks used by analysis mode.
//!
//! These hooks cover small, well-defined libc++ functions that commonly appear
//! as imported symbols in no-dyld Mach-O runs. They intentionally model function
//! semantics and libc++'s documented string object layouts rather than
//! sample-specific object offsets.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::libcpp::{
    decode_basic_string as decode_libcpp_basic_string, hex_preview,
    read_capped_cstring as read_capped_libcpp_cstring,
    read_capped_guest_bytes as read_capped_libcpp_guest_bytes, text_preview, DecodedLibcppString,
    ALT_LONG_FLAG, ARM64_CPP_CERR_OBJECT_OFFSET, ARM64_CPP_CIN_OBJECT_OFFSET,
    ARM64_CPP_CTYPE_ID_OFFSET, ARM64_CPP_DATA_REGION_SIZE, ARM64_CPP_VTABLE_STORAGE_OFFSET,
    ARM64_CPP_VTT_OFFSET, CERR_SYMBOL, CIN_SYMBOL, CTYPE_ID_SYMBOL, ISTREAM_SENTRY_C1_SYMBOL,
    LIBCPP_SHORT_MAX, LIBCPP_STRING_OBJECT_SIZE, LIBCPP_VTABLE_SYMBOLS, LIBCPP_VTT_SYMBOLS,
    MAX_SYNTHETIC_STRING_LEN, NPOS, OSTREAM_WRITE_SYMBOL, SENTRY_C1_SYMBOL,
    STRING_APPEND_CSTR_LEN_SYMBOL, STRING_APPEND_CSTR_SYMBOL, STRING_APPEND_STRING_SYMBOL,
    STRING_ASSIGN_CSTR_LEN_SYMBOL, STRING_ASSIGN_CSTR_SYMBOL, STRING_COMPARE_N_SYMBOL,
    STRING_COMPARE_SYMBOL, STRING_COPY_C1_SYMBOL, STRING_COPY_C2_SYMBOL, STRING_D1_SYMBOL,
    STRING_D2_SYMBOL, STRING_ERASE_SYMBOL, STRING_FIND_CHAR_SYMBOL, STRING_INIT_CSTR_LEN_SYMBOL,
    STRING_PLUS_CSTR_STRING_SYMBOL, STRING_PLUS_STRING_CSTR_SYMBOL, STRING_PUSH_BACK_SYMBOL,
    STRING_RFIND_CHAR_SYMBOL, TO_STRING_U32_SYMBOL, WCERR_SYMBOL, WCIN_SYMBOL,
};
use crate::operator_hooks::{FunctionEntryProbeSpec, UsageBypassHookSpec};

pub trait Arm64AnalysisEmulator: Sized + 'static {
    fn read_memory(&mut self, addr: u64, size: usize) -> Option<Vec<u8>>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> bool;
    fn read_reg(&mut self, reg: &str) -> Option<u64>;
    fn write_reg(&mut self, reg: &str, value: u64) -> bool;

    fn add_code_hook<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<(), Box<dyn Error>>
    where
        F: Fn(&mut Self, u64, u32) + Send + 'static;
}

pub trait Arm64AnalysisImportTracker: Clone + Send + 'static {
    fn record_import(&self, name: &str, address: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisTraceCategory {
    Process,
    Memory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisTraceRecord {
    pub category: AnalysisTraceCategory,
    pub process_name: String,
    pub event_name: String,
    pub call_name: String,
    pub args: Vec<(String, String)>,
}

impl AnalysisTraceRecord {
    pub fn process(
        process_name: impl Into<String>,
        event_name: impl Into<String>,
        call_name: impl Into<String>,
    ) -> Self {
        Self {
            category: AnalysisTraceCategory::Process,
            process_name: process_name.into(),
            event_name: event_name.into(),
            call_name: call_name.into(),
            args: Vec::new(),
        }
    }

    pub fn memory(process_name: impl Into<String>, call_name: impl Into<String>) -> Self {
        let call_name = call_name.into();
        Self {
            category: AnalysisTraceCategory::Memory,
            process_name: process_name.into(),
            event_name: call_name.clone(),
            call_name,
            args: Vec::new(),
        }
    }

    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push((key.into(), value.into()));
        self
    }
}

pub trait AnalysisTraceSink: Clone + Send + 'static {
    fn emit(&self, record: AnalysisTraceRecord);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopAnalysisTraceSink;

impl AnalysisTraceSink for NoopAnalysisTraceSink {
    fn emit(&self, _record: AnalysisTraceRecord) {}
}

/// Allocate and initialize a fake C++ data-symbol region.
///
/// Returns a map of known C++ data-symbol names -> resolved
/// addresses. Pass it to `process_chained_fixups_with_binary` as
/// `data_symbols` so the chain walker patches data binds (like
/// `__ZNSt3__14cerrE`) into this region instead of a function
/// stub.
pub fn setup_analysis_arm64_cpp_data_region<E, T>(
    emulator: &mut E,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    done_addr: u64,
    trace_sink: T,
    process_name: &str,
) -> Result<HashMap<String, u64>, Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
{
    let region_size = ARM64_CPP_DATA_REGION_SIZE;
    let base = mmap_next.fetch_add(region_size, Ordering::Relaxed);
    if base.saturating_add(region_size) > mmap_end {
        return Err("mmap arena exhausted while allocating C++ data region".into());
    }

    let zeros = vec![0u8; region_size as usize];
    write_guest_memory(emulator, base, &zeros)?;

    let vtable_storage_addr = base + ARM64_CPP_VTABLE_STORAGE_OFFSET;
    let vtable_addr = vtable_storage_addr + 16;
    write_guest_memory(emulator, vtable_storage_addr, &0u64.to_le_bytes())?;
    write_guest_memory(emulator, vtable_storage_addr + 8, &0u64.to_le_bytes())?;
    for i in 0..32 {
        write_guest_memory(emulator, vtable_addr + i * 8, &done_addr.to_le_bytes())?;
    }

    let cerr_addr = base + ARM64_CPP_CERR_OBJECT_OFFSET;
    write_guest_memory(emulator, cerr_addr, &vtable_addr.to_le_bytes())?;
    let cin_addr = base + ARM64_CPP_CIN_OBJECT_OFFSET;
    write_guest_memory(emulator, cin_addr, &vtable_addr.to_le_bytes())?;
    let ctype_id_addr = base + ARM64_CPP_CTYPE_ID_OFFSET;

    let mut data_symbols: HashMap<String, u64> = HashMap::new();

    data_symbols.insert(CERR_SYMBOL.to_string(), cerr_addr);
    data_symbols.insert(CIN_SYMBOL.to_string(), cin_addr);
    data_symbols.insert(WCERR_SYMBOL.to_string(), cerr_addr);
    data_symbols.insert(WCIN_SYMBOL.to_string(), cin_addr);
    data_symbols.insert(CTYPE_ID_SYMBOL.to_string(), ctype_id_addr);

    for &name in LIBCPP_VTABLE_SYMBOLS {
        data_symbols.insert(name.to_string(), vtable_addr);
    }

    let vtt_addr = base + ARM64_CPP_VTT_OFFSET;
    for i in 0..8 {
        write_guest_memory(emulator, vtt_addr + i * 8, &vtable_addr.to_le_bytes())?;
    }
    for &name in LIBCPP_VTT_SYMBOLS {
        data_symbols.insert(name.to_string(), vtt_addr);
    }

    trace_sink.emit(
        AnalysisTraceRecord::memory(process_name, "cpp-data-region")
            .arg("Base", format!("0x{:X}", base))
            .arg("Size", format!("0x{:X}", region_size))
            .arg("VTable", format!("0x{:X}", vtable_addr))
            .arg("Vtt", format!("0x{:X}", vtt_addr))
            .arg("Cerr", format!("0x{:X}", cerr_addr)),
    );
    Ok(data_symbols)
}

fn write_guest_memory<E: Arm64AnalysisEmulator>(
    emulator: &mut E,
    addr: u64,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    emulator
        .write_memory(addr, data)
        .then_some(())
        .ok_or_else(|| format!("failed to write guest memory at 0x{addr:X}").into())
}

#[derive(Clone, Copy)]
enum ByteArg {
    Cstr,
    CstrLen,
    StringRef,
}

fn read_capped_guest_bytes<E: Arm64AnalysisEmulator>(emu: &mut E, ptr: u64, len: usize) -> Vec<u8> {
    read_capped_libcpp_guest_bytes(ptr, len, |addr, size| emu.read_memory(addr, size))
}

fn read_capped_cstring<E: Arm64AnalysisEmulator>(emu: &mut E, ptr: u64, max_len: usize) -> Vec<u8> {
    read_capped_libcpp_cstring(ptr, max_len, |addr, size| emu.read_memory(addr, size))
}

fn decode_basic_string<E: Arm64AnalysisEmulator>(emu: &mut E, this: u64) -> DecodedLibcppString {
    decode_libcpp_basic_string(this, |addr, size| emu.read_memory(addr, size))
}

fn allocate_guest_bytes<E: Arm64AnalysisEmulator>(
    emu: &mut E,
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
    if !emu.write_memory(data_ptr, &payload) {
        return None;
    }
    Some((data_ptr, alloc_len))
}

fn write_basic_string<E: Arm64AnalysisEmulator>(
    emu: &mut E,
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
        if !emu.write_memory(this, &object) {
            return None;
        }
        return Some((this, "libc++-alternate-short"));
    }

    let (data_ptr, allocation_count) =
        allocate_guest_bytes(emu, mmap_next, mmap_end, &bytes[..len])?;
    object[0..8].copy_from_slice(&data_ptr.to_le_bytes());
    object[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    object[16..24].copy_from_slice(&(allocation_count | ALT_LONG_FLAG).to_le_bytes());
    if !emu.write_memory(this, &object) {
        return None;
    }
    Some((data_ptr, "libc++-alternate-long"))
}

fn record_import<T: Arm64AnalysisImportTracker>(tracker: &T, name: &str, address: u64) {
    tracker.record_import(name, address);
}

pub fn install_analysis_arm64_cpp_imports<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: T,
    import_tracker: R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    install_ostream_sentry_hook(
        emulator,
        stub_map,
        SENTRY_C1_SYMBOL,
        "ostream-sentry",
        "ostream_sentry_C1",
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_ostream_sentry_hook(
        emulator,
        stub_map,
        ISTREAM_SENTRY_C1_SYMBOL,
        "istream-sentry",
        "istream_sentry_C1",
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_ostream_write_hook(
        emulator,
        stub_map,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_string_init_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_string_copy_hooks(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_string_destructor_hooks(emulator, stub_map, &import_tracker)?;
    install_string_assign_hook(
        emulator,
        stub_map,
        STRING_ASSIGN_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        ByteArg::Cstr,
    )?;
    install_string_assign_hook(
        emulator,
        stub_map,
        STRING_ASSIGN_CSTR_LEN_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        ByteArg::CstrLen,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        ByteArg::Cstr,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_CSTR_LEN_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        ByteArg::CstrLen,
    )?;
    install_string_append_hook(
        emulator,
        stub_map,
        STRING_APPEND_STRING_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        ByteArg::StringRef,
    )?;
    install_string_erase_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_string_push_back_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_find_char_hook(
        emulator,
        stub_map,
        STRING_FIND_CHAR_SYMBOL,
        &trace_sink,
        &import_tracker,
        process_name,
        false,
    )?;
    install_find_char_hook(
        emulator,
        stub_map,
        STRING_RFIND_CHAR_SYMBOL,
        &trace_sink,
        &import_tracker,
        process_name,
        true,
    )?;
    install_to_string_u32_hook(
        emulator,
        stub_map,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
    )?;
    install_string_plus_hook(
        emulator,
        stub_map,
        STRING_PLUS_CSTR_STRING_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        true,
    )?;
    install_string_plus_hook(
        emulator,
        stub_map,
        STRING_PLUS_STRING_CSTR_SYMBOL,
        mmap_next,
        mmap_end,
        &trace_sink,
        &import_tracker,
        process_name,
        false,
    )?;
    install_compare_hook(
        emulator,
        stub_map,
        STRING_COMPARE_SYMBOL,
        &trace_sink,
        &import_tracker,
        process_name,
        false,
    )?;
    install_compare_hook(
        emulator,
        stub_map,
        STRING_COMPARE_N_SYMBOL,
        &trace_sink,
        &import_tracker,
        process_name,
        true,
    )?;

    Ok(())
}

pub fn install_arm64_operator_hooks<E, T>(
    emulator: &mut E,
    function_entry_specs: Vec<FunctionEntryProbeSpec>,
    usage_bypass_specs: Vec<UsageBypassHookSpec>,
    trace_sink: T,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
{
    for spec in function_entry_specs {
        let label_owned = spec.label;
        let addr = spec.addr;
        let trace_sink_for_hook = trace_sink.clone();
        let proc_name = process_name.to_string();
        emulator.add_code_hook(addr, addr + 4, move |emu: &mut E, _address, _size| {
            let x0 = emu.read_reg("x0").unwrap_or(0);
            let x1 = emu.read_reg("x1").unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(proc_name.clone(), "function-entry", "function_entry")
                    .arg("Label", label_owned.clone())
                    .arg("Pc", format!("0x{:X}", addr))
                    .arg("X0", format!("0x{:X}", x0))
                    .arg("X1", format!("0x{:X}", x1))
                    .arg("Lr", format!("0x{:X}", lr)),
            );
        })?;
    }

    for spec in usage_bypass_specs {
        let addr = spec.addr;
        let lr_filter = spec.lr_filter;
        let values = spec.values;
        let trace_sink_for_hook = trace_sink.clone();
        let proc_name = process_name.to_string();
        let counter = Arc::new(AtomicUsize::new(0));
        emulator.add_code_hook(addr, addr + 4, move |emu: &mut E, _address, _size| {
            let x0_in = emu.read_reg("x0").unwrap_or(0);
            let x1_in = emu.read_reg("x1").unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);
            if lr_filter.is_some_and(|expected| expected != lr) {
                return;
            }
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let value = if values.is_empty() {
                0
            } else if n < values.len() {
                values[n]
            } else {
                *values.last().unwrap()
            };
            let _ = emu.write_reg("x0", value);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(
                    proc_name.clone(),
                    "bypass-usage-check",
                    "bypass_usage_check",
                )
                .arg("Pc", format!("0x{:X}", addr))
                .arg("CallIndex", n.to_string())
                .arg("ReturnValue", format!("0x{:X}", value))
                .arg("X0In", format!("0x{:X}", x0_in))
                .arg("X1In", format!("0x{:X}", x1_in))
                .arg("Lr", format!("0x{:X}", lr))
                .arg(
                    "LrFilter",
                    lr_filter
                        .map(|expected| format!("0x{:X}", expected))
                        .unwrap_or_else(|| "none".to_string()),
                ),
            );
        })?;
    }

    Ok(())
}

fn install_ostream_sentry_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    event_name: &'static str,
    call_name: &'static str,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(proc_name.clone(), event_name, call_name)
                    .arg("This", format!("0x{:X}", this))
                    .arg("Stream", format!("0x{:X}", stream)),
            );
        },
    )?;
    Ok(())
}

fn install_ostream_write_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(OSTREAM_WRITE_SYMBOL) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(proc_name.clone(), "ostream-write", "ostream_write")
                    .arg("Stream", format!("0x{:X}", this))
                    .arg("BufPtr", format!("0x{:X}", buf_ptr))
                    .arg("Len", format!("0x{:X}", n))
                    .arg("Text", text_preview(&bytes, bytes.len()))
                    .arg("Hex", hex_preview(&bytes, bytes.len())),
            );
        },
    )?;
    Ok(())
}

fn install_string_init_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(STRING_INIT_CSTR_LEN_SYMBOL) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_string_copy_hooks<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    for symbol in [STRING_COPY_C1_SYMBOL, STRING_COPY_C2_SYMBOL] {
        let Some(&addr) = stub_map.get(symbol) else {
            continue;
        };
        let tracker = (*import_tracker).clone();
        let trace_sink_for_hook = (*trace_sink).clone();
        let proc_name = process_name.to_string();
        let mmap_next_for_hook = mmap_next.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut E, _address: u64, _size: u32| {
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
                    &trace_sink_for_hook,
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

fn install_string_destructor_hooks<E, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    import_tracker: &R,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    R: Arm64AnalysisImportTracker,
{
    for symbol in [STRING_D1_SYMBOL, STRING_D2_SYMBOL] {
        let Some(&addr) = stub_map.get(symbol) else {
            continue;
        };
        let tracker = (*import_tracker).clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut E, _address: u64, _size: u32| {
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

fn read_byte_arg<E: Arm64AnalysisEmulator>(
    emu: &mut E,
    ptr: u64,
    len: u64,
    kind: ByteArg,
) -> Vec<u8> {
    match kind {
        ByteArg::Cstr => read_capped_cstring(emu, ptr, MAX_SYNTHETIC_STRING_LEN),
        ByteArg::CstrLen => {
            read_capped_guest_bytes(emu, ptr, len.min(MAX_SYNTHETIC_STRING_LEN as u64) as usize)
        }
        ByteArg::StringRef => decode_basic_string(emu, ptr).bytes,
    }
}

fn install_string_assign_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
    arg_kind: ByteArg,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_string_append_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
    arg_kind: ByteArg,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_string_erase_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(STRING_ERASE_SYMBOL) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_string_push_back_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(STRING_PUSH_BACK_SYMBOL) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_to_string_u32_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(TO_STRING_U32_SYMBOL) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_string_plus_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    mmap_next: &Arc<AtomicU64>,
    mmap_end: u64,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
    cstr_first: bool,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    let mmap_next_for_hook = mmap_next.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
                &trace_sink_for_hook,
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

fn install_find_char_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
    reverse: bool,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(
                    proc_name.clone(),
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
        },
    )?;
    Ok(())
}

fn install_compare_hook<E, T, R>(
    emulator: &mut E,
    stub_map: &HashMap<String, u64>,
    symbol: &'static str,
    trace_sink: &T,
    import_tracker: &R,
    process_name: &str,
    has_n2: bool,
) -> Result<(), Box<dyn Error>>
where
    E: Arm64AnalysisEmulator,
    T: AnalysisTraceSink,
    R: Arm64AnalysisImportTracker,
{
    let Some(&addr) = stub_map.get(symbol) else {
        return Ok(());
    };
    let tracker = (*import_tracker).clone();
    let trace_sink_for_hook = (*trace_sink).clone();
    let proc_name = process_name.to_string();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut E, _address: u64, _size: u32| {
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
            trace_sink_for_hook.emit(
                AnalysisTraceRecord::process(proc_name.clone(), "string-compare", "string_compare")
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
        },
    )?;
    Ok(())
}

fn emit_string_event<T, F>(
    trace_sink: &T,
    process_name: &str,
    event_name: &'static str,
    call_name: &'static str,
    this: u64,
    data_ptr: u64,
    layout: &'static str,
    bytes: &[u8],
    add_args: F,
) where
    T: AnalysisTraceSink,
    F: FnOnce(AnalysisTraceRecord) -> AnalysisTraceRecord,
{
    let event = AnalysisTraceRecord::process(process_name.to_string(), event_name, call_name)
        .arg("This", format!("0x{:X}", this))
        .arg("Data", format!("0x{:X}", data_ptr))
        .arg("Layout", layout)
        .arg("Len", bytes.len().to_string())
        .arg("Text", text_preview(bytes, 160))
        .arg("Hex", hex_preview(bytes, 96));
    trace_sink.emit(add_args(event));
}

#[cfg(test)]
mod tests {
    use super::*;

    type FakeHook = Box<dyn Fn(&mut FakeEmulator, u64, u32) + Send>;

    #[derive(Default)]
    struct FakeEmulator {
        regs: HashMap<String, u64>,
        hooks: Vec<(u64, u64, FakeHook)>,
    }

    impl FakeEmulator {
        fn run_next_hook(&mut self, address: u64) {
            let (_, _, hook) = self.hooks.pop().expect("expected installed hook");
            hook(self, address, 4);
        }
    }

    impl Arm64AnalysisEmulator for FakeEmulator {
        fn read_memory(&mut self, _addr: u64, _size: usize) -> Option<Vec<u8>> {
            None
        }

        fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> bool {
            true
        }

        fn read_reg(&mut self, reg: &str) -> Option<u64> {
            self.regs.get(reg).copied()
        }

        fn write_reg(&mut self, reg: &str, value: u64) -> bool {
            self.regs.insert(reg.to_string(), value);
            true
        }

        fn add_code_hook<F>(
            &mut self,
            begin: u64,
            end: u64,
            callback: F,
        ) -> Result<(), Box<dyn Error>>
        where
            F: Fn(&mut Self, u64, u32) + Send + 'static,
        {
            self.hooks.push((begin, end, Box::new(callback)));
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct CollectTrace(Arc<std::sync::Mutex<Vec<AnalysisTraceRecord>>>);

    impl CollectTrace {
        fn records(&self) -> Vec<AnalysisTraceRecord> {
            self.0.lock().expect("trace lock").clone()
        }
    }

    impl AnalysisTraceSink for CollectTrace {
        fn emit(&self, record: AnalysisTraceRecord) {
            self.0.lock().expect("trace lock").push(record);
        }
    }

    #[test]
    fn operator_hook_installer_emits_function_entry_trace() {
        let mut emulator = FakeEmulator::default();
        emulator.regs.insert("x0".to_string(), 0x11);
        emulator.regs.insert("x1".to_string(), 0x22);
        emulator.regs.insert("lr".to_string(), 0x3333);
        let trace = CollectTrace::default();

        install_arm64_operator_hooks(
            &mut emulator,
            vec![FunctionEntryProbeSpec {
                label: "probe".to_string(),
                addr: 0x1000,
            }],
            Vec::new(),
            trace.clone(),
            "sample",
        )
        .expect("operator hook install should succeed");
        emulator.run_next_hook(0x1000);

        let records = trace.records();
        assert_eq!(records[0].event_name, "function-entry");
        assert!(records[0]
            .args
            .iter()
            .any(|(key, value)| key == "Label" && value == "probe"));
    }

    #[test]
    fn usage_bypass_hook_writes_return_and_trace_record() {
        let mut emulator = FakeEmulator::default();
        emulator.regs.insert("x0".to_string(), 0x11);
        emulator.regs.insert("x1".to_string(), 0x22);
        emulator.regs.insert("lr".to_string(), 0x4444);
        let trace = CollectTrace::default();

        install_arm64_operator_hooks(
            &mut emulator,
            Vec::new(),
            vec![UsageBypassHookSpec {
                addr: 0x2000,
                lr_filter: Some(0x4444),
                values: vec![0x77],
            }],
            trace.clone(),
            "sample",
        )
        .expect("usage bypass hook install should succeed");
        emulator.run_next_hook(0x2000);

        assert_eq!(emulator.regs.get("x0"), Some(&0x77));
        assert_eq!(emulator.regs.get("pc"), Some(&0x4444));
        let records = trace.records();
        assert_eq!(records[0].event_name, "bypass-usage-check");
        assert!(records[0]
            .args
            .iter()
            .any(|(key, value)| key == "ReturnValue" && value == "0x77"));
    }
}
