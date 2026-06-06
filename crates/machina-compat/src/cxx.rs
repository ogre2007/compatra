#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::{GuestMemory, HostCallResult};

const LIBCPP_STRING_OBJECT_SIZE: usize = 24;
const LIBCPP_SHORT_MAX: usize = 22;
const MAX_COMPAT_STRING_LEN: usize = 0x10_000;
const ALT_LONG_FLAG: u64 = 1u64 << 63;
const NPOS: usize = usize::MAX;

const STRING_INIT_CSTR_LEN_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm";
const STRING_COPY_C1_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_";
const STRING_COPY_C2_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_";
const STRING_D1_SYMBOL: &str = "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev";
const STRING_D2_SYMBOL: &str = "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev";
const STRING_ASSIGN_CSTR_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc";
const STRING_ASSIGN_CSTR_LEN_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKcm";
const STRING_APPEND_CSTR_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc";
const STRING_APPEND_CSTR_LEN_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm";
const STRING_APPEND_STRING_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendERKS5_";
const STRING_ERASE_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm";
const STRING_PUSH_BACK_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc";
const STRING_FIND_CHAR_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm";
const STRING_RFIND_CHAR_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm";
const STRING_COMPARE_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc";
const STRING_COMPARE_N_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm";
const STRING_SIZE_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv";
const STRING_LENGTH_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6lengthEv";
const STRING_EMPTY_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5emptyEv";
const STRING_DATA_CONST_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataEv";
const STRING_DATA_MUT_SYMBOL: &str =
    "ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataEv";
const STRING_C_STR_SYMBOL: &str =
    "ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CxxImportKind {
    LibcppNextPrime,
    CxaGuardAcquire,
    CxaGuardRelease,
    CxaGuardAbort,
    StringInitCstrLen,
    StringCopy,
    StringDtor,
    StringAssignCstr,
    StringAssignCstrLen,
    StringAppendCstr,
    StringAppendCstrLen,
    StringAppendString,
    StringErase,
    StringPushBack,
    StringFindChar,
    StringRfindChar,
    StringCompare,
    StringCompareN,
    StringSize,
    StringLength,
    StringEmpty,
    StringData,
    StringCStr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CxxDiagnostic {
    pub category: &'static str,
    pub strategy: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedString {
    bytes: Vec<u8>,
    layout: &'static str,
    data_ptr: Option<u64>,
}

pub(crate) fn classify_import(symbol: &str) -> Option<CxxImportKind> {
    let symbol = normalize_cxx_symbol(symbol);
    if is_libcpp_next_prime_symbol(symbol) {
        return Some(CxxImportKind::LibcppNextPrime);
    }
    if is_cxa_guard_symbol(symbol, "acquire") {
        return Some(CxxImportKind::CxaGuardAcquire);
    }
    if is_cxa_guard_symbol(symbol, "release") {
        return Some(CxxImportKind::CxaGuardRelease);
    }
    if is_cxa_guard_symbol(symbol, "abort") {
        return Some(CxxImportKind::CxaGuardAbort);
    }
    classify_libcpp_string_import(symbol)
}

pub(crate) fn diagnose_symbol(symbol: &str) -> Option<CxxDiagnostic> {
    let symbol = normalize_cxx_symbol(symbol);
    if classify_import(symbol).is_some() {
        return Some(CxxDiagnostic {
            category: "supported-cxx-compat",
            strategy: "handled by machina-compat C++ router",
        });
    }
    if is_libcpp_basic_string_symbol(symbol) {
        return Some(CxxDiagnostic {
            category: "libc++-basic-string-object-abi",
            strategy: "needs guest std::string object model; raw host proxy would dereference guest pointers",
        });
    }
    if is_libcpp_container_symbol(symbol) {
        return Some(CxxDiagnostic {
            category: "libc++-container-object-abi",
            strategy: "needs guest container object model or per-signature marshalling",
        });
    }
    if symbol.starts_with("cxa_") {
        return Some(CxxDiagnostic {
            category: "c++-runtime-abi",
            strategy: "needs libc++abi guest-state model or explicit scalar host bridge",
        });
    }
    if symbol.starts_with("ZNSt3__1")
        || symbol.starts_with("ZNKSt3__1")
        || symbol.starts_with("ZTVNSt3__1")
        || symbol.starts_with("ZTSNSt3__1")
        || symbol.starts_with("ZTINSt3__1")
    {
        return Some(CxxDiagnostic {
            category: "libc++-mangled-symbol",
            strategy: "needs signature classification before proxying",
        });
    }
    if looks_itanium_cxx_symbol(symbol) {
        return Some(CxxDiagnostic {
            category: "itanium-c++-mangled-symbol",
            strategy: "needs signature classification before proxying",
        });
    }
    None
}

pub(crate) fn proxy_import<M: GuestMemory + ?Sized>(
    kind: CxxImportKind,
    memory: &mut M,
    args: &[u64; 8],
) -> Option<HostCallResult> {
    match kind {
        CxxImportKind::StringInitCstrLen => {
            let bytes = read_capped_guest_bytes(memory, args[1], capped_len(args[2]))?;
            write_basic_string(memory, args[0], &bytes)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringCopy => {
            let source = decode_basic_string(memory, args[1])?;
            write_basic_string(memory, args[0], &source.bytes)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringDtor => {
            if let Some(decoded) = decode_basic_string(memory, args[0]) {
                if let Some(data_ptr) = decoded.data_ptr {
                    let _ = memory.free_memory(data_ptr);
                }
            }
            Some(call_value(args[0]))
        }
        CxxImportKind::StringAssignCstr => {
            let bytes = read_capped_cstring(memory, args[1], MAX_COMPAT_STRING_LEN)?;
            write_basic_string(memory, args[0], &bytes)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringAssignCstrLen => {
            let bytes = read_capped_guest_bytes(memory, args[1], capped_len(args[2]))?;
            write_basic_string(memory, args[0], &bytes)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringAppendCstr => {
            let suffix = read_capped_cstring(memory, args[1], MAX_COMPAT_STRING_LEN)?;
            append_basic_string(memory, args[0], &suffix)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringAppendCstrLen => {
            let suffix = read_capped_guest_bytes(memory, args[1], capped_len(args[2]))?;
            append_basic_string(memory, args[0], &suffix)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringAppendString => {
            let suffix = decode_basic_string(memory, args[1])?;
            append_basic_string(memory, args[0], &suffix.bytes)?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringErase => {
            erase_basic_string(memory, args[0], args[1], args[2])?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringPushBack => {
            append_basic_string(memory, args[0], &[args[1] as u8])?;
            Some(call_value(args[0]))
        }
        CxxImportKind::StringFindChar => {
            let string = decode_basic_string(memory, args[0])?;
            let index = find_char(&string.bytes, args[1] as u8, args[2], false);
            Some(call_value(index as u64))
        }
        CxxImportKind::StringRfindChar => {
            let string = decode_basic_string(memory, args[0])?;
            let index = find_char(&string.bytes, args[1] as u8, args[2], true);
            Some(call_value(index as u64))
        }
        CxxImportKind::StringCompare => {
            let string = decode_basic_string(memory, args[0])?;
            let right = read_capped_cstring(memory, args[3], MAX_COMPAT_STRING_LEN)?;
            let cmp = compare_substring(&string.bytes, args[1], args[2], &right);
            Some(call_i32(cmp))
        }
        CxxImportKind::StringCompareN => {
            let string = decode_basic_string(memory, args[0])?;
            let right = read_capped_guest_bytes(memory, args[3], capped_len(args[4]))?;
            let cmp = compare_substring(&string.bytes, args[1], args[2], &right);
            Some(call_i32(cmp))
        }
        CxxImportKind::StringSize | CxxImportKind::StringLength => {
            let string = decode_basic_string(memory, args[0])?;
            Some(call_value(string.bytes.len() as u64))
        }
        CxxImportKind::StringEmpty => {
            let string = decode_basic_string(memory, args[0])?;
            Some(call_value(u64::from(string.bytes.is_empty())))
        }
        CxxImportKind::StringData | CxxImportKind::StringCStr => {
            let string = decode_basic_string(memory, args[0])?;
            Some(call_value(string_data_pointer(args[0], &string)))
        }
        _ => None,
    }
}

fn classify_libcpp_string_import(symbol: &str) -> Option<CxxImportKind> {
    Some(match symbol {
        STRING_INIT_CSTR_LEN_SYMBOL => CxxImportKind::StringInitCstrLen,
        STRING_COPY_C1_SYMBOL | STRING_COPY_C2_SYMBOL => CxxImportKind::StringCopy,
        STRING_D1_SYMBOL | STRING_D2_SYMBOL => CxxImportKind::StringDtor,
        STRING_ASSIGN_CSTR_SYMBOL => CxxImportKind::StringAssignCstr,
        STRING_ASSIGN_CSTR_LEN_SYMBOL => CxxImportKind::StringAssignCstrLen,
        STRING_APPEND_CSTR_SYMBOL => CxxImportKind::StringAppendCstr,
        STRING_APPEND_CSTR_LEN_SYMBOL => CxxImportKind::StringAppendCstrLen,
        STRING_APPEND_STRING_SYMBOL => CxxImportKind::StringAppendString,
        STRING_ERASE_SYMBOL => CxxImportKind::StringErase,
        STRING_PUSH_BACK_SYMBOL => CxxImportKind::StringPushBack,
        STRING_FIND_CHAR_SYMBOL => CxxImportKind::StringFindChar,
        STRING_RFIND_CHAR_SYMBOL => CxxImportKind::StringRfindChar,
        STRING_COMPARE_SYMBOL => CxxImportKind::StringCompare,
        STRING_COMPARE_N_SYMBOL => CxxImportKind::StringCompareN,
        STRING_SIZE_SYMBOL => CxxImportKind::StringSize,
        STRING_LENGTH_SYMBOL => CxxImportKind::StringLength,
        STRING_EMPTY_SYMBOL => CxxImportKind::StringEmpty,
        STRING_DATA_CONST_SYMBOL | STRING_DATA_MUT_SYMBOL => CxxImportKind::StringData,
        STRING_C_STR_SYMBOL => CxxImportKind::StringCStr,
        _ => return None,
    })
}

fn normalize_cxx_symbol(symbol: &str) -> &str {
    let mut symbol = symbol.trim();
    while let Some(rest) = symbol.strip_prefix('_') {
        symbol = rest;
    }
    symbol
        .split_once('$')
        .map(|(base, _suffix)| base)
        .unwrap_or(symbol)
}

fn is_libcpp_next_prime_symbol(symbol: &str) -> bool {
    symbol == "next_prime"
        || symbol == "ZNSt3__112__next_primeEm"
        || symbol == "ZNSt3__112__next_primeEy"
        || symbol.contains("__next_prime")
}

fn is_cxa_guard_symbol(symbol: &str, suffix: &str) -> bool {
    symbol.strip_prefix("cxa_guard_") == Some(suffix)
}

fn is_libcpp_basic_string_symbol(symbol: &str) -> bool {
    symbol.contains("basic_string") || symbol.contains("12basic_string")
}

fn is_libcpp_container_symbol(symbol: &str) -> bool {
    [
        "3map",
        "3set",
        "4list",
        "5deque",
        "6vector",
        "8function",
        "9allocator",
        "10shared_ptr",
        "10unique_ptr",
        "12basic_string",
        "13unordered_map",
        "13unordered_set",
    ]
    .iter()
    .any(|fragment| symbol.contains(fragment))
}

fn looks_itanium_cxx_symbol(symbol: &str) -> bool {
    symbol.starts_with('Z') || symbol.starts_with("GLOBAL__")
}

fn decode_basic_string<M: GuestMemory + ?Sized>(
    memory: &mut M,
    this: u64,
) -> Option<DecodedString> {
    let header = memory.read_memory(this, LIBCPP_STRING_OBJECT_SIZE).ok()?;
    if header.len() < LIBCPP_STRING_OBJECT_SIZE {
        return None;
    }

    let word0 = read_u64(&header, 0);
    let word1 = read_u64(&header, 8);
    let word2 = read_u64(&header, 16);

    if (word2 & ALT_LONG_FLAG) != 0 {
        return decode_long_string(memory, word0, word1, "libc++-alternate-long");
    }

    let alt_short_len = (header[23] & 0x7f) as usize;
    let alt_short_is_long = (header[23] & 0x80) != 0;
    if is_alternate_short_string(&header, alt_short_len, alt_short_is_long) {
        return Some(DecodedString {
            bytes: header[0..alt_short_len].to_vec(),
            layout: "libc++-alternate-short",
            data_ptr: None,
        });
    }

    let default_short_tag = header[0];
    let default_short_len = (default_short_tag >> 1) as usize;
    if (default_short_tag & 1) == 0 && default_short_len <= LIBCPP_SHORT_MAX {
        return Some(DecodedString {
            bytes: header[1..1 + default_short_len].to_vec(),
            layout: "libc++-default-short",
            data_ptr: None,
        });
    }

    if (word0 & 1) != 0 {
        return decode_long_string(memory, word2, word1, "libc++-default-long");
    }

    Some(DecodedString {
        bytes: Vec::new(),
        layout: "unknown",
        data_ptr: None,
    })
}

fn is_alternate_short_string(header: &[u8], len: usize, is_long: bool) -> bool {
    if is_long || len > LIBCPP_SHORT_MAX {
        return false;
    }
    if len == 0 {
        return header.first().copied().unwrap_or(0) == 0;
    }
    header
        .get(len..LIBCPP_STRING_OBJECT_SIZE - 1)
        .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
}

fn decode_long_string<M: GuestMemory + ?Sized>(
    memory: &mut M,
    data_ptr: u64,
    len: u64,
    layout: &'static str,
) -> Option<DecodedString> {
    if len > MAX_COMPAT_STRING_LEN as u64 {
        return None;
    }
    let bytes = read_guest_bytes(memory, data_ptr, len as usize)?;
    Some(DecodedString {
        bytes,
        layout,
        data_ptr: Some(data_ptr),
    })
}

fn string_data_pointer(this: u64, string: &DecodedString) -> u64 {
    if let Some(data_ptr) = string.data_ptr {
        return data_ptr;
    }
    if string.layout == "libc++-default-short" {
        return this.saturating_add(1);
    }
    this
}

fn write_basic_string<M: GuestMemory + ?Sized>(
    memory: &mut M,
    this: u64,
    bytes: &[u8],
) -> Option<()> {
    let bytes = capped_bytes(bytes);
    let mut object = [0u8; LIBCPP_STRING_OBJECT_SIZE];
    if bytes.len() <= LIBCPP_SHORT_MAX {
        object[0..bytes.len()].copy_from_slice(bytes);
        object[23] = bytes.len() as u8;
        memory.write_memory(this, &object).ok()?;
        return Some(());
    }

    let alloc_len = align_up(bytes.len().saturating_add(1), 16);
    let data_ptr = memory.allocate_memory(alloc_len, 16).ok()?;
    let mut storage = Vec::with_capacity(alloc_len);
    storage.extend_from_slice(bytes);
    storage.push(0);
    storage.resize(alloc_len, 0);
    memory.write_memory(data_ptr, &storage).ok()?;

    object[0..8].copy_from_slice(&data_ptr.to_le_bytes());
    object[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    object[16..24].copy_from_slice(&((alloc_len as u64) | ALT_LONG_FLAG).to_le_bytes());
    memory.write_memory(this, &object).ok()?;
    Some(())
}

fn append_basic_string<M: GuestMemory + ?Sized>(
    memory: &mut M,
    this: u64,
    suffix: &[u8],
) -> Option<()> {
    let mut string = decode_basic_string(memory, this)?.bytes;
    let available = MAX_COMPAT_STRING_LEN.saturating_sub(string.len());
    string.extend_from_slice(&suffix[..suffix.len().min(available)]);
    write_basic_string(memory, this, &string)
}

fn erase_basic_string<M: GuestMemory + ?Sized>(
    memory: &mut M,
    this: u64,
    pos: u64,
    len: u64,
) -> Option<()> {
    let mut string = decode_basic_string(memory, this)?.bytes;
    let pos = capped_len(pos).min(string.len());
    let requested = capped_len(len);
    let end = if requested == NPOS {
        string.len()
    } else {
        pos.saturating_add(requested).min(string.len())
    };
    string.drain(pos..end);
    write_basic_string(memory, this, &string)
}

fn read_capped_cstring<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    max_len: usize,
) -> Option<Vec<u8>> {
    if ptr < 0x1000 {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for idx in 0..max_len.min(MAX_COMPAT_STRING_LEN) {
        let byte = memory.read_memory(ptr + idx as u64, 1).ok()?;
        let byte = *byte.first()?;
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    Some(out)
}

fn read_capped_guest_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    len: usize,
) -> Option<Vec<u8>> {
    if ptr < 0x1000 {
        return Some(Vec::new());
    }
    read_guest_bytes(memory, ptr, len.min(MAX_COMPAT_STRING_LEN))
}

fn read_guest_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    len: usize,
) -> Option<Vec<u8>> {
    if ptr < 0x1000 || len > MAX_COMPAT_STRING_LEN {
        return None;
    }
    if len == 0 {
        return Some(Vec::new());
    }
    memory.read_memory(ptr, len).ok()
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return value;
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .unwrap_or(value)
}

fn capped_len(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn capped_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_COMPAT_STRING_LEN)]
}

fn find_char(bytes: &[u8], needle: u8, pos: u64, reverse: bool) -> usize {
    if bytes.is_empty() {
        return NPOS;
    }
    let pos = capped_len(pos);
    if reverse {
        let start = pos.min(bytes.len() - 1);
        return bytes[..=start]
            .iter()
            .rposition(|byte| *byte == needle)
            .unwrap_or(NPOS);
    }
    if pos >= bytes.len() {
        return NPOS;
    }
    bytes[pos..]
        .iter()
        .position(|byte| *byte == needle)
        .map(|index| index + pos)
        .unwrap_or(NPOS)
}

fn compare_substring(left: &[u8], pos: u64, len: u64, right: &[u8]) -> i32 {
    let pos = capped_len(pos).min(left.len());
    let requested = capped_len(len);
    let end = if requested == NPOS {
        left.len()
    } else {
        pos.saturating_add(requested).min(left.len())
    };
    compare_bytes(&left[pos..end], right)
}

fn compare_bytes(left: &[u8], right: &[u8]) -> i32 {
    let len = left.len().min(right.len());
    for index in 0..len {
        if left[index] != right[index] {
            return left[index] as i32 - right[index] as i32;
        }
    }
    match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

fn call_value(value: u64) -> HostCallResult {
    HostCallResult {
        return_value: value,
        errno: None,
    }
}

fn call_i32(value: i32) -> HostCallResult {
    HostCallResult {
        return_value: value as i64 as u64,
        errno: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestMemory, GuestMemoryError};
    use std::collections::BTreeMap;

    #[derive(Debug)]
    struct TestMemory {
        bytes: BTreeMap<u64, u8>,
        next_alloc: u64,
    }

    impl Default for TestMemory {
        fn default() -> Self {
            Self {
                bytes: BTreeMap::new(),
                next_alloc: 0x10_000,
            }
        }
    }

    impl TestMemory {
        fn write_at(&mut self, addr: u64, data: &[u8]) {
            self.write_memory(addr, data).expect("write should succeed");
        }
    }

    impl GuestMemory for TestMemory {
        fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
            Ok((0..size)
                .map(|offset| {
                    self.bytes
                        .get(&(addr + offset as u64))
                        .copied()
                        .unwrap_or(0)
                })
                .collect())
        }

        fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
            for (offset, byte) in data.iter().enumerate() {
                self.bytes.insert(addr + offset as u64, *byte);
            }
            Ok(())
        }

        fn allocate_memory(
            &mut self,
            size: usize,
            alignment: usize,
        ) -> Result<u64, GuestMemoryError> {
            let addr = align_up(self.next_alloc as usize, alignment) as u64;
            self.next_alloc = addr + size as u64;
            Ok(addr)
        }
    }

    fn args(values: &[u64]) -> [u64; 8] {
        let mut args = [0u64; 8];
        args[..values.len()].copy_from_slice(values);
        args
    }

    #[test]
    fn classifier_covers_supported_cxx_runtime_glue() {
        assert_eq!(
            classify_import("___cxa_guard_acquire"),
            Some(CxxImportKind::CxaGuardAcquire)
        );
        assert_eq!(
            classify_import("__cxa_guard_release"),
            Some(CxxImportKind::CxaGuardRelease)
        );
        assert_eq!(
            classify_import("__ZNSt3__112__next_primeEm"),
            Some(CxxImportKind::LibcppNextPrime)
        );
    }

    #[test]
    fn classifier_covers_basic_libcpp_string_imports() {
        assert_eq!(
            classify_import(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc"
            ),
            Some(CxxImportKind::StringAppendCstr)
        );
        assert_eq!(
            classify_import(
                "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm"
            ),
            Some(CxxImportKind::StringFindChar)
        );
        assert_eq!(
            classify_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm"
            ),
            Some(CxxImportKind::StringCompareN)
        );
        assert_eq!(
            classify_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv"
            ),
            Some(CxxImportKind::StringSize)
        );
        assert_eq!(
            classify_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataEv"
            ),
            Some(CxxImportKind::StringData)
        );
        assert_eq!(
            classify_import(
                "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv"
            ),
            Some(CxxImportKind::StringCStr)
        );
    }

    #[test]
    fn diagnostics_classify_unhandled_object_abi_symbols() {
        let diagnostic = diagnose_symbol(
            "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE8capacityEv",
        )
        .expect("libc++ string symbol should be diagnosed");
        assert_eq!(diagnostic.category, "libc++-basic-string-object-abi");
        assert!(diagnostic
            .strategy
            .contains("guest std::string object model"));

        let diagnostic =
            diagnose_symbol("__ZNSt3__113unordered_mapINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEiE4findERKS5_")
                .expect("libc++ container symbol should be diagnosed");
        assert_eq!(diagnostic.category, "libc++-basic-string-object-abi");
    }

    #[test]
    fn proxies_basic_libcpp_string_operations() {
        let mut memory = TestMemory::default();
        let object = 0x3000;
        memory.write_at(0x2000, b"hello\0");
        memory.write_at(0x2020, b" world\0");
        memory.write_at(0x2040, b"world\0");
        memory.write_at(0x2060, b"jello\0");

        let result = proxy_import(
            CxxImportKind::StringInitCstrLen,
            &mut memory,
            &args(&[object, 0x2000, 5]),
        )
        .expect("string init should be proxied");
        assert_eq!(result.return_value, object);
        assert_eq!(
            decode_basic_string(&mut memory, object).unwrap().bytes,
            b"hello"
        );

        proxy_import(
            CxxImportKind::StringAppendCstrLen,
            &mut memory,
            &args(&[object, 0x2020, 6]),
        )
        .expect("string append should be proxied");
        proxy_import(
            CxxImportKind::StringPushBack,
            &mut memory,
            &args(&[object, b'!' as u64]),
        )
        .expect("string push_back should be proxied");
        assert_eq!(
            decode_basic_string(&mut memory, object).unwrap().bytes,
            b"hello world!"
        );

        let size = proxy_import(CxxImportKind::StringSize, &mut memory, &args(&[object]))
            .expect("string size should be proxied");
        assert_eq!(size.return_value, 12);
        let length = proxy_import(CxxImportKind::StringLength, &mut memory, &args(&[object]))
            .expect("string length should be proxied");
        assert_eq!(length.return_value, 12);
        let empty = proxy_import(CxxImportKind::StringEmpty, &mut memory, &args(&[object]))
            .expect("string empty should be proxied");
        assert_eq!(empty.return_value, 0);
        let data = proxy_import(CxxImportKind::StringData, &mut memory, &args(&[object]))
            .expect("string data should be proxied");
        assert_eq!(data.return_value, object);
        assert_eq!(
            memory.read_memory(data.return_value, 12).unwrap(),
            b"hello world!"
        );
        let c_str = proxy_import(CxxImportKind::StringCStr, &mut memory, &args(&[object]))
            .expect("string c_str should be proxied");
        assert_eq!(c_str.return_value, object);

        let find = proxy_import(
            CxxImportKind::StringFindChar,
            &mut memory,
            &args(&[object, b'w' as u64, 0]),
        )
        .expect("string find should be proxied");
        assert_eq!(find.return_value, 6);

        let rfind = proxy_import(
            CxxImportKind::StringRfindChar,
            &mut memory,
            &args(&[object, b'l' as u64, u64::MAX]),
        )
        .expect("string rfind should be proxied");
        assert_eq!(rfind.return_value, 9);

        let compare = proxy_import(
            CxxImportKind::StringCompare,
            &mut memory,
            &args(&[object, 6, 5, 0x2040]),
        )
        .expect("string compare should be proxied");
        assert_eq!(compare.return_value, 0);

        let compare = proxy_import(
            CxxImportKind::StringCompare,
            &mut memory,
            &args(&[object, 0, 5, 0x2060]),
        )
        .expect("string compare should be proxied");
        assert_ne!(compare.return_value, 0);

        proxy_import(
            CxxImportKind::StringErase,
            &mut memory,
            &args(&[object, 5, 1]),
        )
        .expect("string erase should be proxied");
        assert_eq!(
            decode_basic_string(&mut memory, object).unwrap().bytes,
            b"helloworld!"
        );

        let copy = 0x3040;
        proxy_import(
            CxxImportKind::StringCopy,
            &mut memory,
            &args(&[copy, object]),
        )
        .expect("string copy should be proxied");
        assert_eq!(
            decode_basic_string(&mut memory, copy).unwrap().bytes,
            b"helloworld!"
        );

        let empty_object = 0x3080;
        proxy_import(
            CxxImportKind::StringInitCstrLen,
            &mut memory,
            &args(&[empty_object, 0x2000, 0]),
        )
        .expect("empty string init should be proxied");
        let empty = proxy_import(
            CxxImportKind::StringEmpty,
            &mut memory,
            &args(&[empty_object]),
        )
        .expect("empty string check should be proxied");
        assert_eq!(empty.return_value, 1);
    }

    #[test]
    fn decodes_alternate_short_strings_starting_with_odd_ascii_bytes() {
        let mut memory = TestMemory::default();
        let object = 0x3000;
        memory.write_at(0x2000, b"glue\0");
        memory.write_at(0x2020, b"-cxx\0");

        proxy_import(
            CxxImportKind::StringInitCstrLen,
            &mut memory,
            &args(&[object, 0x2000, 4]),
        )
        .expect("string init should be proxied");
        proxy_import(
            CxxImportKind::StringAppendCstrLen,
            &mut memory,
            &args(&[object, 0x2020, 4]),
        )
        .expect("string append should be proxied");
        proxy_import(
            CxxImportKind::StringPushBack,
            &mut memory,
            &args(&[object, b'!' as u64]),
        )
        .expect("string push_back should be proxied");

        let decoded = decode_basic_string(&mut memory, object).expect("string should decode");
        assert_eq!(decoded.bytes, b"glue-cxx!");
        assert_eq!(decoded.layout, "libc++-alternate-short");
    }

    #[test]
    fn writes_and_decodes_alternate_long_strings() {
        let mut memory = TestMemory::default();
        let object = 0x3000;
        let text = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDE";
        memory.write_at(0x5000, text);

        proxy_import(
            CxxImportKind::StringInitCstrLen,
            &mut memory,
            &args(&[object, 0x5000, text.len() as u64]),
        )
        .expect("long string init should be proxied");

        let decoded = decode_basic_string(&mut memory, object).expect("string should decode");
        assert_eq!(decoded.bytes, text);
        assert_eq!(decoded.layout, "libc++-alternate-long");
        assert!(decoded.data_ptr.unwrap_or(0) >= 0x10_000);

        let data = proxy_import(CxxImportKind::StringCStr, &mut memory, &args(&[object]))
            .expect("long string c_str should be proxied");
        assert_eq!(
            memory.read_memory(data.return_value, text.len()).unwrap(),
            text
        );
    }
}
