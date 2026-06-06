pub const LIBCPP_STRING_OBJECT_SIZE: usize = 24;
pub const LIBCPP_SHORT_MAX: usize = 22;
pub const MAX_SYNTHETIC_STRING_LEN: usize = 0x10_000;
pub const ALT_LONG_FLAG: u64 = 1u64 << 63;
pub const NPOS: usize = usize::MAX;

/// Size of the fake C++ data region carved out of the guest mmap arena.
pub const ARM64_CPP_DATA_REGION_SIZE: u64 = 0x2000;
pub const ARM64_CPP_VTABLE_STORAGE_OFFSET: u64 = 0x100;
pub const ARM64_CPP_VTT_OFFSET: u64 = 0x300;
pub const ARM64_CPP_CERR_OBJECT_OFFSET: u64 = 0x400;
pub const ARM64_CPP_CIN_OBJECT_OFFSET: u64 = 0x500;
pub const ARM64_CPP_CTYPE_ID_OFFSET: u64 = 0x600;

pub const CERR_SYMBOL: &str = "__ZNSt3__14cerrE";
pub const CIN_SYMBOL: &str = "__ZNSt3__14cinE";
pub const WCERR_SYMBOL: &str = "__ZNSt3__15wcerrE";
pub const WCIN_SYMBOL: &str = "__ZNSt3__15wcinE";
pub const CTYPE_ID_SYMBOL: &str = "__ZNSt3__15ctypeIcE2idE";

pub const LIBCPP_VTABLE_SYMBOLS: &[&str] = &[
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

pub const LIBCPP_VTT_SYMBOLS: &[&str] = &[
    "__ZTTNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE",
    "__ZTTNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE",
    "__ZTTNSt3__119basic_istringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    "__ZTTNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
];

pub const SENTRY_C1_SYMBOL: &str = "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
pub const ISTREAM_SENTRY_C1_SYMBOL: &str =
    "__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b";
pub const OSTREAM_WRITE_SYMBOL: &str =
    "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5writeEPKcl";

pub const STRING_INIT_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm";
pub const STRING_COPY_C1_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_";
pub const STRING_COPY_C2_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_";
pub const STRING_D1_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev";
pub const STRING_D2_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev";
pub const STRING_ASSIGN_CSTR_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc";
pub const STRING_ASSIGN_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKcm";
pub const STRING_APPEND_CSTR_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc";
pub const STRING_APPEND_CSTR_LEN_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm";
pub const STRING_APPEND_STRING_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendERKS5_";
pub const STRING_ERASE_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm";
pub const STRING_PUSH_BACK_SYMBOL: &str =
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc";
pub const STRING_FIND_CHAR_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm";
pub const STRING_RFIND_CHAR_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm";
pub const TO_STRING_U32_SYMBOL: &str = "__ZNSt3__19to_stringEj";
pub const STRING_PLUS_CSTR_STRING_SYMBOL: &str =
    "__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_";
pub const STRING_PLUS_STRING_CSTR_SYMBOL: &str =
    "__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EERKS9_PKS6_";
pub const STRING_COMPARE_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc";
pub const STRING_COMPARE_N_SYMBOL: &str =
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedLibcppString {
    pub bytes: Vec<u8>,
    pub layout: &'static str,
    pub raw_header: String,
}

pub fn text_preview(bytes: &[u8], max_len: usize) -> String {
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

pub fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn read_capped_guest_bytes<F>(ptr: u64, len: usize, mut read_memory: F) -> Vec<u8>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    read_guest_bytes(ptr, len.min(MAX_SYNTHETIC_STRING_LEN), &mut read_memory).unwrap_or_default()
}

pub fn read_capped_cstring<F>(ptr: u64, max_len: usize, mut read_memory: F) -> Vec<u8>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    if ptr < 0x1000 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for idx in 0..max_len.min(MAX_SYNTHETIC_STRING_LEN) {
        let Some(bytes) = read_memory(ptr + idx as u64, 1) else {
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

pub fn decode_basic_string<F>(this: u64, mut read_memory: F) -> DecodedLibcppString
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    let header = read_memory(this, LIBCPP_STRING_OBJECT_SIZE)
        .unwrap_or_else(|| vec![0u8; LIBCPP_STRING_OBJECT_SIZE]);
    let raw_header = hex_preview(&header, LIBCPP_STRING_OBJECT_SIZE);

    let word0 = read_u64(&header, 0..8);
    let word1 = read_u64(&header, 8..16);
    let word2 = read_u64(&header, 16..24);

    // Apple arm64 libc++ uses the alternate layout: long strings store
    // {data, size, capacity|long-bit}, short strings store bytes at +0 and
    // size in the low seven bits of byte 23. Decode it first because Compatra
    // targets macOS arm64.
    if (word2 & ALT_LONG_FLAG) != 0 {
        if let Some(decoded) = decode_long_string(
            word0,
            word1,
            "libc++-alternate-long",
            &raw_header,
            &mut read_memory,
        ) {
            return decoded;
        }
    }

    // Non-alternate libc++ layout: long strings store
    // {capacity|long-bit, size, data}.
    if (word0 & 1) != 0 {
        if let Some(decoded) = decode_long_string(
            word2,
            word1,
            "libc++-default-long",
            &raw_header,
            &mut read_memory,
        ) {
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
        return DecodedLibcppString {
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
        return DecodedLibcppString {
            bytes,
            layout: "libc++-default-short",
            raw_header,
        };
    }

    DecodedLibcppString {
        bytes: Vec::new(),
        layout: "unknown",
        raw_header,
    }
}

fn decode_long_string<F>(
    data_ptr: u64,
    len: u64,
    layout: &'static str,
    raw_header: &str,
    read_memory: &mut F,
) -> Option<DecodedLibcppString>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    if len > MAX_SYNTHETIC_STRING_LEN as u64 {
        return None;
    }
    let bytes = read_guest_bytes(data_ptr, len as usize, read_memory)?;
    Some(DecodedLibcppString {
        bytes,
        layout,
        raw_header: raw_header.to_string(),
    })
}

fn read_guest_bytes<F>(ptr: u64, len: usize, read_memory: &mut F) -> Option<Vec<u8>>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    if ptr < 0x1000 || len > MAX_SYNTHETIC_STRING_LEN {
        return None;
    }
    if len == 0 {
        return Some(Vec::new());
    }
    read_memory(ptr, len)
}

fn read_u64(bytes: &[u8], range: std::ops::Range<usize>) -> u64 {
    bytes
        .get(range)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_match_cpp_trace_style() {
        assert_eq!(text_preview(b"a\n\t\xff", 8), "a\u{240A}\u{2409}.");
        assert_eq!(hex_preview(&[0, 0xab, 0xff], 8), "00abff");
    }

    #[test]
    fn capped_cstring_stops_at_nul_and_low_pointer() {
        let bytes = *b"hello\0ignored";
        let read = |addr: u64, size: usize| {
            let offset = addr.checked_sub(0x1000)? as usize;
            Some(bytes.get(offset..offset + size)?.to_vec())
        };

        assert_eq!(read_capped_cstring(0x1000, 32, read), b"hello");
        assert!(read_capped_cstring(0xfff, 32, |_addr, _size| Some(vec![b'x'])).is_empty());
    }

    #[test]
    fn decodes_alternate_short_string() {
        let mut object = [0u8; LIBCPP_STRING_OBJECT_SIZE];
        object[0..5].copy_from_slice(b"hello");
        object[23] = 5;

        let decoded = decode_basic_string(0x2000, |addr, size| {
            (addr == 0x2000 && size == LIBCPP_STRING_OBJECT_SIZE).then(|| object.to_vec())
        });

        assert_eq!(decoded.bytes, b"hello");
        assert_eq!(decoded.layout, "libc++-alternate-short");
    }

    #[test]
    fn decodes_alternate_long_string() {
        let mut object = [0u8; LIBCPP_STRING_OBJECT_SIZE];
        object[0..8].copy_from_slice(&0x3000u64.to_le_bytes());
        object[8..16].copy_from_slice(&11u64.to_le_bytes());
        object[16..24].copy_from_slice(&(0x20 | ALT_LONG_FLAG).to_le_bytes());

        let decoded = decode_basic_string(0x2000, |addr, size| match (addr, size) {
            (0x2000, LIBCPP_STRING_OBJECT_SIZE) => Some(object.to_vec()),
            (0x3000, 11) => Some(b"hello world".to_vec()),
            _ => None,
        });

        assert_eq!(decoded.bytes, b"hello world");
        assert_eq!(decoded.layout, "libc++-alternate-long");
    }
}
