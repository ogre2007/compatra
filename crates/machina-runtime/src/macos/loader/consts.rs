//! Mach-O binary format constants
//!
//! Contains constants from Apple's Mach-O format specification:
//! https://opensource.apple.com/source/cctools/cctools-795/include/mach-o/loader.h

pub type CpuType = u32;

/// Mach-O magic numbers
pub mod magic {
    /// 32-bit Mach-O little endian
    pub const MH_MAGIC_32: u32 = 0xFEEDFACE;
    /// 32-bit Mach-O big endian
    pub const MH_CIGAM_32: u32 = 0xCEFAEDFE;
    /// 64-bit Mach-O little endian
    pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
    /// 64-bit Mach-O big endian
    pub const MH_CIGAM_64: u32 = 0xCFFAEDFE;
    /// FAT binary little endian
    pub const FAT_MAGIC: u32 = 0xBEBAFECA;
    /// FAT binary big endian
    pub const FAT_CIGAM: u32 = 0xCAFEBABE;
}

/// CPU types
pub mod cpu_type {
    use super::CpuType;

    pub const CPU_TYPE_X86: CpuType = 0x0000_0007;
    pub const CPU_TYPE_X86_64: CpuType = 0x0100_0007;
    pub const CPU_TYPE_ARM: CpuType = 0x0000_000C;
    pub const CPU_TYPE_ARM64: CpuType = 0x0100_000C;

    pub const CPU_SUBTYPE_X86_64_ALL: u32 = 0x0000_0030;
    pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0x0000_0006;
    pub const CPU_SUBTYPE_I386_ALL: u32 = 0x0000_0030;
}

/// File types
pub mod file_type {
    pub const MH_EXECUTE: u32 = 0x0000_0002;
    pub const MH_DYLIB: u32 = 0x0000_0006;
    pub const MH_DYLINKER: u32 = 0x0000_0007;
    pub const MH_BUNDLE: u32 = 0x0000_0008;
    pub const MH_KEXT_BUNDLE: u32 = 0x0000_000B;
    pub const MH_FVMLIB: u32 = 0x0000_0001;
    pub const MH_PRELOAD: u32 = 0x0000_0005;
}

/// Load command IDs
pub mod load_command {
    pub const LC_SEGMENT: u32 = 0x0000_0001;
    pub const LC_SYMTAB: u32 = 0x0000_0002;
    pub const LC_SYMSEG: u32 = 0x0000_0003;
    pub const LC_THREAD: u32 = 0x0000_0004;
    pub const LC_UNIXTHREAD: u32 = 0x0000_0005;
    pub const LC_LOADFVMLIB: u32 = 0x0000_0006;
    pub const LC_IDFVMLIB: u32 = 0x0000_0007;
    pub const LC_IDENT: u32 = 0x0000_0008;
    pub const LC_FVMFILE: u32 = 0x0000_0009;
    pub const LC_PREPAGE: u32 = 0x0000_000A;
    pub const LC_DYSYMTAB: u32 = 0x0000_000B;
    pub const LC_LOAD_DYLIB: u32 = 0x0000_000C;
    pub const LC_ID_DYLIB: u32 = 0x0000_000D;
    pub const LC_LOAD_DYLINKER: u32 = 0x0000_000E;
    pub const LC_ID_DYLINKER: u32 = 0x0000_000F;
    pub const LC_PREBOUND_DYLIB: u32 = 0x0000_0010;
    pub const LC_ROUTINES: u32 = 0x0000_0011;
    pub const LC_SUB_FRAMEWORK: u32 = 0x0000_0012;
    pub const LC_SUB_UMBRELLA: u32 = 0x0000_0013;
    pub const LC_SUB_CLIENT: u32 = 0x0000_0014;
    pub const LC_SUB_LIBRARY: u32 = 0x0000_0015;
    pub const LC_TWOLEVEL_HINTS: u32 = 0x0000_0016;
    pub const LC_PREBIND_CKSUM: u32 = 0x0000_0017;
    pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    pub const LC_SEGMENT_64: u32 = 0x0000_0019;
    pub const LC_ROUTINES_64: u32 = 0x0000_001A;
    pub const LC_UUID: u32 = 0x0000_001B;
    pub const LC_RPATH: u32 = 0x8000_001C;
    pub const LC_CODE_SIGNATURE: u32 = 0x0000_001D;
    pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x0000_001E;
    pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
    pub const LC_LAZY_LOAD_DYLIB: u32 = 0x0000_0020;
    pub const LC_ENCRYPTION_INFO: u32 = 0x0000_0021;
    pub const LC_COMPRESSED_DYLIB_ID: u32 = 0x0000_0022;
    pub const LC_VERSION_MIN_MACOSX: u32 = 0x0000_0024;
    pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x0000_0025;
    pub const LC_FUNCTION_STARTS: u32 = 0x0000_0026;
    pub const LC_DATA_IN_CODE: u32 = 0x0000_0029;
    pub const LC_SOURCE_VERSION: u32 = 0x0000_002A;
    pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
    pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x0000_002B;
    pub const LC_ENCRYPTION_INFO_64: u32 = 0x0000_002C;
    pub const LC_LINKER_OPTION: u32 = 0x0000_002D;
    pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x0000_002E;
    pub const LC_VERSION_MIN_TVOS: u32 = 0x0000_002F;
    pub const LC_VERSION_MIN_WATCHOS: u32 = 0x0000_0030;
    pub const LC_NOTE: u32 = 0x0000_0031;
    pub const LC_BUILD_VERSION: u32 = 0x0000_0032;
    pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
    pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    pub const LC_FILESET_ID: u32 = 0x0000_0035;
    pub const LC_MAIN: u32 = 0x8000_0028;
}

/// Thread flavors
pub mod thread_flavor {
    pub const X86_THREAD_STATE32: u32 = 0x0000_0001;
    pub const X86_THREAD_STATE64: u32 = 0x0000_0004;
    pub const X86_FLOAT_STATE32: u32 = 0x0000_0002;
    pub const X86_FLOAT_STATE64: u32 = 0x0000_0005;
    pub const X86_EXCEPTION_STATE32: u32 = 0x0000_0003;
    pub const X86_EXCEPTION_STATE64: u32 = 0x0000_0006;
    pub const ARM_THREAD_STATE32: u32 = 0x0000_0001;
    pub const ARM_THREAD_STATE64: u32 = 0x0000_0006;
    pub const ARM_FLOAT_STATE32: u32 = 0x0000_0002;
    pub const ARM_FLOAT_STATE64: u32 = 0x0000_0007;
    pub const ARM_EXCEPTION_STATE64: u32 = 0x0000_0008;
    pub const ARM_THREAD_STATE: u32 = 0x0000_0003;
}

/// Chained-fixups (LC_DYLD_CHAINED_FIXUPS) layout constants.
///
/// Layout of the blob pointed at by LC_DYLD_CHAINED_FIXUPS's
/// linkedit_data_command:
///
/// ```c
/// struct dyld_chained_fixups_header {
///     uint32_t fixups_version;   // 0
///     uint32_t starts_offset;    // offset of dyld_chained_starts_in_image
///     uint32_t imports_offset;   // offset to imports table
///     uint32_t symbols_offset;   // offset to symbol strings
///     uint32_t imports_count;
///     uint32_t imports_format;   // DYLD_CHAINED_IMPORT_* values below
///     uint32_t symbols_format;   // 0 = uncompressed
/// };
/// ```
pub mod dyld_chained_fixups {
    pub const DYLD_CHAINED_IMPORT: u32 = 1;
    pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
    pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

    pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
    pub const DYLD_CHAINED_PTR_64: u16 = 2;
    pub const DYLD_CHAINED_PTR_32: u16 = 3;
    pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
    pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
    pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
    pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
    pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
    pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
    pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
    pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
    pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

    pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
    pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
    pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;
}

/// VM protection constants
pub mod vm_protection {
    pub const VM_PROT_READ: i32 = 0x01;
    pub const VM_PROT_WRITE: i32 = 0x02;
    pub const VM_PROT_EXECUTE: i32 = 0x04;

    pub const VM_PROT_DEFAULT: i32 = VM_PROT_READ | VM_PROT_WRITE;
    pub const VM_PROT_ALL: i32 = 0x07;
    pub const VM_PROT_NO_CHANGE: i32 = 0x08;
    pub const VM_PROT_COPY: i32 = 0x10;
}

/// Segment flags
pub mod segment_flags {
    pub const SG_NONE: u32 = 0x00;
    pub const SG_HIGHVM: u32 = 0x01;
    pub const SG_FVMLIB: u32 = 0x02;
    pub const SG_NORELOC: u32 = 0x04;
    pub const SG_PROTECTED_VERSION_1: u32 = 0x08;
}

/// Section flags
pub mod section_flags {
    pub const SECTION_TYPE: u32 = 0x0000_00FF;
    pub const S_REGULAR: u32 = 0x00;
    pub const S_ZEROFILL: u32 = 0x01;
    pub const S_CSTRING_LITERALS: u32 = 0x02;
    pub const S_4BYTE_LITERALS: u32 = 0x03;
    pub const S_8BYTE_LITERALS: u32 = 0x04;
    pub const S_LITERAL_POINTERS: u32 = 0x05;
    pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x06;
    pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x07;
    pub const S_SYMBOL_STUBS: u32 = 0x08;
    pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x09;
    pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0x0A;
    pub const S_COALESCED: u32 = 0x0B;
    pub const S_GB_ZEROFILL: u32 = 0x0C;
    pub const S_INTERPOSING: u32 = 0x0D;
    pub const S_16BYTE_LITERALS: u32 = 0x0E;
    pub const S_DTRACE_DOF: u32 = 0x0F;
    pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
    pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
    pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
    pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
    pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
    pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
    pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;
    pub const S_MODULE_INIT_FUNC_OFFSETS: u32 = 0x17;
}

/// Relocation types for x86_64
pub mod relocation {
    pub const X86_64_RELOC_UNSIGNED: u8 = 0;
    pub const X86_64_RELOC_SIGNED: u8 = 1;
    pub const X86_64_RELOC_BRANCH: u8 = 2;
    pub const X86_64_RELOC_GOT_LOAD: u8 = 3;
    pub const X86_64_RELOC_GOT: u8 = 4;
    pub const X86_64_RELOC_SUBTRACTOR: u8 = 5;
    pub const X86_64_RELOC_SIGNED_1: u8 = 6;
    pub const X86_64_RELOC_SIGNED_2: u8 = 7;
    pub const X86_64_RELOC_SIGNED_4: u8 = 8;
    pub const X86_64_RELOC_TLV: u8 = 9;
}

/// Relocation types for ARM64
pub mod relocation_arm64 {
    pub const ARM64_RELOC_UNSIGNED: u8 = 0;
    pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
    pub const ARM64_RELOC_BRANCH26: u8 = 2;
    pub const ARM64_RELOC_PAGE21: u8 = 3;
    pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
    pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
    pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
    pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
    pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
    pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
    pub const ARM64_RELOC_ADDEND: u8 = 10;
}
