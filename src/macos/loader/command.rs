//! Mach-O load command structures

use std::io::{Cursor, Read};

use crate::macos::loader::consts::*;
use crate::macos::MacOsError;

/// Represents a load command in a Mach-O binary
#[derive(Debug, Clone)]
pub enum LoadCommand {
    Segment64(SegmentCommand64),
    Segment(SegmentCommand32),
    Symtab(SymtabCommand),
    Dysymtab(DysymtabCommand),
    Dylinker(DylinkerCommand),
    IdDylinker(IdDylinkerCommand),
    Uuid(UuidCommand),
    Unixthread(UnixThreadCommand),
    Main(MainCommand),
    Dylib(DylibCommand),
    Rpath(RpathCommand),
    CodeSignature(CodeSignatureCommand),
    VersionMinMacosx(VersionMinCommand),
    VersionMinIphoneos(VersionMinCommand),
    SourceVersion(SourceVersionCommand),
    SegmentSplitInfo(SegmentSplitInfoCommand),
    FunctionStarts(FunctionStartsCommand),
    DataInCode(DataInCodeCommand),
    DyldInfoOnly(DyldInfoOnlyCommand),
    Unknown {
        cmd_id: u32,
        cmd_size: u32,
        data: Vec<u8>,
    },
}

impl LoadCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<(Self, usize), MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "Load command too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let mut bytes = [0u8; 4];

        cursor.read_exact(&mut bytes)?;
        let cmd = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let cmdsize_raw = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        if cmdsize_raw < 8 || cmdsize_raw > 65536 {
            return Err(MacOsError::LoaderError(format!(
                "Invalid cmdsize {} (0x{:X})",
                cmdsize_raw, cmdsize_raw
            )));
        }

        let cmdsize = cmdsize_raw as usize;

        let cmd_data = &data[8..];

        let load_cmd = match cmd {
            load_command::LC_SEGMENT_64 => {
                LoadCommand::Segment64(SegmentCommand64::parse(cmd_data, big_endian)?)
            }
            load_command::LC_SEGMENT => {
                LoadCommand::Segment(SegmentCommand32::parse(cmd_data, big_endian)?)
            }
            load_command::LC_SYMTAB => {
                LoadCommand::Symtab(SymtabCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_DYSYMTAB => {
                LoadCommand::Dysymtab(DysymtabCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_LOAD_DYLINKER => {
                LoadCommand::Dylinker(DylinkerCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_ID_DYLINKER => {
                LoadCommand::IdDylinker(IdDylinkerCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_UUID => LoadCommand::Uuid(UuidCommand::parse(cmd_data)?),
            load_command::LC_UNIXTHREAD => {
                LoadCommand::Unixthread(UnixThreadCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_MAIN => LoadCommand::Main(MainCommand::parse(cmd_data, big_endian)?),
            load_command::LC_LOAD_DYLIB | load_command::LC_LOAD_WEAK_DYLIB => {
                LoadCommand::Dylib(DylibCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_RPATH => {
                LoadCommand::Rpath(RpathCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_CODE_SIGNATURE => {
                LoadCommand::CodeSignature(CodeSignatureCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_VERSION_MIN_MACOSX => {
                LoadCommand::VersionMinMacosx(VersionMinCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_VERSION_MIN_IPHONEOS => {
                LoadCommand::VersionMinIphoneos(VersionMinCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_SOURCE_VERSION => {
                LoadCommand::SourceVersion(SourceVersionCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_SEGMENT_SPLIT_INFO => {
                LoadCommand::SegmentSplitInfo(SegmentSplitInfoCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_FUNCTION_STARTS => {
                LoadCommand::FunctionStarts(FunctionStartsCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_DATA_IN_CODE => {
                LoadCommand::DataInCode(DataInCodeCommand::parse(cmd_data, big_endian)?)
            }
            load_command::LC_DYLD_INFO_ONLY => {
                LoadCommand::DyldInfoOnly(DyldInfoOnlyCommand::parse(cmd_data, big_endian)?)
            }
            _ => LoadCommand::Unknown {
                cmd_id: cmd,
                cmd_size: cmdsize as u32,
                data: cmd_data.to_vec(),
            },
        };

        Ok((load_cmd, cmdsize))
    }

    pub fn cmd_id(&self) -> u32 {
        match self {
            LoadCommand::Segment64(_) => load_command::LC_SEGMENT_64,
            LoadCommand::Segment(_) => load_command::LC_SEGMENT,
            LoadCommand::Symtab(_) => load_command::LC_SYMTAB,
            LoadCommand::Dysymtab(_) => load_command::LC_DYSYMTAB,
            LoadCommand::Dylinker(_) => load_command::LC_LOAD_DYLINKER,
            LoadCommand::IdDylinker(_) => load_command::LC_ID_DYLINKER,
            LoadCommand::Uuid(_) => load_command::LC_UUID,
            LoadCommand::Unixthread(_) => load_command::LC_UNIXTHREAD,
            LoadCommand::Main(_) => load_command::LC_MAIN,
            LoadCommand::Dylib(_) => load_command::LC_LOAD_DYLIB,
            LoadCommand::Rpath(_) => load_command::LC_RPATH,
            LoadCommand::CodeSignature(_) => load_command::LC_CODE_SIGNATURE,
            LoadCommand::VersionMinMacosx(_) => load_command::LC_VERSION_MIN_MACOSX,
            LoadCommand::VersionMinIphoneos(_) => load_command::LC_VERSION_MIN_IPHONEOS,
            LoadCommand::SourceVersion(_) => load_command::LC_SOURCE_VERSION,
            LoadCommand::SegmentSplitInfo(_) => load_command::LC_SEGMENT_SPLIT_INFO,
            LoadCommand::FunctionStarts(_) => load_command::LC_FUNCTION_STARTS,
            LoadCommand::DataInCode(_) => load_command::LC_DATA_IN_CODE,
            LoadCommand::DyldInfoOnly(_) => load_command::LC_DYLD_INFO_ONLY,
            LoadCommand::Unknown { cmd_id, .. } => *cmd_id,
        }
    }
}

/// 64-bit segment command
#[derive(Debug, Clone)]
pub struct SegmentCommand64 {
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<Section64>,
    pub reloff: u32,
    pub nreloc: u32,
}

impl SegmentCommand64 {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 72 {
            if data.len() < 64 {
                return Err(MacOsError::LoaderError(format!(
                    "Segment64 data too short: got {} bytes, need at least 64",
                    data.len()
                )));
            }
        }

        let mut cursor = Cursor::new(data);

        let mut segname = [0u8; 16];
        cursor
            .read_exact(&mut segname)
            .map_err(|_| MacOsError::LoaderError("Failed to read segname".to_string()))?;

        let vmaddr = read_u64(&mut cursor, big_endian)?;
        let vmsize = read_u64(&mut cursor, big_endian)?;
        let fileoff = read_u64(&mut cursor, big_endian)?;
        let filesize = read_u64(&mut cursor, big_endian)?;
        let maxprot = read_i32(&mut cursor, big_endian)?;
        let initprot = read_i32(&mut cursor, big_endian)?;

        let nsects = read_u32(&mut cursor, big_endian)?;
        let flags = read_u32(&mut cursor, big_endian)?;

        // Standard LC_SEGMENT_64: no optional fields between flags and sections
        // But we still declare these for the struct (set to 0)
        let (reloff, nreloc) = (0u32, 0u32);

        // `data` here starts after cmd/cmdsize, so section array starts right after
        // segment_command_64 payload (64 bytes).
        // Section data is: sectname(16) + segname(16) + addr(8) + size(8) + ... = 80 bytes each
        let section_start_pos = 64u64;
        cursor.set_position(section_start_pos);

        let mut sections = Vec::new();
        if data.len() >= 72 {
            for _ in 0..nsects {
                let section_offset = cursor.position() as usize;
                let section_data = &data[section_offset..];
                if section_data.len() < 80 {
                    break;
                }
                let section = Section64::parse(section_data, big_endian)?;
                sections.push(section);
                cursor.set_position(cursor.position() + 80);
            }
        }

        Ok(Self {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
            sections,
            reloff,
            nreloc,
        })
    }

    pub fn segname_str(&self) -> String {
        String::from_utf8_lossy(
            &self.segname[..self.segname.iter().position(|&c| c == 0).unwrap_or(16)],
        )
        .to_string()
    }
}

/// 32-bit segment command
#[derive(Debug, Clone)]
pub struct SegmentCommand32 {
    pub segname: [u8; 16],
    pub vmaddr: u32,
    pub vmsize: u32,
    pub fileoff: u32,
    pub filesize: u32,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<Section32>,
}

impl SegmentCommand32 {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 48 {
            return Err(MacOsError::LoaderError(format!(
                "Segment32 data too short: got {} bytes, need at least 48",
                data.len()
            )));
        }

        let mut cursor = Cursor::new(data);

        let mut segname = [0u8; 16];
        cursor.read_exact(&mut segname)?;

        let vmaddr = read_u32(&mut cursor, big_endian)?;
        let vmsize = read_u32(&mut cursor, big_endian)?;
        let fileoff = read_u32(&mut cursor, big_endian)?;
        let filesize = read_u32(&mut cursor, big_endian)?;
        let maxprot = read_i32(&mut cursor, big_endian)?;
        let initprot = read_i32(&mut cursor, big_endian)?;
        let nsects = read_u32(&mut cursor, big_endian)?;
        let flags = read_u32(&mut cursor, big_endian)?;

        let mut sections = Vec::new();
        for _ in 0..nsects {
            let section_data = &data[cursor.position() as usize..];
            if section_data.len() < 68 {
                break;
            }
            if let Ok(section) = Section32::parse(section_data, big_endian) {
                sections.push(section);
                cursor.set_position(cursor.position() + 68);
            } else {
                break;
            }
        }

        Ok(Self {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
            sections,
        })
    }

    pub fn segname_str(&self) -> String {
        String::from_utf8_lossy(
            &self.segname[..self.segname.iter().position(|&c| c == 0).unwrap_or(16)],
        )
        .to_string()
    }
}

/// 64-bit section structure
#[derive(Debug, Clone)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section64 {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 80 {
            return Err(MacOsError::LoaderError(
                "Section64 data too short".to_string(),
            ));
        }

        let mut sectname_array: [u8; 16] = [0u8; 16];
        sectname_array[..16].copy_from_slice(&data[0..16]);

        let mut segname_array: [u8; 16] = [0u8; 16];
        segname_array[..16].copy_from_slice(&data[16..32]);

        let addr = if big_endian {
            u64::from_be_bytes(data[32..40].try_into().unwrap())
        } else {
            u64::from_le_bytes(data[32..40].try_into().unwrap())
        };
        let size = if big_endian {
            u64::from_be_bytes(data[40..48].try_into().unwrap())
        } else {
            u64::from_le_bytes(data[40..48].try_into().unwrap())
        };
        let offset = if big_endian {
            u32::from_be_bytes(data[48..52].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[48..52].try_into().unwrap())
        };
        let align = if big_endian {
            u32::from_be_bytes(data[52..56].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[52..56].try_into().unwrap())
        };
        let reloff = if big_endian {
            u32::from_be_bytes(data[56..60].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[56..60].try_into().unwrap())
        };
        let nreloc = if big_endian {
            u32::from_be_bytes(data[60..64].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[60..64].try_into().unwrap())
        };
        let flags = if big_endian {
            u32::from_be_bytes(data[64..68].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[64..68].try_into().unwrap())
        };
        let reserved1 = if big_endian {
            u32::from_be_bytes(data[68..72].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[68..72].try_into().unwrap())
        };
        let reserved2 = if big_endian {
            u32::from_be_bytes(data[72..76].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[72..76].try_into().unwrap())
        };
        let reserved3 = if big_endian {
            u32::from_be_bytes(data[76..80].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[76..80].try_into().unwrap())
        };

        Ok(Self {
            sectname: sectname_array,
            segname: segname_array,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
            reserved3,
        })
    }
}

/// 32-bit section structure
#[derive(Debug, Clone)]
pub struct Section32 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u32,
    pub size: u32,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

impl Section32 {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 68 {
            return Err(MacOsError::LoaderError(
                "Section32 data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);

        let mut sectname = [0u8; 16];
        cursor.read_exact(&mut sectname)?;

        let mut segname = [0u8; 16];
        cursor.read_exact(&mut segname)?;

        let addr = read_u32(&mut cursor, big_endian)?;
        let size = read_u32(&mut cursor, big_endian)?;
        let offset = read_u32(&mut cursor, big_endian)?;
        let align = read_u32(&mut cursor, big_endian)?;
        let reloff = read_u32(&mut cursor, big_endian)?;
        let nreloc = read_u32(&mut cursor, big_endian)?;
        let flags = read_u32(&mut cursor, big_endian)?;
        let reserved1 = read_u32(&mut cursor, big_endian)?;
        let reserved2 = read_u32(&mut cursor, big_endian)?;

        Ok(Self {
            sectname,
            segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
        })
    }
}

/// Symbol table command
#[derive(Debug, Clone)]
pub struct SymtabCommand {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

impl SymtabCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 16 {
            return Err(MacOsError::LoaderError("Symtab data too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            symoff: read_u32(&mut cursor, big_endian)?,
            nsyms: read_u32(&mut cursor, big_endian)?,
            stroff: read_u32(&mut cursor, big_endian)?,
            strsize: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// Dynamic symbol table command
#[derive(Debug, Clone)]
pub struct DysymtabCommand {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl DysymtabCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 72 {
            return Err(MacOsError::LoaderError(
                "Dysymtab data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            ilocalsym: read_u32(&mut cursor, big_endian)?,
            nlocalsym: read_u32(&mut cursor, big_endian)?,
            iextdefsym: read_u32(&mut cursor, big_endian)?,
            nextdefsym: read_u32(&mut cursor, big_endian)?,
            iundefsym: read_u32(&mut cursor, big_endian)?,
            nundefsym: read_u32(&mut cursor, big_endian)?,
            tocoff: read_u32(&mut cursor, big_endian)?,
            ntoc: read_u32(&mut cursor, big_endian)?,
            modtaboff: read_u32(&mut cursor, big_endian)?,
            nmodtab: read_u32(&mut cursor, big_endian)?,
            extrefsymoff: read_u32(&mut cursor, big_endian)?,
            nextrefsyms: read_u32(&mut cursor, big_endian)?,
            indirectsymoff: read_u32(&mut cursor, big_endian)?,
            nindirectsyms: read_u32(&mut cursor, big_endian)?,
            extreloff: read_u32(&mut cursor, big_endian)?,
            nextrel: read_u32(&mut cursor, big_endian)?,
            locreloff: read_u32(&mut cursor, big_endian)?,
            nlocrel: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// Dylinker command
#[derive(Debug, Clone)]
pub struct DylinkerCommand {
    pub name_offset: u32,
    pub name: String,
}

impl DylinkerCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 4 {
            return Err(MacOsError::LoaderError(
                "Dylinker data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let name_offset = read_u32(&mut cursor, big_endian)?;
        let local_offset = name_offset
            .checked_sub(8)
            .ok_or_else(|| MacOsError::LoaderError("Invalid dylinker name offset".to_string()))?
            as usize;

        if local_offset >= data.len() {
            return Err(MacOsError::LoaderError(
                "Dylinker name offset out of bounds".to_string(),
            ));
        }

        let name_data = &data[local_offset..];
        let null_pos = name_data
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(name_data.len());
        let name = String::from_utf8_lossy(&name_data[..null_pos]).to_string();

        Ok(Self { name_offset, name })
    }
}

/// ID Dylinker command
#[derive(Debug, Clone)]
pub struct IdDylinkerCommand {
    pub name_offset: u32,
    pub name: String,
}

impl IdDylinkerCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 4 {
            return Err(MacOsError::LoaderError(
                "IdDylinker data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let name_offset = read_u32(&mut cursor, big_endian)?;
        let local_offset = name_offset
            .checked_sub(8)
            .ok_or_else(|| MacOsError::LoaderError("Invalid id_dylinker name offset".to_string()))?
            as usize;

        if local_offset >= data.len() {
            return Err(MacOsError::LoaderError(
                "ID dylinker name offset out of bounds".to_string(),
            ));
        }

        let name_data = &data[local_offset..];
        let null_pos = name_data
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(name_data.len());
        let name = String::from_utf8_lossy(&name_data[..null_pos]).to_string();

        Ok(Self { name_offset, name })
    }
}

/// UUID command
#[derive(Debug, Clone)]
pub struct UuidCommand {
    pub uuid: [u8; 16],
}

impl UuidCommand {
    pub fn parse(data: &[u8]) -> Result<Self, MacOsError> {
        if data.len() < 16 {
            return Err(MacOsError::LoaderError("UUID data too short".to_string()));
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[..16]);

        Ok(Self { uuid })
    }
}

/// UNIX thread command (contains CPU state)
#[derive(Debug, Clone)]
pub struct UnixThreadCommand {
    pub flavor: u32,
    pub count: u32,
    pub entry: u64,
    pub registers: ThreadRegisters,
}

#[derive(Debug, Clone)]
pub struct ThreadRegisters {
    pub x86_32: Option<X86ThreadState32>,
    pub x86_64: Option<X86ThreadState64>,
    pub arm32: Option<ArmThreadState32>,
    pub arm64: Option<Arm64ThreadState>,
}

impl Default for ThreadRegisters {
    fn default() -> Self {
        Self {
            x86_32: None,
            x86_64: None,
            arm32: None,
            arm64: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct X86ThreadState32 {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ss: u32,
    pub eflags: u32,
    pub eip: u32,
    pub cs: u32,
    pub ds: u32,
    pub es: u32,
    pub fs: u32,
    pub gs: u32,
}

#[derive(Debug, Clone)]
pub struct X86ThreadState64 {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub fs: u64,
    pub gs: u64,
}

#[derive(Debug, Clone)]
pub struct ArmThreadState32 {
    pub r0: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub r12: u32,
    pub sp: u32,
    pub lr: u32,
    pub pc: u32,
    pub cpsr: u32,
}

#[derive(Debug, Clone)]
pub struct Arm64ThreadState {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub sp: u64,
    pub pc: u64,
}

impl UnixThreadCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "UnixThread data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let flavor = read_u32(&mut cursor, big_endian)?;
        let count = read_u32(&mut cursor, big_endian)?;

        let mut registers = ThreadRegisters::default();
        let mut entry = 0u64;

        match flavor {
            thread_flavor::X86_THREAD_STATE32 => {
                // Flavor value 1 is used by both x86_32 and arm32 depending on cputype.
                // We don't receive cputype here, so use count/size heuristic.
                if count >= 17 && data.len() >= 8 + 68 {
                    let regs = ArmThreadState32 {
                        r0: read_u32(&mut cursor, big_endian)?,
                        r1: read_u32(&mut cursor, big_endian)?,
                        r2: read_u32(&mut cursor, big_endian)?,
                        r3: read_u32(&mut cursor, big_endian)?,
                        r4: read_u32(&mut cursor, big_endian)?,
                        r5: read_u32(&mut cursor, big_endian)?,
                        r6: read_u32(&mut cursor, big_endian)?,
                        r7: read_u32(&mut cursor, big_endian)?,
                        r8: read_u32(&mut cursor, big_endian)?,
                        r9: read_u32(&mut cursor, big_endian)?,
                        r10: read_u32(&mut cursor, big_endian)?,
                        r11: read_u32(&mut cursor, big_endian)?,
                        r12: read_u32(&mut cursor, big_endian)?,
                        sp: read_u32(&mut cursor, big_endian)?,
                        lr: read_u32(&mut cursor, big_endian)?,
                        pc: read_u32(&mut cursor, big_endian)?,
                        cpsr: read_u32(&mut cursor, big_endian)?,
                    };
                    entry = regs.pc as u64;
                    registers.arm32 = Some(regs);
                } else if data.len() >= 8 + 64 {
                    let regs = X86ThreadState32 {
                        eax: read_u32(&mut cursor, big_endian)?,
                        ebx: read_u32(&mut cursor, big_endian)?,
                        ecx: read_u32(&mut cursor, big_endian)?,
                        edx: read_u32(&mut cursor, big_endian)?,
                        edi: read_u32(&mut cursor, big_endian)?,
                        esi: read_u32(&mut cursor, big_endian)?,
                        ebp: read_u32(&mut cursor, big_endian)?,
                        esp: read_u32(&mut cursor, big_endian)?,
                        ss: read_u32(&mut cursor, big_endian)?,
                        eflags: read_u32(&mut cursor, big_endian)?,
                        eip: read_u32(&mut cursor, big_endian)?,
                        cs: read_u32(&mut cursor, big_endian)?,
                        ds: read_u32(&mut cursor, big_endian)?,
                        es: read_u32(&mut cursor, big_endian)?,
                        fs: read_u32(&mut cursor, big_endian)?,
                        gs: read_u32(&mut cursor, big_endian)?,
                    };
                    entry = regs.eip as u64;
                    registers.x86_32 = Some(regs);
                }
            }
            thread_flavor::X86_THREAD_STATE64 => {
                if data.len() >= 8 + 168 {
                    let regs = X86ThreadState64 {
                        rax: read_u64(&mut cursor, big_endian)?,
                        rbx: read_u64(&mut cursor, big_endian)?,
                        rcx: read_u64(&mut cursor, big_endian)?,
                        rdx: read_u64(&mut cursor, big_endian)?,
                        rdi: read_u64(&mut cursor, big_endian)?,
                        rsi: read_u64(&mut cursor, big_endian)?,
                        rbp: read_u64(&mut cursor, big_endian)?,
                        rsp: read_u64(&mut cursor, big_endian)?,
                        r8: read_u64(&mut cursor, big_endian)?,
                        r9: read_u64(&mut cursor, big_endian)?,
                        r10: read_u64(&mut cursor, big_endian)?,
                        r11: read_u64(&mut cursor, big_endian)?,
                        r12: read_u64(&mut cursor, big_endian)?,
                        r13: read_u64(&mut cursor, big_endian)?,
                        r14: read_u64(&mut cursor, big_endian)?,
                        r15: read_u64(&mut cursor, big_endian)?,
                        rip: read_u64(&mut cursor, big_endian)?,
                        rflags: read_u64(&mut cursor, big_endian)?,
                        cs: read_u64(&mut cursor, big_endian)?,
                        fs: read_u64(&mut cursor, big_endian)?,
                        gs: read_u64(&mut cursor, big_endian)?,
                    };
                    entry = regs.rip;
                    registers.x86_64 = Some(regs);
                }
            }
            thread_flavor::ARM_THREAD_STATE64 => {
                if data.len() >= 8 + 168 {
                    let regs = Arm64ThreadState {
                        x0: read_u64(&mut cursor, big_endian)?,
                        x1: read_u64(&mut cursor, big_endian)?,
                        x2: read_u64(&mut cursor, big_endian)?,
                        x3: read_u64(&mut cursor, big_endian)?,
                        x4: read_u64(&mut cursor, big_endian)?,
                        x5: read_u64(&mut cursor, big_endian)?,
                        x6: read_u64(&mut cursor, big_endian)?,
                        x7: read_u64(&mut cursor, big_endian)?,
                        x8: read_u64(&mut cursor, big_endian)?,
                        x9: read_u64(&mut cursor, big_endian)?,
                        x10: read_u64(&mut cursor, big_endian)?,
                        x11: read_u64(&mut cursor, big_endian)?,
                        x12: read_u64(&mut cursor, big_endian)?,
                        x13: read_u64(&mut cursor, big_endian)?,
                        x14: read_u64(&mut cursor, big_endian)?,
                        x15: read_u64(&mut cursor, big_endian)?,
                        x16: read_u64(&mut cursor, big_endian)?,
                        x17: read_u64(&mut cursor, big_endian)?,
                        x18: read_u64(&mut cursor, big_endian)?,
                        x19: read_u64(&mut cursor, big_endian)?,
                        x20: read_u64(&mut cursor, big_endian)?,
                        x21: read_u64(&mut cursor, big_endian)?,
                        x22: read_u64(&mut cursor, big_endian)?,
                        x23: read_u64(&mut cursor, big_endian)?,
                        x24: read_u64(&mut cursor, big_endian)?,
                        x25: read_u64(&mut cursor, big_endian)?,
                        x26: read_u64(&mut cursor, big_endian)?,
                        x27: read_u64(&mut cursor, big_endian)?,
                        x28: read_u64(&mut cursor, big_endian)?,
                        x29: read_u64(&mut cursor, big_endian)?,
                        sp: read_u64(&mut cursor, big_endian)?,
                        pc: read_u64(&mut cursor, big_endian)?,
                    };
                    entry = regs.pc;
                    registers.arm64 = Some(regs);
                }
            }
            _ => {}
        }

        Ok(Self {
            flavor,
            count,
            entry,
            registers,
        })
    }
}

/// LC_MAIN command
#[derive(Debug, Clone)]
pub struct MainCommand {
    pub entryoff: u64,
    pub stacksize: u64,
}

impl MainCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 16 {
            return Err(MacOsError::LoaderError(
                "Main command data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            entryoff: read_u64(&mut cursor, big_endian)?,
            stacksize: read_u64(&mut cursor, big_endian)?,
        })
    }
}

/// Dynamic library command
#[derive(Debug, Clone)]
pub struct DylibCommand {
    pub name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub name: String,
}

impl DylibCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 24 {
            return Err(MacOsError::LoaderError("Dylib data too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let name_offset = read_u32(&mut cursor, big_endian)?;
        let timestamp = read_u32(&mut cursor, big_endian)?;
        let current_version = read_u32(&mut cursor, big_endian)?;
        let compatibility_version = read_u32(&mut cursor, big_endian)?;
        let local_offset = name_offset
            .checked_sub(8)
            .ok_or_else(|| MacOsError::LoaderError("Invalid dylib name offset".to_string()))?
            as usize;

        if local_offset >= data.len() {
            return Err(MacOsError::LoaderError(
                "Dylib name offset out of bounds".to_string(),
            ));
        }

        let name_data = &data[local_offset..];
        let null_pos = name_data
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(name_data.len());
        let name = String::from_utf8_lossy(&name_data[..null_pos]).to_string();

        Ok(Self {
            name_offset,
            timestamp,
            current_version,
            compatibility_version,
            name,
        })
    }
}

/// RPATH command
#[derive(Debug, Clone)]
pub struct RpathCommand {
    pub path_offset: u32,
    pub path: String,
}

impl RpathCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 4 {
            return Err(MacOsError::LoaderError("Rpath data too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let path_offset = read_u32(&mut cursor, big_endian)?;
        let local_offset = path_offset
            .checked_sub(8)
            .ok_or_else(|| MacOsError::LoaderError("Invalid rpath offset".to_string()))?
            as usize;

        if local_offset >= data.len() {
            return Err(MacOsError::LoaderError(
                "Rpath offset out of bounds".to_string(),
            ));
        }

        let path_data = &data[local_offset..];
        let null_pos = path_data
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(path_data.len());
        let path = String::from_utf8_lossy(&path_data[..null_pos]).to_string();

        Ok(Self { path_offset, path })
    }
}

/// Code signature command
#[derive(Debug, Clone)]
pub struct CodeSignatureCommand {
    pub data_offset: u32,
    pub data_size: u32,
}

impl CodeSignatureCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "CodeSignature data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            data_offset: read_u32(&mut cursor, big_endian)?,
            data_size: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// Version minimum command
#[derive(Debug, Clone)]
pub struct VersionMinCommand {
    pub version: u32,
    pub reserved: u32,
}

impl VersionMinCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "VersionMin data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            version: read_u32(&mut cursor, big_endian)?,
            reserved: read_u32(&mut cursor, big_endian)?,
        })
    }

    pub fn version_string(&self) -> String {
        let major = (self.version >> 16) & 0xFFFF;
        let minor = (self.version >> 8) & 0xFF;
        let patch = self.version & 0xFF;
        format!("{}.{}.{}", major, minor, patch)
    }
}

/// Source version command
#[derive(Debug, Clone)]
pub struct SourceVersionCommand {
    pub version: u64,
}

impl SourceVersionCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "SourceVersion data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            version: read_u64(&mut cursor, big_endian)?,
        })
    }
}

/// Segment split info command
#[derive(Debug, Clone)]
pub struct SegmentSplitInfoCommand {
    pub data_offset: u32,
    pub data_size: u32,
}

impl SegmentSplitInfoCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "SegmentSplitInfo data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            data_offset: read_u32(&mut cursor, big_endian)?,
            data_size: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// Function starts command
#[derive(Debug, Clone)]
pub struct FunctionStartsCommand {
    pub data_offset: u32,
    pub data_size: u32,
}

impl FunctionStartsCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "FunctionStarts data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            data_offset: read_u32(&mut cursor, big_endian)?,
            data_size: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// Data in code command
#[derive(Debug, Clone)]
pub struct DataInCodeCommand {
    pub data_offset: u32,
    pub data_size: u32,
}

impl DataInCodeCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError(
                "DataInCode data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            data_offset: read_u32(&mut cursor, big_endian)?,
            data_size: read_u32(&mut cursor, big_endian)?,
        })
    }
}

/// DYLD info only command
#[derive(Debug, Clone)]
pub struct DyldInfoOnlyCommand {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub binding_off: u32,
    pub binding_size: u32,
    pub weak_binding_off: u32,
    pub weak_binding_size: u32,
    pub lazy_binding_off: u32,
    pub lazy_binding_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

impl DyldInfoOnlyCommand {
    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 40 {
            return Err(MacOsError::LoaderError(
                "DyldInfoOnly data too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        Ok(Self {
            rebase_off: read_u32(&mut cursor, big_endian)?,
            rebase_size: read_u32(&mut cursor, big_endian)?,
            binding_off: read_u32(&mut cursor, big_endian)?,
            binding_size: read_u32(&mut cursor, big_endian)?,
            weak_binding_off: read_u32(&mut cursor, big_endian)?,
            weak_binding_size: read_u32(&mut cursor, big_endian)?,
            lazy_binding_off: read_u32(&mut cursor, big_endian)?,
            lazy_binding_size: read_u32(&mut cursor, big_endian)?,
            export_off: read_u32(&mut cursor, big_endian)?,
            export_size: read_u32(&mut cursor, big_endian)?,
        })
    }
}

fn read_u32(cursor: &mut Cursor<&[u8]>, big_endian: bool) -> Result<u32, MacOsError> {
    let mut bytes = [0u8; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| MacOsError::LoaderError("Failed to read u32".to_string()))?;
    Ok(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

fn read_i32(cursor: &mut Cursor<&[u8]>, big_endian: bool) -> Result<i32, MacOsError> {
    let mut bytes = [0u8; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| MacOsError::LoaderError("Failed to read i32".to_string()))?;
    Ok(if big_endian {
        i32::from_be_bytes(bytes)
    } else {
        i32::from_le_bytes(bytes)
    })
}

fn read_u64(cursor: &mut Cursor<&[u8]>, big_endian: bool) -> Result<u64, MacOsError> {
    let mut bytes = [0u8; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| MacOsError::LoaderError("Failed to read u64".to_string()))?;
    Ok(if big_endian {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}
