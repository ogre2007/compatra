//! Mach-O binary format header structures

use std::io::{Cursor, Read};

use crate::macos::loader::consts::*;
use crate::macos::MacOsError;

pub type CpuType = u32;

/// Mach-O magic number detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOMagic {
    Magic32,
    Magic64,
    Fat,
    Unknown,
}

impl MachOMagic {
    pub fn from_u32(magic: u32) -> Self {
        match magic {
            magic::MH_MAGIC_32 | magic::MH_CIGAM_32 => MachOMagic::Magic32,
            magic::MH_MAGIC_64 | magic::MH_CIGAM_64 => MachOMagic::Magic64,
            magic::FAT_MAGIC | magic::FAT_CIGAM => MachOMagic::Fat,
            _ => MachOMagic::Unknown,
        }
    }

    pub fn is_64_bit(&self) -> bool {
        matches!(self, MachOMagic::Magic64)
    }

    pub fn is_big_endian(&self, magic: u32) -> bool {
        matches!(
            magic,
            magic::MH_CIGAM_32 | magic::MH_CIGAM_64 | magic::FAT_CIGAM
        )
    }

    pub fn is_cigam(magic: u32) -> bool {
        magic == magic::MH_CIGAM_32 || magic == magic::MH_CIGAM_64
    }
}

/// Mach-O header for 32-bit binaries
#[derive(Debug, Clone)]
pub struct MachHeader {
    pub magic: u32,
    pub cputype: CpuType,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

impl MachHeader {
    pub fn parse_with_auto_detect(data: &[u8]) -> Result<(Self, bool), MacOsError> {
        if data.len() < 28 {
            return Err(MacOsError::LoaderError("Header too short".to_string()));
        }

        let magic_bytes = [data[0], data[1], data[2], data[3]];
        let magic_le = u32::from_le_bytes(magic_bytes);
        let magic_be = u32::from_be_bytes(magic_bytes);

        let is_cigam = magic_le == magic::MH_CIGAM_32;
        let should_be_big_endian = is_cigam || magic_be == magic::MH_MAGIC_32;

        let cputype_le = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cputype_be = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let valid_cpu_types = [
            cpu_type::CPU_TYPE_X86,
            cpu_type::CPU_TYPE_X86_64,
            cpu_type::CPU_TYPE_ARM,
            cpu_type::CPU_TYPE_ARM64,
        ];

        let le_is_valid = valid_cpu_types.contains(&cputype_le);
        let be_is_valid = valid_cpu_types.contains(&cputype_be);

        let actual_big_endian = if should_be_big_endian && be_is_valid && !le_is_valid {
            true
        } else if !should_be_big_endian && le_is_valid && !be_is_valid {
            false
        } else if le_is_valid && !be_is_valid {
            false
        } else if be_is_valid && !le_is_valid {
            true
        } else {
            should_be_big_endian
        };

        let header = Self::parse(data, actual_big_endian)?;
        Ok((header, actual_big_endian))
    }

    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 28 {
            return Err(MacOsError::LoaderError("Header too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let mut bytes = [0u8; 4];

        cursor.read_exact(&mut bytes)?;
        let magic = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let cputype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let cpusubtype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let filetype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let ncmds = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let sizeofcmds = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let flags = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        Ok(Self {
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
        })
    }

    pub fn file_type_name(&self) -> &'static str {
        match self.filetype {
            file_type::MH_EXECUTE => "Executable",
            file_type::MH_DYLIB => "Dynamic Library",
            file_type::MH_DYLINKER => "Dynamic Linker",
            file_type::MH_BUNDLE => "Bundle",
            file_type::MH_KEXT_BUNDLE => "KEXT Bundle",
            file_type::MH_FVMLIB => "Fixed VM Library",
            file_type::MH_PRELOAD => "Preloaded Executable",
            _ => "Unknown",
        }
    }

    pub fn is_driver(&self) -> bool {
        self.filetype == file_type::MH_KEXT_BUNDLE
    }
}

/// Mach-O header for 64-bit binaries
#[derive(Debug, Clone)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: CpuType,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl MachHeader64 {
    pub fn parse_with_auto_detect(data: &[u8]) -> Result<(Self, bool), MacOsError> {
        if data.len() < 32 {
            return Err(MacOsError::LoaderError("Header too short".to_string()));
        }

        let magic_bytes = [data[0], data[1], data[2], data[3]];
        let magic_le = u32::from_le_bytes(magic_bytes);
        let magic_be = u32::from_be_bytes(magic_bytes);

        let is_cigam = magic_le == magic::MH_CIGAM_64 || magic_le == magic::MH_CIGAM_32;

        let cputype_le = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cputype_be = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let valid_cpu_types = [
            cpu_type::CPU_TYPE_X86,
            cpu_type::CPU_TYPE_X86_64,
            cpu_type::CPU_TYPE_ARM,
            cpu_type::CPU_TYPE_ARM64,
            0x07000001,
            0x01000007,
        ];

        let _le_is_valid = valid_cpu_types.contains(&cputype_le);
        let _be_is_valid = valid_cpu_types.contains(&cputype_be);

        let actual_big_endian = if is_cigam {
            true
        } else if magic_le == magic::MH_MAGIC_64 || magic_be == magic::MH_MAGIC_64 {
            if cputype_le == cpu_type::CPU_TYPE_X86_64 || cputype_le == cpu_type::CPU_TYPE_ARM64 {
                false
            } else if cputype_be == cpu_type::CPU_TYPE_X86_64
                || cputype_be == cpu_type::CPU_TYPE_ARM64
            {
                true
            } else {
                false
            }
        } else {
            false
        };

        let header = Self::parse(data, actual_big_endian)?;
        Ok((header, actual_big_endian))
    }

    pub fn parse(data: &[u8], big_endian: bool) -> Result<Self, MacOsError> {
        if data.len() < 32 {
            return Err(MacOsError::LoaderError("Header too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let mut bytes = [0u8; 4];

        cursor.read_exact(&mut bytes)?;
        let magic = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let cputype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let cpusubtype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let filetype = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let ncmds = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let sizeofcmds = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let flags = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        cursor.read_exact(&mut bytes)?;
        let reserved = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };

        Ok(Self {
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }

    pub fn file_type_name(&self) -> &'static str {
        match self.filetype {
            file_type::MH_EXECUTE => "Executable",
            file_type::MH_DYLIB => "Dynamic Library",
            file_type::MH_DYLINKER => "Dynamic Linker",
            file_type::MH_BUNDLE => "Bundle",
            file_type::MH_KEXT_BUNDLE => "KEXT Bundle",
            file_type::MH_FVMLIB => "Fixed VM Library",
            file_type::MH_PRELOAD => "Preloaded Executable",
            _ => "Unknown",
        }
    }

    pub fn is_driver(&self) -> bool {
        self.filetype == file_type::MH_KEXT_BUNDLE
    }
}

/// FAT binary header for multi-architecture binaries
#[derive(Debug, Clone)]
pub struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

impl FatHeader {
    pub fn parse(data: &[u8]) -> Result<Self, MacOsError> {
        if data.len() < 8 {
            return Err(MacOsError::LoaderError("FAT header too short".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let mut bytes = [0u8; 4];

        cursor.read_exact(&mut bytes)?;
        let magic = u32::from_be_bytes(bytes);

        cursor.read_exact(&mut bytes)?;
        let nfat_arch = u32::from_be_bytes(bytes);

        Ok(Self { magic, nfat_arch })
    }
}

/// FAT binary architecture entry
#[derive(Debug, Clone)]
pub struct FatArch {
    pub cputype: CpuType,
    pub cpusubtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

impl FatArch {
    pub fn parse(data: &[u8]) -> Result<Self, MacOsError> {
        if data.len() < 20 {
            return Err(MacOsError::LoaderError(
                "FAT arch entry too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let mut bytes = [0u8; 4];

        cursor.read_exact(&mut bytes)?;
        let cputype = CpuType::from_be_bytes(bytes);

        cursor.read_exact(&mut bytes)?;
        let cpusubtype = u32::from_be_bytes(bytes);

        cursor.read_exact(&mut bytes)?;
        let offset = u32::from_be_bytes(bytes);

        cursor.read_exact(&mut bytes)?;
        let size = u32::from_be_bytes(bytes);

        cursor.read_exact(&mut bytes)?;
        let align = u32::from_be_bytes(bytes);

        Ok(Self {
            cputype,
            cpusubtype,
            offset,
            size,
            align,
        })
    }
}
