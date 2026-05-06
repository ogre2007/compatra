//! Kernel structures for macOS emulation
//!
//! This module provides Rust representations of macOS kernel data structures
//! used in emulation, including process structures, credentials, network sockets,
//! and KEXT-related structures.

use crate::macos::Emulator;
use crate::macos::MacOsError;

/// A 64-bit pointer representation for kernel memory addresses.
#[derive(Debug, Clone, Copy)]
pub struct Pointer64(pub u64);

impl Pointer64 {
    /// Returns the raw pointer value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Writes the pointer value to memory at the specified address.
    pub fn write_to_memory(
        &self,
        emulator: &mut dyn Emulator,
        addr: u64,
    ) -> Result<(), MacOsError> {
        emulator.write_memory(addr, &self.0.to_le_bytes())
    }
}

/// macOS Mandatory Access Control (MAC) policy list structure.
///
/// This structure tracks registered MAC policies in the kernel.
///
/// # Layout
/// - `base`: Base address of the structure in memory
/// - `mpl_list`: Pointer to the policy list
/// - `mpl_lock`: Lock for thread-safe access
#[derive(Debug, Clone)]
pub struct MacPolicyList {
    /// Base address of this structure in memory
    pub base: u64,
    /// Pointer to the policy list
    pub mpl_list: Pointer64,
    /// Lock for thread-safe access
    pub mpl_lock: Pointer64,
}

impl MacPolicyList {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            mpl_list: Pointer64(0),
            mpl_lock: Pointer64(0),
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        self.mpl_list.write_to_memory(emulator, self.base)?;
        self.mpl_lock.write_to_memory(emulator, self.base + 8)?;
        Ok(())
    }
}

/// Kernel extension (KEXT) information structure.
///
/// Represents the `kmod_info` structure from xnu kernel for tracking loaded kernel extensions.
#[derive(Debug, Clone)]
pub struct KmodInfo {
    /// Base address of this structure in memory
    pub base: u64,
    /// Pointer to next kmod_info in the list
    pub next: u64,
    /// Version of this structure (currently 1)
    pub info_version: i32,
    /// Unique identifier for this KEXT
    pub id: i32,
    /// Bundle identifier (e.g., "com.apple.driver.IOHIDSystem")
    pub name: String,
    /// Version string
    pub version: String,
    /// Reference count
    pub reference_count: i32,
    /// List of references to this KEXT
    pub reference_list: u64,
    /// Load address of the KEXT
    pub address: u64,
    /// Size of the KEXT in memory
    pub size: u64,
    /// Size of the KEXT header
    pub hdr_size: u64,
    /// Address of the start function
    pub start: u64,
    /// Address of the stop function
    pub stop: u64,
}

impl KmodInfo {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            next: 0,
            info_version: 0,
            id: 0,
            name: String::new(),
            version: String::new(),
            reference_count: 0,
            reference_list: 0,
            address: 0,
            size: 0,
            hdr_size: 0,
            start: 0,
            stop: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.next.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.info_version.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.id.to_le_bytes())?;
        offset += 4;

        let name_bytes = self.name.as_bytes();
        let mut name_buf = [0u8; 64];
        let copy_len = name_bytes.len().min(63);
        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        emulator.write_memory(self.base + offset, &name_buf)?;
        offset += 64;

        let version_bytes = self.version.as_bytes();
        let mut version_buf = [0u8; 64];
        let copy_len = version_bytes.len().min(63);
        version_buf[..copy_len].copy_from_slice(&version_bytes[..copy_len]);
        emulator.write_memory(self.base + offset, &version_buf)?;
        offset += 64;

        emulator.write_memory(self.base + offset, &self.reference_count.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.reference_list.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.address.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.size.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.hdr_size.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.start.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.stop.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Ucred {
    pub base: u64,
    pub cr_ref: i32,
    pub cr_uid: u32,
    pub cr_ruid: u32,
    pub cr_svuid: u32,
    pub cr_ngroups: i32,
    pub cr_groups: [u32; 16],
    pub cr_rgid: u32,
    pub cr_svgid: u32,
    pub cr_label: u64,
}

impl Ucred {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            cr_ref: 0,
            cr_uid: 0,
            cr_ruid: 0,
            cr_svuid: 0,
            cr_ngroups: 0,
            cr_groups: [0; 16],
            cr_rgid: 0,
            cr_svgid: 0,
            cr_label: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.cr_ref.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_uid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_ruid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_svuid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_ngroups.to_le_bytes())?;
        offset += 8;

        for &group in &self.cr_groups {
            emulator.write_memory(self.base + offset, &group.to_le_bytes())?;
            offset += 4;
        }

        emulator.write_memory(self.base + offset, &self.cr_rgid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_svgid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.cr_label.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Vnode {
    pub base: u64,
    pub v_name: u64,
    pub v_type: i32,
    pub v_flag: i32,
}

impl Vnode {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            v_name: 0,
            v_type: 0,
            v_flag: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.v_name.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.v_type.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.v_flag.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Label {
    pub base: u64,
    pub l_flags: u32,
}

impl Label {
    pub fn new(base: u64) -> Self {
        Self { base, l_flags: 0 }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        emulator.write_memory(self.base, &self.l_flags.to_le_bytes())?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Proc {
    pub base: u64,
    pub p_pid: u32,
    pub p_ppid: u32,
    pub p_pgrpid: u32,
    pub p_flag: u32,
    pub p_uid: u32,
    pub p_gid: u32,
    pub p_ruid: u32,
    pub p_rgid: u32,
    pub p_svuid: u32,
    pub p_svgid: u32,
    pub p_comm: [u8; 17],
    pub p_name: [u8; 33],
    pub p_ucred: u64,
    pub p_list_next: u64,
    pub p_list_prev: u64,
}

impl Proc {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            p_pid: 0,
            p_ppid: 0,
            p_pgrpid: 0,
            p_flag: 0,
            p_uid: 0,
            p_gid: 0,
            p_ruid: 0,
            p_rgid: 0,
            p_svuid: 0,
            p_svgid: 0,
            p_comm: [0; 17],
            p_name: [0; 33],
            p_ucred: 0,
            p_list_next: 0,
            p_list_prev: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.p_list_next.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.p_list_prev.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.p_pid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_ppid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_pgrpid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_flag.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_uid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_gid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_ruid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_rgid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_svuid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_svgid.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.p_comm)?;
        offset += 17;

        emulator.write_memory(self.base + offset, &self.p_name)?;
        offset += 33;

        emulator.write_memory(self.base + offset, &self.p_ucred.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SockaddrCtl {
    pub base: u64,
    pub sc_len: u8,
    pub sc_family: u8,
    pub ss_sysaddr: u16,
    pub sc_id: u32,
    pub sc_unit: u32,
}

impl SockaddrCtl {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            sc_len: 0,
            sc_family: 0,
            ss_sysaddr: 0,
            sc_id: 0,
            sc_unit: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &[self.sc_len])?;
        offset += 1;

        emulator.write_memory(self.base + offset, &[self.sc_family])?;
        offset += 1;

        emulator.write_memory(self.base + offset, &self.ss_sysaddr.to_le_bytes())?;
        offset += 2;

        emulator.write_memory(self.base + offset, &self.sc_id.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.sc_unit.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SockaddrIn {
    pub base: u64,
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

impl SockaddrIn {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            sin_len: 0,
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &[self.sin_len])?;
        offset += 1;

        emulator.write_memory(self.base + offset, &[self.sin_family])?;
        offset += 1;

        emulator.write_memory(self.base + offset, &self.sin_port.to_le_bytes())?;
        offset += 2;

        emulator.write_memory(self.base + offset, &self.sin_addr.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.sin_zero)?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Sysent {
    pub sy_narg: i16,
    pub sy_call: u64,
    pub sy_arg_munge32: u64,
    pub sy_return_type: i32,
    pub sy_arg_bytes: i16,
}

impl Sysent {
    pub fn read_from_memory(emulator: &dyn Emulator, addr: u64) -> Result<Self, MacOsError> {
        let mut offset = 0;

        let sy_narg_bytes = emulator.read_memory(addr + offset, 2)?;
        let sy_narg = i16::from_le_bytes([sy_narg_bytes[0], sy_narg_bytes[1]]);
        offset += 2;

        let sy_call_bytes = emulator.read_memory(addr + offset, 8)?;
        let sy_call = u64::from_le_bytes(sy_call_bytes.try_into().unwrap());
        offset += 8;

        let sy_arg_munge32_bytes = emulator.read_memory(addr + offset, 8)?;
        let sy_arg_munge32 = u64::from_le_bytes(sy_arg_munge32_bytes.try_into().unwrap());
        offset += 8;

        let sy_return_type_bytes = emulator.read_memory(addr + offset, 4)?;
        let sy_return_type = i32::from_le_bytes(sy_return_type_bytes.try_into().unwrap());
        offset += 4;

        let sy_arg_bytes_val_bytes = emulator.read_memory(addr + offset, 2)?;
        let sy_arg_bytes_val = i16::from_le_bytes(sy_arg_bytes_val_bytes.try_into().unwrap());

        Ok(Self {
            sy_narg,
            sy_call,
            sy_arg_munge32,
            sy_return_type,
            sy_arg_bytes: sy_arg_bytes_val,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Mbuf {
    pub base: u64,
    pub m_hdr: MbufHeader,
    pub m_flags: u32,
}

#[derive(Debug, Clone)]
pub struct MbufHeader {
    pub mh_len: u32,
    pub mh_data: u64,
    pub mh_flags: u32,
    pub mh_types: u32,
    pub pkt_hdr: u64,
    pub ext_buf: u64,
}

impl Mbuf {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            m_hdr: MbufHeader {
                mh_len: 0,
                mh_data: 0,
                mh_flags: 0,
                mh_types: 0,
                pkt_hdr: 0,
                ext_buf: 0,
            },
            m_flags: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.m_hdr.mh_len.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.m_hdr.mh_data.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.m_hdr.mh_flags.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.m_hdr.mh_types.to_le_bytes())?;
        offset += 4;

        emulator.write_memory(self.base + offset, &self.m_hdr.pkt_hdr.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.m_hdr.ext_buf.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SockOpt {
    pub base: u64,
    pub sopt_val: u64,
    pub sopt_valsize: u64,
}

impl SockOpt {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            sopt_val: 0,
            sopt_valsize: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.sopt_val.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.sopt_valsize.to_le_bytes())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ListHead {
    pub base: u64,
    pub lh_first: Pointer64,
}

impl ListHead {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            lh_first: Pointer64(0),
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        self.lh_first.write_to_memory(emulator, self.base)
    }

    pub fn read_from_memory(emulator: &dyn Emulator, addr: u64) -> Result<Self, MacOsError> {
        let bytes = emulator.read_memory(addr, 8)?;
        let lh_first = u64::from_le_bytes(bytes.try_into().unwrap());
        Ok(Self {
            base: addr,
            lh_first: Pointer64(lh_first),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SysctlByNameArgs {
    pub base: u64,
    pub name: u64,
    pub namelen: u64,
    pub oldp: u64,
    pub oldlenp: u64,
    pub new: u64,
    pub newlen: u64,
}

impl SysctlByNameArgs {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            name: 0,
            namelen: 0,
            oldp: 0,
            oldlenp: 0,
            new: 0,
            newlen: 0,
        }
    }

    pub fn write_to_memory(&self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let mut offset = 0;

        emulator.write_memory(self.base + offset, &self.name.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.namelen.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.oldp.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.oldlenp.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.new.to_le_bytes())?;
        offset += 8;

        emulator.write_memory(self.base + offset, &self.newlen.to_le_bytes())?;

        Ok(())
    }
}
