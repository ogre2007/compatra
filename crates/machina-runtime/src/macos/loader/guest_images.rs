//! Registry of guest Mach-O images loaded into emulated memory.
//!
//! Rosetta-style loading needs a stable place to answer "which guest image owns
//! this address?" before a future translator can map guest addresses to
//! translated host code. The no-dyld compat runner uses this today for
//! structured diagnostics; the model is deliberately loader-level and
//! architecture-neutral.

use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::macos::loader::guest_libraries::{GuestLibraryImage, GuestLibrarySet};
use crate::macos::loader::parser::MachoBinary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestImageKind {
    MainExecutable,
    Library,
}

impl GuestImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MainExecutable => "main",
            Self::Library => "library",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestImageRecord {
    pub index: usize,
    pub kind: GuestImageKind,
    pub path: PathBuf,
    pub install_name: Option<String>,
    pub slide: u64,
    pub vm_range: Range<u64>,
    pub mapped_range: Range<u64>,
    pub export_count: usize,
}

impl GuestImageRecord {
    pub fn contains_runtime_address(&self, address: u64) -> bool {
        address >= self.mapped_range.start && address < self.mapped_range.end
    }

    pub fn contains_file_vmaddr(&self, vmaddr: u64) -> bool {
        vmaddr >= self.vm_range.start && vmaddr < self.vm_range.end
    }

    pub fn runtime_address_for_file_vmaddr(&self, vmaddr: u64) -> Option<u64> {
        self.contains_file_vmaddr(vmaddr)
            .then_some(vmaddr.wrapping_add(self.slide))
    }

    pub fn file_vmaddr_for_runtime_address(&self, address: u64) -> Option<u64> {
        self.contains_runtime_address(address)
            .then_some(address.wrapping_sub(self.slide))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestImageAddress {
    pub image_index: usize,
    pub kind: GuestImageKind,
    pub path: PathBuf,
    pub install_name: Option<String>,
    pub file_vmaddr: u64,
    pub runtime_address: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestImageRegistry {
    records: Vec<GuestImageRecord>,
}

impl GuestImageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_loaded_images(
        main_path: impl AsRef<Path>,
        main_binary: &MachoBinary,
        main_slide: u64,
        guest_libraries: &GuestLibrarySet,
    ) -> Self {
        let mut registry = Self::new();
        registry.push_main(main_path, main_binary, main_slide);
        for image in guest_libraries.images() {
            registry.push_library(image);
        }
        registry
    }

    pub fn push_main(
        &mut self,
        path: impl AsRef<Path>,
        binary: &MachoBinary,
        slide: u64,
    ) -> Option<usize> {
        let vm_range = macho_vm_range(binary)?;
        let index = self.records.len();
        let record = GuestImageRecord {
            index,
            kind: GuestImageKind::MainExecutable,
            path: path.as_ref().to_path_buf(),
            install_name: None,
            slide,
            mapped_range: vm_range.start.wrapping_add(slide)..vm_range.end.wrapping_add(slide),
            vm_range,
            export_count: binary.get_defined_symbols().len(),
        };
        self.records.push(record);
        Some(index)
    }

    pub fn push_library(&mut self, image: &GuestLibraryImage) -> usize {
        let index = self.records.len();
        self.records.push(GuestImageRecord {
            index,
            kind: GuestImageKind::Library,
            path: image.path.clone(),
            install_name: image.install_name.clone(),
            slide: image.slide,
            vm_range: image.vm_range.clone(),
            mapped_range: image.mapped_range.clone(),
            export_count: image.export_count(),
        });
        index
    }

    pub fn records(&self) -> &[GuestImageRecord] {
        &self.records
    }

    pub fn image_count(&self) -> usize {
        self.records.len()
    }

    pub fn library_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.kind == GuestImageKind::Library)
            .count()
    }

    pub fn mapped_start(&self) -> Option<u64> {
        self.records
            .iter()
            .map(|record| record.mapped_range.start)
            .min()
    }

    pub fn mapped_end(&self) -> Option<u64> {
        self.records
            .iter()
            .map(|record| record.mapped_range.end)
            .max()
    }

    pub fn resolve_runtime_address(&self, address: u64) -> Option<GuestImageAddress> {
        let record = self
            .records
            .iter()
            .find(|record| record.contains_runtime_address(address))?;
        Some(GuestImageAddress {
            image_index: record.index,
            kind: record.kind,
            path: record.path.clone(),
            install_name: record.install_name.clone(),
            file_vmaddr: record.file_vmaddr_for_runtime_address(address)?,
            runtime_address: address,
        })
    }

    pub fn resolve_file_address(&self, image_index: usize, vmaddr: u64) -> Option<u64> {
        self.records
            .get(image_index)?
            .runtime_address_for_file_vmaddr(vmaddr)
    }
}

fn macho_vm_range(binary: &MachoBinary) -> Option<Range<u64>> {
    let mut start = u64::MAX;
    let mut end = 0u64;
    for segment in &binary.segments {
        if segment.segname_str() == "__PAGEZERO" || segment.vmsize == 0 {
            continue;
        }
        start = start.min(segment.vmaddr);
        end = end.max(segment.vmaddr.saturating_add(segment.vmsize));
    }
    (start != u64::MAX && end > start).then_some(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::loader::command::SegmentCommand64;
    use crate::macos::loader::consts::{cpu_type, file_type, magic};
    use crate::macos::loader::header::{MachHeader64, MachOMagic};
    use std::collections::HashMap;

    #[test]
    fn registry_maps_main_runtime_addresses_back_to_file_vmaddrs() {
        let binary = binary_with_segments(vec![
            segment("__PAGEZERO", 0, 0x1000),
            segment("__TEXT", 0x1000, 0x2000),
            segment("__DATA", 0x3000, 0x1000),
        ]);
        let mut registry = GuestImageRegistry::new();
        let index = registry
            .push_main("main.bin", &binary, 0x1000_0000)
            .unwrap();

        assert_eq!(registry.image_count(), 1);
        assert_eq!(
            registry.resolve_file_address(index, 0x1234),
            Some(0x1000_1234)
        );

        let address = registry.resolve_runtime_address(0x1000_3456).unwrap();
        assert_eq!(address.kind, GuestImageKind::MainExecutable);
        assert_eq!(address.file_vmaddr, 0x3456);
        assert!(registry.resolve_runtime_address(0x1000_4000).is_none());
    }

    fn binary_with_segments(segments: Vec<SegmentCommand64>) -> MachoBinary {
        MachoBinary {
            data: Vec::new(),
            magic: MachOMagic::Magic64,
            header_64: Some(MachHeader64 {
                magic: magic::MH_MAGIC_64,
                cputype: cpu_type::CPU_TYPE_ARM64,
                cpusubtype: cpu_type::CPU_SUBTYPE_ARM64_ALL,
                filetype: file_type::MH_EXECUTE,
                ncmds: 0,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            }),
            header_32: None,
            commands: Vec::new(),
            segments,
            entry_point: None,
            is_driver: false,
            segments_data: HashMap::new(),
        }
    }

    fn segment(name: &str, vmaddr: u64, vmsize: u64) -> SegmentCommand64 {
        let mut segname = [0u8; 16];
        segname[..name.len()].copy_from_slice(name.as_bytes());
        SegmentCommand64 {
            segname,
            vmaddr,
            vmsize,
            fileoff: 0,
            filesize: vmsize,
            maxprot: 7,
            initprot: 5,
            nsects: 0,
            flags: 0,
            sections: Vec::new(),
            reloff: 0,
            nreloc: 0,
        }
    }
}
