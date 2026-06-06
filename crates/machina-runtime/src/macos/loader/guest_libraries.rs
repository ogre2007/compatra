//! Guest-side Mach-O dynamic-library support.
//!
//! This is the no-dyld foundation for libraries that should execute as arm64
//! guest code instead of being proxied through host functions. It deliberately
//! stops short of a full dyld implementation: libraries are provided explicitly,
//! mapped into guest memory, and their exported symbols become import-resolution
//! candidates for the main image.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::macos::guest_memory::align_up;
use crate::macos::loader::consts::{cpu_type, file_type, vm_protection};
use crate::macos::loader::parser::MachoBinary;
use crate::macos::{Emulator, MacOsError};
use crate::UnicornEmulator;
use unicorn_engine::Prot;

pub const MACHINA_GUEST_LIBS_ENV: &str = "MACHINA_GUEST_LIBS";

const GUEST_LIBRARY_LOAD_ALIGN: u64 = 0x10000;
const GUEST_LIBRARY_LOAD_GAP: u64 = 0x10000;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestLibrarySpec {
    pub path: PathBuf,
}

impl GuestLibrarySpec {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestLibrarySymbol {
    pub library_index: usize,
    pub library_path: PathBuf,
    pub install_name: Option<String>,
    pub symbol: String,
    pub file_vmaddr: u64,
    pub address: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestLibraryImportSetReport {
    pub added: usize,
    pub total: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestLibraryBinding {
    pub import_name: String,
    pub export_symbol: String,
    pub address: u64,
    pub library_path: PathBuf,
    pub install_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GuestLibraryChainedFixupReport {
    pub path: PathBuf,
    pub install_name: Option<String>,
    pub stats: Option<crate::macos::imports::ChainedFixupStats>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GuestLibraryImage {
    pub path: PathBuf,
    pub install_name: Option<String>,
    pub load_base: u64,
    pub slide: u64,
    pub vm_range: Range<u64>,
    pub mapped_range: Range<u64>,
    pub exports: BTreeMap<String, u64>,
    pub binary: MachoBinary,
}

impl GuestLibraryImage {
    pub fn from_path(path: impl AsRef<Path>, load_base: u64) -> Result<Self, MacOsError> {
        let path = path.as_ref().to_path_buf();
        let binary = MachoBinary::parse_file(&path)?;
        Self::from_binary(path, binary, load_base)
    }

    pub fn from_binary(
        path: impl Into<PathBuf>,
        binary: MachoBinary,
        requested_load_base: u64,
    ) -> Result<Self, MacOsError> {
        let path = path.into();
        validate_guest_library_binary(&path, &binary)?;
        let vm_range = guest_library_vm_range(&binary).ok_or_else(|| {
            MacOsError::LoaderError(format!(
                "Guest library '{}' has no loadable non-PAGEZERO segments",
                path.display()
            ))
        })?;
        let load_base = align_up(requested_load_base.max(vm_range.start), PAGE_SIZE);
        let slide = load_base.checked_sub(vm_range.start).ok_or_else(|| {
            MacOsError::LoaderError(format!(
                "Guest library '{}' load base 0x{:x} is below image base 0x{:x}",
                path.display(),
                load_base,
                vm_range.start
            ))
        })?;
        let mapped_size = vm_range.end.checked_sub(vm_range.start).ok_or_else(|| {
            MacOsError::LoaderError(format!(
                "Guest library '{}' has invalid VM range",
                path.display()
            ))
        })?;
        let mapped_end = load_base.checked_add(mapped_size).ok_or_else(|| {
            MacOsError::LoaderError(format!(
                "Guest library '{}' mapped range overflows",
                path.display()
            ))
        })?;
        let exports = binary
            .get_defined_symbols()
            .into_iter()
            .filter(|(_, vmaddr)| *vmaddr >= vm_range.start && *vmaddr < vm_range.end)
            .collect::<BTreeMap<_, _>>();

        Ok(Self {
            install_name: binary.get_dylib_id().or_else(|| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.to_string())
            }),
            path,
            load_base,
            slide,
            vm_range,
            mapped_range: load_base..mapped_end,
            exports,
            binary,
        })
    }

    pub fn export_count(&self) -> usize {
        self.exports.len()
    }

    pub fn resolve_export_vmaddr(&self, symbol: &str) -> Option<(&str, u64)> {
        for key in guest_library_symbol_lookup_keys(symbol) {
            if let Some(&vmaddr) = self.exports.get(&key) {
                return Some((self.exports.get_key_value(&key)?.0.as_str(), vmaddr));
            }
        }
        None
    }

    pub fn resolve_export_address(&self, symbol: &str) -> Option<u64> {
        self.resolve_export_vmaddr(symbol)
            .map(|(_, vmaddr)| vmaddr.wrapping_add(self.slide))
    }

    pub fn matches_reference(&self, reference: &str) -> bool {
        let reference = reference.trim_matches('\0').trim();
        if reference.is_empty() {
            return false;
        }
        if self.install_name.as_deref() == Some(reference) {
            return true;
        }

        let reference_path = Path::new(reference);
        if reference_path == self.path {
            return true;
        }

        let reference_name = reference_path.file_name().and_then(|name| name.to_str());
        let path_name = self.path.file_name().and_then(|name| name.to_str());
        if reference_name.is_some() && reference_name == path_name {
            return true;
        }

        if let Some(install_name) = &self.install_name {
            let install_name = Path::new(install_name)
                .file_name()
                .and_then(|name| name.to_str());
            return reference_name.is_some() && reference_name == install_name;
        }

        false
    }

    pub fn map_into(&self, emulator: &mut UnicornEmulator) -> Result<(), MacOsError> {
        for segment in &self.binary.segments {
            let seg_name = segment.segname_str();
            if seg_name == "__PAGEZERO" || segment.vmsize == 0 {
                continue;
            }

            let mapped_addr = segment.vmaddr.wrapping_add(self.slide);
            let aligned_size = align_up(segment.vmsize, PAGE_SIZE);
            emulator.map_memory_with_prot(
                mapped_addr,
                aligned_size,
                Prot::READ | Prot::WRITE | Prot::EXEC,
            )?;

            if segment.filesize > 0 {
                let start = segment.fileoff as usize;
                let end = segment
                    .fileoff
                    .checked_add(segment.filesize)
                    .ok_or_else(|| {
                        MacOsError::LoaderError(format!(
                            "Guest library '{}' segment '{}' file range overflows",
                            self.path.display(),
                            seg_name
                        ))
                    })? as usize;
                if end > self.binary.data.len() || start > end {
                    return Err(MacOsError::LoaderError(format!(
                        "Guest library '{}' segment '{}' extends past EOF",
                        self.path.display(),
                        seg_name
                    )));
                }
                emulator.write_memory(mapped_addr, &self.binary.data[start..end])?;
            }

            emulator.protect_memory(mapped_addr, aligned_size, segment_prot(segment.initprot))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct GuestLibrarySet {
    images: Vec<GuestLibraryImage>,
    exports: BTreeMap<String, Vec<GuestLibrarySymbol>>,
}

impl GuestLibrarySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_env(load_base: u64) -> Result<Self, MacOsError> {
        Self::from_specs(guest_library_specs_from_env(), load_base)
    }

    pub fn from_specs(specs: Vec<GuestLibrarySpec>, load_base: u64) -> Result<Self, MacOsError> {
        let mut set = Self::new();
        let mut next_base = align_up(load_base, GUEST_LIBRARY_LOAD_ALIGN);
        let mut seen = BTreeSet::<PathBuf>::new();

        for spec in specs {
            for path in expand_guest_library_spec(&spec)? {
                if !seen.insert(path.clone()) {
                    continue;
                }
                let image = GuestLibraryImage::from_path(&path, next_base)?;
                next_base = align_up(
                    image
                        .mapped_range
                        .end
                        .saturating_add(GUEST_LIBRARY_LOAD_GAP),
                    GUEST_LIBRARY_LOAD_ALIGN,
                );
                set.push(image);
            }
        }

        Ok(set)
    }

    pub fn push(&mut self, image: GuestLibraryImage) {
        let library_index = self.images.len();
        for (symbol, file_vmaddr) in &image.exports {
            let resolved = GuestLibrarySymbol {
                library_index,
                library_path: image.path.clone(),
                install_name: image.install_name.clone(),
                symbol: symbol.clone(),
                file_vmaddr: *file_vmaddr,
                address: file_vmaddr.wrapping_add(image.slide),
            };
            for alias in guest_library_symbol_lookup_keys(symbol) {
                self.exports
                    .entry(alias)
                    .or_default()
                    .push(resolved.clone());
            }
        }
        self.images.push(image);
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    pub fn export_count(&self) -> usize {
        self.images
            .iter()
            .map(GuestLibraryImage::export_count)
            .sum()
    }

    pub fn images(&self) -> &[GuestLibraryImage] {
        &self.images
    }

    pub fn mapped_end(&self) -> u64 {
        self.images
            .iter()
            .map(|image| image.mapped_range.end)
            .max()
            .unwrap_or(0)
    }

    pub fn map_into(&self, emulator: &mut UnicornEmulator) -> Result<(), MacOsError> {
        for image in &self.images {
            image.map_into(emulator)?;
        }
        Ok(())
    }

    pub fn resolve_symbol(&self, symbol: &str) -> Option<&GuestLibrarySymbol> {
        for key in guest_library_symbol_lookup_keys(symbol) {
            if let Some(symbols) = self.exports.get(&key) {
                if let Some(symbol) = symbols.first() {
                    return Some(symbol);
                }
            }
        }
        None
    }

    pub fn resolve_symbol_for_library_reference(
        &self,
        library_reference: Option<&str>,
        symbol: &str,
    ) -> Option<&GuestLibrarySymbol> {
        let Some(reference) = library_reference else {
            return self.resolve_symbol(symbol);
        };
        for key in guest_library_symbol_lookup_keys(symbol) {
            let Some(symbols) = self.exports.get(&key) else {
                continue;
            };
            for symbol in symbols {
                if self
                    .images
                    .get(symbol.library_index)
                    .is_some_and(|image| image.matches_reference(reference))
                {
                    return Some(symbol);
                }
            }
        }
        None
    }

    pub fn extend_undefined_imports(
        &self,
        undefs: &mut Vec<(String, u8)>,
    ) -> GuestLibraryImportSetReport {
        let mut report = GuestLibraryImportSetReport {
            total: undefs.len(),
            ..GuestLibraryImportSetReport::default()
        };
        if self.is_empty() {
            return report;
        }

        for image in &self.images {
            for (name, n_type) in image.binary.get_undefined_symbols() {
                if push_undefined_symbol_if_missing(undefs, name, n_type) {
                    report.added += 1;
                }
            }
            match crate::macos::imports::chained_fixup_import_symbols(&image.binary) {
                Ok(symbols) => {
                    for name in symbols {
                        if push_undefined_symbol_if_missing(undefs, name, 0) {
                            report.added += 1;
                        }
                    }
                }
                Err(err) => {
                    report
                        .errors
                        .push(format!("{}: {}", image.path.display(), err));
                }
            }
        }
        report.total = undefs.len();
        report
    }

    pub fn apply_import_bindings<F>(
        &self,
        undefs: &[(String, u8)],
        stub_map: &mut HashMap<String, u64>,
        mut should_resolve: F,
    ) -> Vec<GuestLibraryBinding>
    where
        F: FnMut(&str) -> bool,
    {
        if self.is_empty() {
            return Vec::new();
        }

        let mut bindings = Vec::new();
        for (name, _) in undefs {
            if !should_resolve(name) {
                continue;
            }
            let Some(export) = self.resolve_symbol(name) else {
                continue;
            };
            for key in guest_library_symbol_lookup_keys(name) {
                stub_map.insert(key, export.address);
            }
            bindings.push(GuestLibraryBinding {
                import_name: name.clone(),
                export_symbol: export.symbol.clone(),
                address: export.address,
                library_path: export.library_path.clone(),
                install_name: export.install_name.clone(),
            });
        }
        bindings
    }

    pub fn process_chained_fixups(
        &self,
        emulator: &mut dyn Emulator,
        stub_map: &HashMap<String, u64>,
        data_symbols: Option<&HashMap<String, u64>>,
        fallback_addr: u64,
    ) -> Vec<GuestLibraryChainedFixupReport> {
        let mut reports = Vec::new();
        for image in &self.images {
            match crate::macos::imports::process_chained_fixups_with_binary(
                emulator,
                &image.binary,
                image.slide,
                stub_map,
                data_symbols,
                fallback_addr,
            ) {
                Ok(stats) => reports.push(GuestLibraryChainedFixupReport {
                    path: image.path.clone(),
                    install_name: image.install_name.clone(),
                    stats: Some(stats),
                    error: None,
                }),
                Err(err) => reports.push(GuestLibraryChainedFixupReport {
                    path: image.path.clone(),
                    install_name: image.install_name.clone(),
                    stats: None,
                    error: Some(err.to_string()),
                }),
            }
        }
        reports
    }
}

pub fn guest_library_specs_from_env() -> Vec<GuestLibrarySpec> {
    std::env::var(MACHINA_GUEST_LIBS_ENV)
        .ok()
        .map(|raw| parse_guest_library_specs(&raw))
        .unwrap_or_default()
}

pub fn parse_guest_library_specs(raw: &str) -> Vec<GuestLibrarySpec> {
    raw.split(',')
        .flat_map(|part| std::env::split_paths(part.trim()))
        .filter(|path| !path.as_os_str().is_empty())
        .map(GuestLibrarySpec::new)
        .collect()
}

pub fn guest_library_symbol_lookup_keys(symbol: &str) -> Vec<String> {
    let mut keys = BTreeSet::<String>::new();
    add_symbol_lookup_forms(&mut keys, symbol);
    if let Some((base, _suffix)) = symbol.split_once('$') {
        add_symbol_lookup_forms(&mut keys, base);
    }
    keys.into_iter().collect()
}

fn add_symbol_lookup_forms(keys: &mut BTreeSet<String>, symbol: &str) {
    if symbol.is_empty() {
        return;
    }
    keys.insert(symbol.to_string());
    if let Some(stripped) = symbol.strip_prefix('_') {
        if !stripped.is_empty() {
            keys.insert(stripped.to_string());
        }
        keys.insert(format!("_{symbol}"));
    } else {
        keys.insert(format!("_{symbol}"));
    }
}

fn expand_guest_library_spec(spec: &GuestLibrarySpec) -> Result<Vec<PathBuf>, MacOsError> {
    let path = &spec.path;
    if path.is_file() {
        return Ok(vec![path.clone()]);
    }

    if path.is_dir() && path.extension().and_then(|ext| ext.to_str()) == Some("framework") {
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            let candidate = path.join(stem);
            if candidate.is_file() {
                return Ok(vec![candidate]);
            }
        }
    }

    if path.is_dir() {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).map_err(|err| {
            MacOsError::LoaderError(format!(
                "Failed to read guest library directory '{}': {}",
                path.display(),
                err
            ))
        })? {
            let entry = entry.map_err(|err| {
                MacOsError::LoaderError(format!(
                    "Failed to read guest library directory '{}': {}",
                    path.display(),
                    err
                ))
            })?;
            let candidate = entry.path();
            if candidate.is_file()
                && candidate.extension().and_then(|ext| ext.to_str()) == Some("dylib")
            {
                files.push(candidate);
            }
        }
        files.sort();
        return Ok(files);
    }

    Err(MacOsError::LoaderError(format!(
        "Guest library path '{}' does not exist",
        path.display()
    )))
}

fn push_undefined_symbol_if_missing(
    undefs: &mut Vec<(String, u8)>,
    name: String,
    n_type: u8,
) -> bool {
    let normalized = crate::macos::imports::normalize_import_symbol(name.clone());
    let already_present = undefs.iter().any(|(existing, _)| {
        existing == &name
            || crate::macos::imports::normalize_import_symbol(existing.clone()) == normalized
    });
    if already_present {
        return false;
    }
    undefs.push((name, n_type));
    true
}

fn validate_guest_library_binary(path: &Path, binary: &MachoBinary) -> Result<(), MacOsError> {
    let header = binary.header_64.as_ref().ok_or_else(|| {
        MacOsError::LoaderError(format!(
            "Guest library '{}' is not a 64-bit Mach-O image",
            path.display()
        ))
    })?;
    if header.cputype != cpu_type::CPU_TYPE_ARM64 {
        return Err(MacOsError::LoaderError(format!(
            "Guest library '{}' is CPU type 0x{:x}, expected arm64",
            path.display(),
            header.cputype
        )));
    }
    if !matches!(header.filetype, file_type::MH_DYLIB | file_type::MH_BUNDLE) {
        return Err(MacOsError::LoaderError(format!(
            "Guest library '{}' is filetype 0x{:x}, expected dylib/bundle",
            path.display(),
            header.filetype
        )));
    }
    Ok(())
}

fn guest_library_vm_range(binary: &MachoBinary) -> Option<Range<u64>> {
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

fn segment_prot(initprot: i32) -> Prot {
    let mut prot = Prot::NONE;
    if initprot & vm_protection::VM_PROT_READ != 0 {
        prot |= Prot::READ;
    }
    if initprot & vm_protection::VM_PROT_WRITE != 0 {
        prot |= Prot::WRITE;
    }
    if initprot & vm_protection::VM_PROT_EXECUTE != 0 {
        prot |= Prot::EXEC;
    }
    if prot == Prot::NONE {
        Prot::READ
    } else {
        prot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::loader::consts::{load_command, magic};

    #[test]
    fn path_list_accepts_os_separator_and_commas() {
        let joined = std::env::join_paths([Path::new("liba.dylib"), Path::new("libb.dylib")])
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let raw = format!("{joined}, libc.dylib");
        let specs = parse_guest_library_specs(&raw);

        assert!(specs
            .iter()
            .any(|spec| spec.path == PathBuf::from("libc.dylib")));
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn arm64_dylib_identity_and_exports_are_indexed() {
        let data = synthetic_arm64_dylib();
        let binary = MachoBinary::parse(&data).unwrap();
        assert_eq!(
            binary.get_dylib_id().as_deref(),
            Some("@rpath/libguest.dylib")
        );

        let image = GuestLibraryImage::from_binary("libguest.dylib", binary, 0x2000_0000).unwrap();
        assert_eq!(image.vm_range, 0x1000..0x2000);
        assert_eq!(image.load_base, 0x2000_0000);
        assert_eq!(
            image.resolve_export_address("_guest_add"),
            Some(0x2000_0080)
        );

        let mut set = GuestLibrarySet::new();
        set.push(image);
        assert_eq!(set.image_count(), 1);
        assert_eq!(set.export_count(), 2);
        assert_eq!(
            set.resolve_symbol("guest_add").unwrap().address,
            0x2000_0080
        );
        assert_eq!(
            set.resolve_symbol("_ZN5guest3runEv").unwrap().address,
            0x2000_0090
        );
        assert_eq!(
            set.resolve_symbol_for_library_reference(Some("@rpath/libguest.dylib"), "_guest_add")
                .unwrap()
                .address,
            0x2000_0080
        );

        let mut stub_map = HashMap::new();
        let bindings = set.apply_import_bindings(
            &[("guest_add".to_string(), 0), ("_open".to_string(), 0)],
            &mut stub_map,
            |name| name != "_open",
        );
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].import_name, "guest_add");
        assert_eq!(bindings[0].export_symbol, "_guest_add");
        assert_eq!(stub_map.get("guest_add").copied(), Some(0x2000_0080));
        assert_eq!(stub_map.get("_guest_add").copied(), Some(0x2000_0080));
    }

    fn synthetic_arm64_dylib() -> Vec<u8> {
        let id_cmd = dylib_command(load_command::LC_ID_DYLIB, "@rpath/libguest.dylib");
        let segment_cmd = segment64_command("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5);
        let symtab_cmd = symtab_command(0x300, 2, 0x320, 0x40);
        let sizeofcmds = (id_cmd.len() + segment_cmd.len() + symtab_cmd.len()) as u32;

        let mut data = Vec::new();
        data.extend_from_slice(&magic::MH_MAGIC_64.to_le_bytes());
        data.extend_from_slice(&cpu_type::CPU_TYPE_ARM64.to_le_bytes());
        data.extend_from_slice(&cpu_type::CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        data.extend_from_slice(&file_type::MH_DYLIB.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&sizeofcmds.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&id_cmd);
        data.extend_from_slice(&segment_cmd);
        data.extend_from_slice(&symtab_cmd);
        data.resize(0x1000, 0);

        write_nlist64(&mut data, 0x300, 1, 0x1080);
        write_nlist64(&mut data, 0x310, 12, 0x1090);
        data[0x320] = 0;
        data[0x321..0x32c].copy_from_slice(b"_guest_add\0");
        data[0x32c..0x33d].copy_from_slice(b"__ZN5guest3runEv\0");
        data
    }

    fn dylib_command(cmd: u32, name: &str) -> Vec<u8> {
        let raw_size = 24 + name.len() + 1;
        let cmdsize = ((raw_size + 7) & !7) as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&cmd.to_le_bytes());
        data.extend_from_slice(&cmdsize.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        data.resize(cmdsize as usize, 0);
        data
    }

    fn segment64_command(
        name: &str,
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        initprot: i32,
    ) -> Vec<u8> {
        let mut segname = [0u8; 16];
        segname[..name.len()].copy_from_slice(name.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&load_command::LC_SEGMENT_64.to_le_bytes());
        data.extend_from_slice(&72u32.to_le_bytes());
        data.extend_from_slice(&segname);
        data.extend_from_slice(&vmaddr.to_le_bytes());
        data.extend_from_slice(&vmsize.to_le_bytes());
        data.extend_from_slice(&fileoff.to_le_bytes());
        data.extend_from_slice(&filesize.to_le_bytes());
        data.extend_from_slice(&7i32.to_le_bytes());
        data.extend_from_slice(&initprot.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    fn symtab_command(symoff: u32, nsyms: u32, stroff: u32, strsize: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&load_command::LC_SYMTAB.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&symoff.to_le_bytes());
        data.extend_from_slice(&nsyms.to_le_bytes());
        data.extend_from_slice(&stroff.to_le_bytes());
        data.extend_from_slice(&strsize.to_le_bytes());
        data
    }

    fn write_nlist64(data: &mut [u8], offset: usize, strx: u32, value: u64) {
        data[offset..offset + 4].copy_from_slice(&strx.to_le_bytes());
        data[offset + 4] = 0x0f;
        data[offset + 5] = 1;
        data[offset + 6..offset + 8].copy_from_slice(&0u16.to_le_bytes());
        data[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
}
