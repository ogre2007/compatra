use crate::macos::guest_memory::align_up;
use crate::macos::MacOsError;
use crate::UnicornEmulator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryArena {
    pub heap_base: u64,
    pub heap_size: u64,
    pub heap_cursor: u64,
    pub mmap_base: u64,
    pub mmap_size: u64,
    pub mmap_end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryArenaConfig {
    pub max_addr: u64,
    pub min_heap_base: u64,
    pub heap_size: u64,
    pub mmap_offset: u64,
    pub mmap_size: u64,
    pub map_mmap: bool,
}

impl GuestMemoryArenaConfig {
    pub fn arm64(max_addr: u64) -> Self {
        Self {
            max_addr,
            min_heap_base: 0,
            heap_size: 0x100_0000,
            mmap_offset: 0x20_0000,
            mmap_size: 0x0100_0000_0000,
            map_mmap: false,
        }
    }
}

pub fn setup_guest_memory_arena(
    emulator: &mut UnicornEmulator,
    config: GuestMemoryArenaConfig,
) -> Result<GuestMemoryArena, MacOsError> {
    let heap_base = (config.max_addr.max(config.min_heap_base) + 0xFFFF) & !0xFFFF;
    let _ = emulator.map_data_memory(heap_base, config.heap_size);

    let mmap_base = align_up(heap_base + config.mmap_offset, 0x1000);
    let mmap_end = mmap_base + config.mmap_size;
    if config.map_mmap {
        let _ = emulator.map_data_memory(mmap_base, config.mmap_size);
    }

    Ok(GuestMemoryArena {
        heap_base,
        heap_size: config.heap_size,
        heap_cursor: heap_base + 0x1000,
        mmap_base,
        mmap_size: config.mmap_size,
        mmap_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_uses_large_unmapped_mmap_arena() {
        let config = GuestMemoryArenaConfig::arm64(0x1_0000_0000);

        assert_eq!(config.mmap_size, 0x0100_0000_0000);
        assert!(!config.map_mmap);
    }
}
