//! arm64 adapter for allocator-backed compatibility host calls.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::macos::arm64_state::Arm64SharedState;
use crate::macos::{align_up, Emulator};
use crate::UnicornEmulator;

const ARM64_MALLOC_CHUNK_SIZE: u64 = 0x10_0000;

pub(crate) fn ensure_malloc_range_mapped(
    emu: &mut UnicornEmulator,
    malloc_mapped_until: &Arc<Mutex<u64>>,
    addr: u64,
    size: u64,
) -> bool {
    let end = align_up(addr.saturating_add(size), 0x1000);
    let mut mapped_until = match malloc_mapped_until.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    if *mapped_until == 0 {
        *mapped_until = align_up(addr, 0x1000);
    }
    while *mapped_until < end {
        let chunk_start = *mapped_until;
        let chunk_end = align_up(
            end.max(chunk_start.saturating_add(ARM64_MALLOC_CHUNK_SIZE)),
            0x1000,
        );
        if emu
            .map_data_memory(chunk_start, chunk_end.saturating_sub(chunk_start))
            .is_err()
        {
            return false;
        }
        *mapped_until = chunk_end;
    }
    true
}

pub(crate) fn allocate_arm64_heap(
    emu: &mut UnicornEmulator,
    malloc_next_addr: &Arc<Mutex<u64>>,
    malloc_mapped_until: &Arc<Mutex<u64>>,
    malloc_allocations: &Arc<Mutex<HashMap<u64, u64>>>,
    requested: u64,
    alignment: u64,
) -> Option<(u64, u64)> {
    let alignment = alignment.max(0x10);
    let alloc_size = align_up(requested.max(1), alignment);
    let page_size = align_up(alloc_size, 0x1000);
    let result = {
        let mut next = malloc_next_addr.lock().ok()?;
        let addr = align_up(*next, alignment);
        *next = addr.saturating_add(page_size);
        if !ensure_malloc_range_mapped(emu, malloc_mapped_until, addr, page_size) {
            return None;
        }
        let _ = emu.write_memory(addr, &vec![0u8; alloc_size as usize]);
        addr
    };
    if let Ok(mut allocations) = malloc_allocations.lock() {
        allocations.insert(result, alloc_size);
    }
    Some((result, alloc_size))
}

pub(crate) struct Arm64CompatGuestMemory<'a> {
    pub emulator: &'a mut UnicornEmulator,
    pub shared_state: &'a Arm64SharedState,
}

impl machina_compat::GuestMemory for Arm64CompatGuestMemory<'_> {
    fn read_memory(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<Vec<u8>, machina_compat::GuestMemoryError> {
        self.emulator
            .read_memory(addr, size)
            .map_err(|_| machina_compat::GuestMemoryError)
    }

    fn write_memory(
        &mut self,
        addr: u64,
        data: &[u8],
    ) -> Result<(), machina_compat::GuestMemoryError> {
        self.emulator
            .write_memory(addr, data)
            .map_err(|_| machina_compat::GuestMemoryError)
    }

    fn allocate_memory(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<u64, machina_compat::GuestMemoryError> {
        allocate_arm64_heap(
            self.emulator,
            &self.shared_state.malloc_next_addr,
            &self.shared_state.malloc_mapped_until,
            &self.shared_state.malloc_allocations,
            size as u64,
            alignment as u64,
        )
        .map(|(addr, _)| addr)
        .ok_or(machina_compat::GuestMemoryError)
    }

    fn free_memory(&mut self, addr: u64) -> Result<(), machina_compat::GuestMemoryError> {
        if let Ok(mut allocations) = self.shared_state.malloc_allocations.lock() {
            allocations.remove(&addr);
        }
        Ok(())
    }
}
