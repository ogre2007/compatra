pub const IMPORT_STUB_STRIDE: u64 = 0x100;
pub const STUB_REGION_BASE: u64 = 0x2_0000_0000;
pub const STUB_REGION_SIZE: u64 = 0x100_0000;
pub const DONE_STUB_OFFSET: u64 = 0x800;
pub const THREAD_EXIT_STUB_OFFSET: u64 = 0x900;
pub const RETURN_ZERO_STUB_BYTES: &[u8] = &[0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6];
pub const RETURN_STUB_BYTES: &[u8] = &[0xC0, 0x03, 0x5F, 0xD6];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_stub_layout_keeps_terminal_slots_in_region() {
        assert!(DONE_STUB_OFFSET < STUB_REGION_SIZE);
        assert!(THREAD_EXIT_STUB_OFFSET < STUB_REGION_SIZE);
        assert_ne!(DONE_STUB_OFFSET, THREAD_EXIT_STUB_OFFSET);
        assert_eq!(DONE_STUB_OFFSET % IMPORT_STUB_STRIDE, 0);
        assert_eq!(THREAD_EXIT_STUB_OFFSET % IMPORT_STUB_STRIDE, 0);
    }
}
