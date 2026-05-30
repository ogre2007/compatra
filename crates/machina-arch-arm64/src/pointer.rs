pub fn sanitize_indirect_target(
    target: u64,
    image_base: u64,
    mapped_ranges: &[(u64, u64)],
) -> Option<u64> {
    sanitize_pointer_to_mapped_range(target, image_base, mapped_ranges)
}

pub fn sanitize_signed_code_pointer(
    raw_value: u64,
    image_base: u64,
    mapped_ranges: &[(u64, u64)],
) -> Option<u64> {
    sanitize_pointer_to_mapped_range(raw_value, image_base, mapped_ranges)
}

fn sanitize_pointer_to_mapped_range(
    value: u64,
    image_base: u64,
    mapped_ranges: &[(u64, u64)],
) -> Option<u64> {
    if is_in_mapped_ranges(value, mapped_ranges) {
        return Some(value);
    }
    if (value >> 48) == 0 {
        return None;
    }
    let low32 = value & 0xFFFF_FFFF;
    let image_high = image_base & 0xFFFF_FFFF_0000_0000;
    let candidate = image_high | low32;
    if is_in_mapped_ranges(candidate, mapped_ranges) {
        return Some(candidate);
    }
    None
}

fn is_in_mapped_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| addr >= *start && addr < *end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pointer_high_bits_are_rebased_to_image() {
        let ranges = [(0x1_0000_0000, 0x1_0001_0000)];
        let raw = 0xABCD_0000_0000_1234;
        assert_eq!(
            sanitize_signed_code_pointer(raw, 0x1_0000_0000, &ranges),
            Some(0x1_0000_1234)
        );
    }

    #[test]
    fn unmapped_low_pointer_is_not_sanitized() {
        let ranges = [(0x1_0000_0000, 0x1_0001_0000)];
        assert_eq!(
            sanitize_indirect_target(0x1234, 0x1_0000_0000, &ranges),
            None
        );
    }
}
