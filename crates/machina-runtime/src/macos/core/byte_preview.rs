pub fn lossy_data_preview(data: &[u8], max_len: usize) -> String {
    let mut preview = String::new();
    for &byte in data.iter().take(max_len) {
        match byte {
            b'\\' => preview.push_str("\\\\"),
            b'"' => preview.push_str("\\\""),
            b'\n' => preview.push_str("\\n"),
            b'\r' => preview.push_str("\\r"),
            b'\t' => preview.push_str("\\t"),
            0x20..=0x7e => preview.push(byte as char),
            _ => preview.push('.'),
        }
    }
    if data.len() > max_len {
        preview.push_str("...");
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_escapes_control_characters() {
        assert_eq!(lossy_data_preview(b"a\nb\tc", 32), "a\\nb\\tc");
    }

    #[test]
    fn preview_replaces_binary_noise_with_dots_and_json_safe_escapes() {
        assert_eq!(
            lossy_data_preview(&[0, b'"', b'\\', 0xff, b'A', b'\r'], 32),
            ".\\\"\\\\.A\\r"
        );
    }
}
