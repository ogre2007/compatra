use std::borrow::Cow;

pub fn canonical_darwin_import_symbol(symbol: &str) -> String {
    normalize_darwin_import_name(symbol).into_owned()
}

pub(crate) fn normalize_darwin_import_name(symbol: &str) -> Cow<'_, str> {
    let trimmed = symbol.trim();
    let (without_suffix, suffix_changed) = strip_darwin_abi_suffix(trimmed);

    if let Some(alias) = special_darwin_alias(without_suffix) {
        return Cow::Borrowed(alias);
    }
    if let Some(alias) = fortified_alias(without_suffix) {
        return Cow::Borrowed(alias);
    }

    let (without_prefix, prefix_changed) = strip_macho_c_prefix(without_suffix);

    if let Some(alias) = special_darwin_alias(without_prefix) {
        return Cow::Borrowed(alias);
    }
    if let Some(alias) = fortified_alias(without_prefix) {
        return Cow::Borrowed(alias);
    }
    if let Some(alias) = legacy_64_alias(without_prefix) {
        return Cow::Borrowed(alias);
    }

    if suffix_changed || prefix_changed || trimmed.len() != symbol.len() {
        Cow::Owned(without_prefix.to_string())
    } else {
        Cow::Borrowed(without_prefix)
    }
}

fn strip_darwin_abi_suffix(symbol: &str) -> (&str, bool) {
    if let Some((base, _suffix)) = symbol.split_once('$') {
        (base, true)
    } else {
        (symbol, false)
    }
}

fn strip_macho_c_prefix(symbol: &str) -> (&str, bool) {
    if symbol.starts_with("___") {
        (&symbol[1..], true)
    } else if symbol.starts_with('_') && !symbol.starts_with("__") {
        (&symbol[1..], true)
    } else {
        (symbol, false)
    }
}

fn special_darwin_alias(symbol: &str) -> Option<&'static str> {
    match symbol {
        "__NSGetExecutablePath" | "_NSGetExecutablePath" | "NSGetExecutablePath" => {
            Some("NSGetExecutablePath")
        }
        "__dyld_image_count" | "_dyld_image_count" | "dyld_image_count" => Some("dyld_image_count"),
        "__dyld_get_image_name" | "_dyld_get_image_name" | "dyld_get_image_name" => {
            Some("dyld_get_image_name")
        }
        "__dyld_get_image_header" | "_dyld_get_image_header" | "dyld_get_image_header" => {
            Some("dyld_get_image_header")
        }
        "__dyld_get_image_vmaddr_slide"
        | "_dyld_get_image_vmaddr_slide"
        | "dyld_get_image_vmaddr_slide" => Some("dyld_get_image_vmaddr_slide"),
        _ => None,
    }
}

fn fortified_alias(symbol: &str) -> Option<&'static str> {
    match symbol {
        "__memcpy_chk" => Some("memcpy"),
        "__memmove_chk" => Some("memmove"),
        "__memset_chk" => Some("memset"),
        "__bzero_chk" => Some("bzero"),
        "__memcmp_chk" => Some("memcmp"),
        "__memchr_chk" => Some("memchr"),
        "__strcpy_chk" => Some("strcpy"),
        "__strncpy_chk" => Some("strncpy"),
        "__strcat_chk" => Some("strcat"),
        "__strlcpy_chk" => Some("strlcpy"),
        "__strlcat_chk" => Some("strlcat"),
        _ => None,
    }
}

fn legacy_64_alias(symbol: &str) -> Option<&'static str> {
    match symbol {
        "stat64" => Some("stat"),
        "lstat64" => Some("lstat"),
        "fstat64" => Some("fstat"),
        "fstatat64" => Some("fstatat"),
        "statfs64" => Some("statfs"),
        "fstatfs64" => Some("fstatfs"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_darwin_import_symbol;

    #[test]
    fn canonicalizes_darwin_abi_suffixes() {
        assert_eq!(canonical_darwin_import_symbol("_open$NOCANCEL"), "open");
        assert_eq!(canonical_darwin_import_symbol("_read$NOCANCEL"), "read");
        assert_eq!(canonical_darwin_import_symbol("_close$NOCANCEL"), "close");
        assert_eq!(canonical_darwin_import_symbol("_fopen$UNIX2003"), "fopen");
        assert_eq!(
            canonical_darwin_import_symbol("_realpath$DARWIN_EXTSN"),
            "realpath"
        );
        assert_eq!(
            canonical_darwin_import_symbol("_readdir$INODE64"),
            "readdir"
        );
        assert_eq!(canonical_darwin_import_symbol("_select$1050"), "select");
    }

    #[test]
    fn canonicalizes_fortified_memory_and_string_aliases() {
        assert_eq!(canonical_darwin_import_symbol("___memcpy_chk"), "memcpy");
        assert_eq!(canonical_darwin_import_symbol("__memcpy_chk"), "memcpy");
        assert_eq!(canonical_darwin_import_symbol("___strlcpy_chk"), "strlcpy");
        assert_eq!(
            canonical_darwin_import_symbol("___snprintf_chk"),
            "__snprintf_chk"
        );
    }

    #[test]
    fn canonicalizes_legacy_64_and_double_underscore_darwin_names() {
        assert_eq!(canonical_darwin_import_symbol("_stat64"), "stat");
        assert_eq!(canonical_darwin_import_symbol("_stat64$INODE64"), "stat");
        assert_eq!(
            canonical_darwin_import_symbol("__NSGetExecutablePath"),
            "NSGetExecutablePath"
        );
        assert_eq!(
            canonical_darwin_import_symbol("__dyld_get_image_name"),
            "dyld_get_image_name"
        );
    }
}
