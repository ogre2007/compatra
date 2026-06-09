//! Synthetic Apple framework imports used by the current macOS userland runner.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use crate::macos::byte_preview::lossy_data_preview;
use crate::macos::runner_support::{
    emit_arm64_event, record_arm64_import, Arm64ImportTracker, Arm64SharedState,
};
use crate::macos::{
    process_event, read_cstring, runtime_process_metadata, Emulator, SharedTraceBus, StubRegion,
};
use crate::UnicornEmulator;

fn normalized_apple_symbol(symbol: &str) -> &str {
    symbol.strip_prefix('_').unwrap_or(symbol)
}

pub fn is_apple_import_symbol(symbol: &str) -> bool {
    matches!(
        normalized_apple_symbol(symbol),
        "CFStringCreateWithCString"
            | "CFStringCreateWithBytes"
            | "CFStringCreateExternalRepresentation"
            | "CFStringGetCString"
            | "CFStringGetLength"
            | "CFStringGetTypeID"
            | "CFDataCreate"
            | "CFDataGetLength"
            | "CFDataGetBytePtr"
            | "CFDataGetTypeID"
            | "CFStringCompare"
            | "CFStringCreateCopy"
            | "CFStringGetCStringPtr"
            | "CFArrayCreateMutable"
            | "CFArrayCreate"
            | "CFArrayAppendValue"
            | "CFArrayGetCount"
            | "CFArrayGetValueAtIndex"
            | "CFArrayGetTypeID"
            | "CFDictionaryCreate"
            | "CFDictionaryGetValueIfPresent"
            | "CFDictionaryGetTypeID"
            | "CFDateCreate"
            | "CFErrorCreate"
            | "CFErrorGetCode"
            | "CFErrorCopyDescription"
            | "CFGetTypeID"
            | "CFNumberGetTypeID"
            | "CFNumberGetValue"
            | "CFBooleanGetTypeID"
            | "CFBooleanGetValue"
            | "CFURLCreateWithFileSystemPath"
            | "CFURLCopyFileSystemPath"
            | "CFBundleGetMainBundle"
            | "CFBundleCopyBundleURL"
            | "CFRelease"
            | "CFRetain"
            | "IONotificationPortCreate"
            | "IONotificationPortDestroy"
            | "IOServiceMatching"
            | "IOServiceGetMatchingService"
            | "IOServiceGetMatchingServices"
            | "IOIteratorNext"
            | "IORegistryEntryCreateCFProperty"
            | "IOObjectRelease"
            | "objc_getClass"
            | "objc_lookUpClass"
            | "objc_getRequiredClass"
            | "objc_getMetaClass"
            | "object_getClass"
            | "class_getName"
            | "sel_registerName"
            | "sel_getUid"
            | "sel_getName"
            | "sel_isEqual"
            | "objc_msgSend"
            | "objc_alloc"
            | "objc_alloc_init"
            | "objc_opt_self"
            | "objc_opt_class"
            | "objc_opt_new"
            | "objc_autoreleasePoolPush"
            | "objc_autoreleasePoolPop"
            | "objc_retain"
            | "objc_release"
            | "objc_autorelease"
            | "objc_storeStrong"
            | "objc_storeWeak"
            | "objc_initWeak"
            | "objc_destroyWeak"
            | "objc_loadWeakRetained"
            | "objc_retainAutorelease"
            | "objc_retainAutoreleasedReturnValue"
            | "objc_retainAutoreleaseReturnValue"
            | "objc_autoreleaseReturnValue"
            | "objc_unsafeClaimAutoreleasedReturnValue"
            | "NSHomeDirectory"
            | "NSTemporaryDirectory"
            | "NSUserName"
            | "NSFullUserName"
            | "NSSearchPathForDirectoriesInDomains"
            | "NSClassFromString"
            | "NSSelectorFromString"
            | "NSStringFromClass"
            | "NSStringFromSelector"
            | "NSLog"
            | "NSApplicationLoad"
            | "NSApplicationMain"
            | "CGMainDisplayID"
            | "CGDisplayPixelsWide"
            | "CGDisplayPixelsHigh"
            | "CGDisplayIsActive"
            | "CGDisplayIsOnline"
            | "CGPreflightScreenCaptureAccess"
            | "CGRequestScreenCaptureAccess"
            | "CGDisplayCreateImage"
            | "CGImageGetWidth"
            | "CGImageGetHeight"
            | "CGImageGetBitsPerPixel"
            | "CGImageGetBytesPerRow"
            | "CGImageGetDataProvider"
            | "CGImageRelease"
            | "CGDataProviderCopyData"
            | "CGEventSourceKeyState"
            | "CGPreflightListenEventAccess"
            | "CGRequestListenEventAccess"
            | "AXIsProcessTrusted"
            | "AXIsProcessTrustedWithOptions"
            | "SecRandomCopyBytes"
            | "SecCopyErrorMessageString"
            | "SecCertificateCreateWithData"
            | "SecCertificateCopyData"
            | "SecPolicyCreateSSL"
            | "SecItemCopyMatching"
            | "SecKeychainCopyDefault"
            | "SecKeychainOpen"
            | "SecKeychainGetPath"
            | "SecKeychainFindGenericPassword"
            | "SecKeychainItemFreeContent"
            | "SecTrustCreateWithCertificates"
            | "SecTrustEvaluateWithError"
            | "SecTrustGetCertificateCount"
            | "SecTrustGetCertificateAtIndex"
            | "SecTrustSetVerifyDate"
            | "xpc_date_create_from_current"
    )
}

fn read_guest_bytes(emu: &mut dyn Emulator, addr: u64, len: usize, cap: usize) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return Vec::new();
    }
    emu.read_memory(addr, len.min(cap)).unwrap_or_default()
}

fn read_guest_u64_array(emu: &mut dyn Emulator, addr: u64, count: usize, cap: usize) -> Vec<u64> {
    if addr == 0 || count == 0 {
        return Vec::new();
    }
    let capped = count.min(cap);
    let mut out = Vec::with_capacity(capped);
    for i in 0..capped {
        let Ok(bytes) = emu.read_memory(addr + (i as u64 * 8), 8) else {
            break;
        };
        let Ok(array) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            break;
        };
        out.push(u64::from_le_bytes(array));
    }
    out
}

fn read_guest_u64(emu: &mut dyn Emulator, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let bytes = emu.read_memory(addr, 8).ok()?;
    let array = <[u8; 8]>::try_from(bytes.as_slice()).ok()?;
    Some(u64::from_le_bytes(array))
}

fn read_guest_u32(emu: &mut dyn Emulator, addr: u64) -> Option<u32> {
    if addr == 0 {
        return None;
    }
    let bytes = emu.read_memory(addr, 4).ok()?;
    let array = <[u8; 4]>::try_from(bytes.as_slice()).ok()?;
    Some(u32::from_le_bytes(array))
}

fn write_guest_cstring(emu: &mut dyn Emulator, addr: u64, capacity: usize, bytes: &[u8]) -> bool {
    if addr == 0 || capacity == 0 {
        return false;
    }
    let copy_len = bytes.len().min(capacity.saturating_sub(1));
    if copy_len > 0 && emu.write_memory(addr, &bytes[..copy_len]).is_err() {
        return false;
    }
    emu.write_memory(addr + copy_len as u64, &[0]).is_ok()
}

fn write_guest_bool(emu: &mut dyn Emulator, addr: u64, value: bool) -> bool {
    addr != 0 && emu.write_memory(addr, &[value as u8]).is_ok()
}

fn write_guest_u32(emu: &mut dyn Emulator, addr: u64, value: u32) -> bool {
    addr != 0 && emu.write_memory(addr, &value.to_le_bytes()).is_ok()
}

fn cf_string_len(data: &[u8]) -> u64 {
    String::from_utf8_lossy(data).encode_utf16().count() as u64
}

const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CFURL_POSIX_PATH_STYLE: u64 = 0;

const APPLE_DIRECT_DISPATCH_IMPORTS: &[&str] = &[
    "_CFStringCreateWithCString",
    "_CFStringGetCString",
    "_CFStringGetLength",
    "_CFStringGetTypeID",
    "_CFStringGetCStringPtr",
    "_CFStringCreateCopy",
    "_CFStringCompare",
    "_CFDataGetTypeID",
    "_CFArrayGetTypeID",
    "_CFDictionaryGetTypeID",
    "_CFBooleanGetTypeID",
    "_CFBooleanGetValue",
    "_CFURLCreateWithFileSystemPath",
    "_CFURLCopyFileSystemPath",
    "_CFBundleGetMainBundle",
    "_CFBundleCopyBundleURL",
    "_IONotificationPortCreate",
    "_IONotificationPortDestroy",
    "_IOServiceMatching",
    "_IOServiceGetMatchingService",
    "_IOServiceGetMatchingServices",
    "_IOIteratorNext",
    "_IORegistryEntryCreateCFProperty",
    "_IOObjectRelease",
    "_objc_getClass",
    "_objc_lookUpClass",
    "_objc_getRequiredClass",
    "_objc_getMetaClass",
    "_object_getClass",
    "_class_getName",
    "_sel_registerName",
    "_sel_getUid",
    "_sel_getName",
    "_sel_isEqual",
    "_objc_msgSend",
    "_objc_alloc",
    "_objc_alloc_init",
    "_objc_opt_self",
    "_objc_opt_class",
    "_objc_opt_new",
    "_objc_autoreleasePoolPush",
    "_objc_autoreleasePoolPop",
    "_objc_retain",
    "_objc_release",
    "_objc_autorelease",
    "_objc_storeStrong",
    "_objc_storeWeak",
    "_objc_initWeak",
    "_objc_destroyWeak",
    "_objc_loadWeakRetained",
    "_objc_retainAutorelease",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_retainAutoreleaseReturnValue",
    "_objc_autoreleaseReturnValue",
    "_objc_unsafeClaimAutoreleasedReturnValue",
    "_NSHomeDirectory",
    "_NSTemporaryDirectory",
    "_NSUserName",
    "_NSFullUserName",
    "_NSSearchPathForDirectoriesInDomains",
    "_NSClassFromString",
    "_NSSelectorFromString",
    "_NSStringFromClass",
    "_NSStringFromSelector",
    "_NSLog",
    "_NSApplicationLoad",
    "_NSApplicationMain",
    "_CGMainDisplayID",
    "_CGDisplayPixelsWide",
    "_CGDisplayPixelsHigh",
    "_CGDisplayIsActive",
    "_CGDisplayIsOnline",
    "_CGPreflightScreenCaptureAccess",
    "_CGRequestScreenCaptureAccess",
    "_CGDisplayCreateImage",
    "_CGImageGetWidth",
    "_CGImageGetHeight",
    "_CGImageGetBitsPerPixel",
    "_CGImageGetBytesPerRow",
    "_CGImageGetDataProvider",
    "_CGImageRelease",
    "_CGDataProviderCopyData",
    "_CGEventSourceKeyState",
    "_CGPreflightListenEventAccess",
    "_CGRequestListenEventAccess",
    "_AXIsProcessTrusted",
    "_AXIsProcessTrustedWithOptions",
    "_SecRandomCopyBytes",
    "_SecCopyErrorMessageString",
    "_SecItemCopyMatching",
    "_SecKeychainCopyDefault",
    "_SecKeychainOpen",
    "_SecKeychainGetPath",
    "_SecKeychainFindGenericPassword",
    "_SecKeychainItemFreeContent",
];

#[cfg(target_os = "macos")]
fn host_cg_main_display_id() -> u32 {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGMainDisplayID() -> u32;
    }
    unsafe { CGMainDisplayID() }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_main_display_id() -> u32 {
    1
}

#[cfg(target_os = "macos")]
fn host_cg_display_pixels_wide(display: u32) -> usize {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDisplayPixelsWide(display: u32) -> usize;
    }
    unsafe { CGDisplayPixelsWide(display) }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_display_pixels_wide(_display: u32) -> usize {
    0
}

#[cfg(target_os = "macos")]
fn host_cg_display_pixels_high(display: u32) -> usize {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDisplayPixelsHigh(display: u32) -> usize;
    }
    unsafe { CGDisplayPixelsHigh(display) }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_display_pixels_high(_display: u32) -> usize {
    0
}

#[cfg(target_os = "macos")]
fn host_cg_display_is_active(display: u32) -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDisplayIsActive(display: u32) -> u8;
    }
    unsafe { CGDisplayIsActive(display) != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_display_is_active(_display: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_display_is_online(display: u32) -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDisplayIsOnline(display: u32) -> u8;
    }
    unsafe { CGDisplayIsOnline(display) != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_display_is_online(_display: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_preflight_screen_capture_access() -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightScreenCaptureAccess() -> u8;
    }
    unsafe { CGPreflightScreenCaptureAccess() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_preflight_screen_capture_access() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_request_screen_capture_access() -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGRequestScreenCaptureAccess() -> u8;
    }
    unsafe { CGRequestScreenCaptureAccess() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_request_screen_capture_access() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_display_create_image(display: u32) -> Option<u64> {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDisplayCreateImage(display: u32) -> *const std::ffi::c_void;
    }
    let image = unsafe { CGDisplayCreateImage(display) };
    (!image.is_null()).then_some(image as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cg_display_create_image(_display: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cg_image_size(image: u64, dimension: &str) -> usize {
    if image == 0 {
        return 0;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGImageGetWidth(image: *const std::ffi::c_void) -> usize;
        fn CGImageGetHeight(image: *const std::ffi::c_void) -> usize;
    }
    unsafe {
        match dimension {
            "height" => CGImageGetHeight(image as *const std::ffi::c_void),
            _ => CGImageGetWidth(image as *const std::ffi::c_void),
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_image_size(_image: u64, _dimension: &str) -> usize {
    0
}

#[cfg(target_os = "macos")]
fn host_cg_image_bits_per_pixel(image: u64) -> usize {
    if image == 0 {
        return 0;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGImageGetBitsPerPixel(image: *const std::ffi::c_void) -> usize;
    }
    unsafe { CGImageGetBitsPerPixel(image as *const std::ffi::c_void) }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_image_bits_per_pixel(_image: u64) -> usize {
    0
}

#[cfg(target_os = "macos")]
fn host_cg_image_bytes_per_row(image: u64) -> usize {
    if image == 0 {
        return 0;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGImageGetBytesPerRow(image: *const std::ffi::c_void) -> usize;
    }
    unsafe { CGImageGetBytesPerRow(image as *const std::ffi::c_void) }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_image_bytes_per_row(_image: u64) -> usize {
    0
}

#[cfg(target_os = "macos")]
fn host_cg_image_get_data_provider(image: u64) -> Option<u64> {
    if image == 0 {
        return None;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGImageGetDataProvider(image: *const std::ffi::c_void) -> *const std::ffi::c_void;
    }
    let provider = unsafe { CGImageGetDataProvider(image as *const std::ffi::c_void) };
    (!provider.is_null()).then_some(provider as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cg_image_get_data_provider(_image: u64) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cg_data_provider_copy_data(provider: u64) -> Option<u64> {
    if provider == 0 {
        return None;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGDataProviderCopyData(provider: *const std::ffi::c_void) -> *const std::ffi::c_void;
    }
    let data = unsafe { CGDataProviderCopyData(provider as *const std::ffi::c_void) };
    (!data.is_null()).then_some(data as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cg_data_provider_copy_data(_provider: u64) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cg_event_source_key_state(state_id: u32, key: u16) -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceKeyState(state_id: u32, key: u16) -> u8;
    }
    unsafe { CGEventSourceKeyState(state_id, key) != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_event_source_key_state(_state_id: u32, _key: u16) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_preflight_listen_event_access() -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightListenEventAccess() -> u8;
    }
    unsafe { CGPreflightListenEventAccess() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_preflight_listen_event_access() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_cg_request_listen_event_access() -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGRequestListenEventAccess() -> u8;
    }
    unsafe { CGRequestListenEventAccess() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_cg_request_listen_event_access() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_ax_is_process_trusted() -> bool {
    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> u8;
    }
    unsafe { AXIsProcessTrusted() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_ax_is_process_trusted() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_ax_is_process_trusted_with_options(options: u64) -> bool {
    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrustedWithOptions(options: *const std::ffi::c_void) -> u8;
    }
    unsafe { AXIsProcessTrustedWithOptions(options as *const std::ffi::c_void) != 0 }
}

#[cfg(not(target_os = "macos"))]
fn host_ax_is_process_trusted_with_options(_options: u64) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn host_sec_random_bytes(len: usize) -> Option<Vec<u8>> {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecRandomCopyBytes(rnd: *const std::ffi::c_void, count: usize, bytes: *mut u8) -> i32;
    }

    let mut out = vec![0u8; len];
    let ret = unsafe { SecRandomCopyBytes(std::ptr::null(), len, out.as_mut_ptr()) };
    (ret == 0).then_some(out)
}

#[cfg(not(target_os = "macos"))]
fn host_sec_random_bytes(len: usize) -> Option<Vec<u8>> {
    let mut x = 0xA5u8;
    Some(
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(33).wrapping_add(17);
                x
            })
            .collect(),
    )
}

#[cfg(target_os = "macos")]
fn host_sec_error_message(status: i32) -> Option<Vec<u8>> {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCopyErrorMessageString(
            status: i32,
            reserved: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringGetCString(
            the_string: *const std::ffi::c_void,
            buffer: *mut std::ffi::c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
        fn CFRelease(cf: *const std::ffi::c_void);
    }

    let cf = unsafe { SecCopyErrorMessageString(status, std::ptr::null()) };
    if cf.is_null() {
        return None;
    }
    let mut buf = vec![0i8; 1024];
    let ok = unsafe {
        CFStringGetCString(
            cf,
            buf.as_mut_ptr(),
            buf.len() as isize,
            K_CFSTRING_ENCODING_UTF8,
        )
    } != 0;
    unsafe { CFRelease(cf) };
    if !ok {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(buf[..end].iter().map(|&b| b as u8).collect())
}

#[cfg(not(target_os = "macos"))]
fn host_sec_error_message(status: i32) -> Option<Vec<u8>> {
    Some(format!("OSStatus {}", status).into_bytes())
}

#[cfg(target_os = "macos")]
fn host_sec_item_copy_matching(query: u64) -> (i32, u64) {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecItemCopyMatching(
            query: *const std::ffi::c_void,
            result: *mut *const std::ffi::c_void,
        ) -> i32;
    }

    let mut result = std::ptr::null();
    let status = unsafe {
        SecItemCopyMatching(
            query as *const std::ffi::c_void,
            &mut result as *mut *const std::ffi::c_void,
        )
    };
    (status, result as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_sec_item_copy_matching(_query: u64) -> (i32, u64) {
    (-50, 0)
}

#[cfg(target_os = "macos")]
fn host_sec_keychain_copy_default() -> (i32, u64) {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainCopyDefault(keychain: *mut *mut std::ffi::c_void) -> i32;
    }

    let mut keychain = std::ptr::null_mut();
    let status = unsafe { SecKeychainCopyDefault(&mut keychain) };
    (status, keychain as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_sec_keychain_copy_default() -> (i32, u64) {
    (-25307, 0)
}

#[cfg(target_os = "macos")]
fn host_sec_keychain_open(path: &[u8]) -> (i32, u64) {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainOpen(
            path_name: *const std::ffi::c_char,
            keychain: *mut *mut std::ffi::c_void,
        ) -> i32;
    }

    let Ok(path) = std::ffi::CString::new(path) else {
        return (-50, 0);
    };
    let mut keychain = std::ptr::null_mut();
    let status = unsafe { SecKeychainOpen(path.as_ptr(), &mut keychain) };
    (status, keychain as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_sec_keychain_open(_path: &[u8]) -> (i32, u64) {
    (-25294, 0)
}

#[cfg(target_os = "macos")]
fn host_sec_keychain_get_path(keychain: u64) -> (i32, Vec<u8>) {
    if keychain == 0 {
        return (-50, Vec::new());
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainGetPath(
            keychain: *mut std::ffi::c_void,
            io_path_length: *mut u32,
            path_name: *mut std::ffi::c_char,
        ) -> i32;
    }

    let mut len = 4096u32;
    let mut buf = vec![0i8; len as usize];
    let status = unsafe {
        SecKeychainGetPath(
            keychain as *mut std::ffi::c_void,
            &mut len,
            buf.as_mut_ptr(),
        )
    };
    if status != 0 {
        return (status, Vec::new());
    }
    let capped_len = (len as usize).min(buf.len());
    let nul = buf[..capped_len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(capped_len);
    (
        status,
        buf[..nul]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>(),
    )
}

#[cfg(not(target_os = "macos"))]
fn host_sec_keychain_get_path(_keychain: u64) -> (i32, Vec<u8>) {
    (-50, Vec::new())
}

struct HostGenericPasswordResult {
    status: i32,
    password: Vec<u8>,
    item: u64,
}

#[cfg(target_os = "macos")]
fn host_sec_keychain_find_generic_password(
    keychain: u64,
    service: &[u8],
    account: &[u8],
) -> HostGenericPasswordResult {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainFindGenericPassword(
            keychain_or_array: *mut std::ffi::c_void,
            service_name_length: u32,
            service_name: *const std::ffi::c_char,
            account_name_length: u32,
            account_name: *const std::ffi::c_char,
            password_length: *mut u32,
            password_data: *mut *mut std::ffi::c_void,
            item_ref: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn SecKeychainItemFreeContent(
            attr_list: *const std::ffi::c_void,
            data: *mut std::ffi::c_void,
        ) -> i32;
    }

    let mut password_len = 0u32;
    let mut password_data = std::ptr::null_mut();
    let mut item_ref = std::ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            keychain as *mut std::ffi::c_void,
            service.len().min(u32::MAX as usize) as u32,
            service.as_ptr() as *const std::ffi::c_char,
            account.len().min(u32::MAX as usize) as u32,
            account.as_ptr() as *const std::ffi::c_char,
            &mut password_len,
            &mut password_data,
            &mut item_ref,
        )
    };
    let password = if status == 0 && !password_data.is_null() && password_len <= 1024 * 1024 {
        unsafe { std::slice::from_raw_parts(password_data as *const u8, password_len as usize) }
            .to_vec()
    } else {
        Vec::new()
    };
    if !password_data.is_null() {
        let _ = unsafe { SecKeychainItemFreeContent(std::ptr::null(), password_data) };
    }
    HostGenericPasswordResult {
        status,
        password,
        item: item_ref as u64,
    }
}

#[cfg(not(target_os = "macos"))]
fn host_sec_keychain_find_generic_password(
    _keychain: u64,
    _service: &[u8],
    _account: &[u8],
) -> HostGenericPasswordResult {
    HostGenericPasswordResult {
        status: -25300,
        password: Vec::new(),
        item: 0,
    }
}

#[cfg(target_os = "macos")]
fn host_cf_release(cf: u64) {
    if cf == 0 {
        return;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(cf: *const std::ffi::c_void);
    }
    unsafe { CFRelease(cf as *const std::ffi::c_void) };
}

#[cfg(not(target_os = "macos"))]
fn host_cf_release(_cf: u64) {}

#[cfg(target_os = "macos")]
fn host_cf_retain(cf: u64) -> u64 {
    if cf == 0 {
        return 0;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRetain(cf: *const std::ffi::c_void) -> *const std::ffi::c_void;
    }
    unsafe { CFRetain(cf as *const std::ffi::c_void) as u64 }
}

#[cfg(target_os = "macos")]
fn host_cfstring_to_bytes(cf: u64) -> Option<Vec<u8>> {
    if cf == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringGetCString(
            the_string: *const std::ffi::c_void,
            buffer: *mut std::ffi::c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
    }

    let mut buf = vec![0i8; 16 * 1024];
    let ok = unsafe {
        CFStringGetCString(
            cf as *const std::ffi::c_void,
            buf.as_mut_ptr(),
            buf.len() as isize,
            K_CFSTRING_ENCODING_UTF8,
        )
    } != 0;
    if !ok {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(buf[..end].iter().map(|&b| b as u8).collect())
}

#[cfg(not(target_os = "macos"))]
fn host_cfstring_to_bytes(_cf: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfstring_create_from_bytes(bytes: &[u8]) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithBytes(
            alloc: *const std::ffi::c_void,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external_representation: u8,
        ) -> *const std::ffi::c_void;
    }
    let ptr = unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as isize,
            K_CFSTRING_ENCODING_UTF8,
            0,
        )
    };
    (!ptr.is_null()).then_some(ptr as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfstring_create_from_bytes(_bytes: &[u8]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfurl_create_with_file_system_path(
    path: &[u8],
    path_style: u64,
    is_directory: bool,
) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFURLCreateWithFileSystemPath(
            allocator: *const std::ffi::c_void,
            file_path: *const std::ffi::c_void,
            path_style: isize,
            is_directory: u8,
        ) -> *const std::ffi::c_void;
    }

    let cf_path = host_cfstring_create_from_bytes(path)?;
    let url = unsafe {
        CFURLCreateWithFileSystemPath(
            std::ptr::null(),
            cf_path as *const std::ffi::c_void,
            path_style as isize,
            is_directory as u8,
        )
    };
    host_cf_release(cf_path);
    (!url.is_null()).then_some(url as u64)
}

#[cfg(target_os = "macos")]
fn host_cfurl_copy_file_system_path(url: u64, path_style: u64) -> Option<Vec<u8>> {
    if url == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFURLCopyFileSystemPath(
            an_url: *const std::ffi::c_void,
            path_style: isize,
        ) -> *const std::ffi::c_void;
    }

    let cf_string =
        unsafe { CFURLCopyFileSystemPath(url as *const std::ffi::c_void, path_style as isize) };
    if cf_string.is_null() {
        return None;
    }
    let bytes = host_cfstring_to_bytes(cf_string as u64);
    host_cf_release(cf_string as u64);
    bytes
}

#[cfg(target_os = "macos")]
fn host_cfurl_create_with_string(url: &[u8]) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFURLCreateWithString(
            allocator: *const std::ffi::c_void,
            url_string: *const std::ffi::c_void,
            base_url: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
    let cf_url_string = host_cfstring_create_from_bytes(url)?;
    let cf_url = unsafe {
        CFURLCreateWithString(
            std::ptr::null(),
            cf_url_string as *const std::ffi::c_void,
            std::ptr::null(),
        )
    };
    host_cf_release(cf_url_string);
    (!cf_url.is_null()).then_some(cf_url as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfurl_create_with_string(_url: &[u8]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cf_bundle_get_main_bundle() -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFBundleGetMainBundle() -> *const std::ffi::c_void;
    }
    let bundle = unsafe { CFBundleGetMainBundle() };
    (!bundle.is_null()).then_some(bundle as u64)
}

#[cfg(target_os = "macos")]
fn host_cf_bundle_copy_bundle_url(bundle: u64) -> Option<(u64, Vec<u8>)> {
    if bundle == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFBundleCopyBundleURL(bundle: *const std::ffi::c_void) -> *const std::ffi::c_void;
    }
    let url = unsafe { CFBundleCopyBundleURL(bundle as *const std::ffi::c_void) };
    if url.is_null() {
        return None;
    }
    let path =
        host_cfurl_copy_file_system_path(url as u64, K_CFURL_POSIX_PATH_STYLE).unwrap_or_default();
    Some((url as u64, path))
}

#[cfg(target_os = "macos")]
fn host_cfdata_to_bytes(cf: u64) -> Option<Vec<u8>> {
    if cf == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDataGetLength(data: *const std::ffi::c_void) -> isize;
        fn CFDataGetBytePtr(data: *const std::ffi::c_void) -> *const u8;
    }
    let len = unsafe { CFDataGetLength(cf as *const std::ffi::c_void) };
    if len < 0 || len as usize > 8 * 1024 * 1024 {
        return None;
    }
    let ptr = unsafe { CFDataGetBytePtr(cf as *const std::ffi::c_void) };
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() && len > 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(slice.to_vec())
}

#[cfg(not(target_os = "macos"))]
fn host_cfdata_to_bytes(_cf: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfdata_create_from_bytes(bytes: &[u8]) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDataCreate(
            allocator: *const std::ffi::c_void,
            bytes: *const u8,
            length: isize,
        ) -> *const std::ffi::c_void;
    }
    let data = unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize) };
    (!data.is_null()).then_some(data as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfdata_create_from_bytes(_bytes: &[u8]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfarray_create(values: &[u64]) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayCreate(
            allocator: *const std::ffi::c_void,
            values: *const *const std::ffi::c_void,
            num_values: isize,
            callbacks: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
    let host_values = values
        .iter()
        .map(|value| *value as *const std::ffi::c_void)
        .collect::<Vec<_>>();
    let array = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            host_values.as_ptr(),
            host_values.len() as isize,
            std::ptr::null(),
        )
    };
    (!array.is_null()).then_some(array as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfarray_create(_values: &[u64]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfdictionary_create(entries: &[(u64, u64)]) -> Option<u64> {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryCreate(
            allocator: *const std::ffi::c_void,
            keys: *const *const std::ffi::c_void,
            values: *const *const std::ffi::c_void,
            num_values: isize,
            key_callbacks: *const std::ffi::c_void,
            value_callbacks: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
    let keys = entries
        .iter()
        .map(|(key, _)| *key as *const std::ffi::c_void)
        .collect::<Vec<_>>();
    let values = entries
        .iter()
        .map(|(_, value)| *value as *const std::ffi::c_void)
        .collect::<Vec<_>>();
    let dict = unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            entries.len() as isize,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    (!dict.is_null()).then_some(dict as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfdictionary_create(_entries: &[(u64, u64)]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfarray_get_count(array: u64) -> Option<usize> {
    if array == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayGetCount(the_array: *const std::ffi::c_void) -> isize;
    }
    let count = unsafe { CFArrayGetCount(array as *const std::ffi::c_void) };
    (count >= 0).then_some(count as usize)
}

#[cfg(not(target_os = "macos"))]
fn host_cfarray_get_count(_array: u64) -> Option<usize> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfarray_get_value_at_index(array: u64, index: usize) -> Option<u64> {
    if array == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayGetCount(the_array: *const std::ffi::c_void) -> isize;
        fn CFArrayGetValueAtIndex(
            the_array: *const std::ffi::c_void,
            idx: isize,
        ) -> *const std::ffi::c_void;
    }
    let count = unsafe { CFArrayGetCount(array as *const std::ffi::c_void) };
    if count < 0 || index >= count as usize {
        return None;
    }
    let value = unsafe { CFArrayGetValueAtIndex(array as *const std::ffi::c_void, index as isize) };
    (!value.is_null()).then_some(value as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfarray_get_value_at_index(_array: u64, _index: usize) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfdictionary_get_count(dict: u64) -> Option<usize> {
    if dict == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryGetCount(the_dict: *const std::ffi::c_void) -> isize;
    }
    let count = unsafe { CFDictionaryGetCount(dict as *const std::ffi::c_void) };
    (count >= 0).then_some(count as usize)
}

#[cfg(not(target_os = "macos"))]
fn host_cfdictionary_get_count(_dict: u64) -> Option<usize> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfdictionary_get_value(dict: u64, key: u64) -> Option<u64> {
    if dict == 0 || key == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryGetValue(
            the_dict: *const std::ffi::c_void,
            key: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
    let value = unsafe {
        CFDictionaryGetValue(
            dict as *const std::ffi::c_void,
            key as *const std::ffi::c_void,
        )
    };
    (!value.is_null()).then_some(value as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_cfdictionary_get_value(_dict: u64, _key: u64) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_cfnumber_to_i64(cf: u64) -> Option<i64> {
    if cf == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFNumberGetValue(
            number: *const std::ffi::c_void,
            the_type: i32,
            value_ptr: *mut std::ffi::c_void,
        ) -> u8;
    }
    const K_CFNUMBER_SINT64_TYPE: i32 = 4;
    let mut out = 0i64;
    let ok = unsafe {
        CFNumberGetValue(
            cf as *const std::ffi::c_void,
            K_CFNUMBER_SINT64_TYPE,
            (&mut out as *mut i64).cast(),
        )
    } != 0;
    ok.then_some(out)
}

#[cfg(target_os = "macos")]
fn host_cfboolean_to_bool(cf: u64) -> Option<bool> {
    if cf == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFBooleanGetValue(boolean: *const std::ffi::c_void) -> u8;
    }
    Some(unsafe { CFBooleanGetValue(cf as *const std::ffi::c_void) != 0 })
}

#[cfg(target_os = "macos")]
fn host_cf_type_ids() -> (u64, u64, u64, u64) {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringGetTypeID() -> u64;
        fn CFDataGetTypeID() -> u64;
        fn CFNumberGetTypeID() -> u64;
        fn CFBooleanGetTypeID() -> u64;
    }
    unsafe {
        (
            CFStringGetTypeID(),
            CFDataGetTypeID(),
            CFNumberGetTypeID(),
            CFBooleanGetTypeID(),
        )
    }
}

#[cfg(target_os = "macos")]
fn host_cf_get_type_id(cf: u64) -> Option<u64> {
    if cf == 0 {
        return None;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFGetTypeID(cf: *const std::ffi::c_void) -> u64;
    }
    Some(unsafe { CFGetTypeID(cf as *const std::ffi::c_void) })
}

#[cfg(target_os = "macos")]
fn host_iokit_io_service_matching(name: &str) -> Option<u64> {
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceMatching(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    }
    let name = std::ffi::CString::new(name).ok()?;
    let dict = unsafe { IOServiceMatching(name.as_ptr()) };
    (!dict.is_null()).then_some(dict as u64)
}

#[cfg(target_os = "macos")]
fn host_iokit_io_service_get_matching_service(master_port: u64, matching: u64) -> u64 {
    if matching == 0 {
        return 0;
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceGetMatchingService(
            master_port: std::ffi::c_uint,
            matching: *mut std::ffi::c_void,
        ) -> std::ffi::c_uint;
    }
    unsafe {
        IOServiceGetMatchingService(
            master_port as std::ffi::c_uint,
            matching as *mut std::ffi::c_void,
        ) as u64
    }
}

#[cfg(target_os = "macos")]
fn host_iokit_io_service_get_matching_services(
    master_port: u64,
    matching: u64,
) -> Option<(i32, u64)> {
    if matching == 0 {
        return Some((-536_870_206, 0));
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceGetMatchingServices(
            master_port: std::ffi::c_uint,
            matching: *mut std::ffi::c_void,
            existing: *mut std::ffi::c_uint,
        ) -> std::ffi::c_int;
    }
    let mut iterator = 0u32;
    let kr = unsafe {
        IOServiceGetMatchingServices(
            master_port as std::ffi::c_uint,
            matching as *mut std::ffi::c_void,
            &mut iterator,
        )
    };
    Some((kr, iterator as u64))
}

#[cfg(target_os = "macos")]
fn host_iokit_io_iterator_next(iterator: u64) -> u64 {
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOIteratorNext(iterator: std::ffi::c_uint) -> std::ffi::c_uint;
    }
    unsafe { IOIteratorNext(iterator as std::ffi::c_uint) as u64 }
}

#[cfg(target_os = "macos")]
fn host_iokit_io_registry_entry_create_cf_property(
    entry: u64,
    key: &[u8],
    options: u64,
) -> Option<u64> {
    if entry == 0 {
        return None;
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IORegistryEntryCreateCFProperty(
            entry: std::ffi::c_uint,
            key: *const std::ffi::c_void,
            allocator: *const std::ffi::c_void,
            options: std::ffi::c_uint,
        ) -> *mut std::ffi::c_void;
    }
    let cf_key = host_cfstring_create_from_bytes(key)?;
    let value = unsafe {
        IORegistryEntryCreateCFProperty(
            entry as std::ffi::c_uint,
            cf_key as *const std::ffi::c_void,
            std::ptr::null(),
            options as std::ffi::c_uint,
        )
    };
    host_cf_release(cf_key);
    (!value.is_null()).then_some(value as u64)
}

#[cfg(target_os = "macos")]
fn host_iokit_io_object_release(object: u64) -> i32 {
    if object == 0 {
        return 0;
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOObjectRelease(object: std::ffi::c_uint) -> std::ffi::c_int;
    }
    unsafe { IOObjectRelease(object as std::ffi::c_uint) }
}

#[cfg(target_os = "macos")]
fn host_io_notification_port_create(master_port: u64) -> Option<u64> {
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IONotificationPortCreate(master_port: std::ffi::c_uint) -> *mut std::ffi::c_void;
    }

    let port = unsafe { IONotificationPortCreate(master_port as std::ffi::c_uint) };
    (!port.is_null()).then_some(port as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_io_notification_port_create(_master_port: u64) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_io_notification_port_destroy(port: u64) {
    if port == 0 {
        return;
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IONotificationPortDestroy(port: *mut std::ffi::c_void);
    }
    unsafe { IONotificationPortDestroy(port as *mut std::ffi::c_void) };
}

#[cfg(not(target_os = "macos"))]
fn host_cfurl_create_with_file_system_path(
    _path: &[u8],
    _path_style: u64,
    _is_directory: bool,
) -> Option<u64> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_cfurl_copy_file_system_path(_url: u64, _path_style: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_cf_bundle_get_main_bundle() -> Option<u64> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_cf_bundle_copy_bundle_url(_bundle: u64) -> Option<(u64, Vec<u8>)> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_service_matching(_name: &str) -> Option<u64> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_service_get_matching_service(_master_port: u64, _matching: u64) -> u64 {
    0
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_service_get_matching_services(
    _master_port: u64,
    _matching: u64,
) -> Option<(i32, u64)> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_iterator_next(_iterator: u64) -> u64 {
    0
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_registry_entry_create_cf_property(
    _entry: u64,
    _key: &[u8],
    _options: u64,
) -> Option<u64> {
    None
}

#[cfg(not(target_os = "macos"))]
fn host_iokit_io_object_release(_object: u64) -> i32 {
    0
}

#[cfg(not(target_os = "macos"))]
fn host_io_notification_port_destroy(_port: u64) {}

#[cfg(target_os = "macos")]
fn host_objc_class_lookup(symbol: &str, name: &str) -> Option<u64> {
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn objc_lookUpClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn objc_getMetaClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    }
    let class_name = name.to_string();
    let name = std::ffi::CString::new(name).ok()?;
    let mut class = unsafe {
        match symbol {
            "objc_lookUpClass" => objc_lookUpClass(name.as_ptr()),
            "objc_getMetaClass" => objc_getMetaClass(name.as_ptr()),
            _ => objc_getClass(name.as_ptr()),
        }
    };
    if class.is_null() {
        host_load_framework_for_objc_class(&class_name);
        class = unsafe {
            match symbol {
                "objc_lookUpClass" => objc_lookUpClass(name.as_ptr()),
                "objc_getMetaClass" => objc_getMetaClass(name.as_ptr()),
                _ => objc_getClass(name.as_ptr()),
            }
        };
    }
    (!class.is_null()).then_some(class as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_objc_class_lookup(_symbol: &str, _name: &str) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_load_framework_for_objc_class(name: &str) {
    let path = if name.starts_with("AVCapture")
        || name.starts_with("AVAudio")
        || name.starts_with("AVAsset")
        || name.starts_with("AVMedia")
    {
        Some("/System/Library/Frameworks/AVFoundation.framework/AVFoundation")
    } else if name.starts_with("SCScreen")
        || name.starts_with("SCShareableContent")
        || name.starts_with("SCStream")
    {
        Some("/System/Library/Frameworks/ScreenCaptureKit.framework/ScreenCaptureKit")
    } else {
        None
    };
    let Some(path) = path else {
        return;
    };
    let Ok(path) = std::ffi::CString::new(path) else {
        return;
    };
    unsafe {
        let _ = libc::dlopen(path.as_ptr(), libc::RTLD_NOW);
    }
}

#[cfg(target_os = "macos")]
fn host_object_get_class(object: u64) -> Option<u64> {
    if object == 0 {
        return None;
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        fn object_getClass(object: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    let class = unsafe { object_getClass(object as *mut std::ffi::c_void) };
    (!class.is_null()).then_some(class as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_object_get_class(_object: u64) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_class_get_name(class: u64) -> Option<Vec<u8>> {
    if class == 0 {
        return None;
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        fn class_getName(class: *mut std::ffi::c_void) -> *const std::ffi::c_char;
    }
    let name = unsafe { class_getName(class as *mut std::ffi::c_void) };
    if name.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_bytes()
            .to_vec(),
    )
}

#[cfg(not(target_os = "macos"))]
fn host_class_get_name(_class: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn host_sel_register_name(name: &str) -> Option<u64> {
    #[link(name = "objc")]
    unsafe extern "C" {
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    }
    let name = std::ffi::CString::new(name).ok()?;
    let selector = unsafe { sel_registerName(name.as_ptr()) };
    (!selector.is_null()).then_some(selector as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_sel_register_name(_name: &str) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_sel_get_name(selector: u64) -> Option<Vec<u8>> {
    if selector == 0 {
        return None;
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        fn sel_getName(selector: *mut std::ffi::c_void) -> *const std::ffi::c_char;
    }
    let name = unsafe { sel_getName(selector as *mut std::ffi::c_void) };
    if name.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_bytes()
            .to_vec(),
    )
}

#[cfg(not(target_os = "macos"))]
fn host_sel_get_name(_selector: u64) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn host_objc_autorelease_pool_push() -> u64 {
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_autoreleasePoolPush() -> *mut std::ffi::c_void;
    }
    unsafe { objc_autoreleasePoolPush() as u64 }
}

#[cfg(not(target_os = "macos"))]
fn host_objc_autorelease_pool_push() -> u64 {
    0
}

#[cfg(target_os = "macos")]
fn host_objc_autorelease_pool_pop(pool: u64) {
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_autoreleasePoolPop(pool: *mut std::ffi::c_void);
    }
    unsafe { objc_autoreleasePoolPop(pool as *mut std::ffi::c_void) };
}

#[cfg(not(target_os = "macos"))]
fn host_objc_autorelease_pool_pop(_pool: u64) {}

#[cfg(target_os = "macos")]
fn host_objc_alloc(class: u64, init: bool) -> Option<u64> {
    if class == 0 {
        return None;
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_alloc(class: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn objc_alloc_init(class: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    let object = unsafe {
        if init {
            objc_alloc_init(class as *mut std::ffi::c_void)
        } else {
            objc_alloc(class as *mut std::ffi::c_void)
        }
    };
    (!object.is_null()).then_some(object as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_objc_alloc(_class: u64, _init: bool) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_objc_msg_send(receiver: u64, selector: u64, args: &[u64; 6]) -> Option<u64> {
    if receiver == 0 || selector == 0 {
        return Some(0);
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn objc_msg_send_6(
            receiver: *mut std::ffi::c_void,
            selector: *mut std::ffi::c_void,
            arg0: usize,
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            arg5: usize,
        ) -> usize;
    }
    Some(unsafe {
        objc_msg_send_6(
            receiver as *mut std::ffi::c_void,
            selector as *mut std::ffi::c_void,
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        ) as u64
    })
}

#[cfg(not(target_os = "macos"))]
fn host_objc_msg_send(_receiver: u64, _selector: u64, _args: &[u64; 6]) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_foundation_no_arg_object(symbol: &str) -> Option<u64> {
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSHomeDirectory() -> *const std::ffi::c_void;
        fn NSTemporaryDirectory() -> *const std::ffi::c_void;
        fn NSUserName() -> *const std::ffi::c_void;
        fn NSFullUserName() -> *const std::ffi::c_void;
    }
    let object = unsafe {
        match symbol {
            "NSHomeDirectory" => NSHomeDirectory(),
            "NSTemporaryDirectory" => NSTemporaryDirectory(),
            "NSUserName" => NSUserName(),
            "NSFullUserName" => NSFullUserName(),
            _ => std::ptr::null(),
        }
    };
    (!object.is_null())
        .then(|| host_cf_retain(object as u64))
        .filter(|object| *object != 0)
}

#[cfg(not(target_os = "macos"))]
fn host_foundation_no_arg_object(_symbol: &str) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_ns_search_path_for_directories_in_domains(
    directory: u64,
    domains: u64,
    expand_tilde: bool,
) -> Option<u64> {
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSSearchPathForDirectoriesInDomains(
            directory: usize,
            domain_mask: usize,
            expand_tilde: u8,
        ) -> *const std::ffi::c_void;
    }
    let array = unsafe {
        NSSearchPathForDirectoriesInDomains(
            directory as usize,
            domains as usize,
            expand_tilde as u8,
        )
    };
    (!array.is_null())
        .then(|| host_cf_retain(array as u64))
        .filter(|array| *array != 0)
}

#[cfg(not(target_os = "macos"))]
fn host_ns_search_path_for_directories_in_domains(
    _directory: u64,
    _domains: u64,
    _expand_tilde: bool,
) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn host_ns_class_from_string(name: u64) -> Option<u64> {
    if name == 0 {
        return None;
    }
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSClassFromString(name: *const std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    let class = unsafe { NSClassFromString(name as *const std::ffi::c_void) };
    (!class.is_null()).then_some(class as u64)
}

#[cfg(not(target_os = "macos"))]
fn host_ns_class_from_string(_name: u64) -> Option<u64> {
    None
}

fn objc_selector_returns_raw_value(selector: &str) -> bool {
    matches!(
        selector,
        "length"
            | "count"
            | "hash"
            | "retainCount"
            | "integerValue"
            | "intValue"
            | "longLongValue"
            | "unsignedIntegerValue"
            | "boolValue"
            | "setActivationPolicy:"
            | "activationPolicy"
            | "isRunning"
            | "isActive"
            | "isHidden"
            | "isMainThread"
            | "isMultiThreaded"
            | "runMode:beforeDate:"
            | "canBecomeKeyWindow"
            | "canBecomeMainWindow"
            | "isVisible"
            | "respondsToSelector:"
            | "instancesRespondToSelector:"
            | "isKindOfClass:"
            | "isMemberOfClass:"
            | "isEqual:"
            | "isEqualToString:"
            | "containsObject:"
            | "isProxy"
            | "authorizationStatusForMediaType:"
            | "isConnected"
            | "hasMediaType:"
            | "supportsAVCaptureSessionPreset:"
            | "canAddInput:"
            | "canAddOutput:"
            | "prepareToRecord"
            | "record"
            | "isRecording"
    )
}

fn objc_symbol_is_identity_return(symbol: &str) -> bool {
    matches!(
        symbol,
        "objc_retain"
            | "objc_autorelease"
            | "objc_retainAutorelease"
            | "objc_retainAutoreleasedReturnValue"
            | "objc_retainAutoreleaseReturnValue"
            | "objc_autoreleaseReturnValue"
            | "objc_unsafeClaimAutoreleasedReturnValue"
            | "objc_opt_self"
    )
}

fn register_host_cf_value(
    runtime: &mut crate::macos::AppleRuntime,
    cf: u64,
    fallback_kind: &str,
) -> u64 {
    register_host_cf_value_with_ownership(runtime, cf, fallback_kind, true)
}

fn register_borrowed_host_cf_value(
    runtime: &mut crate::macos::AppleRuntime,
    cf: u64,
    fallback_kind: &str,
) -> u64 {
    register_host_cf_value_with_ownership(runtime, cf, fallback_kind, false)
}

fn register_host_cf_value_with_ownership(
    runtime: &mut crate::macos::AppleRuntime,
    cf: u64,
    fallback_kind: &str,
    owned: bool,
) -> u64 {
    if cf == 0 {
        return 0;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = owned;
    #[cfg(target_os = "macos")]
    {
        let Some(type_id) = host_cf_get_type_id(cf) else {
            return runtime.register_host_opaque(fallback_kind, cf);
        };
        let (string_type, data_type, number_type, boolean_type) = host_cf_type_ids();
        if type_id == string_type {
            if let Some(data) = host_cfstring_to_bytes(cf) {
                if owned {
                    host_cf_release(cf);
                }
                return runtime.alloc_string(data, K_CFSTRING_ENCODING_UTF8 as u64);
            }
        } else if type_id == data_type {
            if let Some(data) = host_cfdata_to_bytes(cf) {
                if owned {
                    host_cf_release(cf);
                }
                return runtime.alloc_data(data);
            }
        } else if type_id == number_type {
            if let Some(value) = host_cfnumber_to_i64(cf) {
                if owned {
                    host_cf_release(cf);
                }
                return runtime.alloc_number(value);
            }
        } else if type_id == boolean_type {
            if let Some(value) = host_cfboolean_to_bool(cf) {
                if owned {
                    host_cf_release(cf);
                }
                return runtime.alloc_boolean(value);
            }
        }
    }
    runtime.register_host_opaque(fallback_kind, cf)
}

fn runtime_cf_type_id_or_host(runtime: &crate::macos::AppleRuntime, cf: u64) -> u64 {
    let synthetic = runtime.type_id(cf);
    if synthetic != 0 {
        return synthetic;
    }

    #[cfg(target_os = "macos")]
    {
        runtime
            .host_ptr_or_raw_unknown(cf)
            .and_then(host_cf_get_type_id)
            .unwrap_or(0)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = runtime;
        let _ = cf;
        0
    }
}

fn runtime_object_data_or_host_cfstring(
    runtime: &crate::macos::AppleRuntime,
    handle: u64,
) -> Option<Vec<u8>> {
    runtime.object_data(handle).or_else(|| {
        runtime
            .host_ptr_or_raw_unknown(handle)
            .and_then(host_cfstring_to_bytes)
    })
}

fn runtime_object_data_or_host_foundation(
    runtime: &crate::macos::AppleRuntime,
    handle: u64,
) -> Option<Vec<u8>> {
    runtime.object_data(handle).or_else(|| {
        let host_ptr = runtime.host_ptr_or_raw_unknown(handle)?;
        match runtime.objc_object_kind(handle).as_deref() {
            Some("NSData") => host_cfdata_to_bytes(host_ptr),
            Some("NSURL") => host_cfurl_copy_file_system_path(host_ptr, K_CFURL_POSIX_PATH_STYLE),
            Some("NSString") => host_cfstring_to_bytes(host_ptr),
            _ => host_cfstring_to_bytes(host_ptr).or_else(|| host_cfdata_to_bytes(host_ptr)),
        }
    })
}

fn runtime_value_to_host_arg(runtime: &crate::macos::AppleRuntime, value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    runtime.host_ptr_or_raw_unknown(value).unwrap_or(0)
}

fn export_runtime_cstring(
    emu: &mut crate::UnicornEmulator,
    runtime: &mut crate::macos::AppleRuntime,
    bytes: &[u8],
) -> u64 {
    let mut out = bytes.to_vec();
    if !out.ends_with(&[0]) {
        out.push(0);
    }
    runtime.export_bytes(emu, &out).unwrap_or(0)
}

fn register_objc_result(
    runtime: &mut crate::macos::AppleRuntime,
    selector_name: &str,
    result: u64,
) -> u64 {
    if result == 0 || result < 0x10000 || objc_selector_returns_raw_value(selector_name) {
        return result;
    }
    runtime.register_host_objc_object(format!("objc_msgSend:{}", selector_name), result)
}

struct ObjcMsgSendShimResult {
    result: u64,
    shim: &'static str,
    host_proxy: bool,
    preview: Option<Vec<u8>>,
}

fn make_foundation_string_result(
    runtime: &mut crate::macos::AppleRuntime,
    data: Vec<u8>,
) -> (u64, bool) {
    if let Some(host_string) = host_cfstring_create_from_bytes(&data) {
        (
            runtime.register_host_objc_object("NSString", host_string),
            true,
        )
    } else {
        (
            runtime.alloc_string(data, K_CFSTRING_ENCODING_UTF8 as u64),
            false,
        )
    }
}

fn make_foundation_data_result(
    runtime: &mut crate::macos::AppleRuntime,
    data: Vec<u8>,
) -> (u64, bool) {
    if let Some(host_data) = host_cfdata_create_from_bytes(&data) {
        (runtime.register_host_objc_object("NSData", host_data), true)
    } else {
        (runtime.alloc_data(data), false)
    }
}

fn guest_path_bytes(path: impl AsRef<Path>) -> Vec<u8> {
    path.as_ref()
        .to_string_lossy()
        .replace('\\', "/")
        .into_bytes()
}

fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

fn env_value_bytes(keys: &[&str], fallback: &str) -> Vec<u8> {
    keys.iter()
        .find_map(|key| env::var_os(key))
        .map(|value| value.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_else(|| fallback.as_bytes().to_vec())
}

fn foundation_home_dir_bytes() -> Vec<u8> {
    env_value_bytes(&["HOME", "USERPROFILE"], "/Users/guest")
}

fn foundation_temp_dir_bytes() -> Vec<u8> {
    guest_path_bytes(env::temp_dir())
}

fn foundation_user_name_bytes() -> Vec<u8> {
    env_value_bytes(&["USER", "USERNAME", "LOGNAME"], "guest")
}

fn foundation_host_name_bytes() -> Vec<u8> {
    env_value_bytes(&["HOSTNAME", "COMPUTERNAME"], "localhost")
}

fn foundation_current_dir_bytes() -> Vec<u8> {
    env::current_dir()
        .map(guest_path_bytes)
        .unwrap_or_else(|_| b"/".to_vec())
}

fn runtime_process_name_string(runtime: &crate::macos::AppleRuntime) -> String {
    let raw = runtime.process_name().unwrap_or("main");
    Path::new(raw)
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(raw)
        .to_string()
}

fn runtime_executable_path_bytes(runtime: &crate::macos::AppleRuntime) -> Vec<u8> {
    let raw = runtime.process_name().unwrap_or("main");
    let path = Path::new(raw);
    if path.is_absolute() || raw.contains('/') || raw.contains('\\') {
        return raw.replace('\\', "/").into_bytes();
    }
    env::current_dir()
        .map(|cwd| guest_path_bytes(cwd.join(raw)))
        .unwrap_or_else(|_| raw.as_bytes().to_vec())
}

fn runtime_bundle_path_bytes(runtime: &crate::macos::AppleRuntime) -> Vec<u8> {
    let executable = String::from_utf8_lossy(&runtime_executable_path_bytes(runtime)).into_owned();
    let executable_path = Path::new(&executable);
    if let Some(bundle) = executable_path.ancestors().find(|ancestor| {
        ancestor
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(".app"))
            .unwrap_or(false)
    }) {
        return guest_path_bytes(bundle);
    }
    executable_path
        .parent()
        .map(guest_path_bytes)
        .unwrap_or_else(foundation_current_dir_bytes)
}

fn bundle_path_for_receiver(runtime: &crate::macos::AppleRuntime, receiver_ref: u64) -> Vec<u8> {
    runtime
        .bundle_path(receiver_ref)
        .unwrap_or_else(|| runtime_bundle_path_bytes(runtime))
}

fn bundle_resource_path_for_receiver(
    runtime: &crate::macos::AppleRuntime,
    receiver_ref: u64,
) -> Vec<u8> {
    let bundle =
        String::from_utf8_lossy(&bundle_path_for_receiver(runtime, receiver_ref)).into_owned();
    if bundle.ends_with(".app") {
        guest_path_bytes(Path::new(&bundle).join("Contents").join("Resources"))
    } else {
        bundle.into_bytes()
    }
}

fn bundle_executable_path_for_receiver(
    runtime: &crate::macos::AppleRuntime,
    receiver_ref: u64,
) -> Vec<u8> {
    let bundle =
        String::from_utf8_lossy(&bundle_path_for_receiver(runtime, receiver_ref)).into_owned();
    if bundle.ends_with(".app") {
        guest_path_bytes(
            Path::new(&bundle)
                .join("Contents")
                .join("MacOS")
                .join(runtime_process_name_string(runtime)),
        )
    } else {
        runtime_executable_path_bytes(runtime)
    }
}

fn runtime_bundle_identifier_bytes(runtime: &crate::macos::AppleRuntime) -> Vec<u8> {
    let mut name = runtime_process_name_string(runtime)
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>();
    while name.contains("..") {
        name = name.replace("..", ".");
    }
    format!("compatra.compat.{}", name.trim_matches('.')).into_bytes()
}

fn foundation_globally_unique_bytes(runtime: &crate::macos::AppleRuntime) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{}-{}",
        runtime_process_name_string(runtime),
        std::process::id(),
        now
    )
    .into_bytes()
}

fn foundation_search_path(directory: u64, domain: u64, expand_tilde: bool) -> PathBuf {
    let user_home = String::from_utf8_lossy(&foundation_home_dir_bytes()).into_owned();
    let user_prefix = if expand_tilde {
        PathBuf::from(&user_home)
    } else {
        PathBuf::from("~")
    };
    let system_prefix = match domain {
        8 => PathBuf::from("/System"),
        2 => PathBuf::from("/"),
        _ => user_prefix.clone(),
    };
    match directory {
        1 => system_prefix.join("Applications"),
        5 => {
            if domain == 1 {
                user_prefix.join("Library")
            } else {
                system_prefix.join("Library")
            }
        }
        9 => user_prefix.join("Documents"),
        12 => user_prefix.join("Desktop"),
        13 => user_prefix.join("Library").join("Caches"),
        14 => user_prefix.join("Library").join("Application Support"),
        15 => user_prefix.join("Downloads"),
        17 => user_prefix.join("Movies"),
        18 => user_prefix.join("Music"),
        19 => user_prefix.join("Pictures"),
        21 => PathBuf::from("/Users/Shared"),
        102 => user_prefix.join(".Trash"),
        _ => user_prefix,
    }
}

fn foundation_search_paths(directory: u64, domains: u64, expand_tilde: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for domain in [1u64, 2, 8] {
        if domains == 0 || domains & domain != 0 {
            let path = foundation_search_path(directory, domain, expand_tilde);
            if !out.iter().any(|existing| existing == &path) {
                out.push(path);
            }
        }
    }
    if out.is_empty() {
        out.push(foundation_search_path(directory, 1, expand_tilde));
    }
    out
}

fn make_foundation_array_result(
    runtime: &mut crate::macos::AppleRuntime,
    values: Vec<u64>,
) -> (u64, bool) {
    let host_values = values
        .iter()
        .map(|value| runtime_value_to_host_arg(runtime, *value))
        .collect::<Vec<_>>();
    let host_array = host_values
        .iter()
        .all(|value| *value != 0)
        .then(|| host_cfarray_create(&host_values))
        .flatten();
    (
        runtime.alloc_array_with_values_and_host(values, host_array),
        host_array.is_some(),
    )
}

fn make_foundation_dictionary_result(
    runtime: &mut crate::macos::AppleRuntime,
    entries: Vec<(u64, u64)>,
) -> (u64, bool) {
    let host_entries = entries
        .iter()
        .map(|(key, value)| {
            (
                runtime_value_to_host_arg(runtime, *key),
                runtime_value_to_host_arg(runtime, *value),
            )
        })
        .collect::<Vec<_>>();
    let host_dict = host_entries
        .iter()
        .all(|(key, value)| *key != 0 && *value != 0)
        .then(|| host_cfdictionary_create(&host_entries))
        .flatten();
    (
        runtime.alloc_dictionary_with_host(entries, host_dict),
        host_dict.is_some(),
    )
}

fn make_foundation_strings_array_result(
    runtime: &mut crate::macos::AppleRuntime,
    strings: Vec<Vec<u8>>,
) -> (u64, bool) {
    let values = strings
        .into_iter()
        .map(|data| make_foundation_string_result(runtime, data).0)
        .collect::<Vec<_>>();
    make_foundation_array_result(runtime, values)
}

fn make_foundation_url_result(
    runtime: &mut crate::macos::AppleRuntime,
    path: Vec<u8>,
    is_directory: bool,
) -> (u64, bool) {
    let host_url =
        host_cfurl_create_with_file_system_path(&path, K_CFURL_POSIX_PATH_STYLE, is_directory);
    (runtime.alloc_url(path, host_url), host_url.is_some())
}

fn make_foundation_environment_result(runtime: &mut crate::macos::AppleRuntime) -> (u64, bool) {
    let entries = env::vars_os()
        .take(1024)
        .map(|(key, value)| {
            let key_ref = make_foundation_string_result(
                runtime,
                key.to_string_lossy().into_owned().into_bytes(),
            )
            .0;
            let value_ref = make_foundation_string_result(
                runtime,
                value.to_string_lossy().into_owned().into_bytes(),
            )
            .0;
            (key_ref, value_ref)
        })
        .collect::<Vec<_>>();
    make_foundation_dictionary_result(runtime, entries)
}

fn make_foundation_bundle_info_result(runtime: &mut crate::macos::AppleRuntime) -> (u64, bool) {
    let values = [
        (
            b"CFBundleExecutable".to_vec(),
            runtime_process_name_string(runtime).into_bytes(),
        ),
        (
            b"CFBundleIdentifier".to_vec(),
            runtime_bundle_identifier_bytes(runtime),
        ),
        (
            b"CFBundleName".to_vec(),
            runtime_process_name_string(runtime).into_bytes(),
        ),
        (b"CFBundlePackageType".to_vec(), b"APPL".to_vec()),
    ];
    let entries = values
        .into_iter()
        .map(|(key, value)| {
            let key_ref = make_foundation_string_result(runtime, key).0;
            let value_ref = make_foundation_string_result(runtime, value).0;
            (key_ref, value_ref)
        })
        .collect::<Vec<_>>();
    make_foundation_dictionary_result(runtime, entries)
}

fn make_foundation_file_attributes_result(
    runtime: &mut crate::macos::AppleRuntime,
    metadata: &fs::Metadata,
) -> (u64, bool) {
    let file_type = if metadata.is_dir() {
        b"NSFileTypeDirectory".to_vec()
    } else {
        b"NSFileTypeRegular".to_vec()
    };
    let size_key = make_foundation_string_result(runtime, b"NSFileSize".to_vec()).0;
    let type_key = make_foundation_string_result(runtime, b"NSFileType".to_vec()).0;
    let size_value = runtime.alloc_number(metadata.len() as i64);
    let type_value = make_foundation_string_result(runtime, file_type).0;
    make_foundation_dictionary_result(
        runtime,
        vec![(size_key, size_value), (type_key, type_value)],
    )
}

fn dictionary_get_matching_key(
    runtime: &mut crate::macos::AppleRuntime,
    dict_ref: u64,
    key_ref: u64,
) -> Option<u64> {
    if let Some(value) = runtime.dictionary_get(dict_ref, key_ref) {
        return Some(value);
    }
    let needle = runtime_object_data_or_host_foundation(runtime, key_ref);
    if let (Some(needle), Some(entries)) = (needle, runtime.dictionary_entries(dict_ref)) {
        for (key, value) in entries {
            if runtime_object_data_or_host_foundation(runtime, key)
                .map(|candidate| candidate == needle)
                .unwrap_or(false)
            {
                return Some(value);
            }
        }
    }
    let host_dict = runtime.host_ptr_or_raw_unknown(dict_ref)?;
    let host_key = runtime_value_to_host_arg(runtime, key_ref);
    host_cfdictionary_get_value(host_dict, host_key)
        .map(|value| register_borrowed_host_cf_value(runtime, value, "NSDictionaryValue"))
}

fn clear_nserror_out(emu: &mut dyn Emulator, error_out: u64) {
    if error_out != 0 {
        let _ = emu.write_memory(error_out, &0u64.to_le_bytes());
    }
}

fn path_is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn synthetic_objc_class_known(name: &str) -> bool {
    matches!(
        name,
        "NSObject"
            | "NSString"
            | "NSMutableString"
            | "NSData"
            | "NSMutableData"
            | "NSArray"
            | "NSMutableArray"
            | "NSDictionary"
            | "NSMutableDictionary"
            | "NSNumber"
            | "NSDate"
            | "NSError"
            | "NSURL"
            | "NSBundle"
            | "NSProcessInfo"
            | "NSFileManager"
            | "NSApplication"
            | "NSThread"
            | "NSRunLoop"
            | "NSScreen"
            | "NSWindow"
    )
}

fn register_objc_class_lookup_result(
    runtime: &mut crate::macos::AppleRuntime,
    name: &str,
    host_class: Option<u64>,
) -> u64 {
    host_class
        .map(|host_class| runtime.register_host_objc_class(name.to_string(), host_class))
        .or_else(|| {
            synthetic_objc_class_known(name)
                .then(|| runtime.register_host_objc_class(name.to_string(), 0))
        })
        .unwrap_or(0)
}

fn foundation_shim_supports_selector(receiver_kind: &str, selector: &str) -> bool {
    matches!(
        (receiver_kind, selector),
        (_, "self")
            | (_, "class")
            | (_, "description")
            | (_, "respondsToSelector:")
            | ("NSString", "isEqualToString:")
            | ("NSString", "isEqual:")
            | ("NSProcessInfo", "processInfo")
            | ("NSProcessInfo", "arguments")
            | ("NSProcessInfo", "environment")
            | ("NSProcessInfo", "processName")
            | ("NSProcessInfo", "globallyUniqueString")
            | ("NSProcessInfo", "hostName")
            | ("NSProcessInfo", "userName")
            | ("NSProcessInfo", "fullUserName")
            | ("NSProcessInfo", "operatingSystemVersionString")
            | ("NSProcessInfo", "processorCount")
            | ("NSProcessInfo", "activeProcessorCount")
            | ("NSProcessInfo", "processIdentifier")
            | ("NSProcessInfo", "isOperatingSystemAtLeastVersion:")
            | ("NSApplication", "sharedApplication")
            | ("NSApplication", "setActivationPolicy:")
            | ("NSApplication", "activationPolicy")
            | ("NSApplication", "isRunning")
            | ("NSApplication", "isActive")
            | ("NSApplication", "isHidden")
            | ("NSApplication", "run")
            | ("NSApplication", "stop:")
            | ("NSApplication", "terminate:")
            | ("NSApplication", "setDelegate:")
            | ("NSApplication", "delegate")
            | ("NSApplication", "setMainMenu:")
            | ("NSThread", "mainThread")
            | ("NSThread", "currentThread")
            | ("NSThread", "isMainThread")
            | ("NSThread", "isMultiThreaded")
            | ("NSRunLoop", "currentRunLoop")
            | ("NSRunLoop", "mainRunLoop")
            | ("NSRunLoop", "runMode:beforeDate:")
            | ("NSRunLoop", "runUntilDate:")
            | ("NSDate", "date")
            | ("NSDate", "distantFuture")
            | ("NSDate", "distantPast")
            | ("NSScreen", "mainScreen")
            | ("NSScreen", "screens")
            | ("NSScreen", "localizedName")
            | ("NSScreen", "deviceDescription")
            | ("NSWindow", "init")
            | ("NSWindow", "title")
            | ("NSWindow", "setTitle:")
            | ("NSWindow", "orderFront:")
            | ("NSWindow", "makeKeyAndOrderFront:")
            | ("NSWindow", "close")
            | ("NSWindow", "canBecomeKeyWindow")
            | ("NSWindow", "canBecomeMainWindow")
            | ("NSWindow", "isVisible")
            | ("NSBundle", "mainBundle")
            | ("NSBundle", "bundleWithPath:")
            | ("NSBundle", "bundlePath")
            | ("NSBundle", "resourcePath")
            | ("NSBundle", "executablePath")
            | ("NSBundle", "privateFrameworksPath")
            | ("NSBundle", "sharedFrameworksPath")
            | ("NSBundle", "builtInPlugInsPath")
            | ("NSBundle", "bundleIdentifier")
            | ("NSBundle", "bundleURL")
            | ("NSBundle", "resourceURL")
            | ("NSBundle", "executableURL")
            | ("NSBundle", "infoDictionary")
            | ("NSBundle", "objectForInfoDictionaryKey:")
            | ("NSBundle", "pathForResource:ofType:")
            | ("NSBundle", "URLForResource:withExtension:")
            | ("NSBundle", "localizedStringForKey:value:table:")
            | ("NSFileManager", "defaultManager")
            | ("NSFileManager", "currentDirectoryPath")
            | ("NSFileManager", "homeDirectoryForCurrentUser")
            | ("NSFileManager", "temporaryDirectory")
            | ("NSFileManager", "fileExistsAtPath:")
            | ("NSFileManager", "fileExistsAtPath:isDirectory:")
            | ("NSFileManager", "isReadableFileAtPath:")
            | ("NSFileManager", "isWritableFileAtPath:")
            | ("NSFileManager", "isExecutableFileAtPath:")
            | ("NSFileManager", "contentsAtPath:")
            | ("NSFileManager", "contentsOfDirectoryAtPath:error:")
            | (
                "NSFileManager",
                "createDirectoryAtPath:withIntermediateDirectories:attributes:error:"
            )
            | ("NSFileManager", "removeItemAtPath:error:")
            | ("NSFileManager", "attributesOfItemAtPath:error:")
            | ("NSFileManager", "URLsForDirectory:inDomains:")
            | (
                "NSFileManager",
                "URLForDirectory:inDomain:appropriateForURL:create:error:"
            )
    )
}

fn dispatch_foundation_msg_send_shim(
    emu: &mut compatra_runtime::UnicornEmulator,
    apple_runtime: &Arc<Mutex<crate::macos::AppleRuntime>>,
    receiver_ref: u64,
    _selector_ref: u64,
    selector_name: &str,
) -> Option<ObjcMsgSendShimResult> {
    let receiver_kind = {
        let runtime = apple_runtime.lock().ok()?;
        runtime.objc_object_kind(receiver_ref).unwrap_or_default()
    };

    match selector_name {
        "self" => Some(ObjcMsgSendShimResult {
            result: receiver_ref,
            shim: "NSObjectSelf",
            host_proxy: false,
            preview: None,
        }),
        "alloc" | "new" if !receiver_kind.is_empty() => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_objc_object(receiver_kind.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSObjectAlloc",
                host_proxy: false,
                preview: Some(receiver_kind.as_bytes().to_vec()),
            })
        }
        "init" if !receiver_kind.is_empty() => Some(ObjcMsgSendShimResult {
            result: receiver_ref,
            shim: "NSObjectInit",
            host_proxy: false,
            preview: Some(receiver_kind.as_bytes().to_vec()),
        }),
        "class" if !receiver_kind.is_empty() => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let host_class = host_objc_class_lookup("objc_getClass", &receiver_kind);
                let result = host_class
                    .map(|host_class| {
                        runtime.register_host_objc_class(receiver_kind.clone(), host_class)
                    })
                    .unwrap_or_else(|| runtime.register_host_objc_class(receiver_kind.clone(), 0));
                (result, host_class.is_some())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSObjectClass",
                host_proxy,
                preview: Some(receiver_kind.as_bytes().to_vec()),
            })
        }
        "respondsToSelector:" => {
            let query_selector_ref = emu.read_reg("x2").unwrap_or(0);
            let query_selector_name = {
                let runtime = apple_runtime.lock().ok()?;
                let host_selector = runtime
                    .host_ptr_or_raw_unknown(query_selector_ref)
                    .unwrap_or(0);
                runtime
                    .objc_selector_name(query_selector_ref)
                    .or_else(|| {
                        (host_selector != 0)
                            .then(|| host_sel_get_name(host_selector))
                            .flatten()
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    })
                    .unwrap_or_default()
            };
            Some(ObjcMsgSendShimResult {
                result: foundation_shim_supports_selector(&receiver_kind, &query_selector_name)
                    as u64,
                shim: "NSObjectRespondsToSelector",
                host_proxy: false,
                preview: Some(query_selector_name.into_bytes()),
            })
        }
        "isEqualToString:" | "isEqual:" if receiver_kind == "NSString" => {
            let other_ref = emu.read_reg("x2").unwrap_or(0);
            let equal = {
                let runtime = apple_runtime.lock().ok()?;
                let left = runtime_object_data_or_host_foundation(&runtime, receiver_ref);
                let right = runtime_object_data_or_host_foundation(&runtime, other_ref);
                left.is_some() && left == right
            };
            Some(ObjcMsgSendShimResult {
                result: equal as u64,
                shim: "NSStringEqual",
                host_proxy: false,
                preview: None,
            })
        }
        "processInfo" if receiver_kind == "NSProcessInfo" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSProcessInfo")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoSingleton",
                host_proxy: false,
                preview: None,
            })
        }
        "defaultManager" if receiver_kind == "NSFileManager" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSFileManager")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerSingleton",
                host_proxy: false,
                preview: None,
            })
        }
        "mainBundle" if receiver_kind == "NSBundle" => {
            let (result, path) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let path = runtime_bundle_path_bytes(&runtime);
                let result = runtime.alloc_bundle(path.clone(), None);
                (result, path)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleMainBundle",
                host_proxy: false,
                preview: Some(path),
            })
        }
        "sharedApplication" if receiver_kind == "NSApplication" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSApplication")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSApplicationShared",
                host_proxy: false,
                preview: None,
            })
        }
        "setActivationPolicy:" if receiver_kind == "NSApplication" => Some(ObjcMsgSendShimResult {
            result: 1,
            shim: "NSApplicationSetActivationPolicy",
            host_proxy: false,
            preview: None,
        }),
        "activationPolicy" if receiver_kind == "NSApplication" => Some(ObjcMsgSendShimResult {
            result: 0,
            shim: "NSApplicationActivationPolicy",
            host_proxy: false,
            preview: None,
        }),
        "isRunning" | "isActive" | "isHidden" if receiver_kind == "NSApplication" => {
            Some(ObjcMsgSendShimResult {
                result: 0,
                shim: "NSApplicationStatePredicate",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "run" | "stop:" | "terminate:" | "setDelegate:" | "setMainMenu:"
            if receiver_kind == "NSApplication" =>
        {
            Some(ObjcMsgSendShimResult {
                result: 0,
                shim: "NSApplicationNoop",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "delegate" if receiver_kind == "NSApplication" => Some(ObjcMsgSendShimResult {
            result: 0,
            shim: "NSApplicationDelegate",
            host_proxy: false,
            preview: None,
        }),
        "mainThread" | "currentThread" if receiver_kind == "NSThread" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSThread")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSThreadSingleton",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "isMainThread" if receiver_kind == "NSThread" => Some(ObjcMsgSendShimResult {
            result: 1,
            shim: "NSThreadIsMain",
            host_proxy: false,
            preview: None,
        }),
        "isMultiThreaded" if receiver_kind == "NSThread" => Some(ObjcMsgSendShimResult {
            result: 0,
            shim: "NSThreadIsMultiThreaded",
            host_proxy: false,
            preview: None,
        }),
        "currentRunLoop" | "mainRunLoop" if receiver_kind == "NSRunLoop" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSRunLoop")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSRunLoopSingleton",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "runMode:beforeDate:" if receiver_kind == "NSRunLoop" => Some(ObjcMsgSendShimResult {
            result: 0,
            shim: "NSRunLoopRunMode",
            host_proxy: false,
            preview: None,
        }),
        "runUntilDate:" if receiver_kind == "NSRunLoop" => Some(ObjcMsgSendShimResult {
            result: 0,
            shim: "NSRunLoopRunUntilDate",
            host_proxy: false,
            preview: None,
        }),
        "date" | "distantFuture" | "distantPast" if receiver_kind == "NSDate" => {
            let absolute_time = match selector_name {
                "distantFuture" => 63_113_904_000.0,
                "distantPast" => -63_113_904_000.0,
                _ => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs_f64() - 978_307_200.0)
                    .unwrap_or(0.0),
            };
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_date(absolute_time)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSDateCreate",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "mainScreen" if receiver_kind == "NSScreen" => {
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.objc_singleton("NSScreen")
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSScreenMain",
                host_proxy: false,
                preview: None,
            })
        }
        "screens" if receiver_kind == "NSScreen" => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let screen = runtime.objc_singleton("NSScreen");
                make_foundation_array_result(&mut runtime, vec![screen])
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSScreenArray",
                host_proxy,
                preview: None,
            })
        }
        "localizedName" if receiver_kind == "NSScreen" => {
            let data = b"Compatibility Display".to_vec();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSScreenName",
                host_proxy,
                preview: Some(data),
            })
        }
        "deviceDescription" if receiver_kind == "NSScreen" => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let key = make_foundation_string_result(&mut runtime, b"NSScreenNumber".to_vec()).0;
                let value = runtime.alloc_number(1);
                make_foundation_dictionary_result(&mut runtime, vec![(key, value)])
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSScreenDeviceDescription",
                host_proxy,
                preview: None,
            })
        }
        "title" if receiver_kind == "NSWindow" => {
            let data = b"Compatibility Window".to_vec();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSWindowTitle",
                host_proxy,
                preview: Some(data),
            })
        }
        "setTitle:" | "orderFront:" | "makeKeyAndOrderFront:" | "close"
            if receiver_kind == "NSWindow" =>
        {
            Some(ObjcMsgSendShimResult {
                result: 0,
                shim: "NSWindowNoop",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "canBecomeKeyWindow" | "canBecomeMainWindow" | "isVisible"
            if receiver_kind == "NSWindow" =>
        {
            Some(ObjcMsgSendShimResult {
                result: 1,
                shim: "NSWindowPredicate",
                host_proxy: false,
                preview: Some(selector_name.as_bytes().to_vec()),
            })
        }
        "bundleWithPath:" if receiver_kind == "NSBundle" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref)
                    .unwrap_or_else(foundation_current_dir_bytes)
            };
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_bundle(path.clone(), None)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleWithPath",
                host_proxy: false,
                preview: Some(path),
            })
        }
        "stringWithUTF8String:" | "initWithUTF8String:" => {
            let cstr_ptr = emu.read_reg("x2").unwrap_or(0);
            let data = read_cstring(emu, cstr_ptr, 1024 * 1024)
                .unwrap_or_default()
                .into_bytes();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringCString",
                host_proxy,
                preview: Some(data),
            })
        }
        "stringWithCString:encoding:" | "initWithCString:encoding:" => {
            let cstr_ptr = emu.read_reg("x2").unwrap_or(0);
            let data = read_cstring(emu, cstr_ptr, 1024 * 1024)
                .unwrap_or_default()
                .into_bytes();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringCStringEncoding",
                host_proxy,
                preview: Some(data),
            })
        }
        "initWithBytes:length:encoding:" if receiver_kind == "NSString" => {
            let bytes_ptr = emu.read_reg("x2").unwrap_or(0);
            let len = emu.read_reg("x3").unwrap_or(0) as usize;
            let data = read_guest_bytes(emu, bytes_ptr, len, 1024 * 1024);
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringBytes",
                host_proxy,
                preview: Some(data),
            })
        }
        "stringWithFormat:" => {
            let format_ref = emu.read_reg("x2").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, format_ref).unwrap_or_default()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringFormatFallback",
                host_proxy,
                preview: Some(data),
            })
        }
        "UTF8String" | "cStringUsingEncoding:" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, receiver_ref)?
            };
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                export_runtime_cstring(emu, &mut runtime, &data)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringGuestCString",
                host_proxy: false,
                preview: Some(data),
            })
        }
        "dataUsingEncoding:" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, receiver_ref)?
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_data_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSStringDataUsingEncoding",
                host_proxy,
                preview: Some(data),
            })
        }
        "dataWithBytes:length:" | "initWithBytes:length:" => {
            let bytes_ptr = emu.read_reg("x2").unwrap_or(0);
            let len = emu.read_reg("x3").unwrap_or(0) as usize;
            let data = read_guest_bytes(emu, bytes_ptr, len, 8 * 1024 * 1024);
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_data_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSDataBytes",
                host_proxy,
                preview: Some(data),
            })
        }
        "bytes" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, receiver_ref)?
            };
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.export_bytes(emu, &data).unwrap_or(0)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSDataGuestBytes",
                host_proxy: false,
                preview: Some(data),
            })
        }
        "length" => {
            let len = {
                let runtime = apple_runtime.lock().ok()?;
                let data = runtime_object_data_or_host_foundation(&runtime, receiver_ref)?;
                if receiver_kind == "NSString" {
                    cf_string_len(&data)
                } else {
                    data.len() as u64
                }
            };
            Some(ObjcMsgSendShimResult {
                result: len,
                shim: "FoundationLength",
                host_proxy: false,
                preview: None,
            })
        }
        "count" => {
            let (count, host_proxy) = {
                let runtime = apple_runtime.lock().ok()?;
                let synthetic = runtime
                    .array_len(receiver_ref)
                    .or_else(|| runtime.dictionary_len(receiver_ref))
                    .map(|count| count as u64);
                if let Some(count) = synthetic {
                    (count, false)
                } else {
                    let host_ptr = runtime.host_ptr_or_raw_unknown(receiver_ref).unwrap_or(0);
                    let count = if receiver_kind == "NSDictionary" {
                        host_cfdictionary_get_count(host_ptr)
                    } else {
                        host_cfarray_get_count(host_ptr)
                    }
                    .unwrap_or(0) as u64;
                    (count, host_ptr != 0)
                }
            };
            Some(ObjcMsgSendShimResult {
                result: count,
                shim: "FoundationCount",
                host_proxy,
                preview: None,
            })
        }
        "objectAtIndex:" => {
            let index = emu.read_reg("x2").unwrap_or(0) as usize;
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                if let Some(value) = runtime.array_get(receiver_ref, index) {
                    (value, false)
                } else {
                    let host_array = runtime.host_ptr_or_raw_unknown(receiver_ref).unwrap_or(0);
                    let value = host_cfarray_get_value_at_index(host_array, index)
                        .map(|value| {
                            register_borrowed_host_cf_value(&mut runtime, value, "NSArrayValue")
                        })
                        .unwrap_or(0);
                    (value, host_array != 0)
                }
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSArrayObjectAtIndex",
                host_proxy,
                preview: None,
            })
        }
        "objectForKey:" => {
            let key_ref = emu.read_reg("x2").unwrap_or(0);
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let host_dict = runtime.host_ptr_or_raw_unknown(receiver_ref).unwrap_or(0);
                (
                    dictionary_get_matching_key(&mut runtime, receiver_ref, key_ref).unwrap_or(0),
                    host_dict != 0,
                )
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSDictionaryObjectForKey",
                host_proxy,
                preview: None,
            })
        }
        "arrayWithObjects:count:" => {
            let values_ptr = emu.read_reg("x2").unwrap_or(0);
            let count = emu.read_reg("x3").unwrap_or(0) as usize;
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let host_values = {
                let runtime = apple_runtime.lock().ok()?;
                values
                    .iter()
                    .map(|value| runtime_value_to_host_arg(&runtime, *value))
                    .filter(|value| *value != 0)
                    .collect::<Vec<_>>()
            };
            let host_array = (host_values.len() == values.len())
                .then(|| host_cfarray_create(&host_values))
                .flatten();
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_array_with_values_and_host(values, host_array)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSArrayCreate",
                host_proxy: host_array.is_some(),
                preview: None,
            })
        }
        "dictionaryWithObjects:forKeys:count:" => {
            let values_ptr = emu.read_reg("x2").unwrap_or(0);
            let keys_ptr = emu.read_reg("x3").unwrap_or(0);
            let count = emu.read_reg("x4").unwrap_or(0) as usize;
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let keys = read_guest_u64_array(emu, keys_ptr, count, 4096);
            let entries = keys.into_iter().zip(values).collect::<Vec<_>>();
            let host_entries = {
                let runtime = apple_runtime.lock().ok()?;
                entries
                    .iter()
                    .map(|(key, value)| {
                        (
                            runtime_value_to_host_arg(&runtime, *key),
                            runtime_value_to_host_arg(&runtime, *value),
                        )
                    })
                    .filter(|(key, value)| *key != 0 && *value != 0)
                    .collect::<Vec<_>>()
            };
            let host_dict = (host_entries.len() == entries.len())
                .then(|| host_cfdictionary_create(&host_entries))
                .flatten();
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_dictionary_with_host(entries, host_dict)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSDictionaryCreate",
                host_proxy: host_dict.is_some(),
                preview: None,
            })
        }
        "fileURLWithPath:" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let host_url =
                host_cfurl_create_with_file_system_path(&path, K_CFURL_POSIX_PATH_STYLE, false);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_url(path.clone(), host_url)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSURLFileURLWithPath",
                host_proxy: host_url.is_some(),
                preview: Some(path),
            })
        }
        "URLWithString:" => {
            let url_ref = emu.read_reg("x2").unwrap_or(0);
            let url = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, url_ref).unwrap_or_default()
            };
            let host_url = host_cfurl_create_with_string(&url);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_url(url.clone(), host_url)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSURLWithString",
                host_proxy: host_url.is_some(),
                preview: Some(url),
            })
        }
        "path" | "absoluteString" if receiver_kind == "NSURL" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, receiver_ref).unwrap_or_default()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSURLStringProperty",
                host_proxy,
                preview: Some(data),
            })
        }
        "numberWithInt:"
        | "numberWithInteger:"
        | "numberWithLongLong:"
        | "numberWithUnsignedInteger:"
        | "numberWithBool:" => {
            let value = emu.read_reg("x2").unwrap_or(0) as i64;
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_number(value)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSNumberCreate",
                host_proxy: false,
                preview: None,
            })
        }
        "integerValue" | "intValue" | "longLongValue" | "unsignedIntegerValue" | "boolValue" => {
            let value = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.number_value(receiver_ref).unwrap_or(0) as u64
            };
            Some(ObjcMsgSendShimResult {
                result: value,
                shim: "NSNumberValue",
                host_proxy: false,
                preview: None,
            })
        }
        "arguments" if receiver_kind == "NSProcessInfo" => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let args = vec![runtime_executable_path_bytes(&runtime)];
                make_foundation_strings_array_result(&mut runtime, args)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoArguments",
                host_proxy,
                preview: None,
            })
        }
        "environment" if receiver_kind == "NSProcessInfo" => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_environment_result(&mut runtime)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoEnvironment",
                host_proxy,
                preview: None,
            })
        }
        "processName" if receiver_kind == "NSProcessInfo" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_process_name_string(&runtime).into_bytes()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoProcessName",
                host_proxy,
                preview: Some(data),
            })
        }
        "globallyUniqueString" if receiver_kind == "NSProcessInfo" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                foundation_globally_unique_bytes(&runtime)
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoUniqueString",
                host_proxy,
                preview: Some(data),
            })
        }
        "hostName" if receiver_kind == "NSProcessInfo" => {
            let data = foundation_host_name_bytes();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoHostName",
                host_proxy,
                preview: Some(data),
            })
        }
        "userName" | "fullUserName" if receiver_kind == "NSProcessInfo" => {
            let data = foundation_user_name_bytes();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoUserName",
                host_proxy,
                preview: Some(data),
            })
        }
        "operatingSystemVersionString" if receiver_kind == "NSProcessInfo" => {
            let data = b"macOS compatibility host".to_vec();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSProcessInfoOSVersionString",
                host_proxy,
                preview: Some(data),
            })
        }
        "processorCount" | "activeProcessorCount" if receiver_kind == "NSProcessInfo" => {
            let count = std::thread::available_parallelism()
                .map(|count| count.get() as u64)
                .unwrap_or(1);
            Some(ObjcMsgSendShimResult {
                result: count,
                shim: "NSProcessInfoProcessorCount",
                host_proxy: true,
                preview: None,
            })
        }
        "processIdentifier" if receiver_kind == "NSProcessInfo" => Some(ObjcMsgSendShimResult {
            result: std::process::id() as u64,
            shim: "NSProcessInfoProcessIdentifier",
            host_proxy: true,
            preview: None,
        }),
        "isOperatingSystemAtLeastVersion:" if receiver_kind == "NSProcessInfo" => {
            Some(ObjcMsgSendShimResult {
                result: 1,
                shim: "NSProcessInfoOSAtLeast",
                host_proxy: false,
                preview: None,
            })
        }
        "bundlePath"
        | "resourcePath"
        | "executablePath"
        | "privateFrameworksPath"
        | "sharedFrameworksPath"
        | "builtInPlugInsPath"
            if receiver_kind == "NSBundle" =>
        {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                match selector_name {
                    "bundlePath" => bundle_path_for_receiver(&runtime, receiver_ref),
                    "resourcePath" => bundle_resource_path_for_receiver(&runtime, receiver_ref),
                    "executablePath" => bundle_executable_path_for_receiver(&runtime, receiver_ref),
                    "privateFrameworksPath" => {
                        let base = String::from_utf8_lossy(&bundle_path_for_receiver(
                            &runtime,
                            receiver_ref,
                        ))
                        .into_owned();
                        guest_path_bytes(Path::new(&base).join("Contents").join("Frameworks"))
                    }
                    "sharedFrameworksPath" => {
                        let base = String::from_utf8_lossy(&bundle_path_for_receiver(
                            &runtime,
                            receiver_ref,
                        ))
                        .into_owned();
                        guest_path_bytes(Path::new(&base).join("Contents").join("SharedFrameworks"))
                    }
                    _ => {
                        let base = String::from_utf8_lossy(&bundle_path_for_receiver(
                            &runtime,
                            receiver_ref,
                        ))
                        .into_owned();
                        guest_path_bytes(Path::new(&base).join("Contents").join("PlugIns"))
                    }
                }
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundlePathProperty",
                host_proxy,
                preview: Some(data),
            })
        }
        "bundleIdentifier" if receiver_kind == "NSBundle" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_bundle_identifier_bytes(&runtime)
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleIdentifier",
                host_proxy,
                preview: Some(data),
            })
        }
        "bundleURL" | "resourceURL" | "executableURL" if receiver_kind == "NSBundle" => {
            let (data, is_dir) = {
                let runtime = apple_runtime.lock().ok()?;
                match selector_name {
                    "bundleURL" => (bundle_path_for_receiver(&runtime, receiver_ref), true),
                    "resourceURL" => (
                        bundle_resource_path_for_receiver(&runtime, receiver_ref),
                        true,
                    ),
                    _ => (
                        bundle_executable_path_for_receiver(&runtime, receiver_ref),
                        false,
                    ),
                }
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_url_result(&mut runtime, data.clone(), is_dir)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleURLProperty",
                host_proxy,
                preview: Some(data),
            })
        }
        "infoDictionary" if receiver_kind == "NSBundle" => {
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_bundle_info_result(&mut runtime)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleInfoDictionary",
                host_proxy,
                preview: None,
            })
        }
        "objectForInfoDictionaryKey:" if receiver_kind == "NSBundle" => {
            let key_ref = emu.read_reg("x2").unwrap_or(0);
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let (dict_ref, host_proxy) = make_foundation_bundle_info_result(&mut runtime);
                (
                    dictionary_get_matching_key(&mut runtime, dict_ref, key_ref).unwrap_or(0),
                    host_proxy,
                )
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleInfoDictionaryLookup",
                host_proxy,
                preview: None,
            })
        }
        "pathForResource:ofType:" | "URLForResource:withExtension:"
            if receiver_kind == "NSBundle" =>
        {
            let name_ref = emu.read_reg("x2").unwrap_or(0);
            let ext_ref = emu.read_reg("x3").unwrap_or(0);
            let (path, is_url) = {
                let runtime = apple_runtime.lock().ok()?;
                let name =
                    runtime_object_data_or_host_foundation(&runtime, name_ref).unwrap_or_default();
                if name.is_empty() {
                    return Some(ObjcMsgSendShimResult {
                        result: 0,
                        shim: "NSBundleResourceLookup",
                        host_proxy: false,
                        preview: None,
                    });
                }
                let ext =
                    runtime_object_data_or_host_foundation(&runtime, ext_ref).unwrap_or_default();
                let mut file = String::from_utf8_lossy(&name).into_owned();
                if !ext.is_empty() {
                    file.push('.');
                    file.push_str(&String::from_utf8_lossy(&ext));
                }
                let base = String::from_utf8_lossy(&bundle_resource_path_for_receiver(
                    &runtime,
                    receiver_ref,
                ))
                .into_owned();
                (
                    guest_path_bytes(Path::new(&base).join(file)),
                    selector_name == "URLForResource:withExtension:",
                )
            };
            let exists = bytes_to_path(&path).exists();
            let (result, host_proxy) = if exists {
                let mut runtime = apple_runtime.lock().ok()?;
                if is_url {
                    make_foundation_url_result(&mut runtime, path.clone(), false)
                } else {
                    make_foundation_string_result(&mut runtime, path.clone())
                }
            } else {
                (0, false)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleResourceLookup",
                host_proxy,
                preview: Some(path),
            })
        }
        "localizedStringForKey:value:table:" if receiver_kind == "NSBundle" => {
            let key_ref = emu.read_reg("x2").unwrap_or(0);
            let value_ref = emu.read_reg("x3").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, value_ref)
                    .filter(|value| !value.is_empty())
                    .or_else(|| runtime_object_data_or_host_foundation(&runtime, key_ref))
                    .unwrap_or_default()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSBundleLocalizedString",
                host_proxy,
                preview: Some(data),
            })
        }
        "currentDirectoryPath" if receiver_kind == "NSFileManager" => {
            let data = foundation_current_dir_bytes();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerCurrentDirectory",
                host_proxy,
                preview: Some(data),
            })
        }
        "homeDirectoryForCurrentUser" | "temporaryDirectory"
            if receiver_kind == "NSFileManager" =>
        {
            let data = if selector_name == "homeDirectoryForCurrentUser" {
                foundation_home_dir_bytes()
            } else {
                foundation_temp_dir_bytes()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_url_result(&mut runtime, data.clone(), true)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerDirectoryURL",
                host_proxy,
                preview: Some(data),
            })
        }
        "fileExistsAtPath:"
        | "isReadableFileAtPath:"
        | "isWritableFileAtPath:"
        | "isExecutableFileAtPath:"
            if receiver_kind == "NSFileManager" =>
        {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let host_path = bytes_to_path(&path);
            let result = match selector_name {
                "fileExistsAtPath:" => host_path.exists(),
                "isReadableFileAtPath:" => fs::File::open(&host_path).is_ok(),
                "isWritableFileAtPath:" => {
                    fs::OpenOptions::new().write(true).open(&host_path).is_ok()
                }
                _ => path_is_executable(&host_path),
            } as u64;
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerPathPredicate",
                host_proxy: true,
                preview: Some(path),
            })
        }
        "fileExistsAtPath:isDirectory:" if receiver_kind == "NSFileManager" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let is_dir_out = emu.read_reg("x3").unwrap_or(0);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let metadata = fs::metadata(bytes_to_path(&path)).ok();
            let exists = metadata.is_some();
            let is_dir = metadata.map(|metadata| metadata.is_dir()).unwrap_or(false);
            let _ = write_guest_bool(emu, is_dir_out, is_dir);
            Some(ObjcMsgSendShimResult {
                result: exists as u64,
                shim: "NSFileManagerExistsIsDirectory",
                host_proxy: true,
                preview: Some(path),
            })
        }
        "contentsAtPath:" if receiver_kind == "NSFileManager" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let (result, host_proxy) = if let Ok(data) = fs::read(bytes_to_path(&path)) {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_data_result(&mut runtime, data)
            } else {
                (0, true)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerContentsAtPath",
                host_proxy,
                preview: Some(path),
            })
        }
        "contentsOfDirectoryAtPath:error:" if receiver_kind == "NSFileManager" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let error_out = emu.read_reg("x3").unwrap_or(0);
            clear_nserror_out(emu, error_out);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let names = fs::read_dir(bytes_to_path(&path))
                .ok()
                .map(|entries| {
                    entries
                        .flatten()
                        .take(4096)
                        .map(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .into_owned()
                                .into_bytes()
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_strings_array_result(&mut runtime, names)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerDirectoryContents",
                host_proxy,
                preview: Some(path),
            })
        }
        "createDirectoryAtPath:withIntermediateDirectories:attributes:error:"
            if receiver_kind == "NSFileManager" =>
        {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let intermediates = emu.read_reg("x3").unwrap_or(0) != 0;
            let error_out = emu.read_reg("x5").unwrap_or(0);
            clear_nserror_out(emu, error_out);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let host_path = bytes_to_path(&path);
            let ok = if intermediates {
                fs::create_dir_all(&host_path).is_ok()
            } else {
                fs::create_dir(&host_path).is_ok()
            };
            Some(ObjcMsgSendShimResult {
                result: ok as u64,
                shim: "NSFileManagerCreateDirectory",
                host_proxy: true,
                preview: Some(path),
            })
        }
        "removeItemAtPath:error:" if receiver_kind == "NSFileManager" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let error_out = emu.read_reg("x3").unwrap_or(0);
            clear_nserror_out(emu, error_out);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let host_path = bytes_to_path(&path);
            let ok = fs::remove_file(&host_path)
                .or_else(|_| fs::remove_dir_all(&host_path))
                .is_ok();
            Some(ObjcMsgSendShimResult {
                result: ok as u64,
                shim: "NSFileManagerRemoveItem",
                host_proxy: true,
                preview: Some(path),
            })
        }
        "attributesOfItemAtPath:error:" if receiver_kind == "NSFileManager" => {
            let path_ref = emu.read_reg("x2").unwrap_or(0);
            let error_out = emu.read_reg("x3").unwrap_or(0);
            clear_nserror_out(emu, error_out);
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, path_ref).unwrap_or_default()
            };
            let (result, host_proxy) = if let Ok(metadata) = fs::metadata(bytes_to_path(&path)) {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_file_attributes_result(&mut runtime, &metadata)
            } else {
                (0, true)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerAttributes",
                host_proxy,
                preview: Some(path),
            })
        }
        "URLsForDirectory:inDomains:" if receiver_kind == "NSFileManager" => {
            let directory = emu.read_reg("x2").unwrap_or(0);
            let domains = emu.read_reg("x3").unwrap_or(0);
            let paths = foundation_search_paths(directory, domains, true)
                .into_iter()
                .map(guest_path_bytes)
                .collect::<Vec<_>>();
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                let urls = paths
                    .iter()
                    .map(|path| make_foundation_url_result(&mut runtime, path.clone(), true).0)
                    .collect::<Vec<_>>();
                make_foundation_array_result(&mut runtime, urls)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerURLsForDirectory",
                host_proxy,
                preview: None,
            })
        }
        "URLForDirectory:inDomain:appropriateForURL:create:error:"
            if receiver_kind == "NSFileManager" =>
        {
            let directory = emu.read_reg("x2").unwrap_or(0);
            let domain = emu.read_reg("x3").unwrap_or(0);
            let create = emu.read_reg("x5").unwrap_or(0) != 0;
            let error_out = emu.read_reg("x6").unwrap_or(0);
            clear_nserror_out(emu, error_out);
            let path = guest_path_bytes(foundation_search_path(directory, domain, true));
            if create {
                let _ = fs::create_dir_all(bytes_to_path(&path));
            }
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_url_result(&mut runtime, path.clone(), true)
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSFileManagerURLForDirectory",
                host_proxy,
                preview: Some(path),
            })
        }
        "description" => {
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.describe(receiver_ref).into_bytes()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            Some(ObjcMsgSendShimResult {
                result,
                shim: "NSObjectDescription",
                host_proxy,
                preview: Some(data),
            })
        }
        _ => None,
    }
}

fn install_returning_hook<F>(
    emulator: &mut UnicornEmulator,
    addr: u64,
    handler: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn(&mut compatra_runtime::UnicornEmulator) -> u64 + Send + 'static,
{
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
            let result = handler(emu);
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
        },
    )?;
    Ok(())
}

fn dispatch_apple_import(
    emu: &mut compatra_runtime::UnicornEmulator,
    symbol: &str,
    apple_runtime: &Arc<Mutex<crate::macos::AppleRuntime>>,
    tracker: &Arm64ImportTracker,
    trace: &Option<SharedTraceBus>,
    metadata: &crate::macos::TraceMetadata,
) -> Option<u64> {
    match normalized_apple_symbol(symbol) {
        "CFStringCreateWithCString" => {
            let cstr_ptr = emu.read_reg("x1").unwrap_or(0);
            let encoding = emu.read_reg("x2").unwrap_or(0);
            let data = read_cstring(emu, cstr_ptr, 64 * 1024)
                .unwrap_or_default()
                .into_bytes();
            let string_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(data.clone(), encoding)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringCreateWithCString(cstr=0x{:X}, enc=0x{:X}) -> 0x{:X}",
                    cstr_ptr, encoding, string_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringCreateWithCString")
                    .arg("CString", format!("0x{:X}", cstr_ptr))
                    .arg("Encoding", format!("0x{:X}", encoding))
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", lossy_data_preview(&data, 128))
                    .arg("HostProxy", "true"),
            );
            Some(string_ref)
        }
        "CFStringGetLength" => {
            let string_ref = emu.read_reg("x0").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_cfstring(&runtime, string_ref)?
            };
            let len = cf_string_len(&data);
            record_arm64_import(
                tracker,
                format!("_CFStringGetLength(string=0x{:X}) -> {}", string_ref, len),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringGetLength")
                    .arg("String", format!("0x{:X}", string_ref))
                    .arg("Result", len.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(len)
        }
        "CFStringGetCString" => {
            let string_ref = emu.read_reg("x0").unwrap_or(0);
            let buffer = emu.read_reg("x1").unwrap_or(0);
            let capacity = emu.read_reg("x2").unwrap_or(0) as usize;
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_cfstring(&runtime, string_ref)?
            };
            let ok = write_guest_cstring(emu, buffer, capacity, &data);
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringGetCString(string=0x{:X}, buffer=0x{:X}, cap={}) -> {}",
                    string_ref, buffer, capacity, ok as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringGetCString")
                    .arg("String", format!("0x{:X}", string_ref))
                    .arg("Buffer", format!("0x{:X}", buffer))
                    .arg("Capacity", capacity.to_string())
                    .arg("Result", ok.to_string())
                    .arg("Preview", lossy_data_preview(&data, 128))
                    .arg("HostProxy", "true"),
            );
            Some(ok as u64)
        }
        "CFStringGetCStringPtr" => {
            let string_ref = emu.read_reg("x0").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_cfstring(&runtime, string_ref)?
            };
            let exported_ptr = {
                let mut runtime = apple_runtime.lock().ok()?;
                let mut bytes = data.clone();
                if !bytes.ends_with(&[0]) {
                    bytes.push(0);
                }
                runtime.export_bytes(emu, &bytes).unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringGetCStringPtr(string=0x{:X}) -> 0x{:X}",
                    string_ref, exported_ptr
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringGetCStringPtr")
                    .arg("String", format!("0x{:X}", string_ref))
                    .arg("Result", format!("0x{:X}", exported_ptr))
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(exported_ptr)
        }
        "CFStringCreateCopy" => {
            let string_ref = emu.read_reg("x1").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_cfstring(&runtime, string_ref)?
            };
            let copy_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(data.clone(), K_CFSTRING_ENCODING_UTF8 as u64)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringCreateCopy(string=0x{:X}) -> 0x{:X}",
                    string_ref, copy_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringCreateCopy")
                    .arg("String", format!("0x{:X}", string_ref))
                    .arg("Result", format!("0x{:X}", copy_ref))
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(copy_ref)
        }
        "CFStringCompare" => {
            let left_ref = emu.read_reg("x0").unwrap_or(0);
            let right_ref = emu.read_reg("x1").unwrap_or(0);
            let (left, right) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime_object_data_or_host_cfstring(&runtime, left_ref)?,
                    runtime_object_data_or_host_cfstring(&runtime, right_ref)?,
                )
            };
            let cmp = match left.cmp(&right) {
                std::cmp::Ordering::Less => -1i64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringCompare(left=0x{:X}, right=0x{:X}) -> {}",
                    left_ref, right_ref, cmp
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringCompare")
                    .arg("Left", format!("0x{:X}", left_ref))
                    .arg("Right", format!("0x{:X}", right_ref))
                    .arg("Result", cmp.to_string()),
            );
            Some(cmp as u64)
        }
        "CFStringCreateWithBytes" => {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let encoding = emu.read_reg("x3").unwrap_or(0);
            let data = read_guest_bytes(emu, bytes_ptr, len, 64 * 1024);
            let string_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(data.clone(), encoding)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringCreateWithBytes(bytes=0x{:X}, len={}, enc=0x{:X}) -> 0x{:X}",
                    bytes_ptr, len, encoding, string_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringCreateWithBytes")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Encoding", format!("0x{:X}", encoding))
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", lossy_data_preview(&data, 128))
                    .arg("HostProxy", "false"),
            );
            Some(string_ref)
        }
        "CFStringCreateExternalRepresentation" => {
            let string_ref = emu.read_reg("x1").unwrap_or(0);
            let data_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                let data = runtime.object_data(string_ref)?;
                runtime.alloc_data(data)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFStringCreateExternalRepresentation(string=0x{:X}) -> 0x{:X}",
                    string_ref, data_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfstring", "CFStringCreateExternalRepresentation")
                    .arg("String", format!("0x{:X}", string_ref))
                    .arg("Result", format!("0x{:X}", data_ref)),
            );
            Some(data_ref)
        }
        "CFStringGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.string_type_id();
            record_arm64_import(tracker, format!("_CFStringGetTypeID() -> 0x{:X}", type_id));
            Some(type_id)
        }
        "CFURLCreateWithFileSystemPath" => {
            let path_ref = emu.read_reg("x1").unwrap_or(0);
            let path_style = emu.read_reg("x2").unwrap_or(K_CFURL_POSIX_PATH_STYLE);
            let is_directory = emu.read_reg("x3").unwrap_or(0) != 0;
            let path = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_cfstring(&runtime, path_ref)?
            };
            let host_ptr = host_cfurl_create_with_file_system_path(&path, path_style, is_directory);
            let url_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_url(path.clone(), host_ptr)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFURLCreateWithFileSystemPath(path=0x{:X}, style={}, dir={}) -> 0x{:X}",
                    path_ref, path_style, is_directory, url_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfurl", "CFURLCreateWithFileSystemPath")
                    .arg("Path", format!("0x{:X}", path_ref))
                    .arg("PathStyle", path_style.to_string())
                    .arg("Directory", is_directory.to_string())
                    .arg("Result", format!("0x{:X}", url_ref))
                    .arg("HostProxy", host_ptr.is_some().to_string())
                    .arg("Preview", lossy_data_preview(&path, 128)),
            );
            Some(url_ref)
        }
        "CFURLCopyFileSystemPath" => {
            let url_ref = emu.read_reg("x0").unwrap_or(0);
            let path_style = emu.read_reg("x1").unwrap_or(K_CFURL_POSIX_PATH_STYLE);
            let (host_ptr, fallback_path) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(url_ref),
                    runtime.url_path(url_ref),
                )
            };
            let path = host_ptr
                .and_then(|host_ptr| host_cfurl_copy_file_system_path(host_ptr, path_style))
                .or(fallback_path)
                .unwrap_or_default();
            let string_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(path.clone(), K_CFSTRING_ENCODING_UTF8 as u64)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFURLCopyFileSystemPath(url=0x{:X}, style={}) -> 0x{:X}",
                    url_ref, path_style, string_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfurl", "CFURLCopyFileSystemPath")
                    .arg("Url", format!("0x{:X}", url_ref))
                    .arg("PathStyle", path_style.to_string())
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", lossy_data_preview(&path, 128)),
            );
            Some(string_ref)
        }
        "CFBundleGetMainBundle" => {
            let host_ptr = host_cf_bundle_get_main_bundle();
            let bundle_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                match host_ptr {
                    Some(host_ptr) => runtime.register_host_opaque("CFBundleMain", host_ptr),
                    None => runtime.alloc_opaque("CFBundleMain"),
                }
            };
            record_arm64_import(
                tracker,
                format!("_CFBundleGetMainBundle() -> 0x{:X}", bundle_ref),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfbundle", "CFBundleGetMainBundle")
                    .arg("Result", format!("0x{:X}", bundle_ref))
                    .arg("HostProxy", host_ptr.is_some().to_string()),
            );
            Some(bundle_ref)
        }
        "CFBundleCopyBundleURL" => {
            let bundle_ref = emu.read_reg("x0").unwrap_or(0);
            let host_bundle = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(bundle_ref).unwrap_or(0)
            };
            let host = host_cf_bundle_copy_bundle_url(host_bundle);
            let (host_ptr, path) = host.unwrap_or((0, Vec::new()));
            let url_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_url(path.clone(), (host_ptr != 0).then_some(host_ptr))
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFBundleCopyBundleURL(bundle=0x{:X}) -> 0x{:X}",
                    bundle_ref, url_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfbundle", "CFBundleCopyBundleURL")
                    .arg("Bundle", format!("0x{:X}", bundle_ref))
                    .arg("Result", format!("0x{:X}", url_ref))
                    .arg("HostProxy", (host_ptr != 0).to_string())
                    .arg("Preview", lossy_data_preview(&path, 128)),
            );
            Some(url_ref)
        }
        "CFDataCreate" => {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let data = read_guest_bytes(emu, bytes_ptr, len, 8 * 1024 * 1024);
            let data_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_data(data.clone())
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFDataCreate(bytes=0x{:X}, len={}) -> 0x{:X}",
                    bytes_ptr, len, data_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "cfdata", "CFDataCreate")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Result", format!("0x{:X}", data_ref))
                    .arg("Preview", lossy_data_preview(&data, 128))
                    .arg("HostProxy", "true"),
            );
            Some(data_ref)
        }
        "CFDataGetLength" => {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let len = apple_runtime.lock().ok()?.object_len(data_ref).unwrap_or(0) as u64;
            record_arm64_import(
                tracker,
                format!("_CFDataGetLength(data=0x{:X}) -> {}", data_ref, len),
            );
            Some(len)
        }
        "CFDataGetBytePtr" => {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let exported_ptr = {
                let mut runtime = apple_runtime.lock().ok()?;
                let data = runtime.object_data(data_ref)?;
                runtime.export_bytes(emu, &data).unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFDataGetBytePtr(data=0x{:X}) -> 0x{:X}",
                    data_ref, exported_ptr
                ),
            );
            Some(exported_ptr)
        }
        "CFDataGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.data_type_id();
            record_arm64_import(tracker, format!("_CFDataGetTypeID() -> 0x{:X}", type_id));
            Some(type_id)
        }
        "CFArrayCreateMutable" => {
            let array_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_array()
            };
            record_arm64_import(
                tracker,
                format!("_CFArrayCreateMutable() -> 0x{:X}", array_ref),
            );
            Some(array_ref)
        }
        "CFArrayCreate" => {
            let values_ptr = emu.read_reg("x1").unwrap_or(0);
            let count = emu.read_reg("x2").unwrap_or(0) as usize;
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let array_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_array_with_values(values)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFArrayCreate(values=0x{:X}, count={}) -> 0x{:X}",
                    values_ptr, count, array_ref
                ),
            );
            Some(array_ref)
        }
        "CFArrayAppendValue" => {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let value_ref = emu.read_reg("x1").unwrap_or(0);
            let ok = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.array_append(array_ref, value_ref)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFArrayAppendValue(array=0x{:X}, value=0x{:X}) ok={}",
                    array_ref, value_ref, ok
                ),
            );
            Some(0)
        }
        "CFArrayGetCount" => {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let count = apple_runtime.lock().ok()?.array_len(array_ref).unwrap_or(0) as u64;
            record_arm64_import(
                tracker,
                format!("_CFArrayGetCount(array=0x{:X}) -> {}", array_ref, count),
            );
            Some(count)
        }
        "CFArrayGetValueAtIndex" => {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let value_ref = apple_runtime
                .lock()
                .ok()?
                .array_get(array_ref, index)
                .unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_CFArrayGetValueAtIndex(array=0x{:X}, index={}) -> 0x{:X}",
                    array_ref, index, value_ref
                ),
            );
            Some(value_ref)
        }
        "CFArrayGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.array_type_id();
            record_arm64_import(tracker, format!("_CFArrayGetTypeID() -> 0x{:X}", type_id));
            Some(type_id)
        }
        "CFDictionaryCreate" => {
            let keys_ptr = emu.read_reg("x1").unwrap_or(0);
            let values_ptr = emu.read_reg("x2").unwrap_or(0);
            let count = emu.read_reg("x3").unwrap_or(0) as usize;
            let keys = read_guest_u64_array(emu, keys_ptr, count, 4096);
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let entries = keys.into_iter().zip(values).collect::<Vec<_>>();
            let (dict_ref, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_dictionary_result(&mut runtime, entries)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFDictionaryCreate(keys=0x{:X}, values=0x{:X}, count={}, host={}) -> 0x{:X}",
                    keys_ptr, values_ptr, count, host_proxy, dict_ref
                ),
            );
            Some(dict_ref)
        }
        "CFDictionaryGetValueIfPresent" => {
            let dict_ref = emu.read_reg("x0").unwrap_or(0);
            let key_ref = emu.read_reg("x1").unwrap_or(0);
            let value_out = emu.read_reg("x2").unwrap_or(0);
            let value_ref = apple_runtime
                .lock()
                .ok()?
                .dictionary_get(dict_ref, key_ref)
                .unwrap_or(0);
            let present = value_ref != 0;
            if present && value_out != 0 {
                let _ = emu.write_memory(value_out, &value_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_CFDictionaryGetValueIfPresent(dict=0x{:X}, key=0x{:X}, out=0x{:X}) -> {}",
                    dict_ref, key_ref, value_out, present as u64
                ),
            );
            Some(present as u64)
        }
        "CFDictionaryGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.dictionary_type_id();
            record_arm64_import(
                tracker,
                format!("_CFDictionaryGetTypeID() -> 0x{:X}", type_id),
            );
            Some(type_id)
        }
        "CFDateCreate" => {
            let absolute_time = f64::from_bits(emu.read_reg("x1").unwrap_or(0));
            let date_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_date(absolute_time)
            };
            record_arm64_import(
                tracker,
                format!("_CFDateCreate(abs={}) -> 0x{:X}", absolute_time, date_ref),
            );
            Some(date_ref)
        }
        "xpc_date_create_from_current" => {
            let date_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_date(0.0)
            };
            record_arm64_import(
                tracker,
                format!("_xpc_date_create_from_current() -> 0x{:X}", date_ref),
            );
            Some(date_ref)
        }
        "CFErrorCreate" => {
            let domain = emu.read_reg("x1").unwrap_or(0);
            let code = emu.read_reg("x2").unwrap_or(0) as i64;
            let error_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_error(code, format!("compatra synthetic error {}", code))
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFErrorCreate(domain=0x{:X}, code={}) -> 0x{:X}",
                    domain, code, error_ref
                ),
            );
            Some(error_ref)
        }
        "CFErrorGetCode" => {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let code = apple_runtime
                .lock()
                .ok()?
                .error_code(error_ref)
                .unwrap_or(0) as u64;
            record_arm64_import(
                tracker,
                format!("_CFErrorGetCode(error=0x{:X}) -> {}", error_ref, code),
            );
            Some(code)
        }
        "CFErrorCopyDescription" => {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let data = apple_runtime
                .lock()
                .ok()?
                .error_description(error_ref)
                .unwrap_or_else(|| "compatra synthetic error".to_string())
                .into_bytes();
            let string_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(data.clone(), K_CFSTRING_ENCODING_UTF8 as u64)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CFErrorCopyDescription(error=0x{:X}) -> 0x{:X}",
                    error_ref, string_ref
                ),
            );
            Some(string_ref)
        }
        "CFGetTypeID" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let type_id = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_cf_type_id_or_host(&runtime, object_ref)
            };
            record_arm64_import(
                tracker,
                format!("_CFGetTypeID(obj=0x{:X}) -> 0x{:X}", object_ref, type_id),
            );
            Some(type_id)
        }
        "CFNumberGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.number_type_id();
            record_arm64_import(tracker, format!("_CFNumberGetTypeID() -> 0x{:X}", type_id));
            Some(type_id)
        }
        "CFNumberGetValue" => {
            let number_ref = emu.read_reg("x0").unwrap_or(0);
            let number_type = emu.read_reg("x1").unwrap_or(0);
            let out_ptr = emu.read_reg("x2").unwrap_or(0);
            let value = apple_runtime
                .lock()
                .ok()?
                .number_value(number_ref)
                .unwrap_or(0);
            if out_ptr != 0 {
                let _ = emu.write_memory(out_ptr, &value.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_CFNumberGetValue(num=0x{:X}, type=0x{:X}, out=0x{:X}) -> 1",
                    number_ref, number_type, out_ptr
                ),
            );
            Some(1)
        }
        "CFBooleanGetTypeID" => {
            let type_id = apple_runtime.lock().ok()?.boolean_type_id();
            record_arm64_import(tracker, format!("_CFBooleanGetTypeID() -> 0x{:X}", type_id));
            Some(type_id)
        }
        "CFBooleanGetValue" => {
            let boolean_ref = emu.read_reg("x0").unwrap_or(0);
            let value = apple_runtime
                .lock()
                .ok()?
                .boolean_value(boolean_ref)
                .unwrap_or(false);
            record_arm64_import(
                tracker,
                format!(
                    "_CFBooleanGetValue(boolean=0x{:X}) -> {}",
                    boolean_ref, value as u64
                ),
            );
            Some(value as u64)
        }
        "SecRandomCopyBytes" => {
            let count = emu.read_reg("x1").unwrap_or(0) as usize;
            let out_ptr = emu.read_reg("x2").unwrap_or(0);
            let result: i32 = if out_ptr == 0 {
                -1
            } else if let Some(bytes) = host_sec_random_bytes(count) {
                if emu.write_memory(out_ptr, &bytes).is_ok() {
                    0
                } else {
                    -1
                }
            } else {
                -1
            };
            record_arm64_import(
                tracker,
                format!(
                    "_SecRandomCopyBytes(count={}, out=0x{:X}) -> {}",
                    count, out_ptr, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "secrandom", "SecRandomCopyBytes")
                    .arg("Count", count.to_string())
                    .arg("Out", format!("0x{:X}", out_ptr))
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "SecCopyErrorMessageString" => {
            let status = emu.read_reg("x0").unwrap_or(0) as i32;
            let data = host_sec_error_message(status)
                .unwrap_or_else(|| format!("OSStatus {}", status).into_bytes());
            let string_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_string(data.clone(), K_CFSTRING_ENCODING_UTF8 as u64)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_SecCopyErrorMessageString(status={}) -> 0x{:X}",
                    status, string_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "secerror", "SecCopyErrorMessageString")
                    .arg("Status", status.to_string())
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", lossy_data_preview(&data, 128))
                    .arg("HostProxy", "true"),
            );
            Some(string_ref)
        }
        "SecCertificateCreateWithData" => {
            let data_ref = emu.read_reg("x1").unwrap_or(0);
            let cert_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_certificate(data_ref)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_SecCertificateCreateWithData(data=0x{:X}) -> 0x{:X}",
                    data_ref, cert_ref
                ),
            );
            Some(cert_ref)
        }
        "SecCertificateCopyData" => {
            let cert_ref = emu.read_reg("x0").unwrap_or(0);
            let data_ref = apple_runtime
                .lock()
                .ok()?
                .certificate_data(cert_ref)
                .unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_SecCertificateCopyData(cert=0x{:X}) -> 0x{:X}",
                    cert_ref, data_ref
                ),
            );
            Some(data_ref)
        }
        "SecPolicyCreateSSL" => {
            let server = emu.read_reg("x0").unwrap_or(0) != 0;
            let hostname = emu.read_reg("x1").unwrap_or(0);
            let policy_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_policy_ssl(server, hostname)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_SecPolicyCreateSSL(server={}, hostname=0x{:X}) -> 0x{:X}",
                    server, hostname, policy_ref
                ),
            );
            Some(policy_ref)
        }
        "SecItemCopyMatching" => {
            let query_ref = emu.read_reg("x0").unwrap_or(0);
            let result_out = emu.read_reg("x1").unwrap_or(0);
            let host_query = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(query_ref).unwrap_or(0)
            };
            let (status, host_result) = if host_query != 0 {
                host_sec_item_copy_matching(host_query)
            } else {
                (-50, 0)
            };
            let result_ref = if status == 0 && host_result != 0 {
                let mut runtime = apple_runtime.lock().ok()?;
                register_host_cf_value_with_ownership(
                    &mut runtime,
                    host_result,
                    "SecItemResult",
                    true,
                )
            } else {
                if host_result != 0 {
                    host_cf_release(host_result);
                }
                0
            };
            if result_out != 0 {
                let _ = emu.write_memory(result_out, &result_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecItemCopyMatching(query=0x{:X}, host=0x{:X}, out=0x{:X}) -> {} result=0x{:X}",
                    query_ref, host_query, result_out, status, result_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "secitem", "SecItemCopyMatching")
                    .arg("Query", format!("0x{:X}", query_ref))
                    .arg("HostQuery", format!("0x{:X}", host_query))
                    .arg("ResultOut", format!("0x{:X}", result_out))
                    .arg("Result", status.to_string())
                    .arg("Item", format!("0x{:X}", result_ref))
                    .arg("HostProxy", (host_query != 0).to_string()),
            );
            Some(status as i64 as u64)
        }
        "SecKeychainCopyDefault" => {
            let keychain_out = emu.read_reg("x0").unwrap_or(0);
            let (status, host_keychain) = host_sec_keychain_copy_default();
            let keychain_ref = if status == 0 && host_keychain != 0 {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.register_host_opaque("SecKeychain", host_keychain)
            } else {
                0
            };
            if keychain_out != 0 {
                let _ = emu.write_memory(keychain_out, &keychain_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecKeychainCopyDefault(out=0x{:X}) -> {} keychain=0x{:X}",
                    keychain_out, status, keychain_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "seckeychain", "SecKeychainCopyDefault")
                    .arg("Out", format!("0x{:X}", keychain_out))
                    .arg("Result", status.to_string())
                    .arg("Keychain", format!("0x{:X}", keychain_ref))
                    .arg("HostProxy", "true"),
            );
            Some(status as i64 as u64)
        }
        "SecKeychainOpen" => {
            let path_ptr = emu.read_reg("x0").unwrap_or(0);
            let keychain_out = emu.read_reg("x1").unwrap_or(0);
            let path = read_cstring(emu, path_ptr, 4096)
                .unwrap_or_default()
                .into_bytes();
            let (status, host_keychain) = host_sec_keychain_open(&path);
            let keychain_ref = if status == 0 && host_keychain != 0 {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.register_host_opaque("SecKeychain", host_keychain)
            } else {
                0
            };
            if keychain_out != 0 {
                let _ = emu.write_memory(keychain_out, &keychain_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecKeychainOpen(path=0x{:X}, out=0x{:X}) -> {} keychain=0x{:X}",
                    path_ptr, keychain_out, status, keychain_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "seckeychain", "SecKeychainOpen")
                    .arg("Path", format!("0x{:X}", path_ptr))
                    .arg("Out", format!("0x{:X}", keychain_out))
                    .arg("Result", status.to_string())
                    .arg("Keychain", format!("0x{:X}", keychain_ref))
                    .arg("Preview", lossy_data_preview(&path, 256))
                    .arg("HostProxy", "true"),
            );
            Some(status as i64 as u64)
        }
        "SecKeychainGetPath" => {
            let keychain_ref = emu.read_reg("x0").unwrap_or(0);
            let length_ptr = emu.read_reg("x1").unwrap_or(0);
            let path_ptr = emu.read_reg("x2").unwrap_or(0);
            let host_keychain = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(keychain_ref).unwrap_or(0)
            };
            let (mut status, path) = host_sec_keychain_get_path(host_keychain);
            let capacity = read_guest_u32(emu, length_ptr).unwrap_or(0) as usize;
            if status == 0 {
                let _ = write_guest_u32(emu, length_ptr, path.len() as u32);
                if !write_guest_cstring(emu, path_ptr, capacity, &path) {
                    status = -50;
                }
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecKeychainGetPath(keychain=0x{:X}, host=0x{:X}, len=0x{:X}, path=0x{:X}) -> {}",
                    keychain_ref, host_keychain, length_ptr, path_ptr, status
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "seckeychain", "SecKeychainGetPath")
                    .arg("Keychain", format!("0x{:X}", keychain_ref))
                    .arg("HostKeychain", format!("0x{:X}", host_keychain))
                    .arg("LengthOut", format!("0x{:X}", length_ptr))
                    .arg("PathOut", format!("0x{:X}", path_ptr))
                    .arg("Capacity", capacity.to_string())
                    .arg("Result", status.to_string())
                    .arg("Preview", lossy_data_preview(&path, 256))
                    .arg("HostProxy", (host_keychain != 0).to_string()),
            );
            Some(status as i64 as u64)
        }
        "SecKeychainFindGenericPassword" => {
            let keychain_ref = emu.read_reg("x0").unwrap_or(0);
            let service_len = emu.read_reg("x1").unwrap_or(0) as usize;
            let service_ptr = emu.read_reg("x2").unwrap_or(0);
            let account_len = emu.read_reg("x3").unwrap_or(0) as usize;
            let account_ptr = emu.read_reg("x4").unwrap_or(0);
            let password_len_out = emu.read_reg("x5").unwrap_or(0);
            let password_data_out = emu.read_reg("x6").unwrap_or(0);
            let item_out = emu.read_reg("x7").unwrap_or(0);
            let service = read_guest_bytes(emu, service_ptr, service_len, 64 * 1024);
            let account = read_guest_bytes(emu, account_ptr, account_len, 64 * 1024);
            let host_keychain = if keychain_ref == 0 {
                0
            } else {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(keychain_ref).unwrap_or(0)
            };
            let result = host_sec_keychain_find_generic_password(host_keychain, &service, &account);
            let password_ptr = if result.status == 0 && !result.password.is_empty() {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.export_bytes(emu, &result.password).unwrap_or(0)
            } else {
                0
            };
            let item_ref = if result.status == 0 && result.item != 0 {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.register_host_opaque("SecKeychainItem", result.item)
            } else {
                0
            };
            let _ = write_guest_u32(emu, password_len_out, result.password.len() as u32);
            if password_data_out != 0 {
                let _ = emu.write_memory(password_data_out, &password_ptr.to_le_bytes());
            }
            if item_out != 0 {
                let _ = emu.write_memory(item_out, &item_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecKeychainFindGenericPassword(keychain=0x{:X}, service_len={}, account_len={}) -> {} password_len={} item=0x{:X}",
                    keychain_ref,
                    service_len,
                    account_len,
                    result.status,
                    result.password.len(),
                    item_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "seckeychain", "SecKeychainFindGenericPassword")
                    .arg("Keychain", format!("0x{:X}", keychain_ref))
                    .arg("HostKeychain", format!("0x{:X}", host_keychain))
                    .arg("Service", lossy_data_preview(&service, 128))
                    .arg("Account", lossy_data_preview(&account, 128))
                    .arg("PasswordLen", result.password.len().to_string())
                    .arg("PasswordOut", format!("0x{:X}", password_data_out))
                    .arg("PasswordGuestPtr", format!("0x{:X}", password_ptr))
                    .arg("Item", format!("0x{:X}", item_ref))
                    .arg("Result", result.status.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result.status as i64 as u64)
        }
        "SecKeychainItemFreeContent" => {
            let attr_list = emu.read_reg("x0").unwrap_or(0);
            let data = emu.read_reg("x1").unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_SecKeychainItemFreeContent(attrs=0x{:X}, data=0x{:X}) -> 0",
                    attr_list, data
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "seckeychain", "SecKeychainItemFreeContent")
                    .arg("Attributes", format!("0x{:X}", attr_list))
                    .arg("Data", format!("0x{:X}", data))
                    .arg("Result", "0")
                    .arg("HostProxy", "false")
                    .arg("Model", "guest-copy-cleanup"),
            );
            Some(0)
        }
        "SecTrustCreateWithCertificates" => {
            let certificates = emu.read_reg("x0").unwrap_or(0);
            let policies = emu.read_reg("x1").unwrap_or(0);
            let trust_out = emu.read_reg("x2").unwrap_or(0);
            let trust_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                runtime.alloc_trust(certificates, policies)
            };
            if trust_out != 0 {
                let _ = emu.write_memory(trust_out, &trust_ref.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecTrustCreateWithCertificates(certs=0x{:X}, policies=0x{:X}, out=0x{:X}) -> 0x{:X}",
                    certificates, policies, trust_out, trust_ref
                ),
            );
            Some(0)
        }
        "SecTrustEvaluateWithError" => {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let error_out = emu.read_reg("x1").unwrap_or(0);
            if error_out != 0 {
                let _ = emu.write_memory(error_out, &0u64.to_le_bytes());
            }
            record_arm64_import(
                tracker,
                format!(
                    "_SecTrustEvaluateWithError(trust=0x{:X}, error=0x{:X}) -> 1",
                    trust_ref, error_out
                ),
            );
            Some(1)
        }
        "SecTrustGetCertificateCount" => {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let count = apple_runtime
                .lock()
                .ok()?
                .trust_certificate_count(trust_ref)
                .unwrap_or(0) as u64;
            record_arm64_import(
                tracker,
                format!(
                    "_SecTrustGetCertificateCount(trust=0x{:X}) -> {}",
                    trust_ref, count
                ),
            );
            Some(count)
        }
        "SecTrustGetCertificateAtIndex" => {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let cert_ref = apple_runtime
                .lock()
                .ok()?
                .trust_certificate_at_index(trust_ref, index)
                .unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_SecTrustGetCertificateAtIndex(trust=0x{:X}, index={}) -> 0x{:X}",
                    trust_ref, index, cert_ref
                ),
            );
            Some(cert_ref)
        }
        "SecTrustSetVerifyDate" => {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let date_ref = emu.read_reg("x1").unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_SecTrustSetVerifyDate(trust=0x{:X}, date=0x{:X})",
                    trust_ref, date_ref
                ),
            );
            Some(0)
        }
        "IONotificationPortCreate" => {
            let master_port = emu.read_reg("x0").unwrap_or(0);
            let host_ptr = host_io_notification_port_create(master_port);
            let port_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                match host_ptr {
                    Some(host_ptr) => runtime.register_host_opaque("IONotificationPort", host_ptr),
                    None => runtime.alloc_opaque("IONotificationPort"),
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IONotificationPortCreate(master=0x{:X}) -> 0x{:X}",
                    master_port, port_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IONotificationPortCreate")
                    .arg("MasterPort", format!("0x{:X}", master_port))
                    .arg("Result", format!("0x{:X}", port_ref))
                    .arg("HostProxy", host_ptr.is_some().to_string())
                    .arg("Synthetic", host_ptr.is_none().to_string()),
            );
            Some(port_ref)
        }
        "IONotificationPortDestroy" => {
            let port_ref = emu.read_reg("x0").unwrap_or(0);
            let host_port = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(port_ref).unwrap_or(0)
            };
            host_io_notification_port_destroy(host_port);
            record_arm64_import(
                tracker,
                format!("_IONotificationPortDestroy(port=0x{:X})", port_ref),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IONotificationPortDestroy")
                    .arg("Port", format!("0x{:X}", port_ref))
                    .arg("HostProxy", (host_port != 0).to_string()),
            );
            Some(0)
        }
        "IOServiceMatching" => {
            let name_ptr = emu.read_reg("x0").unwrap_or(0);
            let name = read_cstring(emu, name_ptr, 1024).unwrap_or_default();
            let host_ptr = host_iokit_io_service_matching(&name);
            let matching_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                match host_ptr {
                    Some(host_ptr) => runtime
                        .register_host_opaque(format!("IOServiceMatching:{}", name), host_ptr),
                    None => runtime.alloc_opaque(format!("IOServiceMatching:{}", name)),
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IOServiceMatching(name=0x{:X}, class={}) -> 0x{:X}",
                    name_ptr, name, matching_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IOServiceMatching")
                    .arg("Name", name)
                    .arg("Result", format!("0x{:X}", matching_ref))
                    .arg("HostProxy", host_ptr.is_some().to_string()),
            );
            Some(matching_ref)
        }
        "IOServiceGetMatchingService" => {
            let master_port = emu.read_reg("x0").unwrap_or(0);
            let matching_ref = emu.read_reg("x1").unwrap_or(0);
            let host_matching = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(matching_ref).unwrap_or(0)
            };
            let service = host_iokit_io_service_get_matching_service(master_port, host_matching);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                if service != 0 {
                    runtime.register_host_opaque("IOService", service)
                } else {
                    0
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IOServiceGetMatchingService(master=0x{:X}, matching=0x{:X}) -> 0x{:X}",
                    master_port, matching_ref, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IOServiceGetMatchingService")
                    .arg("MasterPort", format!("0x{:X}", master_port))
                    .arg("Matching", format!("0x{:X}", matching_ref))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", (host_matching != 0).to_string()),
            );
            Some(result)
        }
        "IOServiceGetMatchingServices" => {
            let master_port = emu.read_reg("x0").unwrap_or(0);
            let matching_ref = emu.read_reg("x1").unwrap_or(0);
            let iterator_out = emu.read_reg("x2").unwrap_or(0);
            let host_matching = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(matching_ref).unwrap_or(0)
            };
            let (kr, iterator) =
                host_iokit_io_service_get_matching_services(master_port, host_matching)
                    .unwrap_or((-1, 0));
            if iterator_out != 0 {
                let iterator32 = (iterator as u32).to_le_bytes();
                let _ = emu.write_memory(iterator_out, &iterator32);
            }
            let iterator_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                if iterator != 0 {
                    runtime.register_host_opaque("IOIterator", iterator)
                } else {
                    0
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IOServiceGetMatchingServices(master=0x{:X}, matching=0x{:X}, out=0x{:X}) -> {} iterator=0x{:X}",
                    master_port, matching_ref, iterator_out, kr, iterator_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IOServiceGetMatchingServices")
                    .arg("MasterPort", format!("0x{:X}", master_port))
                    .arg("Matching", format!("0x{:X}", matching_ref))
                    .arg("IteratorOut", format!("0x{:X}", iterator_out))
                    .arg("Iterator", format!("0x{:X}", iterator_ref))
                    .arg("Result", kr.to_string())
                    .arg("HostProxy", (host_matching != 0).to_string()),
            );
            Some(kr as i64 as u64)
        }
        "IOIteratorNext" => {
            let iterator_ref = emu.read_reg("x0").unwrap_or(0);
            let host_iterator = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(iterator_ref).unwrap_or(0)
            };
            let object = host_iokit_io_iterator_next(host_iterator);
            let object_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                if object != 0 {
                    runtime.register_host_opaque("IOObject", object)
                } else {
                    0
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IOIteratorNext(iterator=0x{:X}) -> 0x{:X}",
                    iterator_ref, object_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IOIteratorNext")
                    .arg("Iterator", format!("0x{:X}", iterator_ref))
                    .arg("Result", format!("0x{:X}", object_ref))
                    .arg("HostProxy", (host_iterator != 0).to_string()),
            );
            Some(object_ref)
        }
        "IORegistryEntryCreateCFProperty" => {
            let entry_ref = emu.read_reg("x0").unwrap_or(0);
            let key_ref = emu.read_reg("x1").unwrap_or(0);
            let options = emu.read_reg("x3").unwrap_or(0);
            let (host_entry, key) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(entry_ref).unwrap_or(0),
                    runtime_object_data_or_host_cfstring(&runtime, key_ref).unwrap_or_default(),
                )
            };
            let host_value =
                host_iokit_io_registry_entry_create_cf_property(host_entry, &key, options);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_value
                    .map(|cf| register_host_cf_value(&mut runtime, cf, "IORegistryProperty"))
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_IORegistryEntryCreateCFProperty(entry=0x{:X}, key=0x{:X}, options=0x{:X}) -> 0x{:X}",
                    entry_ref, key_ref, options, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IORegistryEntryCreateCFProperty")
                    .arg("Entry", format!("0x{:X}", entry_ref))
                    .arg("Key", format!("0x{:X}", key_ref))
                    .arg("Options", format!("0x{:X}", options))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", (host_entry != 0).to_string())
                    .arg("Preview", lossy_data_preview(&key, 128)),
            );
            Some(result)
        }
        "IOObjectRelease" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let host_object = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(object_ref).unwrap_or(0)
            };
            let kr = host_iokit_io_object_release(host_object);
            record_arm64_import(
                tracker,
                format!("_IOObjectRelease(object=0x{:X}) -> {}", object_ref, kr),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "iokit", "IOObjectRelease")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Result", kr.to_string())
                    .arg("HostProxy", (host_object != 0).to_string()),
            );
            Some(kr as i64 as u64)
        }
        "objc_getClass" | "objc_lookUpClass" | "objc_getRequiredClass" | "objc_getMetaClass" => {
            let name_ptr = emu.read_reg("x0").unwrap_or(0);
            let name = read_cstring(emu, name_ptr, 1024).unwrap_or_default();
            let host_class = host_objc_class_lookup(normalized_apple_symbol(symbol), &name);
            let class_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                register_objc_class_lookup_result(&mut runtime, &name, host_class)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(name=0x{:X}, class={}) -> 0x{:X}",
                    normalized_apple_symbol(symbol),
                    name_ptr,
                    name,
                    class_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", normalized_apple_symbol(symbol))
                    .arg("Name", name)
                    .arg("Result", format!("0x{:X}", class_ref))
                    .arg("HostProxy", host_class.is_some().to_string()),
            );
            Some(class_ref)
        }
        "object_getClass" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let host_object = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(object_ref).unwrap_or(0)
            };
            let host_class = host_object_get_class(host_object);
            let class_name = host_class
                .and_then(host_class_get_name)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_else(|| "object-class".to_string());
            let class_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_class
                    .map(|host_class| {
                        runtime.register_host_objc_class(class_name.clone(), host_class)
                    })
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_object_getClass(object=0x{:X}) -> 0x{:X}",
                    object_ref, class_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "object_getClass")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Class", class_name)
                    .arg("Result", format!("0x{:X}", class_ref))
                    .arg(
                        "HostProxy",
                        (host_object != 0 && host_class.is_some()).to_string(),
                    ),
            );
            Some(class_ref)
        }
        "class_getName" => {
            let class_ref = emu.read_reg("x0").unwrap_or(0);
            let (host_class, cached_name) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(class_ref).unwrap_or(0),
                    runtime.objc_class_name(class_ref),
                )
            };
            let data = cached_name
                .map(|name| name.into_bytes())
                .or_else(|| host_class_get_name(host_class))
                .unwrap_or_default();
            let name_ptr = {
                let mut runtime = apple_runtime.lock().ok()?;
                export_runtime_cstring(emu, &mut runtime, &data)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_class_getName(class=0x{:X}) -> 0x{:X}",
                    class_ref, name_ptr
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "class_getName")
                    .arg("Class", format!("0x{:X}", class_ref))
                    .arg("Result", format!("0x{:X}", name_ptr))
                    .arg("HostProxy", (host_class != 0).to_string())
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(name_ptr)
        }
        "sel_registerName" | "sel_getUid" => {
            let name_ptr = emu.read_reg("x0").unwrap_or(0);
            let name = read_cstring(emu, name_ptr, 1024).unwrap_or_default();
            let host_selector = host_sel_register_name(&name);
            let selector_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_selector
                    .map(|host_selector| {
                        runtime.register_host_objc_selector(name.clone(), host_selector)
                    })
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(name=0x{:X}, selector={}) -> 0x{:X}",
                    normalized_apple_symbol(symbol),
                    name_ptr,
                    name,
                    selector_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", normalized_apple_symbol(symbol))
                    .arg("Name", name)
                    .arg("Result", format!("0x{:X}", selector_ref))
                    .arg("HostProxy", host_selector.is_some().to_string()),
            );
            Some(selector_ref)
        }
        "sel_getName" => {
            let selector_ref = emu.read_reg("x0").unwrap_or(0);
            let (host_selector, cached_name) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(selector_ref).unwrap_or(0),
                    runtime.objc_selector_name(selector_ref),
                )
            };
            let data = cached_name
                .map(|name| name.into_bytes())
                .or_else(|| host_sel_get_name(host_selector))
                .unwrap_or_default();
            let name_ptr = {
                let mut runtime = apple_runtime.lock().ok()?;
                export_runtime_cstring(emu, &mut runtime, &data)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_sel_getName(selector=0x{:X}) -> 0x{:X}",
                    selector_ref, name_ptr
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "sel_getName")
                    .arg("Selector", format!("0x{:X}", selector_ref))
                    .arg("Result", format!("0x{:X}", name_ptr))
                    .arg("HostProxy", (host_selector != 0).to_string())
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(name_ptr)
        }
        "sel_isEqual" => {
            let left_ref = emu.read_reg("x0").unwrap_or(0);
            let right_ref = emu.read_reg("x1").unwrap_or(0);
            let (left_host, right_host, left_name, right_name) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(left_ref).unwrap_or(0),
                    runtime.host_ptr_or_raw_unknown(right_ref).unwrap_or(0),
                    runtime.objc_selector_name(left_ref),
                    runtime.objc_selector_name(right_ref),
                )
            };
            let equal = if left_host != 0 && right_host != 0 {
                left_host == right_host
            } else {
                left_name.is_some() && left_name == right_name
            };
            record_arm64_import(
                tracker,
                format!(
                    "_sel_isEqual(left=0x{:X}, right=0x{:X}) -> {}",
                    left_ref, right_ref, equal as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "sel_isEqual")
                    .arg("Left", format!("0x{:X}", left_ref))
                    .arg("Right", format!("0x{:X}", right_ref))
                    .arg("Result", equal.to_string()),
            );
            Some(equal as u64)
        }
        "objc_msgSend" => {
            let receiver_ref = emu.read_reg("x0").unwrap_or(0);
            let selector_ref = emu.read_reg("x1").unwrap_or(0);
            let selector_name = {
                let runtime = apple_runtime.lock().ok()?;
                let host_selector = runtime.host_ptr_or_raw_unknown(selector_ref).unwrap_or(0);
                runtime
                    .objc_selector_name(selector_ref)
                    .or_else(|| {
                        (host_selector != 0)
                            .then(|| host_sel_get_name(host_selector))
                            .flatten()
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    })
                    .unwrap_or_else(|| "unknown".to_string())
            };
            if let Some(shim) = dispatch_foundation_msg_send_shim(
                emu,
                apple_runtime,
                receiver_ref,
                selector_ref,
                &selector_name,
            ) {
                record_arm64_import(
                    tracker,
                    format!(
                        "_objc_msgSend(receiver=0x{:X}, selector=0x{:X} {}, shim={}) -> 0x{:X}",
                        receiver_ref, selector_ref, selector_name, shim.shim, shim.result
                    ),
                );
                let mut event = process_event(metadata, "objc", "objc_msgSend")
                    .arg("Receiver", format!("0x{:X}", receiver_ref))
                    .arg("Selector", format!("0x{:X}", selector_ref))
                    .arg("SelectorName", selector_name)
                    .arg("Shim", shim.shim)
                    .arg("Result", format!("0x{:X}", shim.result))
                    .arg("HostProxy", shim.host_proxy.to_string());
                if let Some(preview) = shim.preview {
                    event = event.arg("Preview", lossy_data_preview(&preview, 128));
                }
                emit_arm64_event(trace, event);
                return Some(shim.result);
            }
            let (host_receiver, host_selector, host_args) = {
                let runtime = apple_runtime.lock().ok()?;
                let host_receiver = runtime.host_ptr_or_raw_unknown(receiver_ref).unwrap_or(0);
                let host_selector = runtime.host_ptr_or_raw_unknown(selector_ref).unwrap_or(0);
                let mut host_args = [0u64; 6];
                for (idx, host_arg) in host_args.iter_mut().enumerate() {
                    let raw = emu.read_reg(&format!("x{}", idx + 2)).unwrap_or(0);
                    *host_arg = runtime_value_to_host_arg(&runtime, raw);
                }
                (host_receiver, host_selector, host_args)
            };
            let raw_result =
                host_objc_msg_send(host_receiver, host_selector, &host_args).unwrap_or(0);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                register_objc_result(&mut runtime, &selector_name, raw_result)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_objc_msgSend(receiver=0x{:X}, selector=0x{:X} {}, host_receiver=0x{:X}) -> 0x{:X}",
                    receiver_ref, selector_ref, selector_name, host_receiver, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_msgSend")
                    .arg("Receiver", format!("0x{:X}", receiver_ref))
                    .arg("Selector", format!("0x{:X}", selector_ref))
                    .arg("SelectorName", selector_name)
                    .arg("Result", format!("0x{:X}", result))
                    .arg(
                        "HostProxy",
                        (host_receiver != 0 && host_selector != 0).to_string(),
                    ),
            );
            Some(result)
        }
        "objc_alloc" | "objc_alloc_init" | "objc_opt_new" => {
            let class_ref = emu.read_reg("x0").unwrap_or(0);
            let (host_class, class_name) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime.host_ptr_or_raw_unknown(class_ref).unwrap_or(0),
                    runtime
                        .objc_class_name(class_ref)
                        .unwrap_or_else(|| normalized_apple_symbol(symbol).to_string()),
                )
            };
            let init = !matches!(normalized_apple_symbol(symbol), "objc_alloc");
            let raw_object = host_objc_alloc(host_class, init).unwrap_or(0);
            let object_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                if raw_object != 0 {
                    runtime.register_host_objc_object(class_name.clone(), raw_object)
                } else {
                    runtime.alloc_objc_object(class_name.clone())
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(class=0x{:X} {}) -> 0x{:X}",
                    normalized_apple_symbol(symbol),
                    class_ref,
                    class_name,
                    object_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", normalized_apple_symbol(symbol))
                    .arg("Class", format!("0x{:X}", class_ref))
                    .arg("ClassName", class_name)
                    .arg("Result", format!("0x{:X}", object_ref))
                    .arg(
                        "HostProxy",
                        (host_class != 0 && raw_object != 0).to_string(),
                    ),
            );
            Some(object_ref)
        }
        "objc_opt_class" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let host_object = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(object_ref).unwrap_or(0)
            };
            let host_class = host_object_get_class(host_object);
            let class_name = host_class
                .and_then(host_class_get_name)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_else(|| "objc-opt-class".to_string());
            let class_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_class
                    .map(|host_class| {
                        runtime.register_host_objc_class(class_name.clone(), host_class)
                    })
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_objc_opt_class(object=0x{:X}) -> 0x{:X}",
                    object_ref, class_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_opt_class")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Class", class_name)
                    .arg("Result", format!("0x{:X}", class_ref))
                    .arg(
                        "HostProxy",
                        (host_object != 0 && host_class.is_some()).to_string(),
                    ),
            );
            Some(class_ref)
        }
        symbol if objc_symbol_is_identity_return(symbol) => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_{}(object=0x{:X}) -> 0x{:X}",
                    symbol, object_ref, object_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", symbol)
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Result", format!("0x{:X}", object_ref))
                    .arg("HostProxy", "false"),
            );
            Some(object_ref)
        }
        "objc_release" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            record_arm64_import(tracker, format!("_objc_release(object=0x{:X})", object_ref));
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_release")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("HostProxy", "false"),
            );
            Some(0)
        }
        "objc_autoreleasePoolPush" => {
            let host_pool = host_objc_autorelease_pool_push();
            let pool_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                if host_pool != 0 {
                    runtime.register_host_opaque("objc-autorelease-pool", host_pool)
                } else {
                    0
                }
            };
            record_arm64_import(
                tracker,
                format!("_objc_autoreleasePoolPush() -> 0x{:X}", pool_ref),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_autoreleasePoolPush")
                    .arg("Result", format!("0x{:X}", pool_ref))
                    .arg("HostProxy", (host_pool != 0).to_string()),
            );
            Some(pool_ref)
        }
        "objc_autoreleasePoolPop" => {
            let pool_ref = emu.read_reg("x0").unwrap_or(0);
            let host_pool = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(pool_ref).unwrap_or(0)
            };
            if host_pool != 0 {
                host_objc_autorelease_pool_pop(host_pool);
            }
            record_arm64_import(
                tracker,
                format!("_objc_autoreleasePoolPop(pool=0x{:X})", pool_ref),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_autoreleasePoolPop")
                    .arg("Pool", format!("0x{:X}", pool_ref))
                    .arg("HostProxy", (host_pool != 0).to_string()),
            );
            Some(0)
        }
        "objc_storeStrong" | "objc_storeWeak" | "objc_initWeak" => {
            let location = emu.read_reg("x0").unwrap_or(0);
            let object_ref = emu.read_reg("x1").unwrap_or(0);
            let ok = location != 0
                && emu
                    .write_memory(location, &object_ref.to_le_bytes())
                    .is_ok();
            record_arm64_import(
                tracker,
                format!(
                    "_{}(location=0x{:X}, object=0x{:X}) -> ok={}",
                    normalized_apple_symbol(symbol),
                    location,
                    object_ref,
                    ok
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", normalized_apple_symbol(symbol))
                    .arg("Location", format!("0x{:X}", location))
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Ok", ok.to_string()),
            );
            if matches!(normalized_apple_symbol(symbol), "objc_storeStrong") {
                Some(0)
            } else {
                Some(object_ref)
            }
        }
        "objc_destroyWeak" => {
            let location = emu.read_reg("x0").unwrap_or(0);
            let ok = location != 0 && emu.write_memory(location, &0u64.to_le_bytes()).is_ok();
            record_arm64_import(
                tracker,
                format!("_objc_destroyWeak(location=0x{:X}) -> ok={}", location, ok),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_destroyWeak")
                    .arg("Location", format!("0x{:X}", location))
                    .arg("Ok", ok.to_string()),
            );
            Some(0)
        }
        "objc_loadWeakRetained" => {
            let location = emu.read_reg("x0").unwrap_or(0);
            let object_ref = read_guest_u64(emu, location).unwrap_or(0);
            record_arm64_import(
                tracker,
                format!(
                    "_objc_loadWeakRetained(location=0x{:X}) -> 0x{:X}",
                    location, object_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "objc", "objc_loadWeakRetained")
                    .arg("Location", format!("0x{:X}", location))
                    .arg("Result", format!("0x{:X}", object_ref)),
            );
            Some(object_ref)
        }
        "NSHomeDirectory" | "NSTemporaryDirectory" | "NSUserName" | "NSFullUserName" => {
            let symbol = normalized_apple_symbol(symbol);
            let fallback = match symbol {
                "NSHomeDirectory" => foundation_home_dir_bytes(),
                "NSTemporaryDirectory" => foundation_temp_dir_bytes(),
                "NSUserName" | "NSFullUserName" => foundation_user_name_bytes(),
                _ => Vec::new(),
            };
            let (result, host_proxy, preview) = {
                let mut runtime = apple_runtime.lock().ok()?;
                if let Some(host_object) = host_foundation_no_arg_object(symbol) {
                    let preview = host_cfstring_to_bytes(host_object).unwrap_or(fallback);
                    (
                        runtime.register_host_objc_object("NSString", host_object),
                        true,
                        preview,
                    )
                } else {
                    let (result, host_proxy) =
                        make_foundation_string_result(&mut runtime, fallback.clone());
                    (result, host_proxy, fallback)
                }
            };
            record_arm64_import(tracker, format!("_{}() -> 0x{:X}", symbol, result));
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", symbol)
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", host_proxy.to_string())
                    .arg("Preview", lossy_data_preview(&preview, 128)),
            );
            Some(result)
        }
        "NSSearchPathForDirectoriesInDomains" => {
            let directory = emu.read_reg("x0").unwrap_or(0);
            let domains = emu.read_reg("x1").unwrap_or(0);
            let expand_tilde = emu.read_reg("x2").unwrap_or(0) != 0;
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                if let Some(host_array) =
                    host_ns_search_path_for_directories_in_domains(directory, domains, expand_tilde)
                {
                    (
                        runtime.register_host_objc_object("NSArray", host_array),
                        true,
                    )
                } else {
                    let paths = foundation_search_paths(directory, domains, expand_tilde)
                        .into_iter()
                        .map(guest_path_bytes)
                        .collect::<Vec<_>>();
                    make_foundation_strings_array_result(&mut runtime, paths)
                }
            };
            record_arm64_import(
                tracker,
                format!(
                    "_NSSearchPathForDirectoriesInDomains(dir={}, domains=0x{:X}, expand={}) -> 0x{:X}",
                    directory, domains, expand_tilde, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(
                    metadata,
                    "foundation",
                    "NSSearchPathForDirectoriesInDomains",
                )
                .arg("Directory", directory.to_string())
                .arg("Domains", format!("0x{:X}", domains))
                .arg("ExpandTilde", expand_tilde.to_string())
                .arg("Result", format!("0x{:X}", result))
                .arg("HostProxy", host_proxy.to_string()),
            );
            Some(result)
        }
        "NSClassFromString" => {
            let name_ref = emu.read_reg("x0").unwrap_or(0);
            let (name, host_name) = {
                let runtime = apple_runtime.lock().ok()?;
                (
                    runtime_object_data_or_host_foundation(&runtime, name_ref).unwrap_or_default(),
                    runtime_value_to_host_arg(&runtime, name_ref),
                )
            };
            let name_string = String::from_utf8_lossy(&name).into_owned();
            let host_class = if host_name != 0 {
                host_ns_class_from_string(host_name)
            } else {
                host_objc_class_lookup("objc_getClass", &name_string)
            };
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_class
                    .map(|host_class| {
                        runtime.register_host_objc_class(name_string.clone(), host_class)
                    })
                    .unwrap_or_else(|| runtime.register_host_objc_class(name_string.clone(), 0))
            };
            record_arm64_import(
                tracker,
                format!(
                    "_NSClassFromString(name=0x{:X} {}) -> 0x{:X}",
                    name_ref, name_string, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", "NSClassFromString")
                    .arg("Name", name_string)
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", host_class.is_some().to_string()),
            );
            Some(result)
        }
        "NSSelectorFromString" => {
            let name_ref = emu.read_reg("x0").unwrap_or(0);
            let name = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, name_ref).unwrap_or_default()
            };
            let name_string = String::from_utf8_lossy(&name).into_owned();
            let host_selector = host_sel_register_name(&name_string);
            let result = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_selector
                    .map(|host_selector| {
                        runtime.register_host_objc_selector(name_string.clone(), host_selector)
                    })
                    .unwrap_or_else(|| runtime.register_host_objc_selector(name_string.clone(), 0))
            };
            record_arm64_import(
                tracker,
                format!(
                    "_NSSelectorFromString(name=0x{:X} {}) -> 0x{:X}",
                    name_ref, name_string, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", "NSSelectorFromString")
                    .arg("Name", name_string)
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", host_selector.is_some().to_string()),
            );
            Some(result)
        }
        "NSStringFromClass" => {
            let class_ref = emu.read_reg("x0").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime
                    .objc_class_name(class_ref)
                    .map(|name| name.into_bytes())
                    .or_else(|| {
                        runtime
                            .host_ptr_or_raw_unknown(class_ref)
                            .and_then(host_class_get_name)
                    })
                    .unwrap_or_default()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            record_arm64_import(
                tracker,
                format!(
                    "_NSStringFromClass(class=0x{:X}) -> 0x{:X}",
                    class_ref, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", "NSStringFromClass")
                    .arg("Class", format!("0x{:X}", class_ref))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", host_proxy.to_string())
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(result)
        }
        "NSStringFromSelector" => {
            let selector_ref = emu.read_reg("x0").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime
                    .objc_selector_name(selector_ref)
                    .map(|name| name.into_bytes())
                    .or_else(|| {
                        runtime
                            .host_ptr_or_raw_unknown(selector_ref)
                            .and_then(host_sel_get_name)
                    })
                    .unwrap_or_default()
            };
            let (result, host_proxy) = {
                let mut runtime = apple_runtime.lock().ok()?;
                make_foundation_string_result(&mut runtime, data.clone())
            };
            record_arm64_import(
                tracker,
                format!(
                    "_NSStringFromSelector(selector=0x{:X}) -> 0x{:X}",
                    selector_ref, result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", "NSStringFromSelector")
                    .arg("Selector", format!("0x{:X}", selector_ref))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("HostProxy", host_proxy.to_string())
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            Some(result)
        }
        "NSLog" => {
            let format_ref = emu.read_reg("x0").unwrap_or(0);
            let data = {
                let runtime = apple_runtime.lock().ok()?;
                runtime_object_data_or_host_foundation(&runtime, format_ref).unwrap_or_default()
            };
            record_arm64_import(tracker, format!("_NSLog(format=0x{:X})", format_ref));
            emit_arm64_event(
                trace,
                process_event(metadata, "foundation", "NSLog")
                    .arg("Format", format!("0x{:X}", format_ref))
                    .arg("Preview", lossy_data_preview(&data, 256))
                    .arg("HostProxy", "false"),
            );
            Some(0)
        }
        "NSApplicationLoad" => {
            record_arm64_import(tracker, "_NSApplicationLoad() -> 1".to_string());
            emit_arm64_event(
                trace,
                process_event(metadata, "appkit", "NSApplicationLoad")
                    .arg("Result", "1")
                    .arg("Model", "synthetic-ui-startup"),
            );
            Some(1)
        }
        "NSApplicationMain" => {
            let argc = emu.read_reg("x0").unwrap_or(0);
            let argv = emu.read_reg("x1").unwrap_or(0);
            record_arm64_import(
                tracker,
                format!("_NSApplicationMain(argc={}, argv=0x{:X}) -> 0", argc, argv),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "appkit", "NSApplicationMain")
                    .arg("Argc", argc.to_string())
                    .arg("Argv", format!("0x{:X}", argv))
                    .arg("Result", "0")
                    .arg("Model", "synthetic-no-event-loop"),
            );
            Some(0)
        }
        "CGMainDisplayID" => {
            let display = host_cg_main_display_id();
            record_arm64_import(tracker, format!("_CGMainDisplayID() -> {}", display));
            emit_arm64_event(
                trace,
                process_event(metadata, "coregraphics", "CGMainDisplayID")
                    .arg("Result", display.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(display as u64)
        }
        "CGDisplayPixelsWide" | "CGDisplayPixelsHigh" => {
            let display = emu.read_reg("x0").unwrap_or(0) as u32;
            let result = if normalized_apple_symbol(symbol) == "CGDisplayPixelsWide" {
                host_cg_display_pixels_wide(display)
            } else {
                host_cg_display_pixels_high(display)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(display={}) -> {}",
                    normalized_apple_symbol(symbol),
                    display,
                    result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "coregraphics", normalized_apple_symbol(symbol))
                    .arg("Display", display.to_string())
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "CGDisplayIsActive" | "CGDisplayIsOnline" => {
            let display = emu.read_reg("x0").unwrap_or(0) as u32;
            let result = if normalized_apple_symbol(symbol) == "CGDisplayIsActive" {
                host_cg_display_is_active(display)
            } else {
                host_cg_display_is_online(display)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(display={}) -> {}",
                    normalized_apple_symbol(symbol),
                    display,
                    result as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "coregraphics", normalized_apple_symbol(symbol))
                    .arg("Display", display.to_string())
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "CGPreflightScreenCaptureAccess" | "CGRequestScreenCaptureAccess" => {
            let request = normalized_apple_symbol(symbol) == "CGRequestScreenCaptureAccess";
            let result = if request {
                host_cg_request_screen_capture_access()
            } else {
                host_cg_preflight_screen_capture_access()
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}() -> {}",
                    normalized_apple_symbol(symbol),
                    result as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "privacy", normalized_apple_symbol(symbol))
                    .arg("Capability", "screen-capture")
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "CGDisplayCreateImage" => {
            let display = emu.read_reg("x0").unwrap_or(0) as u32;
            let host_image = host_cg_display_create_image(display);
            let image_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_image
                    .map(|host_image| runtime.register_host_opaque("CGImage", host_image))
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CGDisplayCreateImage(display={}) -> 0x{:X}",
                    display, image_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", "CGDisplayCreateImage")
                    .arg("Display", display.to_string())
                    .arg("Result", format!("0x{:X}", image_ref))
                    .arg("HostProxy", host_image.is_some().to_string()),
            );
            Some(image_ref)
        }
        "CGImageGetWidth" | "CGImageGetHeight" => {
            let image_ref = emu.read_reg("x0").unwrap_or(0);
            let host_image = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(image_ref).unwrap_or(0)
            };
            let result = host_cg_image_size(
                host_image,
                if normalized_apple_symbol(symbol) == "CGImageGetHeight" {
                    "height"
                } else {
                    "width"
                },
            );
            record_arm64_import(
                tracker,
                format!(
                    "_{}(image=0x{:X}, host=0x{:X}) -> {}",
                    normalized_apple_symbol(symbol),
                    image_ref,
                    host_image,
                    result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", normalized_apple_symbol(symbol))
                    .arg("Image", format!("0x{:X}", image_ref))
                    .arg("HostImage", format!("0x{:X}", host_image))
                    .arg("Result", result.to_string())
                    .arg("HostProxy", (host_image != 0).to_string()),
            );
            Some(result as u64)
        }
        "CGImageGetBitsPerPixel" | "CGImageGetBytesPerRow" => {
            let image_ref = emu.read_reg("x0").unwrap_or(0);
            let host_image = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(image_ref).unwrap_or(0)
            };
            let result = if normalized_apple_symbol(symbol) == "CGImageGetBitsPerPixel" {
                host_cg_image_bits_per_pixel(host_image)
            } else {
                host_cg_image_bytes_per_row(host_image)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}(image=0x{:X}, host=0x{:X}) -> {}",
                    normalized_apple_symbol(symbol),
                    image_ref,
                    host_image,
                    result
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", normalized_apple_symbol(symbol))
                    .arg("Image", format!("0x{:X}", image_ref))
                    .arg("HostImage", format!("0x{:X}", host_image))
                    .arg("Result", result.to_string())
                    .arg("HostProxy", (host_image != 0).to_string()),
            );
            Some(result as u64)
        }
        "CGImageGetDataProvider" => {
            let image_ref = emu.read_reg("x0").unwrap_or(0);
            let host_image = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(image_ref).unwrap_or(0)
            };
            let host_provider = host_cg_image_get_data_provider(host_image);
            let provider_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_provider
                    .map(|host_provider| {
                        runtime.register_host_opaque("CGDataProvider", host_provider)
                    })
                    .unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CGImageGetDataProvider(image=0x{:X}, host=0x{:X}) -> 0x{:X}",
                    image_ref, host_image, provider_ref
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", "CGImageGetDataProvider")
                    .arg("Image", format!("0x{:X}", image_ref))
                    .arg("HostImage", format!("0x{:X}", host_image))
                    .arg("Result", format!("0x{:X}", provider_ref))
                    .arg("HostProxy", host_provider.is_some().to_string()),
            );
            Some(provider_ref)
        }
        "CGDataProviderCopyData" => {
            let provider_ref = emu.read_reg("x0").unwrap_or(0);
            let host_provider = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(provider_ref).unwrap_or(0)
            };
            let host_data = host_cg_data_provider_copy_data(host_provider);
            let data_ref = {
                let mut runtime = apple_runtime.lock().ok()?;
                host_data
                    .map(|host_data| {
                        register_host_cf_value_with_ownership(
                            &mut runtime,
                            host_data,
                            "CGImageData",
                            true,
                        )
                    })
                    .unwrap_or(0)
            };
            let data_len = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.object_len(data_ref).unwrap_or(0)
            };
            record_arm64_import(
                tracker,
                format!(
                    "_CGDataProviderCopyData(provider=0x{:X}, host=0x{:X}) -> 0x{:X} len={}",
                    provider_ref, host_provider, data_ref, data_len
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", "CGDataProviderCopyData")
                    .arg("Provider", format!("0x{:X}", provider_ref))
                    .arg("HostProvider", format!("0x{:X}", host_provider))
                    .arg("Result", format!("0x{:X}", data_ref))
                    .arg("Bytes", data_len.to_string())
                    .arg("HostProxy", host_data.is_some().to_string()),
            );
            Some(data_ref)
        }
        "CGImageRelease" => {
            let image_ref = emu.read_reg("x0").unwrap_or(0);
            let host_image = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(image_ref).unwrap_or(0)
            };
            if host_image != 0 {
                host_cf_release(host_image);
            }
            if let Ok(mut runtime) = apple_runtime.lock() {
                runtime.release(image_ref);
            }
            record_arm64_import(
                tracker,
                format!(
                    "_CGImageRelease(image=0x{:X}, host=0x{:X})",
                    image_ref, host_image
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "screen-capture", "CGImageRelease")
                    .arg("Image", format!("0x{:X}", image_ref))
                    .arg("HostImage", format!("0x{:X}", host_image))
                    .arg("HostProxy", (host_image != 0).to_string()),
            );
            Some(0)
        }
        "CGEventSourceKeyState" => {
            let state_id = emu.read_reg("x0").unwrap_or(0) as u32;
            let key = emu.read_reg("x1").unwrap_or(0) as u16;
            let pressed = host_cg_event_source_key_state(state_id, key);
            record_arm64_import(
                tracker,
                format!(
                    "_CGEventSourceKeyState(state={}, key={}) -> {}",
                    state_id, key, pressed as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "keyboard", "CGEventSourceKeyState")
                    .arg("State", state_id.to_string())
                    .arg("Key", key.to_string())
                    .arg("Pressed", pressed.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(pressed as u64)
        }
        "CGPreflightListenEventAccess" | "CGRequestListenEventAccess" => {
            let request = normalized_apple_symbol(symbol) == "CGRequestListenEventAccess";
            let result = if request {
                host_cg_request_listen_event_access()
            } else {
                host_cg_preflight_listen_event_access()
            };
            record_arm64_import(
                tracker,
                format!(
                    "_{}() -> {}",
                    normalized_apple_symbol(symbol),
                    result as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "privacy", normalized_apple_symbol(symbol))
                    .arg("Capability", "keyboard-listen")
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "AXIsProcessTrusted" => {
            let result = host_ax_is_process_trusted();
            record_arm64_import(
                tracker,
                format!("_AXIsProcessTrusted() -> {}", result as u64),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "accessibility", "AXIsProcessTrusted")
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "AXIsProcessTrustedWithOptions" => {
            let options_ref = emu.read_reg("x0").unwrap_or(0);
            let host_options = {
                let runtime = apple_runtime.lock().ok()?;
                runtime.host_ptr_or_raw_unknown(options_ref).unwrap_or(0)
            };
            let result = host_ax_is_process_trusted_with_options(host_options);
            record_arm64_import(
                tracker,
                format!(
                    "_AXIsProcessTrustedWithOptions(options=0x{:X}, host=0x{:X}) -> {}",
                    options_ref, host_options, result as u64
                ),
            );
            emit_arm64_event(
                trace,
                process_event(metadata, "accessibility", "AXIsProcessTrustedWithOptions")
                    .arg("Options", format!("0x{:X}", options_ref))
                    .arg("HostOptions", format!("0x{:X}", host_options))
                    .arg("Result", result.to_string())
                    .arg("HostProxy", "true"),
            );
            Some(result as u64)
        }
        "CFRelease" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            if let Ok(mut runtime) = apple_runtime.lock() {
                runtime.release(object_ref);
            }
            record_arm64_import(tracker, format!("_CFRelease(0x{:X})", object_ref));
            Some(0)
        }
        "CFRetain" => {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            if let Ok(runtime) = apple_runtime.lock() {
                let _ = runtime.retain(object_ref);
            }
            record_arm64_import(tracker, format!("_CFRetain(0x{:X})", object_ref));
            Some(object_ref)
        }
        _ => None,
    }
}

fn install_dispatch_hook(
    emulator: &mut UnicornEmulator,
    addr: u64,
    symbol: &'static str,
    apple_runtime: Arc<Mutex<crate::macos::AppleRuntime>>,
    trace_bus: Option<SharedTraceBus>,
    import_tracker: Arm64ImportTracker,
    metadata: crate::macos::TraceMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
            let result = dispatch_apple_import(
                emu,
                symbol,
                &apple_runtime,
                &import_tracker,
                &trace_bus,
                &metadata,
            )
            .unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
        },
    )?;
    Ok(())
}

fn install_dynamic_dispatch_hook(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    stub_name_map: Arc<Mutex<HashMap<u64, String>>>,
    next_dynamic_stub_addr: Arc<Mutex<u64>>,
    apple_runtime: Arc<Mutex<crate::macos::AppleRuntime>>,
    trace_bus: Option<SharedTraceBus>,
    import_tracker: Arm64ImportTracker,
    metadata: crate::macos::TraceMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    let dynamic_start = next_dynamic_stub_addr
        .lock()
        .ok()
        .map(|next| *next)
        .unwrap_or_else(|| stub_region.base.saturating_add(stub_region.size));
    let dynamic_end = stub_region.base.saturating_add(stub_region.size);
    if dynamic_start >= dynamic_end {
        return Ok(());
    }

    emulator.add_code_hook(
        dynamic_start,
        dynamic_end,
        move |emu: &mut compatra_runtime::UnicornEmulator, address: u64, _size: u32| {
            let bucket = stub_region.bucket(address);
            let symbol = stub_name_map
                .lock()
                .ok()
                .and_then(|symbols| symbols.get(&bucket).cloned());
            let Some(symbol) = symbol else {
                return;
            };
            if !is_apple_import_symbol(&symbol) {
                return;
            }
            let Some(result) = dispatch_apple_import(
                emu,
                &symbol,
                &apple_runtime,
                &import_tracker,
                &trace_bus,
                &metadata,
            ) else {
                return;
            };
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
        },
    )?;
    Ok(())
}

pub fn install_apple_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    stub_region: StubRegion,
    stub_name_map: Arc<Mutex<HashMap<u64, String>>>,
    next_dynamic_stub_addr: Arc<Mutex<u64>>,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = runtime_process_metadata(process_name.to_string());
    if let Ok(mut runtime) = shared_state.apple_runtime.lock() {
        runtime.set_process_name(process_name);
    }

    install_dynamic_dispatch_hook(
        emulator,
        stub_region,
        stub_name_map,
        next_dynamic_stub_addr,
        shared_state.apple_runtime.clone(),
        trace_bus.clone(),
        import_tracker.clone(),
        metadata.clone(),
    )?;

    for &symbol in APPLE_DIRECT_DISPATCH_IMPORTS {
        if let Some(&addr) = stub_map.get(symbol) {
            install_dispatch_hook(
                emulator,
                addr,
                symbol,
                shared_state.apple_runtime.clone(),
                trace_bus.clone(),
                import_tracker.clone(),
                metadata.clone(),
            )?;
        }
    }

    if let Some(&addr) = stub_map.get("_CFStringCreateWithBytes") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let encoding = emu.read_reg("x3").unwrap_or(0);
            let data = read_guest_bytes(emu, bytes_ptr, len, 64 * 1024);
            let string_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_string(data.clone(), encoding)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFStringCreateWithBytes(bytes=0x{:X}, len={}, enc=0x{:X}) -> 0x{:X}",
                    bytes_ptr, len, encoding, string_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfstring", "CFStringCreateWithBytes")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Encoding", format!("0x{:X}", encoding))
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            string_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFStringCreateExternalRepresentation") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let string_ref = emu.read_reg("x1").unwrap_or(0);
            let data_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let Some(data) = runtime.object_data(string_ref) else {
                    return 0;
                };
                runtime.alloc_data(data)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFStringCreateExternalRepresentation(string=0x{:X}) -> 0x{:X}",
                    string_ref, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(
                    &metadata,
                    "cfstring",
                    "CFStringCreateExternalRepresentation",
                )
                .arg("String", format!("0x{:X}", string_ref))
                .arg("Result", format!("0x{:X}", data_ref)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let data = read_guest_bytes(emu, bytes_ptr, len, 8 * 1024 * 1024);
            let data_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_data(data.clone())
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDataCreate(bytes=0x{:X}, len={}) -> 0x{:X}",
                    bytes_ptr, len, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataCreate")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Result", format!("0x{:X}", data_ref))
                    .arg("Preview", lossy_data_preview(&data, 128)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataGetLength") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let len = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.object_len(data_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFDataGetLength(data=0x{:X}) -> {}", data_ref, len),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataGetLength")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", len.to_string()),
            );
            len
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataGetBytePtr") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let exported_ptr = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let Some(data) = runtime.object_data(data_ref) else {
                    return 0;
                };
                runtime.export_bytes(emu, &data).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDataGetBytePtr(data=0x{:X}) -> 0x{:X}",
                    data_ref, exported_ptr
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataGetBytePtr")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", format!("0x{:X}", exported_ptr)),
            );
            exported_ptr
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayCreateMutable") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let array_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_array()
            };
            record_arm64_import(
                &tracker,
                format!("_CFArrayCreateMutable() -> 0x{:X}", array_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayCreateMutable")
                    .arg("Result", format!("0x{:X}", array_ref)),
            );
            array_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let values_ptr = emu.read_reg("x1").unwrap_or(0);
            let count = emu.read_reg("x2").unwrap_or(0) as usize;
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let array_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_array_with_values(values.clone())
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFArrayCreate(values=0x{:X}, count={}) -> 0x{:X}",
                    values_ptr, count, array_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayCreate")
                    .arg("Values", format!("0x{:X}", values_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", format!("0x{:X}", array_ref)),
            );
            array_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayAppendValue") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let array_ref = emu.read_reg("x0").unwrap_or(0);
                let value_ref = emu.read_reg("x1").unwrap_or(0);
                let (ok, array_desc) = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    let ok = runtime.array_append(array_ref, value_ref);
                    let desc = runtime.describe(array_ref);
                    (ok, desc)
                };
                record_arm64_import(
                    &tracker,
                    format!(
                        "_CFArrayAppendValue(array=0x{:X}, value=0x{:X}) ok={}",
                        array_ref, value_ref, ok
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "cfarray", "CFArrayAppendValue")
                        .arg("Array", format!("0x{:X}", array_ref))
                        .arg("Value", format!("0x{:X}", value_ref))
                        .arg("Ok", ok.to_string())
                        .arg("ArrayDesc", array_desc),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayGetCount") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let count = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.array_len(array_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFArrayGetCount(array=0x{:X}) -> {}", array_ref, count),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayGetCount")
                    .arg("Array", format!("0x{:X}", array_ref))
                    .arg("Result", count.to_string()),
            );
            count
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayGetValueAtIndex") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let value_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.array_get(array_ref, index).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFArrayGetValueAtIndex(array=0x{:X}, index={}) -> 0x{:X}",
                    array_ref, index, value_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayGetValueAtIndex")
                    .arg("Array", format!("0x{:X}", array_ref))
                    .arg("Index", index.to_string())
                    .arg("Result", format!("0x{:X}", value_ref)),
            );
            value_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDateCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let absolute_time = f64::from_bits(emu.read_reg("x1").unwrap_or(0));
            let date_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_date(absolute_time)
            };
            record_arm64_import(
                &tracker,
                format!("_CFDateCreate(abs={}) -> 0x{:X}", absolute_time, date_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdate", "CFDateCreate")
                    .arg("AbsoluteTime", absolute_time.to_string())
                    .arg("Result", format!("0x{:X}", date_ref)),
            );
            date_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_xpc_date_create_from_current") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let date_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_date(0.0)
            };
            record_arm64_import(
                &tracker,
                format!("_xpc_date_create_from_current() -> 0x{:X}", date_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "xpcdate", "xpc_date_create_from_current")
                    .arg("Result", format!("0x{:X}", date_ref)),
            );
            date_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFRelease") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let object_ref = emu.read_reg("x0").unwrap_or(0);
                let desc = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    let desc = runtime.describe(object_ref);
                    runtime.release(object_ref);
                    desc
                };
                record_arm64_import(&tracker, format!("_CFRelease(0x{:X})", object_ref));
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "cfobject", "CFRelease")
                        .arg("Object", format!("0x{:X}", object_ref))
                        .arg("Desc", desc),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_CFRetain") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let desc = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return object_ref,
                };
                let _ = runtime.retain(object_ref);
                runtime.describe(object_ref)
            };
            record_arm64_import(&tracker, format!("_CFRetain(0x{:X})", object_ref));
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfobject", "CFRetain")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Desc", desc),
            );
            object_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorGetCode") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let code = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.error_code(error_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFErrorGetCode(error=0x{:X}) -> {}", error_ref, code),
            );
            code
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let domain = emu.read_reg("x1").unwrap_or(0);
            let code = emu.read_reg("x2").unwrap_or(0) as i64;
            let error_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_error(code, format!("compatra synthetic error {}", code))
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFErrorCreate(domain=0x{:X}, code={}) -> 0x{:X}",
                    domain, code, error_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cferror", "CFErrorCreate")
                    .arg("Domain", format!("0x{:X}", domain))
                    .arg("Code", code.to_string())
                    .arg("Result", format!("0x{:X}", error_ref)),
            );
            error_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorCopyDescription") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let description_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let description = runtime
                    .error_description(error_ref)
                    .unwrap_or_else(|| "compatra synthetic error".to_string());
                runtime.alloc_string(description.into_bytes(), 0x8000_0100)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFErrorCopyDescription(error=0x{:X}) -> 0x{:X}",
                    error_ref, description_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cferror", "CFErrorCopyDescription")
                    .arg("Error", format!("0x{:X}", error_ref))
                    .arg("Result", format!("0x{:X}", description_ref)),
            );
            description_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDictionaryCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let keys_ptr = emu.read_reg("x1").unwrap_or(0);
            let values_ptr = emu.read_reg("x2").unwrap_or(0);
            let count = emu.read_reg("x3").unwrap_or(0) as usize;
            let keys = read_guest_u64_array(emu, keys_ptr, count, 4096);
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let entries = keys.into_iter().zip(values).collect::<Vec<_>>();
            let (dict_ref, host_proxy) = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                make_foundation_dictionary_result(&mut runtime, entries)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDictionaryCreate(keys=0x{:X}, values=0x{:X}, count={}, host={}) -> 0x{:X}",
                    keys_ptr, values_ptr, count, host_proxy, dict_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdictionary", "CFDictionaryCreate")
                    .arg("Keys", format!("0x{:X}", keys_ptr))
                    .arg("Values", format!("0x{:X}", values_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", format!("0x{:X}", dict_ref))
                    .arg("HostProxy", host_proxy.to_string()),
            );
            dict_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDictionaryGetValueIfPresent") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let dict_ref = emu.read_reg("x0").unwrap_or(0);
            let key_ref = emu.read_reg("x1").unwrap_or(0);
            let value_out = emu.read_reg("x2").unwrap_or(0);
            let value_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.dictionary_get(dict_ref, key_ref).unwrap_or(0)
            };
            let present = value_ref != 0;
            if present && value_out != 0 {
                let _ = emu.write_memory(value_out, &value_ref.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDictionaryGetValueIfPresent(dict=0x{:X}, key=0x{:X}, out=0x{:X}) -> {}",
                    dict_ref, key_ref, value_out, present as u64
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdictionary", "CFDictionaryGetValueIfPresent")
                    .arg("Dictionary", format!("0x{:X}", dict_ref))
                    .arg("Key", format!("0x{:X}", key_ref))
                    .arg("ValueOut", format!("0x{:X}", value_out))
                    .arg("Value", format!("0x{:X}", value_ref))
                    .arg("Present", present.to_string()),
            );
            present as u64
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFGetTypeID") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let type_id = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.type_id(object_ref)
            };
            record_arm64_import(
                &tracker,
                format!("_CFGetTypeID(obj=0x{:X}) -> 0x{:X}", object_ref, type_id),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfobject", "CFGetTypeID")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Result", format!("0x{:X}", type_id)),
            );
            type_id
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFNumberGetTypeID") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let type_id = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.number_type_id()
            };
            record_arm64_import(&tracker, format!("_CFNumberGetTypeID() -> 0x{:X}", type_id));
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfnumber", "CFNumberGetTypeID")
                    .arg("Result", format!("0x{:X}", type_id)),
            );
            type_id
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFNumberGetValue") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let number_ref = emu.read_reg("x0").unwrap_or(0);
            let number_type = emu.read_reg("x1").unwrap_or(0);
            let out_ptr = emu.read_reg("x2").unwrap_or(0);
            let value = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.number_value(number_ref).unwrap_or(0)
            };
            if out_ptr != 0 {
                let _ = emu.write_memory(out_ptr, &value.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_CFNumberGetValue(num=0x{:X}, type=0x{:X}, out=0x{:X}) -> 1",
                    number_ref, number_type, out_ptr
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfnumber", "CFNumberGetValue")
                    .arg("Number", format!("0x{:X}", number_ref))
                    .arg("Type", format!("0x{:X}", number_type))
                    .arg("Out", format!("0x{:X}", out_ptr))
                    .arg("Value", value.to_string())
                    .arg("Result", "1"),
            );
            1
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecCertificateCreateWithData") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x1").unwrap_or(0);
            let cert_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_certificate(data_ref)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecCertificateCreateWithData(data=0x{:X}) -> 0x{:X}",
                    data_ref, cert_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "seccertificate", "SecCertificateCreateWithData")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", format!("0x{:X}", cert_ref)),
            );
            cert_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecCertificateCopyData") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let cert_ref = emu.read_reg("x0").unwrap_or(0);
            let data_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.certificate_data(cert_ref).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecCertificateCopyData(cert=0x{:X}) -> 0x{:X}",
                    cert_ref, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "seccertificate", "SecCertificateCopyData")
                    .arg("Certificate", format!("0x{:X}", cert_ref))
                    .arg("Result", format!("0x{:X}", data_ref)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecPolicyCreateSSL") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let server = emu.read_reg("x0").unwrap_or(0) != 0;
            let hostname = emu.read_reg("x1").unwrap_or(0);
            let policy_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_policy_ssl(server, hostname)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecPolicyCreateSSL(server={}, hostname=0x{:X}) -> 0x{:X}",
                    server, hostname, policy_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "secpolicy", "SecPolicyCreateSSL")
                    .arg("Server", server.to_string())
                    .arg("Hostname", format!("0x{:X}", hostname))
                    .arg("Result", format!("0x{:X}", policy_ref)),
            );
            policy_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustCreateWithCertificates") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let certificates = emu.read_reg("x0").unwrap_or(0);
                let policies = emu.read_reg("x1").unwrap_or(0);
                let trust_out = emu.read_reg("x2").unwrap_or(0);
                let trust_ref = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    runtime.alloc_trust(certificates, policies)
                };
                if trust_out != 0 {
                    let _ = emu.write_memory(trust_out, &trust_ref.to_le_bytes());
                }
                record_arm64_import(
                    &tracker,
                    format!(
                        "_SecTrustCreateWithCertificates(certs=0x{:X}, policies=0x{:X}, out=0x{:X}) -> 0x{:X}",
                        certificates, policies, trust_out, trust_ref
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "sectrust", "SecTrustCreateWithCertificates")
                        .arg("Certificates", format!("0x{:X}", certificates))
                        .arg("Policies", format!("0x{:X}", policies))
                        .arg("TrustOut", format!("0x{:X}", trust_out))
                        .arg("Trust", format!("0x{:X}", trust_ref)),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustEvaluateWithError") {
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let error_out = emu.read_reg("x1").unwrap_or(0);
            if error_out != 0 {
                let _ = emu.write_memory(error_out, &0u64.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustEvaluateWithError(trust=0x{:X}, error=0x{:X}) -> 1",
                    trust_ref, error_out
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustEvaluateWithError")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("ErrorOut", format!("0x{:X}", error_out))
                    .arg("Result", "1"),
            );
            1
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustGetCertificateCount") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let count = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.trust_certificate_count(trust_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustGetCertificateCount(trust=0x{:X}) -> {}",
                    trust_ref, count
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustGetCertificateCount")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("Result", count.to_string()),
            );
            count
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustGetCertificateAtIndex") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let cert_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime
                    .trust_certificate_at_index(trust_ref, index)
                    .unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustGetCertificateAtIndex(trust=0x{:X}, index={}) -> 0x{:X}",
                    trust_ref, index, cert_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustGetCertificateAtIndex")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("Index", index.to_string())
                    .arg("Result", format!("0x{:X}", cert_ref)),
            );
            cert_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustSetVerifyDate") {
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut compatra_runtime::UnicornEmulator, _address: u64, _size: u32| {
                let trust_ref = emu.read_reg("x0").unwrap_or(0);
                let date_ref = emu.read_reg("x1").unwrap_or(0);
                record_arm64_import(
                    &tracker,
                    format!(
                        "_SecTrustSetVerifyDate(trust=0x{:X}, date=0x{:X})",
                        trust_ref, date_ref
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "sectrust", "SecTrustSetVerifyDate")
                        .arg("Trust", format!("0x{:X}", trust_ref))
                        .arg("Date", format!("0x{:X}", date_ref)),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iokit_notification_port_import_is_apple_dispatched() {
        assert!(is_apple_import_symbol("_IONotificationPortCreate"));
        assert!(is_apple_import_symbol("IONotificationPortCreate"));
        assert!(is_apple_import_symbol("_IONotificationPortDestroy"));
    }

    #[test]
    fn cf_bundle_url_imports_are_apple_dispatched() {
        assert!(is_apple_import_symbol("_CFStringCompare"));
        assert!(is_apple_import_symbol("_CFStringCreateCopy"));
        assert!(is_apple_import_symbol("_CFStringGetCStringPtr"));
        assert!(is_apple_import_symbol("_CFURLCreateWithFileSystemPath"));
        assert!(is_apple_import_symbol("_CFURLCopyFileSystemPath"));
        assert!(is_apple_import_symbol("_CFBundleGetMainBundle"));
        assert!(is_apple_import_symbol("_CFBundleCopyBundleURL"));
    }

    #[test]
    fn iokit_registry_imports_are_apple_dispatched() {
        assert!(is_apple_import_symbol("_IOServiceMatching"));
        assert!(is_apple_import_symbol("_IOServiceGetMatchingService"));
        assert!(is_apple_import_symbol("_IOServiceGetMatchingServices"));
        assert!(is_apple_import_symbol("_IOIteratorNext"));
        assert!(is_apple_import_symbol("_IORegistryEntryCreateCFProperty"));
        assert!(is_apple_import_symbol("_IOObjectRelease"));
    }

    #[test]
    fn cf_bundle_iokit_imports_are_installed_as_direct_dispatch_hooks() {
        for symbol in [
            "_CFStringGetCStringPtr",
            "_CFStringCreateCopy",
            "_CFStringCompare",
            "_CFURLCreateWithFileSystemPath",
            "_CFURLCopyFileSystemPath",
            "_CFBundleGetMainBundle",
            "_CFBundleCopyBundleURL",
            "_IONotificationPortDestroy",
            "_IOServiceMatching",
            "_IOServiceGetMatchingService",
            "_IOServiceGetMatchingServices",
            "_IOIteratorNext",
            "_IORegistryEntryCreateCFProperty",
            "_IOObjectRelease",
        ] {
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn corefoundation_object_imports_are_apple_dispatched() {
        for symbol in [
            "_CFStringCreateWithBytes",
            "_CFStringCreateExternalRepresentation",
            "_CFStringGetTypeID",
            "_CFDataCreate",
            "_CFDataGetLength",
            "_CFDataGetBytePtr",
            "_CFDataGetTypeID",
            "_CFArrayCreateMutable",
            "_CFArrayCreate",
            "_CFArrayAppendValue",
            "_CFArrayGetCount",
            "_CFArrayGetValueAtIndex",
            "_CFArrayGetTypeID",
            "_CFDictionaryCreate",
            "_CFDictionaryGetValueIfPresent",
            "_CFDictionaryGetTypeID",
            "_CFDateCreate",
            "_CFErrorCreate",
            "_CFErrorGetCode",
            "_CFErrorCopyDescription",
            "_CFGetTypeID",
            "_CFNumberGetTypeID",
            "_CFNumberGetValue",
            "_CFBooleanGetTypeID",
            "_CFBooleanGetValue",
            "_xpc_date_create_from_current",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
        }
    }

    #[test]
    fn corefoundation_type_imports_use_direct_dispatch_hooks() {
        for symbol in [
            "_CFStringGetTypeID",
            "_CFDataGetTypeID",
            "_CFArrayGetTypeID",
            "_CFDictionaryGetTypeID",
            "_CFBooleanGetTypeID",
            "_CFBooleanGetValue",
        ] {
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn object_imports_with_special_static_hooks_avoid_double_direct_dispatch() {
        for symbol in [
            "_CFStringCreateWithBytes",
            "_CFStringCreateExternalRepresentation",
            "_CFDataCreate",
            "_CFDataGetLength",
            "_CFDataGetBytePtr",
            "_CFArrayCreateMutable",
            "_CFArrayCreate",
            "_CFArrayAppendValue",
            "_CFArrayGetCount",
            "_CFArrayGetValueAtIndex",
            "_CFDictionaryCreate",
            "_CFDictionaryGetValueIfPresent",
            "_CFDateCreate",
            "_CFErrorCreate",
            "_CFErrorGetCode",
            "_CFErrorCopyDescription",
            "_CFGetTypeID",
            "_CFNumberGetTypeID",
            "_CFNumberGetValue",
            "_SecCertificateCreateWithData",
            "_SecCertificateCopyData",
            "_SecPolicyCreateSSL",
            "_SecTrustCreateWithCertificates",
            "_SecTrustEvaluateWithError",
            "_SecTrustGetCertificateCount",
            "_SecTrustGetCertificateAtIndex",
            "_SecTrustSetVerifyDate",
            "_xpc_date_create_from_current",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should still be Apple-dispatched"
            );
            assert!(
                !APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} has a dedicated static hook and should not also use direct dispatch"
            );
        }
    }

    #[test]
    fn security_object_imports_are_apple_dispatched() {
        for symbol in [
            "_SecCertificateCreateWithData",
            "_SecCertificateCopyData",
            "_SecPolicyCreateSSL",
            "_SecTrustCreateWithCertificates",
            "_SecTrustEvaluateWithError",
            "_SecTrustGetCertificateCount",
            "_SecTrustGetCertificateAtIndex",
            "_SecTrustSetVerifyDate",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
        }
    }

    #[test]
    fn security_keychain_imports_use_direct_dispatch_hooks() {
        for symbol in [
            "_SecItemCopyMatching",
            "_SecKeychainCopyDefault",
            "_SecKeychainOpen",
            "_SecKeychainGetPath",
            "_SecKeychainFindGenericPassword",
            "_SecKeychainItemFreeContent",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn objc_runtime_imports_are_apple_dispatched() {
        for symbol in [
            "_objc_getClass",
            "_objc_lookUpClass",
            "_objc_getRequiredClass",
            "_objc_getMetaClass",
            "_object_getClass",
            "_class_getName",
            "_sel_registerName",
            "_sel_getUid",
            "_sel_getName",
            "_sel_isEqual",
            "_objc_msgSend",
            "_objc_alloc",
            "_objc_alloc_init",
            "_objc_opt_self",
            "_objc_opt_class",
            "_objc_opt_new",
            "_objc_autoreleasePoolPush",
            "_objc_autoreleasePoolPop",
            "_objc_retain",
            "_objc_release",
            "_objc_autorelease",
            "_objc_storeStrong",
            "_objc_storeWeak",
            "_objc_initWeak",
            "_objc_destroyWeak",
            "_objc_loadWeakRetained",
            "_objc_retainAutorelease",
            "_objc_retainAutoreleasedReturnValue",
            "_objc_retainAutoreleaseReturnValue",
            "_objc_autoreleaseReturnValue",
            "_objc_unsafeClaimAutoreleasedReturnValue",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn foundation_startup_imports_are_apple_dispatched() {
        for symbol in [
            "_NSHomeDirectory",
            "_NSTemporaryDirectory",
            "_NSUserName",
            "_NSFullUserName",
            "_NSSearchPathForDirectoriesInDomains",
            "_NSClassFromString",
            "_NSSelectorFromString",
            "_NSStringFromClass",
            "_NSStringFromSelector",
            "_NSLog",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn objc_selector_raw_return_classifier_covers_foundation_scalars() {
        for selector in [
            "length",
            "count",
            "integerValue",
            "boolValue",
            "isEqualToString:",
            "respondsToSelector:",
            "authorizationStatusForMediaType:",
            "isConnected",
            "hasMediaType:",
            "prepareToRecord",
            "record",
            "isRecording",
        ] {
            assert!(objc_selector_returns_raw_value(selector));
        }
        assert!(!objc_selector_returns_raw_value("stringWithUTF8String:"));
        assert!(!objc_selector_returns_raw_value("dataUsingEncoding:"));
    }

    #[test]
    fn foundation_selector_classifier_covers_startup_glue() {
        for (kind, selector) in [
            ("NSProcessInfo", "processInfo"),
            ("NSProcessInfo", "environment"),
            ("NSBundle", "mainBundle"),
            ("NSBundle", "objectForInfoDictionaryKey:"),
            ("NSFileManager", "defaultManager"),
            ("NSFileManager", "fileExistsAtPath:isDirectory:"),
            ("NSFileManager", "URLsForDirectory:inDomains:"),
        ] {
            assert!(
                foundation_shim_supports_selector(kind, selector),
                "{kind} {selector} should be shimmed"
            );
        }
        assert!(!foundation_shim_supports_selector(
            "NSFileManager",
            "compatraUnknownSelector"
        ));
    }

    #[test]
    fn ui_selector_classifier_covers_appkit_startup_glue() {
        for (kind, selector) in [
            ("NSApplication", "sharedApplication"),
            ("NSApplication", "setActivationPolicy:"),
            ("NSApplication", "activationPolicy"),
            ("NSApplication", "isRunning"),
            ("NSThread", "mainThread"),
            ("NSThread", "isMainThread"),
            ("NSRunLoop", "currentRunLoop"),
            ("NSRunLoop", "runMode:beforeDate:"),
            ("NSDate", "date"),
            ("NSScreen", "mainScreen"),
            ("NSScreen", "screens"),
            ("NSScreen", "localizedName"),
            ("NSWindow", "title"),
            ("NSWindow", "setTitle:"),
            ("NSWindow", "orderFront:"),
        ] {
            assert!(
                foundation_shim_supports_selector(kind, selector),
                "{kind} {selector} should be shimmed"
            );
        }
    }

    #[test]
    fn synthetic_objc_class_fallback_covers_appkit_startup_classes() {
        let mut runtime = crate::macos::AppleRuntime::default();

        for name in [
            "NSApplication",
            "NSScreen",
            "NSWindow",
            "NSThread",
            "NSRunLoop",
        ] {
            let class_ref = register_objc_class_lookup_result(&mut runtime, name, None);
            assert_ne!(
                class_ref, 0,
                "{name} should have a synthetic class fallback"
            );
            assert_eq!(runtime.objc_class_name(class_ref).as_deref(), Some(name));
            assert_eq!(runtime.host_ptr_or_raw_unknown(class_ref), None);
        }

        assert_eq!(
            register_objc_class_lookup_result(&mut runtime, "CompatraUnknownClass", None),
            0
        );
    }

    #[test]
    fn apple_direct_dispatch_imports_cover_ui_startup_glue() {
        for symbol in [
            "_NSApplicationLoad",
            "_NSApplicationMain",
            "_CGMainDisplayID",
            "_CGDisplayPixelsWide",
            "_CGDisplayPixelsHigh",
            "_CGDisplayIsActive",
            "_CGDisplayIsOnline",
            "_CGPreflightScreenCaptureAccess",
            "_CGRequestScreenCaptureAccess",
            "_CGDisplayCreateImage",
            "_CGImageGetWidth",
            "_CGImageGetHeight",
            "_CGImageGetBitsPerPixel",
            "_CGImageGetBytesPerRow",
            "_CGImageGetDataProvider",
            "_CGImageRelease",
            "_CGDataProviderCopyData",
            "_CGEventSourceKeyState",
            "_CGPreflightListenEventAccess",
            "_CGRequestListenEventAccess",
            "_AXIsProcessTrusted",
            "_AXIsProcessTrustedWithOptions",
        ] {
            assert!(
                is_apple_import_symbol(symbol),
                "{symbol} should be Apple-dispatched"
            );
            assert!(
                APPLE_DIRECT_DISPATCH_IMPORTS.contains(&symbol),
                "{symbol} must be installed by install_apple_imports for static imports"
            );
        }
    }

    #[test]
    fn foundation_search_paths_include_common_user_directories() {
        let docs = foundation_search_paths(9, 1, true)
            .into_iter()
            .map(guest_path_bytes)
            .collect::<Vec<_>>();
        let caches = foundation_search_paths(13, 1, true)
            .into_iter()
            .map(guest_path_bytes)
            .collect::<Vec<_>>();

        assert!(
            docs.iter()
                .any(|path| String::from_utf8_lossy(path).contains("Documents")),
            "document search path should be present: {docs:?}"
        );
        assert!(
            caches
                .iter()
                .any(|path| String::from_utf8_lossy(path).contains("Caches")),
            "cache search path should be present: {caches:?}"
        );
    }

    #[test]
    fn bundle_path_helpers_preserve_explicit_bundle_path() {
        let mut runtime = crate::macos::AppleRuntime::default();
        runtime.set_process_name("/tmp/Test.app/Contents/MacOS/Test");
        let bundle = runtime.alloc_bundle(b"/tmp/Custom.app".to_vec(), None);

        assert_eq!(
            bundle_path_for_receiver(&runtime, bundle),
            b"/tmp/Custom.app".to_vec()
        );
        assert_eq!(
            bundle_resource_path_for_receiver(&runtime, bundle),
            b"/tmp/Custom.app/Contents/Resources".to_vec()
        );
        assert_eq!(
            bundle_executable_path_for_receiver(&runtime, bundle),
            b"/tmp/Custom.app/Contents/MacOS/Test".to_vec()
        );
    }
}
