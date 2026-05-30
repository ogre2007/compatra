//! Compatibility-mode host service boundary.

#[cfg(target_os = "macos")]
use std::ffi::CString;

pub use machina_mode::RuntimeMode;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityServices;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestMemoryError;

pub trait GuestMemory {
    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCallResult {
    pub return_value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOpenResult {
    pub path: String,
    pub return_value: u64,
    pub errno: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIoResult {
    pub return_value: u64,
    pub errno: u32,
    pub transferred: usize,
    pub preview: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostImportKind {
    #[cfg(target_os = "macos")]
    Puts,
    #[cfg(target_os = "macos")]
    Printf,
    #[cfg(target_os = "macos")]
    Putchar,
}

impl CompatibilityServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        mode.is_compat().then_some(Self)
    }

    pub fn should_proxy_import(&self, symbol: &str) -> bool {
        host_import_kind(symbol).is_some()
    }

    pub fn proxy_cstring_arg0_import<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        arg0_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(not(target_os = "macos"))]
        let _ = (&mut *memory, arg0_ptr);

        match host_import_kind(symbol)? {
            #[cfg(target_os = "macos")]
            HostImportKind::Puts => proxy_host_puts(memory, arg0_ptr),
            #[cfg(target_os = "macos")]
            HostImportKind::Printf => {
                proxy_host_printf(memory, &[arg0_ptr, 0, 0, 0, 0, 0, 0, 0], None)
            }
            #[cfg(target_os = "macos")]
            HostImportKind::Putchar => proxy_host_putchar(arg0_ptr),
        }
    }

    pub fn proxy_arm64_import<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        args: &[u64; 8],
    ) -> Option<HostCallResult> {
        self.proxy_arm64_import_with_stack(memory, symbol, args, None)
    }

    pub fn proxy_arm64_import_with_stack<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        symbol: &str,
        args: &[u64; 8],
        stack_ptr: Option<u64>,
    ) -> Option<HostCallResult> {
        #[cfg(not(target_os = "macos"))]
        let _ = (&mut *memory, args, stack_ptr);

        match host_import_kind(symbol)? {
            #[cfg(target_os = "macos")]
            HostImportKind::Puts => proxy_host_puts(memory, args[0]),
            #[cfg(target_os = "macos")]
            HostImportKind::Printf => {
                let stack_args = stack_ptr.map(|sp| read_stack_u64_args(memory, sp, 16));
                proxy_host_printf(memory, args, stack_args.as_deref())
            }
            #[cfg(target_os = "macos")]
            HostImportKind::Putchar => proxy_host_putchar(args[0]),
        }
    }

    pub fn open_path_arg0<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_open_arg0(memory, path_ptr, flags, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, flags, mode);
            None
        }
    }

    pub fn read_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_read(memory, fd, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            None
        }
    }

    pub fn write_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_write(memory, fd, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            None
        }
    }

    pub fn close_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_close(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }
}

fn host_import_kind(symbol: &str) -> Option<HostImportKind> {
    #[cfg(target_os = "macos")]
    {
        match normalize_import_name(symbol) {
            "puts" => Some(HostImportKind::Puts),
            "printf" => Some(HostImportKind::Printf),
            "putchar" => Some(HostImportKind::Putchar),
            _ => None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = symbol;
        None
    }
}

#[cfg(target_os = "macos")]
fn normalize_import_name(symbol: &str) -> &str {
    symbol.strip_prefix('_').unwrap_or(symbol)
}

#[cfg(target_os = "macos")]
fn read_cstring<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    max_len: usize,
) -> Result<String, GuestMemoryError> {
    let mut bytes = Vec::new();
    for offset in 0..max_len {
        let byte = memory
            .read_memory(addr.saturating_add(offset as u64), 1)?
            .first()
            .copied()
            .ok_or(GuestMemoryError)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "macos")]
fn read_stack_u64_args<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stack_ptr: u64,
    max_args: usize,
) -> Vec<u64> {
    let mut args = Vec::new();
    for idx in 0..max_args {
        let addr = stack_ptr.saturating_add((idx * 8) as u64);
        let Ok(bytes) = memory.read_memory(addr, 8) else {
            break;
        };
        let Ok(raw) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            break;
        };
        args.push(u64::from_le_bytes(raw));
    }
    args
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(target_os = "macos")]
fn host_errno() -> u32 {
    unsafe { *libc::__error() as u32 }
}

#[cfg(target_os = "macos")]
fn signed_return_value(ret: isize) -> u64 {
    ret as i64 as u64
}

#[cfg(target_os = "macos")]
fn host_io_result(ret: isize, preview: Vec<u8>) -> HostIoResult {
    HostIoResult {
        return_value: signed_return_value(ret),
        errno: if ret < 0 { host_errno() } else { 0 },
        transferred: ret.max(0) as usize,
        preview,
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_puts<M: GuestMemory + ?Sized>(
    memory: &mut M,
    arg0_ptr: u64,
) -> Option<HostCallResult> {
    let text = read_cstring(memory, arg0_ptr, 4096).ok()?;
    let host_text = CString::new(text).ok()?;
    clear_errno();
    let ret = unsafe { libc::puts(host_text.as_ptr()) };
    Some(HostCallResult {
        return_value: signed_return_value(ret as isize),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_putchar(ch: u64) -> Option<HostCallResult> {
    clear_errno();
    let ret = unsafe { libc::putchar(ch as libc::c_int) };
    Some(HostCallResult {
        return_value: signed_return_value(ret as isize),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_printf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    args: &[u64; 8],
    stack_args: Option<&[u64]>,
) -> Option<HostCallResult> {
    let format = read_cstring(memory, args[0], 4096).ok()?;
    let rendered = render_arm64_printf(memory, &format, &args[1..], stack_args);
    let host_text = CString::new(rendered).ok()?;
    clear_errno();
    let ret = unsafe { libc::printf(b"%s\0".as_ptr().cast(), host_text.as_ptr()) };
    Some(HostCallResult {
        return_value: signed_return_value(ret as isize),
    })
}

#[cfg(target_os = "macos")]
fn render_arm64_printf<M: GuestMemory + ?Sized>(
    memory: &mut M,
    format: &str,
    register_args: &[u64],
    stack_args: Option<&[u64]>,
) -> String {
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_index = 0usize;
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            out.push('%');
            continue;
        }

        while matches!(chars.peek(), Some('#' | '0' | '-' | '+' | ' ')) {
            chars.next();
        }
        while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            chars.next();
        }
        if chars.peek() == Some(&'.') {
            chars.next();
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                chars.next();
            }
        }
        let mut long_count = 0usize;
        while chars.peek() == Some(&'l') {
            chars.next();
            long_count += 1;
        }
        let spec = chars.next().unwrap_or('%');
        let stack_arg = stack_args.and_then(|args| args.get(arg_index).copied());
        let register_arg = register_args.get(arg_index).copied();
        let arg = stack_arg.or(register_arg).unwrap_or(0);
        if !matches!(spec, '%') {
            arg_index = arg_index.saturating_add(1);
        }
        match spec {
            's' => {
                let mut rendered = false;
                for candidate in stack_arg.into_iter().chain(register_arg) {
                    if candidate == 0 {
                        out.push_str("(null)");
                        rendered = true;
                        break;
                    }
                    if let Ok(value) = read_cstring(memory, candidate, 4096) {
                        out.push_str(&value);
                        rendered = true;
                        break;
                    }
                }
                if !rendered {
                    // Leave unreadable string arguments empty, matching the
                    // previous permissive renderer behavior.
                }
            }
            'c' => out.push(char::from_u32((arg as u8) as u32).unwrap_or('\u{FFFD}')),
            'd' | 'i' => {
                if long_count > 0 {
                    out.push_str(&(arg as i64).to_string());
                } else {
                    out.push_str(&(arg as i32).to_string());
                }
            }
            'u' => {
                if long_count > 0 {
                    out.push_str(&arg.to_string());
                } else {
                    out.push_str(&(arg as u32).to_string());
                }
            }
            'x' => {
                if long_count > 0 {
                    out.push_str(&format!("{:x}", arg));
                } else {
                    out.push_str(&format!("{:x}", arg as u32));
                }
            }
            'X' => {
                if long_count > 0 {
                    out.push_str(&format!("{:X}", arg));
                } else {
                    out.push_str(&format!("{:X}", arg as u32));
                }
            }
            'p' => out.push_str(&format!("0x{:x}", arg)),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn proxy_host_open_arg0<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> Option<HostOpenResult> {
    let path = read_cstring(memory, path_ptr, 4096).ok()?;
    let host_path = CString::new(path.clone()).ok()?;
    clear_errno();
    let ret = unsafe {
        libc::open(
            host_path.as_ptr(),
            flags as libc::c_int,
            mode as libc::mode_t as libc::c_uint,
        )
    };
    Some(HostOpenResult {
        path,
        return_value: signed_return_value(ret as isize),
        errno: if ret < 0 { host_errno() } else { 0 },
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_read<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::read(fd as libc::c_int, data.as_mut_ptr().cast(), count) };
    if ret > 0 {
        let read_len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..read_len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        data.truncate(read_len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_write<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => {
                return Some(HostIoResult {
                    return_value: u64::MAX,
                    errno: libc::EFAULT as u32,
                    transferred: 0,
                    preview: Vec::new(),
                });
            }
        }
    };
    clear_errno();
    let ret = unsafe { libc::write(fd as libc::c_int, data.as_ptr().cast(), data.len()) };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_close(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::close(fd as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_mode_has_no_compat_services() {
        assert_eq!(CompatibilityServices::for_mode(RuntimeMode::Analysis), None);
        assert_eq!(
            CompatibilityServices::for_mode(RuntimeMode::Compat),
            Some(CompatibilityServices)
        );
    }

    #[test]
    fn host_proxy_imports_are_darwin_bound() {
        let compat = CompatibilityServices;
        #[cfg(target_os = "macos")]
        {
            assert!(compat.should_proxy_import("_puts"));
            assert!(compat.should_proxy_import("_printf"));
            assert!(compat.should_proxy_import("_putchar"));
        }
        #[cfg(not(target_os = "macos"))]
        assert!(!compat.should_proxy_import("_puts"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn printf_renderer_prefers_darwin_stack_varargs() {
        #[derive(Default)]
        struct TestMemory {
            bytes: std::collections::HashMap<u64, u8>,
        }

        impl TestMemory {
            fn write_guest(&mut self, addr: u64, data: &[u8]) {
                for (offset, byte) in data.iter().enumerate() {
                    self.bytes.insert(addr + offset as u64, *byte);
                }
            }
        }

        impl GuestMemory for TestMemory {
            fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
                (0..size)
                    .map(|offset| {
                        self.bytes
                            .get(&(addr + offset as u64))
                            .copied()
                            .ok_or(GuestMemoryError)
                    })
                    .collect()
            }

            fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryError> {
                self.write_guest(addr, data);
                Ok(())
            }
        }

        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, b"dlsym\0");
        memory.write_guest(0x2000, &0x1000u64.to_le_bytes());
        memory.write_guest(0x3000, b"register\0");

        let stack_args = read_stack_u64_args(&mut memory, 0x2000, 1);
        assert_eq!(
            render_arm64_printf(
                &mut memory,
                "compat %s path\n",
                &[0x3000],
                Some(&stack_args)
            ),
            "compat dlsym path\n"
        );
    }
}
