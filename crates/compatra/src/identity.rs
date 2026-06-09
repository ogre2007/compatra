//! Host-backed user and group identity services.

use crate::{CompatibilityServices, GuestMemory, HostCallResult, HostIoResult};

#[cfg(target_os = "macos")]
use crate::logging::{emit_verbose_compat_payload, hex_arg};
#[cfg(target_os = "macos")]
use crate::{
    clear_errno, host_call_error, host_call_value, host_errno, host_io_error, host_io_result,
    read_cstring,
};

#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::ptr;

impl CompatibilityServices {
    pub fn getlogin_name<M: GuestMemory + ?Sized>(&self, memory: &mut M) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getlogin(memory);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = memory;
            None
        }
    }

    pub fn getlogin_r_name<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        buf_size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getlogin_r(memory, buf_ptr, buf_size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, buf_size);
            None
        }
    }

    pub fn getpwuid_entry<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        uid: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getpwuid(memory, uid);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, uid);
            None
        }
    }

    pub fn getpwnam_entry<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        name_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getpwnam(memory, name_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, name_ptr);
            None
        }
    }

    pub fn getgroups_list<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        count: u64,
        list_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getgroups(memory, count, list_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, count, list_ptr);
            None
        }
    }
}

#[cfg(target_os = "macos")]
const DARWIN_PASSWD_SIZE: usize = 72;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_NAME: usize = 0;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_PASSWD: usize = 8;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_UID: usize = 16;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_GID: usize = 20;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_CHANGE: usize = 24;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_CLASS: usize = 32;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_GECOS: usize = 40;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_DIR: usize = 48;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_SHELL: usize = 56;
#[cfg(target_os = "macos")]
const DARWIN_PASSWD_PW_EXPIRE: usize = 64;

#[cfg(target_os = "macos")]
fn proxy_host_getlogin<M: GuestMemory + ?Sized>(memory: &mut M) -> Option<HostCallResult> {
    match host_login_name() {
        Some(name) => {
            let ptr = allocate_guest_cstring(memory, &name)?;
            emit_identity_log(
                "getlogin",
                vec![],
                vec![
                    ("Name", Some(name)),
                    ("Model", Some("host-userdb".to_string())),
                ],
                &host_call_value(ptr),
            );
            Some(host_call_value(ptr))
        }
        None => {
            let result = host_call_error(host_errno());
            emit_identity_log(
                "getlogin",
                vec![],
                vec![
                    ("Name", None),
                    ("Model", Some("host-userdb".to_string())),
                    ("Reason", Some("host getlogin returned null".to_string())),
                ],
                &result,
            );
            Some(result)
        }
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_getlogin_r<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    buf_size: u64,
) -> Option<HostCallResult> {
    if buf_ptr == 0 {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    let Some(name) = host_login_name() else {
        return Some(host_call_value(host_errno() as u64));
    };
    let required = name.len().saturating_add(1);
    if buf_size < required as u64 {
        return Some(host_call_value(libc::ERANGE as u64));
    }
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    let result = if memory.write_memory(buf_ptr, &bytes).is_ok() {
        host_call_value(0)
    } else {
        host_call_value(libc::EFAULT as u64)
    };
    emit_identity_log(
        "getlogin_r",
        vec![("buf", hex_arg(buf_ptr)), ("size", buf_size.to_string())],
        vec![
            ("Name", Some(name)),
            ("RequiredBytes", Some(required.to_string())),
            ("Model", Some("host-userdb".to_string())),
        ],
        &result,
    );
    Some(result)
}

#[cfg(target_os = "macos")]
fn proxy_host_getpwuid<M: GuestMemory + ?Sized>(
    memory: &mut M,
    uid: u64,
) -> Option<HostCallResult> {
    clear_errno();
    let passwd = unsafe { libc::getpwuid(uid as libc::uid_t) };
    let result = marshal_host_passwd(memory, passwd, "getpwuid", vec![("uid", uid.to_string())]);
    Some(result)
}

#[cfg(target_os = "macos")]
fn proxy_host_getpwnam<M: GuestMemory + ?Sized>(
    memory: &mut M,
    name_ptr: u64,
) -> Option<HostCallResult> {
    let name = match read_cstring(memory, name_ptr, 1024) {
        Ok(name) => name,
        Err(_) => return Some(host_call_error(libc::EFAULT as u32)),
    };
    let host_name = match CString::new(name.clone()) {
        Ok(host_name) => host_name,
        Err(_) => return Some(host_call_error(libc::EINVAL as u32)),
    };
    clear_errno();
    let passwd = unsafe { libc::getpwnam(host_name.as_ptr()) };
    let result = marshal_host_passwd(
        memory,
        passwd,
        "getpwnam",
        vec![("name", hex_arg(name_ptr))],
    );
    if result.return_value == 0 {
        emit_identity_log(
            "getpwnam",
            vec![("name", hex_arg(name_ptr))],
            vec![
                ("Name", Some(name)),
                ("Model", Some("host-userdb".to_string())),
            ],
            &result,
        );
    }
    Some(result)
}

#[cfg(target_os = "macos")]
fn proxy_host_getgroups<M: GuestMemory + ?Sized>(
    memory: &mut M,
    count: u64,
    list_ptr: u64,
) -> Option<HostIoResult> {
    if count > i32::MAX as u64 {
        return Some(host_io_error(libc::EINVAL as u32));
    }
    if count > 0 && list_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    clear_errno();
    let result = unsafe {
        libc::getgroups(
            count as libc::c_int,
            if count == 0 {
                ptr::null_mut()
            } else {
                groups.as_mut_ptr()
            },
        )
    };
    let errno = if result < 0 { host_errno() } else { 0 };
    let returned = result.max(0) as usize;
    if result >= 0 && count > 0 {
        let mut bytes = Vec::with_capacity(returned.saturating_mul(4));
        for gid in groups.into_iter().take(returned) {
            bytes.extend_from_slice(&(gid as u32).to_le_bytes());
        }
        if memory.write_memory(list_ptr, &bytes).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
    }
    let io = host_io_result(result as isize, Vec::new());
    emit_identity_io_log(
        "getgroups",
        vec![("count", count.to_string()), ("list", hex_arg(list_ptr))],
        vec![
            ("ReturnedGroups", Some(returned.to_string())),
            ("Model", Some("host-userdb".to_string())),
        ],
        &io,
    );
    Some(HostIoResult {
        return_value: io.return_value,
        errno,
        transferred: returned.saturating_mul(4),
        preview: Vec::new(),
    })
}

#[cfg(target_os = "macos")]
fn marshal_host_passwd<M: GuestMemory + ?Sized>(
    memory: &mut M,
    passwd: *mut libc::passwd,
    call: &str,
    args: Vec<(&str, String)>,
) -> HostCallResult {
    if passwd.is_null() {
        let result = HostCallResult {
            return_value: 0,
            errno: Some(host_errno()),
        };
        emit_identity_log(
            call,
            args,
            vec![
                ("Model", Some("host-userdb".to_string())),
                ("Reason", Some("host passwd entry not found".to_string())),
            ],
            &result,
        );
        return result;
    }
    let passwd = unsafe { &*passwd };
    let name = host_cstr(passwd.pw_name);
    let password = host_cstr(passwd.pw_passwd);
    let class = host_cstr(passwd.pw_class);
    let gecos = host_cstr(passwd.pw_gecos);
    let dir = host_cstr(passwd.pw_dir);
    let shell = host_cstr(passwd.pw_shell);

    let Some(name_ptr) = allocate_guest_cstring(memory, &name) else {
        return host_call_error(libc::ENOMEM as u32);
    };
    let Some(password_ptr) = allocate_guest_cstring(memory, &password) else {
        return host_call_error(libc::ENOMEM as u32);
    };
    let Some(class_ptr) = allocate_guest_cstring(memory, &class) else {
        return host_call_error(libc::ENOMEM as u32);
    };
    let Some(gecos_ptr) = allocate_guest_cstring(memory, &gecos) else {
        return host_call_error(libc::ENOMEM as u32);
    };
    let Some(dir_ptr) = allocate_guest_cstring(memory, &dir) else {
        return host_call_error(libc::ENOMEM as u32);
    };
    let Some(shell_ptr) = allocate_guest_cstring(memory, &shell) else {
        return host_call_error(libc::ENOMEM as u32);
    };

    let Some(struct_ptr) = allocate_guest_passwd(
        memory,
        GuestPasswd {
            name_ptr,
            password_ptr,
            uid: passwd.pw_uid as u32,
            gid: passwd.pw_gid as u32,
            change: passwd.pw_change as i64,
            class_ptr,
            gecos_ptr,
            dir_ptr,
            shell_ptr,
            expire: passwd.pw_expire as i64,
        },
    ) else {
        return host_call_error(libc::ENOMEM as u32);
    };

    let result = host_call_value(struct_ptr);
    emit_identity_log(
        call,
        args,
        vec![
            ("Name", Some(name)),
            ("Uid", Some((passwd.pw_uid as u32).to_string())),
            ("Gid", Some((passwd.pw_gid as u32).to_string())),
            ("Dir", Some(dir)),
            ("Shell", Some(shell)),
            ("Struct", Some(hex_arg(struct_ptr))),
            ("Model", Some("host-userdb".to_string())),
        ],
        &result,
    );
    result
}

#[cfg(target_os = "macos")]
struct GuestPasswd {
    name_ptr: u64,
    password_ptr: u64,
    uid: u32,
    gid: u32,
    change: i64,
    class_ptr: u64,
    gecos_ptr: u64,
    dir_ptr: u64,
    shell_ptr: u64,
    expire: i64,
}

#[cfg(target_os = "macos")]
fn allocate_guest_passwd<M: GuestMemory + ?Sized>(
    memory: &mut M,
    passwd: GuestPasswd,
) -> Option<u64> {
    let addr = memory.allocate_memory(DARWIN_PASSWD_SIZE, 8).ok()?;
    let mut bytes = vec![0u8; DARWIN_PASSWD_SIZE];
    write_u64(&mut bytes, DARWIN_PASSWD_PW_NAME, passwd.name_ptr);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_PASSWD, passwd.password_ptr);
    write_u32(&mut bytes, DARWIN_PASSWD_PW_UID, passwd.uid);
    write_u32(&mut bytes, DARWIN_PASSWD_PW_GID, passwd.gid);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_CHANGE, passwd.change as u64);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_CLASS, passwd.class_ptr);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_GECOS, passwd.gecos_ptr);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_DIR, passwd.dir_ptr);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_SHELL, passwd.shell_ptr);
    write_u64(&mut bytes, DARWIN_PASSWD_PW_EXPIRE, passwd.expire as u64);
    if memory.write_memory(addr, &bytes).is_err() {
        let _ = memory.free_memory(addr);
        return None;
    }
    Some(addr)
}

#[cfg(target_os = "macos")]
fn allocate_guest_cstring<M: GuestMemory + ?Sized>(memory: &mut M, text: &str) -> Option<u64> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    let addr = memory.allocate_memory(bytes.len(), 1).ok()?;
    if memory.write_memory(addr, &bytes).is_err() {
        let _ = memory.free_memory(addr);
        return None;
    }
    Some(addr)
}

#[cfg(target_os = "macos")]
fn host_login_name() -> Option<String> {
    clear_errno();
    let login = unsafe { libc::getlogin() };
    if !login.is_null() {
        return Some(host_cstr(login));
    }
    std::env::var("USER")
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| {
            let passwd = unsafe { libc::getpwuid(libc::getuid()) };
            (!passwd.is_null()).then(|| host_cstr(unsafe { (*passwd).pw_name }))
        })
}

#[cfg(target_os = "macos")]
fn host_cstr(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(target_os = "macos")]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "macos")]
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "macos")]
fn emit_identity_log(
    call: &str,
    args: Vec<(&str, String)>,
    mut fields: Vec<(&str, Option<String>)>,
    result: &HostCallResult,
) {
    fields.push((
        "return",
        Some(crate::logging::format_return(result.return_value)),
    ));
    fields.push(("return_hex", Some(format!("0x{:X}", result.return_value))));
    fields.push(("errno", result.errno.map(|errno| errno.to_string())));
    emit_verbose_compat_payload("identity", call, &args, &mut fields, None);
}

#[cfg(target_os = "macos")]
fn emit_identity_io_log(
    call: &str,
    args: Vec<(&str, String)>,
    mut fields: Vec<(&str, Option<String>)>,
    result: &HostIoResult,
) {
    fields.push((
        "return",
        Some(crate::logging::format_return(result.return_value)),
    ));
    fields.push(("return_hex", Some(format!("0x{:X}", result.return_value))));
    fields.push(("errno", Some(result.errno.to_string())));
    fields.push(("transferred", Some(result.transferred.to_string())));
    emit_verbose_compat_payload("identity", call, &args, &mut fields, None);
}
