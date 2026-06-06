//! Network host proxy services for compatibility mode.

use crate::logging::{hex_arg, CompatLogScope};
use crate::{CompatibilityServices, GuestMemory, HostCallResult, HostIoResult};

#[cfg(target_os = "macos")]
use crate::filesystem::{
    host_iovec_from_buffer, host_iovec_from_mut_buffer, preview_iovec_bytes,
    read_guest_iovec_bytes, read_guest_iovecs, write_guest_iovec_bytes,
};
#[cfg(target_os = "macos")]
use crate::{
    allocate_guest_bytes, clear_errno, host_call_error, host_call_result, host_errno,
    host_io_error, host_io_result, read_cstring, signed_return_value, write_guest_i32,
    write_guest_u32, write_guest_u64, write_i32_at, write_u32_at, write_u64_at, GuestMemoryError,
};
#[cfg(any(target_os = "macos", test))]
use crate::{read_i32_at, read_u32_at, read_u64_at};

#[cfg(target_os = "macos")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::mem::{self, MaybeUninit};
#[cfg(target_os = "macos")]
use std::ptr;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_SIZE: usize = 48;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_FLAGS: usize = 0;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_FAMILY: usize = 4;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_SOCKTYPE: usize = 8;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_PROTOCOL: usize = 12;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_ADDRLEN: usize = 16;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_CANONNAME: usize = 24;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_ADDR: usize = 32;
#[cfg(target_os = "macos")]
const DARWIN_ADDRINFO_AI_NEXT: usize = 40;
#[cfg(target_os = "macos")]
const MAX_ADDRINFO_RESULTS: usize = 64;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_SIZE: usize = 48;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_NAME: usize = 0;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_NAMELEN: usize = 8;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_IOV: usize = 16;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_IOVLEN: usize = 24;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_CONTROL: usize = 32;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_CONTROLLEN: usize = 40;
#[cfg(any(target_os = "macos", test))]
const DARWIN_MSGHDR_FLAGS: usize = 44;
#[cfg(target_os = "macos")]
const MAX_GUEST_MSG_SIDE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "macos")]
extern "C" {
    fn inet_addr(cp: *const libc::c_char) -> libc::in_addr_t;
    fn inet_aton(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
    fn inet_ntop(
        af: libc::c_int,
        src: *const libc::c_void,
        dst: *mut libc::c_char,
        size: libc::socklen_t,
    ) -> *const libc::c_char;
}

impl CompatibilityServices {
    pub fn socket(&self, domain: u64, kind: u64, protocol: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_socket(domain, kind, protocol);
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
            ];
            log_scope.io_result("direct", "socket", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (domain, kind, protocol);
            let result = None;
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
            ];
            log_scope.io_result("direct", "socket", &log_args, &result);
            result
        }
    }

    pub fn connect_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_connect(memory, fd, sockaddr_ptr, sockaddr_len);
            let mut log_args = vec![
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_args.extend(sockaddr_log_fields(memory, sockaddr_ptr, sockaddr_len));
            log_scope.io_result("direct", "connect", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "connect", &log_args, &result);
            result
        }
    }

    pub fn bind_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_bind(memory, fd, sockaddr_ptr, sockaddr_len);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "bind", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "bind", &log_args, &result);
            result
        }
    }

    pub fn listen_socket(&self, fd: u64, backlog: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_listen(fd, backlog);
            let log_args = [("fd", fd.to_string()), ("backlog", backlog.to_string())];
            log_scope.io_result("direct", "listen", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, backlog);
            let result = None;
            let log_args = [("fd", fd.to_string()), ("backlog", backlog.to_string())];
            log_scope.io_result("direct", "listen", &log_args, &result);
            result
        }
    }

    pub fn send_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_send(memory, fd, buf_ptr, count, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "send", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "send", &log_args, &result);
            result
        }
    }

    pub fn recv_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recv(memory, fd, buf_ptr, count, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recv", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recv", &log_args, &result);
            result
        }
    }

    pub fn sendto_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_sendto(
                memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "sendto", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
            ];
            log_scope.io_result("direct", "sendto", &log_args, &result);
            result
        }
    }

    pub fn recvfrom_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recvfrom(
                memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len_ptr,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "recvfrom", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                buf_ptr,
                count,
                flags,
                sockaddr_ptr,
                sockaddr_len_ptr,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
                ("flags", hex_arg(flags)),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "recvfrom", &log_args, &result);
            result
        }
    }

    pub fn sendmsg_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_sendmsg(memory, fd, msg_ptr, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "sendmsg", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, msg_ptr, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "sendmsg", &log_args, &result);
            result
        }
    }

    pub fn recvmsg_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_recvmsg(memory, fd, msg_ptr, flags);
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recvmsg", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, msg_ptr, flags);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("msg", hex_arg(msg_ptr)),
                ("flags", hex_arg(flags)),
            ];
            log_scope.io_result("direct", "recvmsg", &log_args, &result);
            result
        }
    }

    pub fn shutdown_socket(&self, fd: u64, how: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_shutdown(fd, how);
            let log_args = [("fd", fd.to_string()), ("how", how.to_string())];
            log_scope.io_result("direct", "shutdown", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, how);
            let result = None;
            let log_args = [("fd", fd.to_string()), ("how", how.to_string())];
            log_scope.io_result("direct", "shutdown", &log_args, &result);
            result
        }
    }

    pub fn setsockopt_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result =
                proxy_host_setsockopt(memory, fd, level, option_name, option_value_ptr, option_len);
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len", option_len.to_string()),
            ];
            log_scope.io_result("direct", "setsockopt", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len", option_len.to_string()),
            ];
            log_scope.io_result("direct", "setsockopt", &log_args, &result);
            result
        }
    }

    pub fn getsockopt_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getsockopt(
                memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len_ptr,
            );
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len_ptr", hex_arg(option_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockopt", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                fd,
                level,
                option_name,
                option_value_ptr,
                option_len_ptr,
            );
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("level", level.to_string()),
                ("option", option_name.to_string()),
                ("value", hex_arg(option_value_ptr)),
                ("len_ptr", hex_arg(option_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockopt", &log_args, &result);
            result
        }
    }

    pub fn accept_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_accept(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "accept", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "accept", &log_args, &result);
            result
        }
    }

    pub fn getpeername_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getpeername(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getpeername", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getpeername", &log_args, &result);
            result
        }
    }

    pub fn getsockname_socket<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getsockname(memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockname", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, sockaddr_ptr, sockaddr_len_ptr);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len_ptr", hex_arg(sockaddr_len_ptr)),
            ];
            log_scope.io_result("direct", "getsockname", &log_args, &result);
            result
        }
    }

    pub fn socketpair<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        domain: u64,
        kind: u64,
        protocol: u64,
        sv_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_socketpair(memory, domain, kind, protocol, sv_ptr);
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
                ("sv", hex_arg(sv_ptr)),
            ];
            log_scope.io_result("direct", "socketpair", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, domain, kind, protocol, sv_ptr);
            let result = None;
            let log_args = [
                ("domain", domain.to_string()),
                ("type", kind.to_string()),
                ("protocol", protocol.to_string()),
                ("sv", hex_arg(sv_ptr)),
            ];
            log_scope.io_result("direct", "socketpair", &log_args, &result);
            result
        }
    }
    pub fn getaddrinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        node_ptr: u64,
        service_ptr: u64,
        hints_ptr: u64,
        result_ptr: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result =
                proxy_host_getaddrinfo(memory, node_ptr, service_ptr, hints_ptr, result_ptr);
            let log_args = [
                ("node", hex_arg(node_ptr)),
                ("service", hex_arg(service_ptr)),
                ("hints", hex_arg(hints_ptr)),
                ("result_ptr", hex_arg(result_ptr)),
            ];
            log_scope.call_result("direct", "getaddrinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, node_ptr, service_ptr, hints_ptr, result_ptr);
            let result = None;
            let log_args = [
                ("node", hex_arg(node_ptr)),
                ("service", hex_arg(service_ptr)),
                ("hints", hex_arg(hints_ptr)),
                ("result_ptr", hex_arg(result_ptr)),
            ];
            log_scope.call_result("direct", "getaddrinfo", &log_args, &result);
            result
        }
    }

    pub fn freeaddrinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        addrinfo_ptr: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_freeaddrinfo(memory, addrinfo_ptr);
            let log_args = [("addrinfo", hex_arg(addrinfo_ptr))];
            log_scope.call_result("direct", "freeaddrinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, addrinfo_ptr);
            let result = None;
            let log_args = [("addrinfo", hex_arg(addrinfo_ptr))];
            log_scope.call_result("direct", "freeaddrinfo", &log_args, &result);
            result
        }
    }

    pub fn gai_strerror<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        errcode: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_gai_strerror(memory, errcode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, errcode);
            None
        }
    }

    pub fn getnameinfo<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
        host_ptr: u64,
        host_len: u64,
        service_ptr: u64,
        service_len: u64,
        flags: u64,
    ) -> Option<HostCallResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_getnameinfo(
                memory,
                sockaddr_ptr,
                sockaddr_len,
                host_ptr,
                host_len,
                service_ptr,
                service_len,
                flags,
            );
            let log_args = [
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
                ("host", hex_arg(host_ptr)),
                ("host_len", host_len.to_string()),
                ("service", hex_arg(service_ptr)),
                ("service_len", service_len.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.call_result("direct", "getnameinfo", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                sockaddr_ptr,
                sockaddr_len,
                host_ptr,
                host_len,
                service_ptr,
                service_len,
                flags,
            );
            let result = None;
            let log_args = [
                ("sockaddr", hex_arg(sockaddr_ptr)),
                ("sockaddr_len", sockaddr_len.to_string()),
                ("host", hex_arg(host_ptr)),
                ("host_len", host_len.to_string()),
                ("service", hex_arg(service_ptr)),
                ("service_len", service_len.to_string()),
                ("flags", hex_arg(flags)),
            ];
            log_scope.call_result("direct", "getnameinfo", &log_args, &result);
            result
        }
    }

    pub fn inet_pton<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        family: u64,
        src_ptr: u64,
        dst_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_pton(memory, family, src_ptr, dst_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, family, src_ptr, dst_ptr);
            None
        }
    }

    pub fn inet_ntop<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        family: u64,
        src_ptr: u64,
        dst_ptr: u64,
        dst_len: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_ntop(memory, family, src_ptr, dst_ptr, dst_len);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, family, src_ptr, dst_ptr, dst_len);
            None
        }
    }

    pub fn inet_addr<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        src_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_addr(memory, src_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, src_ptr);
            None
        }
    }

    pub fn inet_aton<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        src_ptr: u64,
        dst_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_inet_aton(memory, src_ptr, dst_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, src_ptr, dst_ptr);
            None
        }
    }
}
#[cfg(target_os = "macos")]
fn gai_call_result(ret: libc::c_int) -> HostCallResult {
    HostCallResult {
        return_value: signed_return_value(ret as isize),
        errno: None,
    }
}
#[cfg(target_os = "macos")]
fn read_socklen<M: GuestMemory + ?Sized>(memory: &mut M, addr: u64) -> Option<libc::socklen_t> {
    let bytes = memory
        .read_memory(addr, mem::size_of::<libc::socklen_t>())
        .ok()?;
    let raw = <[u8; 4]>::try_from(bytes.as_slice()).ok()?;
    Some(u32::from_le_bytes(raw) as libc::socklen_t)
}

#[cfg(target_os = "macos")]
fn write_socklen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    value: libc::socklen_t,
) -> Result<(), GuestMemoryError> {
    memory.write_memory(addr, &(value as u32).to_le_bytes())
}

#[cfg(target_os = "macos")]
fn read_sockaddr_storage<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    len: u64,
) -> Option<(MaybeUninit<libc::sockaddr_storage>, libc::socklen_t)> {
    if addr == 0 || len == 0 {
        return None;
    }
    let copy_len = (len as usize).min(mem::size_of::<libc::sockaddr_storage>());
    let bytes = memory.read_memory(addr, copy_len).ok()?;
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast::<u8>(), copy_len);
    }
    Some((storage, copy_len as libc::socklen_t))
}

#[cfg(target_os = "macos")]
pub(crate) fn sockaddr_log_fields<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    len: u64,
) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if addr == 0 || len < 2 {
        fields.push(("SockaddrDecode", "unavailable".to_string()));
        return fields;
    }
    let Ok(bytes) = memory.read_memory(addr, (len as usize).min(256)) else {
        fields.push(("SockaddrDecode", "read-error".to_string()));
        return fields;
    };
    if bytes.len() < 2 {
        fields.push(("SockaddrDecode", "short".to_string()));
        return fields;
    }

    let family = bytes[1] as i32;
    fields.push(("Family", sockaddr_family_name(family).to_string()));
    match family {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let address = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            fields.push(("Address", address.to_string()));
            fields.push(("Port", port.to_string()));
            fields.push(("Endpoint", format!("{address}:{port}")));
        }
        libc::AF_INET6 if bytes.len() >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[8..24]);
            let address = std::net::Ipv6Addr::from(raw);
            let scope = read_u32_at(&bytes, 24).unwrap_or(0);
            fields.push(("Address", address.to_string()));
            fields.push(("Port", port.to_string()));
            if scope != 0 {
                fields.push(("ScopeId", scope.to_string()));
                fields.push(("Endpoint", format!("[{address}%{scope}]:{port}")));
            } else {
                fields.push(("Endpoint", format!("[{address}]:{port}")));
            }
        }
        libc::AF_UNIX if bytes.len() > 2 => {
            let path = bytes[2..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|end| &bytes[2..2 + end])
                .unwrap_or(&bytes[2..]);
            fields.push(("Address", String::from_utf8_lossy(path).into_owned()));
        }
        _ => {
            fields.push(("SockaddrDecode", "unsupported-family".to_string()));
        }
    }
    fields
}

#[cfg(target_os = "macos")]
fn sockaddr_family_name(family: i32) -> &'static str {
    match family {
        libc::AF_UNIX => "AF_UNIX",
        libc::AF_INET => "AF_INET",
        libc::AF_INET6 => "AF_INET6",
        _ => "unknown",
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_socket(domain: u64, kind: u64, protocol: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe {
        libc::socket(
            domain as libc::c_int,
            kind as libc::c_int,
            protocol as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_connect<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::connect(
            fd as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_bind<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::bind(
            fd as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_listen(fd: u64, backlog: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::listen(fd as libc::c_int, backlog as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_send<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
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
    let ret = unsafe {
        libc::send(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_recv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::recv(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            flags as libc::c_int,
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_sendto<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len == 0 {
        return proxy_host_send(memory, fd, buf_ptr, count, flags);
    }
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
    let (storage, len) = match read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len) {
        Some(value) => value,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    clear_errno();
    let ret = unsafe {
        libc::sendto(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            flags as libc::c_int,
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_recvfrom<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    flags: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
        return proxy_host_recv(memory, fd, buf_ptr, count, flags);
    }
    let requested_len = read_socklen(memory, sockaddr_len_ptr)
        .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
        .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t);
    let mut data = vec![0u8; count];
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        libc::recvfrom(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            flags as libc::c_int,
            storage.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut addr_len,
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(HostIoResult {
                return_value: u64::MAX,
                errno: libc::EFAULT as u32,
                transferred: 0,
                preview: Vec::new(),
            });
        }
        let sockaddr_copy_len = (addr_len as usize)
            .min(requested_len as usize)
            .min(mem::size_of::<libc::sockaddr_storage>());
        let sockaddr_bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), sockaddr_copy_len) };
        if sockaddr_copy_len > 0 && memory.write_memory(sockaddr_ptr, sockaddr_bytes).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if write_socklen(memory, sockaddr_len_ptr, addr_len).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestMsghdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: i32,
    control: u64,
    controllen: u32,
    flags: i32,
}

#[cfg(any(target_os = "macos", test))]
fn parse_darwin_msghdr(bytes: &[u8]) -> Option<GuestMsghdr> {
    Some(GuestMsghdr {
        name: read_u64_at(bytes, DARWIN_MSGHDR_NAME)?,
        namelen: read_u32_at(bytes, DARWIN_MSGHDR_NAMELEN)?,
        iov: read_u64_at(bytes, DARWIN_MSGHDR_IOV)?,
        iovlen: read_i32_at(bytes, DARWIN_MSGHDR_IOVLEN)?,
        control: read_u64_at(bytes, DARWIN_MSGHDR_CONTROL)?,
        controllen: read_u32_at(bytes, DARWIN_MSGHDR_CONTROLLEN)?,
        flags: read_i32_at(bytes, DARWIN_MSGHDR_FLAGS)?,
    })
}

#[cfg(target_os = "macos")]
fn read_guest_msghdr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    msg_ptr: u64,
) -> Result<GuestMsghdr, u32> {
    if msg_ptr == 0 {
        return Err(libc::EFAULT as u32);
    }
    let bytes = memory
        .read_memory(msg_ptr, DARWIN_MSGHDR_SIZE)
        .map_err(|_| libc::EFAULT as u32)?;
    parse_darwin_msghdr(&bytes).ok_or(libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn write_guest_msghdr_outputs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    msg_ptr: u64,
    msg: &GuestMsghdr,
) -> Result<(), u32> {
    write_guest_u32(memory, msg_ptr + DARWIN_MSGHDR_NAMELEN as u64, msg.namelen)
        .map_err(|_| libc::EFAULT as u32)?;
    write_guest_u32(
        memory,
        msg_ptr + DARWIN_MSGHDR_CONTROLLEN as u64,
        msg.controllen,
    )
    .map_err(|_| libc::EFAULT as u32)?;
    write_guest_i32(memory, msg_ptr + DARWIN_MSGHDR_FLAGS as u64, msg.flags)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn read_guest_side_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    ptr: u64,
    len: usize,
) -> Result<Vec<u8>, u32> {
    if len > MAX_GUEST_MSG_SIDE_BYTES {
        return Err(libc::EINVAL as u32);
    }
    if ptr == 0 || len == 0 {
        return Ok(Vec::new());
    }
    memory
        .read_memory(ptr, len)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn zeroed_guest_side_bytes(ptr: u64, len: usize) -> Result<Vec<u8>, u32> {
    if len > MAX_GUEST_MSG_SIDE_BYTES {
        return Err(libc::EINVAL as u32);
    }
    if ptr == 0 || len == 0 {
        Ok(Vec::new())
    } else {
        Ok(vec![0u8; len])
    }
}

#[cfg(target_os = "macos")]
fn optional_vec_mut_ptr(data: &mut Vec<u8>) -> *mut libc::c_void {
    if data.is_empty() {
        ptr::null_mut()
    } else {
        data.as_mut_ptr().cast()
    }
}

#[cfg(target_os = "macos")]
fn msg_iovcnt(iovlen: libc::c_int) -> Result<u64, u32> {
    u64::try_from(iovlen).map_err(|_| libc::EINVAL as u32)
}

#[cfg(target_os = "macos")]
fn proxy_host_sendmsg<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    msg_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let guest_msg = match read_guest_msghdr(memory, msg_ptr) {
        Ok(msg) => msg,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovcnt = match msg_iovcnt(guest_msg.iovlen) {
        Ok(iovcnt) => iovcnt,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovecs = match read_guest_iovecs(memory, guest_msg.iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let buffers = match read_guest_iovec_bytes(memory, &iovecs) {
        Ok(buffers) => buffers,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut host_iovecs = buffers
        .iter()
        .map(host_iovec_from_buffer)
        .collect::<Vec<_>>();
    let mut name = match read_guest_side_bytes(memory, guest_msg.name, guest_msg.namelen as usize) {
        Ok(name) => name,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut control =
        match read_guest_side_bytes(memory, guest_msg.control, guest_msg.controllen as usize) {
            Ok(control) => control,
            Err(errno) => return Some(host_io_error(errno)),
        };
    let preview = preview_iovec_bytes(&buffers);
    let host_msg = libc::msghdr {
        msg_name: optional_vec_mut_ptr(&mut name),
        msg_namelen: if name.is_empty() {
            0
        } else {
            guest_msg.namelen as libc::socklen_t
        },
        msg_iov: host_iovecs.as_mut_ptr(),
        msg_iovlen: host_iovecs.len() as libc::c_int,
        msg_control: optional_vec_mut_ptr(&mut control),
        msg_controllen: if control.is_empty() {
            0
        } else {
            guest_msg.controllen as libc::socklen_t
        },
        msg_flags: guest_msg.flags,
    };
    clear_errno();
    let ret = unsafe { libc::sendmsg(fd as libc::c_int, &host_msg, flags as libc::c_int) };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_recvmsg<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    msg_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let mut guest_msg = match read_guest_msghdr(memory, msg_ptr) {
        Ok(msg) => msg,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovcnt = match msg_iovcnt(guest_msg.iovlen) {
        Ok(iovcnt) => iovcnt,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let iovecs = match read_guest_iovecs(memory, guest_msg.iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut buffers = iovecs
        .iter()
        .map(|iov| vec![0u8; iov.len])
        .collect::<Vec<_>>();
    let mut host_iovecs = buffers
        .iter_mut()
        .map(host_iovec_from_mut_buffer)
        .collect::<Vec<_>>();
    let mut name = match zeroed_guest_side_bytes(guest_msg.name, guest_msg.namelen as usize) {
        Ok(name) => name,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut control =
        match zeroed_guest_side_bytes(guest_msg.control, guest_msg.controllen as usize) {
            Ok(control) => control,
            Err(errno) => return Some(host_io_error(errno)),
        };
    let mut host_msg = libc::msghdr {
        msg_name: optional_vec_mut_ptr(&mut name),
        msg_namelen: if name.is_empty() {
            0
        } else {
            guest_msg.namelen as libc::socklen_t
        },
        msg_iov: host_iovecs.as_mut_ptr(),
        msg_iovlen: host_iovecs.len() as libc::c_int,
        msg_control: optional_vec_mut_ptr(&mut control),
        msg_controllen: if control.is_empty() {
            0
        } else {
            guest_msg.controllen as libc::socklen_t
        },
        msg_flags: guest_msg.flags,
    };
    clear_errno();
    let ret = unsafe { libc::recvmsg(fd as libc::c_int, &mut host_msg, flags as libc::c_int) };
    if ret >= 0 {
        if ret > 0 {
            let read_len = ret as usize;
            if let Err(errno) = write_guest_iovec_bytes(memory, &iovecs, &buffers, read_len) {
                return Some(host_io_error(errno));
            }
        }
        if guest_msg.name != 0 && !name.is_empty() {
            let name_len = (host_msg.msg_namelen as usize).min(name.len());
            if memory
                .write_memory(guest_msg.name, &name[..name_len])
                .is_err()
            {
                return Some(host_io_error(libc::EFAULT as u32));
            }
        }
        if guest_msg.control != 0 && !control.is_empty() {
            let control_len = (host_msg.msg_controllen as usize).min(control.len());
            if memory
                .write_memory(guest_msg.control, &control[..control_len])
                .is_err()
            {
                return Some(host_io_error(libc::EFAULT as u32));
            }
        }
        guest_msg.namelen = host_msg.msg_namelen as u32;
        guest_msg.controllen = host_msg.msg_controllen as u32;
        guest_msg.flags = host_msg.msg_flags;
        if let Err(errno) = write_guest_msghdr_outputs(memory, msg_ptr, &guest_msg) {
            return Some(host_io_error(errno));
        }
    }
    let preview = if ret > 0 {
        preview_iovec_bytes(&buffers)
    } else {
        Vec::new()
    };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_shutdown(fd: u64, how: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::shutdown(fd as libc::c_int, how as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_setsockopt<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    level: u64,
    option_name: u64,
    option_value_ptr: u64,
    option_len: u64,
) -> Option<HostIoResult> {
    let option_data = if option_len == 0 {
        Vec::new()
    } else {
        match memory.read_memory(option_value_ptr, option_len as usize) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let ret = unsafe {
        libc::setsockopt(
            fd as libc::c_int,
            level as libc::c_int,
            option_name as libc::c_int,
            option_data.as_ptr().cast(),
            option_data.len() as libc::socklen_t,
        )
    };
    Some(host_io_result(
        ret as isize,
        option_data[..option_data.len().min(128)].to_vec(),
    ))
}

#[cfg(target_os = "macos")]
fn proxy_host_getsockopt<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    level: u64,
    option_name: u64,
    option_value_ptr: u64,
    option_len_ptr: u64,
) -> Option<HostIoResult> {
    let requested_len = match read_socklen(memory, option_len_ptr) {
        Some(value) => value as usize,
        None => return Some(host_io_error(libc::EFAULT as u32)),
    };
    if option_value_ptr == 0 && requested_len > 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut option_data = vec![0u8; requested_len];
    let mut option_len = requested_len as libc::socklen_t;
    clear_errno();
    let ret = unsafe {
        libc::getsockopt(
            fd as libc::c_int,
            level as libc::c_int,
            option_name as libc::c_int,
            option_data.as_mut_ptr().cast(),
            &mut option_len,
        )
    };
    if ret == 0 {
        let write_len = (option_len as usize).min(option_data.len());
        if write_len > 0
            && memory
                .write_memory(option_value_ptr, &option_data[..write_len])
                .is_err()
        {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        if write_socklen(memory, option_len_ptr, option_len).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        option_data.truncate(write_len.min(128));
    } else {
        option_data.clear();
    }
    Some(host_io_result(ret as isize, option_data))
}

#[cfg(target_os = "macos")]
fn copy_sockaddr_to_guest<M: GuestMemory + ?Sized>(
    memory: &mut M,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
    storage: &MaybeUninit<libc::sockaddr_storage>,
    requested_len: libc::socklen_t,
    actual_len: libc::socklen_t,
) {
    if sockaddr_ptr != 0 && requested_len > 0 {
        let copy_len = (actual_len as usize)
            .min(requested_len as usize)
            .min(mem::size_of::<libc::sockaddr_storage>());
        let sockaddr_bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), copy_len) };
        let _ = memory.write_memory(sockaddr_ptr, sockaddr_bytes);
    }
    if sockaddr_len_ptr != 0 {
        let _ = write_socklen(memory, sockaddr_len_ptr, actual_len);
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_accept<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let requested_len = if sockaddr_ptr != 0 && sockaddr_len_ptr != 0 {
        read_socklen(memory, sockaddr_len_ptr)
            .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
            .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
    } else {
        0
    };
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        libc::accept(
            fd as libc::c_int,
            if sockaddr_ptr == 0 {
                ptr::null_mut()
            } else {
                storage.as_mut_ptr().cast::<libc::sockaddr>()
            },
            if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
                ptr::null_mut()
            } else {
                &mut addr_len
            },
        )
    };
    if ret >= 0 && sockaddr_ptr != 0 && sockaddr_len_ptr != 0 {
        copy_sockaddr_to_guest(
            memory,
            sockaddr_ptr,
            sockaddr_len_ptr,
            &storage,
            requested_len,
            addr_len,
        );
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_getpeername<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    proxy_host_socket_name(
        memory,
        fd,
        sockaddr_ptr,
        sockaddr_len_ptr,
        libc::getpeername,
    )
}

#[cfg(target_os = "macos")]
fn proxy_host_getsockname<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
) -> Option<HostIoResult> {
    proxy_host_socket_name(
        memory,
        fd,
        sockaddr_ptr,
        sockaddr_len_ptr,
        libc::getsockname,
    )
}

#[cfg(target_os = "macos")]
fn proxy_host_socket_name<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    sockaddr_ptr: u64,
    sockaddr_len_ptr: u64,
    call: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int,
) -> Option<HostIoResult> {
    if sockaddr_ptr == 0 || sockaddr_len_ptr == 0 {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EFAULT as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let requested_len = read_socklen(memory, sockaddr_len_ptr)
        .unwrap_or(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t)
        .min(mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t);
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut addr_len = requested_len;
    clear_errno();
    let ret = unsafe {
        call(
            fd as libc::c_int,
            storage.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut addr_len,
        )
    };
    if ret == 0 {
        copy_sockaddr_to_guest(
            memory,
            sockaddr_ptr,
            sockaddr_len_ptr,
            &storage,
            requested_len,
            addr_len,
        );
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_socketpair<M: GuestMemory + ?Sized>(
    memory: &mut M,
    domain: u64,
    kind: u64,
    protocol: u64,
    sv_ptr: u64,
) -> Option<HostIoResult> {
    if sv_ptr == 0 {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EFAULT as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let mut sv = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe {
        libc::socketpair(
            domain as libc::c_int,
            kind as libc::c_int,
            protocol as libc::c_int,
            sv.as_mut_ptr(),
        )
    };
    if ret == 0 {
        let _ = write_guest_i32(memory, sv_ptr, sv[0]);
        let _ = write_guest_i32(memory, sv_ptr + 4, sv[1]);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}
#[cfg(target_os = "macos")]
fn read_guest_addrinfo_hint<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
) -> Option<libc::addrinfo> {
    if addr == 0 {
        return None;
    }
    let bytes = memory.read_memory(addr, DARWIN_ADDRINFO_SIZE).ok()?;
    let mut hint: libc::addrinfo = unsafe { mem::zeroed() };
    hint.ai_flags = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_FLAGS)? as libc::c_int;
    hint.ai_family = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_FAMILY)? as libc::c_int;
    hint.ai_socktype = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_SOCKTYPE)? as libc::c_int;
    hint.ai_protocol = read_i32_at(&bytes, DARWIN_ADDRINFO_AI_PROTOCOL)? as libc::c_int;
    hint.ai_addrlen = read_u32_at(&bytes, DARWIN_ADDRINFO_AI_ADDRLEN)? as libc::socklen_t;
    Some(hint)
}

#[cfg(target_os = "macos")]
fn write_guest_addrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    ai: &libc::addrinfo,
    canonname: u64,
    sockaddr: u64,
    next: u64,
) -> Result<(), GuestMemoryError> {
    let mut bytes = vec![0u8; DARWIN_ADDRINFO_SIZE];
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_FLAGS, ai.ai_flags).ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_FAMILY, ai.ai_family).ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_SOCKTYPE, ai.ai_socktype)
        .ok_or(GuestMemoryError)?;
    write_i32_at(&mut bytes, DARWIN_ADDRINFO_AI_PROTOCOL, ai.ai_protocol)
        .ok_or(GuestMemoryError)?;
    write_u32_at(&mut bytes, DARWIN_ADDRINFO_AI_ADDRLEN, ai.ai_addrlen as u32)
        .ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_CANONNAME, canonname).ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_ADDR, sockaddr).ok_or(GuestMemoryError)?;
    write_u64_at(&mut bytes, DARWIN_ADDRINFO_AI_NEXT, next).ok_or(GuestMemoryError)?;
    memory.write_memory(addr, &bytes)
}

#[cfg(target_os = "macos")]
fn read_optional_guest_cstring<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    max_len: usize,
) -> Option<Option<CString>> {
    if addr == 0 {
        return Some(None);
    }
    let text = read_cstring(memory, addr, max_len).ok()?;
    Some(Some(CString::new(text).ok()?))
}
#[cfg(target_os = "macos")]
fn proxy_host_getaddrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    node_ptr: u64,
    service_ptr: u64,
    hints_ptr: u64,
    result_ptr: u64,
) -> Option<HostCallResult> {
    if result_ptr == 0 {
        return Some(gai_call_result(libc::EAI_FAIL));
    }
    let node = read_optional_guest_cstring(memory, node_ptr, 4096)?;
    let service = read_optional_guest_cstring(memory, service_ptr, 4096)?;
    let hints = read_guest_addrinfo_hint(memory, hints_ptr);
    let mut host_result: *mut libc::addrinfo = ptr::null_mut();
    clear_errno();
    let ret = unsafe {
        libc::getaddrinfo(
            node.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            service.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            hints
                .as_ref()
                .map_or(ptr::null(), |value| value as *const libc::addrinfo),
            &mut host_result,
        )
    };
    if ret != 0 {
        let _ = write_guest_u64(memory, result_ptr, 0);
        return Some(gai_call_result(ret));
    }

    let mut first_guest = 0u64;
    let mut previous_guest = 0u64;
    let mut current = host_result;
    let mut copied = 0usize;
    while !current.is_null() && copied < MAX_ADDRINFO_RESULTS {
        let ai = unsafe { &*current };
        let guest_ai = match memory.allocate_memory(DARWIN_ADDRINFO_SIZE, 8) {
            Ok(addr) => addr,
            Err(_) => {
                unsafe { libc::freeaddrinfo(host_result) };
                let _ = write_guest_u64(memory, result_ptr, 0);
                return Some(gai_call_result(libc::EAI_MEMORY));
            }
        };
        let guest_sockaddr = if ai.ai_addr.is_null() || ai.ai_addrlen == 0 {
            0
        } else {
            let sockaddr_bytes = unsafe {
                std::slice::from_raw_parts(ai.ai_addr.cast::<u8>(), ai.ai_addrlen as usize)
            };
            match allocate_guest_bytes(memory, sockaddr_bytes) {
                Some(addr) => addr,
                None => {
                    unsafe { libc::freeaddrinfo(host_result) };
                    let _ = write_guest_u64(memory, result_ptr, 0);
                    return Some(gai_call_result(libc::EAI_MEMORY));
                }
            }
        };
        let guest_canonname = if ai.ai_canonname.is_null() {
            0
        } else {
            let canon = unsafe { CStr::from_ptr(ai.ai_canonname).to_bytes_with_nul() };
            match allocate_guest_bytes(memory, canon) {
                Some(addr) => addr,
                None => {
                    unsafe { libc::freeaddrinfo(host_result) };
                    let _ = write_guest_u64(memory, result_ptr, 0);
                    return Some(gai_call_result(libc::EAI_MEMORY));
                }
            }
        };
        if write_guest_addrinfo(memory, guest_ai, ai, guest_canonname, guest_sockaddr, 0).is_err() {
            unsafe { libc::freeaddrinfo(host_result) };
            let _ = write_guest_u64(memory, result_ptr, 0);
            return Some(gai_call_result(libc::EAI_MEMORY));
        }
        if previous_guest != 0 {
            let _ = write_guest_u64(
                memory,
                previous_guest + DARWIN_ADDRINFO_AI_NEXT as u64,
                guest_ai,
            );
        } else {
            first_guest = guest_ai;
        }
        previous_guest = guest_ai;
        current = ai.ai_next;
        copied += 1;
    }
    unsafe { libc::freeaddrinfo(host_result) };
    if write_guest_u64(memory, result_ptr, first_guest).is_err() {
        return Some(gai_call_result(libc::EAI_MEMORY));
    }
    Some(gai_call_result(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_freeaddrinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addrinfo_ptr: u64,
) -> Option<HostCallResult> {
    let mut current = addrinfo_ptr;
    let mut seen = HashSet::new();
    for _ in 0..MAX_ADDRINFO_RESULTS {
        if current == 0 || !seen.insert(current) {
            break;
        }
        let Ok(bytes) = memory.read_memory(current, DARWIN_ADDRINFO_SIZE) else {
            break;
        };
        let canonname = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_CANONNAME).unwrap_or(0);
        let sockaddr = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_ADDR).unwrap_or(0);
        let next = read_u64_at(&bytes, DARWIN_ADDRINFO_AI_NEXT).unwrap_or(0);
        if canonname != 0 {
            let _ = memory.free_memory(canonname);
        }
        if sockaddr != 0 {
            let _ = memory.free_memory(sockaddr);
        }
        let _ = memory.free_memory(current);
        current = next;
    }
    Some(HostCallResult {
        return_value: 0,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_gai_strerror<M: GuestMemory + ?Sized>(
    memory: &mut M,
    errcode: u64,
) -> Option<HostCallResult> {
    let message = unsafe { libc::gai_strerror(errcode as libc::c_int) };
    if message.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: None,
        });
    }
    let bytes = unsafe { CStr::from_ptr(message).to_bytes_with_nul() };
    let addr = allocate_guest_bytes(memory, bytes).unwrap_or(0);
    Some(HostCallResult {
        return_value: addr,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_getnameinfo<M: GuestMemory + ?Sized>(
    memory: &mut M,
    sockaddr_ptr: u64,
    sockaddr_len: u64,
    host_ptr: u64,
    host_len: u64,
    service_ptr: u64,
    service_len: u64,
    flags: u64,
) -> Option<HostCallResult> {
    let (storage, len) = read_sockaddr_storage(memory, sockaddr_ptr, sockaddr_len)?;
    let mut host = vec![0u8; host_len as usize];
    let mut service = vec![0u8; service_len as usize];
    clear_errno();
    let ret = unsafe {
        libc::getnameinfo(
            storage.as_ptr().cast::<libc::sockaddr>(),
            len,
            if host_ptr == 0 || host.is_empty() {
                ptr::null_mut()
            } else {
                host.as_mut_ptr().cast::<libc::c_char>()
            },
            host_len as libc::socklen_t,
            if service_ptr == 0 || service.is_empty() {
                ptr::null_mut()
            } else {
                service.as_mut_ptr().cast::<libc::c_char>()
            },
            service_len as libc::socklen_t,
            flags as libc::c_int,
        )
    };
    if ret == 0 {
        if host_ptr != 0 && !host.is_empty() {
            let _ = memory.write_memory(host_ptr, &host);
        }
        if service_ptr != 0 && !service.is_empty() {
            let _ = memory.write_memory(service_ptr, &service);
        }
    }
    Some(gai_call_result(ret))
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_pton<M: GuestMemory + ?Sized>(
    memory: &mut M,
    family: u64,
    src_ptr: u64,
    dst_ptr: u64,
) -> Option<HostCallResult> {
    let src = read_cstring(memory, src_ptr, 4096).ok()?;
    let host_src = CString::new(src).ok()?;
    let mut storage = [0u8; 16];
    clear_errno();
    let ret = unsafe {
        inet_pton(
            family as libc::c_int,
            host_src.as_ptr(),
            storage.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    if ret == 1 {
        let len = match family as libc::c_int {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        if len > 0 && memory.write_memory(dst_ptr, &storage[..len]).is_err() {
            return Some(host_call_error(libc::EFAULT as u32));
        }
    }
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_ntop<M: GuestMemory + ?Sized>(
    memory: &mut M,
    family: u64,
    src_ptr: u64,
    dst_ptr: u64,
    dst_len: u64,
) -> Option<HostCallResult> {
    let src_len = match family as libc::c_int {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => 16,
    };
    let src = memory.read_memory(src_ptr, src_len).ok()?;
    let mut dst = vec![0u8; dst_len as usize];
    clear_errno();
    let ret = unsafe {
        inet_ntop(
            family as libc::c_int,
            src.as_ptr().cast::<libc::c_void>(),
            dst.as_mut_ptr().cast::<libc::c_char>(),
            dst_len as libc::socklen_t,
        )
    };
    if !ret.is_null() {
        if memory.write_memory(dst_ptr, &dst).is_err() {
            return Some(host_call_error(libc::EFAULT as u32));
        }
        return Some(HostCallResult {
            return_value: dst_ptr,
            errno: None,
        });
    }
    Some(HostCallResult {
        return_value: 0,
        errno: Some(host_errno()),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_addr<M: GuestMemory + ?Sized>(
    memory: &mut M,
    src_ptr: u64,
) -> Option<HostCallResult> {
    let host_src = match read_cstring(memory, src_ptr, 4096)
        .ok()
        .and_then(|src| CString::new(src).ok())
    {
        Some(value) => value,
        None => {
            return Some(HostCallResult {
                return_value: libc::INADDR_NONE as u64,
                errno: Some(libc::EFAULT as u32),
            });
        }
    };
    clear_errno();
    let ret = unsafe { inet_addr(host_src.as_ptr()) };
    Some(HostCallResult {
        return_value: ret as u64,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_inet_aton<M: GuestMemory + ?Sized>(
    memory: &mut M,
    src_ptr: u64,
    dst_ptr: u64,
) -> Option<HostCallResult> {
    if dst_ptr == 0 {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(libc::EFAULT as u32),
        });
    }

    let host_src = match read_cstring(memory, src_ptr, 4096)
        .ok()
        .and_then(|src| CString::new(src).ok())
    {
        Some(value) => value,
        None => {
            return Some(HostCallResult {
                return_value: 0,
                errno: Some(libc::EFAULT as u32),
            });
        }
    };
    let mut addr = libc::in_addr { s_addr: 0 };
    clear_errno();
    let ret = unsafe { inet_aton(host_src.as_ptr(), &mut addr) };
    if ret != 0 {
        if memory
            .write_memory(dst_ptr, &addr.s_addr.to_le_bytes())
            .is_err()
        {
            return Some(HostCallResult {
                return_value: 0,
                errno: Some(libc::EFAULT as u32),
            });
        }
    }
    Some(HostCallResult {
        return_value: ret as u64,
        errno: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn darwin_msghdr_fixture_bytes() -> Vec<u8> {
        fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
            put_u32(bytes, offset, value as u32);
        }

        fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let mut raw = vec![0u8; DARWIN_MSGHDR_SIZE];
        put_u64(&mut raw, DARWIN_MSGHDR_NAME, 0x1111);
        put_u32(&mut raw, DARWIN_MSGHDR_NAMELEN, 12);
        put_u64(&mut raw, DARWIN_MSGHDR_IOV, 0x2222);
        put_i32(&mut raw, DARWIN_MSGHDR_IOVLEN, 2);
        put_u64(&mut raw, DARWIN_MSGHDR_CONTROL, 0x3333);
        put_u32(&mut raw, DARWIN_MSGHDR_CONTROLLEN, 24);
        put_i32(&mut raw, DARWIN_MSGHDR_FLAGS, 0x40);
        raw
    }

    fn expected_darwin_msghdr() -> GuestMsghdr {
        GuestMsghdr {
            name: 0x1111,
            namelen: 12,
            iov: 0x2222,
            iovlen: 2,
            control: 0x3333,
            controllen: 24,
            flags: 0x40,
        }
    }

    #[test]
    fn msghdr_parser_uses_darwin_guest_layout() {
        let raw = darwin_msghdr_fixture_bytes();
        assert_eq!(parse_darwin_msghdr(&raw), Some(expected_darwin_msghdr()));
        assert_eq!(parse_darwin_msghdr(&raw[..DARWIN_MSGHDR_SIZE - 1]), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn msghdr_output_write_preserves_darwin_pointer_fields() {
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
        let raw = darwin_msghdr_fixture_bytes();
        memory.write_guest(0x1000, &raw);

        let mut msg = read_guest_msghdr(&mut memory, 0x1000).unwrap();
        assert_eq!(msg, expected_darwin_msghdr());

        msg.namelen = 8;
        msg.controllen = 16;
        msg.flags = 0x80;
        write_guest_msghdr_outputs(&mut memory, 0x1000, &msg).unwrap();

        let updated = memory.read_memory(0x1000, DARWIN_MSGHDR_SIZE).unwrap();
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_NAME), Some(0x1111));
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_IOV), Some(0x2222));
        assert_eq!(read_u64_at(&updated, DARWIN_MSGHDR_CONTROL), Some(0x3333));
        assert_eq!(read_u32_at(&updated, DARWIN_MSGHDR_NAMELEN), Some(8));
        assert_eq!(read_u32_at(&updated, DARWIN_MSGHDR_CONTROLLEN), Some(16));
        assert_eq!(read_i32_at(&updated, DARWIN_MSGHDR_FLAGS), Some(0x80));
    }
}
