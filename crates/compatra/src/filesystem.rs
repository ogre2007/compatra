//! Filesystem, file-descriptor, stdio, directory, and entropy host proxy services.

use crate::logging::{hex_arg, CompatLogScope};
use crate::{
    CompatibilityServices, GuestMemory, HostCallResult, HostIoResult, HostOpenResult,
    HostPipeResult,
};

#[cfg(target_os = "macos")]
use crate::{
    allocate_guest_bytes, arm64_variadic_open_mode, clear_errno, host_call_error, host_call_result,
    host_call_value, host_errno, host_io_error, host_io_result, host_null_error, io_error_errno,
    read_cstring, read_darwin_timeval, read_guest_i32, read_i16_at, read_i32_at, read_u64_at,
    signed_return_value, write_guest_host_struct, write_guest_i32, write_guest_u64, write_i16_at,
    write_i32_at,
};

#[cfg(target_os = "macos")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::mem::{self, MaybeUninit};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::ptr;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "macos")]
const MAX_GUEST_POLL_FDS: usize = 4096;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_SIZE: usize = 16;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_BASE: usize = 0;
#[cfg(target_os = "macos")]
const DARWIN_IOVEC_LEN: usize = 8;
#[cfg(target_os = "macos")]
const DARWIN_STAT_SIZE_OFFSET: usize = 96;
#[cfg(target_os = "macos")]
const MAX_GUEST_IOV: usize = 1024;
#[cfg(target_os = "macos")]
const MAX_GUEST_IOV_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const HOST_PATH_BUFFER_SIZE: usize = 4096;
#[cfg(target_os = "macos")]
const MAX_GUEST_STDIO_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const HOST_FILE_HANDLE_SIZE: usize = 8;
#[cfg(target_os = "macos")]
const HOST_DIRENT_SIZE: usize = mem::size_of::<libc::dirent>();
impl CompatibilityServices {
    pub fn open_path_arg0<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_open_arg0(memory, path_ptr, flags, mode);
            let log_args = [
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "open", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, flags, mode);
            let result = None;
            let log_args = [
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "open", &log_args, &result);
            result
        }
    }

    pub fn open_path_arm64<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        flags: u64,
        register_mode: u64,
        stack_ptr: Option<u64>,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let mode = arm64_variadic_open_mode(memory, flags, register_mode, stack_ptr);
            let result = proxy_host_open_arg0(memory, path_ptr, flags, mode);
            let mut log_args = vec![
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
                ("register_mode", hex_arg(register_mode)),
            ];
            if let Some(stack_ptr) = stack_ptr {
                log_args.push(("sp", hex_arg(stack_ptr)));
            }
            log_scope.open_result("direct", "open", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, flags, register_mode, stack_ptr);
            let result = None;
            let mut log_args = vec![
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("register_mode", hex_arg(register_mode)),
            ];
            if let Some(stack_ptr) = stack_ptr {
                log_args.push(("sp", hex_arg(stack_ptr)));
            }
            log_scope.open_result("direct", "open", &log_args, &result);
            result
        }
    }

    pub fn openat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_openat(memory, dirfd, path_ptr, flags, mode);
            let log_args = [
                ("dirfd", dirfd.to_string()),
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "openat", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, flags, mode);
            let result = None;
            let log_args = [
                ("dirfd", dirfd.to_string()),
                ("path_ptr", hex_arg(path_ptr)),
                ("flags", hex_arg(flags)),
                ("mode", format!("{mode:o}")),
            ];
            log_scope.open_result("direct", "openat", &log_args, &result);
            result
        }
    }

    pub fn read_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_read(memory, fd, buf_ptr, count);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "read", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "read", &log_args, &result);
            result
        }
    }

    pub fn write_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_write(memory, fd, buf_ptr, count);
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "write", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count);
            let result = None;
            let log_args = [
                ("fd", fd.to_string()),
                ("buf", hex_arg(buf_ptr)),
                ("count", count.to_string()),
            ];
            log_scope.io_result("direct", "write", &log_args, &result);
            result
        }
    }

    pub fn close_fd(&self, fd: u64) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_close(fd);
            let log_args = [("fd", fd.to_string())];
            log_scope.io_result("direct", "close", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            let result = None;
            let log_args = [("fd", fd.to_string())];
            log_scope.io_result("direct", "close", &log_args, &result);
            result
        }
    }

    pub fn fcntl_fd(&self, fd: u64, cmd: u64, arg: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fcntl(fd, cmd, arg);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, cmd, arg);
            None
        }
    }

    pub fn ioctl_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        request: u64,
        data_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ioctl(memory, fd, request, data_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, request, data_ptr);
            None
        }
    }

    pub fn fsync_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fsync(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn poll_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fds_ptr: u64,
        nfds: u64,
        timeout: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_poll(memory, fds_ptr, nfds, timeout);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fds_ptr, nfds, timeout);
            None
        }
    }

    pub fn readv_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readv(memory, fd, iov_ptr, iovcnt);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, iov_ptr, iovcnt);
            None
        }
    }

    pub fn writev_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_writev(memory, fd, iov_ptr, iovcnt);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, iov_ptr, iovcnt);
            None
        }
    }

    pub fn pread_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_pread(memory, fd, buf_ptr, count, offset);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, offset);
            None
        }
    }

    pub fn pwrite_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_pwrite(memory, fd, buf_ptr, count, offset);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr, count, offset);
            None
        }
    }

    pub fn lseek_fd(&self, fd: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_lseek(fd, offset, whence);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, offset, whence);
            None
        }
    }

    pub fn dup_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dup(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn dup2_fd(&self, from: u64, to: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dup2(from, to);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (from, to);
            None
        }
    }

    pub fn pipe_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fds_ptr: u64,
    ) -> Option<HostIoResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_pipe(memory, fds_ptr);
            let log_args = [("fds_ptr", hex_arg(fds_ptr))];
            log_scope.io_result("direct", "pipe", &log_args, &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fds_ptr);
            let result = None;
            let log_args = [("fds_ptr", hex_arg(fds_ptr))];
            log_scope.io_result("direct", "pipe", &log_args, &result);
            result
        }
    }

    pub fn pipe_pair(&self) -> Option<HostPipeResult> {
        let log_scope = CompatLogScope::enter();
        #[cfg(target_os = "macos")]
        {
            let result = proxy_host_pipe_pair();
            log_scope.pipe_result("direct", "pipe_pair", &[], &result);
            return result;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let result = None;
            log_scope.pipe_result("direct", "pipe_pair", &[], &result);
            result
        }
    }

    pub fn select_fds<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        nfds: u64,
        readfds_ptr: u64,
        writefds_ptr: u64,
        exceptfds_ptr: u64,
        timeout_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_select(
                memory,
                nfds,
                readfds_ptr,
                writefds_ptr,
                exceptfds_ptr,
                timeout_ptr,
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &mut *memory,
                nfds,
                readfds_ptr,
                writefds_ptr,
                exceptfds_ptr,
                timeout_ptr,
            );
            None
        }
    }

    pub fn access_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_access(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn faccessat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_faccessat(memory, dirfd, path_ptr, mode, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode, flags);
            None
        }
    }

    pub fn chmod_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_chmod(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn fchmod_fd(&self, fd: u64, mode: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchmod(fd, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, mode);
            None
        }
    }

    pub fn fchmodat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchmodat(memory, dirfd, path_ptr, mode, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode, flags);
            None
        }
    }

    pub fn chdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_chdir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn fchdir_fd(&self, fd: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fchdir(fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            None
        }
    }

    pub fn getcwd_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getcwd(memory, buf_ptr, size);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size);
            None
        }
    }

    pub fn stat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_stat(memory, path_ptr, stat_ptr, true);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, stat_ptr);
            None
        }
    }

    pub fn lstat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_stat(memory, path_ptr, stat_ptr, false);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, stat_ptr);
            None
        }
    }

    pub fn fstat_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstat(memory, fd, stat_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, stat_ptr);
            None
        }
    }

    pub fn fstatat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        stat_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstatat(memory, dirfd, path_ptr, stat_ptr, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, stat_ptr, flags);
            None
        }
    }

    pub fn statfs_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        buf_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_statfs(memory, path_ptr, buf_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, buf_ptr);
            None
        }
    }

    pub fn fstatfs_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        buf_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fstatfs(memory, fd, buf_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, buf_ptr);
            None
        }
    }

    pub fn truncate_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        length: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_truncate(memory, path_ptr, length);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, length);
            None
        }
    }

    pub fn ftruncate_fd(&self, fd: u64, length: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ftruncate(fd, length);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (fd, length);
            None
        }
    }

    pub fn mkdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_mkdir(memory, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode);
            None
        }
    }

    pub fn mkdirat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_mkdirat(memory, dirfd, path_ptr, mode);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, mode);
            None
        }
    }

    pub fn rmdir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rmdir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn unlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_unlink(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn unlinkat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_unlinkat(memory, dirfd, path_ptr, flags);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, flags);
            None
        }
    }

    pub fn rename_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        from_ptr: u64,
        to_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rename(memory, from_ptr, to_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, from_ptr, to_ptr);
            None
        }
    }

    pub fn renameat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fromfd: u64,
        from_ptr: u64,
        tofd: u64,
        to_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_renameat(memory, fromfd, from_ptr, tofd, to_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fromfd, from_ptr, tofd, to_ptr);
            None
        }
    }

    pub fn readlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readlink(memory, path_ptr, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, buf_ptr, count);
            None
        }
    }

    pub fn readlinkat_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirfd: u64,
        path_ptr: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readlinkat(memory, dirfd, path_ptr, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirfd, path_ptr, buf_ptr, count);
            None
        }
    }

    pub fn symlink_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        target_ptr: u64,
        link_ptr: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_symlink(memory, target_ptr, link_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, target_ptr, link_ptr);
            None
        }
    }

    pub fn realpath_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        resolved_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_realpath(memory, path_ptr, resolved_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, resolved_ptr);
            None
        }
    }
    pub fn fopen_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
        mode_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fopen(memory, path_ptr, mode_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr, mode_ptr);
            None
        }
    }

    pub fn fdopen_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
        mode_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fdopen(memory, fd, mode_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd, mode_ptr);
            None
        }
    }

    pub fn fclose_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fclose(memory, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, stream);
            None
        }
    }

    pub fn fread_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        nmemb: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fread(memory, buf_ptr, size, nmemb, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, nmemb, stream);
            None
        }
    }

    pub fn fwrite_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        nmemb: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fwrite(memory, buf_ptr, size, nmemb, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, nmemb, stream);
            None
        }
    }

    pub fn fflush_stream(&self, stream: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fflush(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fseek_stream(&self, stream: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fseek(stream, offset, whence);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (stream, offset, whence);
            None
        }
    }

    pub fn ftell_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ftell(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fgets_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        size: u64,
        stream: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fgets(memory, buf_ptr, size, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, size, stream);
            None
        }
    }

    pub fn fputs_stream<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        text_ptr: u64,
        stream: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fputs(memory, text_ptr, stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, text_ptr, stream);
            None
        }
    }

    pub fn feof_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_feof(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn ferror_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_ferror(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn clearerr_stream(&self, stream: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_clearerr(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }

    pub fn fileno_stream(&self, stream: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fileno(stream);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            None
        }
    }
    pub fn opendir_path<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        path_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_opendir(memory, path_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, path_ptr);
            None
        }
    }

    pub fn fdopendir_fd<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        fd: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_fdopendir(memory, fd);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, fd);
            None
        }
    }

    pub fn readdir_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readdir(memory, dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp);
            None
        }
    }

    pub fn readdir_r_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
        entry_ptr: u64,
        result_ptr: u64,
    ) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_readdir_r(memory, dirp, entry_ptr, result_ptr);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp, entry_ptr, result_ptr);
            None
        }
    }

    pub fn closedir_handle<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        dirp: u64,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_closedir(memory, dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, dirp);
            None
        }
    }

    pub fn dirfd_handle(&self, dirp: u64) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_dirfd(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn rewinddir_handle(&self, dirp: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_rewinddir(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn telldir_handle(&self, dirp: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_telldir(dirp);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = dirp;
            None
        }
    }

    pub fn seekdir_handle(&self, dirp: u64, loc: u64) -> Option<HostCallResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_seekdir(dirp, loc);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (dirp, loc);
            None
        }
    }

    pub fn getentropy<M: GuestMemory + ?Sized>(
        &self,
        memory: &mut M,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        #[cfg(target_os = "macos")]
        {
            return proxy_host_getentropy(memory, buf_ptr, count);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&mut *memory, buf_ptr, count);
            None
        }
    }
}
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct HostFileHandle {
    file_ptr: usize,
}

#[cfg(target_os = "macos")]
fn host_file_handles() -> &'static Mutex<std::collections::HashMap<u64, HostFileHandle>> {
    static HANDLES: OnceLock<Mutex<std::collections::HashMap<u64, HostFileHandle>>> =
        OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "macos")]
fn host_file_ptr(stream: u64) -> Option<*mut libc::FILE> {
    let handles = host_file_handles().lock().ok()?;
    let handle = handles.get(&stream)?;
    Some(handle.file_ptr as *mut libc::FILE)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct HostDirHandle {
    dir_ptr: usize,
    dirent_guest_ptr: u64,
}

#[cfg(target_os = "macos")]
fn host_dir_handles() -> &'static Mutex<std::collections::HashMap<u64, HostDirHandle>> {
    static HANDLES: OnceLock<Mutex<std::collections::HashMap<u64, HostDirHandle>>> =
        OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct HostFdReadiness {
    pipe_write_to_read: HashMap<libc::c_int, libc::c_int>,
    pending_read_bytes: HashMap<libc::c_int, usize>,
}

#[cfg(target_os = "macos")]
fn host_fd_readiness() -> &'static Mutex<HostFdReadiness> {
    static READINESS: OnceLock<Mutex<HostFdReadiness>> = OnceLock::new();
    READINESS.get_or_init(|| Mutex::new(HostFdReadiness::default()))
}

#[cfg(target_os = "macos")]
fn note_host_pipe(read_fd: libc::c_int, write_fd: libc::c_int) {
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        readiness.pipe_write_to_read.insert(write_fd, read_fd);
        readiness.pending_read_bytes.entry(read_fd).or_default();
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_write(fd: u64, ret: isize) {
    if ret <= 0 {
        return;
    }
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        let Some(read_fd) = readiness.pipe_write_to_read.get(&fd).copied() else {
            return;
        };
        let pending = readiness.pending_read_bytes.entry(read_fd).or_default();
        *pending = pending.saturating_add(ret as usize);
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_read(fd: u64, ret: isize) {
    if ret <= 0 {
        return;
    }
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        if let Some(pending) = readiness.pending_read_bytes.get_mut(&fd) {
            *pending = pending.saturating_sub(ret as usize);
        }
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_dup(from: u64, to: libc::c_int) {
    if to < 0 {
        return;
    }
    let from = from as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        if let Some(read_fd) = readiness.pipe_write_to_read.get(&from).copied() {
            readiness.pipe_write_to_read.insert(to, read_fd);
        }
        if let Some(pending) = readiness.pending_read_bytes.get(&from).copied() {
            readiness.pending_read_bytes.insert(to, pending);
        }
    }
}

#[cfg(target_os = "macos")]
fn note_host_fd_close(fd: u64) {
    let fd = fd as libc::c_int;
    if let Ok(mut readiness) = host_fd_readiness().lock() {
        readiness.pipe_write_to_read.remove(&fd);
        readiness
            .pipe_write_to_read
            .retain(|_write_fd, read_fd| *read_fd != fd);
        readiness.pending_read_bytes.remove(&fd);
    }
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
fn proxy_host_openat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> Option<HostOpenResult> {
    let path = read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).ok()?;
    let host_path = CString::new(path.clone()).ok()?;
    clear_errno();
    let ret = unsafe {
        libc::openat(
            dirfd as libc::c_int,
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
        note_host_fd_read(fd, ret);
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
    note_host_fd_write(fd, ret);
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_close(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::close(fd as libc::c_int) };
    if ret == 0 {
        note_host_fd_close(fd);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_host_path<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Result<(String, CString), u32> {
    let path =
        read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).map_err(|_| libc::EFAULT as u32)?;
    let host_path = CString::new(path.clone()).map_err(|_| libc::EINVAL as u32)?;
    Ok((path, host_path))
}

#[cfg(target_os = "macos")]
fn proxy_host_access<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::access(path.as_ptr(), mode as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_faccessat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::faccessat(
            dirfd as libc::c_int,
            path.as_ptr(),
            mode as libc::c_int,
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_chmod<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchmod(fd: u64, mode: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fchmod(fd as libc::c_int, mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchmodat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::fchmodat(
            dirfd as libc::c_int,
            path.as_ptr(),
            mode as libc::mode_t,
            flags as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_chdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::chdir(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fchdir(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fchdir(fd as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_getcwd<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
) -> Option<HostCallResult> {
    if buf_ptr != 0 && size == 0 {
        return Some(host_null_error(libc::EINVAL as u32));
    }
    let host_size = if size == 0 {
        HOST_PATH_BUFFER_SIZE
    } else {
        usize::try_from(size).unwrap_or(HOST_PATH_BUFFER_SIZE)
    };
    let mut host_buf = vec![0u8; host_size.max(1)];
    clear_errno();
    let ret = unsafe { libc::getcwd(host_buf.as_mut_ptr().cast::<libc::c_char>(), host_buf.len()) };
    if ret.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let bytes = unsafe { CStr::from_ptr(host_buf.as_ptr().cast()).to_bytes_with_nul() };
    let dest = if buf_ptr == 0 {
        match allocate_guest_bytes(memory, bytes) {
            Some(addr) => addr,
            None => return Some(host_null_error(libc::ENOMEM as u32)),
        }
    } else {
        if bytes.len() > host_size || memory.write_memory(buf_ptr, bytes).is_err() {
            return Some(host_null_error(libc::ERANGE as u32));
        }
        buf_ptr
    };
    Some(HostCallResult {
        return_value: dest,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn write_darwin_stat_from_metadata<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stat_ptr: u64,
    metadata: &fs::Metadata,
) -> Result<(), u32> {
    write_darwin_minimal_stat(memory, stat_ptr, metadata.size())
}

#[cfg(target_os = "macos")]
fn write_darwin_minimal_stat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    stat_ptr: u64,
    size: u64,
) -> Result<(), u32> {
    // Small compatibility fixtures and real guests may allocate a Darwin
    // `struct stat` shape that is smaller than the host Rust libc view. The
    // size field is the contract used by current compat callers, so write it
    // directly instead of treating an oversized full-struct write as EFAULT.
    memory
        .write_memory(
            stat_ptr + DARWIN_STAT_SIZE_OFFSET as u64,
            &size.to_le_bytes(),
        )
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn proxy_host_stat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    stat_ptr: u64,
    follow: bool,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (path, _) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let metadata = if follow {
        fs::metadata(&path)
    } else {
        fs::symlink_metadata(&path)
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(error) => return Some(host_io_error(io_error_errno(&error))),
    };
    if write_darwin_stat_from_metadata(memory, stat_ptr, &metadata).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(0, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    stat_ptr: u64,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    clear_errno();
    let ret = unsafe { libc::fstat(fd as libc::c_int, stat.as_mut_ptr()) };
    if ret == 0 {
        let size = unsafe { (*stat.as_ptr()).st_size }.max(0) as u64;
        if write_darwin_minimal_stat(memory, stat_ptr, size).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstatat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    stat_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    if stat_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    clear_errno();
    let ret = unsafe {
        libc::fstatat(
            dirfd as libc::c_int,
            path.as_ptr(),
            stat.as_mut_ptr(),
            flags as libc::c_int,
        )
    };
    if ret == 0 {
        let size = unsafe { (*stat.as_ptr()).st_size }.max(0) as u64;
        if write_darwin_minimal_stat(memory, stat_ptr, size).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_statfs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    buf_ptr: u64,
) -> Option<HostIoResult> {
    if buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut statfs = MaybeUninit::<libc::statfs>::zeroed();
    clear_errno();
    let ret = unsafe { libc::statfs(path.as_ptr(), statfs.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, buf_ptr, &statfs).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fstatfs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
) -> Option<HostIoResult> {
    if buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut statfs = MaybeUninit::<libc::statfs>::zeroed();
    clear_errno();
    let ret = unsafe { libc::fstatfs(fd as libc::c_int, statfs.as_mut_ptr()) };
    if ret == 0 && write_guest_host_struct(memory, buf_ptr, &statfs).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_truncate<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    length: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::truncate(path.as_ptr(), length as libc::off_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ftruncate(fd: u64, length: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::ftruncate(fd as libc::c_int, length as libc::off_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_mkdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::mkdir(path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_mkdirat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::mkdirat(dirfd as libc::c_int, path.as_ptr(), mode as libc::mode_t) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rmdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::rmdir(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_unlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::unlink(path.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_unlinkat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::unlinkat(dirfd as libc::c_int, path.as_ptr(), flags as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rename<M: GuestMemory + ?Sized>(
    memory: &mut M,
    from_ptr: u64,
    to_ptr: u64,
) -> Option<HostIoResult> {
    let (_, from) = match read_host_path(memory, from_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, to) = match read_host_path(memory, to_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::rename(from.as_ptr(), to.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_renameat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fromfd: u64,
    from_ptr: u64,
    tofd: u64,
    to_ptr: u64,
) -> Option<HostIoResult> {
    let (_, from) = match read_host_path(memory, from_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, to) = match read_host_path(memory, to_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe {
        libc::renameat(
            fromfd as libc::c_int,
            from.as_ptr(),
            tofd as libc::c_int,
            to.as_ptr(),
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_readlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::readlink(path.as_ptr(), data.as_mut_ptr().cast(), data.len()) };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_readlinkat<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirfd: u64,
    path_ptr: u64,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::readlinkat(
            dirfd as libc::c_int,
            path.as_ptr(),
            data.as_mut_ptr().cast(),
            data.len(),
        )
    };
    if ret > 0 {
        let len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_symlink<M: GuestMemory + ?Sized>(
    memory: &mut M,
    target_ptr: u64,
    link_ptr: u64,
) -> Option<HostIoResult> {
    let (_, target) = match read_host_path(memory, target_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let (_, link) = match read_host_path(memory, link_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_io_error(errno)),
    };
    clear_errno();
    let ret = unsafe { libc::symlink(target.as_ptr(), link.as_ptr()) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_realpath<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    resolved_ptr: u64,
) -> Option<HostCallResult> {
    let (_, path) = match read_host_path(memory, path_ptr) {
        Ok(path) => path,
        Err(errno) => return Some(host_null_error(errno)),
    };
    let mut resolved = vec![0u8; HOST_PATH_BUFFER_SIZE];
    clear_errno();
    let ret = unsafe { libc::realpath(path.as_ptr(), resolved.as_mut_ptr().cast()) };
    if ret.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let bytes = unsafe { CStr::from_ptr(resolved.as_ptr().cast()).to_bytes_with_nul() };
    let dest = if resolved_ptr == 0 {
        match allocate_guest_bytes(memory, bytes) {
            Some(addr) => addr,
            None => return Some(host_null_error(libc::ENOMEM as u32)),
        }
    } else {
        if memory.write_memory(resolved_ptr, bytes).is_err() {
            return Some(host_null_error(libc::EFAULT as u32));
        }
        resolved_ptr
    };
    Some(HostCallResult {
        return_value: dest,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fcntl(fd: u64, cmd: u64, arg: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fcntl(fd as libc::c_int, cmd as libc::c_int, arg as libc::c_long) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ioctl<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    request: u64,
    data_ptr: u64,
) -> Option<HostIoResult> {
    match request {
        value if value == libc::FIONREAD as u64 => {
            if data_ptr == 0 {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let mut available: libc::c_int = 0;
            clear_errno();
            let ret = unsafe {
                libc::ioctl(
                    fd as libc::c_int,
                    libc::FIONREAD,
                    &mut available as *mut libc::c_int,
                )
            };
            if ret == 0 && write_guest_i32(memory, data_ptr, available).is_err() {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let preview = if ret == 0 {
                available.to_le_bytes().to_vec()
            } else {
                Vec::new()
            };
            Some(host_io_result(ret as isize, preview))
        }
        value if value == libc::FIONBIO as u64 => {
            if data_ptr == 0 {
                return Some(host_io_error(libc::EFAULT as u32));
            }
            let mut enable = match read_guest_i32(memory, data_ptr) {
                Ok(value) => value,
                Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
            };
            clear_errno();
            let ret = unsafe {
                libc::ioctl(
                    fd as libc::c_int,
                    libc::FIONBIO,
                    &mut enable as *mut libc::c_int,
                )
            };
            Some(host_io_result(ret as isize, Vec::new()))
        }
        _ => Some(host_io_result(0, Vec::new())),
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_fsync(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::fsync(fd as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_poll<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fds_ptr: u64,
    nfds: u64,
    timeout: u64,
) -> Option<HostIoResult> {
    if nfds as usize > MAX_GUEST_POLL_FDS {
        return Some(HostIoResult {
            return_value: u64::MAX,
            errno: libc::EINVAL as u32,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let entry_size = mem::size_of::<libc::pollfd>();
    let bytes_len = (nfds as usize).saturating_mul(entry_size);
    let bytes = if bytes_len == 0 {
        Vec::new()
    } else {
        memory.read_memory(fds_ptr, bytes_len).ok()?
    };
    let mut fds = vec![
        libc::pollfd {
            fd: 0,
            events: 0,
            revents: 0,
        };
        nfds as usize
    ];
    for (idx, pollfd) in fds.iter_mut().enumerate() {
        let offset = idx * entry_size;
        pollfd.fd = read_i32_at(&bytes, offset)? as libc::c_int;
        pollfd.events = read_i16_at(&bytes, offset + 4)?;
        pollfd.revents = 0;
    }
    clear_errno();
    let ret = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            nfds as libc::nfds_t,
            timeout as libc::c_int,
        )
    };
    if ret >= 0 && bytes_len > 0 {
        let mut out = bytes;
        for (idx, pollfd) in fds.iter().enumerate() {
            let offset = idx * entry_size;
            let _ = write_i32_at(&mut out, offset, pollfd.fd);
            let _ = write_i16_at(&mut out, offset + 4, pollfd.events);
            let _ = write_i16_at(&mut out, offset + 6, pollfd.revents);
        }
        let _ = memory.write_memory(fds_ptr, &out);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuestIovec {
    pub(crate) base: u64,
    pub(crate) len: usize,
}

#[cfg(target_os = "macos")]
pub(crate) fn read_guest_iovecs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iov_ptr: u64,
    iovcnt: u64,
) -> Result<Vec<GuestIovec>, u32> {
    let iovcnt = usize::try_from(iovcnt).map_err(|_| libc::EINVAL as u32)?;
    if iovcnt > MAX_GUEST_IOV {
        return Err(libc::EINVAL as u32);
    }
    if iovcnt == 0 {
        return Ok(Vec::new());
    }
    if iov_ptr == 0 {
        return Err(libc::EFAULT as u32);
    }
    let bytes_len = iovcnt
        .checked_mul(DARWIN_IOVEC_SIZE)
        .ok_or(libc::EINVAL as u32)?;
    let bytes = memory
        .read_memory(iov_ptr, bytes_len)
        .map_err(|_| libc::EFAULT as u32)?;
    let mut iovecs = Vec::with_capacity(iovcnt);
    let mut total = 0usize;
    for idx in 0..iovcnt {
        let offset = idx * DARWIN_IOVEC_SIZE;
        let base = read_u64_at(&bytes, offset + DARWIN_IOVEC_BASE).ok_or(libc::EFAULT as u32)?;
        let len = usize::try_from(
            read_u64_at(&bytes, offset + DARWIN_IOVEC_LEN).ok_or(libc::EFAULT as u32)?,
        )
        .map_err(|_| libc::EINVAL as u32)?;
        total = total.checked_add(len).ok_or(libc::EINVAL as u32)?;
        if total > MAX_GUEST_IOV_BYTES {
            return Err(libc::EINVAL as u32);
        }
        iovecs.push(GuestIovec { base, len });
    }
    Ok(iovecs)
}

#[cfg(target_os = "macos")]
pub(crate) fn read_guest_iovec_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iovecs: &[GuestIovec],
) -> Result<Vec<Vec<u8>>, u32> {
    let mut buffers = Vec::with_capacity(iovecs.len());
    for iov in iovecs {
        if iov.len == 0 {
            buffers.push(Vec::new());
            continue;
        }
        if iov.base == 0 {
            return Err(libc::EFAULT as u32);
        }
        let data = memory
            .read_memory(iov.base, iov.len)
            .map_err(|_| libc::EFAULT as u32)?;
        buffers.push(data);
    }
    Ok(buffers)
}

#[cfg(target_os = "macos")]
pub(crate) fn write_guest_iovec_bytes<M: GuestMemory + ?Sized>(
    memory: &mut M,
    iovecs: &[GuestIovec],
    buffers: &[Vec<u8>],
    count: usize,
) -> Result<(), u32> {
    let mut remaining = count;
    for (iov, buffer) in iovecs.iter().zip(buffers.iter()) {
        if remaining == 0 {
            break;
        }
        let write_len = remaining.min(iov.len);
        if write_len == 0 {
            continue;
        }
        if iov.base == 0 {
            return Err(libc::EFAULT as u32);
        }
        memory
            .write_memory(iov.base, &buffer[..write_len])
            .map_err(|_| libc::EFAULT as u32)?;
        remaining -= write_len;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn preview_iovec_bytes(buffers: &[Vec<u8>]) -> Vec<u8> {
    let mut preview = Vec::new();
    for buffer in buffers {
        if preview.len() >= 128 {
            break;
        }
        let remaining = 128 - preview.len();
        preview.extend_from_slice(&buffer[..buffer.len().min(remaining)]);
    }
    preview
}

#[cfg(target_os = "macos")]
pub(crate) fn host_iovec_from_mut_buffer(buffer: &mut Vec<u8>) -> libc::iovec {
    libc::iovec {
        iov_base: if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        },
        iov_len: buffer.len(),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn host_iovec_from_buffer(buffer: &Vec<u8>) -> libc::iovec {
    libc::iovec {
        iov_base: if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_ptr().cast::<libc::c_void>().cast_mut()
        },
        iov_len: buffer.len(),
    }
}

#[cfg(target_os = "macos")]
fn proxy_host_readv<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    iov_ptr: u64,
    iovcnt: u64,
) -> Option<HostIoResult> {
    let iovecs = match read_guest_iovecs(memory, iov_ptr, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut buffers = iovecs
        .iter()
        .map(|iov| vec![0u8; iov.len])
        .collect::<Vec<_>>();
    let host_iovecs = buffers
        .iter_mut()
        .map(host_iovec_from_mut_buffer)
        .collect::<Vec<_>>();
    clear_errno();
    let ret = unsafe {
        libc::readv(
            fd as libc::c_int,
            host_iovecs.as_ptr(),
            host_iovecs.len() as libc::c_int,
        )
    };
    if ret > 0 {
        let read_len = ret as usize;
        if let Err(errno) = write_guest_iovec_bytes(memory, &iovecs, &buffers, read_len) {
            return Some(host_io_error(errno));
        }
        note_host_fd_read(fd, ret);
    }
    let preview = if ret > 0 {
        preview_iovec_bytes(&buffers)
    } else {
        Vec::new()
    };
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_writev<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    iov_ptr: u64,
    iovcnt: u64,
) -> Option<HostIoResult> {
    let iovecs = match read_guest_iovecs(memory, iov_ptr, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let buffers = match read_guest_iovec_bytes(memory, &iovecs) {
        Ok(buffers) => buffers,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let host_iovecs = buffers
        .iter()
        .map(host_iovec_from_buffer)
        .collect::<Vec<_>>();
    let preview = preview_iovec_bytes(&buffers);
    clear_errno();
    let ret = unsafe {
        libc::writev(
            fd as libc::c_int,
            host_iovecs.as_ptr(),
            host_iovecs.len() as libc::c_int,
        )
    };
    note_host_fd_write(fd, ret);
    Some(host_io_result(ret, preview))
}

#[cfg(target_os = "macos")]
fn proxy_host_pread<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    offset: u64,
) -> Option<HostIoResult> {
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe {
        libc::pread(
            fd as libc::c_int,
            data.as_mut_ptr().cast(),
            count,
            offset as libc::off_t,
        )
    };
    if ret > 0 {
        let read_len = ret as usize;
        if memory.write_memory(buf_ptr, &data[..read_len]).is_err() {
            return Some(host_io_error(libc::EFAULT as u32));
        }
        data.truncate(read_len.min(128));
    } else {
        data.clear();
    }
    Some(host_io_result(ret, data))
}

#[cfg(target_os = "macos")]
fn proxy_host_pwrite<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    buf_ptr: u64,
    count: usize,
    offset: u64,
) -> Option<HostIoResult> {
    let data = if count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, count) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let ret = unsafe {
        libc::pwrite(
            fd as libc::c_int,
            data.as_ptr().cast(),
            data.len(),
            offset as libc::off_t,
        )
    };
    Some(host_io_result(ret, data[..data.len().min(128)].to_vec()))
}

#[cfg(target_os = "macos")]
fn proxy_host_lseek(fd: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe {
        libc::lseek(
            fd as libc::c_int,
            offset as libc::off_t,
            whence as libc::c_int,
        )
    };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dup(fd: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::dup(fd as libc::c_int) };
    if ret >= 0 {
        note_host_fd_dup(fd, ret);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dup2(from: u64, to: u64) -> Option<HostIoResult> {
    clear_errno();
    let ret = unsafe { libc::dup2(from as libc::c_int, to as libc::c_int) };
    if ret >= 0 {
        note_host_fd_dup(from, ret);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_pipe<M: GuestMemory + ?Sized>(memory: &mut M, fds_ptr: u64) -> Option<HostIoResult> {
    if fds_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut fds = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret == 0 {
        if write_guest_i32(memory, fds_ptr, fds[0]).is_err()
            || write_guest_i32(memory, fds_ptr + 4, fds[1]).is_err()
        {
            let _ = unsafe { libc::close(fds[0]) };
            let _ = unsafe { libc::close(fds[1]) };
            return Some(host_io_error(libc::EFAULT as u32));
        }
        note_host_pipe(fds[0], fds[1]);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_pipe_pair() -> Option<HostPipeResult> {
    let mut fds = [0 as libc::c_int; 2];
    clear_errno();
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret == 0 {
        note_host_pipe(fds[0], fds[1]);
        Some(HostPipeResult {
            read_fd: fds[0] as u64,
            write_fd: fds[1] as u64,
            errno: 0,
        })
    } else {
        Some(HostPipeResult {
            read_fd: u64::MAX,
            write_fd: 0,
            errno: host_errno(),
        })
    }
}
#[cfg(target_os = "macos")]
fn proxy_host_select<M: GuestMemory + ?Sized>(
    memory: &mut M,
    nfds: u64,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
) -> Option<HostIoResult> {
    if nfds > libc::c_int::MAX as u64 {
        return Some(host_io_error(libc::EINVAL as u32));
    }
    let readfds = match read_darwin_fd_set(memory, readfds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let writefds = match read_darwin_fd_set(memory, writefds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let exceptfds = match read_darwin_fd_set(memory, exceptfds_ptr, nfds) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut timeout = match read_darwin_timeval(memory, timeout_ptr) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };

    let mut read_host = match build_host_fd_set(readfds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut write_host = match build_host_fd_set(writefds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };
    let mut except_host = match build_host_fd_set(exceptfds.as_ref()) {
        Ok(value) => value,
        Err(errno) => return Some(host_io_error(errno)),
    };

    clear_errno();
    let mut ret = unsafe {
        libc::select(
            nfds as libc::c_int,
            read_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            write_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            except_host
                .as_mut()
                .map(|set| set.as_mut_ptr())
                .unwrap_or(ptr::null_mut()),
            timeout
                .as_mut()
                .map(|timeout| timeout as *mut libc::timeval)
                .unwrap_or(ptr::null_mut()),
        )
    };
    if ret < 0 {
        return Some(host_io_result(ret as isize, Vec::new()));
    }

    let mut ready_read = collect_ready_host_fd_set(readfds.as_ref(), read_host.as_ref());
    let ready_write = collect_ready_host_fd_set(writefds.as_ref(), write_host.as_ref());
    let ready_except = collect_ready_host_fd_set(exceptfds.as_ref(), except_host.as_ref());
    let inferred_readfds = infer_single_read_fd(readfds.as_ref(), readfds_ptr, nfds);
    let fallback_readfds = inferred_readfds.as_ref().or(readfds.as_ref());
    if ready_read.is_empty() {
        ready_read = collect_tracked_read_ready(readfds.as_ref());
        if ready_read.is_empty() {
            ready_read = collect_fionread_ready(readfds.as_ref());
        }
        if ready_read.is_empty() {
            ready_read = collect_poll_ready(readfds.as_ref());
        }
        if ready_read.is_empty() && inferred_readfds.is_some() {
            ready_read = collect_tracked_read_ready(fallback_readfds);
            if ready_read.is_empty() {
                ready_read = collect_fionread_ready(fallback_readfds);
            }
            if ready_read.is_empty() {
                ready_read = collect_poll_ready(fallback_readfds);
            }
        }
        if !ready_read.is_empty() {
            ret = ret.max(ready_read.len() as libc::c_int);
        } else if ret > 0 {
            if let Some(original) = readfds.as_ref() {
                ready_read = original.iter().copied().take(ret as usize).collect();
            }
        }
    }

    if let Err(errno) = write_darwin_fd_set(memory, readfds_ptr, fallback_readfds, &ready_read)
        .and_then(|_| write_darwin_fd_set(memory, writefds_ptr, writefds.as_ref(), &ready_write))
        .and_then(|_| write_darwin_fd_set(memory, exceptfds_ptr, exceptfds.as_ref(), &ready_except))
    {
        return Some(host_io_error(errno));
    }

    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_darwin_fd_set<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    nfds: u64,
) -> Result<Option<HashSet<libc::c_int>>, u32> {
    if addr == 0 {
        return Ok(None);
    }
    const DARWIN_FD_SET_BYTES: usize = 128;
    const DARWIN_NFDBITS: usize = 32;
    let bytes = memory
        .read_memory(addr, DARWIN_FD_SET_BYTES)
        .map_err(|_| libc::EFAULT as u32)?;
    let mut fds = HashSet::new();
    for fd in 0..(nfds as usize).min(DARWIN_FD_SET_BYTES * 8) {
        let bit = fd % DARWIN_NFDBITS;
        let word_start = (fd / DARWIN_NFDBITS) * 4;
        if word_start + 4 > bytes.len() {
            break;
        }
        let word = u32::from_le_bytes([
            bytes[word_start],
            bytes[word_start + 1],
            bytes[word_start + 2],
            bytes[word_start + 3],
        ]);
        if (word & (1u32 << bit)) != 0 {
            fds.insert(fd as libc::c_int);
        }
    }
    Ok(Some(fds))
}

#[cfg(target_os = "macos")]
fn write_darwin_fd_set<M: GuestMemory + ?Sized>(
    memory: &mut M,
    addr: u64,
    original: Option<&HashSet<libc::c_int>>,
    ready: &HashSet<libc::c_int>,
) -> Result<(), u32> {
    if addr == 0 || original.is_none() {
        return Ok(());
    }
    const DARWIN_FD_SET_BYTES: usize = 128;
    const DARWIN_NFDBITS: usize = 32;
    let mut bytes = vec![0u8; DARWIN_FD_SET_BYTES];
    for fd in ready {
        if *fd < 0 {
            continue;
        }
        let fd = *fd as usize;
        let word_start = (fd / DARWIN_NFDBITS) * 4;
        if word_start + 4 > bytes.len() {
            continue;
        }
        let bit = fd % DARWIN_NFDBITS;
        let mut word = u32::from_le_bytes([
            bytes[word_start],
            bytes[word_start + 1],
            bytes[word_start + 2],
            bytes[word_start + 3],
        ]);
        word |= 1u32 << bit;
        bytes[word_start..word_start + 4].copy_from_slice(&word.to_le_bytes());
    }
    memory
        .write_memory(addr, &bytes)
        .map_err(|_| libc::EFAULT as u32)
}

#[cfg(target_os = "macos")]
fn build_host_fd_set(
    fds: Option<&HashSet<libc::c_int>>,
) -> Result<Option<MaybeUninit<libc::fd_set>>, u32> {
    let Some(fds) = fds else {
        return Ok(None);
    };
    let mut set = MaybeUninit::<libc::fd_set>::zeroed();
    unsafe {
        libc::FD_ZERO(set.as_mut_ptr());
    }
    for fd in fds {
        if *fd < 0 || *fd as usize >= libc::FD_SETSIZE {
            return Err(libc::EINVAL as u32);
        }
        unsafe {
            libc::FD_SET(*fd, set.as_mut_ptr());
        }
    }
    Ok(Some(set))
}

#[cfg(target_os = "macos")]
fn collect_ready_host_fd_set(
    original: Option<&HashSet<libc::c_int>>,
    host: Option<&MaybeUninit<libc::fd_set>>,
) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let (Some(original), Some(host)) = (original, host) else {
        return ready;
    };
    for fd in original {
        let is_ready = unsafe { libc::FD_ISSET(*fd, host.as_ptr()) };
        if is_ready {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn infer_single_read_fd(
    original: Option<&HashSet<libc::c_int>>,
    readfds_ptr: u64,
    nfds: u64,
) -> Option<HashSet<libc::c_int>> {
    if readfds_ptr == 0 || !original.is_some_and(HashSet::is_empty) || nfds == 0 {
        return None;
    }
    let fd = nfds.checked_sub(1)? as libc::c_int;
    if fd < 0 || fd as usize >= libc::FD_SETSIZE {
        return None;
    }
    Some(HashSet::from([fd]))
}

#[cfg(target_os = "macos")]
fn collect_tracked_read_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    let Ok(readiness) = host_fd_readiness().lock() else {
        return ready;
    };
    for fd in original {
        if readiness
            .pending_read_bytes
            .get(fd)
            .copied()
            .unwrap_or_default()
            > 0
        {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn collect_fionread_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    for fd in original {
        let mut available: libc::c_int = 0;
        let ret = unsafe { libc::ioctl(*fd, libc::FIONREAD, &mut available as *mut libc::c_int) };
        if ret == 0 && available > 0 {
            ready.insert(*fd);
        }
    }
    ready
}

#[cfg(target_os = "macos")]
fn collect_poll_ready(original: Option<&HashSet<libc::c_int>>) -> HashSet<libc::c_int> {
    let mut ready = HashSet::new();
    let Some(original) = original else {
        return ready;
    };
    let mut fds = original
        .iter()
        .copied()
        .filter(|fd| *fd >= 0)
        .map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect::<Vec<_>>();
    if fds.is_empty() {
        return ready;
    }
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
    if ret <= 0 {
        return ready;
    }
    for fd in fds {
        if (fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            ready.insert(fd.fd);
        }
    }
    ready
}
#[cfg(target_os = "macos")]
fn allocate_guest_file_handle<M: GuestMemory + ?Sized>(
    memory: &mut M,
    file_ptr: *mut libc::FILE,
) -> Option<u64> {
    let guest_handle = memory.allocate_memory(HOST_FILE_HANDLE_SIZE, 8).ok()?;
    memory
        .write_memory(guest_handle, &0u64.to_le_bytes())
        .ok()?;
    host_file_handles().lock().ok()?.insert(
        guest_handle,
        HostFileHandle {
            file_ptr: file_ptr as usize,
        },
    );
    Some(guest_handle)
}

#[cfg(target_os = "macos")]
fn proxy_host_fopen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
    mode_ptr: u64,
) -> Option<HostCallResult> {
    let path = read_cstring(memory, path_ptr, HOST_PATH_BUFFER_SIZE).ok()?;
    let mode = read_cstring(memory, mode_ptr, 64).ok()?;
    let host_path = CString::new(path).ok()?;
    let host_mode = CString::new(mode).ok()?;
    clear_errno();
    let file = unsafe { libc::fopen(host_path.as_ptr(), host_mode.as_ptr()) };
    if file.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let Some(guest_handle) = allocate_guest_file_handle(memory, file) else {
        unsafe {
            libc::fclose(file);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(host_call_value(guest_handle))
}

#[cfg(target_os = "macos")]
fn proxy_host_fdopen<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
    mode_ptr: u64,
) -> Option<HostCallResult> {
    let mode = read_cstring(memory, mode_ptr, 64).ok()?;
    let host_mode = CString::new(mode).ok()?;
    clear_errno();
    let file = unsafe { libc::fdopen(fd as libc::c_int, host_mode.as_ptr()) };
    if file.is_null() {
        return Some(host_null_error(host_errno()));
    }
    let Some(guest_handle) = allocate_guest_file_handle(memory, file) else {
        unsafe {
            libc::fclose(file);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(host_call_value(guest_handle))
}

#[cfg(target_os = "macos")]
fn proxy_host_fclose<M: GuestMemory + ?Sized>(memory: &mut M, stream: u64) -> Option<HostIoResult> {
    let handle = match host_file_handles().lock().ok()?.remove(&stream) {
        Some(handle) => handle,
        None => return Some(host_io_error(libc::EBADF as u32)),
    };
    clear_errno();
    let ret = unsafe { libc::fclose(handle.file_ptr as *mut libc::FILE) };
    let _ = memory.free_memory(stream);
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn guest_stdio_size(size: u64, nmemb: u64) -> Option<(usize, usize, usize)> {
    let item_size = usize::try_from(size).ok()?;
    let item_count = usize::try_from(nmemb).ok()?;
    let byte_count = item_size.checked_mul(item_count)?;
    (byte_count <= MAX_GUEST_STDIO_BYTES).then_some((item_size, item_count, byte_count))
}

#[cfg(target_os = "macos")]
fn proxy_host_fread<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    nmemb: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let (item_size, item_count, byte_count) = match guest_stdio_size(size, nmemb) {
        Some(sizes) => sizes,
        None => return Some(host_io_error(libc::EINVAL as u32)),
    };
    if byte_count > 0 && buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    if byte_count == 0 {
        return Some(HostIoResult {
            return_value: 0,
            errno: 0,
            transferred: 0,
            preview: Vec::new(),
        });
    }
    let mut data = vec![0u8; byte_count];
    clear_errno();
    let items = unsafe {
        libc::fread(
            data.as_mut_ptr().cast::<libc::c_void>(),
            item_size,
            item_count,
            file,
        )
    };
    let transferred = items.saturating_mul(item_size).min(data.len());
    if transferred > 0 && memory.write_memory(buf_ptr, &data[..transferred]).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let errno = if items < item_count && unsafe { libc::ferror(file) } != 0 {
        host_errno()
    } else {
        0
    };
    Some(HostIoResult {
        return_value: items as u64,
        errno,
        transferred,
        preview: data[..transferred.min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fwrite<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    nmemb: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let (item_size, item_count, byte_count) = match guest_stdio_size(size, nmemb) {
        Some(sizes) => sizes,
        None => return Some(host_io_error(libc::EINVAL as u32)),
    };
    if byte_count > 0 && buf_ptr == 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    let data = if byte_count == 0 {
        Vec::new()
    } else {
        match memory.read_memory(buf_ptr, byte_count) {
            Ok(data) => data,
            Err(_) => return Some(host_io_error(libc::EFAULT as u32)),
        }
    };
    clear_errno();
    let items = unsafe {
        libc::fwrite(
            data.as_ptr().cast::<libc::c_void>(),
            item_size,
            item_count,
            file,
        )
    };
    let transferred = items.saturating_mul(item_size).min(data.len());
    let errno = if items < item_count && unsafe { libc::ferror(file) } != 0 {
        host_errno()
    } else {
        0
    };
    Some(HostIoResult {
        return_value: items as u64,
        errno,
        transferred,
        preview: data[..transferred.min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fflush(stream: u64) -> Option<HostIoResult> {
    let file = if stream == 0 {
        ptr::null_mut()
    } else {
        let Some(file) = host_file_ptr(stream) else {
            return Some(host_io_error(libc::EBADF as u32));
        };
        file
    };
    clear_errno();
    let ret = unsafe { libc::fflush(file) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_fseek(stream: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fseek(file, offset as i64 as libc::c_long, whence as libc::c_int) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_ftell(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::ftell(file) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_fgets<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    size: u64,
    stream: u64,
) -> Option<HostCallResult> {
    if buf_ptr == 0 || size == 0 || size > libc::c_int::MAX as u64 {
        return Some(host_null_error(libc::EINVAL as u32));
    }
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_null_error(libc::EBADF as u32));
    };
    let mut data = vec![0u8; size as usize];
    clear_errno();
    let ret = unsafe {
        libc::fgets(
            data.as_mut_ptr().cast::<libc::c_char>(),
            size as libc::c_int,
            file,
        )
    };
    if ret.is_null() {
        let errno = if unsafe { libc::ferror(file) } != 0 {
            Some(host_errno())
        } else {
            None
        };
        return Some(HostCallResult {
            return_value: 0,
            errno,
        });
    }
    let write_len = data
        .iter()
        .position(|byte| *byte == 0)
        .map(|idx| idx + 1)
        .unwrap_or(data.len());
    if memory.write_memory(buf_ptr, &data[..write_len]).is_err() {
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(host_call_value(buf_ptr))
}

#[cfg(target_os = "macos")]
fn proxy_host_fputs<M: GuestMemory + ?Sized>(
    memory: &mut M,
    text_ptr: u64,
    stream: u64,
) -> Option<HostIoResult> {
    let text = read_cstring(memory, text_ptr, MAX_GUEST_STDIO_BYTES).ok()?;
    let bytes = text.as_bytes().to_vec();
    let host_text = CString::new(text).ok()?;
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fputs(host_text.as_ptr(), file) };
    Some(HostIoResult {
        return_value: signed_return_value(ret as isize),
        errno: if ret < 0 { host_errno() } else { 0 },
        transferred: if ret < 0 { 0 } else { bytes.len() },
        preview: bytes[..bytes.len().min(128)].to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_feof(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    let ret = unsafe { libc::feof(file) };
    Some(host_call_value(ret as u64))
}

#[cfg(target_os = "macos")]
fn proxy_host_ferror(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    let ret = unsafe { libc::ferror(file) };
    Some(host_call_value(ret as u64))
}

#[cfg(target_os = "macos")]
fn proxy_host_clearerr(stream: u64) -> Option<HostCallResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::clearerr(file);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_fileno(stream: u64) -> Option<HostIoResult> {
    let Some(file) = host_file_ptr(stream) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::fileno(file) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn allocate_guest_dir_handle<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dir_ptr: *mut libc::DIR,
) -> Option<u64> {
    let guest_handle = memory.allocate_memory(8, 8).ok()?;
    memory
        .write_memory(guest_handle, &0u64.to_le_bytes())
        .ok()?;
    host_dir_handles().lock().ok()?.insert(
        guest_handle,
        HostDirHandle {
            dir_ptr: dir_ptr as usize,
            dirent_guest_ptr: 0,
        },
    );
    Some(guest_handle)
}

#[cfg(target_os = "macos")]
fn proxy_host_opendir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    path_ptr: u64,
) -> Option<HostCallResult> {
    let path = read_cstring(memory, path_ptr, 4096).ok()?;
    let host_path = CString::new(path).ok()?;
    clear_errno();
    let dir = unsafe { libc::opendir(host_path.as_ptr()) };
    if dir.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(host_errno()),
        });
    }
    let Some(guest_handle) = allocate_guest_dir_handle(memory, dir) else {
        unsafe {
            libc::closedir(dir);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(HostCallResult {
        return_value: guest_handle,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_fdopendir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    fd: u64,
) -> Option<HostCallResult> {
    clear_errno();
    let dir = unsafe { libc::fdopendir(fd as libc::c_int) };
    if dir.is_null() {
        return Some(HostCallResult {
            return_value: 0,
            errno: Some(host_errno()),
        });
    }
    let Some(guest_handle) = allocate_guest_dir_handle(memory, dir) else {
        unsafe {
            libc::closedir(dir);
        }
        return Some(host_null_error(libc::ENOMEM as u32));
    };
    Some(HostCallResult {
        return_value: guest_handle,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_readdir<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirp: u64,
) -> Option<HostCallResult> {
    let mut handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get_mut(&dirp) else {
        return Some(host_null_error(libc::EBADF as u32));
    };
    clear_errno();
    let entry = unsafe { libc::readdir(handle.dir_ptr as *mut libc::DIR) };
    if entry.is_null() {
        let errno = host_errno();
        return Some(HostCallResult {
            return_value: 0,
            errno: (errno != 0).then_some(errno),
        });
    }
    if handle.dirent_guest_ptr == 0 {
        handle.dirent_guest_ptr = match memory.allocate_memory(HOST_DIRENT_SIZE, 8) {
            Ok(addr) => addr,
            Err(_) => return Some(host_null_error(libc::ENOMEM as u32)),
        };
    }
    let bytes = unsafe { std::slice::from_raw_parts(entry.cast::<u8>(), HOST_DIRENT_SIZE) };
    if memory.write_memory(handle.dirent_guest_ptr, bytes).is_err() {
        return Some(host_null_error(libc::EFAULT as u32));
    }
    Some(HostCallResult {
        return_value: handle.dirent_guest_ptr,
        errno: None,
    })
}

#[cfg(target_os = "macos")]
fn proxy_host_readdir_r<M: GuestMemory + ?Sized>(
    memory: &mut M,
    dirp: u64,
    entry_ptr: u64,
    result_ptr: u64,
) -> Option<HostCallResult> {
    if entry_ptr == 0 || result_ptr == 0 {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    let result = proxy_host_readdir(memory, dirp)?;
    if result.return_value == 0 {
        let _ = write_guest_u64(memory, result_ptr, 0);
        return Some(host_call_value(result.errno.unwrap_or(0) as u64));
    }
    let bytes = match memory.read_memory(result.return_value, HOST_DIRENT_SIZE) {
        Ok(bytes) => bytes,
        Err(_) => return Some(host_call_value(libc::EFAULT as u64)),
    };
    if memory.write_memory(entry_ptr, &bytes).is_err()
        || write_guest_u64(memory, result_ptr, entry_ptr).is_err()
    {
        return Some(host_call_value(libc::EFAULT as u64));
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_closedir<M: GuestMemory + ?Sized>(memory: &mut M, dirp: u64) -> Option<HostIoResult> {
    let handle = match host_dir_handles().lock().ok()?.remove(&dirp) {
        Some(handle) => handle,
        None => return Some(host_io_error(libc::EBADF as u32)),
    };
    clear_errno();
    let ret = unsafe { libc::closedir(handle.dir_ptr as *mut libc::DIR) };
    let _ = memory.free_memory(dirp);
    if handle.dirent_guest_ptr != 0 {
        let _ = memory.free_memory(handle.dirent_guest_ptr);
    }
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_dirfd(dirp: u64) -> Option<HostIoResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_io_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::dirfd(handle.dir_ptr as *mut libc::DIR) };
    Some(host_io_result(ret as isize, Vec::new()))
}

#[cfg(target_os = "macos")]
fn proxy_host_rewinddir(dirp: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::rewinddir(handle.dir_ptr as *mut libc::DIR);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_telldir(dirp: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    clear_errno();
    let ret = unsafe { libc::telldir(handle.dir_ptr as *mut libc::DIR) };
    Some(host_call_result(ret as isize))
}

#[cfg(target_os = "macos")]
fn proxy_host_seekdir(dirp: u64, loc: u64) -> Option<HostCallResult> {
    let handles = host_dir_handles().lock().ok()?;
    let Some(handle) = handles.get(&dirp) else {
        return Some(host_call_error(libc::EBADF as u32));
    };
    unsafe {
        libc::seekdir(handle.dir_ptr as *mut libc::DIR, loc as libc::c_long);
    }
    Some(host_call_value(0))
}

#[cfg(target_os = "macos")]
fn proxy_host_getentropy<M: GuestMemory + ?Sized>(
    memory: &mut M,
    buf_ptr: u64,
    count: usize,
) -> Option<HostIoResult> {
    if count > 256 {
        return Some(host_io_error(libc::EIO as u32));
    }
    if buf_ptr == 0 && count > 0 {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    let mut data = vec![0u8; count];
    clear_errno();
    let ret = unsafe { libc::getentropy(data.as_mut_ptr().cast::<libc::c_void>(), data.len()) };
    if ret == 0 && count > 0 && memory.write_memory(buf_ptr, &data).is_err() {
        return Some(host_io_error(libc::EFAULT as u32));
    }
    Some(host_io_result(ret as isize, data))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn pipe_readiness_cache_marks_read_end_ready() {
        let read_fd = 700;
        let write_fd = 701;
        note_host_fd_close(read_fd as u64);
        note_host_fd_close(write_fd as u64);

        note_host_pipe(read_fd, write_fd);
        let read_set = HashSet::from([read_fd]);
        assert!(collect_tracked_read_ready(Some(&read_set)).is_empty());

        note_host_fd_write(write_fd as u64, 1);
        assert_eq!(collect_tracked_read_ready(Some(&read_set)), read_set);

        note_host_fd_read(read_fd as u64, 1);
        assert!(collect_tracked_read_ready(Some(&read_set)).is_empty());

        note_host_fd_close(read_fd as u64);
        note_host_fd_close(write_fd as u64);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn select_fallback_can_infer_single_requested_read_fd() {
        let empty = HashSet::new();
        let inferred = infer_single_read_fd(Some(&empty), 0x1000, 4)
            .expect("empty read fd_set with nfds should infer the highest fd");
        assert_eq!(inferred, HashSet::from([3]));

        let non_empty = HashSet::from([2]);
        assert!(infer_single_read_fd(Some(&non_empty), 0x1000, 4).is_none());
        assert!(infer_single_read_fd(Some(&empty), 0, 4).is_none());
        assert!(infer_single_read_fd(Some(&empty), 0x1000, 0).is_none());
    }
}
