//! Compatibility-mode adapter for Machina's emulator trait.
//!
//! Host proxy behavior lives in `machina-compat`. This module only adapts the
//! main crate's `Emulator` trait into the guest-memory trait that the compat
//! crate consumes, keeping compatibility logic out of the analysis runtime.

use crate::macos::{Emulator, RuntimeMode};

pub use machina_compat::{HostCallResult, HostIoResult, HostOpenResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityServices;

struct EmulatorGuestMemory<'a> {
    emulator: &'a mut dyn Emulator,
}

impl machina_compat::GuestMemory for EmulatorGuestMemory<'_> {
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
}

impl CompatibilityServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        machina_compat::CompatibilityServices::for_mode(mode).map(|_| Self)
    }

    pub fn should_proxy_import(&self, symbol: &str) -> bool {
        machina_compat::CompatibilityServices.should_proxy_import(symbol)
    }

    pub fn proxy_cstring_arg0_import(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        arg0_ptr: u64,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_cstring_arg0_import(
            &mut memory,
            symbol,
            arg0_ptr,
        )
    }

    pub fn proxy_arm64_import(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        args: &[u64; 8],
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_arm64_import(&mut memory, symbol, args)
    }

    pub fn proxy_arm64_import_with_stack(
        &self,
        emu: &mut dyn Emulator,
        symbol: &str,
        args: &[u64; 8],
        stack_ptr: Option<u64>,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.proxy_arm64_import_with_stack(
            &mut memory,
            symbol,
            args,
            stack_ptr,
        )
    }

    pub fn open_path_arg0(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        flags: u64,
        mode: u64,
    ) -> Option<HostOpenResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.open_path_arg0(&mut memory, path_ptr, flags, mode)
    }

    pub fn read_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.read_fd(&mut memory, fd, buf_ptr, count)
    }

    pub fn write_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.write_fd(&mut memory, fd, buf_ptr, count)
    }

    pub fn close_fd(&self, fd: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.close_fd(fd)
    }

    pub fn socket(&self, domain: u64, kind: u64, protocol: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.socket(domain, kind, protocol)
    }

    pub fn connect_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.connect_socket(
            &mut memory,
            fd,
            sockaddr_ptr,
            sockaddr_len,
        )
    }

    pub fn bind_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.bind_socket(
            &mut memory,
            fd,
            sockaddr_ptr,
            sockaddr_len,
        )
    }

    pub fn listen_socket(&self, fd: u64, backlog: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.listen_socket(fd, backlog)
    }

    pub fn send_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.send_socket(&mut memory, fd, buf_ptr, count, flags)
    }

    pub fn recv_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.recv_socket(&mut memory, fd, buf_ptr, count, flags)
    }

    pub fn sendto_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.sendto_socket(
            &mut memory,
            fd,
            buf_ptr,
            count,
            flags,
            sockaddr_ptr,
            sockaddr_len,
        )
    }

    pub fn recvfrom_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        flags: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.recvfrom_socket(
            &mut memory,
            fd,
            buf_ptr,
            count,
            flags,
            sockaddr_ptr,
            sockaddr_len_ptr,
        )
    }

    pub fn sendmsg_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.sendmsg_socket(&mut memory, fd, msg_ptr, flags)
    }

    pub fn recvmsg_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        msg_ptr: u64,
        flags: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.recvmsg_socket(&mut memory, fd, msg_ptr, flags)
    }

    pub fn shutdown_socket(&self, fd: u64, how: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.shutdown_socket(fd, how)
    }

    pub fn setsockopt_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.setsockopt_socket(
            &mut memory,
            fd,
            level,
            option_name,
            option_value_ptr,
            option_len,
        )
    }

    pub fn getsockopt_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        level: u64,
        option_name: u64,
        option_value_ptr: u64,
        option_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getsockopt_socket(
            &mut memory,
            fd,
            level,
            option_name,
            option_value_ptr,
            option_len_ptr,
        )
    }

    pub fn accept_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.accept_socket(
            &mut memory,
            fd,
            sockaddr_ptr,
            sockaddr_len_ptr,
        )
    }

    pub fn getpeername_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getpeername_socket(
            &mut memory,
            fd,
            sockaddr_ptr,
            sockaddr_len_ptr,
        )
    }

    pub fn getsockname_socket(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        sockaddr_ptr: u64,
        sockaddr_len_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getsockname_socket(
            &mut memory,
            fd,
            sockaddr_ptr,
            sockaddr_len_ptr,
        )
    }

    pub fn socketpair(
        &self,
        emu: &mut dyn Emulator,
        domain: u64,
        kind: u64,
        protocol: u64,
        sv_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.socketpair(
            &mut memory,
            domain,
            kind,
            protocol,
            sv_ptr,
        )
    }

    pub fn fcntl_fd(&self, fd: u64, cmd: u64, arg: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.fcntl_fd(fd, cmd, arg)
    }

    pub fn poll_fds(
        &self,
        emu: &mut dyn Emulator,
        fds_ptr: u64,
        nfds: u64,
        timeout: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.poll_fds(&mut memory, fds_ptr, nfds, timeout)
    }

    pub fn readv_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.readv_fd(&mut memory, fd, iov_ptr, iovcnt)
    }

    pub fn writev_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        iov_ptr: u64,
        iovcnt: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.writev_fd(&mut memory, fd, iov_ptr, iovcnt)
    }

    pub fn pread_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.pread_fd(&mut memory, fd, buf_ptr, count, offset)
    }

    pub fn pwrite_fd(
        &self,
        emu: &mut dyn Emulator,
        fd: u64,
        buf_ptr: u64,
        count: usize,
        offset: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.pwrite_fd(&mut memory, fd, buf_ptr, count, offset)
    }

    pub fn lseek_fd(&self, fd: u64, offset: u64, whence: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.lseek_fd(fd, offset, whence)
    }

    pub fn dup_fd(&self, fd: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.dup_fd(fd)
    }

    pub fn dup2_fd(&self, from: u64, to: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.dup2_fd(from, to)
    }

    pub fn select_fds(
        &self,
        emu: &mut dyn Emulator,
        nfds: u64,
        readfds_ptr: u64,
        writefds_ptr: u64,
        exceptfds_ptr: u64,
        timeout_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.select_fds(
            &mut memory,
            nfds,
            readfds_ptr,
            writefds_ptr,
            exceptfds_ptr,
            timeout_ptr,
        )
    }

    pub fn access_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.access_path(&mut memory, path_ptr, mode)
    }

    pub fn chdir_path(&self, emu: &mut dyn Emulator, path_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.chdir_path(&mut memory, path_ptr)
    }

    pub fn fchdir_fd(&self, fd: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.fchdir_fd(fd)
    }

    pub fn getcwd_path(
        &self,
        emu: &mut dyn Emulator,
        buf_ptr: u64,
        size: u64,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getcwd_path(&mut memory, buf_ptr, size)
    }

    pub fn stat_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.stat_path(&mut memory, path_ptr, stat_ptr)
    }

    pub fn lstat_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        stat_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.lstat_path(&mut memory, path_ptr, stat_ptr)
    }

    pub fn fstat_fd(&self, emu: &mut dyn Emulator, fd: u64, stat_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.fstat_fd(&mut memory, fd, stat_ptr)
    }

    pub fn mkdir_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        mode: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.mkdir_path(&mut memory, path_ptr, mode)
    }

    pub fn rmdir_path(&self, emu: &mut dyn Emulator, path_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.rmdir_path(&mut memory, path_ptr)
    }

    pub fn unlink_path(&self, emu: &mut dyn Emulator, path_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.unlink_path(&mut memory, path_ptr)
    }

    pub fn rename_path(
        &self,
        emu: &mut dyn Emulator,
        from_ptr: u64,
        to_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.rename_path(&mut memory, from_ptr, to_ptr)
    }

    pub fn readlink_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.readlink_path(&mut memory, path_ptr, buf_ptr, count)
    }

    pub fn symlink_path(
        &self,
        emu: &mut dyn Emulator,
        target_ptr: u64,
        link_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.symlink_path(&mut memory, target_ptr, link_ptr)
    }

    pub fn realpath_path(
        &self,
        emu: &mut dyn Emulator,
        path_ptr: u64,
        resolved_ptr: u64,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.realpath_path(&mut memory, path_ptr, resolved_ptr)
    }

    pub fn setenv_var(
        &self,
        emu: &mut dyn Emulator,
        name_ptr: u64,
        value_ptr: u64,
        overwrite: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.setenv_var(
            &mut memory,
            name_ptr,
            value_ptr,
            overwrite,
        )
    }

    pub fn unsetenv_var(&self, emu: &mut dyn Emulator, name_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.unsetenv_var(&mut memory, name_ptr)
    }

    pub fn getpid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getpid()
    }

    pub fn getppid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getppid()
    }

    pub fn getuid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getuid()
    }

    pub fn geteuid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.geteuid()
    }

    pub fn getgid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getgid()
    }

    pub fn getegid(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getegid()
    }

    pub fn sysconf(&self, name: u64) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.sysconf(name)
    }

    pub fn getpagesize(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.getpagesize()
    }

    pub fn gethostname(
        &self,
        emu: &mut dyn Emulator,
        name_ptr: u64,
        len: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.gethostname(&mut memory, name_ptr, len)
    }

    pub fn uname(&self, emu: &mut dyn Emulator, uts_ptr: u64) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.uname(&mut memory, uts_ptr)
    }

    pub fn gettimeofday(
        &self,
        emu: &mut dyn Emulator,
        tv_ptr: u64,
        tz_ptr: u64,
        mach_absolute_time_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.gettimeofday(
            &mut memory,
            tv_ptr,
            tz_ptr,
            mach_absolute_time_ptr,
        )
    }

    pub fn clock_gettime(
        &self,
        emu: &mut dyn Emulator,
        clock_id: u64,
        tp_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.clock_gettime(&mut memory, clock_id, tp_ptr)
    }

    pub fn nanosleep(
        &self,
        emu: &mut dyn Emulator,
        req_ptr: u64,
        rem_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.nanosleep(&mut memory, req_ptr, rem_ptr)
    }

    pub fn sleep_seconds(&self, seconds: u64) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.sleep_seconds(seconds)
    }

    pub fn usleep_usecs(&self, usecs: u64) -> Option<HostIoResult> {
        machina_compat::CompatibilityServices.usleep_usecs(usecs)
    }

    pub fn mach_absolute_time(&self) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.mach_absolute_time()
    }

    pub fn mach_timebase_info(
        &self,
        emu: &mut dyn Emulator,
        info_ptr: u64,
    ) -> Option<HostCallResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.mach_timebase_info(&mut memory, info_ptr)
    }

    pub fn getrlimit(
        &self,
        emu: &mut dyn Emulator,
        resource: u64,
        rlp_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getrlimit(&mut memory, resource, rlp_ptr)
    }

    pub fn setrlimit(
        &self,
        emu: &mut dyn Emulator,
        resource: u64,
        rlp_ptr: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.setrlimit(&mut memory, resource, rlp_ptr)
    }

    pub fn sysctl(
        &self,
        emu: &mut dyn Emulator,
        name_ptr: u64,
        namelen: u64,
        oldp: u64,
        oldlenp: u64,
        newp: u64,
        newlen: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.sysctl(
            &mut memory,
            name_ptr,
            namelen,
            oldp,
            oldlenp,
            newp,
            newlen,
        )
    }

    pub fn sysctlbyname(
        &self,
        emu: &mut dyn Emulator,
        name_ptr: u64,
        oldp: u64,
        oldlenp: u64,
        newp: u64,
        newlen: u64,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.sysctlbyname(
            &mut memory,
            name_ptr,
            oldp,
            oldlenp,
            newp,
            newlen,
        )
    }

    pub fn umask(&self, mask: u64) -> Option<HostCallResult> {
        machina_compat::CompatibilityServices.umask(mask)
    }

    pub fn getentropy(
        &self,
        emu: &mut dyn Emulator,
        buf_ptr: u64,
        count: usize,
    ) -> Option<HostIoResult> {
        let mut memory = EmulatorGuestMemory { emulator: emu };
        machina_compat::CompatibilityServices.getentropy(&mut memory, buf_ptr, count)
    }
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
}
