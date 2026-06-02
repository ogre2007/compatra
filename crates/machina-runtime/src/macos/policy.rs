use crate::macos::Emulator;
use crate::macos::LogLevel;
use crate::macos::MacOsError;

pub struct MacOsPolicyManager {
    policies: Vec<PolicyEntry>,
    #[allow(dead_code)]
    ev_manager_ref: Option<u64>,
}

pub(crate) struct PolicyEntry {
    name: String,
    ops: PolicyOps,
    #[allow(dead_code)]
    flags: u32,
    #[allow(dead_code)]
    label: Option<u64>,
}

#[derive(Debug, Clone)]
struct PolicyOps {
    mpo_vnode_check_access: Option<u64>,
    mpo_vnode_check_chdir: Option<u64>,
    mpo_vnode_check_chroot: Option<u64>,
    mpo_vnode_check_create: Option<u64>,
    mpo_vnode_check_delete: Option<u64>,
    mpo_vnode_check_exec: Option<u64>,
    mpo_vnode_check_link: Option<u64>,
    mpo_vnode_check_lookup: Option<u64>,
    mpo_vnode_check_open: Option<u64>,
    mpo_vnode_check_readlink: Option<u64>,
    mpo_vnode_check_rename_from: Option<u64>,
    mpo_vnode_check_rename_to: Option<u64>,
    mpo_vnode_check_revoke: Option<u64>,
    mpo_vnode_check_stat: Option<u64>,
    mpo_vnode_check_unlink: Option<u64>,
    mpo_proc_check_fork: Option<u64>,
    mpo_proc_check_signal: Option<u64>,
    mpo_proc_check_wait: Option<u64>,
    mpo_file_check_mmap: Option<u64>,
    mpo_file_check_mmap_downgrade: Option<u64>,
    mpo_file_check_mmap_protect: Option<u64>,
    mpo_socket_check_bind: Option<u64>,
    mpo_socket_check_connect: Option<u64>,
    mpo_socket_check_create: Option<u64>,
    mpo_socket_check_deliver: Option<u64>,
    mpo_socket_check_listen: Option<u64>,
    mpo_socket_check_receive: Option<u64>,
    mpo_socket_check_send: Option<u64>,
    mpo_system_check_sysctlbyname: Option<u64>,
}

impl MacOsPolicyManager {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            ev_manager_ref: None,
        }
    }

    pub fn register_policy(&mut self, name: &str, flags: u32) {
        let entry = PolicyEntry {
            name: name.to_string(),
            ops: PolicyOps {
                mpo_vnode_check_access: None,
                mpo_vnode_check_chdir: None,
                mpo_vnode_check_chroot: None,
                mpo_vnode_check_create: None,
                mpo_vnode_check_delete: None,
                mpo_vnode_check_exec: None,
                mpo_vnode_check_link: None,
                mpo_vnode_check_lookup: None,
                mpo_vnode_check_open: None,
                mpo_vnode_check_readlink: None,
                mpo_vnode_check_rename_from: None,
                mpo_vnode_check_rename_to: None,
                mpo_vnode_check_revoke: None,
                mpo_vnode_check_stat: None,
                mpo_vnode_check_unlink: None,
                mpo_proc_check_fork: None,
                mpo_proc_check_signal: None,
                mpo_proc_check_wait: None,
                mpo_file_check_mmap: None,
                mpo_file_check_mmap_downgrade: None,
                mpo_file_check_mmap_protect: None,
                mpo_socket_check_bind: None,
                mpo_socket_check_connect: None,
                mpo_socket_check_create: None,
                mpo_socket_check_deliver: None,
                mpo_socket_check_listen: None,
                mpo_socket_check_receive: None,
                mpo_socket_check_send: None,
                mpo_system_check_sysctlbyname: None,
            },
            flags,
            label: None,
        };
        self.policies.push(entry);
    }

    pub fn hook_policy_callback(
        &mut self,
        policy_name: &str,
        callback_name: &str,
        callback_addr: u64,
    ) {
        if let Some(policy) = self.policies.iter_mut().find(|p| p.name == policy_name) {
            match callback_name {
                "mpo_vnode_check_access" => policy.ops.mpo_vnode_check_access = Some(callback_addr),
                "mpo_vnode_check_chdir" => policy.ops.mpo_vnode_check_chdir = Some(callback_addr),
                "mpo_vnode_check_chroot" => policy.ops.mpo_vnode_check_chroot = Some(callback_addr),
                "mpo_vnode_check_create" => policy.ops.mpo_vnode_check_create = Some(callback_addr),
                "mpo_vnode_check_delete" => policy.ops.mpo_vnode_check_delete = Some(callback_addr),
                "mpo_vnode_check_exec" => policy.ops.mpo_vnode_check_exec = Some(callback_addr),
                "mpo_vnode_check_link" => policy.ops.mpo_vnode_check_link = Some(callback_addr),
                "mpo_vnode_check_lookup" => policy.ops.mpo_vnode_check_lookup = Some(callback_addr),
                "mpo_vnode_check_open" => policy.ops.mpo_vnode_check_open = Some(callback_addr),
                "mpo_vnode_check_readlink" => {
                    policy.ops.mpo_vnode_check_readlink = Some(callback_addr)
                }
                "mpo_vnode_check_rename_from" => {
                    policy.ops.mpo_vnode_check_rename_from = Some(callback_addr)
                }
                "mpo_vnode_check_rename_to" => {
                    policy.ops.mpo_vnode_check_rename_to = Some(callback_addr)
                }
                "mpo_vnode_check_revoke" => policy.ops.mpo_vnode_check_revoke = Some(callback_addr),
                "mpo_vnode_check_stat" => policy.ops.mpo_vnode_check_stat = Some(callback_addr),
                "mpo_vnode_check_unlink" => policy.ops.mpo_vnode_check_unlink = Some(callback_addr),
                "mpo_proc_check_fork" => policy.ops.mpo_proc_check_fork = Some(callback_addr),
                "mpo_proc_check_signal" => policy.ops.mpo_proc_check_signal = Some(callback_addr),
                "mpo_proc_check_wait" => policy.ops.mpo_proc_check_wait = Some(callback_addr),
                "mpo_file_check_mmap" => policy.ops.mpo_file_check_mmap = Some(callback_addr),
                "mpo_file_check_mmap_downgrade" => {
                    policy.ops.mpo_file_check_mmap_downgrade = Some(callback_addr)
                }
                "mpo_file_check_mmap_protect" => {
                    policy.ops.mpo_file_check_mmap_protect = Some(callback_addr)
                }
                "mpo_socket_check_bind" => policy.ops.mpo_socket_check_bind = Some(callback_addr),
                "mpo_socket_check_connect" => {
                    policy.ops.mpo_socket_check_connect = Some(callback_addr)
                }
                "mpo_socket_check_create" => {
                    policy.ops.mpo_socket_check_create = Some(callback_addr)
                }
                "mpo_socket_check_deliver" => {
                    policy.ops.mpo_socket_check_deliver = Some(callback_addr)
                }
                "mpo_socket_check_listen" => {
                    policy.ops.mpo_socket_check_listen = Some(callback_addr)
                }
                "mpo_socket_check_receive" => {
                    policy.ops.mpo_socket_check_receive = Some(callback_addr)
                }
                "mpo_socket_check_send" => policy.ops.mpo_socket_check_send = Some(callback_addr),
                "mpo_system_check_sysctlbyname" => {
                    policy.ops.mpo_system_check_sysctlbyname = Some(callback_addr)
                }
                _ => {}
            }
        }
    }

    pub fn trigger_vnode_check(
        &self,
        emulator: &mut dyn Emulator,
        policy_name: &str,
        check_name: &str,
        cred: u64,
        vnode: u64,
        label: u64,
        access_mode: u32,
    ) -> Result<i64, MacOsError> {
        if let Some(policy) = self.policies.iter().find(|p| p.name == policy_name) {
            let callback_addr = match check_name {
                "access" => policy.ops.mpo_vnode_check_access,
                "chdir" => policy.ops.mpo_vnode_check_chdir,
                "chroot" => policy.ops.mpo_vnode_check_chroot,
                "create" => policy.ops.mpo_vnode_check_create,
                "delete" => policy.ops.mpo_vnode_check_delete,
                "exec" => policy.ops.mpo_vnode_check_exec,
                "link" => policy.ops.mpo_vnode_check_link,
                "lookup" => policy.ops.mpo_vnode_check_lookup,
                "open" => policy.ops.mpo_vnode_check_open,
                "readlink" => policy.ops.mpo_vnode_check_readlink,
                "rename_from" => policy.ops.mpo_vnode_check_rename_from,
                "rename_to" => policy.ops.mpo_vnode_check_rename_to,
                "revoke" => policy.ops.mpo_vnode_check_revoke,
                "stat" => policy.ops.mpo_vnode_check_stat,
                "unlink" => policy.ops.mpo_vnode_check_unlink,
                _ => None,
            };

            if let Some(addr) = callback_addr {
                emulator.write_reg("rdi", cred)?;
                emulator.write_reg("rsi", vnode)?;
                emulator.write_reg("rdx", label)?;
                emulator.write_reg("rcx", access_mode as u64)?;

                emulator.run(addr, None)?;
                let result = emulator.read_reg("rax")?;
                emulator.log(
                    LogLevel::Debug,
                    &format!("Policy {}::{} returned {}", policy_name, check_name, result),
                );
                return Ok(result as i64);
            }
        }
        Ok(0)
    }

    pub fn trigger_proc_check(
        &self,
        emulator: &mut dyn Emulator,
        policy_name: &str,
        check_name: &str,
        cred: u64,
        proc: u64,
    ) -> Result<i64, MacOsError> {
        if let Some(policy) = self.policies.iter().find(|p| p.name == policy_name) {
            let callback_addr = match check_name {
                "fork" => policy.ops.mpo_proc_check_fork,
                "signal" => policy.ops.mpo_proc_check_signal,
                "wait" => policy.ops.mpo_proc_check_wait,
                _ => None,
            };

            if let Some(addr) = callback_addr {
                emulator.write_reg("rdi", cred)?;
                emulator.write_reg("rsi", proc)?;

                emulator.run(addr, None)?;
                return Ok(emulator.read_reg("rax")? as i64);
            }
        }
        Ok(0)
    }

    pub fn trigger_socket_check(
        &self,
        emulator: &mut dyn Emulator,
        policy_name: &str,
        check_name: &str,
        cred: u64,
        socket: u64,
        address: u64,
    ) -> Result<i64, MacOsError> {
        if let Some(policy) = self.policies.iter().find(|p| p.name == policy_name) {
            let callback_addr = match check_name {
                "bind" => policy.ops.mpo_socket_check_bind,
                "connect" => policy.ops.mpo_socket_check_connect,
                "create" => policy.ops.mpo_socket_check_create,
                "deliver" => policy.ops.mpo_socket_check_deliver,
                "listen" => policy.ops.mpo_socket_check_listen,
                "receive" => policy.ops.mpo_socket_check_receive,
                "send" => policy.ops.mpo_socket_check_send,
                _ => None,
            };

            if let Some(addr) = callback_addr {
                emulator.write_reg("rdi", cred)?;
                emulator.write_reg("rsi", socket)?;
                emulator.write_reg("rdx", address)?;

                emulator.run(addr, None)?;
                return Ok(emulator.read_reg("rax")? as i64);
            }
        }
        Ok(0)
    }

    #[allow(dead_code)]
    pub(crate) fn get_policies(&self) -> &[PolicyEntry] {
        &self.policies
    }

    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }
}
