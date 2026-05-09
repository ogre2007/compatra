//! Synthetic arm64 runtime state used by the no-dyld runner.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use crate::macos::guest_files::{
    fstat_guest_file as shared_fstat_guest_file,
    open_guest_path_with_flags as shared_open_guest_path_with_flags,
    read_guest_directory_entry as shared_read_guest_directory_entry,
    read_guest_file as shared_read_guest_file, stat_guest_path as shared_stat_guest_path,
    GuestDirectoryEntry, GuestFileTable, GuestOpenTarget,
};
use crate::{Emulator, UnicornEmulator};

pub const ARM64_SYNTHETIC_THREAD_STACK_BASE: u64 = 0x3300_0000;
pub const ARM64_SYNTHETIC_THREAD_STACK_SIZE: u64 = 0x20_000;
pub const MAX_SYNTHETIC_THREADS: u64 = 6;

#[derive(Clone, Debug)]
pub struct Arm64ThreadContext {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
}

#[derive(Clone, Debug)]
pub struct PendingArm64Thread {
    pub thread_id: u64,
    pub entry: u64,
    pub arg: u64,
    pub stack_top: u64,
    pub exit_pc: u64,
    pub resume: Option<Arm64ThreadContext>,
}

#[derive(Clone, Debug)]
pub struct ActiveArm64Thread {
    pub thread_id: u64,
    pub parent_thread_id: u64,
    pub parent: Arm64ThreadContext,
}

#[derive(Clone, Debug)]
pub struct ForkParentResume {
    pub parent_tid: u64,
    pub child_pid: u64,
    pub context: Arm64ThreadContext,
}

#[derive(Clone, Debug)]
pub struct WaitingArm64Thread {
    pub thread_id: u64,
    pub mutex: u64,
    pub pending: PendingArm64Thread,
}

#[derive(Clone, Debug)]
pub struct SyntheticProcess {
    pub pid: u64,
    pub parent_pid: u64,
    pub exit_status: i32,
    pub running: bool,
    pub reaped: bool,
    pub exec_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SyntheticPipe {
    pub read_fd: u64,
    pub write_fd: u64,
    pub buffer: VecDeque<u8>,
    pub read_open: bool,
    pub write_open: bool,
    pub capture_label: Option<String>,
    pub capture_consumer_pid: Option<u64>,
    pub captured_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntheticFdTarget {
    PipeRead(u64),
    PipeWrite(u64),
    File(u64),
    Directory(u64),
}

#[derive(Clone, Debug)]
pub struct SyntheticKeventRegistration {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: i64,
    pub udata: u64,
}

#[derive(Debug, Default)]
pub struct Arm64SyntheticOsRuntime {
    pub next_process_id: u64,
    pub next_fd: u64,
    pub next_dir_stream: u64,
    pub next_kqueue_fd: u64,
    pub guest_fs_base: PathBuf,
    pub processes: HashMap<u64, SyntheticProcess>,
    pub process_thread_ids: HashSet<u64>,
    pub thread_processes: HashMap<u64, u64>,
    pub process_fds: HashMap<u64, HashSet<u64>>,
    pub fd_flags: HashMap<u64, u64>,
    pub process_fd_targets: HashMap<(u64, u64), SyntheticFdTarget>,
    pub process_dir_streams: HashMap<(u64, u64), u64>,
    pub fd_targets: HashMap<u64, SyntheticFdTarget>,
    pub pipes: HashMap<u64, SyntheticPipe>,
    pub guest_files: GuestFileTable,
    pub last_pipe_reads: HashMap<(u64, u64), VecDeque<Vec<u8>>>,
    pub pipe_empty_eof_reads: HashMap<(u64, u64, u64), u64>,
    pub kqueues: HashMap<u64, Vec<SyntheticKeventRegistration>>,
}

fn synthetic_target_ref_exists(
    os: &Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
    target: SyntheticFdTarget,
) -> bool {
    has_pipe_endpoint_ref(os, pid, fd, &target)
}

pub fn open_guest_file(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    raw_path: &str,
) -> Result<(u64, PathBuf), u32> {
    open_guest_file_with_flags(os, pid, raw_path, 0)
}

pub fn open_guest_file_with_flags(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    raw_path: &str,
    flags: u64,
) -> Result<(u64, PathBuf), u32> {
    let fd = os.next_fd.max(3);
    os.next_fd = fd.saturating_add(1);
    let (target, resolved) =
        shared_open_guest_path_with_flags(&mut os.guest_files, pid, fd, raw_path, flags)?;
    let fd_target = match target {
        GuestOpenTarget::File(file_id) => SyntheticFdTarget::File(file_id),
        GuestOpenTarget::Directory(dir_id) => SyntheticFdTarget::Directory(dir_id),
    };
    bind_process_fd_target(os, pid, fd, fd_target);
    Ok((fd, resolved))
}

pub fn read_guest_file(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
    count: usize,
) -> Option<(Vec<u8>, bool)> {
    let SyntheticFdTarget::File(file_id) = resolve_process_fd_target(os, pid, fd)? else {
        return None;
    };
    shared_read_guest_file(&mut os.guest_files, pid, fd, file_id, count)
}

pub fn stat_guest_path(
    os: &Arm64SyntheticOsRuntime,
    raw_path: &str,
) -> Result<(u64, PathBuf), u32> {
    shared_stat_guest_path(&os.guest_files, raw_path)
}

pub fn fstat_guest_file(os: &Arm64SyntheticOsRuntime, pid: u64, fd: u64) -> Result<u64, u32> {
    match resolve_process_fd_target(os, pid, fd) {
        Some(SyntheticFdTarget::File(file_id)) => shared_fstat_guest_file(&os.guest_files, file_id),
        Some(SyntheticFdTarget::Directory(_)) => Ok(0),
        _ => Err(9),
    }
}

pub fn read_guest_directory_entry(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
) -> Option<GuestDirectoryEntry> {
    let SyntheticFdTarget::Directory(dir_id) = resolve_process_fd_target(os, pid, fd)? else {
        return None;
    };
    shared_read_guest_directory_entry(&mut os.guest_files, pid, fd, dir_id)
}

pub fn open_directory_stream(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
) -> Result<u64, u32> {
    match resolve_process_fd_target(os, pid, fd) {
        Some(SyntheticFdTarget::Directory(_)) => {
            let dir_stream = os.next_dir_stream.max(0x4000_0000);
            os.next_dir_stream = dir_stream.saturating_add(0x100);
            os.process_dir_streams.insert((pid, dir_stream), fd);
            Ok(dir_stream)
        }
        Some(_) => Err(20),
        None => Err(9),
    }
}

pub fn resolve_directory_stream_fd(
    os: &Arm64SyntheticOsRuntime,
    pid: u64,
    dir_stream: u64,
) -> Option<u64> {
    os.process_dir_streams.get(&(pid, dir_stream)).copied()
}

pub fn close_directory_stream(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    dir_stream: u64,
) -> Result<u64, u32> {
    let Some(fd) = os.process_dir_streams.remove(&(pid, dir_stream)) else {
        return Err(9);
    };
    let _ = close_synthetic_fd(os, pid, fd);
    Ok(fd)
}

#[derive(Debug, Default)]
pub struct Arm64ThreadRuntime {
    pub next_thread_id: u64,
    pub current_thread_id: u64,
    pub next_stack_base: u64,
    pub pending_threads: VecDeque<PendingArm64Thread>,
    pub active_thread: Option<ActiveArm64Thread>,
    pub cond_wait_streaks: HashMap<(u64, u64), u32>,
    pub cond_signal_counts: HashMap<u64, u32>,
    pub mutex_owners: HashMap<u64, u64>,
    pub cond_waiters: HashMap<u64, VecDeque<WaitingArm64Thread>>,
    pub fork_parent_resumes: HashMap<u64, ForkParentResume>,
}

pub fn register_process_fd(os: &mut Arm64SyntheticOsRuntime, pid: u64, fd: u64) {
    os.process_fds.entry(pid).or_default().insert(fd);
}

pub fn bind_process_fd_target(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
    target: SyntheticFdTarget,
) {
    register_process_fd(os, pid, fd);
    os.process_fd_targets.insert((pid, fd), target);
}

pub fn resolve_process_fd_target(
    os: &Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
) -> Option<SyntheticFdTarget> {
    os.process_fd_targets
        .get(&(pid, fd))
        .cloned()
        .or_else(|| os.fd_targets.get(&fd).cloned())
}

pub fn duplicate_synthetic_fd(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
    min_fd: u64,
) -> Result<u64, u32> {
    let target = resolve_process_fd_target(os, pid, fd).ok_or(9u32)?;
    let mut new_fd = os.next_fd.max(min_fd).max(3);
    while os.process_fd_targets.contains_key(&(pid, new_fd)) || os.fd_targets.contains_key(&new_fd)
    {
        new_fd = new_fd.saturating_add(1);
    }
    os.next_fd = new_fd.saturating_add(1);
    bind_process_fd_target(os, pid, new_fd, target.clone());
    if let Some(flags) = os.fd_flags.get(&fd).copied() {
        os.fd_flags.insert(new_fd, flags);
    }
    match target {
        SyntheticFdTarget::File(_) => {
            let offset = os
                .guest_files
                .file_offsets
                .get(&(pid, fd))
                .copied()
                .unwrap_or(0);
            os.guest_files.file_offsets.insert((pid, new_fd), offset);
        }
        SyntheticFdTarget::Directory(_) => {
            let offset = os
                .guest_files
                .directory_offsets
                .get(&(pid, fd))
                .copied()
                .unwrap_or(0);
            os.guest_files
                .directory_offsets
                .insert((pid, new_fd), offset);
        }
        SyntheticFdTarget::PipeRead(_) | SyntheticFdTarget::PipeWrite(_) => {}
    }
    Ok(new_fd)
}

pub fn has_pipe_endpoint_ref(
    os: &Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
    target: &SyntheticFdTarget,
) -> bool {
    os.process_fd_targets
        .iter()
        .any(|((other_pid, other_fd), other_target)| {
            !(*other_pid == pid && *other_fd == fd) && other_target == target
        })
        || os
            .fd_targets
            .iter()
            .any(|(other_fd, other_target)| *other_fd != fd && other_target == target)
}

pub fn close_synthetic_fd(
    os: &mut Arm64SyntheticOsRuntime,
    pid: u64,
    fd: u64,
) -> Option<SyntheticPipe> {
    os.fd_flags.remove(&fd);
    os.process_fds.entry(pid).or_default().remove(&fd);
    let target = os.process_fd_targets.remove(&(pid, fd));
    os.fd_targets.remove(&fd);
    match target {
        Some(SyntheticFdTarget::PipeRead(pipe_id)) => {
            let target = SyntheticFdTarget::PipeRead(pipe_id);
            let still_open = has_pipe_endpoint_ref(os, pid, fd, &target);
            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                if !still_open {
                    pipe.read_open = false;
                    pipe.read_fd = fd;
                }
                if !pipe.read_open && !pipe.write_open {
                    return os.pipes.remove(&pipe_id);
                }
            }
            None
        }
        Some(SyntheticFdTarget::PipeWrite(pipe_id)) => {
            let target = SyntheticFdTarget::PipeWrite(pipe_id);
            let still_open = has_pipe_endpoint_ref(os, pid, fd, &target);
            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                if !still_open {
                    pipe.write_open = false;
                    pipe.write_fd = fd;
                }
                if !pipe.read_open && !pipe.write_open {
                    return os.pipes.remove(&pipe_id);
                }
            }
            None
        }
        Some(SyntheticFdTarget::File(file_id)) => {
            os.guest_files.file_offsets.remove(&(pid, fd));
            let still_open =
                synthetic_target_ref_exists(os, pid, fd, SyntheticFdTarget::File(file_id));
            if !still_open {
                os.guest_files.files.remove(&file_id);
            }
            None
        }
        Some(SyntheticFdTarget::Directory(dir_id)) => {
            os.guest_files.directory_offsets.remove(&(pid, fd));
            let still_open =
                synthetic_target_ref_exists(os, pid, fd, SyntheticFdTarget::Directory(dir_id));
            if !still_open {
                os.guest_files.directories.remove(&dir_id);
            }
            None
        }
        None => None,
    }
}

pub fn terminate_synthetic_process(os: &mut Arm64SyntheticOsRuntime, pid: u64, exit_status: i32) {
    if let Some(proc_state) = os.processes.get_mut(&pid) {
        proc_state.running = false;
        proc_state.exit_status = exit_status;
    }
    os.process_dir_streams
        .retain(|(stream_pid, _), _| *stream_pid != pid);
    let fds: Vec<u64> = os
        .process_fds
        .get(&pid)
        .map(|fds| fds.iter().copied().collect())
        .unwrap_or_default();
    for fd in fds {
        let _ = close_synthetic_fd(os, pid, fd);
    }
}

pub fn save_arm64_context(emu: &mut UnicornEmulator) -> Arm64ThreadContext {
    let mut x = [0u64; 29];
    for (idx, slot) in x.iter_mut().enumerate() {
        *slot = emu.read_reg(&format!("x{}", idx)).unwrap_or(0);
    }
    Arm64ThreadContext {
        x,
        fp: emu.read_reg("fp").unwrap_or(0),
        lr: emu.read_reg("lr").unwrap_or(0),
        sp: emu.read_reg("sp").unwrap_or(0),
        pc: emu.read_reg("pc").unwrap_or(0),
    }
}

pub fn restore_arm64_context(
    emu: &mut UnicornEmulator,
    ctx: &Arm64ThreadContext,
    x0: u64,
    pc: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for (idx, value) in ctx.x.iter().enumerate() {
        emu.write_reg(&format!("x{}", idx), *value)?;
    }
    emu.write_reg("x0", x0)?;
    emu.write_reg("fp", ctx.fp)?;
    emu.write_reg("lr", ctx.lr)?;
    emu.write_reg("sp", ctx.sp)?;
    emu.write_reg("pc", pc)?;
    Ok(())
}

pub fn dispatch_pending_arm64_thread(
    emu: &mut UnicornEmulator,
    runtime: &mut Arm64ThreadRuntime,
) -> Result<bool, Box<dyn std::error::Error>> {
    if runtime.active_thread.is_some() {
        return Ok(false);
    }
    let Some(next) = runtime.pending_threads.pop_front() else {
        return Ok(false);
    };

    let parent = save_arm64_context(emu);
    let parent_thread_id = if runtime.current_thread_id == 0 {
        runtime.current_thread_id = 1;
        1
    } else {
        runtime.current_thread_id
    };
    runtime.current_thread_id = next.thread_id;
    runtime.active_thread = Some(ActiveArm64Thread {
        thread_id: next.thread_id,
        parent_thread_id,
        parent,
    });

    if let Some(ctx) = next.resume.as_ref() {
        restore_arm64_context(emu, ctx, ctx.x[0], ctx.pc)?;
    } else {
        emu.write_reg("x0", next.arg)?;
        emu.write_reg("sp", next.stack_top)?;
        emu.write_reg("fp", 0)?;
        emu.write_reg("lr", next.exit_pc)?;
        emu.write_reg("pc", next.entry)?;
    }
    Ok(true)
}

pub fn dispatch_pending_arm64_thread_by_id(
    emu: &mut UnicornEmulator,
    runtime: &mut Arm64ThreadRuntime,
    thread_id: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    if runtime.active_thread.is_some() {
        return Ok(false);
    }
    let Some(index) = runtime
        .pending_threads
        .iter()
        .position(|thread| thread.thread_id == thread_id)
    else {
        return Ok(false);
    };
    let Some(next) = runtime.pending_threads.remove(index) else {
        return Ok(false);
    };

    let parent = save_arm64_context(emu);
    let parent_thread_id = runtime.current_thread_id.max(1);
    runtime.current_thread_id = next.thread_id;
    runtime.active_thread = Some(ActiveArm64Thread {
        thread_id: next.thread_id,
        parent_thread_id,
        parent,
    });

    if let Some(ctx) = next.resume.as_ref() {
        restore_arm64_context(emu, ctx, ctx.x[0], ctx.pc)?;
    } else {
        emu.write_reg("x0", next.arg)?;
        emu.write_reg("sp", next.stack_top)?;
        emu.write_reg("fp", 0)?;
        emu.write_reg("lr", next.exit_pc)?;
        emu.write_reg("pc", next.entry)?;
    }
    Ok(true)
}

pub fn yield_active_arm64_thread(
    emu: &mut UnicornEmulator,
    runtime: &mut Arm64ThreadRuntime,
    x0: u64,
    pc: u64,
) -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    if runtime.pending_threads.is_empty() {
        return Ok(None);
    }
    let Some(active) = runtime.active_thread.take() else {
        return Ok(None);
    };

    let mut resume_ctx = save_arm64_context(emu);
    resume_ctx.x[0] = x0;
    resume_ctx.pc = pc;
    runtime.pending_threads.push_back(PendingArm64Thread {
        thread_id: active.thread_id,
        entry: 0,
        arg: 0,
        stack_top: 0,
        exit_pc: 0,
        resume: Some(resume_ctx),
    });

    let Some(next) = runtime.pending_threads.pop_front() else {
        runtime.active_thread = Some(active);
        return Ok(None);
    };

    let from_thread_id = active.thread_id;
    let parent_thread_id = active.parent_thread_id;
    let parent = active.parent;
    runtime.current_thread_id = next.thread_id;
    runtime.active_thread = Some(ActiveArm64Thread {
        thread_id: next.thread_id,
        parent_thread_id,
        parent,
    });

    if let Some(ctx) = next.resume.as_ref() {
        restore_arm64_context(emu, ctx, ctx.x[0], ctx.pc)?;
    } else {
        emu.write_reg("x0", next.arg)?;
        emu.write_reg("sp", next.stack_top)?;
        emu.write_reg("fp", 0)?;
        emu.write_reg("lr", next.exit_pc)?;
        emu.write_reg("pc", next.entry)?;
    }
    Ok(Some((from_thread_id, next.thread_id)))
}

pub fn block_active_arm64_thread_on_cond(
    emu: &mut UnicornEmulator,
    runtime: &mut Arm64ThreadRuntime,
    cond: u64,
    mutex: u64,
    x0: u64,
    pc: u64,
) -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    let Some(active) = runtime.active_thread.take() else {
        return Ok(None);
    };

    let mut resume_ctx = save_arm64_context(emu);
    resume_ctx.x[0] = x0;
    resume_ctx.pc = pc;
    let blocked_thread_id = active.thread_id;
    let pending = PendingArm64Thread {
        thread_id: active.thread_id,
        entry: 0,
        arg: 0,
        stack_top: 0,
        exit_pc: 0,
        resume: Some(resume_ctx),
    };
    runtime
        .cond_waiters
        .entry(cond)
        .or_default()
        .push_back(WaitingArm64Thread {
            thread_id: blocked_thread_id,
            mutex,
            pending,
        });

    let Some(next) = runtime.pending_threads.pop_front() else {
        runtime.active_thread = Some(active);
        runtime.cond_waiters.entry(cond).or_default().pop_back();
        return Ok(None);
    };

    let parent_thread_id = active.parent_thread_id;
    let parent = active.parent;
    runtime.current_thread_id = next.thread_id;
    runtime.active_thread = Some(ActiveArm64Thread {
        thread_id: next.thread_id,
        parent_thread_id,
        parent,
    });

    if let Some(ctx) = next.resume.as_ref() {
        restore_arm64_context(emu, ctx, ctx.x[0], ctx.pc)?;
    } else {
        emu.write_reg("x0", next.arg)?;
        emu.write_reg("sp", next.stack_top)?;
        emu.write_reg("fp", 0)?;
        emu.write_reg("lr", next.exit_pc)?;
        emu.write_reg("pc", next.entry)?;
    }
    Ok(Some((blocked_thread_id, next.thread_id)))
}

pub fn block_current_arm64_thread_on_cond(
    emu: &mut UnicornEmulator,
    runtime: &mut Arm64ThreadRuntime,
    cond: u64,
    mutex: u64,
    x0: u64,
    pc: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    if runtime.active_thread.is_some() || runtime.pending_threads.is_empty() {
        return Ok(false);
    }

    let thread_id = runtime.current_thread_id.max(1);
    let mut resume_ctx = save_arm64_context(emu);
    resume_ctx.x[0] = x0;
    resume_ctx.pc = pc;
    runtime
        .cond_waiters
        .entry(cond)
        .or_default()
        .push_back(WaitingArm64Thread {
            thread_id,
            mutex,
            pending: PendingArm64Thread {
                thread_id,
                entry: 0,
                arg: 0,
                stack_top: 0,
                exit_pc: 0,
                resume: Some(resume_ctx),
            },
        });

    dispatch_pending_arm64_thread(emu, runtime)
}

pub fn wake_one_arm64_cond_waiter(runtime: &mut Arm64ThreadRuntime) -> Option<(u64, u64)> {
    let cond = runtime
        .cond_waiters
        .iter()
        .find_map(|(cond, queue)| (!queue.is_empty()).then_some(*cond))?;
    let waiter = runtime.cond_waiters.get_mut(&cond)?.pop_front()?;
    if runtime
        .cond_waiters
        .get(&cond)
        .map(|queue| queue.is_empty())
        .unwrap_or(false)
    {
        runtime.cond_waiters.remove(&cond);
    }
    runtime.mutex_owners.insert(waiter.mutex, waiter.thread_id);
    let waiter_tid = waiter.thread_id;
    runtime.pending_threads.push_front(waiter.pending);
    Some((cond, waiter_tid))
}

pub fn wake_arm64_cond_waiters(runtime: &mut Arm64ThreadRuntime, limit: usize) -> Vec<(u64, u64)> {
    let mut woken = Vec::new();
    while woken.len() < limit {
        let Some((cond, tid)) = wake_one_arm64_cond_waiter(runtime) else {
            break;
        };
        woken.push((cond, tid));
    }
    woken
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_runtime() -> Arm64SyntheticOsRuntime {
        Arm64SyntheticOsRuntime {
            guest_files: GuestFileTable::new(std::env::temp_dir().join("machina-runtime-test")),
            ..Default::default()
        }
    }

    #[test]
    fn duplicate_fd_preserves_directory_target() {
        let mut os = os_runtime();
        let (fd, _) = open_guest_file(&mut os, 1, "/Users/analyst/.electrum/wallets/").unwrap();
        let dup_fd = duplicate_synthetic_fd(&mut os, 1, fd, 0).unwrap();

        assert_ne!(fd, dup_fd);
        assert!(matches!(
            resolve_process_fd_target(&os, 1, dup_fd),
            Some(SyntheticFdTarget::Directory(_))
        ));
        assert!(open_directory_stream(&mut os, 1, dup_fd).is_ok());
    }
}
