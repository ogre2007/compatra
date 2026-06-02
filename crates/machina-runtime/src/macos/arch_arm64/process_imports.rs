//! Process lifecycle imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::macos::arm64_compat_memory::allocate_arm64_heap;
use crate::macos::arm64_runner_support::{
    arm64_process_event, emit_arm64_event, record_arm64_import, Arm64ImportTracker,
    Arm64SharedState,
};
use crate::macos::arm64_state::{Arm64ExitHandler, Arm64ExitHandlerKind};
use crate::macos::byte_preview::lossy_data_preview;
use crate::macos::{
    close_synthetic_fd, dispatch_pending_arm64_thread, dispatch_pending_arm64_thread_by_id,
    read_arm64_argv, read_cstring, resolve_process_fd_target, restore_arm64_context,
    save_arm64_context, terminate_synthetic_process, Emulator, ForkParentResume,
    PendingArm64Thread, SharedTraceBus, SyntheticFdTarget, SyntheticPopenStream, SyntheticProcess,
    MAX_SYNTHETIC_THREADS,
};
use crate::UnicornEmulator;

fn vec_u64_le(bytes: Vec<u8>) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn read_popen_stream_bytes(stream: &mut SyntheticPopenStream, byte_count: usize) -> Vec<u8> {
    if byte_count == 0 {
        return Vec::new();
    }
    if stream.offset >= stream.output.len() {
        stream.eof = true;
        return Vec::new();
    }

    let available = stream.output.len() - stream.offset;
    let read_len = available.min(byte_count);
    let data = stream.output[stream.offset..stream.offset + read_len].to_vec();
    stream.offset += read_len;
    if stream.offset >= stream.output.len() {
        stream.eof = true;
    }
    data
}

fn read_popen_stream_line(stream: &mut SyntheticPopenStream, capacity: usize) -> Vec<u8> {
    if capacity <= 1 {
        return Vec::new();
    }
    if stream.offset >= stream.output.len() {
        stream.eof = true;
        return Vec::new();
    }

    let max_payload = capacity - 1;
    let available = &stream.output[stream.offset..];
    let read_len = available
        .iter()
        .take(max_payload)
        .position(|byte| *byte == b'\n')
        .map(|idx| idx + 1)
        .unwrap_or_else(|| available.len().min(max_payload));
    let data = available[..read_len].to_vec();
    stream.offset += read_len;
    if stream.offset >= stream.output.len() {
        stream.eof = true;
    }
    data
}

fn checked_stdio_byte_count(size: u64, nmemb: u64) -> Option<(usize, usize, usize)> {
    if size == 0 || nmemb == 0 {
        return Some((size as usize, nmemb as usize, 0));
    }
    let item_size = usize::try_from(size).ok()?;
    let item_count = usize::try_from(nmemb).ok()?;
    let byte_count = item_size.checked_mul(item_count)?;
    Some((item_size, item_count, byte_count.min(0x10000)))
}

fn install_posix_spawn_hook(
    emulator: &mut UnicornEmulator,
    addr: u64,
    call_name: &'static str,
    errno_ptr: u64,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let os_runtime = shared_state.os_runtime.clone();
    let posix_spawn_file_actions = shared_state.posix_spawn_file_actions.clone();
    let thread_runtime = shared_state.thread_runtime.clone();
    let import_tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let analysis = shared_state.analysis.clone();
    // Per-installation sequence counter so multiple `posix_spawnp`
    // calls from the same parent get distinct dump files.
    let spawn_sequence = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let pid_ptr = emu.read_reg("x0").unwrap_or(0);
            let path_ptr = emu.read_reg("x1").unwrap_or(0);
            let file_actions_ptr = emu.read_reg("x2").unwrap_or(0);
            let attr_ptr = emu.read_reg("x3").unwrap_or(0);
            let argv_ptr = emu.read_reg("x4").unwrap_or(0);
            let envp_ptr = emu.read_reg("x5").unwrap_or(0);
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let argv = if argv_ptr != 0 {
                read_arm64_argv(emu, argv_ptr, 16, 256)
            } else {
                Vec::new()
            };
            let file_actions = posix_spawn_file_actions
                .lock()
                .ok()
                .and_then(|actions| actions.get(&file_actions_ptr).cloned())
                .unwrap_or_default();
            let log_stream = analysis.synthetic_log_stream(&path, &argv);
            let log_stream_messages = log_stream
                .as_ref()
                .map(|stream| stream.messages.clone())
                .unwrap_or_default();
            let synthesize_log_stream = log_stream.is_some();
            let current_tid = thread_runtime
                .lock()
                .ok()
                .map(|rt| rt.current_thread_id.max(1))
                .unwrap_or(1);
            let current_pid = os_runtime
                .lock()
                .ok()
                .and_then(|os| os.thread_processes.get(&current_tid).copied())
                .unwrap_or(1);
            let (child_pid, result, errno) = {
                let mut os = match os_runtime.lock() {
                    Ok(os) => os,
                    Err(_) => return,
                };
                let pid = os.next_process_id.max(2);
                os.next_process_id = pid.saturating_add(1);
                os.processes.insert(
                    pid,
                    SyntheticProcess {
                        pid,
                        parent_pid: current_pid,
                        exit_status: 0,
                        running: false,
                        reaped: false,
                        exec_path: Some(path.clone()),
                    },
                );
                if let Some(log_stream) = &log_stream {
                    for (fd, newfd) in &file_actions {
                        if *newfd != 1 && *newfd != 2 {
                            continue;
                        }
                        if let Some(SyntheticFdTarget::PipeWrite(pipe_id)) =
                            resolve_process_fd_target(&os, current_pid, *fd)
                        {
                            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                                pipe.buffer.extend(log_stream.output.iter().copied());
                                pipe.write_open = false;
                            }
                        }
                    }
                }
                (pid, 0u64, 0u32)
            };
            if pid_ptr != 0 {
                let _ = emu.write_memory(pid_ptr, &(child_pid as u32).to_le_bytes());
            }
            let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_arm64_import(
                &import_tracker,
                format!(
                    "{}(pid=0x{:X}, path={:?}, argv={:?}, file_actions=0x{:X}, dup2={:?}, attr=0x{:X}, envp=0x{:X}) -> result={} child_pid={} synthetic_log_stream={}",
                    call_name, pid_ptr, path, argv, file_actions_ptr, file_actions, attr_ptr, envp_ptr, result, child_pid, synthesize_log_stream
                ),
            );
            let sequence = spawn_sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dump_path = analysis.write_posix_spawn_argv_capture(
                current_pid,
                child_pid,
                sequence,
                &path,
                &argv,
                envp_ptr,
            );
            if let Some(dump_path) = &dump_path {
                println!(
                    "[CAPTURE][arm64] posix-spawn argv pid={} tid={} child_pid={} seq={} path={} dump={}",
                    current_pid,
                    current_tid,
                    child_pid,
                    sequence,
                    path,
                    dump_path.display()
                );
            }
            let mut event = arm64_process_event(current_pid, current_tid, call_name, call_name)
                .arg("PidPtr", format!("0x{:X}", pid_ptr))
                .arg("ChildPid", child_pid.to_string())
                .arg("Path", path)
                .arg("Argv", format!("{:?}", argv))
                .arg("FileActions", format!("0x{:X}", file_actions_ptr))
                .arg("Dup2", format!("{:?}", file_actions))
                .arg("Attr", format!("0x{:X}", attr_ptr))
                .arg("Envp", format!("0x{:X}", envp_ptr))
                .arg("SyntheticLogStream", synthesize_log_stream.to_string())
                .arg("SyntheticLogMessages", format!("{:?}", log_stream_messages))
                .arg("Errno", errno.to_string())
                .arg("Result", result.to_string())
                .arg("ArgvDumpSeq", sequence.to_string());
            if let Some(dump_path) = dump_path {
                event = event.arg("ArgvDumpFile", dump_path.display().to_string());
            }
            emit_arm64_event(&trace_bus_for_hook, event);
        },
    )?;
    Ok(())
}

fn install_posix_spawn_file_action_hooks(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_init") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.insert(actions_ptr, Vec::new());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_init(actions=0x{:X}) -> 0",
                        actions_ptr
                    ),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_adddup2") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                let fd = emu.read_reg("x1").unwrap_or(0);
                let newfd = emu.read_reg("x2").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.entry(actions_ptr).or_default().push((fd, newfd));
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_adddup2(actions=0x{:X}, fd={}, newfd={}) -> 0",
                        actions_ptr, fd, newfd
                    ),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_destroy") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.remove(&actions_ptr);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_destroy(actions=0x{:X}) -> 0",
                        actions_ptr
                    ),
                );
            },
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn popen_stream(output: &[u8]) -> SyntheticPopenStream {
        SyntheticPopenStream {
            command: "test".to_string(),
            mode: "r".to_string(),
            label: Some("test-output".to_string()),
            output: output.to_vec(),
            offset: 0,
            eof: output.is_empty(),
            error: false,
        }
    }

    #[test]
    fn popen_line_reader_keeps_newlines_and_nul_capacity() {
        let mut stream = popen_stream(b"Darwin\narm64\n");

        let first = read_popen_stream_line(&mut stream, 8);
        assert_eq!(first, b"Darwin\n");
        assert_eq!(stream.offset, 7);
        assert!(!stream.eof);

        let second = read_popen_stream_line(&mut stream, 6);
        assert_eq!(second, b"arm64");
        assert_eq!(stream.offset, 12);
        assert!(!stream.eof);

        let third = read_popen_stream_line(&mut stream, 6);
        assert_eq!(third, b"\n");
        assert!(stream.eof);

        let eof = read_popen_stream_line(&mut stream, 6);
        assert!(eof.is_empty());
        assert!(stream.eof);
    }

    #[test]
    fn popen_byte_reader_reports_eof_after_last_byte() {
        let mut stream = popen_stream(b"abcdef");

        assert_eq!(read_popen_stream_bytes(&mut stream, 2), b"ab");
        assert_eq!(stream.offset, 2);
        assert!(!stream.eof);

        assert_eq!(read_popen_stream_bytes(&mut stream, 10), b"cdef");
        assert_eq!(stream.offset, 6);
        assert!(stream.eof);

        assert!(read_popen_stream_bytes(&mut stream, 1).is_empty());
        assert!(stream.eof);
    }

    #[test]
    fn stdio_byte_count_rejects_overflow() {
        assert_eq!(checked_stdio_byte_count(1, 4), Some((1, 4, 4)));
        assert_eq!(checked_stdio_byte_count(0, 4), Some((0, 4, 0)));
        assert!(checked_stdio_byte_count(u64::MAX, 2).is_none());
    }
}

pub fn install_arm64_process_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    done_addr: u64,
    errno_ptr: u64,
    trace_bus: &Option<SharedTraceBus>,
    saw_exit: &Arc<AtomicBool>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let analysis = shared_state.analysis.clone();
    install_posix_spawn_file_action_hooks(emulator, stub_map, shared_state, import_tracker)?;

    if let Some(&addr) = stub_map.get("_popen") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let analysis_for_hook = analysis.clone();
        let malloc_next_addr = shared_state.malloc_next_addr.clone();
        let malloc_mapped_until = shared_state.malloc_mapped_until.clone();
        let malloc_allocations = shared_state.malloc_allocations.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let command_ptr = emu.read_reg("x0").unwrap_or(0);
                let mode_ptr = emu.read_reg("x1").unwrap_or(0);
                let command = read_cstring(emu, command_ptr, 4096).unwrap_or_default();
                let mode = read_cstring(emu, mode_ptr, 32).unwrap_or_default();
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                let result = allocate_arm64_heap(
                    emu,
                    &malloc_next_addr,
                    &malloc_mapped_until,
                    &malloc_allocations,
                    0x100,
                    0x10,
                )
                .map(|(addr, _)| addr)
                .unwrap_or(0);
                let synthetic_output = analysis_for_hook.synthetic_popen_output(&command);
                let synthetic_label = synthetic_output.as_ref().map(|output| output.label.clone());
                let output = synthetic_output
                    .as_ref()
                    .map(|output| output.output.clone())
                    .unwrap_or_default();
                let output_len = output.len();
                if result != 0 {
                    if let Ok(mut os) = os_runtime.lock() {
                        os.popen_streams.insert(
                            result,
                            SyntheticPopenStream {
                                command: command.clone(),
                                mode: mode.clone(),
                                label: synthetic_label.clone(),
                                output,
                                offset: 0,
                                eof: output_len == 0,
                                error: false,
                            },
                        );
                    }
                }
                let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_popen(command={:?}, mode={:?}) -> 0x{:X} synthetic_label={:?} output_bytes={}",
                        command, mode, result, synthetic_label, output_len
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "popen", "popen")
                    .arg("CommandPtr", format!("0x{:X}", command_ptr))
                    .arg("ModePtr", format!("0x{:X}", mode_ptr))
                    .arg("Command", command)
                    .arg("Mode", mode)
                    .arg("SyntheticOutput", synthetic_label.is_some().to_string())
                    .arg("SyntheticLabel", synthetic_label.unwrap_or_default())
                    .arg("OutputBytes", output_len.to_string())
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", "0");
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pclose") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let stream = emu.read_reg("x0").unwrap_or(0);
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                let removed = os_runtime
                    .lock()
                    .ok()
                    .and_then(|mut os| os.popen_streams.remove(&stream));
                let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pclose(stream=0x{:X}) -> 0 synthetic={}",
                        stream,
                        removed.is_some()
                    ),
                );
                let mut event = arm64_process_event(current_pid, current_tid, "pclose", "pclose")
                    .arg("Stream", format!("0x{:X}", stream))
                    .arg("SyntheticPopen", removed.is_some().to_string())
                    .arg("Result", "0")
                    .arg("Errno", "0");
                if let Some(stream_state) = removed {
                    event = event
                        .arg("Command", stream_state.command)
                        .arg("Mode", stream_state.mode)
                        .arg("Offset", stream_state.offset.to_string())
                        .arg("OutputBytes", stream_state.output.len().to_string())
                        .arg("SyntheticLabel", stream_state.label.unwrap_or_default());
                }
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if analysis.is_enabled() {
        if let Some(&addr) = stub_map.get("_fgets") {
            let os_runtime = shared_state.os_runtime.clone();
            let thread_runtime = shared_state.thread_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let buf_ptr = emu.read_reg("x0").unwrap_or(0);
                let size_raw = emu.read_reg("x1").unwrap_or(0);
                let stream = emu.read_reg("x2").unwrap_or(0);
                let size = size_raw as i32;
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);

                let (synthetic, data, eof, label, offset) = if buf_ptr == 0 || size <= 0 {
                    (false, Vec::new(), false, None, 0usize)
                } else {
                    os_runtime
                        .lock()
                        .ok()
                        .and_then(|mut os| {
                            let stream_state = os.popen_streams.get_mut(&stream)?;
                            let data = read_popen_stream_line(stream_state, size as usize);
                            Some((
                                true,
                                data,
                                stream_state.eof,
                                stream_state.label.clone(),
                                stream_state.offset,
                            ))
                        })
                        .unwrap_or((false, Vec::new(), false, None, 0usize))
                };

                let mut errno = 0u32;
                let result = if synthetic && !data.is_empty() {
                    let mut c_string = data.clone();
                    c_string.push(0);
                    match emu.write_memory(buf_ptr, &c_string) {
                        Ok(()) => buf_ptr,
                        Err(_) => {
                            errno = 14;
                            0
                        }
                    }
                } else {
                    0
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }

                let preview = lossy_data_preview(&data, 128);
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_fgets(buf=0x{:X}, size={}, stream=0x{:X}) -> 0x{:X} synthetic={} bytes={} eof={} label={:?}",
                        buf_ptr,
                        size,
                        stream,
                        result,
                        synthetic,
                        data.len(),
                        eof,
                        label
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "fgets", "fgets")
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Size", size.to_string())
                    .arg("Stream", format!("0x{:X}", stream))
                    .arg("SyntheticPopen", synthetic.to_string())
                    .arg("SyntheticLabel", label.unwrap_or_default())
                    .arg("Bytes", data.len().to_string())
                    .arg("Offset", offset.to_string())
                    .arg("Eof", eof.to_string())
                    .arg("Preview", preview)
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
        }

        if let Some(&addr) = stub_map.get("_fread") {
            let os_runtime = shared_state.os_runtime.clone();
            let thread_runtime = shared_state.thread_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let buf_ptr = emu.read_reg("x0").unwrap_or(0);
                let size = emu.read_reg("x1").unwrap_or(0);
                let nmemb = emu.read_reg("x2").unwrap_or(0);
                let stream = emu.read_reg("x3").unwrap_or(0);
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);

                let (item_size, _item_count, byte_count) =
                    checked_stdio_byte_count(size, nmemb).unwrap_or((0, 0, 0));
                let (synthetic, data, eof, label, offset) = if buf_ptr == 0 {
                    (false, Vec::new(), false, None, 0usize)
                } else {
                    os_runtime
                        .lock()
                        .ok()
                        .and_then(|mut os| {
                            let stream_state = os.popen_streams.get_mut(&stream)?;
                            let data = read_popen_stream_bytes(stream_state, byte_count);
                            Some((
                                true,
                                data,
                                stream_state.eof,
                                stream_state.label.clone(),
                                stream_state.offset,
                            ))
                        })
                        .unwrap_or((false, Vec::new(), false, None, 0usize))
                };

                let mut errno = 0u32;
                let result_items = if synthetic && !data.is_empty() {
                    match emu.write_memory(buf_ptr, &data) {
                        Ok(()) => {
                            if item_size == 0 {
                                0
                            } else {
                                data.len() / item_size
                            }
                        }
                        Err(_) => {
                            errno = 14;
                            0
                        }
                    }
                } else {
                    0
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result_items as u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }

                let preview = lossy_data_preview(&data, 128);
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_fread(buf=0x{:X}, size={}, nmemb={}, stream=0x{:X}) -> {} synthetic={} bytes={} eof={} label={:?}",
                        buf_ptr,
                        size,
                        nmemb,
                        stream,
                        result_items,
                        synthetic,
                        data.len(),
                        eof,
                        label
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "fread", "fread")
                    .arg("Buf", format!("0x{:X}", buf_ptr))
                    .arg("Size", size.to_string())
                    .arg("Nmemb", nmemb.to_string())
                    .arg("Stream", format!("0x{:X}", stream))
                    .arg("SyntheticPopen", synthetic.to_string())
                    .arg("SyntheticLabel", label.unwrap_or_default())
                    .arg("Bytes", data.len().to_string())
                    .arg("Offset", offset.to_string())
                    .arg("Eof", eof.to_string())
                    .arg("Preview", preview)
                    .arg("Result", result_items.to_string())
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
        }

        if let Some(&addr) = stub_map.get("_feof") {
            let os_runtime = shared_state.os_runtime.clone();
            let thread_runtime = shared_state.thread_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            emulator.add_code_hook(
                addr,
                addr + 4,
                move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                    let stream = emu.read_reg("x0").unwrap_or(0);
                    let current_tid = thread_runtime
                        .lock()
                        .ok()
                        .map(|rt| rt.current_thread_id.max(1))
                        .unwrap_or(1);
                    let current_pid = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| os.thread_processes.get(&current_tid).copied())
                        .unwrap_or(1);
                    let (synthetic, eof, label) = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| {
                            let stream_state = os.popen_streams.get(&stream)?;
                            Some((true, stream_state.eof, stream_state.label.clone()))
                        })
                        .unwrap_or((false, false, None));
                    let result = u64::from(synthetic && eof);
                    let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let _ = emu.write_reg("x0", result);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_feof(stream=0x{:X}) -> {} synthetic={} label={:?}",
                            stream, result, synthetic, label
                        ),
                    );
                    let event = arm64_process_event(current_pid, current_tid, "feof", "feof")
                        .arg("Stream", format!("0x{:X}", stream))
                        .arg("SyntheticPopen", synthetic.to_string())
                        .arg("SyntheticLabel", label.unwrap_or_default())
                        .arg("Result", result.to_string())
                        .arg("Errno", "0");
                    emit_arm64_event(&trace_bus_for_hook, event);
                },
            )?;
        }

        if let Some(&addr) = stub_map.get("_ferror") {
            let os_runtime = shared_state.os_runtime.clone();
            let thread_runtime = shared_state.thread_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            emulator.add_code_hook(
                addr,
                addr + 4,
                move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                    let stream = emu.read_reg("x0").unwrap_or(0);
                    let current_tid = thread_runtime
                        .lock()
                        .ok()
                        .map(|rt| rt.current_thread_id.max(1))
                        .unwrap_or(1);
                    let current_pid = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| os.thread_processes.get(&current_tid).copied())
                        .unwrap_or(1);
                    let (synthetic, error, label) = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| {
                            let stream_state = os.popen_streams.get(&stream)?;
                            Some((true, stream_state.error, stream_state.label.clone()))
                        })
                        .unwrap_or((false, false, None));
                    let result = u64::from(synthetic && error);
                    let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let _ = emu.write_reg("x0", result);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_ferror(stream=0x{:X}) -> {} synthetic={} label={:?}",
                            stream, result, synthetic, label
                        ),
                    );
                    let event = arm64_process_event(current_pid, current_tid, "ferror", "ferror")
                        .arg("Stream", format!("0x{:X}", stream))
                        .arg("SyntheticPopen", synthetic.to_string())
                        .arg("SyntheticLabel", label.unwrap_or_default())
                        .arg("Result", result.to_string())
                        .arg("Errno", "0");
                    emit_arm64_event(&trace_bus_for_hook, event);
                },
            )?;
        }

        if let Some(&addr) = stub_map.get("_clearerr") {
            let os_runtime = shared_state.os_runtime.clone();
            let thread_runtime = shared_state.thread_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            emulator.add_code_hook(
                addr,
                addr + 4,
                move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                    let stream = emu.read_reg("x0").unwrap_or(0);
                    let current_tid = thread_runtime
                        .lock()
                        .ok()
                        .map(|rt| rt.current_thread_id.max(1))
                        .unwrap_or(1);
                    let current_pid = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| os.thread_processes.get(&current_tid).copied())
                        .unwrap_or(1);
                    let (synthetic, label) = os_runtime
                        .lock()
                        .ok()
                        .and_then(|mut os| {
                            let stream_state = os.popen_streams.get_mut(&stream)?;
                            stream_state.eof = false;
                            stream_state.error = false;
                            Some((true, stream_state.label.clone()))
                        })
                        .unwrap_or((false, None));
                    let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let _ = emu.write_reg("x0", 0u64);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_clearerr(stream=0x{:X}) synthetic={} label={:?}",
                            stream, synthetic, label
                        ),
                    );
                    let event =
                        arm64_process_event(current_pid, current_tid, "clearerr", "clearerr")
                            .arg("Stream", format!("0x{:X}", stream))
                            .arg("SyntheticPopen", synthetic.to_string())
                            .arg("SyntheticLabel", label.unwrap_or_default())
                            .arg("Result", "0")
                            .arg("Errno", "0");
                    emit_arm64_event(&trace_bus_for_hook, event);
                },
            )?;
        }
    }

    if let Some(&addr) = stub_map.get("_kill") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let pid = emu.read_reg("x0").unwrap_or(0);
                let sig = emu.read_reg("x1").unwrap_or(0);
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_kill(pid={}, sig={}) -> 0", pid, sig),
                );
                let event = arm64_process_event(current_pid, current_tid, "kill", "kill")
                    .arg("Pid", pid.to_string())
                    .arg("Sig", sig.to_string())
                    .arg("Result", "0")
                    .arg("Errno", "0");
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_fork") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let lr = emu.read_reg("lr").unwrap_or(0);
                let parent_ctx = save_arm64_context(emu);
                let parent_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);

                let parent_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&parent_tid).copied())
                    .unwrap_or(1);

                let (child_pid, child_tid, spawned) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    match runtime.reserve_thread_id(MAX_SYNTHETIC_THREADS) {
                        Ok(child_tid) => {
                        let mut child_ctx = parent_ctx.clone();
                        child_ctx.x[0] = 0;
                        child_ctx.x[1] = 0;
                        child_ctx.x[2] = 0;
                        child_ctx.pc = lr;
                        runtime.enqueue_pending_front(PendingArm64Thread {
                            thread_id: child_tid,
                            entry: 0,
                            arg: 0,
                            stack_top: child_ctx.sp,
                            exit_pc: done_addr,
                            resume: Some(child_ctx),
                        });
                        let child_pid = {
                            let mut os = match os_runtime.lock() {
                                Ok(os) => os,
                                Err(_) => return,
                            };
                            let pid = os.next_process_id.max(2);
                            os.next_process_id = pid.saturating_add(1);
                            os.processes.insert(
                                pid,
                                SyntheticProcess {
                                    pid,
                                    parent_pid,
                                    exit_status: 0,
                                    running: true,
                                    reaped: false,
                                    exec_path: None,
                                },
                            );
                            os.process_thread_ids.insert(child_tid);
                            os.thread_processes.insert(child_tid, pid);
                            pid
                        };
                        let raw_syscall_frame = emu
                            .read_memory(parent_ctx.sp.saturating_add(8), 8)
                            .ok()
                            .and_then(vec_u64_le)
                            .map(|arg_frame| arg_frame.saturating_sub(0x18))
                            .unwrap_or(parent_ctx.sp);
                        let raw_syscall_resume_pc = 0x10006A5F4;
                        let mut parent_resume_ctx = parent_ctx.clone();
                        parent_resume_ctx.x[0] = child_pid;
                        parent_resume_ctx.x[1] = 0;
                        parent_resume_ctx.x[2] = 0;
                        parent_resume_ctx.sp = raw_syscall_frame;
                        parent_resume_ctx.fp = raw_syscall_frame.saturating_add(0x88);
                        parent_resume_ctx.pc = raw_syscall_resume_pc;
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x38),
                            &child_pid.to_le_bytes(),
                        );
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x40),
                            &0u64.to_le_bytes(),
                        );
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x48),
                            &0u64.to_le_bytes(),
                        );
                        runtime.fork_parent_resumes.insert(
                            child_tid,
                            ForkParentResume {
                                parent_tid,
                                child_pid,
                                context: parent_resume_ctx,
                            },
                        );
                        println!(
                            "[PROC][arm64] fork parent resume snapshot child_tid={} parent_tid={} child_pid={} pc=0x{:X} raw_sp=0x{:X}",
                            child_tid, parent_tid, child_pid, raw_syscall_resume_pc, raw_syscall_frame
                        );
                        (child_pid, child_tid, true)
                        }
                        Err(_) => (u64::MAX, 0u64, false),
                    }
                };

                let mut yielded_to = None;
                if spawned {
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        if runtime.active_thread.is_some() && !runtime.pending_threads.is_empty() {
                            runtime.active_thread.take();
                            if let Ok(true) =
                                dispatch_pending_arm64_thread_by_id(emu, &mut runtime, child_tid)
                            {
                                yielded_to = Some((parent_tid, child_tid));
                            }
                        } else if runtime.active_thread.is_none() && !runtime.pending_threads.is_empty()
                        {
                            if let Ok(true) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                                yielded_to = Some((parent_tid, child_tid));
                            }
                        }
                    }
                } else {
                    let _ = emu.write_reg("x0", u64::MAX);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }

                if yielded_to.is_none() {
                    let _ = emu.write_reg("x0", child_pid);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_fork(parent_tid={}, parent_pid={}) -> pid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X}",
                        parent_tid, parent_pid, child_pid, child_tid, lr, parent_ctx.lr
                    ),
                );
                if let Some((from_tid, to_tid)) = yielded_to {
                    println!(
                        "[PROC][arm64] _fork parent_pid={} child_pid={} parent_tid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X} parent_sp=0x{:X} yield {}->{}",
                        parent_pid, child_pid, parent_tid, child_tid, lr, parent_ctx.lr, parent_ctx.sp, from_tid, to_tid
                    );
                } else {
                    println!(
                        "[PROC][arm64] _fork parent_pid={} child_pid={} parent_tid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X} parent_sp=0x{:X}",
                        parent_pid, child_pid, parent_tid, child_tid, lr, parent_ctx.lr, parent_ctx.sp
                    );
                }
                let event = arm64_process_event(parent_pid, parent_tid, "fork", "fork")
                    .arg("ChildPid", child_pid.to_string())
                    .arg("ChildTid", child_tid.to_string())
                    .arg("Spawned", spawned.to_string())
                    .arg("ResumePc", format!("0x{:X}", lr))
                    .arg("ParentLr", format!("0x{:X}", parent_ctx.lr))
                    .arg("ParentSp", format!("0x{:X}", parent_ctx.sp));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn") {
        install_posix_spawn_hook(
            emulator,
            addr,
            "posix_spawn",
            errno_ptr,
            trace_bus,
            shared_state,
            import_tracker,
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawnp") {
        install_posix_spawn_hook(
            emulator,
            addr,
            "posix_spawnp",
            errno_ptr,
            trace_bus,
            shared_state,
            import_tracker,
        )?;
    }

    for (sym, call_label, has_rusage) in [("_wait4", "wait4", true), ("_waitpid", "waitpid", false)]
    {
        let Some(&addr) = stub_map.get(sym) else {
            continue;
        };
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let pid_arg = emu.read_reg("x0").unwrap_or(0);
                let status_ptr = emu.read_reg("x1").unwrap_or(0);
                let options = emu.read_reg("x2").unwrap_or(0);
                let rusage_ptr = if has_rusage {
                    emu.read_reg("x3").unwrap_or(0)
                } else {
                    0
                };
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                // WNOHANG (option bit 1) means the caller is polling. Once
                // we've delivered the synthetic exit for a child the caller
                // typically loops again expecting -1/ECHILD; otherwise the
                // RustDoor daemon (and many shells) spin in a tight WNOHANG
                // poll burning the entire instruction budget.
                let wnohang = options & 1 != 0;
                let (result, status_value, errno) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let found = os.processes.iter_mut().find(|(pid, proc_state)| {
                        if **pid == 1 || proc_state.parent_pid != current_pid || proc_state.reaped {
                            return false;
                        }
                        if pid_arg > 0 && **pid != pid_arg {
                            return false;
                        }
                        !proc_state.running
                    });
                    if let Some((pid, proc_state)) = found {
                        proc_state.reaped = true;
                        (*pid, (proc_state.exit_status as u32) << 8, 0u32)
                    } else {
                        let has_child = os.processes.iter().any(|(pid, proc_state)| {
                            *pid != 1
                                && proc_state.parent_pid == current_pid
                                && (pid_arg == 0 || *pid == pid_arg)
                                && !proc_state.reaped
                        });
                        if has_child && !wnohang {
                            (0u64, 0u32, 0u32)
                        } else {
                            // Either no children or WNOHANG with no
                            // dead child to reap. Report ECHILD so
                            // poll loops can advance instead of spinning.
                            (u64::MAX, 0u32, 10u32)
                        }
                    }
                };
                if status_ptr != 0 && result != u64::MAX {
                    let _ = emu.write_memory(status_ptr, &status_value.to_le_bytes());
                }
                if rusage_ptr != 0 {
                    let _ = emu.write_memory(rusage_ptr, &[0u8; 32]);
                }
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "{sym}(pid={pid_arg}, status=0x{status_ptr:X}, options=0x{options:X}) -> pid={result} status=0x{status_value:X} errno={errno}"
                    ),
                );
                println!(
                    "[PROC][arm64] {sym} pid={pid_arg} status=0x{status_ptr:X} options=0x{options:X} rusage=0x{rusage_ptr:X} current_pid={current_pid} -> pid={result} status=0x{status_value:X} errno={errno}"
                );
                let event = arm64_process_event(current_pid, current_tid, call_label, call_label)
                    .arg("TargetPid", pid_arg.to_string())
                    .arg("ResultPid", result.to_string())
                    .arg("StatusPtr", format!("0x{:X}", status_ptr))
                    .arg("StatusValue", status_value.to_string())
                    .arg("Options", format!("0x{:X}", options))
                    .arg("RusagePtr", format!("0x{:X}", rusage_ptr))
                    .arg("Wnohang", wnohang.to_string())
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_execve") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let argv_ptr = emu.read_reg("x1").unwrap_or(0);
                let envp_ptr = emu.read_reg("x2").unwrap_or(0);
                let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
                let argv = if argv_ptr != 0 {
                    read_arm64_argv(emu, argv_ptr, 16, 256)
                } else {
                    Vec::new()
                };
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                let mut stdin_capture_info = None;
                if let Ok(mut os) = os_runtime.lock() {
                    if let Some(proc_state) = os.processes.get_mut(&current_pid) {
                        proc_state.exec_path = Some(path.clone());
                    }
                    if let Some(SyntheticFdTarget::PipeRead(pipe_id)) =
                        resolve_process_fd_target(&os, current_pid, 0)
                    {
                        if let Some(pipe) = os.pipes.get(&pipe_id) {
                            if analysis
                                .arm_pipe_stdin_capture(pipe_id, current_pid, &path, &argv)
                                .is_some()
                            {
                                stdin_capture_info = Some((pipe_id, pipe.read_fd, pipe.write_fd));
                            }
                        }
                    }
                    let close_on_exec_fds = os
                        .process_fds
                        .get(&current_pid)
                        .map(|fds| {
                            fds.iter()
                                .copied()
                                .filter(|fd| *fd > 2 && os.fd_flags.get(fd).copied().unwrap_or(0) & 1 != 0)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    for fd in close_on_exec_fds {
                        let _ = close_synthetic_fd(&mut os, current_pid, fd);
                    }
                    terminate_synthetic_process(&mut os, current_pid, 0);
                }

                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_execve(path={:?}, argv={:?}, envp=0x{:X}) [pid={}, tid={}]",
                        path, argv, envp_ptr, current_pid, current_tid
                    ),
                );
                println!(
                    "[PROC][arm64] _execve pid={} tid={} path={:?} argv={:?} envp=0x{:X}",
                    current_pid, current_tid, path, argv, envp_ptr
                );
                if let Some((pipe_id, read_fd, write_fd)) = stdin_capture_info {
                    println!(
                        "[CAPTURE][arm64] process-stdin armed pid={} path={:?} pipe_id={} read_fd={} write_fd={}",
                        current_pid, path, pipe_id, read_fd, write_fd
                    );
                }

                let mut dispatched = false;
                let mut resumed_parent_tid = None;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if runtime
                        .active_thread
                        .as_ref()
                        .map(|active| active.thread_id == current_tid)
                        .unwrap_or(false)
                    {
                        runtime.active_thread.take();
                        if let Some(parent_resume) = runtime.fork_parent_resumes.get(&current_tid).cloned() {
                            runtime.remove_pending_by_id(parent_resume.parent_tid);
                            runtime.activate_thread(
                                parent_resume.parent_tid,
                                current_tid,
                                save_arm64_context(emu),
                            );
                            if restore_arm64_context(
                                emu,
                                &parent_resume.context,
                                parent_resume.child_pid,
                                parent_resume.context.pc,
                            )
                            .is_ok()
                            {
                                let restored_pc = emu.read_reg("pc").unwrap_or(0);
                                let restored_sp = emu.read_reg("sp").unwrap_or(0);
                                let restored_x0 = emu.read_reg("x0").unwrap_or(0);
                                let restored_x2 = emu.read_reg("x2").unwrap_or(0);
                                println!(
                                    "[PROC][arm64] fork parent context restored tid={} pc=0x{:X} sp=0x{:X} x0=0x{:X} x2=0x{:X}",
                                    parent_resume.parent_tid, restored_pc, restored_sp, restored_x0, restored_x2
                                );
                                dispatched = true;
                                resumed_parent_tid = Some(parent_resume.parent_tid);
                            }
                        }
                        if !dispatched {
                            if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                                dispatched = did_dispatch;
                            }
                        }
                    }
                }
                if dispatched {
                    if let Some(parent_tid) = resumed_parent_tid {
                        println!(
                            "[PROC][arm64] execve consumed synthetic child pid={} tid={} and resumed fork parent tid={}",
                            current_pid, current_tid, parent_tid
                        );
                    } else {
                        println!(
                            "[PROC][arm64] execve consumed synthetic child pid={} and dispatched next thread",
                            current_pid
                        );
                    }
                } else {
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let _ = emu.write_reg("x0", 0);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }
                let event = arm64_process_event(current_pid, current_tid, "execve", "execve")
                    .arg("Path", path)
                    .arg("Argv", format!("{:?}", argv))
                    .arg("Envp", format!("0x{:X}", envp_ptr))
                    .arg("Dispatched", dispatched.to_string())
                    .arg(
                        "ResumedParentTid",
                        resumed_parent_tid.unwrap_or(0).to_string(),
                    );
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    for sym in ["_atexit", "___cxa_atexit"] {
        let Some(&addr) = stub_map.get(sym) else {
            continue;
        };
        let exit_handlers = shared_state.exit_handlers.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let function = emu.read_reg("x0").unwrap_or(0);
                let argument = if sym == "___cxa_atexit" {
                    emu.read_reg("x1").unwrap_or(0)
                } else {
                    0
                };
                let dso_handle = if sym == "___cxa_atexit" {
                    emu.read_reg("x2").unwrap_or(0)
                } else {
                    0
                };
                let kind = if sym == "___cxa_atexit" {
                    Arm64ExitHandlerKind::CxaAtexit
                } else {
                    Arm64ExitHandlerKind::Atexit
                };
                if function != 0 {
                    if let Ok(mut handlers) = exit_handlers.lock() {
                        handlers.push(Arm64ExitHandler {
                            function,
                            argument,
                            dso_handle,
                            kind,
                        });
                    }
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "{sym}(func=0x{function:X}, arg=0x{argument:X}, dso=0x{dso_handle:X}) -> 0"
                    ),
                );
                let event = arm64_process_event(1, 1, "atexit", sym)
                    .arg("Function", format!("0x{:X}", function))
                    .arg("Argument", format!("0x{:X}", argument))
                    .arg("DsoHandle", format!("0x{:X}", dso_handle));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    // Hook both `__exit` (the BSD `_exit(2)` syscall wrapper, symbol prefix
    // `_` + name `_exit`) and `_exit` (the C library `exit(3)` that runs
    // atexit handlers and tail-calls `_exit(2)`, symbol prefix `_` + name
    // `exit`). Without an `_exit` hook the post-fork parent in RustDoor
    // never terminates and instead falls through into a `waitpid`-WNOHANG
    // poll loop that consumes the entire timeout budget without ever
    // reaching the actual command-execution stage.
    for sym in ["__exit", "_exit"] {
        let Some(&addr) = stub_map.get(sym) else {
            continue;
        };
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let saw_exit_import = saw_exit.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let code = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let sp = emu.read_reg("sp").unwrap_or(0);
                let caller_lr = if sp != 0 {
                    emu.read_memory(sp, 8).ok().and_then(vec_u64_le).unwrap_or(0)
                } else {
                    0
                };
                let _lr_code = emu.read_memory(lr.saturating_sub(8), 24).unwrap_or_default();
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                if code == 253 && lr == 0x10006FDEC {
                    let mut dispatched_parent = false;
                    let mut dispatched_tid = 0;
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        let resume_tid = runtime
                            .pending_threads
                            .iter()
                            .find(|thread| {
                                thread.resume.as_ref().map(|ctx| ctx.pc == 0x10006A5F4).unwrap_or(false)
                            })
                            .map(|thread| thread.thread_id);
                        if let Some(resume_tid) = resume_tid {
                            runtime.active_thread.take();
                            if let Ok(did_dispatch) =
                                dispatch_pending_arm64_thread_by_id(emu, &mut runtime, resume_tid)
                            {
                                dispatched_parent = did_dispatch;
                                dispatched_tid = resume_tid;
                            }
                        }
                    }
                    if dispatched_parent {
                        record_arm64_import(
                            &import_tracker,
                            format!("__exit(code=253, tid={}) suppressed post-exec child tail", current_tid),
                        );
                        println!(
                            "[PROC][arm64] suppressed impossible post-exec child __exit(253) tid={} -> dispatched fork parent tid={}",
                            current_tid, dispatched_tid
                        );
                        return;
                    }
                }
                saw_exit_import.store(true, std::sync::atomic::Ordering::Relaxed);
                let has_other_threads = {
                    let runtime = thread_runtime.lock().ok();
                    let os = os_runtime.lock().ok();
                    if let (Some(runtime), Some(os)) = (runtime.as_ref(), os.as_ref()) {
                        let pending_match = runtime.pending_threads.iter().any(|thread| {
                            thread.thread_id != current_tid
                                && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                        });
                        let active_match = runtime
                            .active_thread
                            .as_ref()
                            .map(|thread| {
                                thread.thread_id != current_tid
                                    && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                            })
                            .unwrap_or(false);
                        let waiting_match = runtime.cond_waiters.values().any(|queue| {
                            queue.iter().any(|thread| {
                                thread.thread_id != current_tid
                                    && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                            })
                        });
                        pending_match || active_match || waiting_match
                    } else {
                        false
                    }
                };
                if let Ok(mut os) = os_runtime.lock() {
                    if has_other_threads {
                        os.thread_processes.remove(&current_tid);
                        os.process_thread_ids.remove(&current_tid);
                    } else {
                        terminate_synthetic_process(&mut os, current_pid, code as i32);
                    }
                }
                let mut dispatched = false;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if runtime
                        .active_thread
                        .as_ref()
                        .map(|active| active.thread_id == current_tid)
                        .unwrap_or(false)
                    {
                        runtime.active_thread.take();
                        if let Ok(did_dispatch) =
                            dispatch_pending_arm64_thread(emu, &mut runtime)
                        {
                            dispatched = did_dispatch;
                        }
                    }
                }
                if !dispatched {
                    // The exiting thread was the last live thread we can
                    // schedule. The pre-existing behavior fell through to
                    // `pc = lr`, which left the now-dead caller's
                    // instructions as the active execution path — for the
                    // RustDoor daemon that meant a runaway
                    // `waitpid`/`__error` poll loop after `_exit` consumed
                    // the entire timeout budget. Park PC at done_addr so
                    // the runner stops cleanly with a real `post_exit`
                    // status instead of executing the dead caller's tail.
                    let _ = emu.write_reg("pc", done_addr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "{sym}(code={code}, pid={current_pid}, tid={current_tid}, lr=0x{lr:X}, caller=0x{caller_lr:X})"
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "exit", sym)
                    .arg("Code", code.to_string())
                    .arg("HasOtherThreads", has_other_threads.to_string())
                    .arg("Dispatched", dispatched.to_string())
                    .arg("Lr", format!("0x{:X}", lr))
                    .arg("CallerLr", format!("0x{:X}", caller_lr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    Ok(())
}
