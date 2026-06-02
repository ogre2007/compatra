use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use machina_mode::RuntimeMode;

use crate::capture::lossy_data_preview;
use crate::operator_hooks::{
    function_entry_specs_from_env, usage_bypass_specs_from_env, FunctionEntryProbeSpec,
    UsageBypassHookSpec,
};
use crate::{
    AnalysisServices, FilePayloadDump, PipeStdinCaptureReport, SyntheticLogStream,
    SyntheticPopenOutput,
};

#[derive(Clone, Debug, Default)]
pub struct AnalysisRuntimeHooks {
    services: Option<AnalysisServices>,
    pipe_stdin: Arc<Mutex<HashMap<u64, PipeStdinCaptureState>>>,
}

#[derive(Clone, Debug)]
struct PipeStdinCaptureState {
    label: String,
    consumer_pid: Option<u64>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeStdinCaptureProgress {
    pub label: String,
    pub bytes: usize,
    pub preview: String,
}

impl AnalysisRuntimeHooks {
    pub fn for_mode(mode: RuntimeMode) -> Self {
        Self {
            services: AnalysisServices::for_mode(mode),
            pipe_stdin: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.services.is_some()
    }

    pub fn function_entry_specs_from_env(&self) -> Vec<FunctionEntryProbeSpec> {
        if !self.is_enabled() {
            return Vec::new();
        }
        function_entry_specs_from_env(RuntimeMode::Analysis)
    }

    pub fn usage_bypass_specs_from_env(&self) -> Vec<UsageBypassHookSpec> {
        if !self.is_enabled() {
            return Vec::new();
        }
        usage_bypass_specs_from_env(RuntimeMode::Analysis)
    }

    pub fn synthetic_log_stream(&self, path: &str, argv: &[String]) -> Option<SyntheticLogStream> {
        self.services?.synthetic_log_stream(path, argv)
    }

    pub fn synthetic_popen_output(&self, command: &str) -> Option<SyntheticPopenOutput> {
        self.services?.synthetic_popen_output(command)
    }

    pub fn write_posix_spawn_argv_capture(
        &self,
        parent_pid: u64,
        child_pid: u64,
        sequence: usize,
        path: &str,
        argv: &[String],
        envp_ptr: u64,
    ) -> Option<PathBuf> {
        self.services?
            .write_posix_spawn_argv_capture(parent_pid, child_pid, sequence, path, argv, envp_ptr)
    }

    pub fn arm_pipe_stdin_capture(
        &self,
        pipe_id: u64,
        consumer_pid: u64,
        path: &str,
        argv: &[String],
    ) -> Option<String> {
        let label = self
            .services?
            .process_stdin_capture_label(consumer_pid, path, argv);
        let mut captures = self.pipe_stdin.lock().ok()?;
        captures.insert(
            pipe_id,
            PipeStdinCaptureState {
                label: label.clone(),
                consumer_pid: Some(consumer_pid),
                data: Vec::new(),
            },
        );
        Some(label)
    }

    pub fn observe_pipe_stdin_write(
        &self,
        pipe_id: u64,
        data: &[u8],
    ) -> Option<PipeStdinCaptureProgress> {
        self.services?;
        let mut captures = self.pipe_stdin.lock().ok()?;
        let capture = captures.get_mut(&pipe_id)?;
        capture.data.extend(data.iter().copied());
        Some(PipeStdinCaptureProgress {
            label: capture.label.clone(),
            bytes: capture.data.len(),
            preview: lossy_data_preview(&capture.data, 256),
        })
    }

    pub fn pipe_stdin_consumer_pid(&self, pipe_id: u64) -> Option<u64> {
        self.pipe_stdin.lock().ok().and_then(|captures| {
            captures
                .get(&pipe_id)
                .and_then(|capture| capture.consumer_pid)
        })
    }

    pub fn complete_pipe_stdin_capture(&self, pipe_id: u64) -> Option<PipeStdinCaptureReport> {
        let services = self.services?;
        let capture = self.pipe_stdin.lock().ok()?.remove(&pipe_id)?;
        Some(services.complete_pipe_stdin_capture(
            pipe_id,
            capture.label,
            capture.consumer_pid,
            &capture.data,
        ))
    }

    pub fn capture_file_write_payload(
        &self,
        pid: u64,
        fd: u64,
        raw_path: String,
        data: &[u8],
    ) -> Option<FilePayloadDump> {
        self.services?
            .capture_file_write_payload(pid, fd, raw_path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static CAPTURE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CaptureEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        old: Option<std::ffi::OsString>,
        dir: std::path::PathBuf,
    }

    impl Drop for CaptureEnvGuard {
        fn drop(&mut self) {
            if let Some(old) = self.old.take() {
                std::env::set_var("MACHINA_PAYLOAD_DUMP_DIR", old);
            } else {
                std::env::remove_var("MACHINA_PAYLOAD_DUMP_DIR");
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn temp_capture_env(label: &str) -> CaptureEnvGuard {
        let lock = CAPTURE_ENV_LOCK
            .lock()
            .expect("capture env lock should not be poisoned");
        let dir =
            std::env::temp_dir().join(format!("machina-analysis-{}-{}", label, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let old = std::env::var_os("MACHINA_PAYLOAD_DUMP_DIR");
        std::env::set_var("MACHINA_PAYLOAD_DUMP_DIR", &dir);
        CaptureEnvGuard {
            _lock: lock,
            old,
            dir,
        }
    }

    #[test]
    fn compat_mode_disables_runtime_hooks() {
        let hooks = AnalysisRuntimeHooks::for_mode(RuntimeMode::Compat);
        assert!(!hooks.is_enabled());
        assert!(hooks
            .synthetic_log_stream("log", &["stream".to_string()])
            .is_none());
        assert!(hooks
            .synthetic_popen_output("uname -s 2>/dev/null")
            .is_none());
        assert!(hooks.observe_pipe_stdin_write(1, b"ignored").is_none());
    }

    #[test]
    fn pipe_stdin_capture_tracks_progress_and_completion() {
        let _capture_env = temp_capture_env("pipe-stdin");
        let hooks = AnalysisRuntimeHooks::for_mode(RuntimeMode::Analysis);
        let argv = vec!["arg".to_string()];
        let label = hooks
            .arm_pipe_stdin_capture(7, 42, "/bin/tool", &argv)
            .expect("capture should arm in analysis mode");
        assert!(label.contains("pid=42"));
        assert_eq!(hooks.pipe_stdin_consumer_pid(7), Some(42));

        let progress = hooks
            .observe_pipe_stdin_write(7, b"hello world")
            .expect("write should update armed capture");
        assert_eq!(progress.bytes, 11);
        assert!(progress.preview.contains("hello"));

        let report = hooks
            .complete_pipe_stdin_capture(7)
            .expect("completion should produce a report");
        assert_eq!(report.pipe_id, 7);
        assert_eq!(report.bytes, 11);
        assert!(hooks.complete_pipe_stdin_capture(7).is_none());
    }
}
