use std::path::PathBuf;

use compatra::RuntimeMode;

use crate::capture::{
    append_file_write_payload_to_capture, extract_ascii_indicators, fnv1a64_hex,
    lossy_data_preview, shannon_entropy, write_pipe_stdin_capture, write_posix_spawn_argv_capture,
};
use crate::guest_artifacts::materialize_synthetic_file_bytes;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnalysisServices;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyntheticLogStream {
    pub messages: Vec<String>,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyntheticPopenOutput {
    pub label: String,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FilePayloadDump {
    pub raw_path: String,
    pub dump_path: PathBuf,
    pub dumped_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PipeStdinCaptureReport {
    pub pipe_id: u64,
    pub label: String,
    pub consumer_pid: Option<u64>,
    pub bytes: usize,
    pub raw_hash: String,
    pub raw_entropy: f64,
    pub preview: String,
    pub artifact_summary: String,
    pub analysis_summary: String,
}

impl AnalysisServices {
    pub fn for_mode(mode: RuntimeMode) -> Option<Self> {
        mode.is_analysis().then_some(Self)
    }

    pub fn synthetic_log_stream(&self, path: &str, argv: &[String]) -> Option<SyntheticLogStream> {
        let stream = compatra::synthetic_log_stream(path, argv)?;
        Some(SyntheticLogStream {
            messages: stream.messages,
            output: stream.output,
        })
    }

    pub fn synthetic_popen_output(&self, command: &str) -> Option<SyntheticPopenOutput> {
        let output = compatra::synthetic_process_output(command)?;
        Some(SyntheticPopenOutput {
            label: output.label,
            output: output.output,
        })
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
        write_posix_spawn_argv_capture(parent_pid, child_pid, sequence, path, argv, envp_ptr)
    }

    pub fn process_stdin_capture_label(
        &self,
        current_pid: u64,
        path: &str,
        argv: &[String],
    ) -> String {
        format!("pid={} {} {:?}", current_pid, path, argv)
    }

    pub fn capture_file_write_payload(
        &self,
        pid: u64,
        fd: u64,
        raw_path: impl Into<String>,
        data: &[u8],
    ) -> Option<FilePayloadDump> {
        let raw_path = raw_path.into();
        let dump_path = append_file_write_payload_to_capture(pid, fd, &raw_path, data)?;
        Some(FilePayloadDump {
            raw_path,
            dump_path,
            dumped_bytes: data.len(),
        })
    }

    pub fn materialize_synthetic_file_bytes(&self, raw_path: &str, size: usize) -> Vec<u8> {
        materialize_synthetic_file_bytes(raw_path, size)
    }

    pub fn complete_pipe_stdin_capture(
        &self,
        pipe_id: u64,
        label: String,
        consumer_pid: Option<u64>,
        data: &[u8],
    ) -> PipeStdinCaptureReport {
        let preview = lossy_data_preview(data, 256);
        let raw_hash = fnv1a64_hex(data);
        let raw_entropy = shannon_entropy(data);
        let raw_indicators = extract_ascii_indicators(data, 8, 8);
        let mut artifact_summary = String::new();
        let mut analysis_summary = String::new();

        if !raw_indicators.is_empty() {
            analysis_summary.push_str(&format!(" indicators={:?}", raw_indicators));
        }
        if let Some(raw_path) = write_pipe_stdin_capture(pipe_id, &label, data) {
            artifact_summary.push_str(&format!(" raw={}", raw_path.display()));
        }

        PipeStdinCaptureReport {
            pipe_id,
            label,
            consumer_pid,
            bytes: data.len(),
            raw_hash,
            raw_entropy,
            preview,
            artifact_summary,
            analysis_summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_mode_has_no_analysis_services() {
        assert_eq!(AnalysisServices::for_mode(RuntimeMode::Compat), None);
        assert_eq!(
            AnalysisServices::for_mode(RuntimeMode::Analysis),
            Some(AnalysisServices)
        );
    }

    #[test]
    fn log_stream_synthesis_is_an_analysis_service() {
        let analysis = AnalysisServices;
        let argv = vec![
            "stream".to_string(),
            r#"eventMessage contains "restartInitiated" OR eventMessage contains "shutdownInitiated""#
                .to_string(),
        ];

        let stream = analysis
            .synthetic_log_stream("log", &argv)
            .expect("expected synthetic log stream");

        assert_eq!(
            stream.messages,
            vec![
                "restartInitiated".to_string(),
                "shutdownInitiated".to_string()
            ]
        );
        assert!(String::from_utf8_lossy(&stream.output).contains("restartInitiated"));
        assert!(analysis.synthetic_log_stream("not-log", &argv).is_none());
    }

    #[test]
    fn popen_synthesis_covers_profiler_inventory_commands() {
        let analysis = AnalysisServices;

        let uname = analysis
            .synthetic_popen_output("uname -s 2>/dev/null")
            .expect("uname output should be synthesized");
        assert_eq!(uname.label, "uname-kernel");
        assert_eq!(String::from_utf8_lossy(&uname.output), "Darwin\n");

        let ps = analysis
            .synthetic_popen_output("ps -eo pid,sess,command 2>/dev/null")
            .expect("ps output should be synthesized");
        assert!(String::from_utf8_lossy(&ps.output).contains("Google Chrome"));

        let extensions = analysis
            .synthetic_popen_output(
                "find '/Users/analyst/Library/Application Support/Google/Chrome/Default/Extensions' -maxdepth 1 2>/dev/null",
            )
            .expect("browser extension discovery should be synthesized");
        assert_eq!(extensions.label, "browser-extensions");
        assert!(String::from_utf8_lossy(&extensions.output).contains("Extensions"));

        assert!(analysis.synthetic_popen_output("unknown-command").is_none());
    }

    #[test]
    fn file_payload_dump_keeps_capture_metadata_together() {
        let dump = FilePayloadDump {
            raw_path: "/tmp/out".to_string(),
            dump_path: PathBuf::from("target/compatra-captures/out.bin"),
            dumped_bytes: 4,
        };

        assert_eq!(dump.raw_path, "/tmp/out");
        assert_eq!(dump.dumped_bytes, 4);
    }
}
