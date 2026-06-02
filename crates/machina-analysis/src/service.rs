use std::path::PathBuf;

use machina_mode::RuntimeMode;

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
        let messages = synthetic_log_stream_messages(path, argv);
        if messages.is_empty() {
            return None;
        }
        Some(SyntheticLogStream {
            output: synthetic_log_stream_output(&messages),
            messages,
        })
    }

    pub fn synthetic_popen_output(&self, command: &str) -> Option<SyntheticPopenOutput> {
        synthetic_popen_output(command)
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

fn extract_log_stream_event_messages(predicate: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut rest = predicate;
    while let Some(idx) = rest.find("eventMessage contains") {
        rest = &rest[idx + "eventMessage contains".len()..];
        let Some(start) = rest.find('"') else {
            break;
        };
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        messages.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    messages
}

fn synthetic_log_stream_messages(path: &str, argv: &[String]) -> Vec<String> {
    if path != "log" || !argv.iter().any(|arg| arg == "stream") {
        return Vec::new();
    }
    let mut messages = argv
        .iter()
        .flat_map(|arg| extract_log_stream_event_messages(arg))
        .collect::<Vec<_>>();
    messages.sort();
    messages.dedup();
    messages
}

fn synthetic_log_stream_output(messages: &[String]) -> Vec<u8> {
    let mut output =
        "Timestamp                       Thread     Type        Activity             PID    TTL  \n"
            .as_bytes()
            .to_vec();
    for message in messages {
        output.extend_from_slice(
            format!(
                "2026-05-08 20:00:00.000000+0300 0x000000   Info        0x0                  0      0    {}\n",
                message
            )
            .as_bytes(),
        );
    }
    output
}

fn synthetic_popen_output(command: &str) -> Option<SyntheticPopenOutput> {
    let command = command.trim();
    let (label, output): (&str, &str) = match command {
        "uname -s 2>/dev/null" => ("uname-kernel", "Darwin\n"),
        "uname -m 2>/dev/null" => ("uname-machine", "arm64\n"),
        "uname -r 2>/dev/null" => ("uname-release", "23.6.0\n"),
        "stat -f %SB / 2>/dev/null | head -1" => {
            ("root-birthtime", "Jan  1 00:00:00 2026\n")
        }
        "sysctl -n kern.boottime 2>/dev/null | grep -oE '[0-9]+' | head -1" => {
            ("boot-time", "1735689600\n")
        }
        "date +%Z 2>/dev/null" => ("timezone", "UTC\n"),
        "sysctl -n machdep.cpu.brand_string 2>/dev/null" => {
            ("cpu-brand", "Apple M2\n")
        }
        "ifconfig en0 2>/dev/null | awk '/ether/{print $2}'" => {
            ("en0-mac", "02:42:AC:10:00:02\n")
        }
        "ifconfig en0 2>/dev/null | awk '/inet /{print $2}'" => ("en0-ipv4", "10.0.2.15\n"),
        "ps -eo pid,sess,command 2>/dev/null" => (
            "process-list",
            "  PID  SESS COMMAND\n\
               1     1 /sbin/launchd\n\
             503   503 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
             742   742 /bin/zsh\n",
        ),
        _ if command.contains("find ")
            && command.contains("Extensions")
            && command.contains("2>/dev/null") =>
        {
            (
                "browser-extensions",
                "/Users/analyst/Library/Application Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn\n\
                 /Users/analyst/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/bfnaelmomeimhlpmgjnjophhpkkoljpa\n",
            )
        }
        _ => return None,
    };

    Some(SyntheticPopenOutput {
        label: label.to_string(),
        output: output.as_bytes().to_vec(),
    })
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
            dump_path: PathBuf::from("target/machina-captures/out.bin"),
            dumped_bytes: 4,
        };

        assert_eq!(dump.raw_path, "/tmp/out");
        assert_eq!(dump.dumped_bytes, 4);
    }
}
