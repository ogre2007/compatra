#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisEventCategory {
    Process,
    Thread,
    Syscall,
    Io,
    Memory,
    Kqueue,
    Detect,
    Capture,
    Loader,
    Import,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisPluginSpec {
    pub name: &'static str,
    pub categories: &'static [AnalysisEventCategory],
    pub calls: &'static [&'static str],
}

const PROCMON_CATEGORIES: &[AnalysisEventCategory] = &[
    AnalysisEventCategory::Process,
    AnalysisEventCategory::Thread,
];
const PROCMON_CALLS: &[&str] = &["execve", "fork", "wait4", "exit", "__exit"];

const SYSCALLS_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Syscall];
const SYSCALLS_CALLS: &[&str] = &[
    "open", "read", "write", "close", "mmap", "munmap", "mprotect", "sysctl",
];

const FILEMON_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Io];
const FILEMON_CALLS: &[&str] = &["open", "close", "read", "write", "dup2", "pipe", "fcntl"];

const MEMMON_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Memory];
const MEMMON_CALLS: &[&str] = &["mmap", "munmap", "mprotect", "brk"];

const KQUEUEMON_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Kqueue];
const KQUEUEMON_CALLS: &[&str] = &["kqueue", "kevent"];

const DETECT_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Detect];
const CAPTURE_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Capture];

const LOADER_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Loader];
const LOADER_CALLS: &[&str] = &["dyld", "stub_patch"];

const IMPORTS_CATEGORIES: &[AnalysisEventCategory] = &[AnalysisEventCategory::Import];
const IMPORTS_CALLS: &[&str] = &["ptrace", "execve", "fork", "kevent", "kqueue", "import-hit"];

const ANALYSIS_PLUGIN_SPECS: &[AnalysisPluginSpec] = &[
    AnalysisPluginSpec {
        name: "procmon",
        categories: PROCMON_CATEGORIES,
        calls: PROCMON_CALLS,
    },
    AnalysisPluginSpec {
        name: "syscalls",
        categories: SYSCALLS_CATEGORIES,
        calls: SYSCALLS_CALLS,
    },
    AnalysisPluginSpec {
        name: "filemon",
        categories: FILEMON_CATEGORIES,
        calls: FILEMON_CALLS,
    },
    AnalysisPluginSpec {
        name: "memmon",
        categories: MEMMON_CATEGORIES,
        calls: MEMMON_CALLS,
    },
    AnalysisPluginSpec {
        name: "kqueuemon",
        categories: KQUEUEMON_CATEGORIES,
        calls: KQUEUEMON_CALLS,
    },
    AnalysisPluginSpec {
        name: "detect",
        categories: DETECT_CATEGORIES,
        calls: &[],
    },
    AnalysisPluginSpec {
        name: "capture",
        categories: CAPTURE_CATEGORIES,
        calls: &[],
    },
    AnalysisPluginSpec {
        name: "loader",
        categories: LOADER_CATEGORIES,
        calls: LOADER_CALLS,
    },
    AnalysisPluginSpec {
        name: "imports",
        categories: IMPORTS_CATEGORIES,
        calls: IMPORTS_CALLS,
    },
];

pub fn analysis_plugin_specs() -> &'static [AnalysisPluginSpec] {
    ANALYSIS_PLUGIN_SPECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_preset_owns_operator_stream_names() {
        let names = analysis_plugin_specs()
            .iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>();

        assert!(names.contains(&"procmon"));
        assert!(names.contains(&"filemon"));
        assert!(names.contains(&"detect"));
        assert!(names.contains(&"capture"));
    }
}
