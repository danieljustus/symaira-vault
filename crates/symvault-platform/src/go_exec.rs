//! Go `os/exec` error text for finished child processes.
//!
//! `(*exec.ExitError).Error()` is `os.ProcessState.String()`:
//! `exit status N`, or `signal: <name>` (plus ` (core dumped)`) when the child
//! was ended by a signal, where `<name>` comes from the `signals` table of the
//! GOOS the Go binary was built for (`syscall.Signal.String`). A signal outside
//! the table prints as `signal N`. The tables below are Go's own: the macOS one
//! was recorded by executing `syscall.Signal.String` and the Linux one was
//! extracted from the pinned toolchain's `zerrors_linux_*.go` (see
//! `testdata/port/platform/get_clipboard_darwin.json`).

/// The operating system whose Go signal table names the signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoOs {
    Darwin,
    Linux,
}

impl GoOs {
    /// The table of the OS this crate was compiled for.
    #[must_use]
    pub const fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::Darwin
        } else {
            Self::Linux
        }
    }
}

const DARWIN: [&str; 32] = [
    "",
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/BPT trap",
    "abort trap",
    "EMT trap",
    "floating point exception",
    "killed",
    "bus error",
    "segmentation fault",
    "bad system call",
    "broken pipe",
    "alarm clock",
    "terminated",
    "urgent I/O condition",
    "suspended (signal)",
    "suspended",
    "continued",
    "child exited",
    "stopped (tty input)",
    "stopped (tty output)",
    "I/O possible",
    "cputime limit exceeded",
    "filesize limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window size changes",
    "information request",
    "user defined signal 1",
    "user defined signal 2",
];

const LINUX: [&str; 32] = [
    "",
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/breakpoint trap",
    "aborted",
    "bus error",
    "floating point exception",
    "killed",
    "user defined signal 1",
    "segmentation fault",
    "user defined signal 2",
    "broken pipe",
    "alarm clock",
    "terminated",
    "stack fault",
    "child exited",
    "continued",
    "stopped (signal)",
    "stopped",
    "stopped (tty input)",
    "stopped (tty output)",
    "urgent I/O condition",
    "CPU time limit exceeded",
    "file size limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window changed",
    "I/O possible",
    "power failure",
    "bad system call",
];

/// Go `syscall.Signal.String()`.
#[must_use]
pub fn signal_name(os: GoOs, signal: i32) -> String {
    let table: &[&str; 32] = match os {
        GoOs::Darwin => &DARWIN,
        GoOs::Linux => &LINUX,
    };
    usize::try_from(signal)
        .ok()
        .and_then(|index| table.get(index))
        .filter(|name| !name.is_empty())
        .map_or_else(|| format!("signal {signal}"), |name| (*name).to_owned())
}

/// Go `os.ProcessState.String()` for a finished child: its exit code, or the
/// signal that ended it.
#[must_use]
pub fn exit_status_text(
    os: GoOs,
    code: Option<i32>,
    signal: Option<i32>,
    core_dumped: bool,
) -> String {
    match (code, signal) {
        (_, Some(signal)) => {
            let mut text = format!("signal: {}", signal_name(os, signal));
            if core_dumped {
                text.push_str(" (core dumped)");
            }
            text
        }
        (Some(code), None) => format!("exit status {code}"),
        // A child that neither exited nor was signalled (not reachable for a
        // waited child): Go prints `exit status -1`.
        (None, None) => "exit status -1".to_owned(),
    }
}

/// [`exit_status_text`] for a real [`std::process::ExitStatus`] of this host.
#[cfg(unix)]
#[must_use]
pub fn status_text(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    exit_status_text(
        GoOs::host(),
        status.code(),
        status.signal(),
        status.core_dumped(),
    )
}

#[cfg(not(unix))]
#[must_use]
pub fn status_text(status: &std::process::ExitStatus) -> String {
    exit_status_text(GoOs::host(), status.code(), None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_and_signals_use_go_text() {
        assert_eq!(
            exit_status_text(GoOs::Darwin, Some(3), None, false),
            "exit status 3"
        );
        assert_eq!(
            exit_status_text(GoOs::Darwin, None, Some(9), false),
            "signal: killed"
        );
        assert_eq!(
            exit_status_text(GoOs::Linux, None, Some(6), true),
            "signal: aborted (core dumped)"
        );
        assert_eq!(
            exit_status_text(GoOs::Darwin, None, Some(6), true),
            "signal: abort trap (core dumped)"
        );
    }

    #[test]
    fn signals_outside_the_table_print_their_number() {
        assert_eq!(signal_name(GoOs::Linux, 0), "signal 0");
        assert_eq!(signal_name(GoOs::Darwin, 32), "signal 32");
        assert_eq!(signal_name(GoOs::Linux, 34), "signal 34");
        assert_eq!(signal_name(GoOs::Linux, -1), "signal -1");
    }

    /// Go's own tables: the Darwin one by executing `syscall.Signal.String`
    /// for 0..=40, the Linux one extracted from the pinned toolchain's sources
    /// (amd64 and arm64 agree), both recorded in `get_clipboard_darwin.json`.
    #[test]
    fn tables_equal_the_go_recordings() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/port/platform/get_clipboard_darwin.json"
        ))
        .unwrap();
        let darwin = fixture["darwin_signal_names_executed"].as_object().unwrap();
        assert_eq!(darwin.len(), 41);
        for (number, name) in darwin {
            assert_eq!(
                signal_name(GoOs::Darwin, number.parse().unwrap()),
                name.as_str().unwrap(),
                "darwin signal {number}"
            );
        }
        let linux = fixture["linux_signal_names_extracted_not_executed"]
            .as_object()
            .unwrap();
        assert_eq!(linux.len(), 31);
        for (number, name) in linux {
            assert_eq!(
                signal_name(GoOs::Linux, number.parse().unwrap()),
                name.as_str().unwrap(),
                "linux signal {number}"
            );
        }
    }

    #[test]
    fn the_two_tables_disagree_where_go_does() {
        assert_eq!(signal_name(GoOs::Darwin, 10), "bus error");
        assert_eq!(signal_name(GoOs::Linux, 10), "user defined signal 1");
        assert_eq!(signal_name(GoOs::Darwin, 15), signal_name(GoOs::Linux, 15));
    }
}
