//! Command-line desktop adapters for Linux and Windows (PLATFORM-001).
//!
//! These are the Rust counterparts of the Go code paths that shell out to
//! desktop tools:
//!
//! * [`CommandClipboard`] mirrors the tool selection of `atotto/clipboard`
//!   (the backend behind Go's `internal/clipboard` on Linux): `wl-copy` /
//!   `wl-paste` under Wayland, then `xclip`, `xsel`, the Termux pair and
//!   finally `clip.exe` + `powershell.exe`.
//! * [`LinuxAutotype`] mirrors `internal/autotype/autotype_linux.go`: text goes
//!   to `xdotool`, `wtype` or `ydotool` on stdin, never in argv, behind the same
//!   focus guard.
//! * [`WindowsAutotype`] mirrors `autotype_windows.go`: SendKeys-escaped text on
//!   the stdin of a fixed PowerShell wrapper.
//!
//! Every effect goes through [`DesktopHost`], so selection, argv, stdin routing
//! and error text are testable without a display. [`SystemHost`] is the real
//! implementation. Nothing here claims native desktop behavior: whether a tool
//! actually types or copies on a live session is outside what these tests prove.

use crate::focus;
use crate::{Autotype, Clipboard, PlatformError, PlatformErrorKind};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// Environment variable that turns an unavailable focus probe into a refusal.
pub const STRICT_FOCUS_ENV: &str = "SYMVAULT_AUTOTYPE_STRICT_FOCUS";

/// Go `secrets.DefaultWhitelist`: the only variables passed to autotype tools.
pub const AUTOTYPE_ENV_WHITELIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "SHELL",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "XAUTHORITY",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_LAUNCHER",
    "GNUPGHOME",
];

/// `atotto/clipboard`'s `missingCommands` error text.
pub const MISSING_CLIPBOARD_COMMANDS: &str = "No clipboard utilities available. Please install xsel, xclip, wl-clipboard or Termux:API add-on for termux-clipboard-get/set.";

/// PowerShell wrapper from `autotype_windows.go` (`readSendKeysWrapper`).
pub const SEND_KEYS_WRAPPER: &str = "$ErrorActionPreference = 'Stop';\n$text = [System.Console]::In.ReadToEnd();\n$wshell = New-Object -ComObject WScript.Shell;\n$wshell.SendKeys($text);";

/// PowerShell foreground-process probe from `focus_windows.go`.
pub const FOREGROUND_PROBE: &str = "Add-Type @\"\nusing System;\nusing System.Runtime.InteropServices;\npublic class W { [DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow();\n                 [DllImport(\"user32.dll\")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid); }\n\"@;\n$h = [W]::GetForegroundWindow();\n[int]$pid = 0;\n[void][W]::GetWindowThreadProcessId($h, [ref]$pid);\n$p = Get-Process -Id $pid -ErrorAction SilentlyContinue;\nif ($p) { $p.ProcessName }";

const WAYLAND_INSTALL_HINT: &str = "autotype: Wayland session detected but neither `wtype` nor `ydotool` is installed.\nInstall one of them:\n  Debian/Ubuntu: sudo apt install wtype  (or sudo apt install ydotool)\n  Arch:          sudo pacman -S wtype     (or ydotool)\n  Fedora:        sudo dnf install wtype   (or ydotool)\n`symvault doctor` will warn about this on every run until one is available";

/// Escapes text for an AppleScript `keystroke "…"` literal (Go
/// `escapeAppleScriptString`). The Rust macOS adapter drives JXA instead and
/// does not call this; it is kept so the Go behavior stays pinned.
#[must_use]
pub fn escape_apple_script_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Escapes text for `WScript.Shell.SendKeys` (Go `escapeSendKeysString`).
#[must_use]
pub fn escape_send_keys_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '+' | '^' | '%' | '~' | '{' | '}' | '[' | ']') {
            out.push('{');
            out.push(ch);
            out.push('}');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Deadline of one macOS pasteboard tool run (`pbcopy`/`pbpaste`), the same
/// 30 s the previous native adapter used. Go's atotto has none.
pub const PASTEBOARD_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a bounded run looks at its child and pipes.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Which environment a spawned tool receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvPolicy {
    /// Everything the host process has (atotto's clipboard commands).
    Inherit,
    /// [`AUTOTYPE_ENV_WHITELIST`] only (Go `secrets.PrepareCmd`).
    Whitelist,
    /// `PATH`, `HOME`, `LANG`, `LC_*` and `__CF_USER_TEXT_ENCODING` only: what
    /// `pbcopy`/`pbpaste` need to resolve and encode text. Go's atotto passes
    /// everything; a pasteboard tool gets no credential-bearing variable here
    /// (declared deviation, as the previous native adapter's `env_clear`).
    Pasteboard,
}

impl EnvPolicy {
    fn passes(self, name: &str) -> bool {
        match self {
            Self::Inherit => true,
            Self::Whitelist => AUTOTYPE_ENV_WHITELIST.contains(&name),
            Self::Pasteboard => {
                matches!(name, "PATH" | "HOME" | "LANG" | "__CF_USER_TEXT_ENCODING")
                    || name.starts_with("LC_")
            }
        }
    }
}

/// Result of one tool invocation that started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolOutput {
    /// Exit code, or `None` when the tool was ended by a signal.
    pub code: Option<i32>,
    /// Captured stdout when requested, otherwise empty.
    pub stdout: Vec<u8>,
    /// The signal that ended the tool, when it did not exit by itself (Go's
    /// `signal: <name>` text needs it).
    pub signal: Option<i32>,
    /// Whether that signal left a core dump (Go appends ` (core dumped)`).
    pub core_dumped: bool,
}

impl ToolOutput {
    fn from_status(status: std::process::ExitStatus, stdout: Vec<u8>) -> Self {
        #[cfg(unix)]
        let (signal, core_dumped) = {
            use std::os::unix::process::ExitStatusExt;
            (status.signal(), status.core_dumped())
        };
        #[cfg(not(unix))]
        let (signal, core_dumped) = (None, false);
        Self {
            code: status.code(),
            stdout,
            signal,
            core_dumped,
        }
    }

    /// The result of a run that was killed at its deadline: SIGKILL on Unix
    /// (`signal: killed`), `TerminateProcess`'s exit code 1 elsewhere.
    fn killed() -> Self {
        Self {
            #[cfg(unix)]
            code: None,
            #[cfg(unix)]
            signal: Some(9),
            #[cfg(not(unix))]
            code: Some(1),
            #[cfg(not(unix))]
            signal: None,
            stdout: Vec::new(),
            core_dumped: false,
        }
    }

    /// Go's `*exec.ExitError` text for this result.
    fn status_text(&self) -> String {
        crate::go_exec::exit_status_text(
            crate::go_exec::GoOs::host(),
            self.code,
            self.signal,
            self.core_dumped,
        )
    }
}

/// Everything the adapters need from the machine they run on.
pub trait DesktopHost: Send + Sync {
    /// Value of an environment variable of the host process.
    fn env_var(&self, name: &str) -> Option<String>;
    /// Whether `name` resolves to an executable on the host's search path
    /// (Go `exec.LookPath`).
    fn tool_exists(&self, name: &str) -> bool;
    /// Runs `program` with `args`, writing `stdin`. A spawn failure is an `Err`
    /// with the OS message; a non-zero exit is an `Ok` with its code.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
        capture_stdout: bool,
        env: EnvPolicy,
    ) -> Result<ToolOutput, String>;

    /// Go atotto's `writeAll`: start `program`, write `stdin` to its pipe on
    /// the calling thread, close it and wait. Unlike [`DesktopHost::run`]
    /// (Go `exec.Cmd.Stdin`, which ignores a closed pipe), a failed stdin write
    /// is returned at once, as `write |1: <reason>`, without waiting for the
    /// tool, so a tool that exits 0 without reading a payload larger than the
    /// pipe buffer is still a copy failure. A host with a deadline
    /// ([`SystemHost::with_timeout`]) kills the tool when it expires. The
    /// default delegates to `run` for hosts that have no real pipe.
    fn run_write_all(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
        env: EnvPolicy,
    ) -> Result<ToolOutput, String> {
        self.run(program, args, stdin, false, env)
    }
}

/// Outcome of a Go `exec.LookPath`-style search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// An executable reached through an absolute path.
    Found(PathBuf),
    /// The first executable hit came from a relative or empty `PATH` entry.
    /// Go returns `exec.ErrDot` (`cannot run executable found relative to
    /// current directory`) and does not keep searching later entries.
    RelativeToCwd,
    /// Nothing executable was found.
    NotFound,
}

/// `filepath.SplitList` for the platform: an empty `PATH` yields **no**
/// entries (Rust's `split_paths("")` would yield one empty entry, which then
/// resolves to the working directory).
#[must_use]
pub fn go_split_list(value: &std::ffi::OsStr) -> Vec<PathBuf> {
    if value.is_empty() {
        Vec::new()
    } else {
        std::env::split_paths(value).collect()
    }
}

/// The real host. An explicit search path and environment make it usable in
/// disposable test roots without mutating the test process; an explicit working
/// directory stands in for the process cwd when relative `PATH` entries are
/// exercised.
#[derive(Clone, Debug, Default)]
pub struct SystemHost {
    path: Option<Vec<PathBuf>>,
    env: Option<HashMap<String, String>>,
    cwd: Option<PathBuf>,
    /// Deadline of every tool run. `None` waits for ever, like atotto; a
    /// bounded host also starts each tool in its own process group so that an
    /// expired run can be killed as a whole.
    timeout: Option<Duration>,
}

impl SystemHost {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A host that sees exactly `env` and resolves tools in `path`.
    #[must_use]
    pub fn isolated(path: Vec<PathBuf>, env: HashMap<String, String>) -> Self {
        Self {
            path: Some(path),
            env: Some(env),
            cwd: None,
            timeout: None,
        }
    }

    /// A host that keeps the process environment but resolves tools only in
    /// `path`: the system tools a native adapter wants, however `PATH` is set.
    #[must_use]
    pub fn with_search_path(path: Vec<PathBuf>) -> Self {
        Self {
            path: Some(path),
            env: None,
            cwd: None,
            timeout: None,
        }
    }

    /// The real macOS pasteboard tools: looked up in `/usr/bin` only (so a
    /// planted `pbcopy` earlier on `PATH` never receives a secret) and bounded
    /// by [`PASTEBOARD_TIMEOUT`].
    #[must_use]
    pub fn pasteboard() -> Self {
        Self::with_search_path(vec![PathBuf::from("/usr/bin")]).with_timeout(PASTEBOARD_TIMEOUT)
    }

    /// Bounds every run of this host. When the deadline passes, the tool's
    /// whole process group is killed and reaped and the run reports Go's text
    /// for a killed child (`signal: killed`; non-Unix: `exit status 1`).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Resolves relative `PATH` entries against, and spawns tools in, `cwd`
    /// instead of the process working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    fn search_path(&self) -> Vec<PathBuf> {
        match &self.path {
            Some(path) => path.clone(),
            None => std::env::var_os("PATH")
                .map(|value| go_split_list(&value))
                .unwrap_or_default(),
        }
    }

    fn on_disk(&self, candidate: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) if candidate.is_relative() => cwd.join(candidate),
            _ => candidate.to_path_buf(),
        }
    }

    /// Go `exec.LookPath` on Unix: the first executable hit wins; if it is
    /// reached through a relative (or empty, i.e. ".") entry the lookup is an
    /// `ErrDot` error rather than a hit.
    fn lookup(&self, name: &str) -> Lookup {
        if name.contains(std::path::MAIN_SEPARATOR) {
            return if is_executable(&self.on_disk(Path::new(name))) {
                Lookup::Found(PathBuf::from(name))
            } else {
                Lookup::NotFound
            };
        }
        for dir in self.search_path() {
            let dir = if dir.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                dir
            };
            let candidate = dir.join(name);
            if is_executable(&self.on_disk(&candidate)) {
                return if candidate.is_absolute() {
                    Lookup::Found(candidate)
                } else {
                    Lookup::RelativeToCwd
                };
            }
        }
        Lookup::NotFound
    }

    fn base_env(&self) -> Vec<(String, String)> {
        match &self.env {
            Some(env) => env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            // Non-UTF-8 names or values are dropped (Go passes raw bytes
            // through). Documented residual: no tool this adapter spawns needs
            // them.
            None => std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect(),
        }
    }

    /// Spawns `program` with the host's environment policy, a piped stdin, and
    /// stdout piped or discarded; stderr is always discarded.
    fn spawn_piped(
        &self,
        program: &str,
        args: &[&str],
        capture_stdout: bool,
        env: EnvPolicy,
    ) -> Result<std::process::Child, String> {
        let resolved = match self.lookup(program) {
            Lookup::Found(path) => path,
            Lookup::RelativeToCwd => {
                return Err(format!(
                    "exec: \"{program}\": cannot run executable found relative to current directory"
                ));
            }
            Lookup::NotFound => {
                return Err(format!(
                    "exec: \"{program}\": executable file not found in $PATH"
                ));
            }
        };
        let mut command = Command::new(self.on_disk(&resolved));
        command.args(args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        command.env_clear();
        let base = self.base_env();
        let mut passed: Vec<(String, String)> = base
            .iter()
            .filter(|(key, _)| env.passes(key))
            .cloned()
            .collect();
        if env == EnvPolicy::Whitelist {
            let systemroot = base
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("SYSTEMROOT"))
                .map(|(_, v)| v.clone());
            add_critical_env(&mut passed, systemroot, cfg!(windows));
        }
        command.envs(passed);
        command
            .stdin(Stdio::piped())
            .stdout(if capture_stdout {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::null());
        #[cfg(unix)]
        if self.timeout.is_some() {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().map_err(|error| error.to_string())
    }

    /// Drives a spawned tool to its end: writes `stdin` and reads stdout on
    /// helper threads and polls the child, so nothing here can block past the
    /// host's deadline. With `write_all` (atotto `writeAll`) a failed stdin
    /// write is returned at once as Go's `write |1: <reason>` and the tool is
    /// not waited for; otherwise (`exec.Cmd.Stdin`) it is ignored. A run that
    /// outlives the deadline kills the tool's process group and reaps it.
    fn drive(
        &self,
        mut child: std::process::Child,
        stdin: &[u8],
        capture_stdout: bool,
        write_all: bool,
    ) -> Result<ToolOutput, String> {
        let deadline = self.timeout.and_then(|t| Instant::now().checked_add(t));
        let own_group = deadline.is_some();
        let (write_tx, write_rx) = mpsc::channel::<std::io::Result<()>>();
        if let Some(mut pipe) = child.stdin.take() {
            let data = stdin.to_vec();
            std::thread::spawn(move || {
                let result = pipe.write_all(&data);
                // Close the tool's stdin before reporting.
                drop(pipe);
                let _ = write_tx.send(result);
            });
        }
        let read_rx = if capture_stdout {
            child.stdout.take().map(|mut pipe| {
                let (tx, rx) = mpsc::channel::<Vec<u8>>();
                std::thread::spawn(move || {
                    let mut buffer = Vec::new();
                    let _ = pipe.read_to_end(&mut buffer);
                    let _ = tx.send(buffer);
                });
                rx
            })
        } else {
            None
        };
        let (mut write_done, mut status, mut stdout) = (false, None, None);
        loop {
            if !write_done {
                match write_rx.try_recv() {
                    Ok(Ok(())) | Err(mpsc::TryRecvError::Disconnected) => write_done = true,
                    Ok(Err(error)) => {
                        if write_all {
                            reap_later(child, deadline, own_group);
                            return Err(go_pipe_write_error(&error));
                        }
                        write_done = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if status.is_none() {
                match child.try_wait() {
                    Ok(found) => status = found,
                    Err(error) => {
                        kill_and_reap(&mut child, own_group);
                        return Err(error.to_string());
                    }
                }
            }
            if stdout.is_none() {
                stdout = match &read_rx {
                    None => Some(Vec::new()),
                    Some(rx) => match rx.try_recv() {
                        Ok(bytes) => Some(bytes),
                        Err(mpsc::TryRecvError::Disconnected) => Some(Vec::new()),
                        Err(mpsc::TryRecvError::Empty) => None,
                    },
                };
            }
            if let (Some(status), true, Some(stdout)) = (status, write_done, stdout.as_mut()) {
                return Ok(ToolOutput::from_status(status, std::mem::take(stdout)));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                kill_and_reap(&mut child, own_group);
                return Ok(ToolOutput::killed());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// Kills the tool (and, when it leads its own process group, everything it
/// started) and reaps it. A killed child's `wait` returns at once.
fn kill_and_reap(child: &mut std::process::Child, own_group: bool) {
    #[cfg(unix)]
    if own_group
        && let Some(pid) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = own_group;
    let _ = child.kill();
    let _ = child.wait();
}

/// Hands a tool whose stdin write failed to a thread that reaps it: when it
/// ends by itself, or at the deadline by a kill. Without a deadline it waits
/// as long as the tool lives, like Go's leaked process.
fn reap_later(mut child: std::process::Child, deadline: Option<Instant>, own_group: bool) {
    std::thread::spawn(move || {
        let Some(deadline) = deadline else {
            let _ = child.wait();
            return;
        };
        loop {
            match child.try_wait() {
                Ok(None) => {}
                Ok(Some(_)) | Err(_) => return,
            }
            if Instant::now() >= deadline {
                kill_and_reap(&mut child, own_group);
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    });
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Go's `exec` re-adds `SYSTEMROOT` on Windows when `cmd.Env` is set without
/// it (`addCriticalEnv`); the value is the host's, possibly empty.
fn add_critical_env(
    env: &mut Vec<(String, String)>,
    host_systemroot: Option<String>,
    windows: bool,
) {
    if !windows
        || env
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("SYSTEMROOT"))
    {
        return;
    }
    env.push(("SYSTEMROOT".to_owned(), host_systemroot.unwrap_or_default()));
}

impl DesktopHost for SystemHost {
    fn env_var(&self, name: &str) -> Option<String> {
        match &self.env {
            Some(env) => env.get(name).cloned(),
            None => std::env::var(name).ok(),
        }
    }

    fn tool_exists(&self, name: &str) -> bool {
        matches!(self.lookup(name), Lookup::Found(_))
    }

    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
        capture_stdout: bool,
        env: EnvPolicy,
    ) -> Result<ToolOutput, String> {
        let child = self.spawn_piped(program, args, capture_stdout, env)?;
        self.drive(child, stdin, capture_stdout, false)
    }

    fn run_write_all(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
        env: EnvPolicy,
    ) -> Result<ToolOutput, String> {
        let child = self.spawn_piped(program, args, false, env)?;
        self.drive(child, stdin, false, true)
    }
}

/// Go's `*os.PathError` text for a failed write to the pipe `os.Pipe` made for
/// `exec.Cmd.StdinPipe` (`write |1: broken pipe`): the pipe's write end is
/// named `|1` and `syscall.Errno` prints its lowercase message.
fn go_pipe_write_error(error: &std::io::Error) -> String {
    let reason = if error.kind() == std::io::ErrorKind::BrokenPipe {
        "broken pipe".to_owned()
    } else {
        let text = error.to_string();
        let text = text.split(" (os error").next().unwrap_or(&text);
        text.to_lowercase()
    };
    format!("write |1: {reason}")
}

fn failed(message: impl Into<String>) -> PlatformError {
    PlatformError {
        kind: PlatformErrorKind::Failed,
        message: message.into(),
    }
}

fn run_checked(
    host: &dyn DesktopHost,
    program: &str,
    args: &[&str],
    stdin: &[u8],
    env: EnvPolicy,
) -> Result<(), String> {
    let output = host.run(program, args, stdin, false, env)?;
    if output.code == Some(0) {
        Ok(())
    } else {
        Err(output.status_text())
    }
}

/// [`run_checked`] with atotto `writeAll` semantics (see
/// [`DesktopHost::run_write_all`]).
fn run_write_all_checked(
    host: &dyn DesktopHost,
    program: &str,
    args: &[&str],
    stdin: &[u8],
    env: EnvPolicy,
) -> Result<(), String> {
    let output = host.run_write_all(program, args, stdin, env)?;
    if output.code == Some(0) {
        Ok(())
    } else {
        Err(output.status_text())
    }
}

// ---------------------------------------------------------------- clipboard

/// One resolved copy/paste tool pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardBackend {
    pub copy: &'static [&'static str],
    pub paste: &'static [&'static str],
    /// `clip.exe`/`powershell.exe` output ends in CRLF; atotto drops the last
    /// two bytes of any paste longer than one byte.
    pub trim_dos: bool,
}

const WL: ClipboardBackend = ClipboardBackend {
    copy: &["wl-copy"],
    paste: &["wl-paste", "--no-newline"],
    trim_dos: false,
};
const XCLIP: ClipboardBackend = ClipboardBackend {
    copy: &["xclip", "-in", "-selection", "clipboard"],
    paste: &["xclip", "-out", "-selection", "clipboard"],
    trim_dos: false,
};
const XSEL: ClipboardBackend = ClipboardBackend {
    copy: &["xsel", "--input", "--clipboard"],
    paste: &["xsel", "--output", "--clipboard"],
    trim_dos: false,
};
const TERMUX: ClipboardBackend = ClipboardBackend {
    copy: &["termux-clipboard-set"],
    paste: &["termux-clipboard-get"],
    trim_dos: false,
};
const WINDOWS_EXE: ClipboardBackend = ClipboardBackend {
    copy: &["clip.exe"],
    paste: &["powershell.exe", "Get-Clipboard"],
    trim_dos: true,
};

/// atotto/clipboard `init()` selection order. `None` is its `Unsupported`.
#[must_use]
pub fn select_clipboard_backend(host: &dyn DesktopHost) -> Option<ClipboardBackend> {
    let wayland = host
        .env_var("WAYLAND_DISPLAY")
        .is_some_and(|v| !v.is_empty());
    if wayland && host.tool_exists("wl-copy") && host.tool_exists("wl-paste") {
        return Some(WL);
    }
    if host.tool_exists("xclip") {
        return Some(XCLIP);
    }
    if host.tool_exists("xsel") {
        return Some(XSEL);
    }
    if host.tool_exists("termux-clipboard-set") && host.tool_exists("termux-clipboard-get") {
        return Some(TERMUX);
    }
    if host.tool_exists("clip.exe") && host.tool_exists("powershell.exe") {
        return Some(WINDOWS_EXE);
    }
    None
}

/// Text clipboard backed by external tools, selected once at construction as
/// atotto does at process start.
pub struct CommandClipboard {
    host: Arc<dyn DesktopHost>,
    backend: Option<ClipboardBackend>,
}

impl CommandClipboard {
    #[must_use]
    pub fn new(host: Arc<dyn DesktopHost>) -> Self {
        let backend = select_clipboard_backend(host.as_ref());
        Self { host, backend }
    }

    #[must_use]
    pub fn backend(&self) -> Option<&ClipboardBackend> {
        self.backend.as_ref()
    }

    fn backend_or_unavailable(&self) -> Result<&ClipboardBackend, PlatformError> {
        self.backend
            .as_ref()
            .ok_or_else(|| PlatformError::unavailable(MISSING_CLIPBOARD_COMMANDS))
    }

    /// Reads the clipboard (Go `Clipboard.Read`), including atotto's
    /// unconditional two-byte CRLF trim for the Windows tools.
    pub fn read(&self) -> Result<Vec<u8>, PlatformError> {
        let backend = self.backend_or_unavailable()?;
        let output = self
            .host
            .run(
                backend.paste[0],
                &backend.paste[1..],
                b"",
                true,
                EnvPolicy::Inherit,
            )
            .map_err(failed)?;
        if output.code != Some(0) {
            return Err(failed(output.status_text()));
        }
        let mut text = output.stdout;
        if backend.trim_dos && text.len() > 1 {
            text.truncate(text.len() - 2);
        }
        Ok(text)
    }
}

impl Clipboard for CommandClipboard {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
        let backend = self.backend_or_unavailable()?;
        run_write_all_checked(
            self.host.as_ref(),
            backend.copy[0],
            &backend.copy[1..],
            text,
            EnvPolicy::Inherit,
        )
        .map_err(failed)
    }

    fn clear(&self) -> Result<(), PlatformError> {
        self.set(b"")
    }
}

/// Go's macOS `clipboard.DefaultClipboard()`: atotto/clipboard v0.1.4 runs
/// `pbcopy` (text on stdin, `writeAll` semantics) and `pbpaste` (stdout is the
/// text) and reports the raw `os/exec` error text, e.g. `exit status 3`,
/// `signal: killed`, `write |1: broken pipe` or `exec: "pbcopy": executable
/// file not found in $PATH`. There is no tool selection, like atotto.
///
/// Two declared deviations: the tools get [`EnvPolicy::Pasteboard`] instead of
/// the whole environment, and the real host ([`SystemHost::pasteboard`])
/// bounds each run by [`PASTEBOARD_TIMEOUT`] (atotto never gives up on a hung
/// tool, which would freeze `get --clip`, MCP, the TUI and the auto-clear): a
/// run that expires kills the tool's process group, reaps it and reports
/// `signal: killed`, the text Go prints for a killed child.
pub struct PasteboardClipboard {
    host: Arc<dyn DesktopHost>,
}

impl PasteboardClipboard {
    #[must_use]
    pub fn new(host: Arc<dyn DesktopHost>) -> Self {
        Self { host }
    }

    /// The real macOS pasteboard tools. Unlike Go, which resolves `pbcopy`
    /// through `PATH`, they are looked up in `/usr/bin` only, so a planted
    /// `pbcopy` earlier on `PATH` never receives a secret, and every run is
    /// bounded (see [`SystemHost::pasteboard`]).
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(SystemHost::pasteboard()))
    }

    /// Reads the pasteboard (Go `Clipboard.Read`).
    pub fn read(&self) -> Result<Vec<u8>, PlatformError> {
        let output = self
            .host
            .run("pbpaste", &[], b"", true, EnvPolicy::Pasteboard)
            .map_err(failed)?;
        if output.code != Some(0) {
            return Err(failed(output.status_text()));
        }
        Ok(output.stdout)
    }
}

impl Clipboard for PasteboardClipboard {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
        run_write_all_checked(
            self.host.as_ref(),
            "pbcopy",
            &[],
            text,
            EnvPolicy::Pasteboard,
        )
        .map_err(failed)
    }

    fn clear(&self) -> Result<(), PlatformError> {
        self.set(b"")
    }
}

// ----------------------------------------------------------------- autotype

fn strict_focus(host: &dyn DesktopHost) -> String {
    host.env_var(STRICT_FOCUS_ENV).unwrap_or_default()
}

/// Linux autotype through `xdotool` (X11) or `wtype`/`ydotool` (Wayland).
pub struct LinuxAutotype {
    host: Arc<dyn DesktopHost>,
}

impl LinuxAutotype {
    #[must_use]
    pub fn new(host: Arc<dyn DesktopHost>) -> Self {
        Self { host }
    }

    fn wayland(&self) -> bool {
        self.host
            .env_var("WAYLAND_DISPLAY")
            .is_some_and(|v| !v.is_empty())
    }

    /// Go `defaultCaptureActiveWindow` for Linux.
    fn capture_active_window(&self) -> Result<String, PlatformError> {
        if self.wayland() || !self.host.tool_exists("xdotool") {
            return Err(focus::unavailable());
        }
        let output = self
            .host
            .run(
                "xdotool",
                &["getactivewindow", "getwindowclassname"],
                b"",
                true,
                EnvPolicy::Whitelist,
            )
            .map_err(|_| focus::unavailable())?;
        if output.code != Some(0) {
            return Err(focus::unavailable());
        }
        Ok(format!(
            "wmclass:{}",
            String::from_utf8_lossy(&output.stdout).trim()
        ))
    }

    fn type_x11(&self, text: &str) -> Result<(), PlatformError> {
        if !self.host.tool_exists("xdotool") {
            return Err(PlatformError::unavailable(
                "autotype failed: xdotool not installed",
            ));
        }
        run_checked(
            self.host.as_ref(),
            "xdotool",
            &["type", "--clearmodifiers", "--delay", "0", "--file", "-"],
            text.as_bytes(),
            EnvPolicy::Whitelist,
        )
        .map_err(|error| {
            failed(format!(
                "autotype failed (xdotool may not be installed or display not available): {error}"
            ))
        })
    }

    fn type_wayland(&self, text: &str) -> Result<(), PlatformError> {
        if self.host.tool_exists("wtype") {
            return run_checked(
                self.host.as_ref(),
                "wtype",
                &["-"],
                text.as_bytes(),
                EnvPolicy::Whitelist,
            )
            .map_err(|error| failed(format!("autotype failed (wtype): {error}")));
        }
        if self.host.tool_exists("ydotool") {
            return run_checked(
                self.host.as_ref(),
                "ydotool",
                &["type", "--file", "/dev/stdin"],
                text.as_bytes(),
                EnvPolicy::Whitelist,
            )
            .map_err(|error| failed(format!("autotype failed (ydotool): {error}")));
        }
        Err(PlatformError::unavailable(WAYLAND_INSTALL_HINT))
    }
}

impl Autotype for LinuxAutotype {
    fn type_text(&self, text: &str) -> Result<(), PlatformError> {
        focus::guard(&strict_focus(self.host.as_ref()), || {
            self.capture_active_window()
        })?;
        if self.wayland() {
            self.type_wayland(text)
        } else {
            self.type_x11(text)
        }
    }
}

/// Windows autotype through a fixed PowerShell wrapper reading stdin.
pub struct WindowsAutotype {
    host: Arc<dyn DesktopHost>,
}

impl WindowsAutotype {
    #[must_use]
    pub fn new(host: Arc<dyn DesktopHost>) -> Self {
        Self { host }
    }

    /// Go `defaultCaptureActiveWindow` for Windows.
    fn capture_active_window(&self) -> Result<String, PlatformError> {
        let output = self
            .host
            .run(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    FOREGROUND_PROBE,
                ],
                b"",
                true,
                EnvPolicy::Whitelist,
            )
            .map_err(|_| focus::unavailable())?;
        if output.code != Some(0) {
            return Err(focus::unavailable());
        }
        let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if name.is_empty() {
            return Err(focus::unavailable());
        }
        Ok(format!("process:{name}"))
    }
}

impl Autotype for WindowsAutotype {
    fn type_text(&self, text: &str) -> Result<(), PlatformError> {
        focus::guard(&strict_focus(self.host.as_ref()), || {
            self.capture_active_window()
        })?;
        let escaped = escape_send_keys_string(text);
        run_checked(
            self.host.as_ref(),
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                SEND_KEYS_WRAPPER,
            ],
            escaped.as_bytes(),
            EnvPolicy::Whitelist,
        )
        .map_err(|error| failed(format!("autotype failed: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type RecordedCall = (String, Vec<String>, Vec<u8>, EnvPolicy);

    #[derive(Default)]
    struct Recorder {
        tools: Vec<&'static str>,
        env: Vec<(&'static str, &'static str)>,
        code: Option<i32>,
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl DesktopHost for Recorder {
        fn env_var(&self, name: &str) -> Option<String> {
            self.env
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
        fn tool_exists(&self, name: &str) -> bool {
            self.tools.contains(&name)
        }
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: &[u8],
            _capture: bool,
            env: EnvPolicy,
        ) -> Result<ToolOutput, String> {
            self.calls.lock().unwrap().push((
                program.to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
                stdin.to_vec(),
                env,
            ));
            Ok(ToolOutput {
                code: self.code.or(Some(0)),
                stdout: b"firefox\n".to_vec(),
                ..ToolOutput::default()
            })
        }
    }

    #[test]
    fn secrets_never_reach_argv_and_clipboard_inherits_env() {
        let host = Arc::new(Recorder {
            tools: vec!["xclip"],
            ..Recorder::default()
        });
        let clipboard = CommandClipboard::new(host.clone());
        clipboard.set(b"hunter2-supersecret").unwrap();
        let calls = host.calls.lock().unwrap();
        assert_eq!(calls[0].0, "xclip");
        assert!(
            calls[0]
                .1
                .iter()
                .all(|arg| !arg.contains("hunter2-supersecret"))
        );
        assert_eq!(calls[0].2, b"hunter2-supersecret");
        assert_eq!(calls[0].3, EnvPolicy::Inherit);
    }

    #[test]
    fn autotype_tools_get_the_whitelisted_environment_only() {
        let host = Arc::new(Recorder {
            tools: vec!["wtype"],
            env: vec![("WAYLAND_DISPLAY", "wayland-0")],
            ..Recorder::default()
        });
        LinuxAutotype::new(host.clone())
            .type_text("hunter2")
            .unwrap();
        let calls = host.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].3, EnvPolicy::Whitelist);
    }

    #[test]
    fn critical_env_readds_systemroot_only_on_windows_when_absent() {
        let mut env = vec![("PATH".to_owned(), "x".to_owned())];
        add_critical_env(&mut env, Some("C:\\Windows".to_owned()), false);
        assert_eq!(env.len(), 1, "non-Windows must not add anything");
        add_critical_env(&mut env, Some("C:\\Windows".to_owned()), true);
        assert_eq!(env[1], ("SYSTEMROOT".to_owned(), "C:\\Windows".to_owned()));
        add_critical_env(&mut env, Some("other".to_owned()), true);
        assert_eq!(env.len(), 2, "already present");
        let mut lower = vec![("SystemRoot".to_owned(), "a".to_owned())];
        add_critical_env(&mut lower, None, true);
        assert_eq!(lower.len(), 1, "case-insensitive match like Go EqualFold");
        let mut empty = Vec::new();
        add_critical_env(&mut empty, None, true);
        assert_eq!(empty, [("SYSTEMROOT".to_owned(), String::new())]);
    }

    #[test]
    fn go_split_list_has_no_entries_for_an_empty_path() {
        use std::ffi::OsStr;
        assert!(go_split_list(OsStr::new("")).is_empty());
        #[cfg(unix)]
        assert_eq!(
            go_split_list(OsStr::new(":/bin")),
            [PathBuf::new(), PathBuf::from("/bin")]
        );
    }

    #[test]
    fn windows_autotype_escapes_sendkeys_and_keeps_text_off_argv() {
        let host = Arc::new(Recorder::default());
        WindowsAutotype::new(host.clone())
            .type_text("p+a^s%s~{w}[o]rd")
            .unwrap();
        let calls = host.calls.lock().unwrap();
        // Two probes in the focus guard, then the typing call.
        let typing = calls.last().unwrap();
        assert_eq!(typing.0, "powershell.exe");
        assert_eq!(typing.1[3], SEND_KEYS_WRAPPER);
        assert_eq!(
            String::from_utf8(typing.2.clone()).unwrap(),
            "p{+}a{^}s{%}s{~}{{}w{}}{[}o{]}rd"
        );
        assert!(typing.1.iter().all(|arg| !arg.contains("p+a^s")));
    }

    #[test]
    fn windows_focus_probe_unavailable_is_lenient_and_strict_refuses() {
        struct NoProbe;
        impl DesktopHost for NoProbe {
            fn env_var(&self, name: &str) -> Option<String> {
                (name == STRICT_FOCUS_ENV).then(|| "1".to_owned())
            }
            fn tool_exists(&self, _: &str) -> bool {
                false
            }
            fn run(
                &self,
                _: &str,
                _: &[&str],
                _: &[u8],
                _: bool,
                _: EnvPolicy,
            ) -> Result<ToolOutput, String> {
                Ok(ToolOutput {
                    code: Some(1),
                    stdout: Vec::new(),
                    ..ToolOutput::default()
                })
            }
        }
        let error = WindowsAutotype::new(Arc::new(NoProbe))
            .type_text("x")
            .unwrap_err();
        assert_eq!(error.kind, PlatformErrorKind::Unavailable);
    }

    #[test]
    fn pasteboard_host_is_bounded_and_its_environment_is_narrow() {
        assert_eq!(SystemHost::pasteboard().timeout, Some(PASTEBOARD_TIMEOUT));
        assert_eq!(SystemHost::new().timeout, None);
        for name in [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "__CF_USER_TEXT_ENCODING",
        ] {
            assert!(EnvPolicy::Pasteboard.passes(name), "{name}");
        }
        for name in [
            "SYMVAULT_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "TMPDIR",
            "LCX",
        ] {
            assert!(!EnvPolicy::Pasteboard.passes(name), "{name}");
        }
    }

    #[test]
    fn pipe_write_errors_use_go_os_patherror_text() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            go_pipe_write_error(&Error::from(ErrorKind::BrokenPipe)),
            "write |1: broken pipe"
        );
        // `syscall.Errno` prints the lowercase message without Rust's suffix.
        assert_eq!(
            go_pipe_write_error(&Error::from_raw_os_error(28)),
            "write |1: no space left on device"
        );
    }

    /// atotto's `writeAll` returns the stdin write error (the tool is never
    /// waited for), while a tool run through `exec.Cmd.Stdin` (`run`, used by
    /// autotype) ignores a closed pipe and reports the exit status. Go's own
    /// capture of the clipboard side is in `copy-clipboard-linux.json` and
    /// `get_clipboard_linux.json` (`large_payload_tool_closes_stdin_*`).
    #[cfg(unix)]
    #[test]
    fn write_all_reports_a_closed_stdin_but_run_does_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("symvault-write-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("closer");
        std::fs::write(&tool, "#!/bin/sh\nexec 0<&-\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
        let host = SystemHost::isolated(vec![dir.clone()], HashMap::new());
        // Far above any pipe buffer, so the write cannot finish before the
        // tool closes its end.
        let payload = vec![b'x'; 4 * 1024 * 1024];
        let copied = host.run_write_all("closer", &[], &payload, EnvPolicy::Inherit);
        let ran = host.run("closer", &[], &payload, false, EnvPolicy::Inherit);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(copied.unwrap_err(), "write |1: broken pipe");
        assert_eq!(ran.unwrap().code, Some(0));
    }
}
