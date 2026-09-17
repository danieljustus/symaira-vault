use crate::offline::{NETWORK_MESSAGE, PushError, is_offline_error};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};
#[cfg(not(windows))]
use std::{thread, time::Instant};
use thiserror::Error;

pub const DEFAULT_GITIGNORE: &str = "# Symaira Vault vault - ignore sensitive files\nidentity.age\n.device-id\n*.key\n*.pem\n# Ignore Symaira Vault runtime artifacts\nmcp-token\nmcp-tokens.json\n.runtime-port\n# Ignore OS files\n.DS_Store\nThumbs.db\n# Ignore IDE files\n.idea/\n.vscode/\n*.swp\n*.swo\n*~\n";

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git repository path is invalid: {0}")]
    InvalidPath(PathBuf),
    #[error("git command failed ({status}): {stderr}")]
    Command { status: String, stderr: String },
    #[error("git output was invalid: {0}")]
    Parse(String),
    #[error("git {operation} timed out after {timeout:?}")]
    Timeout {
        operation: String,
        timeout: Duration,
    },
    #[error("git I/O failed: {0}")]
    Io(#[from] io::Error),
}

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitOptions {
    pub message: String,
    pub author: Option<String>,
    pub email: Option<String>,
    pub affected_paths: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Commit {
    pub hash: String,
    pub author: String,
    pub date: String,
    pub message: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitStatus {
    pub path: String,
    pub index: char,
    pub worktree: char,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PushResult {
    pub success: bool,
    pub skipped: bool,
    pub remote_url: Option<String>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PullResult {
    pub success: bool,
    pub updated: bool,
    pub skipped: bool,
    pub remote_url: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GitRepository {
    root: PathBuf,
}
impl GitRepository {
    pub fn init(root: impl AsRef<Path>) -> Result<Self, GitError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        if !root.is_dir() {
            return Err(GitError::InvalidPath(root));
        }
        let repo = Self { root };
        if !repo.root.join(".git").exists() {
            repo.command(&["init", "--quiet"])?;
            repo.command(&["symbolic-ref", "HEAD", "refs/heads/master"])?;
            repo.command(&["config", "user.name", "Symaira Vault"])?;
            repo.command(&["config", "user.email", "symvault@example.com"])?;
        }
        Ok(repo)
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self, GitError> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() || !root.join(".git").exists() {
            return Err(GitError::InvalidPath(root));
        }
        Ok(Self { root })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn create_gitignore(&self) -> Result<(), GitError> {
        let path = self.root.join(".gitignore");
        if !path.exists() {
            fs::write(&path, DEFAULT_GITIGNORE)?;
            return Ok(());
        }
        let old = fs::read_to_string(&path)?;
        let mut lines: Vec<String> = old.lines().map(str::to_owned).collect();
        for line in DEFAULT_GITIGNORE
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if !lines.iter().any(|existing| existing.trim() == line) {
                lines.push(line.to_owned());
            }
        }
        let mut content = lines.join("\n");
        content.push('\n');
        if content != old {
            fs::write(path, content)?;
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Vec<GitStatus>, GitError> {
        let out = self.command(&["status", "--porcelain=v1", "--untracked-files=all"])?;
        let text = String::from_utf8(out.stdout).map_err(|e| GitError::Parse(e.to_string()))?;
        text.lines()
            .map(|line| {
                if line.len() < 3 {
                    return Err(GitError::Parse(format!("short status line: {line:?}")));
                }
                Ok(GitStatus {
                    index: line.as_bytes()[0] as char,
                    worktree: line.as_bytes()[1] as char,
                    path: line[3..].to_owned(),
                })
            })
            .collect()
    }
    pub fn commit(&self, mut opts: CommitOptions) -> Result<Option<Commit>, GitError> {
        self.create_gitignore()?;
        if opts.message.is_empty() {
            opts.message = "Update from Symaira Vault".to_owned();
        }
        let paths = if opts.affected_paths.is_empty() {
            vec![".".to_owned()]
        } else {
            validate_paths(&opts.affected_paths)?;
            opts.affected_paths.clone()
        };
        let mut add = vec!["add", "--all", "--"];
        add.extend(paths.iter().map(String::as_str));
        self.command(&add)?;
        let staged = self.command(&["diff", "--cached", "--quiet"]);
        if staged.is_ok() {
            return Ok(None);
        }
        let mut args = vec![
            "commit".to_owned(),
            "--quiet".to_owned(),
            "-m".to_owned(),
            opts.message,
        ];
        if let (Some(name), Some(email)) = (opts.author.as_deref(), opts.email.as_deref()) {
            args.extend(["--author".to_owned(), format!("{name} <{email}>")]);
        }
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        self.command(&refs)?;
        self.log(1).map(|mut v| v.pop())
    }
    pub fn log(&self, limit: usize) -> Result<Vec<Commit>, GitError> {
        self.log_path(None, limit)
    }

    /// Returns commits, optionally restricted to a repository-relative path.
    ///
    /// The Go CLI's `git log [path]` passes the path to the Git history walk;
    /// retaining that filter here avoids loading unrelated vault history and
    /// keeps the command's path argument after `--`.
    pub fn log_path(&self, path: Option<&str>, limit: usize) -> Result<Vec<Commit>, GitError> {
        let limit_arg = format!("-{limit}");
        let mut args = vec!["log"];
        if limit > 0 {
            args.push(&limit_arg);
        }
        args.extend(["--date=iso-strict", "--format=%H%x1f%an%x1f%aI%x1f%s%x1e"]);
        if let Some(path) = path.filter(|path| !path.is_empty()) {
            validate_paths(&[path.to_owned()])?;
            args.extend(["--", path]);
        }
        let out = self.command(&args)?;
        let text = String::from_utf8(out.stdout).map_err(|e| GitError::Parse(e.to_string()))?;
        text.split('\x1e')
            .filter(|s| !s.trim().is_empty())
            .map(|record| {
                let f: Vec<_> = record.trim_end_matches('\n').split('\x1f').collect();
                if f.len() != 4 {
                    return Err(GitError::Parse(record.to_owned()));
                }
                Ok(Commit {
                    hash: f[0].into(),
                    author: f[1].into(),
                    date: f[2].into(),
                    message: f[3].into(),
                })
            })
            .collect()
    }
    pub fn add_remote(&self, name: &str, url: &str) -> Result<(), GitError> {
        validate_name(name)?;
        self.command(&["remote", "add", name, url]).map(|_| ())
    }
    pub fn remote_url(&self, name: &str) -> Result<Option<String>, GitError> {
        validate_name(name)?;
        let out = self.command(&["remote", "get-url", name]);
        match out {
            Ok(o) => Ok(Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())),
            Err(GitError::Command { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn push(&self, name: &str) -> PushResult {
        self.transfer(name, true)
    }
    pub fn pull(&self, name: &str) -> PullResult {
        let remote_url = self.remote_url(name).ok().flatten();
        let before = self.head().ok();
        let had_merge_state = self.merge_state_exists();
        let args = ["pull", "--no-edit", "--no-rebase", name];
        match self.command(&args) {
            Ok(out) => PullResult {
                success: true,
                updated: before != self.head().ok()
                    || String::from_utf8_lossy(&out.stdout).contains("files changed")
                    || String::from_utf8_lossy(&out.stderr).contains("files changed"),
                remote_url,
                ..Default::default()
            },
            Err(err) if is_up_to_date_error(&err) => PullResult {
                success: true,
                remote_url,
                ..Default::default()
            },
            Err(e) => {
                // `git pull --no-rebase` may leave conflict markers and an
                // in-progress merge behind. go-git returns the pull error
                // without rewriting the local tip, so abort the failed merge
                // before exposing the result to callers. Never abort a merge
                // that was already in progress when this invocation started:
                // that state belongs to the caller and may contain staged
                // conflict resolutions.
                if !had_merge_state && self.merge_state_exists() {
                    let _ = self.command(&["merge", "--abort"]);
                }
                PullResult {
                    remote_url,
                    error: Some(classify_pull_error(&e)),
                    ..Default::default()
                }
            }
        }
    }
    fn merge_state_exists(&self) -> bool {
        let git_dir = self.root.join(".git");
        let git_dir = match fs::symlink_metadata(&git_dir) {
            Ok(metadata) if metadata.is_dir() => git_dir,
            Ok(_) => match fs::read_to_string(&git_dir) {
                Ok(contents) => contents
                    .strip_prefix("gitdir:")
                    .map(str::trim)
                    .map(PathBuf::from)
                    .map(|path| {
                        if path.is_absolute() {
                            path
                        } else {
                            self.root.join(path)
                        }
                    })
                    .unwrap_or(git_dir),
                Err(_) => git_dir,
            },
            Err(_) => git_dir,
        };
        git_dir.join("MERGE_HEAD").exists()
    }
    fn transfer(&self, name: &str, push: bool) -> PushResult {
        let remote_url = self.remote_url(name).ok().flatten();
        if remote_url.is_none() {
            return PushResult {
                skipped: true,
                error: Some(format!("no '{name}' remote configured")),
                ..Default::default()
            };
        }
        let args = if push {
            vec!["push", "--set-upstream", name, "HEAD"]
        } else {
            vec!["fetch", name]
        };
        match self.command(&args) {
            Ok(out) => PushResult {
                success: true,
                skipped: is_up_to_date_output(&out),
                remote_url,
                ..Default::default()
            },
            Err(e) => PushResult {
                remote_url,
                error: Some(classify_push_error(&e)),
                ..Default::default()
            },
        }
    }
    fn head(&self) -> Result<String, GitError> {
        Ok(
            String::from_utf8(self.command(&["rev-parse", "HEAD"])?.stdout)
                .map_err(|e| GitError::Parse(e.to_string()))?
                .trim()
                .to_owned(),
        )
    }
    fn command(&self, args: &[&str]) -> Result<Output, GitError> {
        let out = run_process_with_timeout("git", args, Some(&self.root), GIT_COMMAND_TIMEOUT)?;
        if out.status.success() {
            Ok(out)
        } else {
            Err(GitError::Command {
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            })
        }
    }
}

fn is_up_to_date_output(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout.contains("Everything up-to-date")
        || stdout.contains("Already up to date")
        || stderr.contains("Everything up-to-date")
        || stderr.contains("Already up to date")
}

fn is_up_to_date_error(error: &GitError) -> bool {
    match error {
        GitError::Command { stderr, .. } => {
            stderr.contains("Everything up-to-date") || stderr.contains("Already up to date")
        }
        _ => false,
    }
}

fn classify_push_error(error: &GitError) -> String {
    let message = error.to_string();
    if message.contains("known_hosts")
        || message.contains("known hosts")
        || message.contains("SSH_KNOWN_HOSTS")
    {
        return PushError::with_cause(
            "SSH configuration error - please check known_hosts or SSH_KNOWN_HOSTS",
            message,
        )
        .to_string();
    }
    if contains_auth_marker(&message) {
        return PushError::with_cause(
            "authentication failed - please check your credentials",
            message,
        )
        .to_string();
    }
    if is_offline_transport_error(&message) {
        return PushError::with_cause(NETWORK_MESSAGE, message).to_string();
    }
    PushError::with_cause("push failed", message).to_string()
}

fn classify_pull_error(error: &GitError) -> String {
    let message = error.to_string();
    if is_offline_transport_error(&message) {
        return PushError::with_cause(NETWORK_MESSAGE, message).to_string();
    }
    if contains_auth_marker(&message) {
        return PushError::with_cause(
            "authentication failed - please check your credentials",
            message,
        )
        .to_string();
    }
    PushError::with_cause("pull failed", message).to_string()
}

fn contains_auth_marker(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("authentication")
        || lowered.contains("credentials")
        || lowered.contains("error: 401")
        || lowered.contains("error: 403")
        || lowered.contains("could not read username")
        || lowered.contains("terminal prompts disabled")
}

fn is_offline_transport_error(message: &str) -> bool {
    if is_offline_error(message) {
        return true;
    }
    let lowered = message.to_ascii_lowercase();
    lowered.contains("couldn't connect") || lowered.contains("unable to access")
}

fn run_process_with_timeout(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<Output, GitError> {
    let (stdout_path, stdout_file) = temporary_output_file("stdout")?;
    let (stderr_path, stderr_file) = match temporary_output_file("stderr") {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            return Err(GitError::Io(error));
        }
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .env_remove("SYMVAULT_PASSPHRASE")
        // Never leave a vault operation waiting for an interactive password.
        // GIT_ASKPASS/SSH_ASKPASS remain available for explicitly configured,
        // non-interactive callers.
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Give the command its own process group so a timed-out git process
        // cannot leave an SSH/helper descendant running after its pipes close.
        command.process_group(0);
    }

    #[cfg(windows)]
    {
        windows_process::run(
            command,
            stdout_path,
            stderr_path,
            args.first().copied().unwrap_or("command"),
            timeout,
        )
    }

    #[cfg(not(windows))]
    {
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&stdout_path);
                let _ = fs::remove_file(&stderr_path);
                return Err(GitError::Io(error));
            }
        };
        let deadline = Instant::now() + timeout;
        let timed_out = loop {
            match child.try_wait() {
                Ok(Some(_)) => break false,
                Ok(None) if Instant::now() >= deadline => break true,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(&stdout_path);
                    let _ = fs::remove_file(&stderr_path);
                    return Err(GitError::Io(error));
                }
            }
        };

        if timed_out {
            terminate_process_group(&mut child);
            let _ = child.wait();
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            let operation = args.first().copied().unwrap_or("command").to_owned();
            return Err(GitError::Timeout { operation, timeout });
        }

        let status = child.wait()?;
        let stdout = read_and_remove(&stdout_path)?;
        let stderr = read_and_remove(&stderr_path)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

fn temporary_output_file(label: &str) -> Result<(PathBuf, std::fs::File), io::Error> {
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "symvault-git-{}-{}-{label}.out",
            std::process::id(),
            attempt
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique git command output file",
    ))
}

fn read_and_remove(path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let result = file.read_to_end(&mut bytes);
    let remove_result = fs::remove_file(path);
    result?;
    remove_result?;
    Ok(bytes)
}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .output();
    let _ = child.kill();
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_process {
    use super::{GitError, read_and_remove};
    use std::{
        fs, io,
        os::windows::{io::AsRawHandle, process::CommandExt},
        process::{Command, Output},
        thread,
        time::{Duration, Instant},
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
            },
            Threading::{CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };

    struct Job(HANDLE);

    impl Job {
        fn new() -> io::Result<Self> {
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    ..Default::default()
                },
                ..Default::default()
            };
            let configured = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                        .cast::<core::ffi::c_void>(),
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            if configured == 0 {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
            Ok(Self(handle))
        }

        fn assign(&self, process: HANDLE) -> io::Result<()> {
            if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn run(
        mut command: Command,
        stdout_path: std::path::PathBuf,
        stderr_path: std::path::PathBuf,
        operation: &str,
        timeout: Duration,
    ) -> Result<Output, GitError> {
        command.creation_flags(CREATE_SUSPENDED);
        let job = match Job::new() {
            Ok(job) => job,
            Err(error) => {
                let _ = fs::remove_file(stdout_path);
                let _ = fs::remove_file(stderr_path);
                return Err(GitError::Io(error));
            }
        };
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(stdout_path);
                let _ = fs::remove_file(stderr_path);
                return Err(GitError::Io(error));
            }
        };

        if let Err(error) = job.assign(child.as_raw_handle()) {
            abort_child(&job, &mut child);
            let _ = fs::remove_file(stdout_path);
            let _ = fs::remove_file(stderr_path);
            return Err(GitError::Io(error));
        }
        if let Err(error) = resume_primary_thread(child.id()) {
            abort_child(&job, &mut child);
            let _ = fs::remove_file(stdout_path);
            let _ = fs::remove_file(stderr_path);
            return Err(GitError::Io(error));
        }

        let deadline = Instant::now() + timeout;
        let timed_out = loop {
            match child.try_wait() {
                Ok(Some(_)) => break false,
                Ok(None) if Instant::now() >= deadline => break true,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    abort_child(&job, &mut child);
                    let _ = fs::remove_file(stdout_path);
                    let _ = fs::remove_file(stderr_path);
                    return Err(GitError::Io(error));
                }
            }
        };

        if timed_out {
            abort_child(&job, &mut child);
            let _ = fs::remove_file(stdout_path);
            let _ = fs::remove_file(stderr_path);
            return Err(GitError::Timeout {
                operation: operation.to_owned(),
                timeout,
            });
        }

        let status = child.wait()?;
        drop(job);
        let stdout = read_and_remove(&stdout_path)?;
        let stderr = read_and_remove(&stderr_path)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn abort_child(job: &Job, child: &mut std::process::Child) {
        let _ = job.terminate();
        // Assignment can fail while CREATE_SUSPENDED is still in effect, so
        // the child must be killed explicitly before waiting for it.
        let _ = child.kill();
        let _ = child.wait();
    }

    fn resume_primary_thread(pid: u32) -> io::Result<()> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let first = unsafe { Thread32First(snapshot, &mut entry) };
        if first == 0 {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(snapshot) };
            return Err(error);
        }

        loop {
            if entry.th32OwnerProcessID == pid {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    let error = io::Error::last_os_error();
                    unsafe { CloseHandle(snapshot) };
                    return Err(error);
                }
                let previous = unsafe { ResumeThread(thread) };
                let resume_error = if previous == u32::MAX {
                    Some(io::Error::last_os_error())
                } else if previous != 1 {
                    Some(io::Error::other(format!(
                        "primary process thread had suspend count {previous}, want 1"
                    )))
                } else {
                    None
                };
                unsafe {
                    CloseHandle(thread);
                    CloseHandle(snapshot);
                }
                return resume_error.map_or(Ok(()), Err);
            }

            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(snapshot) };
                return Err(error);
            }
        }
    }
}

fn validate_name(name: &str) -> Result<(), GitError> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        Err(GitError::Parse(format!("invalid remote name: {name}")))
    } else {
        Ok(())
    }
}
fn validate_paths(paths: &[String]) -> Result<(), GitError> {
    for p in paths {
        let path = Path::new(p);
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(GitError::InvalidPath(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_error(stderr: &str) -> GitError {
        GitError::Command {
            status: "exit status: 1".to_owned(),
            stderr: stderr.to_owned(),
        }
    }

    #[test]
    fn push_precedence_matches_the_go_call_site() {
        let mixed = command_error("authentication failed: connection refused");
        let rendered = classify_push_error(&mixed);
        assert!(rendered.contains("authentication failed"));
        assert!(!rendered.contains(NETWORK_MESSAGE));

        let known_hosts = command_error("known_hosts: authentication failed: connection refused");
        assert!(classify_push_error(&known_hosts).contains("SSH configuration error"));
    }

    #[test]
    fn pull_precedence_keeps_connectivity_before_authentication() {
        let mixed = command_error("authentication failed: connection refused");
        let rendered = classify_pull_error(&mixed);
        assert!(rendered.contains(NETWORK_MESSAGE));
        assert!(!rendered.contains("authentication failed - please check"));
    }

    #[test]
    fn command_runner_disables_terminal_prompts_without_disabling_askpass() {
        let output = run_process_with_timeout(
            "sh",
            &[
                "-c",
                "test \"$GIT_TERMINAL_PROMPT\" = 0 && test -z \"$SYMVAULT_PASSPHRASE\"",
            ],
            None,
            Duration::from_secs(1),
        )
        .expect("probe command succeeds");
        assert!(output.status.success());
    }

    #[cfg(unix)]
    #[test]
    fn temporary_output_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (path, _file) = temporary_output_file("permissions").expect("temporary output file");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        let _ = fs::remove_file(path);
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn command_runner_times_out_and_reaps_the_process_group() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let marker = dir.path().join("descendant.pid");
        let script = dir.path().join("hang.sh");
        let script_body = format!(
            "#!/bin/sh\n(sleep 30) &\nprintf '%s\\n' \"$!\" > {}\nwait\n",
            marker.display()
        );
        fs::write(&script, script_body).expect("write timeout helper");
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .expect("make timeout helper executable");
        }

        let started = Instant::now();
        let error = run_process_with_timeout(
            script.to_str().expect("script path"),
            &[],
            None,
            Duration::from_secs(1),
        )
        .expect_err("helper must exceed the deadline");
        assert!(matches!(error, GitError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(2));

        let pid = fs::read_to_string(&marker)
            .expect("helper recorded descendant pid")
            .trim()
            .to_owned();
        let descendant_gone = (0..40).any(|_| {
            // Linux reports a child killed with its parent process group as
            // "alive" to kill(0) until the orphaned zombie is reaped by
            // init. The timeout runner is not that process's parent and
            // cannot reap it. Treat a zombie as stopped while retaining the
            // kill(0) probe for Unix platforms without /proc.
            let alive = {
                #[cfg(target_os = "linux")]
                {
                    match fs::read_to_string(format!("/proc/{pid}/stat")) {
                        Ok(stat) => {
                            // comm is parenthesized and may itself contain spaces.
                            let (_, tail) = stat.rsplit_once(')').expect("valid proc stat comm");
                            tail.split_whitespace().next().expect("proc state") != "Z"
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                        Err(error) => panic!("cannot inspect descendant {pid}: {error}"),
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Command::new("kill")
                        .args(["-0", &pid])
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false)
                }
            };
            if alive {
                thread::sleep(Duration::from_millis(25));
                false
            } else {
                true
            }
        });
        assert!(descendant_gone, "timed-out descendant {pid} is still alive");
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    mod windows_process_tests {
        use super::*;
        use std::{
            fs,
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        use windows_sys::Win32::{
            Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
        };

        const HELPER_ENV: &str = "SYMVAULT_RUST_GIT_PROCESS_TREE_HELPER";
        const HELPER_TEST: &str = "git::tests::windows_process_tests::descendant_helper";

        #[test]
        fn timeout_kills_descendants_and_reaps_inherited_output_handles() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let launcher = directory.path().join("launch.cmd");
            let executable = std::env::current_exe().expect("test executable");
            let launcher_body = format!(
                "@echo off\r\nset \"{HELPER_ENV}=child\"\r\ncall \"{}\" --exact {HELPER_TEST} --nocapture\r\n",
                executable.display()
            );
            fs::write(&launcher, launcher_body).expect("write helper launcher");
            let working_directory = directory.path().to_path_buf();
            let runner = thread::spawn(move || {
                run_process_with_timeout(
                    "cmd.exe",
                    &["/D", "/C", "call launch.cmd"],
                    Some(&working_directory),
                    Duration::from_secs(5),
                )
            });
            let ready_deadline = Instant::now() + Duration::from_secs(3);
            while !directory.path().join("ready").is_file() && Instant::now() < ready_deadline {
                thread::sleep(Duration::from_millis(25));
            }
            let error = runner
                .join()
                .expect("runner thread")
                .expect_err("helper must exceed the deadline");
            assert!(matches!(error, GitError::Timeout { .. }));

            let child_pid = read_pid(directory.path().join("child.pid"));
            let grandchild_pid = read_pid(directory.path().join("grandchild.pid"));
            assert!(
                wait_process_gone(child_pid),
                "child {child_pid} is still alive"
            );
            assert!(
                wait_process_gone(grandchild_pid),
                "grandchild {grandchild_pid} is still alive"
            );
            assert!(directory.path().join("ready").is_file());
        }

        #[test]
        fn already_gone_process_is_reaped_without_error() {
            let output = run_process_with_timeout(
                "cmd.exe",
                &["/D", "/C", "exit", "0"],
                None,
                Duration::from_secs(1),
            )
            .expect("already-gone process should complete");
            assert!(output.status.success());
        }

        #[test]
        fn descendant_helper() {
            let Ok(mode) = std::env::var(HELPER_ENV) else {
                return;
            };
            let child_pid = std::env::current_dir()
                .expect("helper working directory")
                .join("child.pid");
            let grandchild_pid = child_pid.with_file_name("grandchild.pid");
            let ready = child_pid.with_file_name("ready");

            match mode.as_str() {
                "child" => {
                    fs::write(&child_pid, std::process::id().to_string()).expect("write child pid");
                    let executable = std::env::current_exe().expect("test executable");
                    Command::new(executable)
                        .args(["--exact", HELPER_TEST, "--nocapture"])
                        .env(HELPER_ENV, "grandchild")
                        .spawn()
                        .expect("spawn grandchild helper")
                        .wait()
                        .expect("wait for grandchild helper");
                }
                "grandchild" => {
                    fs::write(&grandchild_pid, std::process::id().to_string())
                        .expect("write grandchild pid");
                    fs::write(&ready, b"ready\n").expect("write helper readiness");
                }
                _ => return,
            }

            loop {
                thread::sleep(Duration::from_secs(30));
            }
        }

        fn read_pid(path: std::path::PathBuf) -> u32 {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(value) = fs::read_to_string(&path) {
                    return value.trim().parse().expect("valid helper pid");
                }
                assert!(
                    Instant::now() < deadline,
                    "helper pid file missing: {}",
                    path.display()
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        fn wait_process_gone(pid: u32) -> bool {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
                if handle.is_null() {
                    return true;
                }
                let state = unsafe { WaitForSingleObject(handle, 0) };
                unsafe { CloseHandle(handle) };
                if state == WAIT_OBJECT_0 {
                    return true;
                }
                if state != WAIT_TIMEOUT || Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
}
