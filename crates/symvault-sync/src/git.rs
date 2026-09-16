use crate::offline::{NETWORK_MESSAGE, PushError, is_offline_error};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
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
        let n = limit.to_string();
        let out = self.command(&[
            "log",
            &format!("-{n}"),
            "--date=iso-strict",
            "--format=%H%x1f%an%x1f%aI%x1f%s%x1e",
        ])?;
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
                // before exposing the result to callers.
                let _ = self.command(&["merge", "--abort"]);
                PullResult {
                    remote_url,
                    error: Some(classify_pull_error(&e)),
                    ..Default::default()
                }
            }
        }
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
    if is_offline_error(&message) {
        return PushError::with_cause(NETWORK_MESSAGE, message).to_string();
    }
    PushError::with_cause("push failed", message).to_string()
}

fn classify_pull_error(error: &GitError) -> String {
    let message = error.to_string();
    if is_offline_error(&message) {
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
    message.contains("authentication")
        || message.contains("credentials")
        || message.contains("error: 401")
        || message.contains("error: 403")
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

fn temporary_output_file(label: &str) -> Result<(PathBuf, std::fs::File), io::Error> {
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "symvault-git-{}-{}-{label}.out",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
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

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill").args(["-KILL", &group]).output();
    }
    let _ = child.kill();
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

    #[test]
    fn command_runner_times_out_and_reaps_the_process_group() {
        let started = Instant::now();
        let error =
            run_process_with_timeout("sh", &["-c", "sleep 30"], None, Duration::from_millis(100))
                .expect_err("sleep must exceed the deadline");
        assert!(matches!(error, GitError::Timeout { operation, .. } if operation == "-c"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
