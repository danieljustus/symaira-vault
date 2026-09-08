use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Output},
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
    #[error("git I/O failed: {0}")]
    Io(#[from] io::Error),
}

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
                updated: String::from_utf8_lossy(&out.stdout).contains("files changed")
                    || before != self.head().ok(),
                remote_url,
                ..Default::default()
            },
            Err(GitError::Command { stderr, .. }) if stderr.contains("Already up to date") => {
                PullResult {
                    success: true,
                    remote_url,
                    ..Default::default()
                }
            }
            Err(e) => {
                // `git pull --no-rebase` may leave conflict markers and an
                // in-progress merge behind. go-git returns the pull error
                // without rewriting the local tip, so abort the failed merge
                // before exposing the result to callers.
                let _ = self.command(&["merge", "--abort"]);
                PullResult {
                    remote_url,
                    error: Some(e.to_string()),
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
                skipped: String::from_utf8_lossy(&out.stdout).contains("Everything up-to-date"),
                remote_url,
                ..Default::default()
            },
            Err(e) => PushResult {
                remote_url,
                error: Some(e.to_string()),
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
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()?;
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
use std::fs;
