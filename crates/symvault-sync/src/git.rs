use crate::offline::{NETWORK_MESSAGE, PushError, is_offline_error};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
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
        if remote_url.is_none() {
            return PullResult {
                skipped: true,
                ..Default::default()
            };
        }
        let before = self.head().ok();
        let branch = self.branch_name();
        let snapshots = match self.snapshot_dirty_candidates() {
            Ok(snapshots) => snapshots,
            Err(error) => {
                return PullResult {
                    remote_url,
                    error: Some(format!("cannot snapshot local files before pull: {error}")),
                    ..Default::default()
                };
            }
        };
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
                let merge_aborted = if !had_merge_state && self.merge_state_exists() {
                    self.command(&["merge", "--abort"]).is_ok() && !self.merge_state_exists()
                } else {
                    true
                };
                let message = e.to_string();
                let should_resolve =
                    !is_offline_transport_error(&message) && !contains_auth_marker(&message);
                if merge_aborted && !had_merge_state && should_resolve {
                    let _ = self.preserve_divergent_conflicts(
                        name,
                        branch.as_deref(),
                        before.as_deref(),
                        &snapshots,
                    );
                }
                PullResult {
                    remote_url,
                    error: Some(classify_pull_error(&e)),
                    ..Default::default()
                }
            }
        }
    }

    fn branch_name(&self) -> Option<String> {
        let output = self.command(&["symbolic-ref", "--short", "HEAD"]).ok()?;
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (!branch.is_empty()).then_some(branch)
    }

    fn snapshot_dirty_candidates(&self) -> Result<BTreeMap<String, Option<Vec<u8>>>, GitError> {
        // Status is metadata-only: ordinary pulls inspect encrypted contents
        // only for dirty tracked candidates, rather than scanning the vault.
        let status = self.force_status()?;
        let mut snapshots = BTreeMap::new();
        for entry in status
            .into_iter()
            .filter(|entry| entry.index != '?' && (entry.index != ' ' || entry.worktree != ' '))
        {
            if !is_conflict_candidate(&entry.path) {
                continue;
            }
            reject_symlinked_ancestors(&self.root, &entry.path)?;
            // Keep a tombstone for a tracked deletion.  It prevents the
            // pre-pull HEAD fallback from resurrecting a locally removed
            // candidate during divergent conflict preservation.
            let data = crate::safeio::read(&self.root.join(&entry.path))
                .map_err(|error| GitError::Parse(error.to_string()))?;
            snapshots.insert(entry.path, data);
        }
        Ok(snapshots)
    }

    fn preserve_divergent_conflicts(
        &self,
        remote_name: &str,
        branch: Option<&str>,
        before: Option<&str>,
        snapshots: &BTreeMap<String, Option<Vec<u8>>>,
    ) -> Result<(), GitError> {
        let (Some(branch), Some(before)) = (branch, before) else {
            return Ok(());
        };
        let remote_branch = format!("{remote_name}/{branch}");
        let output = self.command(&["merge-base", before, &remote_branch])?;
        let ancestor = String::from_utf8(output.stdout)
            .map_err(|error| GitError::Parse(error.to_string()))?
            .trim()
            .to_owned();
        if ancestor.is_empty() {
            return Ok(());
        }
        let device = self.device_identity();
        for path in self.changed_paths(&ancestor, &remote_branch)? {
            if !is_conflict_candidate(&path) {
                continue;
            }
            let clean_local;
            let local: &[u8] = match snapshots.get(&path) {
                Some(Some(local)) => local,
                Some(None) => continue,
                None => {
                    let Ok(data) = self.file_at_ref(before, &path) else {
                        continue;
                    };
                    // Keep this clean committed snapshot scoped to the
                    // remote-touched path; the common case remains lazy.
                    clean_local = data;
                    &clean_local
                }
            };
            if self
                .file_at_ref(&ancestor, &path)
                .is_ok_and(|base| base.as_slice() == local)
            {
                continue;
            }
            let conflict = conflict_copy_path(&path, &device);
            write_conflict_copy(&self.root, &conflict, local)?;
        }
        Ok(())
    }

    /// Fetches and hard-resets the worktree to the remote branch.
    ///
    /// Files changed locally and by the remote are captured as conflict copies
    /// before resetting, matching Go's `sync --force` data-preservation path.
    pub fn force_pull(&self, name: &str) -> PullResult {
        let remote_url = self.remote_url(name).ok().flatten();
        if remote_url.is_none() {
            return PullResult {
                skipped: true,
                ..Default::default()
            };
        }
        let before = self.head().ok();
        let status = match self.force_status() {
            Ok(status) => status,
            Err(error) => {
                return PullResult {
                    remote_url,
                    error: Some(format!(
                        "cannot inspect worktree before force pull: {error}"
                    )),
                    ..Default::default()
                };
            }
        };

        if let Err(error) = self.command(&["fetch", name]) {
            return PullResult {
                remote_url,
                error: Some(classify_pull_error(&error)),
                ..Default::default()
            };
        }
        let branch = match self.command(&["symbolic-ref", "--short", "HEAD"]) {
            Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            Err(error) => {
                return PullResult {
                    remote_url,
                    error: Some(format!("could not resolve local branch: {error}")),
                    ..Default::default()
                };
            }
        };
        if branch.is_empty() {
            return PullResult {
                remote_url,
                error: Some("could not resolve local branch".to_owned()),
                ..Default::default()
            };
        }
        let remote_branch = format!("{name}/{branch}");
        let mut paths = BTreeSet::new();
        paths.extend(
            status
                .into_iter()
                // go-git skips untracked and staged-only paths when
                // collecting force-reset backups. Remote tree differences
                // below cover tracked files changed by the incoming reset.
                .filter(|entry| {
                    entry.index == ' ' && entry.worktree != ' ' && entry.worktree != '?'
                })
                .map(|entry| entry.path),
        );
        if before.is_some() {
            match self.changed_paths("HEAD", &remote_branch) {
                Ok(changed) => paths.extend(changed),
                Err(error) => {
                    return PullResult {
                        remote_url,
                        error: Some(format!("cannot inspect force-pull changes: {error}")),
                        ..Default::default()
                    };
                }
            }
        }
        let device = self.device_identity();
        let mut backups = Vec::new();
        for path in paths {
            if !is_conflict_candidate(&path) {
                continue;
            }
            if let Err(error) = reject_symlinked_ancestors(&self.root, &path) {
                return PullResult {
                    remote_url,
                    error: Some(format!(
                        "cannot read local force-pull change {path}: {error}"
                    )),
                    ..Default::default()
                };
            }
            let full_path = self.root.join(&path);
            let data = match crate::safeio::read(&full_path) {
                Ok(Some(data)) => data,
                Ok(None) => continue,
                Err(error) => {
                    return PullResult {
                        remote_url,
                        error: Some(format!(
                            "cannot read local force-pull change {path}: {error}"
                        )),
                        ..Default::default()
                    };
                }
            };
            if self
                .file_at_ref(&remote_branch, &path)
                .is_ok_and(|remote| remote == data)
            {
                continue;
            }
            backups.push((path, data));
        }
        // Persist each snapshot before the destructive reset. A reset failure
        // or process interruption must not discard the only copy of local
        // encrypted data.
        for (path, data) in &backups {
            let conflict = conflict_copy_path(path, &device);
            // A remote commit containing the generated conflict path would
            // overwrite a pre-reset snapshot during reset --hard. Refuse
            // that ambiguous collision instead of silently losing data.
            let collision = match self.conflict_path_collision(&remote_branch, &conflict) {
                Ok(collision) => collision,
                Err(error) => {
                    return PullResult {
                        remote_url,
                        error: Some(format!("cannot inspect remote conflict path: {error}")),
                        ..Default::default()
                    };
                }
            };
            if collision {
                return PullResult {
                    remote_url,
                    error: Some(format!(
                        "cannot preserve local changes: remote already tracks {conflict}"
                    )),
                    ..Default::default()
                };
            }
            if let Err(error) = write_conflict_copy(&self.root, &conflict, data) {
                return PullResult {
                    remote_url,
                    error: Some(format!(
                        "could not preserve local changes before force reset: {error}"
                    )),
                    ..Default::default()
                };
            }
        }
        if let Err(error) = self.command(&["reset", "--hard", &remote_branch]) {
            return PullResult {
                remote_url,
                error: Some(format!("force reset failed: {error}")),
                ..Default::default()
            };
        }
        PullResult {
            success: true,
            updated: before != self.head().ok(),
            remote_url,
            ..Default::default()
        }
    }

    // A remote file or symlink replacing any parent would remove the backup
    // subtree during reset, even when the exact conflict path is absent.
    fn conflict_path_collision(&self, revision: &str, path: &str) -> Result<bool, GitError> {
        for (depth, ancestor) in Path::new(path).ancestors().enumerate() {
            let ancestor = ancestor
                .to_str()
                .ok_or_else(|| GitError::Parse("invalid conflict path".into()))?;
            if ancestor.is_empty() {
                break;
            }
            let output = self.command(&[
                "--literal-pathspecs",
                "ls-tree",
                "-z",
                revision,
                "--",
                ancestor,
            ])?;
            if !output.stdout.is_empty() && (depth == 0 || !output.stdout.starts_with(b"040000 ")) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn changed_paths(&self, left: &str, right: &str) -> Result<Vec<String>, GitError> {
        let output = self.command(&["diff", "--name-only", "-z", left, right])?;
        output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| {
                String::from_utf8(path.to_vec()).map_err(|error| GitError::Parse(error.to_string()))
            })
            .collect()
    }

    fn force_status(&self) -> Result<Vec<GitStatus>, GitError> {
        let output = self.command(&["status", "--porcelain=v1", "-z", "--untracked-files=all"])?;
        let mut status = Vec::new();
        let mut skip_rename_source = false;
        for record in output.stdout.split(|byte| *byte == 0) {
            if record.is_empty() {
                continue;
            }
            if skip_rename_source {
                skip_rename_source = false;
                continue;
            }
            if record.len() < 3 {
                return Err(GitError::Parse(
                    "short NUL-delimited status record".to_owned(),
                ));
            }
            let index = record[0] as char;
            let worktree = record[1] as char;
            let path = String::from_utf8(record[3..].to_vec())
                .map_err(|error| GitError::Parse(error.to_string()))?;
            if matches!(index, 'R' | 'C') {
                skip_rename_source = true;
            }
            status.push(GitStatus {
                path,
                index,
                worktree,
            });
        }
        Ok(status)
    }

    fn file_at_ref(&self, revision: &str, path: &str) -> Result<Vec<u8>, GitError> {
        let spec = format!("{revision}:{path}");
        Ok(self.command(&["show", &spec])?.stdout)
    }

    fn device_identity(&self) -> String {
        let path = self.root.join(".device-id");
        if let Ok(Some(contents)) = crate::safeio::read(&path)
            && let Ok(contents) = String::from_utf8(contents)
        {
            let identity = normalize_device_name(&contents);
            if identity != "unknown" {
                return identity;
            }
        }
        let hostname = std::env::var_os("HOSTNAME")
            .or_else(|| std::env::var_os("COMPUTERNAME"))
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let identity = normalize_device_name(&hostname);
        let identity = if identity.is_empty() {
            "unknown".to_owned()
        } else {
            identity
        };
        let _ = crate::safeio::write_atomic(&path, identity.as_bytes());
        identity
    }

    /// Records a successful sync in the repository's private git metadata.
    pub fn record_last_sync(&self) -> Result<(), GitError> {
        let timestamp = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|error| GitError::Parse(error.to_string()))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| GitError::Parse(error.to_string()))?;
        fs::write(self.git_dir().join("symvault-last-sync"), timestamp)?;
        Ok(())
    }

    fn git_dir(&self) -> PathBuf {
        let git_path = self.root.join(".git");
        match fs::symlink_metadata(&git_path) {
            Ok(metadata) if metadata.is_dir() => git_path,
            Ok(_) => match fs::read_to_string(&git_path) {
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
                    .unwrap_or(git_path),
                Err(_) => git_path,
            },
            Err(_) => git_path,
        }
    }

    fn merge_state_exists(&self) -> bool {
        self.git_dir().join("MERGE_HEAD").exists()
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

fn is_conflict_candidate(path: &str) -> bool {
    (path == "config.yaml" || path.ends_with(".age"))
        && path != "identity.age"
        && !path.contains(".conflict-")
        && !is_protected_runtime_path(path)
}

fn reject_symlinked_ancestors(root: &Path, relative_path: &str) -> Result<(), GitError> {
    let components: Vec<_> = Path::new(relative_path).components().collect();
    if components.iter().any(|component| {
        !matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    }) {
        return Err(GitError::Parse(format!(
            "unsafe relative conflict path: {relative_path}"
        )));
    }

    let mut ancestor_path = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if let std::path::Component::Normal(component) = component {
            ancestor_path.push(*component);
        }
        match fs::symlink_metadata(&ancestor_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(GitError::Parse(format!(
                    "refusing symlinked conflict path ancestor: {}",
                    ancestor_path.display()
                )));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(GitError::Parse(format!(
                    "refusing non-directory conflict path ancestor: {}",
                    ancestor_path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(GitError::Io(error)),
        }
    }
    Ok(())
}

fn is_protected_runtime_path(path: &str) -> bool {
    let path = path.replace('\\', "/");
    [
        ".device-id",
        "mcp-token",
        "mcp-tokens.json",
        ".runtime-port",
    ]
    .iter()
    .any(|protected| path == *protected || path.starts_with(&format!("{protected}.")))
}

fn conflict_copy_path(path: &str, device: &str) -> String {
    let path = Path::new(path);
    let extension = path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()))
        .unwrap_or_default();
    let path_string = path.to_string_lossy();
    let base = path_string
        .strip_suffix(&extension)
        .unwrap_or(path_string.as_ref());
    format!("{base}.conflict-{device}{extension}")
}

fn write_conflict_copy(root: &Path, relative_path: &str, data: &[u8]) -> Result<(), GitError> {
    reject_symlinked_ancestors(root, relative_path)?;
    let destination = root.join(relative_path);
    match crate::safeio::read(&destination) {
        Ok(Some(existing)) if existing == data => return Ok(()),
        Ok(Some(_)) => {
            return Err(GitError::Parse(format!(
                "conflict copy already exists with different content: {}",
                destination.display()
            )));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(GitError::Parse(format!(
                "{}: {error}",
                destination.display()
            )));
        }
    }
    crate::safeio::write_atomic(&destination, data)
        .map_err(|error| GitError::Parse(format!("{}: {error}", destination.display())))
}

fn normalize_device_name(value: &str) -> String {
    let mut value = value.trim().to_ascii_lowercase();
    while value.ends_with('.') {
        value.pop();
    }
    for suffix in [".local", ".home", ".lan", ".internal", ".home.arpa"] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            value = stripped.to_owned();
            break;
        }
    }
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        // The persisted value is untrusted input and is embedded into a path.
        return "unknown".to_owned();
    }
    value
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
    fn dirty_snapshots_retain_staged_edits_and_deletion_tombstones() {
        let root = tempfile::tempdir().unwrap();
        let repo = GitRepository::init(root.path()).unwrap();
        let config = root.path().join("config.yaml");
        fs::write(&config, b"base").unwrap();
        repo.command(&["add", "config.yaml"]).unwrap();
        repo.command(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "base",
        ])
        .unwrap();
        fs::write(&config, b"staged").unwrap();
        repo.command(&["add", "config.yaml"]).unwrap();
        fs::write(&config, b"working").unwrap();
        assert_eq!(
            repo.snapshot_dirty_candidates().unwrap()["config.yaml"].as_deref(),
            Some(b"working".as_slice())
        );
        fs::remove_file(&config).unwrap();
        assert_eq!(
            repo.snapshot_dirty_candidates().unwrap()["config.yaml"],
            None
        );
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
    fn force_pull_preserves_unicode_newline_file_when_conflict_destination_exists() {
        let local = tempfile::tempdir().expect("local repository");
        let bare = tempfile::tempdir().expect("bare repository");
        let remote = tempfile::tempdir().expect("remote checkout");
        let path = local.path().join("entries").join("über\nlogin.age");
        let remote_path = remote.path().join("entries").join("über\nlogin.age");
        fs::create_dir_all(path.parent().expect("entries parent")).expect("entries directory");

        let run_git = |root: &Path, args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(root)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("run git");
            assert!(
                output.status.success(),
                "git {args:?}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let repo = GitRepository::init(local.path()).expect("init local");
        run_git(local.path(), &["config", "user.name", "Sync Test"]);
        run_git(
            local.path(),
            &["config", "user.email", "sync-test@example.invalid"],
        );
        fs::write(local.path().join("config.yaml"), b"base\n").expect("base config");
        fs::write(&path, b"base-entry\n").expect("base entry");
        run_git(local.path(), &["add", "--all"]);
        run_git(local.path(), &["commit", "--quiet", "-m", "base"]);
        run_git(
            local.path(),
            &[
                "remote",
                "add",
                "origin",
                bare.path().to_str().expect("bare path"),
            ],
        );
        run_git(bare.path(), &["init", "--bare", "--quiet"]);
        run_git(
            local.path(),
            &["push", "--quiet", "--set-upstream", "origin", "HEAD"],
        );

        let clone = Command::new("git")
            .args(["clone", "--quiet", bare.path().to_str().expect("bare path")])
            .arg(remote.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("clone remote");
        assert!(clone.status.success(), "clone remote failed");
        run_git(remote.path(), &["config", "user.name", "Remote Sync Test"]);
        run_git(
            remote.path(),
            &["config", "user.email", "remote-sync@example.invalid"],
        );
        fs::write(&remote_path, b"remote-entry\n").expect("remote entry");
        run_git(remote.path(), &["add", "--all"]);
        run_git(remote.path(), &["commit", "--quiet", "-m", "remote"]);
        run_git(remote.path(), &["push", "--quiet", "origin", "HEAD"]);

        fs::write(&path, b"local-entry\n").expect("local edit");
        fs::write(local.path().join(".device-id"), b"test-device\n").expect("device id");
        let conflict = local
            .path()
            .join(conflict_copy_path("entries/über\nlogin.age", "test-device"));
        fs::write(&conflict, b"existing sentinel\n").expect("existing conflict");
        let before_head = repo.head().expect("head before reset");
        let result = repo.force_pull("origin");
        assert!(
            result.error.is_some(),
            "force pull should reject a different existing conflict copy"
        );
        assert_eq!(repo.head().expect("head after rejected reset"), before_head);
        assert_eq!(fs::read(&path).expect("local bytes"), b"local-entry\n");
        assert_eq!(
            fs::read(&conflict).expect("existing conflict bytes"),
            b"existing sentinel\n"
        );
        fs::remove_file(&conflict).expect("remove own sentinel");
        run_git(remote.path(), &["rm", "-r", "--", "entries"]);
        fs::write(remote.path().join("entries"), b"remote replaces directory").unwrap();
        run_git(remote.path(), &["add", "entries"]);
        run_git(
            remote.path(),
            &["commit", "--quiet", "-m", "replace ancestor"],
        );
        run_git(remote.path(), &["push", "--quiet", "origin", "HEAD"]);
        assert!(repo.force_pull("origin").error.is_some());
        assert_eq!(repo.head().unwrap(), before_head);
        assert_eq!(fs::read(&path).unwrap(), b"local-entry\n");
    }

    #[cfg(unix)]
    #[test]
    fn conflict_copy_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("repository directory");
        let outside = tempfile::tempdir().expect("outside directory");
        symlink(outside.path(), root.path().join("entries")).expect("symlink parent");

        let error = write_conflict_copy(root.path(), "entries/login.age", b"secret")
            .expect_err("symlinked parent must be rejected");
        assert!(
            error
                .to_string()
                .contains("symlinked conflict path ancestor")
        );
        assert!(!outside.path().join("login.age").exists());
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
