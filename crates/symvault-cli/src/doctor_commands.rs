//! Implementation of `symvault doctor` health checks and CLI rendering.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use serde_json::ser::{Formatter, PrettyFormatter, Serializer};
use symvault_core::config::Config;
use symvault_core::policy::glob_match;
use symvault_sync::GitRepository;

/// Status outcome of a health check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

/// A closure representing an automated fix for a check.
pub type FixClosure = Box<dyn Fn() -> Result<(), String> + Send + Sync>;

/// Result of a single doctor check.
#[derive(Serialize)]
pub struct DoctorResult {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub fixable: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fixed: bool,
    #[serde(skip)]
    pub fix: Option<FixClosure>,
}

impl DoctorResult {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        status: Status,
        message: impl Into<String>,
        fixable: bool,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status,
            message: message.into(),
            hint: None,
            tags: Vec::new(),
            fixable,
            fixed: false,
            fix: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_fix(
        mut self,
        fix: impl Fn() -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.fix = Some(Box::new(fix));
        self
    }
}

/// Options controlling doctor check execution and filtering.
#[derive(Clone, Debug, Default)]
pub struct DoctorOptions {
    pub no_network: bool,
    pub quick: bool,
    pub only: Vec<String>,
    pub exclude: Vec<String>,
}

/// Summary score for a set of results.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub ok: usize,
    pub warn: usize,
    pub fail: usize,
    pub total: usize,
}

pub fn score(results: &[DoctorResult]) -> Score {
    let ok = results.iter().filter(|r| r.status == Status::Ok).count();
    let warn = results.iter().filter(|r| r.status == Status::Warn).count();
    let fail = results.iter().filter(|r| r.status == Status::Fail).count();
    Score {
        ok,
        warn,
        fail,
        total: ok + warn + fail,
    }
}

/// Top-level JSON output structure.
#[derive(Serialize)]
pub struct DoctorJsonOutput<'a> {
    pub schema_version: &'static str,
    pub vault_dir: &'a str,
    pub results: &'a [DoctorResult],
    pub score: Score,
}

type CheckFn = fn(&Path, &DoctorOptions) -> DoctorResult;

struct CheckDef {
    #[allow(dead_code)]
    id: &'static str,
    tags: &'static [&'static str],
    run: CheckFn,
}

const ALL_CHECKS: &[CheckDef] = &[
    CheckDef {
        id: "vault.initialized",
        tags: &[],
        run: check_vault_initialized,
    },
    CheckDef {
        id: "vault.config.parses",
        tags: &[],
        run: check_vault_config_parses,
    },
    CheckDef {
        id: "vault.config.validates",
        tags: &[],
        run: check_vault_config_validates,
    },
    CheckDef {
        id: "vault.identity.encrypted",
        tags: &[],
        run: check_vault_identity_encrypted,
    },
    CheckDef {
        id: "vault.permissions",
        tags: &[],
        run: check_vault_permissions,
    },
    CheckDef {
        id: "git.repo",
        tags: &[],
        run: check_git_repo,
    },
    CheckDef {
        id: "git.remote",
        tags: &[],
        run: check_git_remote,
    },
    CheckDef {
        id: "git.gitignore.protects",
        tags: &[],
        run: check_git_gitignore_protects,
    },
    CheckDef {
        id: "git.lastsync.fresh",
        tags: &["network"],
        run: check_git_last_sync,
    },
    CheckDef {
        id: "vault.size",
        tags: &[],
        run: check_vault_size,
    },
    CheckDef {
        id: "vault.stale_temp_files",
        tags: &[],
        run: check_vault_stale_temp_files,
    },
    CheckDef {
        id: "vault.conflict_files",
        tags: &[],
        run: check_vault_conflict_files,
    },
    CheckDef {
        id: "vault.search_index.persistence",
        tags: &[],
        run: check_search_index_persistence,
    },
    CheckDef {
        id: "auth.passphrase.rotation",
        tags: &[],
        run: check_passphrase_rotation,
    },
];

fn matches_any(patterns: &[String], id: &str) -> bool {
    for pattern in patterns {
        if glob_match(pattern, id) {
            return true;
        }
    }
    false
}

/// Runs the health checks against `vault_dir` according to `opts`.
pub fn run_checks(vault_dir: &Path, opts: &DoctorOptions) -> Vec<DoctorResult> {
    let mut defs = Vec::new();
    for def in ALL_CHECKS {
        if opts.no_network && def.tags.contains(&"network") {
            continue;
        }
        if opts.quick && def.tags.contains(&"slow") {
            continue;
        }
        defs.push(def);
    }

    let mut results: Vec<DoctorResult> =
        defs.iter().map(|def| (def.run)(vault_dir, opts)).collect();

    if !opts.only.is_empty() {
        results.retain(|r| matches_any(&opts.only, &r.id));
    }

    if !opts.exclude.is_empty() {
        results.retain(|r| !matches_any(&opts.exclude, &r.id));
    }

    results
}

/// Applies automated fixes to fixable results if `fix` is requested.
pub fn apply_fixes(
    results: &mut [DoctorResult],
    fix: bool,
    fix_dry_run: bool,
    out: &mut impl Write,
) -> Result<(), io::Error> {
    if fix {
        for r in results.iter_mut() {
            if r.fixable && r.status != Status::Ok && r.fix.is_some() {
                if fix_dry_run {
                    writeln!(out, "Would fix {}: {}", r.id, r.message)?;
                    continue;
                }
                if let Some(fix_fn) = &r.fix {
                    match fix_fn() {
                        Ok(()) => {
                            r.fixed = true;
                            r.status = Status::Ok;
                            r.message = format!("fixed \u{2014} {}", r.message);
                        }
                        Err(err) => {
                            r.message = format!("fix failed: {err}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Formats an I/O error to match Go's `*os.PathError` (`open <path>: <error>`).
fn format_go_path_error(op: &str, path: &Path, err: &io::Error) -> String {
    #[cfg(windows)]
    let err_msg = match err.raw_os_error() {
        Some(2) => "The system cannot find the file specified.",
        Some(3) => "The system cannot find the path specified.",
        Some(5) => "Access is denied.",
        _ => {
            if err.kind() == io::ErrorKind::NotFound {
                "The system cannot find the file specified."
            } else {
                "general error"
            }
        }
    };
    #[cfg(not(windows))]
    let err_msg = match err.raw_os_error() {
        Some(2) => "no such file or directory",
        Some(13) => "permission denied",
        _ => {
            if err.kind() == io::ErrorKind::NotFound {
                "no such file or directory"
            } else if err.kind() == io::ErrorKind::PermissionDenied {
                "permission denied"
            } else {
                "input/output error"
            }
        }
    };
    format!("{op} {}: {err_msg}", path.display())
}

// ---------------------------------------------------------------------------
// Individual Checks
// ---------------------------------------------------------------------------

fn check_vault_initialized(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let config_exists = vault_dir.join("config.yaml").exists();
    let identity_exists = vault_dir.join("identity.age").exists();
    if config_exists && identity_exists {
        DoctorResult::new(
            "vault.initialized",
            "Vault initialized",
            Status::Ok,
            "config.yaml and identity.age present",
            false,
        )
    } else {
        DoctorResult::new(
            "vault.initialized",
            "Vault initialized",
            Status::Fail,
            format!("vault not initialized at {}", vault_dir.display()),
            false,
        )
        .with_hint("run `symvault init` or `symvault setup`")
    }
}

fn check_vault_config_parses(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    match fs::read(&cfg_path) {
        Err(err) => DoctorResult::new(
            "vault.config.parses",
            "Vault config parses",
            Status::Fail,
            format!(
                "config.yaml parse error: {}",
                format_go_path_error("open", &cfg_path, &err)
            ),
            false,
        )
        .with_hint(format!(
            "inspect {} for YAML syntax errors",
            cfg_path.display()
        )),
        Ok(bytes) => match Config::load_from_bytes(&bytes) {
            Err(err) => DoctorResult::new(
                "vault.config.parses",
                "Vault config parses",
                Status::Fail,
                format!("config.yaml parse error: {err}"),
                false,
            )
            .with_hint(format!(
                "inspect {} for YAML syntax errors",
                cfg_path.display()
            )),
            Ok(_) => DoctorResult::new(
                "vault.config.parses",
                "Vault config parses",
                Status::Ok,
                "config.yaml loads without errors",
                false,
            ),
        },
    }
}

fn fix_config_validation(cfg_path: &Path) -> Result<(), String> {
    let bytes = fs::read(cfg_path).map_err(|e| format!("reload config: {e}"))?;
    let mut config = Config::load_from_bytes(&bytes).map_err(|e| format!("reload config: {e}"))?;
    let mut fixed = false;

    if config.session_timeout.is_zero() {
        config.session_timeout = Duration::from_secs(15 * 60);
        fixed = true;
    }

    for agent in config.agents.values_mut() {
        if let Some(mode) = &agent.approval_mode
            && !matches!(mode.as_str(), "" | "none" | "deny" | "prompt" | "auto")
        {
            agent.approval_mode = Some("deny".into());
            fixed = true;
        }
    }

    if !fixed {
        return Ok(());
    }

    config
        .save_to(cfg_path)
        .map_err(|e| format!("save config: {e}"))?;
    Ok(())
}

fn check_vault_config_validates(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    match fs::read(&cfg_path) {
        Err(err) => DoctorResult::new(
            "vault.config.validates",
            "Vault config validates",
            Status::Fail,
            format!(
                "failed to load config: {}",
                format_go_path_error("open", &cfg_path, &err)
            ),
            false,
        )
        .with_hint(format!("inspect {} for syntax errors", cfg_path.display())),
        Ok(bytes) => match Config::load_from_bytes(&bytes) {
            Err(err) => DoctorResult::new(
                "vault.config.validates",
                "Vault config validates",
                Status::Fail,
                format!("failed to load config: {err}"),
                false,
            )
            .with_hint(format!("inspect {} for syntax errors", cfg_path.display())),
            Ok(config) => {
                let val_errs = config.validate();
                if val_errs.is_empty() {
                    DoctorResult::new(
                        "vault.config.validates",
                        "Vault config validates",
                        Status::Ok,
                        "config.yaml passes validation",
                        false,
                    )
                } else {
                    let first = &val_errs[0];
                    let msg = if val_errs.len() > 1 {
                        format!(
                            "config validation error: {first} (+{} more)",
                            val_errs.len() - 1
                        )
                    } else {
                        format!("config validation error: {first}")
                    };
                    let p = cfg_path.clone();
                    DoctorResult::new(
                        "vault.config.validates",
                        "Vault config validates",
                        Status::Warn,
                        msg,
                        true,
                    )
                    .with_hint("run `symvault doctor --fix` to auto-correct common issues")
                    .with_fix(move || fix_config_validation(&p))
                }
            }
        },
    }
}

fn check_vault_identity_encrypted(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let identity_path = vault_dir.join("identity.age");
    match fs::read(&identity_path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => DoctorResult::new(
            "vault.identity.encrypted",
            "Identity encrypted",
            Status::Fail,
            "identity.age not found",
            false,
        )
        .with_hint("run `symvault init` to create an encrypted identity"),
        Err(err) => DoctorResult::new(
            "vault.identity.encrypted",
            "Identity encrypted",
            Status::Fail,
            format!("cannot read identity.age: {err}"),
            false,
        ),
        Ok(data) => {
            let s = String::from_utf8_lossy(&data);
            if s.starts_with("age-encryption.org/v1") || s.contains("AGE ENCRYPTED FILE") {
                DoctorResult::new(
                    "vault.identity.encrypted",
                    "Identity encrypted",
                    Status::Ok,
                    "identity.age is age-encrypted",
                    false,
                )
            } else {
                DoctorResult::new(
                    "vault.identity.encrypted",
                    "Identity encrypted",
                    Status::Fail,
                    "identity.age does not appear to be age-encrypted",
                    false,
                )
                .with_hint("the file may be corrupted; re-initialize with `symvault init`")
            }
        }
    }
}

fn check_vault_permissions(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    // The body below is `#[cfg(unix)]`-only, so on Windows the closure captures nothing.
    #[cfg_attr(windows, allow(unused_variables))]
    let vd = vault_dir.to_path_buf();
    let fix_fn = move || {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let entries = vd.join("entries");
            if entries.exists() {
                fs::set_permissions(&entries, fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("chmod entries: {e}"))?;
            }
            let identity = vd.join("identity.age");
            if identity.exists() {
                fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("chmod identity.age: {e}"))?;
            }
        }
        Ok(())
    };

    #[cfg(windows)]
    {
        DoctorResult::new(
            "vault.permissions",
            "File permissions",
            Status::Ok,
            "not applicable on Windows",
            true,
        )
        .with_fix(fix_fn)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut issues = Vec::new();
        let entries_dir = vault_dir.join("entries");
        if let Ok(meta) = fs::metadata(&entries_dir) {
            let perm = meta.permissions().mode() & 0o777;
            if perm & 0o077 != 0 {
                issues.push(format!("entries/ has mode {:o} (expected 0700)", perm));
            }
        }
        let identity_path = vault_dir.join("identity.age");
        if let Ok(meta) = fs::metadata(&identity_path) {
            let perm = meta.permissions().mode() & 0o777;
            if perm & 0o177 != 0 {
                issues.push(format!("identity.age has mode {:o} (expected 0600)", perm));
            }
        }
        if issues.is_empty() {
            DoctorResult::new(
                "vault.permissions",
                "File permissions",
                Status::Ok,
                "entries/=0700, identity.age=0600",
                true,
            )
            .with_fix(fix_fn)
        } else {
            DoctorResult::new(
                "vault.permissions",
                "File permissions",
                Status::Warn,
                issues.join("; "),
                true,
            )
            .with_hint(format!(
                "run `chmod 0700 {} && chmod 0600 {}`",
                entries_dir.display(),
                identity_path.display()
            ))
            .with_fix(fix_fn)
        }
    }
}

fn check_git_repo(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let vd = vault_dir.to_path_buf();
    let fix_fn = move || {
        GitRepository::init(&vd).map_err(|e| e.to_string())?;
        Ok(())
    };
    let git_dir = vault_dir.join(".git");
    if git_dir.is_dir() {
        DoctorResult::new(
            "git.repo",
            "Git repository",
            Status::Ok,
            ".git directory present",
            true,
        )
        .with_fix(fix_fn)
    } else {
        DoctorResult::new(
            "git.repo",
            "Git repository",
            Status::Warn,
            "no git repository in vault directory",
            true,
        )
        .with_hint("run `symvault git init` to enable version history and sync")
        .with_fix(fix_fn)
    }
}

fn check_git_remote(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let git_dir = vault_dir.join(".git");
    if !git_dir.is_dir() {
        DoctorResult::new(
            "git.remote",
            "Git remote",
            Status::Warn,
            "no remote 'origin' \u{2014} vault is local-only",
            false,
        )
        .with_hint("run `symvault git remote add origin <url>` to enable sync")
    } else {
        match GitRepository::open(vault_dir) {
            Err(_) => DoctorResult::new(
                "git.remote",
                "Git remote",
                Status::Warn,
                "no remote 'origin' \u{2014} vault is local-only",
                false,
            )
            .with_hint("run `symvault git remote add origin <url>` to enable sync"),
            Ok(repo) => match repo.remote_url("origin") {
                Err(err) => DoctorResult::new(
                    "git.remote",
                    "Git remote",
                    Status::Warn,
                    format!("cannot determine git remote: {err}"),
                    false,
                ),
                Ok(Some(_)) => DoctorResult::new(
                    "git.remote",
                    "Git remote",
                    Status::Ok,
                    "remote 'origin' configured",
                    false,
                ),
                Ok(None) => DoctorResult::new(
                    "git.remote",
                    "Git remote",
                    Status::Warn,
                    "no remote 'origin' \u{2014} vault is local-only",
                    false,
                )
                .with_hint("run `symvault git remote add origin <url>` to enable sync"),
            },
        }
    }
}

fn check_git_gitignore_protects(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let vd = vault_dir.to_path_buf();
    let fix_fn = move || {
        let gitignore_path = vd.join(".gitignore");
        let mut existing: Vec<String> = if let Ok(data) = fs::read(&gitignore_path) {
            let s = String::from_utf8_lossy(&data);
            s.trim().lines().map(|l| l.to_string()).collect()
        } else {
            Vec::new()
        };
        let required = ["identity.age", "mcp-token", "mcp-tokens.json"];
        let mut to_add = Vec::new();
        for entry in &required {
            let found = existing.iter().any(|e| e.trim() == *entry);
            if !found {
                to_add.push((*entry).to_string());
            }
        }
        if to_add.is_empty() {
            return Ok(());
        }
        existing.extend(to_add);
        let content = existing.join("\n") + "\n";
        fs::write(&gitignore_path, content.as_bytes()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&gitignore_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    };

    let gitignore_path = vault_dir.join(".gitignore");
    match fs::read(&gitignore_path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => DoctorResult::new(
            "git.gitignore.protects",
            ".gitignore protects sensitive files",
            Status::Warn,
            ".gitignore missing",
            true,
        )
        .with_hint("run `symvault git init` to create a protective .gitignore")
        .with_fix(fix_fn),
        Err(err) => DoctorResult::new(
            "git.gitignore.protects",
            ".gitignore protects sensitive files",
            Status::Warn,
            format!("cannot read .gitignore: {err}"),
            true,
        )
        .with_fix(fix_fn),
        Ok(data) => {
            let content = String::from_utf8_lossy(&data);
            let required = ["identity.age", "mcp-token", "mcp-tokens.json"];
            let mut missing = Vec::new();
            for entry in &required {
                if !content.contains(entry) {
                    missing.push(*entry);
                }
            }
            if missing.is_empty() {
                DoctorResult::new(
                    "git.gitignore.protects",
                    ".gitignore protects sensitive files",
                    Status::Ok,
                    "identity.age, mcp-token, mcp-tokens.json are gitignored",
                    true,
                )
                .with_fix(fix_fn)
            } else {
                DoctorResult::new(
                    "git.gitignore.protects",
                    ".gitignore protects sensitive files",
                    Status::Warn,
                    format!(".gitignore missing entries: {}", missing.join(", ")),
                    true,
                )
                .with_hint(format!(
                    "add missing entries to {}",
                    gitignore_path.display()
                ))
                .with_fix(fix_fn)
            }
        }
    }
}

fn format_duration_hours(seconds: i64) -> String {
    // Go: age.Round(time.Hour)
    let rounded_hours = (seconds + 1800) / 3600;
    if rounded_hours == 0 {
        "0s".to_string()
    } else {
        format!("{rounded_hours}h0m0s")
    }
}

fn format_duration_days(seconds: i64) -> String {
    // Go: age.Round(24*time.Hour)
    let rounded_days = (seconds + 43200) / 86400;
    if rounded_days == 0 {
        "0s".to_string()
    } else {
        let hours = rounded_days * 24;
        format!("{hours}h0m0s")
    }
}

fn check_git_last_sync(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let marker_path = vault_dir.join(".git").join("symvault-last-sync");
    match fs::read_to_string(&marker_path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => DoctorResult::new(
            "git.lastsync.fresh",
            "Last sync fresh",
            Status::Warn,
            "no sync recorded yet",
            false,
        )
        .with_hint("run `symvault git push` to sync your vault")
        .with_tags(vec!["network".into()]),
        Err(err) => DoctorResult::new(
            "git.lastsync.fresh",
            "Last sync fresh",
            Status::Warn,
            format!("cannot determine last sync time: {err}"),
            false,
        )
        .with_tags(vec!["network".into()]),
        Ok(content) => {
            let trimmed = content.trim();
            match time::OffsetDateTime::parse(
                trimmed,
                &time::format_description::well_known::Rfc3339,
            ) {
                Err(_) => DoctorResult::new(
                    "git.lastsync.fresh",
                    "Last sync fresh",
                    Status::Warn,
                    "no sync recorded yet",
                    false,
                )
                .with_hint("run `symvault git push` to sync your vault")
                .with_tags(vec!["network".into()]),
                Ok(sync_time) => {
                    let now = time::OffsetDateTime::now_utc();
                    let diff = now - sync_time;
                    let total_seconds = diff.whole_seconds().max(0);
                    let age_str = format_duration_hours(total_seconds);
                    if total_seconds > 7 * 24 * 3600 {
                        DoctorResult::new(
                            "git.lastsync.fresh",
                            "Last sync fresh",
                            Status::Warn,
                            format!("last sync {age_str} ago"),
                            false,
                        )
                        .with_hint("run `symvault git pull` to sync latest changes")
                        .with_tags(vec!["network".into()])
                    } else {
                        DoctorResult::new(
                            "git.lastsync.fresh",
                            "Last sync fresh",
                            Status::Ok,
                            format!("last sync {age_str} ago"),
                            false,
                        )
                        .with_tags(vec!["network".into()])
                    }
                }
            }
        }
    }
}

fn walk_size(dir: &Path, count: &mut usize, total_bytes: &mut u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk_size(&entry.path(), count, total_bytes);
        } else {
            *count += 1;
            if let Ok(meta) = entry.metadata() {
                *total_bytes += meta.len();
            }
        }
    }
}

fn check_vault_size(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let entries_dir = vault_dir.join("entries");
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    walk_size(&entries_dir, &mut count, &mut total_bytes);
    let mb = total_bytes as f64 / 1024.0 / 1024.0;
    DoctorResult::new(
        "vault.size",
        "Vault size",
        Status::Ok,
        format!("{count} entries, {mb:.2} MB"),
        false,
    )
}

fn find_stale_temp_files(vault_dir: &Path, now: SystemTime) -> Result<Vec<PathBuf>, io::Error> {
    let entries = fs::read_dir(vault_dir)?;
    let mut stale = Vec::new();
    let threshold = Duration::from_secs(24 * 3600);

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.contains(".tmp-") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(mod_time) = meta.modified() else {
            continue;
        };
        if let Ok(age) = now.duration_since(mod_time)
            && age > threshold
        {
            stale.push(entry.path());
        }
    }
    stale.sort();
    Ok(stale)
}

fn check_vault_stale_temp_files(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let vd = vault_dir.to_path_buf();
    let fix_fn = move || {
        let stale = find_stale_temp_files(&vd, SystemTime::now()).map_err(|e| e.to_string())?;
        for path in stale {
            let _ = fs::remove_file(&path);
        }
        Ok(())
    };

    match find_stale_temp_files(vault_dir, SystemTime::now()) {
        Err(err) => DoctorResult::new(
            "vault.stale_temp_files",
            "Stale atomic-write temp files",
            Status::Warn,
            format!(
                "cannot inspect atomic-write temp files: {}",
                format_go_path_error("open", vault_dir, &err)
            ),
            true,
        )
        .with_fix(fix_fn),
        Ok(stale) if stale.is_empty() => DoctorResult::new(
            "vault.stale_temp_files",
            "Stale atomic-write temp files",
            Status::Ok,
            "no stale atomic-write temp files",
            true,
        )
        .with_fix(fix_fn),
        Ok(stale) => {
            let names: Vec<String> = stale
                .iter()
                .map(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            DoctorResult::new(
                "vault.stale_temp_files",
                "Stale atomic-write temp files",
                Status::Warn,
                format!(
                    "{} stale atomic-write temp file(s): {}",
                    names.len(),
                    names.join(", ")
                ),
                true,
            )
            .with_hint("run `symvault doctor --fix` to remove files older than 24h")
            .with_fix(fix_fn)
        }
    }
}

pub struct ConflictFile {
    pub path: PathBuf,
    pub rel: String,
    pub redundant: bool,
}

pub fn parse_conflict_name(base: &str) -> Option<(String, String)> {
    let marker = ".conflict-";
    let idx = base.find(marker)?;
    if idx == 0 {
        return None;
    }
    let rest = &base[idx + marker.len()..];
    let dot = rest.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let shadowed = format!("{}{}", &base[..idx], &rest[dot..]);
    let device = rest[..dot].to_string();
    Some((shadowed, device))
}

fn same_content(a: &Path, b: &Path) -> bool {
    let Ok(data_a) = fs::read(a) else {
        return false;
    };
    let Ok(data_b) = fs::read(b) else {
        return false;
    };
    data_a == data_b
}

pub fn find_conflict_copies(vault_dir: &Path) -> Result<Vec<ConflictFile>, io::Error> {
    let mut found = Vec::new();
    walk_conflicts(vault_dir, vault_dir, &mut found)?;
    found.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(found)
}

fn walk_conflicts(
    root: &Path,
    current: &Path,
    found: &mut Vec<ConflictFile>,
) -> Result<(), io::Error> {
    let entries = fs::read_dir(current)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if name == ".git" {
                continue;
            }
            walk_conflicts(root, &path, found)?;
        } else if let Some((shadowed, _)) = parse_conflict_name(&name) {
            let shadowed_path = current.join(shadowed);
            let rel = match path.strip_prefix(root) {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => name,
            };
            found.push(ConflictFile {
                path: path.clone(),
                rel,
                redundant: same_content(&path, &shadowed_path),
            });
        }
    }
    Ok(())
}

fn check_vault_conflict_files(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let vd = vault_dir.to_path_buf();
    let fix_fn = move || {
        let current = find_conflict_copies(&vd).map_err(|e| e.to_string())?;
        for c in current {
            if c.redundant
                && let Err(err) = fs::remove_file(&c.path)
                && err.kind() != io::ErrorKind::NotFound
            {
                return Err(format!("remove {}: {err}", c.rel));
            }
        }
        Ok(())
    };

    match find_conflict_copies(vault_dir) {
        Err(err) => DoctorResult::new(
            "vault.conflict_files",
            "Orphaned git-sync conflict files",
            Status::Warn,
            format!(
                "cannot inspect conflict files: {}",
                format_go_path_error("lstat", vault_dir, &err)
            ),
            false,
        ),
        Ok(found) => {
            let mut redundant = Vec::new();
            let mut pending = Vec::new();
            for c in found {
                if c.redundant {
                    redundant.push(c.rel);
                } else {
                    pending.push(c.rel);
                }
            }
            if redundant.is_empty() && pending.is_empty() {
                DoctorResult::new(
                    "vault.conflict_files",
                    "Orphaned git-sync conflict files",
                    Status::Ok,
                    "no git-sync conflict files",
                    false,
                )
            } else {
                let mut parts = Vec::new();
                if !redundant.is_empty() {
                    parts.push(format!(
                        "{} orphaned conflict file(s) identical to the file they shadow: {}",
                        redundant.len(),
                        redundant.join(", ")
                    ));
                }
                if !pending.is_empty() {
                    parts.push(format!(
                        "{} conflict file(s) with unmerged content: {}",
                        pending.len(),
                        pending.join(", ")
                    ));
                }
                let hint = if !redundant.is_empty() && !pending.is_empty() {
                    "run `symvault doctor --fix` to remove the orphaned copies; compare the remaining ones by hand before deleting them"
                } else if !redundant.is_empty() {
                    "run `symvault doctor --fix` to remove the orphaned copies"
                } else {
                    "compare each conflict file with the file it shadows, then delete it by hand"
                };
                let fixable = !redundant.is_empty();
                let mut r = DoctorResult::new(
                    "vault.conflict_files",
                    "Orphaned git-sync conflict files",
                    Status::Warn,
                    parts.join("; "),
                    fixable,
                )
                .with_hint(hint);
                if fixable {
                    r = r.with_fix(fix_fn);
                }
                r
            }
        }
    }
}

fn check_search_index_persistence(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    DoctorResult::new(
        "vault.search_index.persistence",
        "Search index persistence",
        Status::Ok,
        "no search index persistence failures recorded this session",
        false,
    )
}

fn check_passphrase_rotation(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    match fs::read(&cfg_path) {
        Err(err) => DoctorResult::new(
            "auth.passphrase.rotation",
            "Passphrase rotation",
            Status::Warn,
            format!(
                "cannot load config: {}",
                format_go_path_error("open", &cfg_path, &err)
            ),
            false,
        ),
        Ok(bytes) => match Config::load_from_bytes(&bytes) {
            Err(err) => DoctorResult::new(
                "auth.passphrase.rotation",
                "Passphrase rotation",
                Status::Warn,
                format!("cannot load config: {err}"),
                false,
            ),
            Ok(cfg) => {
                let last_rotated_str = cfg.vault.as_ref().and_then(|v| v.last_rotated.as_deref());
                match last_rotated_str {
                    None | Some("") => DoctorResult::new(
                        "auth.passphrase.rotation",
                        "Passphrase rotation",
                        Status::Warn,
                        "passphrase never rotated \u{2014} rotation is recommended for security hygiene",
                        false,
                    )
                    .with_hint("run `symvault auth rotate-passphrase` to rotate"),
                    Some(s) => {
                        match time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
                            Err(_) => DoctorResult::new(
                                "auth.passphrase.rotation",
                                "Passphrase rotation",
                                Status::Warn,
                                "passphrase never rotated \u{2014} rotation is recommended for security hygiene",
                                false,
                            )
                            .with_hint("run `symvault auth rotate-passphrase` to rotate"),
                            Ok(rotated_time) => {
                                let now = time::OffsetDateTime::now_utc();
                                let diff = now - rotated_time;
                                let total_seconds = diff.whole_seconds().max(0);
                                let age_str = format_duration_days(total_seconds);
                                if total_seconds > 365 * 24 * 3600 {
                                    DoctorResult::new(
                                        "auth.passphrase.rotation",
                                        "Passphrase rotation",
                                        Status::Warn,
                                        format!("last rotated {age_str} ago (recommended: every 365 days)"),
                                        false,
                                    )
                                    .with_hint("run `symvault auth rotate-passphrase` to rotate")
                                } else {
                                    DoctorResult::new(
                                        "auth.passphrase.rotation",
                                        "Passphrase rotation",
                                        Status::Ok,
                                        format!("last rotated {age_str} ago"),
                                        false,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Output Formatting
// ---------------------------------------------------------------------------

pub fn render_text(
    vault_dir: &Path,
    results: &[DoctorResult],
    out: &mut impl Write,
) -> Result<(), io::Error> {
    writeln!(
        out,
        "Symaira Vault Doctor \u{2014} Vault: {}\n",
        vault_dir.display()
    )?;

    for r in results {
        let symbol = match r.status {
            Status::Ok => " \u{2713} ",
            Status::Warn => " \u{26a0} ",
            Status::Fail => " \u{2717} ",
        };

        let fixed_tag = if r.fixed { " (fixed)" } else { "" };
        let fixable_tag = if r.fixable && r.status != Status::Ok {
            " (fixable \u{2014} run with --fix)"
        } else {
            ""
        };

        writeln!(
            out,
            "{symbol} {:<40} {}{fixed_tag}{fixable_tag}",
            r.name, r.message
        )?;

        if let Some(hint) = &r.hint
            && !hint.is_empty()
        {
            writeln!(out, "    \u{2192} {hint}")?;
        }
    }

    let sc = score(results);
    write!(out, "\nScore: {}/{} OK", sc.ok, sc.total)?;
    if sc.warn > 0 {
        write!(out, " \u{00b7} {} warning(s)", sc.warn)?;
    }
    if sc.fail > 0 {
        write!(out, " \u{00b7} {} failed", sc.fail)?;
    }
    writeln!(out)?;
    Ok(())
}

/// A `serde_json` formatter that emits 2-space indented pretty JSON and
/// escapes `<`, `>`, `&`, `\u2028`, `\u2029` like Go's `json.Marshal`.
struct GoPrettyFormatter<'a> {
    pretty: PrettyFormatter<'a>,
}

impl Default for GoPrettyFormatter<'_> {
    fn default() -> Self {
        Self {
            pretty: PrettyFormatter::with_indent(b"  "),
        }
    }
}

impl Formatter for GoPrettyFormatter<'_> {
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_array(writer)
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object(writer)
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }

    fn end_object_key<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_key(writer)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_value(writer)
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (index, ch) in fragment.char_indices() {
            let escaped = match ch {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            if start < index {
                writer.write_all(&fragment.as_bytes()[start..index])?;
            }
            writer.write_all(escaped.as_bytes())?;
            start = index + ch.len_utf8();
        }
        if start < fragment.len() {
            writer.write_all(&fragment.as_bytes()[start..])?;
        }
        Ok(())
    }
}

pub fn to_json_pretty_string<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut buffer = Vec::with_capacity(512);
    let mut serializer = Serializer::with_formatter(&mut buffer, GoPrettyFormatter::default());
    value.serialize(&mut serializer)?;
    let mut s = String::from_utf8(buffer).expect("valid utf-8");
    s.push('\n');
    Ok(s)
}

pub fn render_json(
    vault_dir: &Path,
    results: &[DoctorResult],
    out: &mut impl Write,
) -> Result<(), io::Error> {
    let sc = score(results);
    let vault_str = vault_dir.to_string_lossy();
    let json_out = DoctorJsonOutput {
        schema_version: "1.0",
        vault_dir: &vault_str,
        results,
        score: sc,
    };
    let json_str = to_json_pretty_string(&json_out).map_err(|e| io::Error::other(e.to_string()))?;
    out.write_all(json_str.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_conflict_name_cases() {
        let cases = [
            (
                "config.conflict-macbook-2.yaml",
                Some(("config.yaml", "macbook-2")),
            ),
            (
                "config.conflict-MacBook-2.local.yaml",
                Some(("config.yaml", "MacBook-2.local")),
            ),
            ("a.b.conflict-mac.age", Some(("a.b.age", "mac"))),
            ("config.yaml", None),
            ("manifest.age", None),
            (".conflict-mac.age", None),
            ("config.conflict-macbook", None),
        ];
        for (input, expected) in cases {
            let actual = parse_conflict_name(input);
            match expected {
                Some((sh, dev)) => {
                    assert_eq!(
                        actual,
                        Some((sh.to_string(), dev.to_string())),
                        "failed on {input}"
                    );
                }
                None => {
                    assert_eq!(actual, None, "expected None on {input}");
                }
            }
        }
    }

    #[test]
    fn registry_order_is_deterministic() {
        let opts = DoctorOptions::default();
        let tmp = tempfile::tempdir().unwrap();
        let results = run_checks(tmp.path(), &opts);
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "vault.initialized",
                "vault.config.parses",
                "vault.config.validates",
                "vault.identity.encrypted",
                "vault.permissions",
                "git.repo",
                "git.remote",
                "git.gitignore.protects",
                "git.lastsync.fresh",
                "vault.size",
                "vault.stale_temp_files",
                "vault.conflict_files",
                "vault.search_index.persistence",
                "auth.passphrase.rotation",
            ]
        );
    }

    #[test]
    fn filtering_only_and_exclude_and_no_network() {
        let tmp = tempfile::tempdir().unwrap();

        // no-network excludes git.lastsync.fresh
        let opts = DoctorOptions {
            no_network: true,
            ..Default::default()
        };
        let results = run_checks(tmp.path(), &opts);
        assert!(!results.iter().any(|r| r.id == "git.lastsync.fresh"));

        // only filter
        let opts_only = DoctorOptions {
            only: vec!["vault.config.*".to_string()],
            ..Default::default()
        };
        let results_only = run_checks(tmp.path(), &opts_only);
        let ids: Vec<&str> = results_only.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["vault.config.parses", "vault.config.validates"]);

        // exclude filter
        let opts_exclude = DoctorOptions {
            exclude: vec!["vault.*".to_string(), "git.*".to_string()],
            ..Default::default()
        };
        let results_exclude = run_checks(tmp.path(), &opts_exclude);
        let ids: Vec<&str> = results_exclude.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["auth.passphrase.rotation"]);
    }

    #[test]
    fn fix_dry_run_is_effect_free() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = DoctorOptions {
            only: vec!["git.repo".to_string()],
            ..Default::default()
        };
        let mut results = run_checks(tmp.path(), &opts);
        assert_eq!(results[0].status, Status::Warn);

        let mut output = Vec::new();
        apply_fixes(&mut results, true, true, &mut output).unwrap();

        let log = String::from_utf8_lossy(&output);
        assert!(log.contains("Would fix git.repo:"));
        // Check that .git was NOT created
        assert!(!tmp.path().join(".git").exists());
        // Check that result was NOT marked fixed
        assert!(!results[0].fixed);
        assert_eq!(results[0].status, Status::Warn);
    }

    #[test]
    fn fix_creates_git_repo_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = DoctorOptions {
            only: vec!["git.repo".to_string()],
            ..Default::default()
        };
        let mut results = run_checks(tmp.path(), &opts);
        assert_eq!(results[0].status, Status::Warn);

        let mut output = Vec::new();
        apply_fixes(&mut results, true, false, &mut output).unwrap();

        assert!(tmp.path().join(".git").exists());
        assert!(results[0].fixed);
        assert_eq!(results[0].status, Status::Ok);
        assert!(results[0].message.starts_with("fixed \u{2014} "));

        // Re-run: should be ok and not fix again
        let mut re_results = run_checks(tmp.path(), &opts);
        assert_eq!(re_results[0].status, Status::Ok);
        apply_fixes(&mut re_results, true, false, &mut output).unwrap();
        assert!(!re_results[0].fixed);
    }

    #[test]
    fn fix_protects_gitignore_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = DoctorOptions {
            only: vec!["git.gitignore.protects".to_string()],
            ..Default::default()
        };
        let mut results = run_checks(tmp.path(), &opts);
        assert_eq!(results[0].status, Status::Warn);

        let mut output = Vec::new();
        apply_fixes(&mut results, true, false, &mut output).unwrap();

        let gitignore = tmp.path().join(".gitignore");
        assert!(gitignore.exists());
        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("identity.age"));
        assert!(content.contains("mcp-token"));
        assert!(content.contains("mcp-tokens.json"));
        assert!(results[0].fixed);

        // Run fix again: should remain unchanged
        let before = content.clone();
        let mut re_results = run_checks(tmp.path(), &opts);
        assert_eq!(re_results[0].status, Status::Ok);
        apply_fixes(&mut re_results, true, false, &mut output).unwrap();
        let after = fs::read_to_string(&gitignore).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn fix_removes_stale_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let stale_file = tmp.path().join("test.tmp-12345");
        fs::write(&stale_file, b"temp content").unwrap();

        // Backdate modified time to 2020 using touch -t
        let status = std::process::Command::new("touch")
            .args(["-t", "202001010000", stale_file.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success());

        let opts = DoctorOptions {
            only: vec!["vault.stale_temp_files".to_string()],
            ..Default::default()
        };
        let mut results = run_checks(tmp.path(), &opts);
        assert_eq!(results[0].status, Status::Warn);

        // Dry-run first
        let mut output = Vec::new();
        apply_fixes(&mut results, true, true, &mut output).unwrap();
        assert!(stale_file.exists());

        // Actual fix
        apply_fixes(&mut results, true, false, &mut output).unwrap();
        assert!(!stale_file.exists());
        assert!(results[0].fixed);
    }

    #[test]
    fn fix_removes_redundant_conflict_files() {
        let tmp = tempfile::tempdir().unwrap();
        let main_file = tmp.path().join("config.yaml");
        let conflict_redundant = tmp.path().join("config.conflict-mac.yaml");
        let conflict_different = tmp.path().join("entries.conflict-mac.age");

        fs::write(&main_file, b"same content").unwrap();
        fs::write(&conflict_redundant, b"same content").unwrap();
        fs::write(&conflict_different, b"different content").unwrap();

        let opts = DoctorOptions {
            only: vec!["vault.conflict_files".to_string()],
            ..Default::default()
        };
        let mut results = run_checks(tmp.path(), &opts);
        assert_eq!(results[0].status, Status::Warn);
        assert!(
            results[0]
                .message
                .contains("1 orphaned conflict file(s) identical")
        );
        assert!(
            results[0]
                .message
                .contains("1 conflict file(s) with unmerged content")
        );

        // Dry-run
        let mut output = Vec::new();
        apply_fixes(&mut results, true, true, &mut output).unwrap();
        assert!(conflict_redundant.exists());
        assert!(conflict_different.exists());

        // Real fix
        apply_fixes(&mut results, true, false, &mut output).unwrap();
        assert!(!conflict_redundant.exists());
        assert!(conflict_different.exists());
    }
}
