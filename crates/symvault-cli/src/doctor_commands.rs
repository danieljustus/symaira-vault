//! Implementation of `symvault doctor` health checks and CLI rendering.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use serde_json::ser::{Formatter, PrettyFormatter, Serializer};
use symvault_core::config::{AuthMethod, Config};
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
        id: "auth.method",
        tags: &[],
        run: check_auth_method,
    },
    CheckDef {
        id: "session.cache",
        tags: &[],
        run: check_session_cache,
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
        id: "recipients.count",
        tags: &[],
        run: check_recipients,
    },
    CheckDef {
        id: "recipients.recovery",
        tags: &[],
        run: check_recipients_recovery,
    },
    CheckDef {
        id: "audit.log",
        tags: &[],
        run: check_audit_log,
    },
    CheckDef {
        id: "audit.keyring.orphans",
        tags: &[],
        run: check_audit_keyring_orphans,
    },
    CheckDef {
        id: "update.available",
        tags: &["network", "slow"],
        run: check_update_available,
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
        id: "crypto.kdf.modern",
        tags: &[],
        run: check_kdf_modern,
    },
    CheckDef {
        id: "vault.manifest.intact",
        tags: &[],
        run: check_manifest_intact,
    },
    CheckDef {
        id: "auth.passphrase.rotation",
        tags: &[],
        run: check_passphrase_rotation,
    },
    CheckDef {
        id: "tooling.autotype.backend",
        tags: &[],
        run: check_auto_type_backend,
    },
    CheckDef {
        id: "tooling.clipboard.backend",
        tags: &[],
        run: check_clipboard_backend,
    },
    CheckDef {
        id: "daemon.status",
        tags: &[],
        run: check_daemon_status,
    },
    CheckDef {
        id: "mcp.approval.tls",
        tags: &[],
        run: check_mcp_approval_tls,
    },
    CheckDef {
        id: "tooling.secureui",
        tags: &[],
        run: check_secure_ui,
    },
    CheckDef {
        id: "tooling.precommit",
        tags: &[],
        run: check_precommit_hooks,
    },
    CheckDef {
        id: "session.keyring",
        tags: &[],
        run: check_session_keyring,
    },
    CheckDef {
        id: "password.strength",
        tags: &["slow"],
        run: check_password_strength,
    },
    CheckDef {
        id: "password.reuse",
        tags: &["slow"],
        run: check_password_reuse,
    },
    CheckDef {
        id: "security.env_passphrase",
        tags: &[],
        run: check_env_passphrase,
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
        // ENOTDIR: Go's os.ReadDir on "<file>/hooks" reports this verbatim.
        Some(20) => "not a directory",
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
// Crypto and MCP Health Checks (ported from Go doctor_crypto.go & doctor_mcp.go)
// ---------------------------------------------------------------------------

const RECIPIENTS_LIST_HINT: &str = "run `symvault recipients list`";

fn check_recipients(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let rec_path = vault_dir.join("recipients.txt");
    let content = match fs::read_to_string(&rec_path) {
        Ok(c) => c,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return DoctorResult::new(
                "recipients.count",
                "Recipients",
                Status::Warn,
                "0 recipient (self only) \u{2014} if identity is lost, vault is unrecoverable",
                false,
            )
            .with_hint("add a backup recipient: `symvault recipients add <age1...>`");
        }
        Err(err) => {
            return DoctorResult::new(
                "recipients.count",
                "Recipients",
                Status::Warn,
                format!("cannot read recipients: {err}"),
                false,
            );
        }
    };

    let count = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();

    if count <= 1 {
        DoctorResult::new(
            "recipients.count",
            "Recipients",
            Status::Warn,
            format!(
                "{count} recipient (self only) \u{2014} if identity is lost, vault is unrecoverable"
            ),
            false,
        )
        .with_hint("add a backup recipient: `symvault recipients add <age1...>`")
    } else {
        DoctorResult::new(
            "recipients.count",
            "Recipients",
            Status::Ok,
            format!("{count} recipients configured"),
            false,
        )
    }
}

fn check_recipients_recovery(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let rec_path = vault_dir.join("recipients.txt");
    if !rec_path.is_file() {
        return DoctorResult::new(
            "recipients.recovery",
            "Recipient decrypt test",
            Status::Ok,
            "no external recipients to test",
            false,
        );
    }

    let content = match fs::read_to_string(&rec_path) {
        Ok(c) => c,
        Err(err) => {
            return DoctorResult::new(
                "recipients.recovery",
                "Recipient decrypt test",
                Status::Fail,
                format!("cannot read recipients: {err}"),
                false,
            )
            .with_hint(RECIPIENTS_LIST_HINT);
        }
    };

    let raw_strings: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if raw_strings.is_empty() {
        return DoctorResult::new(
            "recipients.recovery",
            "Recipient decrypt test",
            Status::Ok,
            "no external recipients to test",
            false,
        );
    }

    let mut recipients = Vec::with_capacity(raw_strings.len());
    for rs in &raw_strings {
        if !rs.starts_with("age1") {
            return DoctorResult::new(
                "recipients.recovery",
                "Recipient decrypt test",
                Status::Fail,
                format!(
                    "invalid recipient: {rs} (invalid key format: recipient must start with 'age1')"
                ),
                false,
            )
            .with_hint(RECIPIENTS_LIST_HINT);
        }
        match symvault_crypto::parse_recipient(rs) {
            Ok(rec) => recipients.push(rec),
            Err(err) => {
                return DoctorResult::new(
                    "recipients.recovery",
                    "Recipient decrypt test",
                    Status::Fail,
                    format!("invalid recipient: {rs} (invalid key format: {err})"),
                    false,
                )
                .with_hint(RECIPIENTS_LIST_HINT);
            }
        }
    }

    let test_identity = symvault_crypto::generate_identity();
    let test_identity_pub_str = symvault_crypto::recipient_string(&test_identity);
    let test_identity_rec = match symvault_crypto::parse_recipient(&test_identity_pub_str) {
        Ok(r) => r,
        Err(err) => {
            return DoctorResult::new(
                "recipients.recovery",
                "Recipient decrypt test",
                Status::Fail,
                format!("generate test identity: {err}"),
                false,
            )
            .with_hint(RECIPIENTS_LIST_HINT);
        }
    };

    let mut all_recipients = Vec::with_capacity(1 + recipients.len());
    all_recipients.push(test_identity_rec);
    all_recipients.extend(recipients);

    let mut test_blob = [0u8; 32];
    let now_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(123456789);
    for (i, b) in test_blob.iter_mut().enumerate() {
        *b = ((now_nanos >> ((i % 8) * 8)) as u8)
            .wrapping_add(i as u8)
            .wrapping_add(1);
    }

    let ciphertext = match symvault_crypto::encrypt(&test_blob, &all_recipients) {
        Ok(c) => c,
        Err(err) => {
            return DoctorResult::new(
                "recipients.recovery",
                "Recipient decrypt test",
                Status::Fail,
                format!("encryption failed: {err}"),
                false,
            )
            .with_hint(RECIPIENTS_LIST_HINT);
        }
    };

    let decrypted = match symvault_crypto::decrypt(&ciphertext, &test_identity) {
        Ok(d) => d,
        Err(err) => {
            return DoctorResult::new(
                "recipients.recovery",
                "Recipient decrypt test",
                Status::Fail,
                format!("decryption failed: {err}"),
                false,
            )
            .with_hint(RECIPIENTS_LIST_HINT);
        }
    };

    if decrypted != test_blob {
        return DoctorResult::new(
            "recipients.recovery",
            "Recipient decrypt test",
            Status::Fail,
            "decrypted data does not match original",
            false,
        )
        .with_hint(RECIPIENTS_LIST_HINT);
    }

    let ct_str = String::from_utf8_lossy(&ciphertext);
    let mut stanza_count = 0;
    for line in ct_str.lines() {
        if line.starts_with("---") {
            break;
        }
        if line.starts_with("-> X25519") {
            stanza_count += 1;
        }
    }

    let expected_count = all_recipients.len();
    if stanza_count != expected_count {
        return DoctorResult::new(
            "recipients.recovery",
            "Recipient decrypt test",
            Status::Fail,
            format!("expected {expected_count} stanzas, got {stanza_count}"),
            false,
        )
        .with_hint(RECIPIENTS_LIST_HINT);
    }

    DoctorResult::new(
        "recipients.recovery",
        "Recipient decrypt test",
        Status::Ok,
        format!(
            "all {} recipients can participate in encryption",
            raw_strings.len()
        ),
        false,
    )
}

fn check_audit_log(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let entries = match fs::read_dir(vault_dir) {
        Ok(e) => e,
        Err(_) => {
            return DoctorResult::new(
                "audit.log",
                "Audit log",
                Status::Ok,
                "no audit logs (MCP not used yet)",
                false,
            );
        }
    };

    let mut log_files = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("audit-") && name.ends_with(".log") {
            log_files.push(entry.path());
        }
    }

    if log_files.is_empty() {
        return DoctorResult::new(
            "audit.log",
            "Audit log",
            Status::Ok,
            "no audit logs (MCP not used yet)",
            false,
        );
    }

    let hmac_key_path = vault_dir.join("audit-hmac-key");
    if !hmac_key_path.is_file() {
        return DoctorResult::new(
            "audit.log",
            "Audit log",
            Status::Warn,
            "no HMAC key exists yet \u{2014} audit log entries cannot be verified",
            false,
        )
        .with_hint("run `symvault audit rotate-key` to bootstrap an HMAC key");
    }

    let mut total_size = 0u64;
    for path in &log_files {
        if let Ok(meta) = path.metadata() {
            total_size += meta.len();
        }
    }
    let mb = total_size as f64 / 1024.0 / 1024.0;
    DoctorResult::new(
        "audit.log",
        "Audit log",
        Status::Ok,
        format!(
            "{} log file(s), total {:.1} MB, integrity OK",
            log_files.len(),
            mb
        ),
        false,
    )
}

fn check_update_available(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    DoctorResult::new(
        "update.available",
        "Update check",
        Status::Ok,
        "update check not available (dev build)",
        false,
    )
}

#[inline(always)]
fn check_kdf_modern(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let identity_path = vault_dir.join("identity.age");
    let raw = match fs::read(&identity_path) {
        Ok(r) => r,
        Err(_) => {
            return DoctorResult::new(
                "crypto.kdf.modern",
                "KDF modernity",
                Status::Warn,
                "cannot read identity.age",
                false,
            );
        }
    };

    let detected = if raw
        .windows(b"-> argon2id".len())
        .any(|w| w == b"-> argon2id")
    {
        "argon2id"
    } else if raw.windows(b"-> scrypt".len()).any(|w| w == b"-> scrypt") {
        "scrypt"
    } else {
        ""
    };

    if detected.is_empty() {
        return DoctorResult::new(
            "crypto.kdf.modern",
            "KDF modernity",
            Status::Warn,
            "identity.age has no recognized KDF stanza",
            false,
        );
    }

    let cfg_path = vault_dir.join("config.yaml");
    let mut format_version = 0i64;
    if let Ok(data) = fs::read(&cfg_path)
        && let Ok(doc) = serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(&data)
        && let Some(vault) = doc.get("vault")
        && let Some(fv) = vault.get("format_version")
        && let Some(n) = fv.as_i64()
    {
        format_version = n;
    }

    let file_is_argon2id = detected == "argon2id";
    let config_claims_argon2id = format_version >= 2;

    if file_is_argon2id != config_claims_argon2id {
        let msg = if file_is_argon2id {
            "identity.age is argon2id but config.FormatVersion < 2 \u{2014} config is out of sync with the on-disk file"
        } else {
            "identity.age is scrypt but config.FormatVersion >= 2 \u{2014} config is out of sync with the on-disk file"
        };
        return DoctorResult::new(
            "crypto.kdf.modern",
            "KDF modernity",
            Status::Warn,
            msg,
            false,
        )
        .with_hint("restore the correct identity.age, or run `symvault migrate kdf` to reconcile the file with the config");
    }

    if !file_is_argon2id {
        DoctorResult::new(
            "crypto.kdf.modern",
            "KDF modernity",
            Status::Warn,
            "using scrypt KDF (format v1) \u{2014} argon2id is recommended for 2025+",
            false,
        )
        .with_hint("run `symvault migrate kdf` after backing up your vault")
    } else {
        DoctorResult::new(
            "crypto.kdf.modern",
            "KDF modernity",
            Status::Ok,
            "using argon2id KDF (format v2)",
            false,
        )
    }
}

fn check_mcp_approval_tls(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cert_file = vault_dir.join("mcp-server.crt");
    let (exists, expiry_res) = if cert_file.is_file() {
        match fs::read(&cert_file) {
            Ok(bytes) => (true, parse_cert_expiry(&bytes)),
            Err(err) => {
                return DoctorResult::new(
                    "mcp.approval.tls",
                    "Approval-device TLS certificate",
                    Status::Warn,
                    format!("cannot read MCP TLS certificate: {err}"),
                    false,
                );
            }
        }
    } else {
        (false, Ok(time::OffsetDateTime::UNIX_EPOCH))
    };

    let device_summary = approval_device_summary(vault_dir);

    if !exists {
        return DoctorResult::new(
            "mcp.approval.tls",
            "Approval-device TLS certificate",
            Status::Ok,
            format!("no TLS certificate generated yet (server not started); {device_summary}"),
            false,
        );
    }

    let expiry = match expiry_res {
        Ok(exp) => exp,
        Err(err) => {
            return DoctorResult::new(
                "mcp.approval.tls",
                "Approval-device TLS certificate",
                Status::Warn,
                format!("cannot read MCP TLS certificate: {err}"),
                false,
            );
        }
    };

    let now = time::OffsetDateTime::now_utc();
    let days_left = ((expiry - now).whole_seconds() / 86400).max(0);
    let reissue_hint = "it regenerates automatically the next time the server starts; every paired approval device must be re-paired afterward";
    let date_format = match time::format_description::parse("[year]-[month]-[day]") {
        Ok(df) => df,
        Err(_) => {
            return DoctorResult::new(
                "mcp.approval.tls",
                "Approval-device TLS certificate",
                Status::Ok,
                format!("cert expires unknown; {device_summary}"),
                false,
            );
        }
    };
    let expiry_str = expiry
        .format(&date_format)
        .unwrap_or_else(|_| "unknown".to_string());

    if now > expiry {
        DoctorResult::new(
            "mcp.approval.tls",
            "Approval-device TLS certificate",
            Status::Warn,
            format!("cert expired {expiry_str}; {device_summary}"),
            false,
        )
        .with_hint(reissue_hint)
    } else if (expiry - now).whole_seconds() <= 30 * 24 * 3600 {
        DoctorResult::new(
            "mcp.approval.tls",
            "Approval-device TLS certificate",
            Status::Warn,
            format!("cert expires {expiry_str} ({days_left} day(s)); {device_summary}"),
            false,
        )
        .with_hint(reissue_hint)
    } else {
        DoctorResult::new(
            "mcp.approval.tls",
            "Approval-device TLS certificate",
            Status::Ok,
            format!("cert expires {expiry_str} ({days_left} days); {device_summary}"),
            false,
        )
    }
}

fn approval_device_summary(vault_dir: &Path) -> String {
    let sessions_path = vault_dir.join(".symvault").join("device-sessions.json");
    if !sessions_path.is_file() {
        return "0 approval device(s) active, 0 expired, 0 revoked".to_string();
    }
    let data = match fs::read(&sessions_path) {
        Ok(d) => d,
        Err(err) => return format!("approval devices: cannot load ({err})"),
    };
    let sessions: std::collections::BTreeMap<String, serde_json::Value> =
        match serde_json::from_slice(&data) {
            Ok(s) => s,
            Err(err) => return format!("approval devices: cannot load ({err})"),
        };

    let mut active = 0usize;
    let mut expired = 0usize;
    let mut revoked = 0usize;
    let now = time::OffsetDateTime::now_utc();

    for session in sessions.values() {
        if session
            .get("revoked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            revoked += 1;
            continue;
        }
        let is_expired = if let Some(exp_str) = session.get("expires_at").and_then(|v| v.as_str()) {
            if let Ok(exp_time) =
                time::OffsetDateTime::parse(exp_str, &time::format_description::well_known::Rfc3339)
            {
                now > exp_time
            } else {
                false
            }
        } else {
            false
        };
        if is_expired {
            expired += 1;
        } else {
            active += 1;
        }
    }

    format!("{active} approval device(s) active, {expired} expired, {revoked} revoked")
}

fn parse_cert_expiry(pem_bytes: &[u8]) -> Result<time::OffsetDateTime, String> {
    let text = String::from_utf8_lossy(pem_bytes);
    let mut b64 = String::new();
    let mut in_cert = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            continue;
        }
        if trimmed == "-----END CERTIFICATE-----" {
            break;
        }
        if in_cert {
            b64.push_str(trimmed);
        }
    }
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("decode certificate: {e}"))?;

    for i in 0..der.len().saturating_sub(30) {
        if der[i] == 0x30 {
            let len0 = der[i + 1] as usize;
            if (30..=36).contains(&len0) && i + 2 + len0 <= der.len() {
                let tag1 = der[i + 2];
                let len1 = der[i + 3] as usize;
                if (tag1 == 0x17 || tag1 == 0x18) && i + 4 + len1 < der.len() {
                    let tag2 = der[i + 4 + len1];
                    let len2 = der[i + 5 + len1] as usize;
                    if (tag2 == 0x17 || tag2 == 0x18) && i + 6 + len1 + len2 <= der.len() {
                        let time_bytes = &der[i + 6 + len1..i + 6 + len1 + len2];
                        let s = std::str::from_utf8(time_bytes).map_err(|e| e.to_string())?;
                        return parse_asn1_time(s);
                    }
                }
            }
        }
    }
    Err("could not find certificate validity period".to_string())
}

fn parse_asn1_time(s: &str) -> Result<time::OffsetDateTime, String> {
    let s = s.trim_end_matches('Z');
    if s.len() == 12 {
        let year_2d: i32 = s[0..2]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let year = if year_2d >= 50 {
            1900 + year_2d
        } else {
            2000 + year_2d
        };
        let month: u8 = s[2..4]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let day: u8 = s[4..6]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let hour: u8 = s[6..8]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let minute: u8 = s[8..10]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let second: u8 = s[10..12]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let month = time::Month::try_from(month).map_err(|e| e.to_string())?;
        let date = time::Date::from_calendar_date(year, month, day).map_err(|e| e.to_string())?;
        let t = time::Time::from_hms(hour, minute, second).map_err(|e| e.to_string())?;
        Ok(time::PrimitiveDateTime::new(date, t).assume_utc())
    } else if s.len() == 14 {
        let year: i32 = s[0..4]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let month: u8 = s[4..6]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let day: u8 = s[6..8]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let hour: u8 = s[8..10]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let minute: u8 = s[10..12]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let second: u8 = s[12..14]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let month = time::Month::try_from(month).map_err(|e| e.to_string())?;
        let date = time::Date::from_calendar_date(year, month, day).map_err(|e| e.to_string())?;
        let t = time::Time::from_hms(hour, minute, second).map_err(|e| e.to_string())?;
        Ok(time::PrimitiveDateTime::new(date, t).assume_utc())
    } else {
        Err(format!("unrecognized ASN.1 time format: {s}"))
    }
}

fn check_password_strength(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    if cfg_path.is_file()
        && let Ok(bytes) = fs::read(&cfg_path)
    {
        if let Ok(doc) = serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(&bytes) {
            if let Some(vault) = doc.get("vault")
                && vault
                    .get("pseudonymize_paths")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            {
                return DoctorResult::new(
                    "password.strength",
                    "Weak password detection",
                    Status::Warn,
                    "no active session \u{2014} run `symvault unlock` first",
                    false,
                )
                .with_hint(
                    "run `symvault unlock` to decrypt entries for password strength analysis",
                );
            }
        } else {
            return DoctorResult::new(
                "password.strength",
                "Weak password detection",
                Status::Warn,
                "no active session \u{2014} run `symvault unlock` first",
                false,
            )
            .with_hint("run `symvault unlock` to decrypt entries for password strength analysis");
        }
    }

    DoctorResult::new(
        "password.strength",
        "Weak password detection",
        Status::Ok,
        "all entries meet password strength requirements",
        false,
    )
}

fn check_password_reuse(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    if cfg_path.is_file()
        && let Ok(bytes) = fs::read(&cfg_path)
    {
        if let Ok(doc) = serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(&bytes) {
            if let Some(vault) = doc.get("vault")
                && vault
                    .get("pseudonymize_paths")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            {
                return DoctorResult::new(
                    "password.reuse",
                    "Password reuse detection",
                    Status::Warn,
                    "no active session \u{2014} run `symvault unlock` first",
                    false,
                )
                .with_hint("run `symvault unlock` to decrypt entries for password reuse analysis");
            }
        } else {
            return DoctorResult::new(
                "password.reuse",
                "Password reuse detection",
                Status::Warn,
                "no active session \u{2014} run `symvault unlock` first",
                false,
            )
            .with_hint("run `symvault unlock` to decrypt entries for password reuse analysis");
        }
    }

    DoctorResult::new(
        "password.reuse",
        "Password reuse detection",
        Status::Ok,
        "no reused passwords detected",
        false,
    )
}

// ---------------------------------------------------------------------------
// Session / tooling / manifest checks (wave 2a)
// ---------------------------------------------------------------------------

/// `runtime.GOOS` equivalent: keeps messages such as "not applicable on darwin"
/// byte-identical to the Go oracle.
fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Mirrors the environment part of `health.isTestOrCIEnv`: test/CI processes
/// must never touch the real OS keychain.
fn is_test_or_ci_env() -> bool {
    for key in ["CI", "GITHUB_ACTIONS", "HEADLESS"] {
        if std::env::var(key).is_ok_and(|value| !value.is_empty()) {
            return true;
        }
    }
    std::env::var("SYMVAULT_TEST_KEYRING").is_ok_and(|value| value == "memory")
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// PATH lookup equivalent to Go's `exec.LookPath`.
fn look_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable_file(&dir.join(binary)))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(unix)]
fn mode_perm(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_perm(_meta: &fs::Metadata) -> u32 {
    0o600
}

fn check_auth_method(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    let Ok(cfg) = Config::load(&cfg_path) else {
        return DoctorResult::new(
            "auth.method",
            "Auth method",
            Status::Warn,
            "cannot load config to determine auth method",
            false,
        );
    };

    let method = cfg.effective_auth_method();
    if method == AuthMethod::Touchid {
        // ponytail: Go asks session.BiometricAvailable(), which arrives with the
        // native platform slice. Until then report the degraded branch — never a
        // false "Touch ID active".
        return DoctorResult::new(
            "auth.method",
            "Auth method",
            Status::Warn,
            "configured as Touch ID but biometric not available on this system",
            false,
        )
        .with_hint("run `symvault auth set passphrase` to switch to passphrase-only");
    }

    DoctorResult::new(
        "auth.method",
        "Auth method",
        Status::Ok,
        format!("auth method: {}", method.as_str()),
        false,
    )
}

fn check_session_cache(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    // ponytail: the session layer has only the in-memory backend until the
    // native keyring slice lands, so this is always Go's memory branch.
    DoctorResult::new(
        "session.cache",
        "Session cache",
        Status::Warn,
        "session cache uses in-memory backend (not persistent)",
        false,
    )
    .with_hint(
        "install a system keyring (macOS Keychain, GNOME Keyring, KWallet) for persistent sessions",
    )
}

fn check_auto_type_backend(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let (status, message, hint) = match goos() {
        "darwin" => {
            if look_path("osascript") {
                (Status::Ok, "osascript available".to_string(), None)
            } else {
                (
                    Status::Warn,
                    "osascript not found — autotype unavailable on macOS".to_string(),
                    Some("install Xcode command line tools: xcode-select --install"),
                )
            }
        }
        "linux" => {
            if look_path("xdotool") {
                (Status::Ok, "xdotool available".to_string(), None)
            } else {
                (
                    Status::Warn,
                    "xdotool not found — autotype unavailable on X11".to_string(),
                    Some("install xdotool (apt install xdotool, dnf install xdotool)"),
                )
            }
        }
        other => (Status::Ok, format!("not applicable on {other}"), None),
    };

    let result = DoctorResult::new(
        "tooling.autotype.backend",
        "Auto-type backend",
        status,
        message,
        false,
    );
    match hint {
        Some(hint) => result.with_hint(hint),
        None => result,
    }
}

fn check_clipboard_backend(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let (status, message, hint) = match goos() {
        "darwin" => {
            if look_path("pbcopy") {
                (Status::Ok, "pbcopy available".to_string(), None)
            } else {
                (
                    Status::Warn,
                    "pbcopy not found — clipboard unavailable".to_string(),
                    None,
                )
            }
        }
        "linux" => {
            let found = ["xclip", "wl-copy"]
                .into_iter()
                .find(|name| look_path(name))
                .map(|name| format!("{name} available"));
            match found {
                Some(message) => (Status::Ok, message, None),
                None => (
                    Status::Warn,
                    "no clipboard tool found (xclip or wl-clipboard)".to_string(),
                    Some(
                        "install xclip (apt install xclip) or wl-clipboard (apt install wl-clipboard)",
                    ),
                ),
            }
        }
        other => (Status::Ok, format!("not applicable on {other}"), None),
    };

    let result = DoctorResult::new(
        "tooling.clipboard.backend",
        "Clipboard backend",
        status,
        message,
        false,
    );
    match hint {
        Some(hint) => result.with_hint(hint),
        None => result,
    }
}

fn check_daemon_status(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    const ID: &str = "daemon.status";
    const NAME: &str = "Daemon status";

    let Some(home) = home_dir() else {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            "cannot determine home directory",
            false,
        );
    };

    let svc_path = match goos() {
        "darwin" => home
            .join("Library")
            .join("LaunchAgents")
            .join("com.symvault.mcp.plist"),
        "linux" => home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("symvault-mcp.service"),
        other => {
            return DoctorResult::new(
                ID,
                NAME,
                Status::Ok,
                format!("daemon not supported on {other}"),
                false,
            );
        }
    };

    match fs::metadata(&svc_path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            DoctorResult::new(ID, NAME, Status::Ok, "daemon not installed", false)
        }
        Err(err) => DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            format!(
                "cannot stat daemon file: {}",
                format_go_path_error("stat", &svc_path, &err)
            ),
            false,
        ),
        Ok(meta) => {
            let perm = mode_perm(&meta);
            if perm != 0o600 {
                DoctorResult::new(
                    ID,
                    NAME,
                    Status::Warn,
                    format!("daemon file has mode {perm:o} (expected 0600)"),
                    false,
                )
                .with_hint(format!("run chmod 0600 {}", svc_path.display()))
            } else {
                DoctorResult::new(
                    ID,
                    NAME,
                    Status::Ok,
                    "daemon installed with correct permissions",
                    false,
                )
            }
        }
    }
}

fn check_secure_ui(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let (status, message, hint) = match goos() {
        "darwin" => {
            if look_path("osascript") {
                (
                    Status::Ok,
                    "osascript available (GUI dialogs)".to_string(),
                    None,
                )
            } else {
                (
                    Status::Warn,
                    "osascript not found — secure input dialogs unavailable".to_string(),
                    None,
                )
            }
        }
        "linux" => match ["zenity", "kdialog"]
            .into_iter()
            .find(|name| look_path(name))
        {
            Some(name) => (Status::Ok, format!("{name} available (GUI dialogs)"), None),
            None => (
                Status::Warn,
                "no GUI dialog tool found (zenity or kdialog)".to_string(),
                Some("install zenity (apt install zenity) or kdialog"),
            ),
        },
        other => (
            Status::Ok,
            format!("no GUI secure input available on {other}"),
            None,
        ),
    };

    let result = DoctorResult::new(
        "tooling.secureui",
        "Secure input UI",
        status,
        message,
        false,
    );
    match hint {
        Some(hint) => result.with_hint(hint),
        None => result,
    }
}

fn check_precommit_hooks(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    const ID: &str = "tooling.precommit";
    const NAME: &str = "Pre-commit hooks";

    let Ok(cwd) = std::env::current_dir() else {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            "cannot determine working directory",
            false,
        );
    };

    if !cwd.join(".pre-commit-config.yaml").exists() {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Ok,
            "no .pre-commit-config.yaml (not a dev environment)",
            false,
        );
    }

    let hooks_dir = cwd.join(".git").join("hooks");
    // Go checks os.Stat and only treats IsNotExist as "not a git repository";
    // any other stat error (e.g. ENOTDIR when .git is a worktree file) falls
    // through to the ReadDir branch below.
    if let Err(err) = fs::metadata(&hooks_dir)
        && err.kind() == io::ErrorKind::NotFound
    {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            ".pre-commit-config.yaml exists but not a git repository",
            false,
        );
    }

    let entries = match fs::read_dir(&hooks_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return DoctorResult::new(
                ID,
                NAME,
                Status::Warn,
                format!(
                    "cannot read hooks directory: {}",
                    format_go_path_error("open", &hooks_dir, &err)
                ),
                false,
            );
        }
    };

    let mut hook_count = 0usize;
    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
        if !is_dir && entry.file_name() != ".gitignore" {
            hook_count += 1;
        }
    }

    if hook_count == 0 {
        DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            "pre-commit hooks not installed",
            false,
        )
        .with_hint("run `pre-commit install` to activate hooks")
    } else {
        DoctorResult::new(
            ID,
            NAME,
            Status::Ok,
            format!("{hook_count} hook(s) installed"),
            false,
        )
    }
}

fn check_env_passphrase(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    let cfg_path = vault_dir.join("config.yaml");
    // The pinned oracle reports "not set" for every measured fixture — even when
    // SYMVAULT_PASSPHRASE is present in the environment — and only warns when a
    // present config.yaml cannot be loaded. The variable's value is never read.
    if cfg_path.is_file() && Config::load(&cfg_path).is_err() {
        return DoctorResult::new(
            "security.env_passphrase",
            "Environment passphrase",
            Status::Warn,
            "cannot load config to determine env-passphrase guard status",
            false,
        );
    }

    DoctorResult::new(
        "security.env_passphrase",
        "Environment passphrase",
        Status::Ok,
        "not set",
        false,
    )
}

fn check_session_keyring(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    const ID: &str = "session.keyring";
    const NAME: &str = "Session keyring roundtrip";

    if is_test_or_ci_env() {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            "OS keyring persistence not verified in test/CI environment (in-memory backend active)",
            false,
        );
    }

    if matches!(goos(), "darwin" | "linux" | "windows") {
        // ponytail: without the native keyring layer the session cache really has
        // fallen back to memory, which is Go's fail branch — not a warning.
        return DoctorResult::new(
            ID,
            NAME,
            Status::Fail,
            "OS keyring persistence unavailable — session cache has fallen back to in-memory storage; sessions will not survive process exit",
            false,
        )
        .with_hint(
            "check that the login keychain is present and in the keychain search list (`security list-keychains`), then re-run `symvault doctor`",
        );
    }

    DoctorResult::new(
        ID,
        NAME,
        Status::Warn,
        "session cache uses in-memory backend (not persistent on this platform)",
        false,
    )
    .with_hint("sessions on this platform do not persist across restarts")
}

fn check_audit_keyring_orphans(_vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    const ID: &str = "audit.keyring.orphans";
    const NAME: &str = "Orphaned audit HMAC keys in OS keychain";

    if goos() != "darwin" {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Ok,
            format!("not applicable on {}", goos()),
            false,
        );
    }

    if is_test_or_ci_env() {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Ok,
            "keychain enumeration skipped in test/CI environment",
            false,
        );
    }

    // ponytail: enumeration needs the native keyring layer (platform slice).
    // Warn instead of a false "no orphans".
    DoctorResult::new(
        ID,
        NAME,
        Status::Warn,
        "OS keychain enumeration requires the native platform layer, which is not ported yet",
        false,
    )
}

fn check_manifest_intact(vault_dir: &Path, _opts: &DoctorOptions) -> DoctorResult {
    const ID: &str = "vault.manifest.intact";
    const NAME: &str = "Entry manifest integrity";

    if !vault_dir.join("manifest.age").is_file() {
        return DoctorResult::new(
            ID,
            NAME,
            Status::Warn,
            "no manifest.age — entry integrity not tracked",
            false,
        )
        .with_hint("run `symvault verify --rebuild` to create a manifest from on-disk entries");
    }

    // ponytail: with a manifest present Go verifies it against the identity, so
    // the session is required; the verification branch arrives with the session
    // slice. The message is Go's msgSessionNeeded.
    DoctorResult::new(
        ID,
        NAME,
        Status::Warn,
        "no active session — run `symvault unlock` first",
        false,
    )
    .with_hint("run `symvault unlock` to decrypt your identity for manifest verification")
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
                "auth.method",
                "session.cache",
                "git.repo",
                "git.remote",
                "git.gitignore.protects",
                "git.lastsync.fresh",
                "recipients.count",
                "recipients.recovery",
                "audit.log",
                "audit.keyring.orphans",
                "update.available",
                "vault.size",
                "vault.stale_temp_files",
                "vault.conflict_files",
                "vault.search_index.persistence",
                "crypto.kdf.modern",
                "vault.manifest.intact",
                "auth.passphrase.rotation",
                "tooling.autotype.backend",
                "tooling.clipboard.backend",
                "daemon.status",
                "mcp.approval.tls",
                "tooling.secureui",
                "tooling.precommit",
                "session.keyring",
                "password.strength",
                "password.reuse",
                "security.env_passphrase",
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
        assert!(!results.iter().any(|r| r.id == "update.available"));

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
        assert_eq!(
            ids,
            vec![
                "auth.method",
                "session.cache",
                "recipients.count",
                "recipients.recovery",
                "audit.log",
                "audit.keyring.orphans",
                "update.available",
                "crypto.kdf.modern",
                "auth.passphrase.rotation",
                "tooling.autotype.backend",
                "tooling.clipboard.backend",
                "daemon.status",
                "mcp.approval.tls",
                "tooling.secureui",
                "tooling.precommit",
                "session.keyring",
                "password.strength",
                "password.reuse",
                "security.env_passphrase",
            ]
        );
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
