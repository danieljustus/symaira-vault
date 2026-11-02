//! Configuration defaults, precedence, and canonical YAML bytes.
//!
//! This module deliberately keeps configuration free of filesystem side effects
//! except for the explicit `load` and `save_to` entry points. YAML unknown fields
//! are ignored like the Go loader; absent fields inherit defaults while explicit
//! zero/false values are preserved where the Go field-presence merge does so.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use symvault_gojson::yaml;
use thiserror::Error;
use unicode_categories::UnicodeCategories;

const APP_NAME: &str = "symaira-vault";
const LEGACY_DIR: &str = ".symvault";
const DEFAULT_AGENT: &str = "default";
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);

const ENV_WHITELIST_WARNING: &str =
    "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead";
const APPROVAL_REQUIRED_WARNING: &str =
    "approval_required is deprecated and will be removed in a future version";
const PRINT_BY_DEFAULT_WARNING: &str =
    "clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead";

/// Which once-per-process warnings have already been raised.
///
/// Go keeps this in a package-level atomic, so `clipboard.printByDefault`
/// warns on the first load that meets it and never again. A fresh state models
/// a fresh process.
#[derive(Debug, Default)]
pub struct WarningState {
    print_by_default: AtomicBool,
}

impl WarningState {
    /// Returns true exactly once per state, the way Go's `Swap(true)` does.
    fn first_print_by_default(&self) -> bool {
        !self.print_by_default.swap(true, Ordering::Relaxed)
    }
}

static PROCESS_WARNINGS: WarningState = WarningState {
    print_by_default: AtomicBool::new(false),
};

/// Go's `config.SetWarnFunc`: where a load reports its deprecation warnings.
static WARN_HOOK: OnceLock<fn(&str)> = OnceLock::new();

/// Installs the process-wide warning sink for [`Config::load`] and
/// [`Config::load_from_bytes`], the way the Go CLI installs
/// `config.SetWarnFunc` at start-up. Returns false when a sink is already
/// installed. Without a sink those two loaders drop their warnings.
pub fn set_warn_hook(hook: fn(&str)) -> bool {
    WARN_HOOK.set(hook).is_ok()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Read(#[from] std::io::Error),
    /// A loader failure of the native decoder. Go's `config.Load` returns its
    /// causes bare (callers add their own `load config:` / `cannot load
    /// config from …:` wrapper), so this renders without a prefix of its own.
    #[error("{0}")]
    Parse(String),
    /// A loader failure whose text Go returns unwrapped: a libyaml-level syntax
    /// failure worded as `yaml.v3` words it (`yaml: line 3: …`), a typed-decode
    /// failure (`yaml: unmarshal errors: …`) or the multiple-document
    /// rejection.
    #[error("{0}")]
    Yaml(String),
    /// A semantic rejection (`sessionTimeout: must be greater than 0, got 0s
    /// …`, `agent "x": invalid approvalMode …`). Bare, as Go returns it.
    #[error("{0}")]
    Invalid(String),
    #[error("serialize config: {0}")]
    Serialize(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub vault_dir: String,
    pub default_agent: String,
    pub session_timeout: Duration,
    pub session_max_lifetime: Duration,
    pub auth_method: AuthMethod,
    pub use_touch_id: Option<bool>,
    pub agents: BTreeMap<String, AgentProfile>,
    pub profiles: Option<BTreeMap<String, Profile>>,
    pub default_profile: String,
    pub vault: Option<VaultConfig>,
    pub git: Option<GitConfig>,
    pub mcp: Option<McpConfig>,
    pub update: Option<UpdateConfig>,
    pub clipboard: Option<ClipboardConfig>,
    /// Go's `audit` section, present exactly when the file carries an `audit`
    /// mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditConfig>,
    /// Go's `logging` section, present exactly when the file carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,
    /// Go's `security` section, present exactly when the file carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityConfig>,
    /// Go's `scan_patterns`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scan_patterns: Vec<ScanPattern>,
    /// Go's `paymentPolicies`, keyed by policy name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub payment_policies: BTreeMap<String, PaymentPolicy>,
}

/// Go's `AuditConfig` after `mergeAuditConfig`: `max_file_size` is in bytes
/// (`maxSizeMb` times 1 MiB, wrapping as Go's `int64` product does).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditConfig {
    pub max_file_size: i64,
    pub max_backups: i64,
    pub max_age_days: i64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            max_backups: 5,
            max_age_days: 30,
        }
    }
}

/// Go's `LoggingConfig` after `mergeLoggingConfig`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "warn".into(),
            format: "text".into(),
        }
    }
}

/// Go's `SecurityConfig`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub disable_env_passphrase: bool,
    pub allow_env_passphrase: bool,
}

/// Go's `CustomPattern` (`scan_patterns`).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanPattern {
    pub name: String,
    pub pattern: String,
    pub description: String,
    pub severity: String,
}

/// Go's `PaymentMaxAmount`: decimal limits kept as text.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PaymentMaxAmount {
    pub per_transaction: String,
    pub per_day: String,
}

/// Go's `PaymentPolicy`, as far as `Validate` looks at it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PaymentPolicy {
    pub instrument: String,
    pub allowed_merchants: Vec<String>,
    pub max_amount: PaymentMaxAmount,
    pub currency: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    #[default]
    Passphrase,
    Touchid,
}

impl AuthMethod {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "passphrase" => Ok(Self::Passphrase),
            "touchid" | "touch-id" | "touch_id" | "biometric" | "biometrics" => Ok(Self::Touchid),
            // Go quotes the method as written (`%q` of the argument), not the
            // trimmed, lower-cased form it switched on.
            _ => Err(ConfigError::Invalid(invalid_auth_method_message(value))),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::Touchid => "touchid",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentProfile {
    pub tier: Option<String>,
    pub approval_mode: Option<String>,
    pub allowed_paths: Vec<String>,
    pub redact_fields: Vec<String>,
    /// Go's `perToolRedactFields`: extra redacted fields per MCP tool name.
    #[serde(default)]
    pub per_tool_redact_fields: BTreeMap<String, Vec<String>>,
    pub can_write: bool,
    pub can_run_commands: bool,
    pub can_manage_config: bool,
    pub can_use_clipboard: bool,
    pub can_use_autotype: bool,
    pub can_read_values: bool,
    pub expose_value_tools: bool,
    #[serde(default)]
    pub expose_payment_values: bool,
    pub auto_unseal: bool,
    pub require_approval: bool,
    pub approval_timeout: Duration,
    /// Go's `approvalTimeout` is a `*time.Duration`: an explicit `0s` is a set
    /// pointer and is written back, while an unset one writes nothing. The
    /// plain `Duration` above cannot tell the two apart, so the loader records
    /// a written key whose value is zero here.
    #[serde(default)]
    pub approval_timeout_zero_set: bool,
    pub allowed_tools: Vec<String>,
    pub max_reads_per_hour: i64,
    pub max_reads_per_day: i64,
    pub max_secrets_in_session: i64,
    pub dynamic_providers: BTreeMap<String, Vec<String>>,
    pub allowed_env_vars: Vec<String>,
    pub allowed_executables: Vec<String>,
    pub prompt_injection_mode: String,
    pub skill_path: String,
    pub skill_version: String,
    /// Go's `paymentPolicy`: the name of the `paymentPolicies` entry the
    /// profile is bound to. `None` is a nil pointer (never written).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<String>,
}

impl AgentProfile {
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            approval_mode: Some("deny".into()),
            expose_value_tools: true,
            prompt_injection_mode: "off".into(),
            approval_timeout: Duration::from_secs(5 * 60),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "vault", alias = "VaultPath")]
    pub vault_path: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub path: String,
    pub default_recipients: Vec<String>,
    pub confirm_remove: bool,
    pub auth_method: AuthMethod,
    /// A `vault.authMethod` the file spells in a way [`AuthMethod`] cannot
    /// hold. Go's loader keeps the raw string and lets `Validate` reject it, so
    /// the file loads and `config validate` reports it; the typed field above
    /// then stays at its default. Cleared by [`Config::set_auth_method`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_auth_method: Option<String>,
    pub use_touch_id: bool,
    pub legacy_mode: Option<bool>,
    pub search_index: bool,
    pub search_workers: i64,
    pub search_index_cache: bool,
    pub config_cache_entries: i64,
    pub pseudonymize_paths: bool,
    pub scrypt_work_factor: i64,
    pub auto_migrate_kdf: bool,
    pub auto_heal_zero_key: bool,
    pub last_rotated: Option<String>,
    pub format_version: i64,
    pub argon2id_time: i64,
    pub argon2id_memory: i64,
    pub argon2id_threads: i64,
    pub listing_cache_ttl: Duration,
    pub manifest_generation: i64,
    pub sync: Option<SyncConfig>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncConfig {
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitConfig {
    pub auto_push: bool,
    pub auto_pull: bool,
    pub auto_pull_interval: Duration,
    pub commit_template: String,
    /// Go's `git.author` / `git.email`: the commit identity. Go's loader never
    /// merges them, so its rewrite drops them; they are kept here
    /// (`upstream-go-bugs.md` entry 10).
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpConfig {
    pub port: i64,
    pub bind: String,
    pub stdio: bool,
    pub http_token_file: String,
    #[serde(default)]
    pub otlp_endpoint: String,
    pub read_header_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub approval_timeout: Duration,
    pub rate_limit: i64,
    #[serde(default)]
    pub trusted_proxy_ips: Vec<String>,
    pub metrics_auth_required: bool,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub tls_client_ca_file: String,
    #[serde(default)]
    pub approval_tls_cert_file: String,
    #[serde(default)]
    pub approval_tls_key_file: String,
    pub mtls_enabled: bool,
    pub allow_insecure_bind: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    /// The deprecated `mcp.approval_required`. Go's loader only warns about it
    /// and its rewrite drops the key; it is kept here (entry 10).
    #[serde(default)]
    pub approval_required: bool,
    /// Go's `mcp.perplexity` client block. Go's rewrite drops it, which turns
    /// a configured Perplexity client off; it is kept here (entry 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perplexity: Option<PerplexityConfig>,
}

/// Go's `PerplexityConfig`. `allow_private` is carried through a rewrite but,
/// as in Go, no loader or consumer reads it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PerplexityConfig {
    pub api_key: String,
    pub base_url: String,
    pub rate_limit_per_min: i64,
    pub allow_private: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: Duration::from_secs(24 * 60 * 60),
            refresh_token_ttl: Duration::from_secs(720 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub cache_ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClipboardConfig {
    pub auto_clear_duration: i64,
    pub copy_by_default: bool,
    /// The deprecated `clipboard.printByDefault` as the operator wrote it.
    /// `copy_by_default` already honours it; Go's rewrite drops the key, this
    /// one keeps it (entry 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub print_by_default: Option<bool>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            auto_push: true,
            auto_pull: true,
            auto_pull_interval: Duration::from_secs(10),
            commit_template: "Update from Symaira Vault".into(),
            author: String::new(),
            email: String::new(),
        }
    }
}
impl Default for McpConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            bind: "127.0.0.1".into(),
            stdio: false,
            http_token_file: "auto".into(),
            otlp_endpoint: String::new(),
            read_header_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            approval_timeout: Duration::from_secs(30),
            rate_limit: 60,
            trusted_proxy_ips: Vec::new(),
            metrics_auth_required: true,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_client_ca_file: String::new(),
            approval_tls_cert_file: String::new(),
            approval_tls_key_file: String::new(),
            mtls_enabled: false,
            allow_insecure_bind: false,
            oauth: None,
            approval_required: false,
            perplexity: None,
        }
    }
}
impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(24 * 60 * 60),
        }
    }
}
impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            auto_clear_duration: 30,
            copy_by_default: true,
            print_by_default: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathResolver {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub legacy_dir: Option<PathBuf>,
    pub migrated: bool,
}

/// The discovered environment that path resolution is computed from.
///
/// Keeping the inputs explicit makes resolution deterministic and lets the
/// CFG-001 contract pin it without touching the filesystem or the process
/// environment. Mirrors Go's `config.PathEnvironment`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathEnvironment {
    /// An empty home yields a zero `PathResolver`, matching the behavior when
    /// the home directory cannot be determined at all.
    pub home: String,
    /// Raw environment values. An empty value falls back to the XDG default
    /// beneath `home`, exactly as an unset one does.
    pub xdg_config_home: String,
    pub xdg_data_home: String,
    pub xdg_cache_home: String,
    /// Raw `SYMVAULT_VAULT` value. It is trimmed, and a leading `~` is
    /// expanded against `home`.
    pub vault_override: String,
    /// The two filesystem probes the resolution depends on. The caller
    /// performs them; the resolution itself touches no filesystem.
    pub legacy_dir_exists: bool,
    pub xdg_data_dir_exists: bool,
}

/// Returns the raw XDG value when set, otherwise the XDG default beneath home.
fn xdg_base(value: &str, home: &str, fallback: &[&str]) -> PathBuf {
    if value.is_empty() {
        // Go joins every fallback component separately
        // (`filepath.Join(home, ".local", "share")`), so the resolved path uses
        // host separators throughout. Joining one prepared string instead would
        // keep `/` inside the segment on Windows and produce a mixed path.
        fallback
            .iter()
            .fold(Path::new(home).to_path_buf(), |path, component| {
                path.join(component)
            })
    } else {
        PathBuf::from(value)
    }
}

/// Expands a leading `~` against the supplied home rather than discovering it.
fn expand_tilde_against(value: &str, home: &str) -> PathBuf {
    if value == "~" {
        return PathBuf::from(home);
    }
    match value.strip_prefix("~/") {
        Some(rest) => Path::new(home).join(rest),
        None => PathBuf::from(value),
    }
}

/// The pure CFG-001 path-resolution contract.
///
/// For existing installs: reads from legacy, writes to XDG.
/// For new installs: uses XDG exclusively.
#[must_use]
pub fn resolve_paths(env: &PathEnvironment) -> PathResolver {
    if env.home.is_empty() {
        return PathResolver {
            config_dir: PathBuf::new(),
            data_dir: PathBuf::new(),
            cache_dir: PathBuf::new(),
            legacy_dir: None,
            migrated: false,
        };
    }

    let legacy = Path::new(&env.home).join(LEGACY_DIR);
    let cache_dir = xdg_base(&env.xdg_cache_home, &env.home, &[".cache"]).join(APP_NAME);
    let xdg_config = xdg_base(&env.xdg_config_home, &env.home, &[".config"]).join(APP_NAME);
    let xdg_data = xdg_base(&env.xdg_data_home, &env.home, &[".local", "share"]).join(APP_NAME);

    let (config_dir, mut data_dir, migrated) =
        match (env.legacy_dir_exists, env.xdg_data_dir_exists) {
            (true, false) => (legacy.clone(), legacy.clone(), false),
            (true, true) => (xdg_config, xdg_data, true),
            _ => (xdg_config, xdg_data, false),
        };

    let trimmed = env.vault_override.trim();
    if !trimmed.is_empty() {
        data_dir = expand_tilde_against(trimmed, &env.home);
    }

    PathResolver {
        config_dir,
        data_dir,
        cache_dir,
        legacy_dir: env.legacy_dir_exists.then_some(legacy),
        migrated,
    }
}

impl PathResolver {
    /// Discovers the environment and resolves the paths from it. The
    /// resolution itself lives in [`resolve_paths`]; this is the discovery
    /// wrapper.
    #[must_use]
    pub fn new() -> Self {
        let home = home_dir();
        let env = PathEnvironment {
            home: home.clone(),
            xdg_config_home: env_string("XDG_CONFIG_HOME"),
            xdg_data_home: env_string("XDG_DATA_HOME"),
            xdg_cache_home: env_string("XDG_CACHE_HOME"),
            vault_override: env_string("SYMVAULT_VAULT"),
            legacy_dir_exists: false,
            xdg_data_dir_exists: false,
        };
        if home.is_empty() {
            return resolve_paths(&env);
        }
        let probed = PathEnvironment {
            legacy_dir_exists: Path::new(&home).join(LEGACY_DIR).is_dir(),
            xdg_data_dir_exists: xdg_base(&env.xdg_data_home, &home, &[".local", "share"])
                .join(APP_NAME)
                .is_dir(),
            ..env
        };
        resolve_paths(&probed)
    }

    /// The path to `config.yaml`, beneath the **resolved** config directory.
    /// For a legacy install that is the legacy directory, not the XDG one.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.config_dir.join("config.yaml")
    }
    #[must_use]
    pub fn vault_data_dir(&self) -> &Path {
        &self.data_dir
    }
    #[must_use]
    pub fn audit_dir(&self) -> PathBuf {
        self.data_dir.join("audit")
    }
    #[must_use]
    pub fn cache_path(&self) -> PathBuf {
        self.cache_dir.join("update-cache.json")
    }
}

impl Default for PathResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut agents = BTreeMap::new();
        for (name, can_write, can_run, skill_path) in [
            ("default", false, false, ""),
            (
                "claude-code",
                true,
                true,
                "~/.claude/skills/symvault/SKILL.md",
            ),
            ("codex", false, true, "~/.codex/skills/symvault/AGENTS.md"),
            ("hermes", true, true, "~/.hermes/skills/symvault/SKILL.md"),
            (
                "openclaw",
                true,
                true,
                "~/.openclaw/skills/symvault/SKILL.md",
            ),
            (
                "opencode",
                false,
                true,
                "~/.opencode/skills/symvault/SKILL.md",
            ),
        ] {
            let mut profile = AgentProfile::deny_all();
            profile.can_write = can_write;
            profile.can_run_commands = can_run;
            profile.skill_path = skill_path.into();
            profile.auto_unseal = false;
            agents.insert(name.into(), profile);
        }
        Self {
            vault_dir: PathResolver::new().data_dir.to_string_lossy().into_owned(),
            default_agent: DEFAULT_AGENT.into(),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            session_max_lifetime: DEFAULT_SESSION_MAX_LIFETIME,
            auth_method: AuthMethod::Passphrase,
            use_touch_id: None,
            agents,
            profiles: None,
            default_profile: String::new(),
            vault: None,
            git: None,
            mcp: None,
            update: None,
            clipboard: None,
            audit: None,
            logging: None,
            security: None,
            scan_patterns: Vec::new(),
            payment_policies: BTreeMap::new(),
        }
    }
}

impl Config {
    #[must_use]
    pub fn effective_auth_method(&self) -> AuthMethod {
        if self.use_touch_id == Some(true) {
            AuthMethod::Touchid
        } else {
            self.auth_method
        }
    }

    /// Returns a named vault profile using the Go loader's nil-on-miss semantics.
    #[must_use]
    pub fn profile_for_name(&self, name: &str) -> Option<&Profile> {
        self.profiles.as_ref()?.get(name)
    }

    pub fn set_auth_method(&mut self, method: &str) -> Result<(), ConfigError> {
        let method = AuthMethod::parse(method)?;
        self.auth_method = method;
        self.use_touch_id = Some(method == AuthMethod::Touchid);
        if let Some(vault) = &mut self.vault {
            vault.auth_method = method;
            vault.invalid_auth_method = None;
            vault.use_touch_id = method == AuthMethod::Touchid;
        }
        Ok(())
    }

    /// Checks the config for semantic correctness, matching Go's
    /// `Config.Validate()`. Every violation is collected (not just the first)
    /// so `symvault config validate` can report them all at once, joined with
    /// `\n` the same way Go's `errors.Join(...).Error()` renders them.
    ///
    /// The top-level `authMethod` is not re-checked here: Go's loader only
    /// stores a method that normalizes, so the field Go validates is always
    /// valid, and the Rust `AuthMethod` enum cannot hold anything else. A
    /// `vault.authMethod` that does not normalize is the one case Go's
    /// `Validate` can still reject, and it is carried in
    /// [`VaultConfig::invalid_auth_method`]. The `audit.maxFileSize` check
    /// and the `paymentPolicies` checks run on the two fields that carry just
    /// what they need ([`Config::audit_max_file_size`],
    /// [`Config::payment_policies`]). Go walks its maps in random order, so
    /// when several entries are wrong it reports whichever it meets first;
    /// this port reports the first in name order.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.vault_dir.trim().is_empty() {
            errors.push(
                "vaultDir: must not be empty (set SYMVAULT_VAULT environment variable or configure vaultDir in config.yaml)"
                    .to_owned(),
            );
        }
        if self.session_timeout.is_zero() {
            errors.push(
                "sessionTimeout: must be greater than 0 (default: 15m, configure sessionTimeout in config.yaml)"
                    .to_owned(),
            );
        }
        if self.session_max_lifetime.is_zero() {
            errors.push(
                "sessionMaxLifetime: must be greater than 0 (default: 8h, configure sessionMaxLifetime in config.yaml)"
                    .to_owned(),
            );
        }
        if let Some(raw) = self
            .vault
            .as_ref()
            .and_then(|vault| vault.invalid_auth_method.as_deref())
        {
            errors.push(invalid_auth_method_message(raw));
        }

        if !self.default_agent.is_empty() && !self.agents.contains_key(&self.default_agent) {
            errors.push(format!(
                "defaultAgent: {:?} not found in agents (define a matching agent profile in the agents section of config.yaml)",
                self.default_agent
            ));
        }

        for (name, agent) in &self.agents {
            let mode = agent.approval_mode.as_deref().unwrap_or("");
            if !matches!(mode, "" | "none" | "deny" | "prompt" | "auto") {
                errors.push(format!(
                    "agents.{name}.approvalMode: invalid value {mode:?} (valid: none, deny, prompt, auto; configure in config.yaml)"
                ));
            }
        }

        for (name, agent) in &self.agents {
            for (index, pattern) in agent.allowed_paths.iter().enumerate() {
                if !is_valid_glob_pattern(pattern) {
                    errors.push(format!(
                        "agents.{name}.allowedPaths[{index}]: invalid glob pattern {pattern:?} (use valid filepath.Match syntax, configure in config.yaml)"
                    ));
                }
            }
        }

        if self.audit.is_some_and(|audit| audit.max_file_size <= 0) {
            errors.push(
                "audit.maxFileSize: must be greater than 0 (configure audit.maxFileSize in config.yaml)"
                    .to_owned(),
            );
        }

        if let Some(clipboard) = &self.clipboard
            && clipboard.auto_clear_duration < 0
        {
            errors.push(
                "clipboard.autoClearDuration: must be non-negative (configure clipboard.autoClearDuration in config.yaml)"
                    .to_owned(),
            );
        }

        errors.extend(validate_payment_policies(&self.payment_policies));
        errors.extend(validate_agent_payment_policies(
            &self.agents,
            &self.payment_policies,
        ));

        errors.extend(validate_argon2id_config(self.vault.as_ref()));
        errors
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path)?;
        Self::load_from_bytes(&bytes)
    }

    /// Loads a config and hands its warnings to the sink [`set_warn_hook`]
    /// installed, or drops them when none is.
    ///
    /// With a sink the warnings go out whether or not the load then succeeds
    /// (Go prints a deprecation notice and may still reject the document
    /// afterwards), in the order they were raised, and the once-per-process
    /// `clipboard.printByDefault` guard is the process-wide one. Without a
    /// sink the guard is deliberately not consumed: a load that shows the
    /// operator nothing has not told them anything, so it must not use up the
    /// message a later load that does show warnings is entitled to.
    pub fn load_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let Some(hook) = WARN_HOOK.get() else {
            return Self::load_from_bytes_with_warnings_in(bytes, &WarningState::default())
                .map(|(config, _)| config);
        };
        let mut warnings = Vec::new();
        let result = Self::parse_document(bytes, &mut warnings, &PROCESS_WARNINGS);
        for warning in &warnings {
            hook(warning);
        }
        result
    }

    /// Loads a config and returns the warnings the loader raised.
    ///
    /// Warnings are returned rather than emitted through a global callback, so
    /// they are explicit and thread-safe. Go reaches the same outcome through
    /// `config.SetWarnFunc`, and the CFG-003 contract pins the texts on both
    /// sides. `clipboard.printByDefault` warns once per process, as in Go,
    /// through the process-wide [`WarningState`].
    pub fn load_from_bytes_with_warnings(bytes: &[u8]) -> Result<(Self, Vec<String>), ConfigError> {
        Self::load_from_bytes_with_warnings_in(bytes, &PROCESS_WARNINGS)
    }

    /// [`Config::load_from_bytes_with_warnings`] against an explicit warning
    /// state, so a caller (or a test) can model a fresh process.
    ///
    /// A warning raised before a later rejection is lost here: Go emits it and
    /// then fails, this returns only the error. [`Config::load_from_bytes`]
    /// with a sink installed keeps it.
    pub fn load_from_bytes_with_warnings_in(
        bytes: &[u8],
        state: &WarningState,
    ) -> Result<(Self, Vec<String>), ConfigError> {
        let mut warnings = Vec::new();
        let config = Self::parse_document(bytes, &mut warnings, state)?;
        Ok((config, warnings))
    }

    fn parse_document(
        bytes: &[u8],
        warnings: &mut Vec<String>,
        state: &WarningState,
    ) -> Result<Self, ConfigError> {
        if is_go_blank(bytes) {
            return Ok(Self::default());
        }
        // Go's loader parses the whole first document into a node tree before
        // it decodes anything, so a scanner or parser failure anywhere in it
        // wins over a type error found earlier. Check syntax first and word
        // the failure the way yaml.v3 does.
        if let Some(message) = crate::go_yaml::first_document_syntax_error(bytes) {
            return Err(ConfigError::Yaml(message));
        }
        // An explicit `null` is an empty document. Go already treats an empty
        // file as "use the defaults", so rejecting `null` while accepting ""
        // would be inconsistent.
        if matches!(
            serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(bytes),
            Ok(serde_yaml_ng::Value::Null)
        ) {
            return Ok(Self::default());
        }
        // A second document is rejected rather than dropped: an operator who
        // wrote a restriction there must not believe it is in force. Go rejects
        // it with the same message.
        let mut documents = serde_yaml_ng::Deserializer::from_slice(bytes);
        documents
            .next()
            .ok_or_else(|| ConfigError::Parse("empty YAML stream".to_owned()))?;
        // Go counts a later document only when it decodes: a syntax error in
        // it leaves the stream a single-document one. serde_yaml_ng parses a
        // document into events before it hands it out, so the first can be
        // left unread while the stream is checked.
        if let Some(second) = documents.next()
            && crate::go_yaml::decodes_as_go_node(second)
        {
            return Err(ConfigError::Yaml(MULTIPLE_DOCUMENTS_MESSAGE.to_owned()));
        }
        // Go decodes the whole first document into the typed `Config` before
        // it merges a single field, so a value of the wrong shape anywhere in
        // it (`audit.maxSizeMb: abc`, `logging.level: [1]`, an integer where a
        // `time.Duration` belongs) fails first, worded as yaml.v3 words it.
        // The decode covers every section, including the ones this port does
        // not model.
        if let Ok(text) = std::str::from_utf8(bytes)
            && let Some(cause) = crate::config_typed::unmarshal_errors(text)
        {
            return Err(ConfigError::Yaml(
                String::from_utf8_lossy(&cause).into_owned(),
            ));
        }
        // Every value below is read from the tree yaml.v3's typed decode
        // leaves (`config_typed::coerced_document`): the coercions of the Go
        // field types happen there and nowhere else.
        let document = std::str::from_utf8(bytes)
            .ok()
            .and_then(crate::config_typed::coerced_document)
            .ok_or_else(|| {
                ConfigError::Parse("top-level YAML document must be a mapping".into())
            })?;
        let root = mapping(&document)?;
        let mut config = Self::default();
        let mut auth_method_explicit = false;
        // Go merges `vaultDir` only when the text is non-empty, so `vaultDir:
        // ''` (like `null`) keeps the resolved default; whether that default
        // is empty is `validate`'s business, not the loader's.
        if let Some(v) = scalar(root, "vaultDir") {
            let text = string_field(v, "vaultDir")?;
            if !text.is_empty() {
                config.vault_dir = text;
            }
        }
        if let Some(v) = scalar(root, "defaultAgent") {
            let text = string_field(v, "defaultAgent")?;
            if !text.is_empty() {
                config.default_agent = text;
            }
        }
        // Go's `validateDurationFields` rejects a session duration the
        // operator wrote as zero or negative (a key that is present but null
        // decodes to zero), naming the parsed value, and reports both fields
        // when both are wrong. The typed decode above already refused anything
        // that is not a string `time.ParseDuration` accepts.
        let mut duration_errors = Vec::new();
        for (name, default, target) in [
            ("sessionTimeout", "15m", &mut config.session_timeout),
            ("sessionMaxLifetime", "8h", &mut config.session_max_lifetime),
        ] {
            let nanos = match scalar(root, name) {
                Some(v) => session_duration_nanos(v, name)?,
                None => 0,
            };
            // The error needs the key written by the operator; a value a
            // `<<` merge supplies only counts when it is positive.
            if written(root, name).is_some() && nanos <= 0 {
                duration_errors.push(non_positive_duration_message(name, nanos, default));
            } else if nanos > 0 {
                *target = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
            }
        }
        if !duration_errors.is_empty() {
            return Err(ConfigError::Invalid(duration_errors.join("\n")));
        }
        // Go decodes a null scalar to the zero value, and its merges test the
        // raw method against the exact empty string: only a non-empty text
        // counts as written, whether or not it normalizes. A method that does
        // not normalize is dropped without a word (`config.Load` swallows
        // `NormalizeAuthMethod`'s error and `Validate` only ever sees the
        // default), but it still counts as written, so it keeps `useTouchID`
        // and the vault block from selecting the method. A null or `""` method
        // leaves both free to.
        if let Some(v) = scalar(root, "authMethod").filter(|v| !v.is_null()) {
            let text = string_field(v, "authMethod")?;
            if !text.is_empty() {
                if let Ok(method) = AuthMethod::parse(&text) {
                    config.auth_method = method;
                }
                auth_method_explicit = true;
            }
        }
        // `useTouchID` is a `*bool` in Go: null stays nil and selects nothing.
        if let Some(v) = scalar(root, "useTouchID").filter(|v| !v.is_null()) {
            config.use_touch_id = Some(bool_field(v, "useTouchID")?);
        }
        if let Some(v) = scalar(root, "defaultProfile") {
            config.default_profile = string_field(v, "defaultProfile")?;
        }
        // A `profiles` that is null stays nil in Go, `{}` is an empty map.
        if let Some(profiles) = scalar(root, "profiles").and_then(serde_yaml_ng::Value::as_mapping)
        {
            let mut loaded = BTreeMap::new();
            for (name, value) in entries(profiles) {
                // Go dereferences the nil profile a null entry decodes to and
                // crashes; there is no behavior to match, so refuse it.
                let fields = value.as_mapping().ok_or_else(|| {
                    ConfigError::Parse(format!("profiles.{name}: profile must not be null"))
                })?;
                let vault_path = match scalar(fields, "vault") {
                    Some(v) => string_field(v, "profiles.vault")?,
                    None => String::new(),
                };
                loaded.insert(name.to_owned(), Profile { vault_path });
            }
            config.profiles = Some(loaded);
        }
        // Go applies a top-level `useTouchID: true` as the method only when
        // the operator wrote no `authMethod`; a false value never selects
        // anything. The vault block may still override it below.
        if !auth_method_explicit && config.use_touch_id == Some(true) {
            config.auth_method = AuthMethod::Touchid;
        }
        // Go warns for the deprecated key once the document has decoded and
        // the durations have passed, ahead of every merge. A null list is nil
        // there and neither warns nor overrides; the typed decode has already
        // checked the shape of both lists. Neither key is consumed by a Rust
        // caller today, so they are not carried.
        if scalar(root, "envWhitelist").is_some_and(|v| !v.is_null()) {
            warnings.push(ENV_WHITELIST_WARNING.to_owned());
        }
        if let Some(v) = root.get(key("agents")) {
            merge_agents(&mut config, v)?;
        }
        if config.default_agent.is_empty() {
            config.default_agent = DEFAULT_AGENT.into();
        }
        config
            .agents
            .entry(config.default_agent.clone())
            .or_insert_with(|| AgentProfile {
                // Go ensureAgentDefaults gives an absent selected profile deny.
                approval_mode: Some("deny".into()),
                ..AgentProfile::default()
            });
        // Go Load checks ordinary approval modes after agent merge and before
        // section merge. This is deliberately narrower than Config::validate,
        // which also permits `auto` for directly constructed configurations.
        for (name, agent) in &config.agents {
            let mode = agent.approval_mode.as_deref().unwrap_or("");
            if !matches!(mode, "" | "none" | "deny" | "prompt") {
                return Err(ConfigError::Invalid(format!(
                    "agent {}: invalid approvalMode {} (valid: none, deny, prompt)",
                    crate::go_quote(name),
                    crate::go_quote(mode)
                )));
            }
        }
        // Go's `validateAgents` runs its prompt-injection loop only after the
        // approval-mode loop has passed for every profile.
        for (name, agent) in &config.agents {
            let mode = agent.prompt_injection_mode.as_str();
            if !matches!(mode, "" | "off" | "log-only" | "wrap" | "deny") {
                return Err(ConfigError::Invalid(format!(
                    "agent {}: invalid promptInjectionMode {} (valid: off, log-only, wrap, deny)",
                    crate::go_quote(name),
                    crate::go_quote(mode)
                )));
            }
        }
        if let Some(v) = root.get(key("vault")).filter(|v| !v.is_null()) {
            let (vault, vault_auth) = parse_vault(v)?;
            config.vault = Some(vault);
            // Go's vault merge feeds the top-level method when the operator
            // did not write one there: the vault block's own `authMethod`,
            // else its `useTouchID`.
            if !auth_method_explicit && let Some(method) = vault_auth {
                config.auth_method = method;
            }
        }
        if let Some(v) = root.get(key("git")).filter(|v| !v.is_null()) {
            config.git = Some(parse_git(v)?);
        }
        if let Some(v) = root.get(key("mcp")).filter(|v| !v.is_null()) {
            let mcp = parse_mcp(v, warnings)?;
            if mcp.bind.is_empty() {
                return Err(ConfigError::Invalid("mcp.bind must not be empty".into()));
            }
            config.mcp = Some(mcp);
        }
        if let Some(v) = root.get(key("update")).filter(|v| !v.is_null()) {
            config.update = Some(parse_update(v)?);
        }
        if let Some(v) = root.get(key("clipboard")).filter(|v| !v.is_null()) {
            config.clipboard = Some(parse_clipboard(v, warnings, state)?);
        }
        if let Some(v) = root.get(key("audit")).filter(|v| !v.is_null()) {
            config.audit = Some(parse_audit(v)?);
        }
        if let Some(v) = root.get(key("logging")).filter(|v| !v.is_null()) {
            config.logging = Some(parse_logging(v)?);
        }
        if let Some(v) = root.get(key("security")).filter(|v| !v.is_null()) {
            config.security = Some(parse_security(v)?);
        }
        if let Some(v) = scalar(root, "scan_patterns") {
            config.scan_patterns = parse_scan_patterns(v)?;
        }
        if let Some(v) = scalar(root, "paymentPolicies") {
            config.payment_policies = parse_payment_policies(v)?;
        }
        // Go ends every load by recording the resolved method as the flag.
        config.use_touch_id = Some(config.auth_method == AuthMethod::Touchid);
        Ok(config)
    }

    /// Returns the exact canonical writer bytes used by this Rust slice.
    pub fn to_yaml_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let mut out = String::new();
        if !self.agents.is_empty() {
            out.push_str("agents:\n");
            for (name, profile) in yaml_entries(&self.agents) {
                let mut body = String::new();
                write_agent(&mut body, name, profile)?;
                push_entry(&mut out, &map_key(name, 4), 4, &body);
            }
        }
        if let Some(vault) = &self.vault {
            write_vault(&mut out, vault)?;
        }
        if let Some(git) = &self.git {
            write_git(&mut out, git)?;
        }
        if let Some(mcp) = &self.mcp {
            write_mcp(&mut out, mcp);
        }
        if let Some(update) = &self.update {
            write_update(&mut out, update)?;
        }
        if let Some(clipboard) = &self.clipboard {
            write_clipboard(&mut out, clipboard)?;
        }
        if let Some(audit) = &self.audit {
            write_audit(&mut out, audit);
        }
        if let Some(logging) = &self.logging {
            write_logging(&mut out, logging)?;
        }
        // Rust-safer deviation from Go's `SaveTo`, which never copies the
        // `security` section into its raw struct (docs/rust-port/upstream-go-bugs.md).
        if let Some(security) = &self.security {
            write_security(&mut out, security);
        }
        if !self.vault_dir.is_empty() {
            out.push_str(&format!("vaultDir: {}\n", map_value(&self.vault_dir, 0)));
        }
        if !self.default_agent.is_empty() {
            out.push_str(&format!(
                "defaultAgent: {}\n",
                map_value(&self.default_agent, 0)
            ));
        }
        if self.session_timeout > Duration::ZERO {
            out.push_str(&format!(
                "sessionTimeout: {}\n",
                format_duration(self.session_timeout)
            ));
        }
        if self.session_max_lifetime > Duration::ZERO {
            out.push_str(&format!(
                "sessionMaxLifetime: {}\n",
                format_duration(self.session_max_lifetime)
            ));
        }
        out.push_str(&format!(
            "authMethod: {}\n",
            self.effective_auth_method().as_str()
        ));
        if self.use_touch_id.is_some() {
            out.push_str(&format!(
                "useTouchID: {}\n",
                self.effective_auth_method() == AuthMethod::Touchid
            ));
        }
        if let Some(profiles) = self
            .profiles
            .as_ref()
            .filter(|profiles| !profiles.is_empty())
        {
            out.push_str("profiles:\n");
            for (name, profile) in yaml_entries(profiles) {
                let key = map_key(name, 4);
                if profile.vault_path.is_empty() {
                    out.push_str(&format!("    {key} {{}}\n"));
                } else {
                    let body = format!("        vault: {}\n", map_value(&profile.vault_path, 8));
                    push_entry(&mut out, &key, 4, &body);
                }
            }
        }
        if !self.default_profile.is_empty() {
            out.push_str(&format!(
                "defaultProfile: {}\n",
                map_value(&self.default_profile, 0)
            ));
        }
        if !self.scan_patterns.is_empty() {
            write_scan_patterns(&mut out, &self.scan_patterns)?;
        }
        // Rust-safer deviation: Go's `SaveTo` drops `paymentPolicies`, which
        // leaves every agent's `paymentPolicy` dangling (upstream-go-bugs.md).
        if !self.payment_policies.is_empty() {
            write_payment_policies(&mut out, &self.payment_policies)?;
        }
        Ok(out.into_bytes())
    }

    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ConfigError::Invalid(
                "config file path escapes expected directory".into(),
            ));
        }
        let bytes = self.to_yaml_bytes()?;
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        atomic_write_private(path, &bytes)
    }
}

/// Go's `fsutil.AtomicWriteFile`: a unique temporary file next to the target,
/// created exclusively (so a planted file or symlink at that name is never
/// opened or followed), fsynced, then renamed over the target. Renaming
/// replaces a symlinked target itself rather than writing through it.
fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|error| std::io::Error::other(error.to_string()))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = parent.join(format!(".{name}.tmp-{}-{suffix}", std::process::id()));
    let result = write_private(&temporary, bytes).and_then(|()| Ok(fs::rename(&temporary, path)?));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Creates a directory tree the way the Go writer does: owner-only.
///
/// `fs::create_dir_all` applies 0777 masked by the umask, which is typically
/// 0755 and leaves the directory holding vault configuration world-readable.
fn create_private_dir_all(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

/// Writes a file owner-only, matching the Go writer's 0600.
///
/// The mode is applied at creation rather than afterwards, so the contents are
/// never briefly readable by other users. `fs::write` would apply 0666 masked
/// by the umask, typically 0644.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    // `create_new` (O_CREAT|O_EXCL) refuses an existing name, symlinks included.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn home_dir() -> String {
    env::var("HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("USERPROFILE").ok())
        .unwrap_or_default()
}

fn env_string(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

/// Go's loader starts with `len(bytes.TrimSpace(data)) == 0` and then serves
/// the defaults. `TrimSpace` strips Unicode white space (`unicode.IsSpace`:
/// the ASCII set plus `\v`, U+0085, U+00A0, U+1680, U+2000..=U+200A, U+2028,
/// U+2029, U+202F, U+205F and U+3000), not only ASCII, and it stops at bytes
/// that are not valid UTF-8, so such input is not blank. `char::is_whitespace`
/// is that same `White_Space` set; `go_space_set_matches_unicode_is_space`
/// pins it against the Go table.
fn is_go_blank(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| text.chars().all(char::is_whitespace))
}

fn key(value: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::String(value.into())
}
fn mapping(value: &serde_yaml_ng::Value) -> Result<&serde_yaml_ng::Mapping, ConfigError> {
    value
        .as_mapping()
        .ok_or_else(|| ConfigError::Parse("top-level YAML document must be a mapping".into()))
}
/// The value `name` has after Go's decode (merged keys included).
fn scalar<'a>(map: &'a serde_yaml_ng::Mapping, name: &str) -> Option<&'a serde_yaml_ng::Value> {
    map.get(key(name))
}
static NULL: serde_yaml_ng::Value = serde_yaml_ng::Value::Null;
/// The value of `name` when the operator wrote the key in this mapping itself
/// (not through a `<<` merge or an alias), which is what Go's field-presence
/// walk (`loadSectionFields`, `loadAgentFields`) counts and the section merges
/// are gated on.
fn written<'a>(map: &'a serde_yaml_ng::Mapping, name: &str) -> Option<&'a serde_yaml_ng::Value> {
    map.get(crate::config_typed::own_keys_key())
        .and_then(serde_yaml_ng::Value::as_sequence)
        .is_some_and(|keys| keys.iter().any(|written| written.as_str() == Some(name)))
        .then(|| scalar(map, name).unwrap_or(&NULL))
}
/// A decoded `agents`/`profiles` map's entries, without the bookkeeping key.
fn entries(map: &serde_yaml_ng::Mapping) -> impl Iterator<Item = (&str, &serde_yaml_ng::Value)> {
    map.iter()
        .filter_map(|(name, value)| name.as_str().map(|name| (name, value)))
}
/// A decoded string field; `null` is the empty string.
fn string_field(value: &serde_yaml_ng::Value, field: &str) -> Result<String, ConfigError> {
    match value {
        serde_yaml_ng::Value::Null => Ok(String::new()),
        serde_yaml_ng::Value::String(text) => Ok(text.clone()),
        _ => Err(ConfigError::Parse(format!("{field} must be a string"))),
    }
}
/// Resolves a boolean the way the Go loader does.
///
/// yaml.v3 still honours the YAML 1.1 boolean spellings, so `yes`, `no`, `on`
/// and `off` — in any case, quoted or bare — are accepted there and appear in
/// real config files. Accepting only YAML 1.2 booleans would refuse files that
/// Go reads correctly. Quoted `"true"`/`"false"` are rejected because yaml.v3
/// rejects them too; that is a quirk of its resolver rather than a design, but
/// the contract pins the behaviour either way.
/// Rejection text for a stream carrying more than one YAML document.
///
/// The CFG-003 contract pins whether an input is rejected, not how the
/// rejection reads, so this text need not match Go byte for byte — but it says
/// the same thing, because an operator hitting it reads whichever one their
/// build produces.
pub const MULTIPLE_DOCUMENTS_MESSAGE: &str = "config contains more than one YAML document; split it into separate files or remove everything after the first document separator";

/// Rejection text for a session duration the operator set to a non-positive
/// value, naming the parsed value the way Go's `%s` of a `time.Duration` does
/// (`0s`, `-5m0s`).
#[must_use]
pub fn non_positive_duration_message(field: &str, nanos: i128, default: &str) -> String {
    format!(
        "{field}: must be greater than 0, got {} (default: {default}, configure {field} in config.yaml)",
        go_duration_string(nanos)
    )
}

/// Go's `time.Duration.String()` for a signed nanosecond count.
#[must_use]
pub fn go_duration_string(nanos: i128) -> String {
    if nanos == 0 {
        return "0s".to_owned();
    }
    let sign = if nanos < 0 { "-" } else { "" };
    let magnitude = nanos.unsigned_abs();
    // Digits of `fraction` below `scale`, trailing zeros trimmed.
    let fractional = |fraction: u128, scale: u128| -> String {
        if fraction == 0 {
            return String::new();
        }
        let width = scale.ilog10() as usize;
        let digits = format!("{fraction:0width$}");
        format!(".{}", digits.trim_end_matches('0'))
    };
    if magnitude < 1_000_000_000 {
        let (unit, scale) = if magnitude < 1_000 {
            ("ns", 1_u128)
        } else if magnitude < 1_000_000 {
            ("µs", 1_000)
        } else {
            ("ms", 1_000_000)
        };
        return format!(
            "{sign}{}{}{unit}",
            magnitude / scale,
            fractional(magnitude % scale, scale)
        );
    }
    let seconds = magnitude / 1_000_000_000;
    let mut text = format!(
        "{}{}s",
        seconds % 60,
        fractional(magnitude % 1_000_000_000, 1_000_000_000)
    );
    let minutes = seconds / 60;
    if minutes > 0 {
        text = format!("{}m{text}", minutes % 60);
        let hours = minutes / 60;
        if hours > 0 {
            text = format!("{hours}h{text}");
        }
    }
    format!("{sign}{text}")
}

/// A session duration as the operator wrote it, in nanoseconds. A key that is
/// present but null decodes to zero in Go.
fn session_duration_nanos(value: &serde_yaml_ng::Value, field: &str) -> Result<i128, ConfigError> {
    Ok(i128::from(nanos_field(value, field)?))
}

/// Go's `NormalizeAuthMethod` rejection, quoting the method as written.
fn invalid_auth_method_message(method: &str) -> String {
    format!(
        "invalid authMethod {} (valid: passphrase, touchid)",
        crate::go_quote(method)
    )
}

/// A decoded `time.Duration`, in nanoseconds; `null` is zero.
fn nanos_field(value: &serde_yaml_ng::Value, field: &str) -> Result<i64, ConfigError> {
    match value {
        serde_yaml_ng::Value::Null => Ok(0),
        serde_yaml_ng::Value::Number(number) => number
            .as_i64()
            .ok_or_else(|| ConfigError::Parse(format!("{field} must be a duration"))),
        _ => Err(ConfigError::Parse(format!("{field} must be a duration"))),
    }
}
/// A decoded `time.Duration` in the unsigned [`Duration`] the config models.
///
/// Go keeps a negative value as written; every consumer of the section
/// durations (listing cache, update cache, pull interval, approval timeout,
/// network timeouts) treats a non-positive one as "use the default" or as
/// already expired, which zero says as well.
fn duration_field(value: &serde_yaml_ng::Value, field: &str) -> Result<Duration, ConfigError> {
    Ok(Duration::from_nanos(
        u64::try_from(nanos_field(value, field)?).unwrap_or(0),
    ))
}
/// A decoded bool field; `null` is false.
fn bool_field(value: &serde_yaml_ng::Value, field: &str) -> Result<bool, ConfigError> {
    match value {
        serde_yaml_ng::Value::Null => Ok(false),
        serde_yaml_ng::Value::Bool(flag) => Ok(*flag),
        _ => Err(ConfigError::Parse(format!("{field} must be a boolean"))),
    }
}
/// A decoded int field; `null` is zero.
fn int_field(value: &serde_yaml_ng::Value, field: &str) -> Result<i64, ConfigError> {
    match value {
        serde_yaml_ng::Value::Null => Ok(0),
        serde_yaml_ng::Value::Number(number) => number
            .as_i64()
            .ok_or_else(|| ConfigError::Parse(format!("{field} must be an integer"))),
        _ => Err(ConfigError::Parse(format!("{field} must be an integer"))),
    }
}
/// Parses Go's `time.ParseDuration` grammar and returns nanoseconds.
///
/// The signed result is intentional: Go accepts zero and negative durations;
/// callers decide whether those values are valid for their field. Fractions
/// are truncated to nanoseconds just as `time.Duration` is.
pub fn parse_duration_nanos(text: &str) -> Option<i128> {
    if text.is_empty() {
        return None;
    }
    let (negative, mut rest) = match text.as_bytes()[0] {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total = 0i128;
    while !rest.is_empty() {
        let mut index = 0;
        while index < rest.len() && rest.as_bytes()[index].is_ascii_digit() {
            index += 1;
        }
        let integer = &rest[..index];
        let mut fraction = "";
        if rest[index..].starts_with('.') {
            let fraction_start = index + 1;
            index = fraction_start;
            while index < rest.len() && rest.as_bytes()[index].is_ascii_digit() {
                index += 1;
            }
            fraction = &rest[fraction_start..index];
            if integer.is_empty() && fraction.is_empty() {
                return None;
            }
        } else if integer.is_empty() {
            return None;
        }
        if index == rest.len() {
            return None;
        }
        let (unit, multiplier) = if rest[index..].starts_with("ns") {
            ("ns", 1i128)
        } else if rest[index..].starts_with("us")
            || rest[index..].starts_with("µs")
            || rest[index..].starts_with("μs")
        {
            let length = if rest[index..].starts_with("us") {
                2
            } else {
                3
            };
            (&rest[index..index + length], 1_000i128)
        } else if rest[index..].starts_with("ms") {
            ("ms", 1_000_000i128)
        } else if rest[index..].starts_with('s') {
            ("s", 1_000_000_000i128)
        } else if rest[index..].starts_with('m') {
            ("m", 60_000_000_000i128)
        } else if rest[index..].starts_with('h') {
            ("h", 3_600_000_000_000i128)
        } else {
            return None;
        };
        let unit_len = unit.len();
        let whole = if integer.is_empty() {
            0
        } else {
            integer.parse::<i128>().ok()?
        };
        let whole = whole.checked_mul(multiplier)?;
        let fraction_nanos = if fraction.is_empty() {
            0
        } else {
            go_fraction_nanos(fraction, multiplier)
        };
        total = total.checked_add(whole.checked_add(fraction_nanos)?)?;
        rest = &rest[index + unit_len..];
    }
    let total = if negative {
        total.checked_neg()?
    } else {
        total
    };
    if total < i128::from(i64::MIN) || total > i128::from(i64::MAX) {
        None
    } else {
        Some(total)
    }
}

/// Mirrors `time.leadingFraction` and the fractional part of Go's
/// `time.ParseDuration`. Go keeps up to the first 63 significant fraction
/// bits in a `uint64`, retains the decimal scale as `float64`, and multiplies
/// in floating point before truncating to nanoseconds. In particular, the
/// fraction is a fraction of its unit (`0.1h`), rather than a fraction of a
/// second. Keeping this operation in the same order preserves Go's rounding
/// for long hour and minute fractions.
fn go_fraction_nanos(fraction: &str, multiplier: i128) -> i128 {
    let mut value = 0_u64;
    let mut scale = 1.0_f64;
    let mut overflow = false;
    for byte in fraction.bytes() {
        if overflow {
            continue;
        }
        if value > (i64::MAX as u64) / 10 {
            overflow = true;
            continue;
        }
        let next = value * 10 + u64::from(byte - b'0');
        if next > (1_u64 << 63) {
            overflow = true;
            continue;
        }
        value = next;
        scale *= 10.0;
    }
    if value == 0 {
        return 0;
    }
    (value as f64 * (multiplier as f64 / scale)) as u64 as i128
}

/// Parses a Go `time.ParseDuration` value for APIs whose wire type is an
/// `int64` nanosecond duration. The existing parser remains the shared grammar
/// implementation; this wrapper adds Go's error envelope and range.
pub fn parse_go_duration(text: &str) -> Result<i64, String> {
    let unsigned = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    if unsigned == "0" {
        return Ok(0);
    }
    parse_duration_nanos(text)
        .and_then(|nanos| i64::try_from(nanos).ok())
        .ok_or_else(|| go_duration_error(text))
}

fn go_duration_error(text: &str) -> String {
    match duration_failure_kind(text) {
        Some(DurationFailure::MissingUnit) => {
            format!("time: missing unit in duration {}", go_duration_quote(text))
        }
        Some(DurationFailure::UnknownUnit(unit)) => format!(
            "time: unknown unit {} in duration {}",
            go_duration_quote(&unit),
            go_duration_quote(text)
        ),
        None => format!("time: invalid duration {}", go_duration_quote(text)),
    }
}

enum DurationFailure {
    MissingUnit,
    UnknownUnit(String),
}

fn duration_failure_kind(text: &str) -> Option<DurationFailure> {
    let mut rest = text;
    if matches!(rest.as_bytes().first(), Some(b'+' | b'-')) {
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        if !matches!(bytes.first(), Some(b'.' | b'0'..=b'9')) {
            return None;
        }
        let mut index = 0;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let has_integer = index > 0;
        let mut has_fraction = false;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            has_fraction = index > fraction_start;
        }
        if !has_integer && !has_fraction {
            return None;
        }
        let unit_start = index;
        while index < bytes.len() {
            let character = rest[index..].chars().next()?;
            if character == '.' || character.is_ascii_digit() {
                break;
            }
            index += character.len_utf8();
        }
        if index == unit_start {
            return Some(DurationFailure::MissingUnit);
        }
        let unit = &rest[unit_start..index];
        if !matches!(unit, "ns" | "us" | "µs" | "μs" | "ms" | "s" | "m" | "h") {
            return Some(DurationFailure::UnknownUnit(unit.to_owned()));
        }
        rest = &rest[index..];
    }
    None
}

fn go_duration_quote(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for byte in value.bytes() {
        if !(b' '..0x80).contains(&byte) {
            quoted.push_str("\\x");
            quoted.push(HEX[(byte >> 4) as usize] as char);
            quoted.push(HEX[(byte & 0x0f) as usize] as char);
        } else if matches!(byte, b'"' | b'\\') {
            quoted.push('\\');
            quoted.push(byte as char);
        } else {
            quoted.push(byte as char);
        }
    }
    quoted.push('"');
    quoted
}

/// yaml.v3 writes a `time.Duration` as `Duration.String()`.
fn format_duration(value: Duration) -> String {
    go_duration_string(i128::try_from(value.as_nanos()).unwrap_or(i128::MAX))
}

/// Applies a tier preset to a loaded agent profile, mirroring Go's
/// `config.ApplyTierPreset`.
///
/// `tier::AgentProfile` carries `Option<bool>` like Go's `*bool`, while the
/// loaded profile carries plain `bool`; an absent preset field means `false`,
/// exactly as Go's `BoolPtr(p != nil && *p)` does. An unknown tier changes
/// nothing, and the tier name is still recorded by the caller.
pub fn apply_tier_preset_to_profile(profile: &mut AgentProfile, tier: &str) -> bool {
    let Some(preset) = crate::tier::get_preset(tier) else {
        return false;
    };
    profile.can_write = preset.can_write.unwrap_or(false);
    profile.can_run_commands = preset.can_run_commands.unwrap_or(false);
    profile.can_manage_config = preset.can_manage_config.unwrap_or(false);
    profile.can_use_clipboard = preset.can_use_clipboard.unwrap_or(false);
    profile.can_use_autotype = preset.can_use_autotype.unwrap_or(false);
    profile.can_read_values = preset.can_read_values.unwrap_or(false);
    profile.expose_value_tools = preset.expose_value_tools.unwrap_or(false);
    profile.auto_unseal = preset.auto_unseal.unwrap_or(false);
    profile.require_approval = preset.require_approval.unwrap_or(false);
    if let Some(mode) = preset.approval_mode {
        profile.approval_mode = Some(mode);
    }
    if let Some(executables) = preset.allowed_executables {
        profile.allowed_executables = executables;
    }
    true
}

/// Go's `mergeAgentProfiles`. Pointer fields (`*bool`, `*int`, `*string`,
/// `*time.Duration`) merge whenever the decoded value is not nil, merged keys
/// included; the slice and mode fields, `tier` and `exposeValueTools` merge only
/// when the operator wrote the key in the profile itself (`loadAgentFields`).
fn merge_agents(config: &mut Config, value: &serde_yaml_ng::Value) -> Result<(), ConfigError> {
    // A null `agents` is a nil map.
    let Some(agents) = value.as_mapping() else {
        return Ok(());
    };
    let empty = serde_yaml_ng::Mapping::new();
    for (name, value) in entries(agents) {
        // A null profile decodes to the zero profile: nothing written, no
        // pointer set.
        let fields = value.as_mapping().unwrap_or(&empty);
        let wrote = |field: &str| written(fields, field).is_some();
        // A non-nil pointer in the decoded profile.
        let set = |field: &str| scalar(fields, field).filter(|value| !value.is_null());
        let mut profile = config
            .agents
            .get(name)
            .cloned()
            .unwrap_or_else(AgentProfile::default);
        if !wrote("tier") && !wrote("exposeValueTools") {
            profile.expose_value_tools = true;
        }
        if wrote("tier")
            && let Some(v) = set("tier")
        {
            let tier = string_field(v, "tier")?;
            // The preset is applied before the explicit fields below, so an
            // explicitly written permission still overrides what the tier
            // grants. Go does the same, in the same order. Without this the
            // tier name was recorded but nothing it implies took effect, so a
            // `tier: standard` agent ran without requiring approval.
            apply_tier_preset_to_profile(&mut profile, &tier);
            profile.tier = Some(tier);
        }
        if wrote("approvalMode") {
            profile.approval_mode = set("approvalMode")
                .map(|v| string_field(v, "approvalMode"))
                .transpose()?;
        }
        if wrote("allowedPaths") {
            profile.allowed_paths = string_list(scalar(fields, "allowedPaths"), "allowedPaths")?;
        }
        if wrote("redactFields") {
            profile.redact_fields = string_list(scalar(fields, "redactFields"), "redactFields")?;
        }
        // Go appends each tool's list to what the profile already holds.
        if wrote("perToolRedactFields")
            && let Some(map) = set("perToolRedactFields").and_then(serde_yaml_ng::Value::as_mapping)
        {
            for (tool, list) in entries(map) {
                profile
                    .per_tool_redact_fields
                    .entry(tool.to_owned())
                    .or_default()
                    .extend(string_list(Some(list), "perToolRedactFields")?);
            }
        }
        macro_rules! bool_field {
            ($key:literal, $field:ident) => {
                if let Some(v) = set($key) {
                    profile.$field = bool_field(v, $key)?;
                }
            };
        }
        bool_field!("canWrite", can_write);
        bool_field!("canRunCommands", can_run_commands);
        bool_field!("canManageConfig", can_manage_config);
        bool_field!("canUseClipboard", can_use_clipboard);
        bool_field!("canUseAutotype", can_use_autotype);
        bool_field!("canReadValues", can_read_values);
        bool_field!("exposeValueTools", expose_value_tools);
        bool_field!("exposePaymentValues", expose_payment_values);
        bool_field!("autoUnseal", auto_unseal);
        bool_field!("requireApproval", require_approval);
        if let Some(v) = set("approvalTimeout") {
            profile.approval_timeout = duration_field(v, "approvalTimeout")?;
            profile.approval_timeout_zero_set = profile.approval_timeout.is_zero();
        }
        if wrote("allowed_tools")
            && let Some(v) = set("allowed_tools")
        {
            profile.allowed_tools = string_list(Some(v), "allowed_tools")?;
        }
        macro_rules! int_field {
            ($key:literal, $field:ident) => {
                if let Some(v) = set($key) {
                    profile.$field = int_field(v, $key)?;
                }
            };
        }
        int_field!("max_reads_per_hour", max_reads_per_hour);
        int_field!("max_reads_per_day", max_reads_per_day);
        int_field!("max_secrets_in_session", max_secrets_in_session);
        // Go's `mergeStringSliceMap`: a decoded (non-nil) map replaces the
        // profile's wholesale.
        if wrote("dynamicProviders")
            && let Some(map) = set("dynamicProviders").and_then(serde_yaml_ng::Value::as_mapping)
        {
            profile.dynamic_providers = entries(map)
                .map(|(provider, list)| {
                    Ok((
                        provider.to_owned(),
                        string_list(Some(list), "dynamicProviders")?,
                    ))
                })
                .collect::<Result<_, ConfigError>>()?;
        }
        if wrote("allowedEnvVars")
            && let Some(v) = set("allowedEnvVars")
        {
            profile.allowed_env_vars = string_list(Some(v), "allowedEnvVars")?;
        }
        if wrote("allowedExecutables")
            && let Some(v) = set("allowedExecutables")
        {
            profile.allowed_executables = string_list(Some(v), "allowedExecutables")?;
        }
        if let Some(v) = set("promptInjectionMode") {
            profile.prompt_injection_mode = string_field(v, "promptInjectionMode")?;
        }
        if let Some(v) = set("skillPath") {
            profile.skill_path = string_field(v, "skillPath")?;
        }
        if let Some(v) = set("skillVersion") {
            profile.skill_version = string_field(v, "skillVersion")?;
        }
        if let Some(v) = set("paymentPolicy") {
            profile.payment_policy = Some(string_field(v, "paymentPolicy")?);
        }
        if !wrote("approvalMode") && wrote("requireApproval") && set("requireApproval").is_some() {
            profile.approval_mode = Some(
                if profile.require_approval {
                    "prompt"
                } else {
                    "none"
                }
                .into(),
            );
        }
        config.agents.insert(name.into(), profile);
    }
    Ok(())
}
/// A decoded `[]string`; a nil (null or absent) list is empty.
fn string_list(
    value: Option<&serde_yaml_ng::Value>,
    field: &str,
) -> Result<Vec<String>, ConfigError> {
    match value {
        None | Some(serde_yaml_ng::Value::Null) => Ok(Vec::new()),
        Some(serde_yaml_ng::Value::Sequence(items)) => {
            items.iter().map(|item| string_field(item, field)).collect()
        }
        Some(_) => Err(ConfigError::Parse(format!("{field} must be a sequence"))),
    }
}

/// Go's `validateDecimalString`: at most 30 bytes of an optional leading minus
/// sign, digits and one decimal point, with at least one digit.
fn validate_decimal_string(text: &str, field: &str) -> Result<(), String> {
    let quoted = || crate::go_quote(text);
    if text.is_empty() || text.len() > 30 {
        return Err(format!(
            "{field}: {} is not a valid decimal amount",
            quoted()
        ));
    }
    let mut saw_dot = false;
    let mut has_digit = false;
    for (index, ch) in text.char_indices() {
        match ch {
            '-' => {
                if index != 0 {
                    return Err(format!(
                        "{field}: {} is not a valid decimal amount (minus sign must be leading)",
                        quoted()
                    ));
                }
            }
            '.' => {
                if saw_dot {
                    return Err(format!(
                        "{field}: {} is not a valid decimal amount (multiple decimal points)",
                        quoted()
                    ));
                }
                saw_dot = true;
            }
            '0'..='9' => has_digit = true,
            _ => {
                return Err(format!(
                    "{field}: {} is not a valid decimal amount",
                    quoted()
                ));
            }
        }
    }
    if !has_digit {
        return Err(format!(
            "{field}: {} is not a valid decimal amount (no digits)",
            quoted()
        ));
    }
    // Go finishes with `big.Rat.SetString`, which accepts every string that
    // got this far (a sign, digits and at most one point).
    Ok(())
}

/// Go's `validatePaymentPolicies`: the first failing policy, in name order.
fn validate_payment_policies(policies: &BTreeMap<String, PaymentPolicy>) -> Option<String> {
    for (name, policy) in policies {
        if policy.instrument.trim().is_empty() {
            return Some(format!(
                "paymentPolicies.{name}.instrument: must not be empty"
            ));
        }
        let has_allowlist = !policy.allowed_merchants.is_empty();
        let has_limits =
            !policy.max_amount.per_transaction.is_empty() || !policy.max_amount.per_day.is_empty();
        if !has_allowlist && !has_limits {
            return Some(format!(
                "paymentPolicies.{name}: must have at least one allowed_merchant or max_amount limit"
            ));
        }
        if has_limits && policy.currency.trim().is_empty() {
            return Some(format!(
                "paymentPolicies.{name}.currency: required when max_amount limits are set"
            ));
        }
        if !policy.max_amount.per_transaction.is_empty()
            && let Err(error) = validate_decimal_string(
                &policy.max_amount.per_transaction,
                &format!("paymentPolicies.{name}.max_amount.per_transaction"),
            )
        {
            return Some(error);
        }
        if !policy.max_amount.per_day.is_empty()
            && let Err(error) = validate_decimal_string(
                &policy.max_amount.per_day,
                &format!("paymentPolicies.{name}.max_amount.per_day"),
            )
        {
            return Some(error);
        }
    }
    None
}

/// Go's `validateAgentPaymentPolicies`: the first profile, in name order,
/// that names a policy `paymentPolicies` does not define.
fn validate_agent_payment_policies(
    agents: &BTreeMap<String, AgentProfile>,
    policies: &BTreeMap<String, PaymentPolicy>,
) -> Option<String> {
    for (name, profile) in agents {
        let policy_name = profile.payment_policy.as_deref().unwrap_or("");
        if policy_name.is_empty() {
            continue;
        }
        if !policies.contains_key(policy_name) {
            return Some(format!(
                "agents.{name}.paymentPolicy: policy {} not found in paymentPolicies",
                crate::go_quote(policy_name)
            ));
        }
    }
    None
}

/// Mirrors Go's `validateArgon2idConfig`: an explicit zero means "use the
/// default" and is exempt from range checks, while a non-zero value must fall
/// within the floor/ceiling Go enforces.
fn validate_argon2id_config(vault: Option<&VaultConfig>) -> Vec<String> {
    let Some(vault) = vault else {
        return Vec::new();
    };
    let mut errors = Vec::new();

    if vault.argon2id_time != 0 {
        if vault.argon2id_time < 2 {
            errors.push(format!(
                "vault.argon2id_time: {} is below minimum floor of 2",
                vault.argon2id_time
            ));
        } else if vault.argon2id_time > 16 {
            errors.push(format!(
                "vault.argon2id_time: {} exceeds maximum ceiling of 16",
                vault.argon2id_time
            ));
        }
    }

    let effective_threads = if vault.argon2id_threads != 0 {
        if vault.argon2id_threads < 1 {
            errors.push(format!(
                "vault.argon2id_threads: {} is below minimum floor of 1",
                vault.argon2id_threads
            ));
        } else if vault.argon2id_threads > 16 {
            errors.push(format!(
                "vault.argon2id_threads: {} exceeds maximum ceiling of 16",
                vault.argon2id_threads
            ));
        }
        vault.argon2id_threads
    } else {
        4
    };

    if vault.argon2id_memory != 0 {
        if vault.argon2id_memory < 19456 {
            errors.push(format!(
                "vault.argon2id_memory: {} KiB is below minimum floor of 19456 KiB",
                vault.argon2id_memory
            ));
        } else if vault.argon2id_memory > 2_097_152 {
            errors.push(format!(
                "vault.argon2id_memory: {} KiB exceeds maximum ceiling of 2097152 KiB",
                vault.argon2id_memory
            ));
        }
        if effective_threads > 0 {
            let min_memory = 4 * effective_threads;
            if vault.argon2id_memory < min_memory {
                errors.push(format!(
                    "vault.argon2id_memory: {} KiB must be at least 4*threads ({min_memory} KiB)",
                    vault.argon2id_memory
                ));
            }
        }
    }

    errors
}

/// Reports whether `pattern` is syntactically valid `filepath.Match` glob
/// syntax. Checks only the failure Go's matcher would raise as `ErrBadPattern`
/// on real-world configs: an unterminated `[...]` class or a dangling escape.
/// ponytail: not a full filepath.Match parser (no validation of nested range
/// bounds); widen if a config ever needs stricter glob rejection.
fn is_valid_glob_pattern(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return false;
                }
            }
            b'[' => {
                i += 1;
                if i < bytes.len() && (bytes[i] == b'^' || bytes[i] == b'!') {
                    i += 1;
                }
                let mut closed = false;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 1;
                    } else if bytes[i] == b']' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return false;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    true
}

/// Parses the `vault` section.
///
/// The second value is the method Go's vault merge feeds to the top level when
/// the operator wrote no top-level `authMethod`: the vault block's own method,
/// else its `useTouchID`. An explicitly empty `authMethod` feeds nothing.
///
/// Go merges a field only when the section itself carries the key
/// (`loadSectionFields`), so every read below goes through [`written`]; the
/// value is what the typed decode left, a null being the field's zero value.
fn parse_vault(
    value: &serde_yaml_ng::Value,
) -> Result<(VaultConfig, Option<AuthMethod>), ConfigError> {
    let map = mapping(value)?;
    let mut out = VaultConfig {
        auth_method: AuthMethod::Passphrase,
        search_index: true,
        scrypt_work_factor: 18,
        auto_heal_zero_key: true,
        format_version: 1,
        ..VaultConfig::default()
    };
    let mut fed_auth = None;
    let mut auth_present = false;
    if let Some(v) = written(map, "path") {
        out.path = string_field(v, "vault.path")?;
    }
    if let Some(v) = written(map, "default_recipients").filter(|v| !v.is_null()) {
        out.default_recipients = string_list(Some(v), "default_recipients")?;
    }
    if let Some(v) = written(map, "confirm_remove") {
        out.confirm_remove = bool_field(v, "confirm_remove")?;
    }
    if let Some(v) = written(map, "authMethod") {
        auth_present = true;
        let text = string_field(v, "vault.authMethod")?;
        if !text.is_empty() {
            // Go keeps a method that does not normalize as written and lets
            // `Validate` reject it; it feeds nothing to the top level.
            match AuthMethod::parse(&text) {
                Ok(method) => {
                    out.auth_method = method;
                    fed_auth = Some(method);
                }
                Err(_) => out.invalid_auth_method = Some(text),
            }
        }
    }
    if let Some(v) = written(map, "useTouchID") {
        out.use_touch_id = bool_field(v, "vault.useTouchID")?;
    }
    // The feed reads the decoded flag (`raw.UseTouchID`), merged keys
    // included, while the section's own field keeps only a written one.
    if !auth_present
        && let Some(v) = scalar(map, "useTouchID")
        && bool_field(v, "vault.useTouchID")?
    {
        fed_auth = Some(AuthMethod::Touchid);
    }
    // Go copies a present, non-null `legacy_mode`; a null stays unset.
    if let Some(v) = written(map, "legacy_mode").filter(|v| !v.is_null()) {
        out.legacy_mode = Some(bool_field(v, "legacy_mode")?);
    }
    if let Some(v) = written(map, "search_index") {
        out.search_index = bool_field(v, "search_index")?;
    }
    if let Some(v) = written(map, "search_workers") {
        out.search_workers = int_field(v, "search_workers")?;
    }
    if let Some(v) = written(map, "search_index_cache") {
        out.search_index_cache = bool_field(v, "search_index_cache")?;
    }
    if let Some(v) = written(map, "config_cache_entries") {
        out.config_cache_entries = int_field(v, "config_cache_entries")?;
    }
    if let Some(v) = written(map, "pseudonymize_paths") {
        out.pseudonymize_paths = bool_field(v, "pseudonymize_paths")?;
    }
    if let Some(v) = written(map, "scrypt_work_factor") {
        out.scrypt_work_factor = int_field(v, "scrypt_work_factor")?;
    }
    if let Some(v) = written(map, "auto_migrate_kdf") {
        out.auto_migrate_kdf = bool_field(v, "auto_migrate_kdf")?;
    }
    if let Some(v) = written(map, "auto_heal_zero_key") {
        out.auto_heal_zero_key = bool_field(v, "auto_heal_zero_key")?;
    }
    // `last_rotated` is a `time.Time` in Go: null decodes to the zero time,
    // which is the same as absent, and so does a mapping (a struct with no
    // exported field ignores every key).
    if let Some(v) = written(map, "last_rotated").filter(|v| !v.is_null() && !v.is_mapping()) {
        out.last_rotated = Some(string_field(v, "last_rotated")?);
    }
    if let Some(v) = written(map, "format_version") {
        out.format_version = int_field(v, "format_version")?;
    }
    for (k, field) in [
        ("argon2id_time", &mut out.argon2id_time),
        ("argon2id_memory", &mut out.argon2id_memory),
        ("argon2id_threads", &mut out.argon2id_threads),
        ("manifest_generation", &mut out.manifest_generation),
    ] {
        if let Some(v) = written(map, k) {
            *field = int_field(v, k)?;
        }
    }
    if let Some(v) = written(map, "listing_cache_ttl") {
        out.listing_cache_ttl = duration_field(v, "listing_cache_ttl")?;
    }
    // The sync block is propagated whenever the decoded section holds one,
    // written by the operator or not.
    if let Some(v) = scalar(map, "sync").filter(|v| !v.is_null()) {
        let sync_map = mapping(v)?;
        let method = scalar(sync_map, "method")
            .map(|value| string_field(value, "sync.method"))
            .transpose()?
            .unwrap_or_default();
        out.sync = Some(SyncConfig { method });
    }
    Ok((out, fed_auth))
}
fn parse_git(value: &serde_yaml_ng::Value) -> Result<GitConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = GitConfig::default();
    if let Some(v) = written(map, "auto_push") {
        out.auto_push = bool_field(v, "auto_push")?;
    }
    if let Some(v) = written(map, "auto_pull") {
        out.auto_pull = bool_field(v, "auto_pull")?;
    }
    if let Some(v) = written(map, "auto_pull_interval") {
        out.auto_pull_interval = duration_field(v, "auto_pull_interval")?;
    }
    if let Some(v) = written(map, "commit_template") {
        out.commit_template = string_field(v, "commit_template")?;
    }
    for (key_name, target) in [("author", &mut out.author), ("email", &mut out.email)] {
        if let Some(v) = written(map, key_name) {
            *target = string_field(v, key_name)?;
        }
    }
    Ok(out)
}
fn parse_mcp(
    value: &serde_yaml_ng::Value,
    warnings: &mut Vec<String>,
) -> Result<McpConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = McpConfig::default();
    // Go warns for a true value before it merges anything else in the block,
    // whether or not the section wrote the key itself.
    if let Some(v) = scalar(map, "approval_required")
        && bool_field(v, "approval_required")?
    {
        warnings.push(APPROVAL_REQUIRED_WARNING.to_owned());
        out.approval_required = true;
    }
    if let Some(v) = written(map, "port") {
        out.port = int_field(v, "port")?;
    }
    if let Some(v) = written(map, "bind") {
        out.bind = string_field(v, "bind")?;
    }
    if let Some(v) = written(map, "stdio") {
        out.stdio = bool_field(v, "stdio")?;
    }
    if let Some(v) = written(map, "httpTokenFile") {
        out.http_token_file = string_field(v, "httpTokenFile")?;
    }
    if let Some(v) = written(map, "otlp_endpoint") {
        out.otlp_endpoint = string_field(v, "otlp_endpoint")?;
    }
    for (k, d) in [
        ("read_header_timeout", &mut out.read_header_timeout),
        ("read_timeout", &mut out.read_timeout),
        ("write_timeout", &mut out.write_timeout),
        ("shutdown_timeout", &mut out.shutdown_timeout),
    ] {
        if let Some(v) = written(map, k) {
            // Go's server applies only positive network timeout overrides.
            // Preserve non-positive values as zero in this unsigned model;
            // the transport selects its safe default rather than disabling I/O.
            *d = duration_field(v, k)?;
        }
    }
    if let Some(v) = written(map, "approval_timeout") {
        out.approval_timeout = duration_field(v, "approval_timeout")?;
    }
    if let Some(v) = written(map, "rate_limit") {
        out.rate_limit = int_field(v, "rate_limit")?;
    }
    if let Some(v) = written(map, "trusted_proxy_ips") {
        out.trusted_proxy_ips = string_list(Some(v), "trusted_proxy_ips")?;
    }
    if let Some(v) = written(map, "metrics_auth_required") {
        out.metrics_auth_required = bool_field(v, "metrics_auth_required")?;
    }
    for (key_name, target) in [
        ("tls_cert_file", &mut out.tls_cert_file),
        ("tls_key_file", &mut out.tls_key_file),
        ("tls_client_ca_file", &mut out.tls_client_ca_file),
        ("approval_tls_cert_file", &mut out.approval_tls_cert_file),
        ("approval_tls_key_file", &mut out.approval_tls_key_file),
    ] {
        if let Some(v) = written(map, key_name) {
            *target = string_field(v, key_name)?;
        }
    }
    for (key_name, target) in [
        ("mtls_enabled", &mut out.mtls_enabled),
        ("allow_insecure_bind", &mut out.allow_insecure_bind),
    ] {
        if let Some(v) = written(map, key_name) {
            *target = bool_field(v, key_name)?;
        }
    }
    if let Some(value) = written(map, "oauth").filter(|value| !value.is_null()) {
        let fields = mapping(value)?;
        let mut oauth = OAuthConfig::default();
        for (name, target) in [
            ("access_token_ttl", &mut oauth.access_token_ttl),
            ("refresh_token_ttl", &mut oauth.refresh_token_ttl),
        ] {
            // Go's positive-only config merge retains defaults for zero
            // and negative durations.
            if let Some(value) = written(fields, name) {
                let duration = duration_field(value, name)?;
                if !duration.is_zero() {
                    *target = duration;
                }
            }
        }
        out.oauth = Some(oauth);
    }
    if let Some(value) = written(map, "perplexity").filter(|value| !value.is_null()) {
        let fields = mapping(value)?;
        let mut perplexity = PerplexityConfig::default();
        for (name, target) in [
            ("api_key", &mut perplexity.api_key),
            ("base_url", &mut perplexity.base_url),
        ] {
            if let Some(value) = written(fields, name) {
                *target = string_field(value, name)?;
            }
        }
        if let Some(value) = written(fields, "rate_limit_per_min") {
            perplexity.rate_limit_per_min = int_field(value, "rate_limit_per_min")?;
        }
        if let Some(value) = written(fields, "allow_private") {
            perplexity.allow_private = bool_field(value, "allow_private")?;
        }
        out.perplexity = Some(perplexity);
    }
    Ok(out)
}
/// Go's `mergeAuditConfig`: a written `maxSizeMb` (a `null` decodes to zero)
/// replaces the 100 MiB default and is scaled to bytes with `int64`
/// wrap-around; `maxBackups` and `maxAgeDays` replace their defaults when
/// written.
fn parse_audit(value: &serde_yaml_ng::Value) -> Result<AuditConfig, ConfigError> {
    const MIB: i64 = 1024 * 1024;
    let map = mapping(value)?;
    let mut out = AuditConfig::default();
    if let Some(v) = written(map, "maxSizeMb") {
        out.max_file_size = int_field(v, "maxSizeMb")?.wrapping_mul(MIB);
    }
    if let Some(v) = written(map, "maxBackups") {
        out.max_backups = int_field(v, "maxBackups")?;
    }
    if let Some(v) = written(map, "maxAgeDays") {
        out.max_age_days = int_field(v, "maxAgeDays")?;
    }
    Ok(out)
}

/// Go's `mergeLoggingConfig`.
fn parse_logging(value: &serde_yaml_ng::Value) -> Result<LoggingConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = LoggingConfig::default();
    if let Some(v) = written(map, "level") {
        out.level = string_field(v, "level")?;
    }
    if let Some(v) = written(map, "format") {
        out.format = string_field(v, "format")?;
    }
    Ok(out)
}

/// Go's `mergeSecurityConfig`.
fn parse_security(value: &serde_yaml_ng::Value) -> Result<SecurityConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = SecurityConfig::default();
    if let Some(v) = written(map, "disable_env_passphrase") {
        out.disable_env_passphrase = bool_field(v, "disable_env_passphrase")?;
    }
    if let Some(v) = written(map, "allow_env_passphrase") {
        out.allow_env_passphrase = bool_field(v, "allow_env_passphrase")?;
    }
    Ok(out)
}

/// Go's `[]CustomPattern`: a `null` list is nil, a `null` entry the zero
/// pattern.
fn parse_scan_patterns(value: &serde_yaml_ng::Value) -> Result<Vec<ScanPattern>, ConfigError> {
    let Some(items) = value.as_sequence() else {
        return Ok(Vec::new());
    };
    let empty = serde_yaml_ng::Mapping::new();
    items
        .iter()
        .map(|item| {
            let fields = item.as_mapping().unwrap_or(&empty);
            let text = |field: &str| match scalar(fields, field) {
                Some(v) => string_field(v, field),
                None => Ok(String::new()),
            };
            Ok(ScanPattern {
                name: text("name")?,
                pattern: text("pattern")?,
                description: text("description")?,
                severity: text("severity")?,
            })
        })
        .collect()
}

/// Go's `map[string]PaymentPolicy`: a `null` map is nil, a `null` entry the
/// zero policy.
fn parse_payment_policies(
    value: &serde_yaml_ng::Value,
) -> Result<BTreeMap<String, PaymentPolicy>, ConfigError> {
    let mut policies = BTreeMap::new();
    let Some(map) = value.as_mapping() else {
        return Ok(policies);
    };
    let empty = serde_yaml_ng::Mapping::new();
    for (name, value) in entries(map) {
        let fields = value.as_mapping().unwrap_or(&empty);
        let text = |field: &str| match scalar(fields, field) {
            Some(v) => string_field(v, field),
            None => Ok(String::new()),
        };
        let max_amount = scalar(fields, "max_amount")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .unwrap_or(&empty);
        let amount = |field: &str| match scalar(max_amount, field) {
            Some(v) => string_field(v, field),
            None => Ok(String::new()),
        };
        policies.insert(
            name.to_owned(),
            PaymentPolicy {
                instrument: text("instrument")?,
                allowed_merchants: string_list(
                    scalar(fields, "allowed_merchants"),
                    "allowed_merchants",
                )?,
                max_amount: PaymentMaxAmount {
                    per_transaction: amount("per_transaction")?,
                    per_day: amount("per_day")?,
                },
                currency: text("currency")?,
            },
        );
    }
    Ok(policies)
}

fn parse_update(value: &serde_yaml_ng::Value) -> Result<UpdateConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = UpdateConfig::default();
    if let Some(v) = written(map, "cache_ttl") {
        out.cache_ttl = duration_field(v, "cache_ttl")?;
    }
    Ok(out)
}
fn parse_clipboard(
    value: &serde_yaml_ng::Value,
    warnings: &mut Vec<String>,
    state: &WarningState,
) -> Result<ClipboardConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = ClipboardConfig::default();
    if let Some(v) = written(map, "auto_clear_duration") {
        out.auto_clear_duration = int_field(v, "auto_clear_duration")?;
    }
    if let Some(v) = written(map, "copyByDefault") {
        out.copy_by_default = bool_field(v, "copyByDefault")?;
    } else if let Some(v) = written(map, "printByDefault") {
        // The deprecated key is honored, and warns once per process. Go
        // decodes the document before it merges, so a value that does not
        // decode is rejected without ever reaching the once-only guard:
        // validate first, then consume.
        out.copy_by_default = bool_field(v, "printByDefault")?;
        if state.first_print_by_default() {
            warnings.push(PRINT_BY_DEFAULT_WARNING.to_owned());
        }
    }
    if let Some(v) = written(map, "printByDefault").filter(|v| !v.is_null()) {
        out.print_by_default = Some(bool_field(v, "printByDefault")?);
    }
    Ok(out)
}

fn yaml_entries<T>(map: &BTreeMap<String, T>) -> Vec<(&String, &T)> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| yaml_key_cmp(a, b));
    entries
}

// yaml.v3 orders digit runs numerically, breaking equal values by run length.
fn yaml_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a: Vec<_> = a.chars().collect();
    let b: Vec<_> = b.chars().collect();
    let mut digits = false;
    for i in 0..a.len().min(b.len()) {
        if a[i] == b[i] {
            digits = a[i].is_number_decimal_digit();
            continue;
        }
        let al = a[i].is_letter();
        let bl = b[i].is_letter();
        if al && bl {
            return a[i].cmp(&b[i]);
        }
        if al || bl {
            return if digits { bl.cmp(&al) } else { al.cmp(&bl) };
        }
        let mut an = 0i64;
        let mut bn = 0i64;
        if a[i] == '0' || b[i] == '0' {
            for ch in a[..i]
                .iter()
                .rev()
                .take_while(|ch| ch.is_number_decimal_digit())
            {
                if *ch != '0' {
                    an = 1;
                    bn = 1;
                    break;
                }
            }
        }
        let mut ai = i;
        let mut bi = i;
        while ai < a.len() && a[ai].is_number_decimal_digit() {
            an = an
                .wrapping_mul(10)
                .wrapping_add(i64::from(a[ai] as u32 - '0' as u32));
            ai += 1;
        }
        while bi < b.len() && b[bi].is_number_decimal_digit() {
            bn = bn
                .wrapping_mul(10)
                .wrapping_add(i64::from(b[bi] as u32 - '0' as u32));
            bi += 1;
        }
        return an.cmp(&bn).then(ai.cmp(&bi)).then(a[i].cmp(&b[i]));
    }
    a.len().cmp(&b.len())
}

/// yaml.v3's timestamp forms (`2006-1-2T15:4:5.999999999Z07:00`, the same with
/// a lower-case `t`, `2006-1-2 15:4:5.999999999` and `2006-1-2`) as
/// `time.Time.Format(time.RFC3339Nano)` prints the parsed instant: a missing
/// time of day is midnight, a missing or zero offset is `Z`, and trailing
/// zeros of the fraction are dropped. `None` for anything else.
fn yaml_timestamp_rfc3339(text: &str) -> Option<String> {
    fn number(part: &str, min_digits: usize, max_digits: usize) -> Option<u32> {
        if part.len() < min_digits
            || part.len() > max_digits
            || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        part.parse().ok()
    }
    let (date, rest) = match text.find(['T', 't', ' ']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let (year, month, day) = (
        number(year, 4, 4)?,
        number(month, 1, 2)?,
        number(day, 1, 2)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days {
        return None;
    }
    let (mut hour, mut minute, mut second, mut fraction, mut offset) =
        (0, 0, 0, String::new(), String::from("Z"));
    if let Some(rest) = rest {
        let space = text.as_bytes()[date.len()] == b' ';
        let (clock, zone) = match rest.find(['Z', '+', '-']) {
            Some(at) => (&rest[..at], Some(&rest[at..])),
            None => (rest, None),
        };
        if space && zone.is_some() {
            return None;
        }
        let (whole, frac) = clock
            .split_once('.')
            .map_or((clock, None), |(w, f)| (w, Some(f)));
        let mut hms = whole.split(':');
        let (h, m, sec) = (hms.next()?, hms.next()?, hms.next()?);
        if hms.next().is_some() {
            return None;
        }
        (hour, minute, second) = (number(h, 1, 2)?, number(m, 1, 2)?, number(sec, 1, 2)?);
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        if let Some(frac) = frac {
            number(frac, 1, 9).map(|_| ())?;
            fraction = frac.trim_end_matches('0').to_owned();
        }
        match zone {
            None | Some("Z") => {}
            Some(zone) => {
                let sign = &zone[..1];
                let (zh, zm) = zone[1..].split_once(':')?;
                let (zh, zm) = (number(zh, 2, 2)?, number(zm, 2, 2)?);
                if sign == "Z" || zh > 23 || zm > 59 {
                    return None;
                }
                if zh != 0 || zm != 0 {
                    offset = format!("{sign}{zh:02}:{zm:02}");
                }
            }
        }
    }
    let fraction = if fraction.is_empty() {
        String::new()
    } else {
        format!(".{fraction}")
    };
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}{offset}"
    ))
}

/// A string value of the block mapping whose keys sit at column `indent`, as
/// yaml.v3 emits it (plain, single- or double-quoted, or a literal block).
fn map_value(value: &str, indent: i32) -> String {
    yaml::string_in_mapping(value, indent)
}

/// A key of the block mapping whose keys sit at column `indent`, with its `:`.
fn map_key(key: &str, indent: i32) -> String {
    yaml::mapping_key(key, indent)
}

fn write_agent(out: &mut String, name: &str, p: &AgentProfile) -> Result<(), ConfigError> {
    // Go's `AgentProfile` is a struct of `*T` fields with `omitempty`, so the
    // emission order is the declaration order and an unset pointer writes
    // nothing at all — `tier` leads the block (`internal/config/config.go:144`).
    if let Some(v) = p.tier.as_deref().filter(|value| !value.is_empty()) {
        out.push_str(&format!("        tier: {}\n", map_value(v, 8)));
    }
    // The tier preset the next load applies to every key this block omits.
    let preset = p.tier.as_deref().and_then(crate::tier::get_preset);
    if let Some(v) = &p.approval_mode {
        out.push_str(&format!("        approvalMode: {}\n", map_value(v, 8)));
    } else if preset
        .as_ref()
        .is_some_and(|preset| preset.approval_mode.is_some())
    {
        // An explicit `approvalMode: null` replaced the preset's mode. Leaving
        // the key out would let the preset (and, with `requireApproval`
        // written, the derived mode) come back on the next load.
        out.push_str("        approvalMode: null\n");
    }
    if !p.allowed_paths.is_empty() {
        out.push_str("        allowedPaths:\n");
        write_string_list_body(out, 12, &p.allowed_paths);
    }
    if !p.redact_fields.is_empty() {
        out.push_str("        redactFields:\n");
        write_string_list_body(out, 12, &p.redact_fields);
    }
    if !p.per_tool_redact_fields.is_empty() {
        out.push_str("        perToolRedactFields:\n");
        for (tool, fields) in yaml_entries(&p.per_tool_redact_fields) {
            write_keyed_list(out, 12, tool, fields);
        }
    }
    let builtin = matches!(
        name,
        "default" | "claude-code" | "codex" | "hermes" | "openclaw" | "opencode"
    );
    let tiered = p.tier.as_deref().is_some_and(|t| !t.is_empty());
    // ponytail: Go types these as `*bool`, so a key that was present in the
    // input is written back even when it is false (pinned Go contract:
    // `config_session_contract.rs` expects `exposeValueTools: false` for a
    // non-builtin `custom` profile), while an absent key writes no line at all.
    // Rust stores plain `bool`, so presence cannot be recovered here, except
    // through the `tier` marker: builtins always carry the preset set, tiered
    // profiles carry the full Go-declared preset field set (Go holds non-nil
    // preset pointers after `ApplyTierPreset` and writes them back even when
    // false), everything else carries canWrite and exposeValueTools.
    out.push_str(&format!("        canWrite: {}\n", p.can_write));
    if builtin || tiered || p.can_run_commands {
        out.push_str(&format!("        canRunCommands: {}\n", p.can_run_commands));
    }
    // A capability that is true is always written (dropping it would turn it
    // off on reload); a false one only where Go's profile holds a set pointer
    // (tiered and builtin profiles).
    for (key, value) in [
        ("canManageConfig", p.can_manage_config),
        ("canUseClipboard", p.can_use_clipboard),
        ("canUseAutotype", p.can_use_autotype),
        ("canReadValues", p.can_read_values),
    ] {
        if tiered || value {
            out.push_str(&format!("        {key}: {value}\n"));
        }
    }
    out.push_str(&format!(
        "        exposeValueTools: {}\n",
        p.expose_value_tools
    ));
    if builtin || tiered || p.auto_unseal {
        out.push_str(&format!("        autoUnseal: {}\n", p.auto_unseal));
    }
    if tiered || p.require_approval || p.approval_mode.as_deref() == Some("none") {
        out.push_str(&format!(
            "        requireApproval: {}\n",
            p.require_approval
        ));
    }
    // Go writes the remaining pointer fields only when set. Rust stores plain
    // values, so a zero (or, for the builtin presets, the preset default that
    // `AgentProfile::deny_all` fills in) reads as "not written".
    if p.approval_timeout.is_zero() && p.approval_timeout_zero_set {
        out.push_str("        approvalTimeout: 0s\n");
    } else if !p.approval_timeout.is_zero()
        && !(builtin && p.approval_timeout == Duration::from_secs(5 * 60))
    {
        out.push_str(&format!(
            "        approvalTimeout: {}\n",
            format_duration(p.approval_timeout)
        ));
    }
    if !p.allowed_tools.is_empty() {
        out.push_str("        allowed_tools:\n");
        write_string_list_body(out, 12, &p.allowed_tools);
    }
    for (key, value) in [
        ("max_reads_per_hour", p.max_reads_per_hour),
        ("max_reads_per_day", p.max_reads_per_day),
        ("max_secrets_in_session", p.max_secrets_in_session),
    ] {
        if value != 0 {
            out.push_str(&format!("        {key}: {value}\n"));
        }
    }
    if !p.dynamic_providers.is_empty() {
        out.push_str("        dynamicProviders:\n");
        for (provider, hosts) in yaml_entries(&p.dynamic_providers) {
            write_keyed_list(out, 12, provider, hosts);
        }
    }
    if !p.allowed_env_vars.is_empty() {
        out.push_str("        allowedEnvVars:\n");
        write_string_list_body(out, 12, &p.allowed_env_vars);
    }
    if !p.allowed_executables.is_empty() {
        out.push_str("        allowedExecutables:\n");
        write_string_list_body(out, 12, &p.allowed_executables);
    } else if preset
        .as_ref()
        .and_then(|preset| preset.allowed_executables.as_ref())
        .is_some_and(|executables| !executables.is_empty())
    {
        // An explicit empty allowlist replaced the preset's. Go's omitempty
        // drops it, and the next load then grants the preset's executables
        // again (`tier: standard` gains curl, git, terraform, docker, ...):
        // a rewrite must never widen permissions, so the empty list stays.
        out.push_str("        allowedExecutables: []\n");
    }
    if !p.prompt_injection_mode.is_empty() && !(builtin && p.prompt_injection_mode == "off") {
        out.push_str(&format!(
            "        promptInjectionMode: {}\n",
            map_value(&p.prompt_injection_mode, 8)
        ));
    }
    if !p.skill_path.is_empty() {
        out.push_str(&format!(
            "        skillPath: {}\n",
            map_value(&p.skill_path, 8)
        ));
    }
    // Go's declaration order closes with skillPath, skillVersion,
    // exposePaymentValues and paymentPolicy (`internal/config/config.go:171`).
    if !p.skill_version.is_empty() {
        out.push_str(&format!(
            "        skillVersion: {}\n",
            map_value(&p.skill_version, 8)
        ));
    }
    if p.expose_payment_values {
        out.push_str("        exposePaymentValues: true\n");
    }
    if let Some(policy) = &p.payment_policy {
        out.push_str(&format!(
            "        paymentPolicy: {}\n",
            map_value(policy, 8)
        ));
    }
    Ok(())
}
/// A block sequence of scalars, `indent` spaces deep.
fn write_string_list_body(out: &mut String, indent: usize, items: &[String]) {
    for item in items {
        out.push_str(&format!(
            "{:indent$}- {}\n",
            "",
            yaml::string_in_sequence(item, indent as i32)
        ));
    }
}
/// `key:` and its string list, `indent` being the column of the key. yaml.v3
/// writes an empty (or nil) list as `[]`.
fn write_keyed_list(out: &mut String, indent: usize, key: &str, items: &[String]) {
    let key = yaml::mapping_key(key, indent as i32);
    if items.is_empty() {
        out.push_str(&format!("{:indent$}{key} []\n", ""));
        return;
    }
    let mut body = String::new();
    write_string_list_body(&mut body, indent + 4, items);
    push_entry(out, &key, indent, &body);
}
/// A mapping entry whose value is a non-empty block collection: `key` (as
/// [`map_key`] returns it) written at column `indent`, and `body`, the
/// collection's lines already indented `indent + 4`. After a complex key
/// (`? key` / `:`) yaml.v3 starts the collection on the line of the `:`.
fn push_entry(out: &mut String, key: &str, indent: usize, body: &str) {
    out.push_str(&format!("{:indent$}{key}", ""));
    if key.contains('\n') {
        out.push_str("   ");
        out.push_str(body.trim_start_matches(' '));
    } else {
        out.push('\n');
        out.push_str(body);
    }
}
fn write_vault(out: &mut String, v: &VaultConfig) -> Result<(), ConfigError> {
    let mut body = String::new();
    if !v.path.is_empty() {
        body.push_str(&format!("    path: {}\n", map_value(&v.path, 4)));
    }
    if !v.default_recipients.is_empty() {
        body.push_str("    default_recipients:\n");
        write_string_list_body(&mut body, 8, &v.default_recipients);
    }
    if v.confirm_remove {
        body.push_str("    confirm_remove: true\n");
    }
    // Go's SaveTo always carries the effective vault auth method and the
    // non-zero vault defaults. Omitting these fields silently resets a vault
    // to a different KDF/search/format configuration on the next load.
    body.push_str(&format!(
        "    authMethod: {}\n",
        map_value(
            v.invalid_auth_method
                .as_deref()
                .unwrap_or_else(|| v.auth_method.as_str()),
            4
        )
    ));
    if v.use_touch_id {
        body.push_str("    useTouchID: true\n");
    }
    if let Some(legacy_mode) = v.legacy_mode {
        body.push_str(&format!("    legacy_mode: {legacy_mode}\n"));
    }
    if v.search_index {
        body.push_str("    search_index: true\n");
    }
    if v.search_workers != 0 {
        body.push_str(&format!("    search_workers: {}\n", v.search_workers));
    }
    if v.search_index_cache {
        body.push_str("    search_index_cache: true\n");
    }
    if v.config_cache_entries != 0 {
        body.push_str(&format!(
            "    config_cache_entries: {}\n",
            v.config_cache_entries
        ));
    }
    if v.pseudonymize_paths {
        body.push_str("    pseudonymize_paths: true\n");
    }
    if v.scrypt_work_factor != 0 {
        body.push_str(&format!(
            "    scrypt_work_factor: {}\n",
            v.scrypt_work_factor
        ));
    }
    if v.auto_migrate_kdf {
        body.push_str("    auto_migrate_kdf: true\n");
    }
    if v.auto_heal_zero_key {
        body.push_str("    auto_heal_zero_key: true\n");
    }
    if let Some(last_rotated) = &v.last_rotated {
        // Go's `time.Time` is written as a plain RFC 3339 timestamp (a string
        // would have been quoted); the other timestamp forms yaml.v3 reads
        // are normalised the way `time.Time.Format(RFC3339Nano)` prints them.
        let text =
            yaml_timestamp_rfc3339(last_rotated).unwrap_or_else(|| map_value(last_rotated, 4));
        body.push_str(&format!("    last_rotated: {text}\n"));
    }
    if v.format_version != 0 {
        body.push_str(&format!("    format_version: {}\n", v.format_version));
    }
    for (key, value) in [
        ("argon2id_time", v.argon2id_time),
        ("argon2id_memory", v.argon2id_memory),
        ("argon2id_threads", v.argon2id_threads),
    ] {
        if value != 0 {
            body.push_str(&format!("    {key}: {value}\n"));
        }
    }
    // Go's SaveTo currently does not copy listingCacheTTL, manifestGeneration,
    // or Sync from Config.Vault into its raw writer struct. Keep these fields
    // loadable for compatibility with files written by other callers, but do
    // not emit them here: Rust's canonical writer must follow the Go bytes
    // contract until that production omission is deliberately changed there.
    if body.is_empty() {
        out.push_str("vault: {}\n");
    } else {
        out.push_str("vault:\n");
        out.push_str(&body);
    }
    Ok(())
}
fn write_git(out: &mut String, v: &GitConfig) -> Result<(), ConfigError> {
    let mut body = String::new();
    // Go's `GitConfig` declares `commit_template` first.
    if !v.commit_template.is_empty() {
        body.push_str(&format!(
            "    commit_template: {}\n",
            map_value(&v.commit_template, 4)
        ));
    }
    for (key_name, value) in [("author", &v.author), ("email", &v.email)] {
        if !value.is_empty() {
            body.push_str(&format!("    {key_name}: {}\n", map_value(value, 4)));
        }
    }
    // Preserve an explicit false. Go's raw SaveTo struct uses `omitempty`
    // and consequently reloads false as its true default; retaining the
    // operator's disablement is the safer Rust writer behavior.
    body.push_str(&format!("    auto_push: {}\n", v.auto_push));
    body.push_str(&format!("    auto_pull: {}\n", v.auto_pull));
    if v.auto_pull_interval > Duration::ZERO {
        body.push_str(&format!(
            "    auto_pull_interval: {}\n",
            format_duration(v.auto_pull_interval)
        ));
    }
    if body.is_empty() {
        out.push_str("git: {}\n");
    } else {
        out.push_str("git:\n");
        out.push_str(&body);
    }
    Ok(())
}
/// The `mcp` block in Go's `MCPConfig` field order. Go's `SaveTo` drops
/// `oauth`; Rust keeps it (declared in `upstream-go-bugs.md`).
fn write_mcp(out: &mut String, v: &McpConfig) {
    out.push_str("mcp:\n");
    out.push_str(&format!("    port: {}\n", v.port));
    out.push_str(&format!("    bind: {}\n", map_value(&v.bind, 4)));
    out.push_str(&format!(
        "    httpTokenFile: {}\n",
        map_value(&v.http_token_file, 4)
    ));
    if !v.otlp_endpoint.is_empty() {
        out.push_str(&format!(
            "    otlp_endpoint: {}\n",
            map_value(&v.otlp_endpoint, 4)
        ));
    }
    if v.stdio {
        out.push_str("    stdio: true\n");
    }
    if v.approval_required {
        out.push_str("    approval_required: true\n");
    }
    for (key, value) in [
        ("read_header_timeout", v.read_header_timeout),
        ("read_timeout", v.read_timeout),
        ("write_timeout", v.write_timeout),
        ("shutdown_timeout", v.shutdown_timeout),
        ("approval_timeout", v.approval_timeout),
    ] {
        out.push_str(&format!("    {key}: {}\n", format_duration(value)));
    }
    out.push_str(&format!("    rate_limit: {}\n", v.rate_limit));
    if !v.trusted_proxy_ips.is_empty() {
        write_keyed_list(out, 4, "trusted_proxy_ips", &v.trusted_proxy_ips);
    }
    out.push_str(&format!(
        "    metrics_auth_required: {}\n",
        v.metrics_auth_required
    ));
    for (key_name, value) in [
        ("tls_cert_file", &v.tls_cert_file),
        ("tls_key_file", &v.tls_key_file),
        ("tls_client_ca_file", &v.tls_client_ca_file),
        ("approval_tls_cert_file", &v.approval_tls_cert_file),
        ("approval_tls_key_file", &v.approval_tls_key_file),
    ] {
        if !value.is_empty() {
            out.push_str(&format!("    {key_name}: {}\n", map_value(value, 4)));
        }
    }
    if v.mtls_enabled {
        out.push_str("    mtls_enabled: true\n");
    }
    if v.allow_insecure_bind {
        out.push_str("    allow_insecure_bind: true\n");
    }
    if let Some(oauth) = &v.oauth {
        out.push_str("    oauth:\n");
        out.push_str(&format!(
            "        access_token_ttl: {}\n        refresh_token_ttl: {}\n",
            format_duration(oauth.access_token_ttl),
            format_duration(oauth.refresh_token_ttl)
        ));
    }
    if let Some(perplexity) = &v.perplexity {
        let mut body = String::new();
        for (key_name, value) in [
            ("api_key", &perplexity.api_key),
            ("base_url", &perplexity.base_url),
        ] {
            if !value.is_empty() {
                body.push_str(&format!("        {key_name}: {}\n", map_value(value, 8)));
            }
        }
        if perplexity.rate_limit_per_min != 0 {
            body.push_str(&format!(
                "        rate_limit_per_min: {}\n",
                perplexity.rate_limit_per_min
            ));
        }
        if perplexity.allow_private {
            body.push_str("        allow_private: true\n");
        }
        if body.is_empty() {
            out.push_str("    perplexity: {}\n");
        } else {
            out.push_str("    perplexity:\n");
            out.push_str(&body);
        }
    }
}
/// Go's `AuditConfig`: `maxSizeMb` is `omitempty`, the other two are not, and
/// `SaveTo` writes the megabyte count (integer division of the byte size).
fn write_audit(out: &mut String, v: &AuditConfig) {
    out.push_str("audit:\n");
    let megabytes = v.max_file_size / (1024 * 1024);
    if megabytes != 0 {
        out.push_str(&format!("    maxSizeMb: {megabytes}\n"));
    }
    out.push_str(&format!("    maxBackups: {}\n", v.max_backups));
    out.push_str(&format!("    maxAgeDays: {}\n", v.max_age_days));
}
fn write_logging(out: &mut String, v: &LoggingConfig) -> Result<(), ConfigError> {
    if v.level.is_empty() && v.format.is_empty() {
        out.push_str("logging: {}\n");
        return Ok(());
    }
    out.push_str("logging:\n");
    if !v.level.is_empty() {
        out.push_str(&format!("    level: {}\n", map_value(&v.level, 4)));
    }
    if !v.format.is_empty() {
        out.push_str(&format!("    format: {}\n", map_value(&v.format, 4)));
    }
    Ok(())
}
fn write_security(out: &mut String, v: &SecurityConfig) {
    if !v.disable_env_passphrase && !v.allow_env_passphrase {
        out.push_str("security: {}\n");
        return;
    }
    out.push_str("security:\n");
    if v.disable_env_passphrase {
        out.push_str("    disable_env_passphrase: true\n");
    }
    if v.allow_env_passphrase {
        out.push_str("    allow_env_passphrase: true\n");
    }
}
fn write_scan_patterns(out: &mut String, patterns: &[ScanPattern]) -> Result<(), ConfigError> {
    out.push_str("scan_patterns:\n");
    for p in patterns {
        out.push_str(&format!("    - name: {}\n", map_value(&p.name, 6)));
        out.push_str(&format!("      pattern: {}\n", map_value(&p.pattern, 6)));
        out.push_str(&format!(
            "      description: {}\n",
            map_value(&p.description, 6)
        ));
        out.push_str(&format!("      severity: {}\n", map_value(&p.severity, 6)));
    }
    Ok(())
}
/// Go's `PaymentPolicy`: `instrument` always, the rest `omitempty`; a
/// `max_amount` struct is omitted when both limits are empty.
fn write_payment_policies(
    out: &mut String,
    policies: &BTreeMap<String, PaymentPolicy>,
) -> Result<(), ConfigError> {
    out.push_str("paymentPolicies:\n");
    for (name, policy) in yaml_entries(policies) {
        let mut body = String::new();
        body.push_str(&format!(
            "        instrument: {}\n",
            map_value(&policy.instrument, 8)
        ));
        if !policy.allowed_merchants.is_empty() {
            body.push_str("        allowed_merchants:\n");
            write_string_list_body(&mut body, 12, &policy.allowed_merchants);
        }
        let amount = &policy.max_amount;
        if !amount.per_transaction.is_empty() || !amount.per_day.is_empty() {
            body.push_str("        max_amount:\n");
            if !amount.per_transaction.is_empty() {
                body.push_str(&format!(
                    "            per_transaction: {}\n",
                    map_value(&amount.per_transaction, 12)
                ));
            }
            if !amount.per_day.is_empty() {
                body.push_str(&format!(
                    "            per_day: {}\n",
                    map_value(&amount.per_day, 12)
                ));
            }
        }
        if !policy.currency.is_empty() {
            body.push_str(&format!(
                "        currency: {}\n",
                map_value(&policy.currency, 8)
            ));
        }
        push_entry(out, &map_key(name, 4), 4, &body);
    }
    Ok(())
}
fn write_update(out: &mut String, v: &UpdateConfig) -> Result<(), ConfigError> {
    let mut body = String::new();
    if v.cache_ttl > Duration::ZERO {
        body.push_str(&format!(
            "    cache_ttl: {}\n",
            format_duration(v.cache_ttl)
        ));
    }
    if body.is_empty() {
        out.push_str("update: {}\n");
    } else {
        out.push_str("update:\n");
        out.push_str(&body);
    }
    Ok(())
}
fn write_clipboard(out: &mut String, v: &ClipboardConfig) -> Result<(), ConfigError> {
    let mut body = format!("    auto_clear_duration: {}\n", v.auto_clear_duration);
    // Go's `omitempty` drops false here, which makes a subsequent load turn
    // an explicit opt-out back on. Keep the opt-out in Rust's canonical bytes.
    body.push_str(&format!("    copyByDefault: {}\n", v.copy_by_default));
    if let Some(print_by_default) = v.print_by_default {
        body.push_str(&format!("    printByDefault: {print_by_default}\n"));
    }
    if body.is_empty() {
        out.push_str("clipboard: {}\n");
    } else {
        out.push_str("clipboard:\n");
        out.push_str(&body);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(source: &str) -> Config {
        Config::load_from_bytes(source.as_bytes())
            .unwrap_or_else(|error| panic!("{source}: {error}"))
    }

    fn reject(source: &str) -> String {
        Config::load_from_bytes(source.as_bytes())
            .expect_err(source)
            .to_string()
    }

    #[test]
    fn sections_read_the_values_yaml_v3_decodes() {
        let config = load(
            "vault:\n  path: 5\n  search_workers: 1.5\n  argon2id_time: 0o10\n  listing_cache_ttl: -1s\n  sync:\n    method: 0x10\ngit:\n  commit_template: true\n  auto_push: yes\n  auto_pull_interval: -5m\nmcp:\n  port: 1_000\n  bind: 1.5\n  rate_limit: 017\n  approval_timeout: -1s\nupdate:\n  cache_ttl: -1h\nclipboard:\n  auto_clear_duration: -0.5\n",
        );
        let vault = config.vault.as_ref().expect("vault");
        assert_eq!(vault.path, "5");
        assert_eq!(vault.search_workers, 1);
        assert_eq!(vault.argon2id_time, 8);
        assert_eq!(vault.listing_cache_ttl, Duration::ZERO);
        assert_eq!(vault.sync.as_ref().map(|s| s.method.as_str()), Some("0x10"));
        let git = config.git.as_ref().expect("git");
        assert_eq!(git.commit_template, "true");
        assert!(git.auto_push);
        assert_eq!(git.auto_pull_interval, Duration::ZERO);
        let mcp = config.mcp.as_ref().expect("mcp");
        assert_eq!((mcp.port, mcp.rate_limit), (1000, 15));
        assert_eq!(mcp.bind, "1.5");
        assert_eq!(mcp.approval_timeout, Duration::ZERO);
        assert_eq!(
            config.update.as_ref().expect("update").cache_ttl,
            Duration::ZERO
        );
        assert_eq!(
            config
                .clipboard
                .as_ref()
                .expect("clipboard")
                .auto_clear_duration,
            0
        );
        assert!(config.validate().is_empty());
    }

    #[test]
    fn agents_take_nulls_and_non_string_scalars_like_go() {
        let config = load(
            "agents:\n  a:\n    tier: 5\n    skillPath: 0x10\n    max_reads_per_hour: 1e3\n    canWrite: yes\n  b:\n    canWrite: null\n    tier: null\n    skillPath: null\n    max_reads_per_hour: null\n    allowedPaths: [null, 5]\n  c: null\n",
        );
        let a = &config.agents["a"];
        assert_eq!(a.tier.as_deref(), Some("5"));
        assert_eq!(a.skill_path, "0x10");
        assert_eq!(a.max_reads_per_hour, 1000);
        assert!(a.can_write);
        let b = &config.agents["b"];
        assert_eq!((b.tier.clone(), b.skill_path.as_str()), (None, ""));
        assert!(!b.can_write);
        assert_eq!(b.allowed_paths, ["5"]);
        // `tier: null` was written, so the profile is not made to expose the
        // value tools, while an untouched null profile is.
        assert!(!b.expose_value_tools);
        assert!(config.agents["c"].expose_value_tools);
        assert!(config.agents.contains_key("default"));
        load("agents: null\n");
        load("agents: ~\n");
    }

    #[test]
    fn merged_values_follow_the_gates_of_the_go_merge() {
        // A pointer field comes in through `<<`; approvalMode is gated on the
        // profile writing it, so a merged one is dropped.
        let config = load(
            "base: &base\n  canWrite: true\n  approvalMode: bogus\nagents:\n  x:\n    <<: *base\n",
        );
        assert!(config.agents["x"].can_write);
        assert_eq!(config.agents["x"].approval_mode, None);
        assert!(
            reject("base: &base\n  promptInjectionMode: weird\nagents:\n  x:\n    <<: *base\n")
                .contains("invalid promptInjectionMode \"weird\"")
        );
        // A merged `bind` is not a key the section wrote.
        load("base: &base\n  bind: ''\nmcp:\n  <<: *base\n");
        load("base: &base\n  bind: ''\nmcp: *base\n");
        // The vault merge feeds the top-level method from the decoded
        // `useTouchID` (merged keys included), while the section's own flag
        // keeps only a written one.
        for source in [
            "base: &b\n  useTouchID: true\nvault:\n  <<: *b\n",
            "base: &b\n  useTouchID: true\nvault: {<<: *b}\n",
        ] {
            let config = load(source);
            assert_eq!(config.auth_method, AuthMethod::Touchid, "{source}");
            assert_eq!(config.use_touch_id, Some(true), "{source}");
            assert!(!config.vault.as_ref().unwrap().use_touch_id, "{source}");
        }
        // A flag the vault writes itself wins over the merged one, and an
        // `authMethod` the vault writes keeps the feed off.
        let config = load("base: &b\n  useTouchID: true\nvault:\n  <<: *b\n  useTouchID: false\n");
        assert_eq!(config.auth_method, AuthMethod::Passphrase);
        let config =
            load("base: &b\n  useTouchID: true\nvault:\n  <<: *b\n  authMethod: passphrase\n");
        assert_eq!(config.auth_method, AuthMethod::Passphrase);
        // A merged zero session timeout was not written by the operator.
        load("base: &base\n  sessionTimeout: 0s\n<<: *base\n");
        assert!(
            reject("sessionTimeout: 0s\n")
                .contains("sessionTimeout: must be greater than 0, got 0s")
        );
    }

    #[test]
    fn coerced_values_show_in_the_loader_and_validator_messages() {
        assert!(
            reject("agents:\n  x:\n    approvalMode: 0x10\n")
                .contains("invalid approvalMode \"0x10\"")
        );
        assert!(
            reject("agents:\n  x:\n    approvalMode: 5\n").contains("invalid approvalMode \"5\"")
        );
        let config = load("vault:\n  authMethod: 0x10\n");
        assert_eq!(
            config.validate(),
            ["invalid authMethod \"0x10\" (valid: passphrase, touchid)"]
        );
        let config = load("vault:\n  argon2id_time: 1.5\n");
        assert_eq!(
            config.validate(),
            ["vault.argon2id_time: 1 is below minimum floor of 2"]
        );
        let config = load("agents:\n  x:\n    allowedPaths: [null, '[']\n");
        assert!(config.validate()[0].starts_with("agents.x.allowedPaths[0]:"));
        let config = load("clipboard:\n  auto_clear_duration: -1.5\n");
        assert!(config.validate()[0].starts_with("clipboard.autoClearDuration:"));
    }

    /// A file or symlink planted at a temporary-looking name next to the
    /// config must never be opened or followed (the old fixed `config.yaml.tmp`
    /// let a symlink there redirect the write outside the directory).
    #[cfg(unix)]
    #[test]
    fn save_to_never_writes_through_a_planted_temporary_name() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "symvault-core-save-{}-{unique}",
            std::process::id()
        ));
        let dir = root.join("vault");
        fs::create_dir_all(&dir).unwrap();
        let victim = root.join("victim.txt");
        fs::write(&victim, b"outside data").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("config.yaml.tmp")).unwrap();
        let target = dir.join("config.yaml");

        Config::default().save_to(&target).unwrap();
        Config::default().save_to(&target).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"outside data");
        assert!(fs::symlink_metadata(&target).unwrap().file_type().is_file());
        assert_eq!(
            fs::read(&target).unwrap(),
            Config::default().to_yaml_bytes().unwrap()
        );
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["config.yaml", "config.yaml.tmp"],
            "no temporary file left"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn yaml_timestamps_are_printed_like_rfc3339_nano() {
        for (input, want) in [
            ("2026-01-02T03:04:05Z", Some("2026-01-02T03:04:05Z")),
            ("2026-01-02T03:04:05.50Z", Some("2026-01-02T03:04:05.5Z")),
            (
                "2026-01-02T03:04:05.5+02:00",
                Some("2026-01-02T03:04:05.5+02:00"),
            ),
            ("2026-1-2t3:4:5+00:00", Some("2026-01-02T03:04:05Z")),
            ("2026-01-02 03:04:05", Some("2026-01-02T03:04:05Z")),
            ("2026-01-02", Some("2026-01-02T00:00:00Z")),
            ("2025-02-29", None),
            ("2026-01-02 03:04:05 +02:00", None),
            ("2026-13-01", None),
            ("yesterday", None),
        ] {
            assert_eq!(yaml_timestamp_rfc3339(input).as_deref(), want, "{input}");
        }
    }

    #[test]
    fn defaults_match_go_contract() {
        let c = Config::default();
        assert_eq!(c.default_agent, "default");
        assert_eq!(c.session_timeout, Duration::from_secs(900));
        assert_eq!(c.agents.len(), 6);
        assert!(!c.agents["default"].can_write);
        assert!(c.agents["hermes"].can_write);
    }
    #[test]
    fn parses_precedence_and_duration_strings() {
        let c=Config::load_from_bytes(b"vaultDir: /custom\nsessionTimeout: 30m\nuseTouchID: true\nagents:\n  x:\n    requireApproval: true\n    approvalMode: none\nmcp:\n  port: 9090\n  bind: 0.0.0.0\n").unwrap();
        assert_eq!(c.vault_dir, "/custom");
        assert_eq!(c.session_timeout, Duration::from_secs(1800));
        assert_eq!(c.effective_auth_method(), AuthMethod::Touchid);
        assert_eq!(c.agents["x"].approval_mode.as_deref(), Some("none"));
        assert_eq!(c.mcp.unwrap().port, 9090);
    }

    #[test]
    fn parse_go_duration_matches_ttl_wire_contract() {
        for (text, expected) in [
            ("1h2m3.5s", 3_723_500_000_000_i64),
            ("1µs", 1_000_i64),
            ("1μs", 1_000_i64),
            ("-5m", -300_000_000_000_i64),
            ("0s", 0_i64),
            ("0", 0_i64),
            ("+0", 0_i64),
            ("-0", 0_i64),
        ] {
            assert_eq!(parse_go_duration(text), Ok(expected), "{text}");
        }
        for text in ["", "not-a-duration", ".s", "9223372037s"] {
            assert_eq!(
                parse_go_duration(text),
                Err(format!("time: invalid duration {text:?}")),
                "{text:?}"
            );
        }
        assert_eq!(
            parse_go_duration("1"),
            Err("time: missing unit in duration \"1\"".into())
        );
        assert_eq!(
            parse_go_duration("1fortnight"),
            Err("time: unknown unit \"fortnight\" in duration \"1fortnight\"".into())
        );
        assert_eq!(
            parse_go_duration("1e3s"),
            Err("time: unknown unit \"e\" in duration \"1e3s\"".into())
        );
        assert_eq!(
            parse_go_duration("1msx"),
            Err("time: unknown unit \"msx\" in duration \"1msx\"".into())
        );
        assert_eq!(
            parse_go_duration("1.2.3s"),
            Err("time: missing unit in duration \"1.2.3s\"".into())
        );
    }

    #[test]
    fn parse_go_duration_scales_long_fractions_per_unit() {
        for (text, expected) in [
            ("0.123456789123h", 444_444_440_842_i128),
            ("0.123456789123m", 7_407_407_347_i128),
            ("-0.123456789123h", -444_444_440_842_i128),
        ] {
            assert_eq!(parse_duration_nanos(text), Some(expected), "{text}");
            assert_eq!(parse_go_duration(text), Ok(expected as i64), "{text}");
        }
    }

    #[test]
    fn parse_go_duration_keeps_existing_parser_unmodified() {
        assert_eq!(parse_duration_nanos("1μs"), Some(1_000));
        assert_eq!(parse_duration_nanos("-5m"), Some(-300_000_000_000));
    }

    #[test]
    fn payment_exposure_is_opt_in_and_survives_save() {
        for (value, expected) in [("true", true), ("false", false)] {
            let yaml =
                format!("agents:\n  fixture:\n    tier: admin\n    exposePaymentValues: {value}\n");
            let config = Config::load_from_bytes(yaml.as_bytes()).unwrap();
            assert_eq!(config.agents["fixture"].expose_payment_values, expected);
            let restored = Config::load_from_bytes(&config.to_yaml_bytes().unwrap()).unwrap();
            assert_eq!(restored.agents["fixture"].expose_payment_values, expected);
        }
        let config = Config::load_from_bytes(b"agents:\n  fixture:\n    tier: admin\n").unwrap();
        assert!(!config.agents["fixture"].expose_payment_values);
    }
    #[test]
    fn rejects_explicit_empty_mcp_bind() {
        assert!(Config::load_from_bytes(b"mcp:\n  bind: \"\"\n").is_err());
    }
    #[test]
    fn mcp_tls_settings_survive_config_roundtrip() {
        let yaml = b"mcp:\n  tls_cert_file: cert.pem\n  tls_key_file: key.pem\n  tls_client_ca_file: ca.pem\n  mtls_enabled: true\n  allow_insecure_bind: false\n";
        let config = Config::load_from_bytes(yaml).unwrap();
        let mcp = config.mcp.as_ref().unwrap();
        assert_eq!(mcp.tls_cert_file, "cert.pem");
        assert_eq!(mcp.tls_key_file, "key.pem");
        assert_eq!(mcp.tls_client_ca_file, "ca.pem");
        assert!(mcp.mtls_enabled);
        assert_eq!(
            Config::load_from_bytes(&config.to_yaml_bytes().unwrap())
                .unwrap()
                .mcp,
            config.mcp
        );
        for (access, refresh, expected) in [
            (
                "2s",
                "1m",
                OAuthConfig {
                    access_token_ttl: Duration::from_secs(2),
                    refresh_token_ttl: Duration::from_secs(60),
                },
            ),
            ("0s", "-5m", OAuthConfig::default()),
        ] {
            let yaml = format!(
                "mcp:\n  oauth:\n    access_token_ttl: {access}\n    refresh_token_ttl: {refresh}\n"
            );
            let config = Config::load_from_bytes(yaml.as_bytes()).unwrap();
            assert_eq!(config.mcp.as_ref().unwrap().oauth, Some(expected));
            assert_eq!(
                Config::load_from_bytes(&config.to_yaml_bytes().unwrap())
                    .unwrap()
                    .mcp,
                config.mcp
            );
        }
        assert!(
            Config::load_from_bytes(b"mcp:\n  oauth:\n    access_token_ttl: invalid\n").is_err()
        );
    }
    #[test]
    fn default_writer_matches_go_fixture_shape() {
        let c = Config::default();
        let expected = format!(
            "agents:\n    claude-code:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.claude/skills/symvault/SKILL.md\n    codex:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.codex/skills/symvault/AGENTS.md\n    default:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: false\n        exposeValueTools: true\n        autoUnseal: false\n    hermes:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.hermes/skills/symvault/SKILL.md\n    openclaw:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.openclaw/skills/symvault/SKILL.md\n    opencode:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.opencode/skills/symvault/SKILL.md\nvaultDir: {}\ndefaultAgent: default\nsessionTimeout: 15m0s\nsessionMaxLifetime: 8h0m0s\nauthMethod: passphrase\n",
            c.vault_dir
        );
        assert_eq!(
            String::from_utf8(c.to_yaml_bytes().unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn vault_writer_preserves_modeled_fields() {
        let vault = VaultConfig {
            path: "/fixture/vault".into(),
            default_recipients: vec!["age1fixture".into()],
            confirm_remove: true,
            auth_method: AuthMethod::Touchid,
            use_touch_id: true,
            legacy_mode: Some(false),
            search_index: true,
            search_workers: 4,
            search_index_cache: true,
            config_cache_entries: 12,
            pseudonymize_paths: true,
            scrypt_work_factor: 22,
            auto_migrate_kdf: true,
            auto_heal_zero_key: true,
            last_rotated: Some("2025-06-07T08:09:10.123456789Z".into()),
            format_version: 7,
            argon2id_time: 3,
            argon2id_memory: 65536,
            argon2id_threads: 2,
            ..VaultConfig::default()
        };
        let config = Config {
            auth_method: AuthMethod::Touchid,
            use_touch_id: Some(true),
            vault: Some(vault.clone()),
            ..Config::default()
        };
        let yaml = String::from_utf8(config.to_yaml_bytes().unwrap()).unwrap();
        for field in [
            "path: /fixture/vault",
            "default_recipients:",
            "confirm_remove: true",
            "authMethod: touchid",
            "useTouchID: true",
            "legacy_mode: false",
            "search_index: true",
            "search_workers: 4",
            "search_index_cache: true",
            "config_cache_entries: 12",
            "pseudonymize_paths: true",
            "scrypt_work_factor: 22",
            "auto_migrate_kdf: true",
            "auto_heal_zero_key: true",
            "last_rotated: 2025-06-07T08:09:10.123456789Z",
            "format_version: 7",
            "argon2id_time: 3",
            "argon2id_memory: 65536",
            "argon2id_threads: 2",
        ] {
            assert!(yaml.contains(field), "writer omitted vault field {field:?}");
        }
        let loaded = Config::load_from_bytes(yaml.as_bytes()).unwrap();
        assert_eq!(loaded.vault, Some(vault));

        // These fields are accepted by the loader but are currently omitted
        // by Go's Config.SaveTo raw writer; the canonical Rust writer follows
        // that source-bound behavior until Go changes its copy list.
        let omitted = Config {
            vault: Some(VaultConfig {
                listing_cache_ttl: Duration::from_secs(45 * 60),
                manifest_generation: 9,
                sync: Some(SyncConfig {
                    method: "icloud-drive".into(),
                }),
                ..VaultConfig::default()
            }),
            ..Config::default()
        };
        let omitted_yaml = String::from_utf8(omitted.to_yaml_bytes().unwrap()).unwrap();
        assert!(!omitted_yaml.contains("listing_cache_ttl"));
        assert!(!omitted_yaml.contains("manifest_generation"));
        assert!(!omitted_yaml.contains("sync:"));
    }

    #[test]
    fn optional_sections_use_empty_maps_and_null_sections_are_skipped() {
        let config = Config {
            git: Some(GitConfig {
                auto_push: false,
                auto_pull: false,
                auto_pull_interval: Duration::ZERO,
                commit_template: String::new(),
                author: String::new(),
                email: String::new(),
            }),
            update: Some(UpdateConfig {
                cache_ttl: Duration::ZERO,
            }),
            ..Config::default()
        };
        let yaml = String::from_utf8(config.to_yaml_bytes().unwrap()).unwrap();
        assert!(yaml.contains("git:\n    auto_push: false\n    auto_pull: false\n"));
        assert!(yaml.contains("update: {}\n"));
        Config::load_from_bytes(yaml.as_bytes()).expect("empty optional maps are valid YAML");

        let loaded = Config::load_from_bytes(
            b"vault: null\ngit: null\nmcp: null\nupdate: null\nclipboard: null\n",
        )
        .expect("Go-compatible null optional sections");
        assert!(loaded.vault.is_none());
        assert!(loaded.git.is_none());
        assert!(loaded.mcp.is_none());
        assert!(loaded.update.is_none());
        assert!(loaded.clipboard.is_none());
    }

    /// `time.Duration.String()` for the values a session duration can take.
    #[test]
    fn go_duration_string_matches_time_duration_string() {
        for (nanos, want) in [
            (0_i128, "0s"),
            (1, "1ns"),
            (999, "999ns"),
            (1_500, "1.5\u{b5}s"),
            (1_500_000, "1.5ms"),
            (999_999_999, "999.999999ms"),
            (1_000_000_000, "1s"),
            (1_500_000_000, "1.5s"),
            (90_000_000_000, "1m30s"),
            (300_000_000_000, "5m0s"),
            (3_600_000_000_000, "1h0m0s"),
            (3_600_000_000_001, "1h0m0.000000001s"),
            (90_000_000_000_000, "25h0m0s"),
            (-300_000_000_000, "-5m0s"),
            (-1_500_000_000, "-1.5s"),
            (-1, "-1ns"),
            (i128::from(i64::MIN), "-2562047h47m16.854775808s"),
            (i128::from(i64::MAX), "2562047h47m16.854775807s"),
        ] {
            assert_eq!(go_duration_string(nanos), want, "{nanos}");
        }
    }

    #[test]
    fn non_positive_session_durations_are_reported_with_their_value_and_joined() {
        let error = Config::load_from_bytes(b"sessionTimeout: 0s\nsessionMaxLifetime: -90m\n")
            .expect_err("both durations are rejected");
        assert_eq!(
            error.to_string(),
            "sessionTimeout: must be greater than 0, got 0s (default: 15m, configure sessionTimeout in config.yaml)\n\
             sessionMaxLifetime: must be greater than 0, got -1h30m0s (default: 8h, configure sessionMaxLifetime in config.yaml)"
        );
    }

    #[test]
    fn loader_errors_carry_no_native_prefix() {
        for input in [
            "agents:\n  x:\n    approvalMode: bogus\n",
            "agents:\n  x:\n    promptInjectionMode: weird\n",
            "mcp:\n  bind: ''\n",
            "audit:\n  maxSizeMb: abc\n",
            "sessionTimeout: -5m\n",
        ] {
            let text = Config::load_from_bytes(input.as_bytes())
                .expect_err("rejected")
                .to_string();
            assert!(
                !text.starts_with("parse config:") && !text.starts_with("invalid config:"),
                "{input:?}: {text}"
            );
        }
    }

    #[test]
    fn unknown_auth_methods_load_like_go() {
        // The top-level method is dropped; the key still counts as written.
        let config = Config::load_from_bytes(b"authMethod: bogus\nuseTouchID: true\n").unwrap();
        assert_eq!(config.auth_method, AuthMethod::Passphrase);
        assert!(config.validate().is_empty());
        // A vault method is kept as written and rejected by validate, quoted
        // the way it was written.
        let config = Config::load_from_bytes(b"vault:\n  authMethod: ' Bogus '\n").unwrap();
        assert_eq!(
            config.validate(),
            ["invalid authMethod \" Bogus \" (valid: passphrase, touchid)"]
        );
        let mut config = config;
        config.set_auth_method("touchid").unwrap();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn empty_vault_dir_keeps_the_default() {
        let default = Config::default().vault_dir;
        for input in ["vaultDir: ''\n", "vaultDir: null\n"] {
            assert_eq!(
                Config::load_from_bytes(input.as_bytes()).unwrap().vault_dir,
                default
            );
        }
    }

    #[test]
    fn validate_checks_audit_size_and_payment_policies_like_go() {
        let errors = |source: &str| load(source).validate();
        // audit.maxFileSize: null and zero are zero bytes, the product wraps.
        for source in [
            "audit:\n  maxSizeMb: null\n",
            "audit:\n  maxSizeMb:\n",
            "audit:\n  maxSizeMb: 0\n",
            "audit:\n  maxSizeMb: -3\n",
            "audit:\n  maxSizeMb: 9223372036854775807\n",
            "audit:\n  maxSizeMb: 17592186044416\n",
        ] {
            assert_eq!(
                errors(source),
                [
                    "audit.maxFileSize: must be greater than 0 (configure audit.maxFileSize in config.yaml)"
                ],
                "{source}"
            );
        }
        for source in [
            "audit:\n  maxSizeMb: 5\n",
            "audit: {}\n",
            "audit: null\n",
            "audit:\n  maxBackups: null\n",
            "base: &b\n  maxSizeMb: 0\naudit:\n  <<: *b\n",
        ] {
            assert!(errors(source).is_empty(), "{source}");
        }
        let policy = |body: &str| {
            errors(&format!(
                "paymentPolicies:\n  p:\n    instrument: card\n    currency: EUR\n{body}"
            ))
        };
        assert_eq!(
            errors("paymentPolicies:\n  p: {}\n"),
            ["paymentPolicies.p.instrument: must not be empty"]
        );
        assert_eq!(
            errors("paymentPolicies:\n  p:\n    instrument: ' '\n    allowed_merchants: [a]\n"),
            ["paymentPolicies.p.instrument: must not be empty"]
        );
        assert_eq!(
            policy(""),
            ["paymentPolicies.p: must have at least one allowed_merchant or max_amount limit"]
        );
        assert_eq!(
            errors(
                "paymentPolicies:\n  p:\n    instrument: card\n    max_amount:\n      per_day: '1'\n"
            ),
            ["paymentPolicies.p.currency: required when max_amount limits are set"]
        );
        for (amount, reason) in [
            ("abc", ""),
            ("1.2.3", " (multiple decimal points)"),
            ("5-1", " (minus sign must be leading)"),
            ("-", " (no digits)"),
            (".", " (no digits)"),
            ("+5", ""),
            ("1e3", ""),
            ("1234567890123456789012345678901", ""),
        ] {
            assert_eq!(
                policy(&format!(
                    "    max_amount:\n      per_transaction: '{amount}'\n"
                )),
                [format!(
                    "paymentPolicies.p.max_amount.per_transaction: \"{amount}\" is not a valid decimal amount{reason}"
                )],
                "{amount}"
            );
        }
        assert_eq!(
            policy("    max_amount:\n      per_transaction: '5'\n      per_day: x\n"),
            ["paymentPolicies.p.max_amount.per_day: \"x\" is not a valid decimal amount"]
        );
        for amount in ["5.", ".5", "-0.25", "123456789012345678901234567890"] {
            assert!(
                policy(&format!("    max_amount:\n      per_day: '{amount}'\n")).is_empty(),
                "{amount}"
            );
        }
        // An agent's reference must name a defined policy, case-sensitively.
        assert_eq!(
            errors("agents:\n  x:\n    paymentPolicy: abc\n"),
            ["agents.x.paymentPolicy: policy \"abc\" not found in paymentPolicies"]
        );
        assert!(errors("agents:\n  x:\n    paymentPolicy: ''\n").is_empty());
        assert!(errors("agents:\n  x:\n    paymentPolicy: null\n").is_empty());
        assert_eq!(
            errors(
                "paymentPolicies:\n  p:\n    instrument: c\n    allowed_merchants: [a]\nagents:\n  x:\n    paymentPolicy: P\n"
            ),
            ["agents.x.paymentPolicy: policy \"P\" not found in paymentPolicies"]
        );
        assert!(
            errors(
                "paymentPolicies:\n  5:\n    instrument: c\n    allowed_merchants: [a]\nagents:\n  x:\n    paymentPolicy: 5\n"
            )
            .is_empty()
        );
        // The checks keep Go's order: audit, clipboard, payment, agent
        // reference, Argon2id.
        let order = errors(
            "audit:\n  maxSizeMb: 0\nclipboard:\n  auto_clear_duration: -2\npaymentPolicies:\n  p: {}\nagents:\n  x:\n    paymentPolicy: q\nvault:\n  argon2id_time: 1\n",
        );
        let prefixes: Vec<&str> = order
            .iter()
            .map(|line| line.split(':').next().unwrap_or(""))
            .collect();
        assert_eq!(
            prefixes,
            [
                "audit.maxFileSize",
                "clipboard.autoClearDuration",
                "paymentPolicies.p.instrument",
                "agents.x.paymentPolicy",
                "vault.argon2id_time"
            ]
        );
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(Config::default().validate().is_empty());
    }

    #[test]
    fn validate_reports_every_violation_at_once() {
        let c = Config {
            vault_dir: "  ".into(),
            session_timeout: Duration::ZERO,
            session_max_lifetime: Duration::ZERO,
            default_agent: "missing".into(),
            ..Config::default()
        };
        let errors = c.validate();
        assert_eq!(errors.len(), 4, "errors={errors:?}");
        assert!(errors[0].starts_with("vaultDir: must not be empty"));
        assert!(errors.iter().any(|e| e.starts_with("sessionTimeout:")));
        assert!(errors.iter().any(|e| e.starts_with("sessionMaxLifetime:")));
        assert!(errors.iter().any(|e| e.contains("defaultAgent")));
    }

    #[test]
    fn validate_rejects_unknown_approval_mode_but_allows_auto() {
        let mut c = Config::default();
        c.agents.get_mut("default").unwrap().approval_mode = Some("bogus".into());
        let errors = c.validate();
        assert!(errors.iter().any(|e| e.contains("approvalMode")));

        let mut c = Config::default();
        c.agents.get_mut("default").unwrap().approval_mode = Some("auto".into());
        assert!(c.validate().is_empty());
    }

    #[test]
    fn validate_rejects_unterminated_glob_class() {
        let mut c = Config::default();
        c.agents.get_mut("default").unwrap().allowed_paths = vec!["/tmp/[abc".into()];
        let errors = c.validate();
        assert!(errors.iter().any(|e| e.contains("allowedPaths[0]")));

        c.agents.get_mut("default").unwrap().allowed_paths = vec!["/tmp/[abc]*".into()];
        assert!(c.validate().is_empty());
    }

    #[test]
    fn validate_rejects_negative_clipboard_duration() {
        let c = Config {
            clipboard: Some(ClipboardConfig {
                auto_clear_duration: -1,
                copy_by_default: false,
                print_by_default: None,
            }),
            ..Config::default()
        };
        let errors = c.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("clipboard.autoClearDuration"))
        );
    }

    #[test]
    fn validate_enforces_argon2id_floor_and_ceiling() {
        let c = Config {
            vault: Some(VaultConfig {
                argon2id_time: 1,
                argon2id_threads: 20,
                argon2id_memory: 100,
                ..VaultConfig::default()
            }),
            ..Config::default()
        };
        let errors = c.validate();
        assert!(errors.iter().any(|e| e.contains("argon2id_time")));
        assert!(errors.iter().any(|e| e.contains("argon2id_threads")));
        assert!(errors.iter().any(|e| e.contains("argon2id_memory")));

        let c = Config {
            vault: Some(VaultConfig {
                argon2id_time: 3,
                argon2id_threads: 2,
                argon2id_memory: 65536,
                ..VaultConfig::default()
            }),
            ..Config::default()
        };
        assert!(c.validate().is_empty());
    }

    /// `unicode.IsSpace` of Go 1.26.6, listed by running it over every rune.
    const GO_IS_SPACE: [u32; 25] = [
        0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029,
        0x202F, 0x205F, 0x3000,
    ];

    #[test]
    fn go_space_set_matches_unicode_is_space() {
        let rust: Vec<u32> = (0..=char::MAX as u32)
            .filter(|&code| char::from_u32(code).is_some_and(char::is_whitespace))
            .collect();
        assert_eq!(rust, GO_IS_SPACE);
    }

    #[test]
    fn unicode_only_whitespace_serves_the_defaults_like_go() {
        for blank in [
            "",
            "   ",
            "\u{b}\n",
            "\u{b}",
            "\u{c}\n",
            "\u{a0}\n",
            "\u{85}\n",
            "\u{3000}\n",
            "\u{2028}\u{2029}\n",
            " \t\r\n\u{b}\u{c}\u{a0}\u{85}\u{3000} \n",
        ] {
            assert_eq!(
                Config::load_from_bytes(blank.as_bytes()).expect(blank),
                Config::default(),
                "{blank:?}"
            );
        }
        // Not white space for Go: a BOM, a zero-width space and bytes that are
        // not UTF-8 all reach the YAML reader.
        for not_blank in [
            &b" \xff\n"[..],
            "\u{200b}\n".as_bytes(),
            "\u{a0}[\n".as_bytes(),
        ] {
            assert!(!is_go_blank(not_blank), "{not_blank:?}");
        }
    }
}
