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
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_categories::UnicodeCategories;

const APP_NAME: &str = "symaira-vault";
const LEGACY_DIR: &str = ".symvault";
const DEFAULT_AGENT: &str = "default";
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("parse config: {0}")]
    Parse(String),
    #[error("invalid config: {0}")]
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
            other => Err(ConfigError::Invalid(format!(
                "invalid authMethod {other:?} (valid: passphrase, touchid)"
            ))),
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
    pub format_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitConfig {
    pub auto_push: bool,
    pub auto_pull: bool,
    pub auto_pull_interval: Duration,
    pub commit_template: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpConfig {
    pub port: i64,
    pub bind: String,
    pub stdio: bool,
    pub http_token_file: String,
    pub read_header_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub approval_timeout: Duration,
    pub rate_limit: i64,
    pub metrics_auth_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub cache_ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClipboardConfig {
    pub auto_clear_duration: i64,
    pub copy_by_default: bool,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            auto_push: true,
            auto_pull: true,
            auto_pull_interval: Duration::from_secs(10),
            commit_template: "Update from Symaira Vault".into(),
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
            read_header_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            approval_timeout: Duration::from_secs(30),
            rate_limit: 60,
            metrics_auth_required: true,
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
fn xdg_base(value: &str, home: &str, fallback: &str) -> PathBuf {
    if value.is_empty() {
        Path::new(home).join(fallback)
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
    let cache_dir = xdg_base(&env.xdg_cache_home, &env.home, ".cache").join(APP_NAME);
    let xdg_config = xdg_base(&env.xdg_config_home, &env.home, ".config").join(APP_NAME);
    let xdg_data = xdg_base(&env.xdg_data_home, &env.home, ".local/share").join(APP_NAME);

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
            xdg_data_dir_exists: xdg_base(&env.xdg_data_home, &home, ".local/share")
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
            vault.use_touch_id = method == AuthMethod::Touchid;
        }
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path)?;
        Self::load_from_bytes(&bytes)
    }

    pub fn load_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        Self::load_from_bytes_with_warnings(bytes).map(|(config, _)| config)
    }

    /// Loads a config and returns the warnings the loader raised.
    ///
    /// Warnings are returned rather than emitted through a global callback, so
    /// they are explicit and thread-safe. Go reaches the same outcome through
    /// `config.SetWarnFunc`, and the CFG-003 contract pins the texts on both
    /// sides.
    ///
    /// The list is currently always empty: the two warnings this loader used to
    /// raise became rejections in CFG-003 step two. The seam stays because Go
    /// still warns for the deprecated `envWhitelist`, which this loader cannot
    /// yet reproduce — it does not model `envAllowlist` at all — and the
    /// contract test fails the moment a fixture case carries a warning.
    pub fn load_from_bytes_with_warnings(bytes: &[u8]) -> Result<(Self, Vec<String>), ConfigError> {
        let mut warnings = Vec::new();
        let config = Self::parse_document(bytes, &mut warnings)?;
        Ok((config, warnings))
    }

    #[allow(
        clippy::ptr_arg,
        unused_variables,
        reason = "the warning seam is retained; see load_from_bytes_with_warnings"
    )]
    fn parse_document(bytes: &[u8], warnings: &mut Vec<String>) -> Result<Self, ConfigError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
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
        let first = documents
            .next()
            .ok_or_else(|| ConfigError::Parse("empty YAML stream".to_owned()))?;
        let profiles = ProfileFields::deserialize(first)
            .map_err(|error| ConfigError::Parse(error.to_string()))?;
        if documents.next().is_some() {
            return Err(ConfigError::Parse(MULTIPLE_DOCUMENTS_MESSAGE.to_owned()));
        }
        let fields: serde_yaml_ng::Mapping = profiles
            .fields
            .into_iter()
            .map(|(name, value)| (key(&name), value))
            .collect();
        let root = &fields;
        let mut config = Self::default();
        let mut auth_method_explicit = false;
        if let Some(v) = scalar(root, "vaultDir") {
            config.vault_dir = string(v, "vaultDir")?;
        }
        if let Some(v) = scalar(root, "defaultAgent") {
            config.default_agent = string(v, "defaultAgent")?;
        }
        if let Some(v) = scalar(root, "sessionTimeout") {
            match duration_allowing_negative(v, "sessionTimeout")? {
                Some(d) if d > Duration::ZERO => config.session_timeout = d,
                // Go's Validate already states this rule; its merge guard used
                // to discard the value before Validate could see it, so a
                // config that disabled a timeout silently ran with the default.
                // Both sides now reject it.
                _ => {
                    return Err(ConfigError::Parse(non_positive_duration_message(
                        "sessionTimeout",
                        "15m",
                    )));
                }
            }
        }
        if let Some(v) = scalar(root, "sessionMaxLifetime") {
            match duration_allowing_negative(v, "sessionMaxLifetime")? {
                Some(d) if d > Duration::ZERO => config.session_max_lifetime = d,
                // Go's Validate already states this rule; its merge guard used
                // to discard the value before Validate could see it, so a
                // config that disabled a timeout silently ran with the default.
                // Both sides now reject it.
                _ => {
                    return Err(ConfigError::Parse(non_positive_duration_message(
                        "sessionMaxLifetime",
                        "8h",
                    )));
                }
            }
        }
        if let Some(v) = scalar(root, "authMethod") {
            config.auth_method = AuthMethod::parse(&string(v, "authMethod")?)?;
            auth_method_explicit = true;
        }
        if let Some(v) = scalar(root, "useTouchID") {
            config.use_touch_id = Some(boolean(v, "useTouchID")?);
        }
        config.default_profile = profiles.default_profile.unwrap_or_default();
        config.profiles = profiles.profiles.map(|profiles| {
            profiles
                .into_iter()
                .map(|(name, profile)| {
                    (
                        name,
                        Profile {
                            vault_path: profile.vault_path(),
                        },
                    )
                })
                .collect()
        });
        if auth_method_explicit {
            config.use_touch_id = Some(config.auth_method == AuthMethod::Touchid);
        } else if config.use_touch_id.is_none() {
            config.use_touch_id = Some(false);
        }
        if let Some(v) = root.get(key("agents")) {
            merge_agents(&mut config, v)?;
        }
        if let Some(v) = root.get(key("vault")) {
            config.vault = Some(parse_vault(v, config.auth_method)?);
        }
        if let Some(v) = root.get(key("git")) {
            config.git = Some(parse_git(v)?);
        }
        if let Some(v) = root.get(key("mcp")) {
            let mcp = parse_mcp(v)?;
            if mcp.bind.is_empty() {
                return Err(ConfigError::Invalid("mcp.bind must not be empty".into()));
            }
            config.mcp = Some(mcp);
        }
        if let Some(v) = root.get(key("update")) {
            config.update = Some(parse_update(v)?);
        }
        if let Some(v) = root.get(key("clipboard")) {
            config.clipboard = Some(parse_clipboard(v)?);
        }
        if config.default_agent.is_empty() {
            config.default_agent = DEFAULT_AGENT.into();
        }
        config
            .agents
            .entry(config.default_agent.clone())
            .or_insert_with(AgentProfile::default);
        Ok(config)
    }

    /// Returns the exact canonical writer bytes used by this Rust slice.
    pub fn to_yaml_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let mut out = String::new();
        if !self.agents.is_empty() {
            out.push_str("agents:\n");
            for (name, profile) in yaml_entries(&self.agents) {
                out.push_str(&format!("    {}:\n", yaml_scalar(name)?));
                write_agent(&mut out, name, profile)?;
            }
        }
        if let Some(vault) = &self.vault {
            write_vault(&mut out, vault)?;
        }
        if let Some(git) = &self.git {
            write_git(&mut out, git)?;
        }
        if let Some(mcp) = &self.mcp {
            write_mcp(&mut out, mcp)?;
        }
        if let Some(update) = &self.update {
            write_update(&mut out, update)?;
        }
        if let Some(clipboard) = &self.clipboard {
            write_clipboard(&mut out, clipboard)?;
        }
        if !self.vault_dir.is_empty() {
            out.push_str(&format!("vaultDir: {}\n", yaml_scalar(&self.vault_dir)?));
        }
        if !self.default_agent.is_empty() {
            out.push_str(&format!(
                "defaultAgent: {}\n",
                yaml_scalar(&self.default_agent)?
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
                out.push_str(&format!("    {}:", yaml_scalar(name)?));
                if profile.vault_path.is_empty() {
                    out.push_str(" {}\n");
                } else {
                    out.push('\n');
                    out.push_str("        vault: ");
                    out.push_str(&yaml_scalar(&profile.vault_path)?);
                    out.push('\n');
                }
            }
        }
        if !self.default_profile.is_empty() {
            out.push_str(&format!(
                "defaultProfile: {}\n",
                yaml_scalar(&self.default_profile)?
            ));
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
        let tmp = path.with_extension("yaml.tmp");
        write_private(&tmp, &bytes)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
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
    options.write(true).create(true).truncate(true);
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
fn key(value: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::String(value.into())
}
fn mapping(value: &serde_yaml_ng::Value) -> Result<&serde_yaml_ng::Mapping, ConfigError> {
    value
        .as_mapping()
        .ok_or_else(|| ConfigError::Parse("top-level YAML document must be a mapping".into()))
}
fn scalar<'a>(map: &'a serde_yaml_ng::Mapping, name: &str) -> Option<&'a serde_yaml_ng::Value> {
    map.get(key(name))
}
fn string(value: &serde_yaml_ng::Value, field: &str) -> Result<String, ConfigError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ConfigError::Parse(format!("{field} must be a string")))
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
/// value.
///
/// The offending value is deliberately not interpolated: Go reaches this point
/// with a parsed `time.Duration` and would render `-5m0s` where Rust still has
/// the scalar text `-5m`. The field name and the default are what the operator
/// needs.
#[must_use]
pub fn non_positive_duration_message(field: &str, default: &str) -> String {
    format!(
        "{field}: must be greater than 0 (default: {default}, configure {field} in config.yaml)"
    )
}

/// Like [`duration`], but reports a syntactically valid non-positive duration
/// as `Ok(None)` instead of an error.
///
/// Go's YAML decoder parses `-5m` into a negative Duration which the merge then
/// drops. Rust's Duration is unsigned, so the sign is detected in the text.
fn duration_allowing_negative(
    value: &serde_yaml_ng::Value,
    field: &str,
) -> Result<Option<Duration>, ConfigError> {
    if let Some(number) = value.as_i64() {
        if number < 0 {
            return Ok(None);
        }
        return u64::try_from(number)
            .map(Duration::from_nanos)
            .map(Some)
            .map_err(|_| ConfigError::Parse(format!("{field} has a negative duration")));
    }
    let text = string(value, field)?;
    let nanos = parse_duration_nanos(&text)
        .ok_or_else(|| ConfigError::Parse(format!("{field} has invalid duration {text:?}")))?;
    if nanos < 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_nanos(nanos as u64)))
}

fn boolean(value: &serde_yaml_ng::Value, field: &str) -> Result<bool, ConfigError> {
    if let Some(flag) = value.as_bool() {
        return Ok(flag);
    }
    if let Some(text) = value.as_str() {
        match text.to_ascii_lowercase().as_str() {
            "yes" | "on" => return Ok(true),
            "no" | "off" => return Ok(false),
            _ => {}
        }
    }
    Err(ConfigError::Parse(format!("{field} must be a boolean")))
}
fn integer(value: &serde_yaml_ng::Value, field: &str) -> Result<i64, ConfigError> {
    value
        .as_i64()
        .ok_or_else(|| ConfigError::Parse(format!("{field} must be an integer")))
}
fn duration(value: &serde_yaml_ng::Value, field: &str) -> Result<Duration, ConfigError> {
    if let Some(number) = value.as_i64() {
        return u64::try_from(number)
            .map(Duration::from_nanos)
            .map_err(|_| ConfigError::Parse(format!("{field} has a negative duration")));
    }
    let text = string(value, field)?;
    let nanos = parse_duration_nanos(&text)
        .ok_or_else(|| ConfigError::Parse(format!("{field} has invalid duration {text:?}")))?;
    if nanos < 0 {
        return Err(ConfigError::Parse(format!(
            "{field} has a negative duration"
        )));
    }
    Ok(Duration::from_nanos(nanos as u64))
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
            let digits = &fraction[..fraction.len().min(9)];
            let value = digits.parse::<i128>().ok()?;
            value.checked_mul(multiplier)? / 10i128.pow(digits.len() as u32)
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
fn format_duration(value: Duration) -> String {
    let secs = value.as_secs();
    let nanos = value.subsec_nanos();
    if nanos == 0 {
        if secs.is_multiple_of(3600) {
            return format!("{}h0m0s", secs / 3600);
        }
        if secs.is_multiple_of(60) {
            return format!("{}m0s", secs / 60);
        }
        return format!("{secs}s");
    }
    format!("{}.{:09}s", secs, nanos)
}

// Decode string-typed YAML fields directly from the source events. Converting
// Value::Number/Bool back to strings loses Go's lexical scalar representation.
#[derive(Deserialize)]
struct ProfileFields {
    #[serde(rename = "defaultProfile")]
    default_profile: Option<String>,
    #[serde(default, deserialize_with = "optional_unique_map")]
    profiles: Option<BTreeMap<String, ProfileYaml>>,
    #[serde(flatten, deserialize_with = "unique_map")]
    fields: BTreeMap<String, serde_yaml_ng::Value>,
}

#[derive(Deserialize)]
struct ProfileYaml {
    vault: Option<String>,
    #[serde(rename = "<<")]
    merge: Option<Box<ProfileYaml>>,
}

impl ProfileYaml {
    fn vault_path(self) -> String {
        self.vault.unwrap_or_else(|| {
            self.merge
                .map_or_else(String::new, |profile| profile.vault_path())
        })
    }
}

fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a mapping with unique keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(serde::de::Error::custom("duplicate mapping key"));
                }
                values.insert(key, map.next_value()?);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

fn optional_unique_map<'de, D, T>(deserializer: D) -> Result<Option<BTreeMap<String, T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    struct Map<T>(
        #[serde(
            deserialize_with = "unique_map",
            bound(deserialize = "T: Deserialize<'de>")
        )]
        BTreeMap<String, T>,
    );
    Option::<Map<T>>::deserialize(deserializer).map(|value| value.map(|map| map.0))
}

/// Applies a tier preset to a loaded agent profile, mirroring Go's
/// `config.ApplyTierPreset`.
///
/// `tier::AgentProfile` carries `Option<bool>` like Go's `*bool`, while the
/// loaded profile carries plain `bool`; an absent preset field means `false`,
/// exactly as Go's `BoolPtr(p != nil && *p)` does. An unknown tier changes
/// nothing, and the tier name is still recorded by the caller.
fn apply_tier_preset_to_profile(profile: &mut AgentProfile, tier: &str) -> bool {
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

fn merge_agents(config: &mut Config, value: &serde_yaml_ng::Value) -> Result<(), ConfigError> {
    let agents = mapping(value)?;
    for (name, value) in agents {
        let name = name
            .as_str()
            .ok_or_else(|| ConfigError::Parse("agent name must be a string".into()))?;
        let fields = mapping(value)?;
        let mut profile = config
            .agents
            .get(name)
            .cloned()
            .unwrap_or_else(AgentProfile::default);
        if !fields.contains_key(key("tier")) && !fields.contains_key(key("exposeValueTools")) {
            profile.expose_value_tools = true;
        }
        if let Some(v) = fields.get(key("tier")) {
            let tier = string(v, "tier")?;
            // The preset is applied before the explicit fields below, so an
            // explicitly written permission still overrides what the tier
            // grants. Go does the same, in the same order. Without this the
            // tier name was recorded but nothing it implies took effect, so a
            // `tier: standard` agent ran without requiring approval.
            apply_tier_preset_to_profile(&mut profile, &tier);
            profile.tier = Some(tier);
        }
        if let Some(v) = fields.get(key("approvalMode")) {
            profile.approval_mode = Some(string(v, "approvalMode")?);
        }
        if let Some(v) = fields.get(key("allowedPaths")) {
            profile.allowed_paths = string_list(v, "allowedPaths")?;
        }
        if let Some(v) = fields.get(key("redactFields")) {
            profile.redact_fields = string_list(v, "redactFields")?;
        }
        macro_rules! bool_field {
            ($key:literal, $field:ident) => {
                if let Some(v) = fields.get(key($key)) {
                    profile.$field = boolean(v, $key)?;
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
        if let Some(v) = fields.get(key("approvalTimeout")) {
            profile.approval_timeout = duration(v, "approvalTimeout")?;
        }
        if let Some(v) = fields.get(key("allowed_tools")) {
            profile.allowed_tools = string_list(v, "allowed_tools")?;
        }
        if let Some(v) = fields.get(key("max_reads_per_hour")) {
            profile.max_reads_per_hour = integer(v, "max_reads_per_hour")?;
        }
        if let Some(v) = fields.get(key("max_reads_per_day")) {
            profile.max_reads_per_day = integer(v, "max_reads_per_day")?;
        }
        if let Some(v) = fields.get(key("max_secrets_in_session")) {
            profile.max_secrets_in_session = integer(v, "max_secrets_in_session")?;
        }
        if let Some(v) = fields.get(key("allowedEnvVars")) {
            profile.allowed_env_vars = string_list(v, "allowedEnvVars")?;
        }
        if let Some(v) = fields.get(key("allowedExecutables")) {
            profile.allowed_executables = string_list(v, "allowedExecutables")?;
        }
        if let Some(v) = fields.get(key("promptInjectionMode")) {
            profile.prompt_injection_mode = string(v, "promptInjectionMode")?;
        }
        if let Some(v) = fields.get(key("skillPath")) {
            profile.skill_path = string(v, "skillPath")?;
        }
        if let Some(v) = fields.get(key("skillVersion")) {
            profile.skill_version = string(v, "skillVersion")?;
        }
        if fields.contains_key(key("requireApproval")) && !fields.contains_key(key("approvalMode"))
        {
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
fn string_list(value: &serde_yaml_ng::Value, field: &str) -> Result<Vec<String>, ConfigError> {
    // A key that is present but null is an explicitly empty list, not an
    // error. Go does this for every list field, and it is how YAML expresses
    // "this setting exists and is deliberately nothing" — which for an
    // allowlist is a meaningful, restrictive statement rather than an absence.
    if value.is_null() {
        return Ok(Vec::new());
    }
    value
        .as_sequence()
        .ok_or_else(|| ConfigError::Parse(format!("{field} must be a sequence")))?
        .iter()
        .map(|v| string(v, field))
        .collect()
}

fn parse_vault(value: &serde_yaml_ng::Value, auth: AuthMethod) -> Result<VaultConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = VaultConfig {
        auth_method: auth,
        search_index: true,
        scrypt_work_factor: 18,
        auto_heal_zero_key: true,
        format_version: 1,
        ..VaultConfig::default()
    };
    if let Some(v) = map.get(key("path")) {
        out.path = string(v, "vault.path")?;
    }
    if let Some(v) = map.get(key("default_recipients")) {
        out.default_recipients = string_list(v, "default_recipients")?;
    }
    if let Some(v) = map.get(key("confirm_remove")) {
        out.confirm_remove = boolean(v, "confirm_remove")?;
    }
    if let Some(v) = map.get(key("authMethod")) {
        out.auth_method = AuthMethod::parse(&string(v, "vault.authMethod")?)?;
    }
    if let Some(v) = map.get(key("useTouchID")) {
        out.use_touch_id = boolean(v, "vault.useTouchID")?;
    }
    if let Some(v) = map.get(key("legacy_mode")) {
        out.legacy_mode = Some(boolean(v, "legacy_mode")?);
    }
    if let Some(v) = map.get(key("search_index")) {
        out.search_index = boolean(v, "search_index")?;
    }
    if let Some(v) = map.get(key("search_workers")) {
        out.search_workers = integer(v, "search_workers")?;
    }
    if let Some(v) = map.get(key("search_index_cache")) {
        out.search_index_cache = boolean(v, "search_index_cache")?;
    }
    if let Some(v) = map.get(key("config_cache_entries")) {
        out.config_cache_entries = integer(v, "config_cache_entries")?;
    }
    if let Some(v) = map.get(key("pseudonymize_paths")) {
        out.pseudonymize_paths = boolean(v, "pseudonymize_paths")?;
    }
    if let Some(v) = map.get(key("scrypt_work_factor")) {
        out.scrypt_work_factor = integer(v, "scrypt_work_factor")?;
    }
    if let Some(v) = map.get(key("auto_migrate_kdf")) {
        out.auto_migrate_kdf = boolean(v, "auto_migrate_kdf")?;
    }
    if let Some(v) = map.get(key("auto_heal_zero_key")) {
        out.auto_heal_zero_key = boolean(v, "auto_heal_zero_key")?;
    }
    if let Some(v) = map.get(key("format_version")) {
        out.format_version = integer(v, "format_version")?;
    }
    Ok(out)
}
fn parse_git(value: &serde_yaml_ng::Value) -> Result<GitConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = GitConfig::default();
    if let Some(v) = map.get(key("auto_push")) {
        out.auto_push = boolean(v, "auto_push")?;
    }
    if let Some(v) = map.get(key("auto_pull")) {
        out.auto_pull = boolean(v, "auto_pull")?;
    }
    if let Some(v) = map.get(key("auto_pull_interval")) {
        out.auto_pull_interval = duration(v, "auto_pull_interval")?;
    }
    if let Some(v) = map.get(key("commit_template")) {
        out.commit_template = string(v, "commit_template")?;
    }
    Ok(out)
}
fn parse_mcp(value: &serde_yaml_ng::Value) -> Result<McpConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = McpConfig::default();
    if let Some(v) = map.get(key("port")) {
        out.port = integer(v, "port")?;
    }
    if let Some(v) = map.get(key("bind")) {
        out.bind = string(v, "bind")?;
    }
    if let Some(v) = map.get(key("stdio")) {
        out.stdio = boolean(v, "stdio")?;
    }
    if let Some(v) = map.get(key("httpTokenFile")) {
        out.http_token_file = string(v, "httpTokenFile")?;
    }
    for (k, d) in [
        ("read_header_timeout", &mut out.read_header_timeout),
        ("read_timeout", &mut out.read_timeout),
        ("write_timeout", &mut out.write_timeout),
        ("shutdown_timeout", &mut out.shutdown_timeout),
        ("approval_timeout", &mut out.approval_timeout),
    ] {
        if let Some(v) = map.get(key(k)) {
            *d = duration(v, k)?;
        }
    }
    if let Some(v) = map.get(key("rate_limit")) {
        out.rate_limit = integer(v, "rate_limit")?;
    }
    if let Some(v) = map.get(key("metrics_auth_required")) {
        out.metrics_auth_required = boolean(v, "metrics_auth_required")?;
    }
    Ok(out)
}
fn parse_update(value: &serde_yaml_ng::Value) -> Result<UpdateConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = UpdateConfig::default();
    if let Some(v) = map.get(key("cache_ttl")) {
        out.cache_ttl = duration(v, "cache_ttl")?;
    }
    Ok(out)
}
fn parse_clipboard(value: &serde_yaml_ng::Value) -> Result<ClipboardConfig, ConfigError> {
    let map = mapping(value)?;
    let mut out = ClipboardConfig::default();
    if let Some(v) = map.get(key("auto_clear_duration")) {
        out.auto_clear_duration = integer(v, "auto_clear_duration")?;
    }
    if let Some(v) = map.get(key("copyByDefault")) {
        out.copy_by_default = boolean(v, "copyByDefault")?;
    } else if let Some(v) = map.get(key("printByDefault")) {
        out.copy_by_default = boolean(v, "printByDefault")?;
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

fn yaml_scalar(value: &str) -> Result<String, ConfigError> {
    // Go's yaml.v3 quotes strings that would otherwise decode as another scalar.
    let resolved = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(value);
    let legacy_bool = matches!(
        value,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    );
    if matches!(
        resolved,
        Ok(serde_yaml_ng::Value::Number(_)
            | serde_yaml_ng::Value::Bool(_)
            | serde_yaml_ng::Value::Null)
    ) || value.replace('_', "").parse::<f64>().is_ok()
        || legacy_bool
        || is_base60(value)
    {
        return serde_json::to_string(value)
            .map_err(|error| ConfigError::Serialize(error.to_string()));
    }
    serde_yaml_ng::to_string(&serde_yaml_ng::Value::String(value.into()))
        .map(|v| v.trim_end().to_owned())
        .map_err(|e| ConfigError::Serialize(e.to_string()))
}
fn is_base60(value: &str) -> bool {
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, None), |(w, f)| (w, Some(f)));
    if fraction.is_some_and(|f| !f.bytes().all(|b| b.is_ascii_digit() || b == b'_')) {
        return false;
    }
    let mut parts = whole.split(':');
    let first = parts.next().unwrap_or_default();
    if !first.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !first.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return false;
    }
    let mut count = 0;
    for part in parts {
        let valid = match part.as_bytes() {
            [digit] => digit.is_ascii_digit(),
            [tens, digit] => *tens >= b'0' && *tens <= b'5' && digit.is_ascii_digit(),
            _ => false,
        };
        if !valid {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn write_agent(out: &mut String, name: &str, p: &AgentProfile) -> Result<(), ConfigError> {
    if let Some(v) = &p.approval_mode {
        out.push_str(&format!("        approvalMode: {}\n", yaml_scalar(v)?));
    }
    if !p.allowed_paths.is_empty() {
        out.push_str("        allowedPaths:\n");
        for v in &p.allowed_paths {
            out.push_str(&format!("            - {}\n", yaml_scalar(v)?));
        }
    }
    if !p.redact_fields.is_empty() {
        out.push_str("        redactFields:\n");
        for v in &p.redact_fields {
            out.push_str(&format!("            - {}\n", yaml_scalar(v)?));
        }
    }
    let builtin = matches!(
        name,
        "default" | "claude-code" | "codex" | "hermes" | "openclaw" | "opencode"
    );
    out.push_str(&format!("        canWrite: {}\n", p.can_write));
    if builtin || p.can_run_commands {
        out.push_str(&format!("        canRunCommands: {}\n", p.can_run_commands));
    }
    out.push_str(&format!(
        "        exposeValueTools: {}\n",
        p.expose_value_tools
    ));
    if p.expose_payment_values {
        out.push_str("        exposePaymentValues: true\n");
    }
    if p.require_approval || p.approval_mode.as_deref() == Some("none") {
        out.push_str(&format!(
            "        requireApproval: {}\n",
            p.require_approval
        ));
    }
    if builtin {
        out.push_str(&format!("        autoUnseal: {}\n", p.auto_unseal));
    }
    if !p.skill_path.is_empty() {
        out.push_str(&format!(
            "        skillPath: {}\n",
            yaml_scalar(&p.skill_path)?
        ));
    }
    Ok(())
}
fn write_vault(out: &mut String, v: &VaultConfig) -> Result<(), ConfigError> {
    out.push_str("vault:\n");
    if !v.path.is_empty() {
        out.push_str(&format!("    path: {}\n", yaml_scalar(&v.path)?));
    }
    if !v.default_recipients.is_empty() {
        out.push_str("    default_recipients:\n");
        for r in &v.default_recipients {
            out.push_str(&format!("        - {}\n", yaml_scalar(r)?));
        }
    }
    if v.confirm_remove {
        out.push_str("    confirm_remove: true\n");
    }
    Ok(())
}
fn write_git(out: &mut String, v: &GitConfig) -> Result<(), ConfigError> {
    out.push_str("git:\n");
    if !v.auto_push {
        out.push_str("    auto_push: false\n");
    }
    if !v.auto_pull {
        out.push_str("    auto_pull: false\n");
    }
    if v.auto_pull_interval > Duration::ZERO {
        out.push_str(&format!(
            "    auto_pull_interval: {}\n",
            format_duration(v.auto_pull_interval)
        ));
    }
    if !v.commit_template.is_empty() {
        out.push_str(&format!(
            "    commit_template: {}\n",
            yaml_scalar(&v.commit_template)?
        ));
    }
    Ok(())
}
fn write_mcp(out: &mut String, v: &McpConfig) -> Result<(), ConfigError> {
    out.push_str("mcp:\n");
    out.push_str(&format!("    port: {}\n", v.port));
    out.push_str(&format!("    bind: {}\n", yaml_scalar(&v.bind)?));
    if v.stdio {
        out.push_str("    stdio: true\n");
    }
    out.push_str(&format!(
        "    httpTokenFile: {}\n",
        yaml_scalar(&v.http_token_file)?
    ));
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
    out.push_str(&format!(
        "    metrics_auth_required: {}\n",
        v.metrics_auth_required
    ));
    Ok(())
}
fn write_update(out: &mut String, v: &UpdateConfig) -> Result<(), ConfigError> {
    out.push_str("update:\n");
    if v.cache_ttl > Duration::ZERO {
        out.push_str(&format!(
            "    cache_ttl: {}\n",
            format_duration(v.cache_ttl)
        ));
    }
    Ok(())
}
fn write_clipboard(out: &mut String, v: &ClipboardConfig) -> Result<(), ConfigError> {
    out.push_str("clipboard:\n");
    if v.auto_clear_duration != 0 {
        out.push_str(&format!(
            "    auto_clear_duration: {}\n",
            v.auto_clear_duration
        ));
    }
    if !v.copy_by_default {
        out.push_str("    copyByDefault: false\n");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
