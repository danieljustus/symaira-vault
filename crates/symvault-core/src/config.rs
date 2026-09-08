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

impl PathResolver {
    #[must_use]
    pub fn new() -> Self {
        let home = home_dir();
        let legacy = home.join(LEGACY_DIR);
        let xdg_data = xdg_home("XDG_DATA_HOME", ".local/share").join(APP_NAME);
        let xdg_config = xdg_home("XDG_CONFIG_HOME", ".config").join(APP_NAME);
        let cache = xdg_home("XDG_CACHE_HOME", ".cache").join(APP_NAME);
        let legacy_exists = legacy.is_dir();
        let xdg_exists = xdg_data.is_dir();
        let (config_dir, mut data_dir, migrated) = if legacy_exists && !xdg_exists {
            (legacy.clone(), legacy.clone(), false)
        } else {
            (xdg_config, xdg_data, legacy_exists && xdg_exists)
        };
        match env::var("SYMVAULT_VAULT") {
            Ok(value) if !value.trim().is_empty() => {
                data_dir = expand_tilde(value.trim()).unwrap_or(data_dir);
            }
            _ => {}
        }
        Self {
            config_dir,
            data_dir,
            cache_dir: cache,
            legacy_dir: legacy_exists.then_some(legacy),
            migrated,
        }
    }

    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        xdg_home("XDG_CONFIG_HOME", ".config")
            .join(APP_NAME)
            .join("config.yaml")
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
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_slice(bytes)
            .map_err(|error| ConfigError::Parse(error.to_string()))?;
        let root = mapping(&value)?;
        let mut config = Self::default();
        if let Some(v) = scalar(root, "vaultDir") {
            config.vault_dir = string(v, "vaultDir")?;
        }
        if let Some(v) = scalar(root, "defaultAgent") {
            config.default_agent = string(v, "defaultAgent")?;
        }
        if let Some(v) = scalar(root, "sessionTimeout") {
            let d = duration(v, "sessionTimeout")?;
            if d > Duration::ZERO {
                config.session_timeout = d;
            }
        }
        if let Some(v) = scalar(root, "sessionMaxLifetime") {
            let d = duration(v, "sessionMaxLifetime")?;
            if d > Duration::ZERO {
                config.session_max_lifetime = d;
            }
        }
        if let Some(v) = scalar(root, "authMethod") {
            config.auth_method = AuthMethod::parse(&string(v, "authMethod")?)?;
        }
        if let Some(v) = scalar(root, "useTouchID") {
            config.use_touch_id = Some(boolean(v, "useTouchID")?);
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
            .or_insert_with(AgentProfile::deny_all);
        Ok(config)
    }

    /// Returns the exact canonical writer bytes used by this Rust slice.
    pub fn to_yaml_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let mut out = String::new();
        if !self.agents.is_empty() {
            out.push_str("agents:\n");
            for (name, profile) in &self.agents {
                out.push_str(&format!("    {}:\n", yaml_scalar(name)?));
                write_agent(&mut out, profile)?;
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
        if let Some(use_touch_id) = self.use_touch_id {
            out.push_str(&format!("useTouchID: {use_touch_id}\n"));
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
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("yaml.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_default()
}
fn xdg_home(var: &str, fallback: &str) -> PathBuf {
    env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(fallback))
}
fn expand_tilde(value: &str) -> Option<PathBuf> {
    value
        .strip_prefix("~/")
        .map(|rest| home_dir().join(rest))
        .or_else(|| (value == "~").then(home_dir))
        .or_else(|| Some(PathBuf::from(value)))
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
fn boolean(value: &serde_yaml_ng::Value, field: &str) -> Result<bool, ConfigError> {
    value
        .as_bool()
        .ok_or_else(|| ConfigError::Parse(format!("{field} must be a boolean")))
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
    parse_duration(&text)
        .ok_or_else(|| ConfigError::Parse(format!("{field} has invalid duration {text:?}")))
}
fn parse_duration(text: &str) -> Option<Duration> {
    let mut total = 0u128;
    let mut number = String::new();
    for ch in text.trim().chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        if number.is_empty() {
            return None;
        }
        let n: u128 = number.parse().ok()?;
        number.clear();
        let unit = match ch {
            'h' => 3_600_000_000_000u128,
            'm' => 60_000_000_000,
            's' => 1_000_000_000,
            'u' => 1_000,
            'n' => 1,
            _ => return None,
        };
        total = total.checked_add(n.checked_mul(unit)?)?;
    }
    if !number.is_empty() {
        total = total.checked_add(number.parse::<u128>().ok()?.checked_mul(1_000_000_000)?)?;
    }
    u64::try_from(total).ok().map(Duration::from_nanos)
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
            .unwrap_or_else(AgentProfile::deny_all);
        if let Some(v) = fields.get(key("tier")) {
            profile.tier = Some(string(v, "tier")?);
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

fn yaml_scalar(value: &str) -> Result<String, ConfigError> {
    serde_yaml_ng::to_string(&serde_yaml_ng::Value::String(value.into()))
        .map(|v| v.trim_end().to_owned())
        .map_err(|e| ConfigError::Serialize(e.to_string()))
}
fn write_agent(out: &mut String, p: &AgentProfile) -> Result<(), ConfigError> {
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
    for (k, v) in [
        ("canWrite", p.can_write),
        ("canRunCommands", p.can_run_commands),
        ("exposeValueTools", p.expose_value_tools),
        ("autoUnseal", p.auto_unseal),
    ] {
        out.push_str(&format!("        {k}: {v}\n"));
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
    if v.port != 0 {
        out.push_str(&format!("    port: {}\n", v.port));
    }
    if !v.bind.is_empty() {
        out.push_str(&format!("    bind: {}\n", yaml_scalar(&v.bind)?));
    }
    if v.stdio {
        out.push_str("    stdio: true\n");
    }
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
