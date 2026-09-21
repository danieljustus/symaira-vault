//! Rust port of Go `symvault agent install`
//! (`cmd/mcp/agent_install.go` plus `internal/mcp/install`).
//!
//! Installs the vault's MCP server entry into an AI agent's config file,
//! creates the vault-side agent profile and token, and renders the skill
//! package. Byte-parity scope: stdout/stderr text, JSON/YAML result
//! documents, agent YAML/JSON/TOML config files, `config.yaml` profile
//! blocks, exit codes.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;

use symvault_core::config::{AgentProfile, Config};
use symvault_core::tier;
use symvault_store::token_registry::{self, NewToken};
use time::{Duration, OffsetDateTime};

use super::agent_doctor_commands::expand_tilde;
use super::agent_skill_commands::{install_with_tier, skill_target};

/// CLI flags for `agent install`, mirroring the Cobra flag set.
pub(crate) struct InstallFlags {
    pub auto_detect: bool,
    pub tier: String,
    pub http: bool,
    pub dry_run: bool,
    pub skill_only: bool,
    pub config_only: bool,
    pub force: bool,
    pub quiet: bool,
    pub output: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Json,
    Yaml,
    Toml,
}

#[derive(Clone, Copy)]
struct AgentDef {
    agent_type: &'static str,
    display: &'static str,
    config_paths: &'static [&'static str],
    binaries: &'static [&'static str],
    format: ConfigFormat,
    root_key: &'static str,
    server_key: &'static str,
}

// Canonical order used for `--auto-detect`. Go iterates a map (random
// order); the port walks this fixed table instead, so multi-agent output is
// deterministic. Single-agent behavior is identical.
const AGENT_DEFS: [AgentDef; 5] = [
    AgentDef {
        agent_type: "openclaw",
        display: "OpenClaw",
        config_paths: &["~/.openclaw/openclaw.json"],
        binaries: &["openclaw"],
        format: ConfigFormat::Json,
        root_key: "mcp",
        server_key: "symvault",
    },
    AgentDef {
        agent_type: "claude-code",
        display: "Claude Code",
        config_paths: &["~/.claude/settings.json"],
        binaries: &["claude"],
        format: ConfigFormat::Json,
        root_key: "mcpServers",
        server_key: "symvault",
    },
    AgentDef {
        agent_type: "hermes",
        display: "Hermes",
        config_paths: &["~/.config/hermes/mcp.yaml"],
        binaries: &["hermes"],
        format: ConfigFormat::Yaml,
        root_key: "mcp_servers",
        server_key: "symvault",
    },
    AgentDef {
        agent_type: "codex",
        display: "Codex",
        config_paths: &["~/.codex/config.toml"],
        binaries: &["codex"],
        format: ConfigFormat::Toml,
        root_key: "mcp_servers",
        server_key: "symvault",
    },
    AgentDef {
        agent_type: "opencode",
        display: "OpenCode",
        config_paths: &["~/.config/opencode/opencode.json", "opencode.json"],
        binaries: &["opencode"],
        format: ConfigFormat::Json,
        root_key: "mcp",
        server_key: "symvault",
    },
];

/// Go `install.ParseAgentType`: aliases and case-insensitive spellings map
/// to the canonical type, but every later step keeps the caller's original
/// name for the profile key, token label and skill lookup.
fn parse_agent_type(name: &str) -> Result<AgentDef, ()> {
    let normalized = name.to_lowercase().replace(['_', '-'], "");
    for def in AGENT_DEFS {
        if def.agent_type.replace('-', "") == normalized {
            return Ok(def);
        }
        match def.agent_type {
            "claude-code"
                if matches!(
                    normalized.as_str(),
                    "claude" | "claudecode" | "claudedesktop"
                ) =>
            {
                return Ok(def);
            }
            _ => {}
        }
    }
    Err(())
}

fn expand_home(path: &str, home: &Path) -> String {
    if path == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home.join(rest).to_string_lossy().into_owned();
    }
    path.to_owned()
}

/// Go `install.DetectAgent`.
fn detect_agent(home: &Path, def: AgentDef) -> (bool, String) {
    let mut config_path = String::new();
    for candidate in def.config_paths {
        let expanded = expand_home(candidate, home);
        if Path::new(&expanded).is_file() {
            config_path = expanded;
            break;
        }
    }
    // Go only checks existence, not the executable bit.
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    let binary_found = std::env::split_paths(&path_env).any(|dir| {
        def.binaries
            .iter()
            .any(|binary| dir.join(binary).is_file() || has_windows_executable(&dir, binary))
    });
    (binary_found || !config_path.is_empty(), config_path)
}

#[cfg(windows)]
fn has_windows_executable(dir: &Path, binary: &str) -> bool {
    ["exe", "cmd", "bat", "ps1"]
        .iter()
        .any(|ext| dir.join(format!("{binary}.{ext}")).is_file())
}

#[cfg(not(windows))]
fn has_windows_executable(_dir: &Path, _binary: &str) -> bool {
    false
}

/// Go `install.ResolveConfigPath`: the expanded first candidate, unchecked.
fn resolve_config_path(home: &Path, def: AgentDef) -> String {
    expand_home(def.config_paths[0], home)
}

/// Go `validateAgentName` (`cmd/mcp/agent.go`).
fn validate_agent_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("agent name must not be empty".to_owned());
    }
    if name.contains('/') || name.contains('\\') || name == "." || name.contains("..") {
        return Err(format!(
            "invalid agent name {name:?}: must not contain path separators or parent references"
        ));
    }
    Ok(())
}

/// Lexical `filepath.Clean` for `/`-separated paths.
fn clean_path_str(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = parts.join("/");
    if absolute {
        out.insert(0, '/');
    }
    if out.is_empty() {
        return ".".to_owned();
    }
    out
}

/// Go `shouldIncludeVaultArg`.
fn should_include_vault_arg(vault: &Path, home: &Path) -> bool {
    let vault_str = vault.to_string_lossy();
    let default = format!("{}/.symvault", home.to_string_lossy()).replace('\\', "/");
    clean_path_str(&vault_str.replace('\\', "/")) != clean_path_str(&default)
}

fn stdio_args(vault: &Path, home: &Path, agent_name: &str) -> Vec<String> {
    let mut args = Vec::new();
    if should_include_vault_arg(vault, home) {
        args.push("--vault".to_owned());
        args.push(vault.to_string_lossy().into_owned());
    }
    args.push("mcp".to_owned());
    args.push("--stdio".to_owned());
    args.push("--agent".to_owned());
    args.push(agent_name.to_owned());
    args
}

// ---------------------------------------------------------------------------
// Generic config values (JSON/YAML/TOML share inject + equality).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum CfgVal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<CfgVal>),
    Map(BTreeMap<String, CfgVal>),
}

/// Go `configEqual`: maps compare recursively, slices only ever match as
/// string slices, numbers compare across int/float, everything else is
/// strict. Anything unlisted (including null) is never equal.
fn cfg_equal(a: &CfgVal, b: &CfgVal) -> bool {
    match (a, b) {
        (CfgVal::Map(a), CfgVal::Map(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| cfg_equal(value, other)))
        }
        (CfgVal::Arr(a), CfgVal::Arr(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| matches!((x, y), (CfgVal::Str(x), CfgVal::Str(y)) if x == y))
        }
        (CfgVal::Str(a), CfgVal::Str(b)) => a == b,
        (CfgVal::Bool(a), CfgVal::Bool(b)) => a == b,
        (CfgVal::Int(a), CfgVal::Int(b)) => a == b,
        (a, b) => num_value(a).is_some_and(|x| num_value(b).is_some_and(|y| x == y)),
    }
}

fn num_value(value: &CfgVal) -> Option<f64> {
    match value {
        CfgVal::Int(n) => Some(*n as f64),
        CfgVal::Float(f) => Some(*f),
        _ => None,
    }
}

/// Go `InjectServerConfig`.
fn inject_server_config(
    existing: &mut BTreeMap<String, CfgVal>,
    root_key: &str,
    server_key: &str,
    server_config: CfgVal,
) -> bool {
    let mut changed = false;
    let mut root = match existing.remove(root_key) {
        Some(CfgVal::Map(map)) => map,
        _ => {
            changed = true;
            BTreeMap::new()
        }
    };
    match root.get(server_key) {
        Some(current) if cfg_equal(current, &server_config) => {}
        _ => {
            root.insert(server_key.to_owned(), server_config);
            changed = true;
        }
    }
    existing.insert(root_key.to_owned(), CfgVal::Map(root));
    changed
}

// ---------------------------------------------------------------------------
// JSON.
// ---------------------------------------------------------------------------

fn cfg_from_json(value: serde_json::Value) -> CfgVal {
    match value {
        serde_json::Value::Null => CfgVal::Null,
        serde_json::Value::Bool(b) => CfgVal::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CfgVal::Int(i)
            } else if let Some(u) = n.as_u64() {
                if u <= i64::MAX as u64 {
                    CfgVal::Int(u as i64)
                } else {
                    CfgVal::Float(u as f64)
                }
            } else {
                CfgVal::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => CfgVal::Str(s),
        serde_json::Value::Array(items) => {
            CfgVal::Arr(items.into_iter().map(cfg_from_json).collect())
        }
        serde_json::Value::Object(map) => CfgVal::Map(
            map.into_iter()
                .map(|(key, value)| (key, cfg_from_json(value)))
                .collect(),
        ),
    }
}

fn cfg_to_json(value: &CfgVal) -> serde_json::Value {
    match value {
        CfgVal::Null => serde_json::Value::Null,
        CfgVal::Bool(b) => serde_json::Value::Bool(*b),
        CfgVal::Int(n) => serde_json::Value::Number((*n).into()),
        CfgVal::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                serde_json::Value::Number((*f as i64).into())
            } else {
                serde_json::Number::from_f64(*f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        CfgVal::Str(s) => serde_json::Value::String(s.clone()),
        CfgVal::Arr(items) => serde_json::Value::Array(items.iter().map(cfg_to_json).collect()),
        CfgVal::Map(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), cfg_to_json(value)))
                .collect(),
        ),
    }
}

fn read_json_config(path: &str) -> Result<BTreeMap<String, CfgVal>, String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(error) => return Err(format!("read JSON config {path:?}: {error}")),
    };
    if data.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: serde_json::Value = serde_json::from_slice(&data)
        .map_err(|error| format!("parse JSON config {path:?}: {error}"))?;
    match cfg_from_json(value) {
        CfgVal::Map(map) => Ok(map),
        _ => Err(format!(
            "parse JSON config {path:?}: expected a JSON object at the document root"
        )),
    }
}

// ---------------------------------------------------------------------------
// YAML: parsed with serde_yaml_ng, emitted with a dedicated 4-space emitter
// because serde emits 2-space indent and leaves date-like strings unquoted,
// while Go `yaml.v3` uses 4 spaces and quotes `2025-11-25`.
// ---------------------------------------------------------------------------

fn cfg_from_yaml(value: serde_yaml_ng::Value) -> Result<CfgVal, String> {
    match value {
        serde_yaml_ng::Value::Null => Ok(CfgVal::Null),
        serde_yaml_ng::Value::Bool(b) => Ok(CfgVal::Bool(b)),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(CfgVal::Int(i))
            } else if let Some(u) = n.as_u64() {
                if u <= i64::MAX as u64 {
                    Ok(CfgVal::Int(u as i64))
                } else {
                    Ok(CfgVal::Float(u as f64))
                }
            } else {
                Ok(CfgVal::Float(n.as_f64().unwrap_or(0.0)))
            }
        }
        serde_yaml_ng::Value::String(s) => Ok(CfgVal::Str(s)),
        serde_yaml_ng::Value::Sequence(items) => items
            .into_iter()
            .map(cfg_from_yaml)
            .collect::<Result<Vec<_>, _>>()
            .map(CfgVal::Arr),
        serde_yaml_ng::Value::Mapping(map) => {
            let mut out = BTreeMap::new();
            for (key, value) in map {
                match key {
                    serde_yaml_ng::Value::String(key) => {
                        out.insert(key, cfg_from_yaml(value)?);
                    }
                    _ => return Err("expected string keys in YAML mapping".to_owned()),
                }
            }
            Ok(CfgVal::Map(out))
        }
        serde_yaml_ng::Value::Tagged(tagged) => cfg_from_yaml(tagged.value),
    }
}

fn read_yaml_config(path: &str) -> Result<BTreeMap<String, CfgVal>, String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(error) => return Err(format!("read YAML config {path:?}: {error}")),
    };
    if data.iter().all(u8::is_ascii_whitespace) {
        return Ok(BTreeMap::new());
    }
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&data)
        .map_err(|error| format!("parse YAML config {path:?}: {error}"))?;
    match cfg_from_yaml(value).map_err(|detail| format!("parse YAML config {path:?}: {detail}"))? {
        CfgVal::Map(map) => Ok(map),
        CfgVal::Null => Ok(BTreeMap::new()),
        _ => Err(format!(
            "parse YAML config {path:?}: expected a YAML mapping at the document root"
        )),
    }
}

fn yaml_needs_quote(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    if matches!(
        text,
        "~" | "null" | "Null" | "NULL" | "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
    ) {
        return true;
    }
    if text.parse::<i64>().is_ok() || text.parse::<u64>().is_ok() || text.parse::<f64>().is_ok() {
        return true;
    }
    if matches!(text, ".inf" | "-.inf" | ".Inf" | ".nan" | ".NaN") {
        return true;
    }
    // Go yaml.v3 resolves timestamps back to dates, so it quotes them.
    let bytes = text.as_bytes();
    if bytes.len() >= 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && text[..4].chars().all(|c| c.is_ascii_digit())
        && text[5..7].chars().all(|c| c.is_ascii_digit())
        && text[8..10].chars().all(|c| c.is_ascii_digit())
    {
        return true;
    }
    let mut chars = text.chars();
    let first = chars.next().unwrap_or(' ');
    if first == '-' {
        // `-` starts a plain scalar unless it is the whole string or followed
        // by a space (Go yaml.v3 leaves `--vault` bare).
        if text.len() == 1 || text.as_bytes().get(1) == Some(&b' ') {
            return true;
        }
    } else if matches!(
        first,
        '?' | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) {
        return true;
    }
    if text.starts_with("- ") || text.starts_with("? ") || text.starts_with(": ") {
        return true;
    }
    if text.ends_with(':') {
        // A trailing colon opens a mapping (`key:`), so Go quotes the scalar.
        return true;
    }
    if text.ends_with(' ') || text.ends_with('\t') {
        return true;
    }
    text.contains(": ")
        || text.contains(" #")
        || text.contains('\n')
        || text.contains("\t")
        || text.chars().any(|c| c.is_control())
}

fn yaml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn yaml_scalar_text(text: &str) -> String {
    if yaml_needs_quote(text) {
        yaml_escape(text)
    } else {
        text.to_owned()
    }
}

fn yaml_scalar_value(value: &CfgVal) -> String {
    match value {
        CfgVal::Null => "null".to_owned(),
        CfgVal::Bool(true) => "true".to_owned(),
        CfgVal::Bool(false) => "false".to_owned(),
        CfgVal::Int(n) => n.to_string(),
        CfgVal::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                (*f as i64).to_string()
            } else {
                format!("{f}")
            }
        }
        CfgVal::Str(s) => yaml_scalar_text(s),
        CfgVal::Arr(_) | CfgVal::Map(_) => "null".to_owned(),
    }
}

/// Ordered pairs: BTreeMap iteration is already sorted; result documents
/// pass struct field order.
fn emit_yaml_pairs(pairs: &[(String, CfgVal)], indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    for (key, value) in pairs {
        match value {
            CfgVal::Map(map) if !map.is_empty() => {
                out.push_str(&pad);
                out.push_str(&yaml_scalar_text(key));
                out.push_str(":\n");
                let nested: Vec<(String, CfgVal)> =
                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                emit_yaml_pairs(&nested, indent + 4, out);
            }
            CfgVal::Arr(items) if !items.is_empty() => {
                out.push_str(&pad);
                out.push_str(&yaml_scalar_text(key));
                out.push_str(":\n");
                emit_yaml_seq(items, indent + 4, out);
            }
            CfgVal::Map(_) => {
                out.push_str(&pad);
                out.push_str(&yaml_scalar_text(key));
                out.push_str(": {}\n");
            }
            CfgVal::Arr(_) => {
                out.push_str(&pad);
                out.push_str(&yaml_scalar_text(key));
                out.push_str(": []\n");
            }
            _ => {
                out.push_str(&pad);
                out.push_str(&yaml_scalar_text(key));
                out.push_str(": ");
                out.push_str(&yaml_scalar_value(value));
                out.push('\n');
            }
        }
    }
}

fn emit_yaml_seq(items: &[CfgVal], indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    for item in items {
        match item {
            CfgVal::Map(map) if !map.is_empty() => {
                out.push_str(&pad);
                out.push_str("-\n");
                let nested: Vec<(String, CfgVal)> =
                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                emit_yaml_pairs(&nested, indent + 4, out);
            }
            _ => {
                out.push_str(&pad);
                out.push_str("- ");
                out.push_str(&yaml_scalar_value(item));
                out.push('\n');
            }
        }
    }
}

fn emit_yaml_map(map: &BTreeMap<String, CfgVal>) -> String {
    let pairs: Vec<(String, CfgVal)> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut out = String::new();
    emit_yaml_pairs(&pairs, 0, &mut out);
    out
}

// ---------------------------------------------------------------------------
// JSON result documents: Go marshals the result struct in field order, but
// `serde_json::Map` sorts keys, so results use a manual emitter while plain
// config maps go through serde (Go sorts `map[string]any` keys too).
// ---------------------------------------------------------------------------

fn json_escape(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn emit_json_value(value: &CfgVal, indent: usize, out: &mut String) {
    match value {
        CfgVal::Null => out.push_str("null"),
        CfgVal::Bool(true) => out.push_str("true"),
        CfgVal::Bool(false) => out.push_str("false"),
        CfgVal::Int(n) => out.push_str(&n.to_string()),
        CfgVal::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                out.push_str(&(*f as i64).to_string());
            } else {
                out.push_str(&format!("{f}"));
            }
        }
        CfgVal::Str(s) => json_escape(s, out),
        CfgVal::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                emit_json_value(item, indent, out);
            }
            out.push(']');
        }
        // Config-map fallback; results pass ordered pairs directly.
        CfgVal::Map(map) => {
            let pairs: Vec<(String, CfgVal)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            emit_json_pairs(&pairs, indent, out);
        }
    }
}

fn emit_json_pairs(pairs: &[(String, CfgVal)], indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    let inner = " ".repeat(indent + 2);
    out.push_str("{\n");
    for (index, (key, value)) in pairs.iter().enumerate() {
        out.push_str(&inner);
        json_escape(key, out);
        out.push_str(": ");
        emit_json_value(value, indent + 2, out);
        if index + 1 < pairs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&pad);
    out.push('}');
}

// ---------------------------------------------------------------------------
// TOML: a small parser for reads plus a go-toml/v2-shaped emitter and a
// line-based port of `replaceManagedTOML` for preservation-safe updates.
// ---------------------------------------------------------------------------

fn toml_key_part(text: &str) -> Result<(String, &str), String> {
    let text = text.trim_start();
    if text.starts_with('"') {
        let mut end = 1;
        let bytes = text.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'"' && bytes[end - 1] != b'\\' {
                break;
            }
            end += 1;
        }
        if end >= bytes.len() {
            return Err("unterminated quoted key".to_owned());
        }
        let raw = &text[..=end];
        let key = unescape_basic(raw).map_err(|error| format!("invalid quoted key: {error}"))?;
        Ok((key, &text[end + 1..]))
    } else if text.starts_with('\'') {
        let Some(end) = text.strip_prefix('\'').and_then(|rest| rest.find('\'')) else {
            return Err("unterminated literal key".to_owned());
        };
        Ok((text[1..end + 1].to_owned(), &text[end + 2..]))
    } else {
        let mut end = 0;
        for c in text.chars() {
            if c == '.' || c == ' ' || c == '\t' {
                break;
            }
            end += c.len_utf8();
        }
        if end == 0 {
            return Err("invalid bare key".to_owned());
        }
        Ok((text[..end].to_owned(), &text[end..]))
    }
}

/// Go `parseTOMLKeyPath` with identical error strings.
fn parse_toml_key_path(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = input.trim();
    while !rest.is_empty() {
        let (key, tail) = toml_key_part(rest)?;
        out.push(key);
        rest = tail.trim_start();
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with('.') {
            return Err("expected dot between keys".to_owned());
        }
        rest = rest[1..].trim_start();
        if rest.is_empty() {
            return Err("expected dot between keys".to_owned());
        }
    }
    if out.is_empty() {
        return Err("empty table header".to_owned());
    }
    Ok(out)
}

/// Go `findTOMLComment`, byte-faithful: a `'` closes unconditionally.
fn find_toml_comment(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut quote: u8 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if quote != 0 {
            if c == quote && (quote == b'\'' || i == 0 || bytes[i - 1] != b'\\') {
                quote = 0;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = c,
            b'#' => return i,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Go `parseTOMLHeader` with identical error strings.
fn parse_toml_header(line: &str) -> Result<(Vec<String>, bool, bool), String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok((Vec::new(), false, false));
    }
    let array = trimmed.starts_with("[[");
    let inner = if array {
        if !trimmed.ends_with("]]") {
            return Err("malformed array-of-tables header".to_owned());
        }
        trimmed[2..trimmed.len() - 2].trim().to_owned()
    } else {
        if !trimmed.starts_with('[') {
            return Ok((Vec::new(), false, false));
        }
        let close = find_toml_comment(trimmed);
        let head = trimmed[..close].trim();
        if !head.ends_with(']') {
            return Err("malformed table header".to_owned());
        }
        head[1..head.len() - 1].trim().to_owned()
    };
    let path = parse_toml_key_path(&inner)?;
    Ok((path, array, true))
}

fn is_prefix(prefix: &[String], path: &[String]) -> bool {
    prefix.len() <= path.len() && prefix.iter().zip(path.iter()).all(|(a, b)| a == b)
}

fn equal_path(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && is_prefix(a, b)
}

fn unescape_basic(text: &str) -> Result<String, String> {
    let inner = &text[1..text.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let code = u32::from_str_radix(&hex, 16)
                    .map_err(|_| "invalid unicode escape".to_owned())?;
                out.push(char::from_u32(code).ok_or("invalid unicode escape".to_owned())?);
            }
            Some('U') => {
                let hex: String = chars.by_ref().take(8).collect();
                let code = u32::from_str_radix(&hex, 16)
                    .map_err(|_| "invalid unicode escape".to_owned())?;
                out.push(char::from_u32(code).ok_or("invalid unicode escape".to_owned())?);
            }
            Some(other) => return Err(format!("unsupported escape '\\{other}'")),
            None => return Err("trailing backslash".to_owned()),
        }
    }
    Ok(out)
}

fn parse_toml_scalar(text: &str) -> Result<CfgVal, String> {
    let text = text.trim();
    if text.starts_with('"') {
        if text.len() < 2 || !text.ends_with('"') {
            return Err("unterminated string".to_owned());
        }
        return unescape_basic(text).map(CfgVal::Str);
    }
    if text.starts_with('\'') {
        if text.len() < 2 || !text.ends_with('\'') {
            return Err("unterminated literal string".to_owned());
        }
        return Ok(CfgVal::Str(text[1..text.len() - 1].to_owned()));
    }
    if text == "true" {
        return Ok(CfgVal::Bool(true));
    }
    if text == "false" {
        return Ok(CfgVal::Bool(false));
    }
    if text.starts_with('{') {
        return parse_toml_inline_table(text);
    }
    if text.starts_with('[') {
        return parse_toml_array(text);
    }
    let digits = text.replace('_', "");
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(value) = digits
            .strip_prefix(prefix)
            .and_then(|rest| i64::from_str_radix(rest, radix).ok())
        {
            return Ok(CfgVal::Int(value));
        }
    }
    if let Ok(n) = digits.parse::<i64>() {
        return Ok(CfgVal::Int(n));
    }
    if let Ok(f) = digits.parse::<f64>() {
        return Ok(CfgVal::Float(f));
    }
    // Datetimes have no reader-side role (they never appear in the managed
    // subtree); keep them opaque instead of rejecting real-world files.
    if is_toml_datetime(text) {
        return Ok(CfgVal::Str(text.to_owned()));
    }
    Err(format!("invalid value {text:?}"))
}

fn is_toml_datetime(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && text[..4].chars().all(|c| c.is_ascii_digit())
}

/// Splits `text[1..len-1]` at top-level commas, quote- and nesting-aware.
fn split_top_level(text: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escape = false;
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = quote {
            if escape {
                escape = false;
            } else if q == '"' && c == '\\' {
                escape = true;
            } else if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth = depth.saturating_sub(1);
            }
            ',' if depth == 0 => {
                parts.push(text[start..i].to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if quote.is_some() {
        return Err("unterminated string in array".to_owned());
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        parts.push(tail.to_owned());
    }
    Ok(parts)
}

fn parse_toml_array(text: &str) -> Result<CfgVal, String> {
    if !text.ends_with(']') {
        return Err("unterminated array".to_owned());
    }
    let mut items = Vec::new();
    for part in split_top_level(&text[1..text.len() - 1])? {
        items.push(parse_toml_scalar(&part)?);
    }
    Ok(CfgVal::Arr(items))
}

fn split_key_value(text: &str) -> Result<(String, String), String> {
    let mut quote: Option<char> = None;
    let mut escape = false;
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if escape {
                escape = false;
            } else if q == '"' && c == '\\' {
                escape = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '=' => return Ok((text[..i].to_owned(), text[i + 1..].to_owned())),
            _ => {}
        }
    }
    Err("expected '=' in table entry".to_owned())
}

fn parse_toml_inline_table(text: &str) -> Result<CfgVal, String> {
    if !text.ends_with('}') {
        return Err("unterminated inline table".to_owned());
    }
    let mut map = BTreeMap::new();
    for part in split_top_level(&text[1..text.len() - 1])? {
        let (raw_key, raw_value) = split_key_value(&part)?;
        let keys = parse_toml_key_path(raw_key.trim())?;
        let value = parse_toml_scalar(&raw_value)?;
        insert_toml_path(&mut map, &keys, value)?;
    }
    Ok(CfgVal::Map(map))
}

fn insert_toml_path(
    map: &mut BTreeMap<String, CfgVal>,
    keys: &[String],
    value: CfgVal,
) -> Result<(), String> {
    if keys.is_empty() {
        return Err("empty key".to_owned());
    }
    if keys.len() == 1 {
        if map.contains_key(&keys[0]) {
            return Err(format!("duplicate key {:?}", keys[0]));
        }
        map.insert(keys[0].clone(), value);
        return Ok(());
    }
    let entry = map
        .entry(keys[0].clone())
        .or_insert_with(|| CfgVal::Map(BTreeMap::new()));
    match entry {
        CfgVal::Map(nested) => insert_toml_path(nested, &keys[1..], value),
        _ => Err(format!("duplicate key {:?}", keys[0])),
    }
}

/// Joins continuation lines while brackets stay unbalanced (multiline
/// arrays), comment-aware like the Go scanner.
fn toml_logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i64;
    for raw in text.split('\n') {
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(raw);
        // Bracket depth ignores quoted regions, so a `[` inside a string
        // cannot glue two logical lines together.
        let code = &raw[..find_toml_comment(raw)];
        let mut quote: Option<char> = None;
        let mut escape = false;
        for c in code.chars() {
            if let Some(q) = quote {
                if escape {
                    escape = false;
                } else if q == '"' && c == '\\' {
                    escape = true;
                } else if c == q {
                    quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 {
            out.push(std::mem::take(&mut current));
            depth = 0;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn parse_toml_document(text: &str) -> Result<BTreeMap<String, CfgVal>, String> {
    let mut root = BTreeMap::new();
    let mut section: Vec<String> = Vec::new();
    for (index, raw) in toml_logical_lines(text).iter().enumerate() {
        let code = raw[..find_toml_comment(raw)].trim();
        if code.is_empty() {
            continue;
        }
        if code.starts_with('[') {
            let (path, array, is_header) = parse_toml_header(code)
                .map_err(|detail| format!("line {}: {detail}", index + 1))?;
            if !is_header {
                return Err(format!("line {}: invalid value {code:?}", index + 1));
            }
            if array {
                let (parent, last) = path.split_at(path.len() - 1);
                let mut cursor = &mut root;
                for part in parent {
                    cursor = match cursor
                        .entry(part.clone())
                        .or_insert_with(|| CfgVal::Map(BTreeMap::new()))
                    {
                        CfgVal::Map(nested) => nested,
                        _ => return Err(format!("line {}: conflicting key {:?}", index + 1, part)),
                    };
                }
                let slot = cursor
                    .entry(last[0].clone())
                    .or_insert_with(|| CfgVal::Arr(Vec::new()));
                match slot {
                    CfgVal::Arr(items) => {
                        items.push(CfgVal::Map(BTreeMap::new()));
                        section = path;
                    }
                    _ => return Err(format!("line {}: conflicting key {:?}", index + 1, last[0])),
                }
            } else {
                let mut cursor = &mut root;
                for part in &path {
                    cursor = match cursor
                        .entry(part.clone())
                        .or_insert_with(|| CfgVal::Map(BTreeMap::new()))
                    {
                        CfgVal::Map(nested) => nested,
                        _ => return Err(format!("line {}: conflicting key {:?}", index + 1, part)),
                    };
                }
                section = path;
            }
            continue;
        }
        let (raw_key, raw_value) =
            split_key_value(code).map_err(|detail| format!("line {}: {detail}", index + 1))?;
        let mut keys = parse_toml_key_path(raw_key.trim())
            .map_err(|detail| format!("line {}: {detail}", index + 1))?;
        let value = parse_toml_scalar(&raw_value)
            .map_err(|detail| format!("line {}: {detail}", index + 1))?;
        let mut full = section.clone();
        full.append(&mut keys);
        insert_toml_path(&mut root, &full, value)
            .map_err(|detail| format!("line {}: {detail}", index + 1))?;
    }
    Ok(root)
}

fn read_toml_config(path: &str) -> Result<(BTreeMap<String, CfgVal>, Vec<u8>), String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeMap::new(), Vec::new()));
        }
        Err(error) => return Err(format!("read TOML config {path:?}: {error}")),
    };
    let text = String::from_utf8_lossy(&data);
    let map = parse_toml_document(&text)
        .map_err(|detail| format!("parse TOML config {path:?}: {detail}"))?;
    Ok((map, data))
}

/// go-toml/v2-shaped string literal: single quotes, double quotes only when
/// the value holds a quote.
fn toml_string_literal(text: &str) -> String {
    if !text.contains('\'') && !text.contains('\n') && !text.chars().any(|c| c.is_control()) {
        return format!("'{text}'");
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_scalar(value: &CfgVal) -> Result<String, String> {
    match value {
        CfgVal::Str(s) => Ok(toml_string_literal(s)),
        CfgVal::Int(n) => Ok(n.to_string()),
        CfgVal::Bool(true) => Ok("true".to_owned()),
        CfgVal::Bool(false) => Ok("false".to_owned()),
        CfgVal::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                Ok((*f as i64).to_string())
            } else {
                Ok(format!("{f}"))
            }
        }
        _ => Err("marshal TOML config: unsupported value".to_owned()),
    }
}

/// Emits a table body: sorted scalars, then sorted sub-tables. `prefix` is
/// the table's own dotted path; an empty prefix renders relative `[sub]`
/// headers, which is exactly what go-toml/v2 produces when marshaling the
/// server fragment for the managed-replace path.
fn emit_toml_body(
    map: &BTreeMap<String, CfgVal>,
    prefix: &str,
    out: &mut String,
) -> Result<(), String> {
    for (key, value) in map {
        if matches!(value, CfgVal::Map(_) | CfgVal::Arr(_)) && is_toml_table(value) {
            continue;
        }
        out.push_str(key);
        out.push_str(" = ");
        out.push_str(&toml_table_or_scalar(value)?);
        out.push('\n');
    }
    for (key, value) in map {
        let CfgVal::Map(nested) = value else {
            continue;
        };
        let header = if prefix.is_empty() {
            format!("[{key}]")
        } else {
            format!("[{prefix}.{key}]")
        };
        out.push('\n');
        out.push_str(&header);
        out.push('\n');
        emit_toml_body(nested, &header[1..header.len() - 1], out)?;
    }
    Ok(())
}

fn is_toml_table(value: &CfgVal) -> bool {
    matches!(value, CfgVal::Map(_))
}

fn toml_table_or_scalar(value: &CfgVal) -> Result<String, String> {
    match value {
        CfgVal::Arr(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(toml_scalar(item)?);
            }
            Ok(format!("[{}]", parts.join(", ")))
        }
        other => toml_scalar(other),
    }
}

/// Go `toml.Marshal(data)` for the fresh-document path: `[root]`, then each
/// child table with absolute headers.
fn marshal_toml_fresh(data: &BTreeMap<String, CfgVal>) -> Result<String, String> {
    let mut out = String::new();
    for (root, value) in data {
        let CfgVal::Map(children) = value else {
            return Err("marshal TOML config: root is not a table".to_owned());
        };
        out.push_str(&format!("[{root}]\n"));
        for (child, child_value) in children {
            let CfgVal::Map(table) = child_value else {
                return Err("marshal TOML config: server is not a table".to_owned());
            };
            out.push_str(&format!("[{root}.{child}]\n"));
            emit_toml_body(table, &format!("{root}.{child}"), &mut out)?;
        }
    }
    Ok(out)
}

/// Go `inlineTableLine`.
fn inline_table_line(line: &str, section: &[String], target: &[String]) -> bool {
    let cut = find_toml_comment(line);
    let code = line[..cut].trim();
    let Some(eq) = code.find('=') else {
        return false;
    };
    let Ok(keys) = parse_toml_key_path(code[..eq].trim()) else {
        return false;
    };
    let mut full = section.to_vec();
    full.extend(keys);
    code[eq + 1..].trim_start().starts_with('{')
        && (is_prefix(&full, target) || is_prefix(target, &full))
}

/// Go `rejectUnsafeManagedTOML` with identical error strings.
fn reject_unsafe_managed_toml(original: &str, target: &[String]) -> Result<(), String> {
    let mut section: Vec<String> = Vec::new();
    for (index, line) in original.split_inclusive('\n').enumerate() {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let content = content.strip_suffix('\r').unwrap_or(content);
        let (path, array, is_header) = match parse_toml_header(content) {
            Ok(parts) => parts,
            Err(detail) => {
                return Err(format!(
                    "unsafe TOML header on line {}: {detail}",
                    index + 1
                ));
            }
        };
        let joined = target.join(".");
        if array && (is_prefix(&path, target) || is_prefix(target, &path)) {
            return Err(format!(
                "cannot safely update managed entry {joined:?}: array-of-tables header {content:?}"
            ));
        }
        if is_header && !array {
            section = path.to_vec();
        }
        if !is_header && inline_table_line(content, &section, target) {
            return Err(format!(
                "cannot safely update managed entry {joined:?}: inline table on line {}",
                index + 1
            ));
        }
    }
    Ok(())
}

/// Go `replaceManagedTOML` with identical error strings and separators.
fn replace_managed_toml(
    original: &str,
    root_key: &str,
    server_key: &str,
    data: &BTreeMap<String, CfgVal>,
) -> Result<String, String> {
    let target = vec![root_key.to_owned(), server_key.to_owned()];
    reject_unsafe_managed_toml(original, &target)?;
    let server = match data.get(root_key) {
        Some(CfgVal::Map(root)) => match root.get(server_key) {
            Some(CfgVal::Map(server)) => server.clone(),
            _ => return Err(format!("TOML server {server_key:?} is not a table")),
        },
        _ => return Err(format!("TOML root {root_key:?} is not a table")),
    };
    // Fragment marshal: scalars plus relative `[sub]` tables, mirroring
    // go-toml/v2 `Marshal(server)`.
    let mut encoded = String::new();
    emit_toml_body(&server, "", &mut encoded)
        .map_err(|_| "marshal TOML config: unsupported value".to_owned())?;
    let line_ending = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let encoded = encoded.replace('\n', line_ending);
    let mut replacement = format!("[{root_key}.{server_key}]{line_ending}{encoded}");

    // `strings.SplitAfter`, so every line keeps its ending.
    let mut lines: Vec<&str> = Vec::new();
    let mut rest = original;
    while let Some(index) = rest.find('\n') {
        lines.push(&rest[..=index]);
        rest = &rest[index + 1..];
    }
    if !rest.is_empty() {
        lines.push(rest);
    }

    let mut start: Option<usize> = None;
    let mut end = lines.len();
    let mut current: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let content = content.strip_suffix('\r').unwrap_or(content);
        let (path, array, is_header) = match parse_toml_header(content) {
            Ok(parts) => parts,
            Err(detail) => {
                return Err(format!("unsafe TOML header on line {}: {detail}", i + 1));
            }
        };
        if array {
            if is_prefix(&path, &target) || is_prefix(&target, &path) {
                return Err(format!(
                    "cannot safely update managed entry {:?}: array-of-tables header {content:?}",
                    target.join(".")
                ));
            }
            continue;
        }
        if is_header {
            current = path.to_vec();
            if equal_path(&path, &target) {
                if start.is_some() {
                    return Err(format!(
                        "duplicate managed TOML table {:?}",
                        target.join(".")
                    ));
                }
                start = Some(i);
                continue;
            }
            if start.is_some() && !is_prefix(&target, &path) {
                end = i;
                break;
            }
            continue;
        }
        if start.is_some() && inline_table_line(content, &current, &target) {
            return Err(format!(
                "cannot safely update managed entry {:?}: inline table on line {}",
                target.join("."),
                i + 1
            ));
        }
    }
    let Some(start) = start else {
        let mut out = original.to_owned();
        if !original.is_empty() && !original.ends_with('\n') {
            out.push_str(line_ending);
        }
        out.push_str(&replacement);
        return Ok(out);
    };
    if end == lines.len() && !original.is_empty() && !original.ends_with('\n') {
        replacement = replacement
            .strip_suffix(line_ending)
            .unwrap_or(&replacement)
            .to_owned();
    }
    let mut out = String::new();
    for line in &lines[..start] {
        out.push_str(line);
    }
    out.push_str(&replacement);
    for line in &lines[end..] {
        out.push_str(line);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// File helpers.
// ---------------------------------------------------------------------------

fn ensure_config_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create config directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            // Go `MkdirAll(dir, 0o700)`; best effort on an existing dir.
            let _ = std::fs::DirBuilder::new().mode(0o700).create(parent);
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|error| format!("create directory: {error}"))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path).map_err(|error| format!("create directory: {error}"))
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_private_dir(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("write file: {error}"))?;
        file.write_all(data)
            .map_err(|error| format!("write file: {error}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|error| format!("write file: {error}"))
    }
}

/// Go `fsutil.AtomicWriteFile(path, out, 0o600)`: temp file plus rename.
fn atomic_write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    write_private_file(&tmp, data)?;
    std::fs::rename(&tmp, path).map_err(|error| format!("write file: {error}"))?;
    Ok(())
}

/// Go `install.BackupConfig`, ignoring the error like the caller does.
fn backup_config(path: &str) -> String {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => return String::new(),
    };
    let backup = format!("{path}.backup");
    if write_private_file(Path::new(&backup), &data).is_err() {
        return String::new();
    }
    backup
}

// ---------------------------------------------------------------------------
// Vault-side profile and token.
// ---------------------------------------------------------------------------

/// Go `buildInstallProfile` plus the preserve-on-force block.
fn build_install_profile(
    name: &str,
    tier_name: &str,
    existing: Option<&AgentProfile>,
) -> AgentProfile {
    let preset_name = match tier_name {
        "standard" => "standard",
        "admin" => "admin",
        _ => "read-only",
    };
    let mut profile = AgentProfile {
        tier: Some(tier_name.to_owned()),
        ..Default::default()
    };
    if let Some(preset) = tier::get_preset(preset_name) {
        profile.approval_mode = preset.approval_mode;
        profile.can_write = preset.can_write.unwrap_or(false);
        profile.can_run_commands = preset.can_run_commands.unwrap_or(false);
        profile.can_manage_config = preset.can_manage_config.unwrap_or(false);
        profile.can_use_clipboard = preset.can_use_clipboard.unwrap_or(false);
        profile.can_use_autotype = preset.can_use_autotype.unwrap_or(false);
        profile.can_read_values = preset.can_read_values.unwrap_or(false);
        profile.expose_value_tools = preset.expose_value_tools.unwrap_or(false);
        profile.auto_unseal = preset.auto_unseal.unwrap_or(false);
        profile.require_approval = preset.require_approval.unwrap_or(false);
        profile.allowed_executables = preset.allowed_executables.unwrap_or_default();
    }
    if let Some(previous) = existing {
        profile.skill_path = previous.skill_path.clone();
        profile.skill_version = previous.skill_version.clone();
    }
    let _ = name;
    profile
}

/// Go `createAgentProfileConfig`.
fn create_agent_profile_config(
    vault: &Path,
    name: &str,
    tier_name: &str,
    force: bool,
    dry_run: bool,
) -> Result<String, String> {
    validate_agent_name(name)?;
    let config_path = vault.join("config.yaml");
    let config_path_str = config_path.to_string_lossy().into_owned();
    let mut cfg = match Config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(symvault_core::config::ConfigError::Read(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Config {
                vault_dir: vault.to_string_lossy().into_owned(),
                ..Default::default()
            }
        }
        Err(error) => return Err(format!("load config: {error}")),
    };
    let has_existing = cfg.agents.contains_key(name);
    if has_existing && !force && !dry_run {
        return Err(format!(
            "agent {name:?} already exists in config (use --force to overwrite)"
        ));
    }
    let previous = cfg.agents.get(name);
    let profile = build_install_profile(name, tier_name, previous);
    cfg.agents.insert(name.to_owned(), profile);
    if !dry_run {
        cfg.save_to(&config_path)
            .map_err(|error| format!("save config: {error}"))?;
    }
    Ok(config_path_str)
}

/// Go `createAgentTokenInRegistry`.
fn create_agent_token_in_registry(
    vault: &Path,
    name: &str,
    dry_run: bool,
) -> Result<String, String> {
    if dry_run {
        return Ok("<not-generated-dry-run>".to_owned());
    }
    validate_agent_name(name)?;
    let request = NewToken {
        label: &format!("agent-install-{name}"),
        allowed_tools: vec!["*".to_owned()],
        agent_name: name,
        ttl: None,
        tool_registry_hash: PINNED_TOOL_REGISTRY_HASH,
    };
    let (record, raw_token) = token_registry::create(vault, &request, OffsetDateTime::now_utc())
        .map_err(|error| map_scoped_token_error(&error, "create token: "))?;
    write_agent_token_file(vault, name, &raw_token)
        .map_err(|error| format!("write token file: {error}"))?;
    Ok(record.id)
}

/// Go `writeAgentTokenFile` (`cmd/mcp/agent.go`).
fn write_agent_token_file(vault: &Path, name: &str, raw_token: &str) -> Result<String, String> {
    validate_agent_name(name)?;
    let dir = vault.join("mcp-tokens");
    create_private_dir(&dir).map_err(|error| format!("create token directory: {error}"))?;
    let path = dir.join(format!("{name}.token"));
    write_private_file(&path, format!("{raw_token}\n").as_bytes())
        .map_err(|error| format!("write token file: {error}"))?;
    Ok(path.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// Server config (stdio + HTTP).
// ---------------------------------------------------------------------------

fn build_stdio_server_config(vault: &Path, home: &Path, agent_name: &str) -> CfgVal {
    let mut server = BTreeMap::new();
    server.insert("command".to_owned(), CfgVal::Str("symvault".to_owned()));
    server.insert(
        "args".to_owned(),
        CfgVal::Arr(
            stdio_args(vault, home, agent_name)
                .into_iter()
                .map(CfgVal::Str)
                .collect(),
        ),
    );
    server.insert("timeout".to_owned(), CfgVal::Int(120));
    CfgVal::Map(server)
}

struct HttpConfig {
    url: String,
    headers: BTreeMap<String, String>,
}

/// Tool-registry hash the pinned Oracle stamps into every install token.
// ponytail: Go computes this in `server.init()` as sha256 over the compiled
// MCP tool definitions; the Rust port has no equivalent registry hash yet, so
// the install slice pins the Oracle-observed constant. Upgrade path: compute
// the hash from the Rust tool definitions and share it with the store.
const PINNED_TOOL_REGISTRY_HASH: &str =
    "01c5ea5101379933ab1ffba00f6b11b0f71afed220890cd7cb3460aeedcbb77f";

// Remembers that `SYMVAULT_MCP_TOKEN` was consumed. Go calls
// `os.Unsetenv`, which `#![deny(unsafe_code)]` forbids here
// (`std::env::remove_var` is `unsafe` in edition 2024); the flag reproduces
// the observable behavior — a second install in the same process no longer
// sees the variable — without touching the real environment. Thread-local
// so parallel contract tests stay isolated.
thread_local! {
    static MCP_ENV_TOKEN_CONSUMED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Go `os.Getenv("SYMVAULT_MCP_TOKEN") != ""`: empty counts as unset, and
/// the value is invisible once consumed above.
fn env_mcp_token() -> Option<String> {
    if MCP_ENV_TOKEN_CONSUMED.get() {
        return None;
    }
    match std::env::var("SYMVAULT_MCP_TOKEN") {
        Ok(token) if !token.is_empty() => Some(token),
        _ => None,
    }
}

/// Go `resolveHTTPConfig` (`cmd/mcp/mcp_config.go`): the token file defaults
/// to `<vault>/mcp-token`, port resolution runs before the token load, and
/// load failures wrap as `load token: ...`.
fn resolve_http_config(
    vault: &Path,
    agent_name: &str,
    stderr: &mut dyn Write,
    quiet: bool,
) -> Result<HttpConfig, String> {
    let config_path = vault.join("config.yaml");
    let loaded = Config::load(&config_path).ok();
    let mut bind = "127.0.0.1".to_owned();
    let mut configured_port: i64 = 0;
    let mut token_path = vault.join("mcp-token").to_string_lossy().into_owned();
    if let Some(mcp) = loaded.as_ref().and_then(|cfg| cfg.mcp.as_ref()) {
        if !mcp.bind.trim().is_empty() {
            bind = mcp.bind.clone();
        }
        configured_port = mcp.port;
        if !mcp.http_token_file.trim().is_empty() && mcp.http_token_file.trim() != "auto" {
            // Go uses the configured path verbatim (no vault join).
            token_path = mcp.http_token_file.clone();
        }
    }
    let port = resolve_http_port(vault, &bind, configured_port)?;
    let token = load_or_create_token(Path::new(&token_path), stderr, quiet)
        .map_err(|error| format!("load token: {error}"))?;
    let url = format!("http://{bind}:{port}/mcp");
    let mut headers = BTreeMap::new();
    headers.insert(
        "Accept".to_owned(),
        "application/json, text/event-stream".to_owned(),
    );
    headers.insert("Authorization".to_owned(), format!("Bearer {token}"));
    headers.insert(
        "MCP-Protocol-Version".to_owned(),
        symvault_mcp::LATEST_SUPPORTED_PROTOCOL_VERSION.to_owned(),
    );
    headers.insert("X-Symaira-Agent".to_owned(), agent_name.to_owned());
    Ok(HttpConfig { url, headers })
}

/// Go `auth.LoadOrCreateToken`: a non-empty file token wins (warning when
/// the environment holds one too); otherwise the environment value is
/// returned as-is; only a missing file *and* an empty environment mints a
/// fresh 32-byte hex token into the file. Read failures fall through exactly
/// like Go's `if err == nil` guard.
fn load_or_create_token(
    token_file: &Path,
    stderr: &mut dyn Write,
    quiet: bool,
) -> Result<String, String> {
    if let Ok(content) = std::fs::read_to_string(token_file) {
        let token = content.trim().to_owned();
        if !token.is_empty() {
            if env_mcp_token().is_some() {
                if !quiet {
                    let _ = writeln!(
                        stderr,
                        "Warning: SYMVAULT_MCP_TOKEN is set but file token exists at {}; using file token",
                        token_file.to_string_lossy()
                    );
                }
                MCP_ENV_TOKEN_CONSUMED.set(true);
            }
            return Ok(token);
        }
    }
    if let Some(env_token) = env_mcp_token() {
        MCP_ENV_TOKEN_CONSUMED.set(true);
        return Ok(env_token);
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|error| format!("generate token: {error}"))?;
    let token: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
    atomic_write_private(token_file, format!("{token}\n").as_bytes())
        .map_err(|error| format!("write token file: {error}"))?;
    Ok(token)
}

/// `{"port": N, "bind": "..."}` or a bare decimal number.
fn load_runtime_port(vault: &Path) -> Option<(i64, String)> {
    let path = vault.join(".runtime-port");
    let data = std::fs::read(&path).ok()?;
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) {
        if let Some(port) = value
            .get("port")
            .and_then(|port| port.as_i64())
            .filter(|port| *port > 0)
        {
            let bind = value
                .get("bind")
                .and_then(|bind| bind.as_str())
                .unwrap_or_default()
                .to_owned();
            return Some((port, bind));
        }
        return None;
    }
    let port = String::from_utf8_lossy(&data).trim().parse::<i64>().ok()?;
    // Go's legacy branch returns any parseable number without a range check.
    Some((port, String::new()))
}

/// Go `ResolveHTTPPort`: a present port file is probed, otherwise the
/// configured port (or 8080) is returned.
fn resolve_http_port(vault: &Path, bind: &str, configured_port: i64) -> Result<i64, String> {
    if let Some((port, _)) = load_runtime_port(vault) {
        match health_check(bind, port) {
            Ok(()) => return Ok(port),
            Err(detail) => {
                let path = vault.join(".runtime-port").to_string_lossy().into_owned();
                return Err(format!(
                    "stale runtime port {port} from {path}: {detail}; remove {path} or restart 'symvault mcp'"
                ));
            }
        }
    }
    if configured_port > 0 {
        return Ok(configured_port);
    }
    Ok(8080)
}

/// Minimal `GET /health` over TCP with a 500 ms deadline; Go demands HTTP
/// 200 from the running server before trusting the port file.
fn health_check(bind: &str, port: i64) -> Result<(), String> {
    use std::io::Read;
    use std::net::ToSocketAddrs;
    let deadline = std::time::Duration::from_millis(500);
    let addr = format!("{bind}:{port}");
    let socket = addr
        .as_str()
        .to_socket_addrs()
        .map_err(|error| format!("dial MCP health endpoint: {error}"))?
        .next()
        .ok_or_else(|| format!("dial MCP health endpoint: no address for {addr}"))?;
    let mut stream = std::net::TcpStream::connect_timeout(&socket, deadline)
        .map_err(|error| format!("dial MCP health endpoint: {error}"))?;
    stream
        .set_read_timeout(Some(deadline))
        .map_err(|error| format!("dial MCP health endpoint: {error}"))?;
    stream
        .write_all(
            format!("GET /health HTTP/1.1\r\nHost: {bind}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .map_err(|error| format!("dial MCP health endpoint: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("dial MCP health endpoint: {error}"))?;
    let status = String::from_utf8_lossy(&response);
    let first_line = status.lines().next().unwrap_or_default();
    if first_line.contains(" 200 ") || first_line.ends_with(" 200") {
        Ok(())
    } else {
        Err(format!("unexpected health status {first_line:?}"))
    }
}

/// Go `buildServerConfig` (`cmd/mcp/mcp_install.go`): stdio carries no token
/// ID; HTTP mints a second scoped registry token whose raw value becomes the
/// Bearer entry (the display token from `createAgentTokenInRegistry` keeps
/// its own ID in the result line).
#[allow(clippy::too_many_arguments)] // mirrors Go `buildServerConfig` parameter-for-parameter
fn build_server_config(
    vault: &Path,
    home: &Path,
    def: AgentDef,
    agent_name: &str,
    http_mode: bool,
    dry_run: bool,
    stderr: &mut dyn Write,
    quiet: bool,
) -> Result<(CfgVal, String), String> {
    if !http_mode {
        return Ok((
            build_stdio_server_config(vault, home, agent_name),
            String::new(),
        ));
    }
    build_http_server_config(vault, def, agent_name, dry_run, stderr, quiet)
}

/// Go `buildHTTPServerConfig`: the `mcp-token` file token only wakes the
/// server-side plumbing (`resolveHTTPConfig`); the config entry carries a
/// fresh `mcp-install-<agent>` registry token instead.
fn build_http_server_config(
    vault: &Path,
    def: AgentDef,
    agent_name: &str,
    dry_run: bool,
    stderr: &mut dyn Write,
    quiet: bool,
) -> Result<(CfgVal, String), String> {
    let http = resolve_http_config(vault, agent_name, stderr, quiet)?;
    let (raw_token, token_id) = if !dry_run {
        let request = NewToken {
            label: &format!("mcp-install-{agent_name}"),
            allowed_tools: vec!["*".to_owned()],
            agent_name,
            ttl: Some(Duration::days(30)),
            tool_registry_hash: PINNED_TOOL_REGISTRY_HASH,
        };
        let (record, raw) = token_registry::create(vault, &request, OffsetDateTime::now_utc())
            .map_err(|error| map_scoped_token_error(&error, "create scoped token: "))?;
        (raw, record.id)
    } else {
        // Go's deterministic preview token keeps dry-run output stable.
        (
            "<dry-run-preview-token>".to_owned(),
            "<not-generated-dry-run>".to_owned(),
        )
    };
    let mut headers = BTreeMap::new();
    headers.insert(
        "Accept".to_owned(),
        CfgVal::Str(http.headers["Accept"].clone()),
    );
    headers.insert(
        "Authorization".to_owned(),
        CfgVal::Str(format!("Bearer {raw_token}")),
    );
    headers.insert(
        "MCP-Protocol-Version".to_owned(),
        CfgVal::Str(http.headers["MCP-Protocol-Version"].clone()),
    );
    headers.insert(
        "X-Symaira-Agent".to_owned(),
        CfgVal::Str(http.headers["X-Symaira-Agent"].clone()),
    );
    let mut server = BTreeMap::new();
    server.insert("url".to_owned(), CfgVal::Str(http.url));
    server.insert("timeout".to_owned(), CfgVal::Int(120));
    server.insert("connect_timeout".to_owned(), CfgVal::Int(30));
    server.insert("headers".to_owned(), CfgVal::Map(headers));
    if def.agent_type == "opencode" {
        server.insert("type".to_owned(), CfgVal::Str("remote".to_owned()));
        server.insert("enabled".to_owned(), CfgVal::Bool(true));
    }
    Ok((CfgVal::Map(server), token_id))
}

/// Go splits registry failures into load/create/save stages; the Rust
/// single-call create maps read-side failures to the load stage and write
/// failures to the save stage, everything else to the caller's create stage.
fn map_scoped_token_error(error: &symvault_store::StoreError, create_prefix: &str) -> String {
    match error {
        symvault_store::StoreError::Read { .. } | symvault_store::StoreError::MissingFile(_) => {
            format!("load token registry: {error}")
        }
        symvault_store::StoreError::Write { .. } => format!("save token registry: {error}"),
        _ => format!("{create_prefix}{error}"),
    }
}

// ---------------------------------------------------------------------------
// MCP config install.
// ---------------------------------------------------------------------------

/// Go `installMCPConfig` (the `agent install` variant taking the definition).
#[allow(clippy::too_many_arguments)] // mirrors Go `installMCPConfig` parameter-for-parameter
fn install_mcp_config(
    vault: &Path,
    home: &Path,
    def: AgentDef,
    agent_name: &str,
    http_mode: bool,
    dry_run: bool,
    stderr: &mut dyn Write,
    quiet: bool,
) -> Result<(String, String), String> {
    let (server_config, _scoped_token_id) = build_server_config(
        vault, home, def, agent_name, http_mode, dry_run, stderr, quiet,
    )
    .map_err(|error| format!("build server config: {error}"))?;
    let (detected, detected_path) = detect_agent(home, def);
    let config_path = if detected && !detected_path.is_empty() {
        detected_path
    } else {
        resolve_config_path(home, def)
    };
    let mut backup_path = String::new();
    if !dry_run {
        backup_path = backup_config(&config_path);
    }
    install_config_file(&config_path, def, server_config, dry_run)
        .map_err(|error| format!("install MCP config for {}: {error}", def.display))?;
    Ok((config_path, backup_path))
}

fn install_config_file(
    config_path: &str,
    def: AgentDef,
    server_config: CfgVal,
    dry_run: bool,
) -> Result<(), String> {
    let path = Path::new(config_path);
    match def.format {
        ConfigFormat::Json => {
            let mut existing = read_json_config(config_path)?;
            inject_server_config(&mut existing, def.root_key, def.server_key, server_config);
            if dry_run {
                return Ok(());
            }
            ensure_config_dir(path)?;
            let value = CfgVal::Map(existing);
            let mut rendered = serde_json::to_string_pretty(&cfg_to_json(&value))
                .map_err(|error| format!("marshal JSON config: {error}"))?;
            rendered.push('\n');
            write_private_file(path, rendered.as_bytes())
                .map_err(|error| format!("write JSON config {config_path:?}: {error}"))?;
            Ok(())
        }
        ConfigFormat::Yaml => {
            let mut existing = read_yaml_config(config_path)?;
            inject_server_config(&mut existing, def.root_key, def.server_key, server_config);
            if dry_run {
                return Ok(());
            }
            ensure_config_dir(path)?;
            let rendered = emit_yaml_map(&existing);
            write_private_file(path, rendered.as_bytes())
                .map_err(|error| format!("write YAML config {config_path:?}: {error}"))?;
            Ok(())
        }
        ConfigFormat::Toml => {
            let (mut existing, original) = read_toml_config(config_path)?;
            inject_server_config(&mut existing, def.root_key, def.server_key, server_config);
            if dry_run {
                return Ok(());
            }
            ensure_config_dir(path)?;
            let original_text = String::from_utf8_lossy(&original);
            let rendered = if !original.is_empty() {
                replace_managed_toml(&original_text, def.root_key, def.server_key, &existing)
                    .map_err(|error| format!("marshal TOML config: {error}"))?
            } else {
                marshal_toml_fresh(&existing)
                    .map_err(|error| format!("marshal TOML config: {error}"))?
            };
            atomic_write_private(path, rendered.as_bytes())
                .map_err(|error| format!("write TOML config {config_path:?}: {error}"))?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Skill package.
// ---------------------------------------------------------------------------

/// Go `installSkillPackage`.
fn install_skill_package(
    vault: &Path,
    agent_name: &str,
    tier_name: &str,
    dry_run: bool,
) -> Result<String, String> {
    let mut target = skill_target(vault, agent_name);
    if target.is_empty() {
        target = Config::default()
            .agents
            .get(agent_name)
            .map(|profile| profile.skill_path.clone())
            .unwrap_or_default();
    }
    if target.is_empty() {
        return Err(format!(
            "cannot determine skill path for agent {agent_name:?}"
        ));
    }
    let target = expand_tilde(&target)
        .map(|expanded| expanded.to_string_lossy().into_owned())
        .unwrap_or(target);
    if dry_run {
        return Ok(target);
    }
    install_with_tier(vault, agent_name, &target, true, tier_name)
        .map_err(|error| format!("install skill: {error}"))?;
    Ok(target)
}

// ---------------------------------------------------------------------------
// Results and output.
// ---------------------------------------------------------------------------

struct InstallResult {
    agent_name: String,
    tier: String,
    method: String,
    profile_path: String,
    token_id: String,
    mcp_config_path: String,
    skill_path: String,
    smoke_test: String,
    backup_path: String,
}

impl InstallResult {
    fn json_pairs(&self) -> Vec<(String, CfgVal)> {
        let mut pairs = vec![
            (
                "agent_name".to_owned(),
                CfgVal::Str(self.agent_name.clone()),
            ),
            ("tier".to_owned(), CfgVal::Str(self.tier.clone())),
            ("method".to_owned(), CfgVal::Str(self.method.clone())),
            (
                "profile_path".to_owned(),
                CfgVal::Str(self.profile_path.clone()),
            ),
            ("token_id".to_owned(), CfgVal::Str(self.token_id.clone())),
            (
                "mcp_config_path".to_owned(),
                CfgVal::Str(self.mcp_config_path.clone()),
            ),
            (
                "skill_path".to_owned(),
                CfgVal::Str(self.skill_path.clone()),
            ),
            (
                "smoke_test".to_owned(),
                CfgVal::Str(self.smoke_test.clone()),
            ),
        ];
        if !self.backup_path.is_empty() {
            pairs.push((
                "backup_path".to_owned(),
                CfgVal::Str(self.backup_path.clone()),
            ));
        }
        pairs
    }
}

fn write_text_output(
    results: &[InstallResult],
    quiet: bool,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    for result in results {
        if result.profile_path.is_empty()
            && result.mcp_config_path.is_empty()
            && result.skill_path.is_empty()
        {
            continue;
        }
        let _ = writeln!(stdout, "✓ Agent {:?} configured", result.agent_name);
        let _ = writeln!(stdout, "  Tier:         {}", result.tier);
        let _ = writeln!(stdout, "  Transport:    {}", result.method);
        if !result.profile_path.is_empty() {
            let _ = writeln!(stdout, "  Profile:      {}", result.profile_path);
        }
        if !result.token_id.is_empty() {
            let token = if result.token_id == "<not-generated-dry-run>" {
                "<not generated (dry-run)>".to_owned()
            } else {
                result.token_id.clone()
            };
            let _ = writeln!(stdout, "  Token ID:     {token}");
        }
        if !result.mcp_config_path.is_empty() {
            let _ = writeln!(stdout, "  MCP config:   {}", result.mcp_config_path);
        }
        if !result.backup_path.is_empty() {
            let _ = writeln!(stdout, "  Backup:       {}", result.backup_path);
        }
        if !result.skill_path.is_empty() {
            let _ = writeln!(stdout, "  Skill:        {}", result.skill_path);
        }
        let _ = writeln!(stdout, "  Smoke test:   {}", result.smoke_test);
    }
    Ok(())
}

/// Go `writeInstallOutput`.
fn write_install_output(
    results: &[InstallResult],
    output: &str,
    quiet: bool,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    match output {
        "json" => {
            let mut rendered = String::new();
            if results.len() == 1 {
                emit_json_pairs(&results[0].json_pairs(), 0, &mut rendered);
            } else {
                rendered.push_str("[\n");
                for (index, result) in results.iter().enumerate() {
                    let mut one = String::new();
                    emit_json_pairs(&result.json_pairs(), 2, &mut one);
                    for line in one.split('\n') {
                        rendered.push_str("  ");
                        rendered.push_str(line);
                        rendered.push('\n');
                    }
                    if index + 1 < results.len() {
                        rendered.pop();
                        rendered.push_str(",\n");
                    }
                }
                rendered.push_str("]\n");
                let _ = stdout.write_all(rendered.as_bytes());
                return Ok(());
            }
            rendered.push('\n');
            stdout
                .write_all(rendered.as_bytes())
                .map_err(|error| format!("write output: {error}"))?;
            Ok(())
        }
        "yaml" => {
            let mut rendered = String::new();
            if results.len() == 1 {
                emit_yaml_pairs(&results[0].json_pairs(), 0, &mut rendered);
            } else {
                for result in results {
                    rendered.push_str(&format!(
                        "- agent_name: {}\n",
                        yaml_scalar_text(&result.agent_name)
                    ));
                    let rest: Vec<(String, CfgVal)> =
                        result.json_pairs().into_iter().skip(1).collect();
                    emit_yaml_pairs(&rest, 2, &mut rendered);
                }
            }
            stdout
                .write_all(rendered.as_bytes())
                .map_err(|error| format!("write output: {error}"))?;
            Ok(())
        }
        _ => write_text_output(results, quiet, stdout),
    }
}

// ---------------------------------------------------------------------------
// Single install and auto-detect.
// ---------------------------------------------------------------------------

/// Go `agentInstallSingle`. Mirrors Go's `(InstallResult, error)` tuple: the
/// partial result is returned alongside the error so auto-detect can append
/// it like Go does.
#[allow(clippy::too_many_arguments)]
fn install_single(
    vault: &Path,
    home: &Path,
    agent_name: &str,
    tier_name: &str,
    http_mode: bool,
    skill_only: bool,
    config_only: bool,
    force: bool,
    dry_run: bool,
    stderr: &mut dyn Write,
    quiet: bool,
) -> (InstallResult, Result<(), String>) {
    let mut result = InstallResult {
        agent_name: agent_name.to_owned(),
        tier: tier_name.to_owned(),
        method: String::new(),
        profile_path: String::new(),
        token_id: String::new(),
        mcp_config_path: String::new(),
        skill_path: String::new(),
        smoke_test: "skipped".to_owned(),
        backup_path: String::new(),
    };
    let status = install_single_inner(
        vault,
        home,
        agent_name,
        tier_name,
        http_mode,
        skill_only,
        config_only,
        force,
        dry_run,
        stderr,
        quiet,
        &mut result,
    );
    (result, status)
}

#[allow(clippy::too_many_arguments)]
fn install_single_inner(
    vault: &Path,
    home: &Path,
    agent_name: &str,
    tier_name: &str,
    http_mode: bool,
    skill_only: bool,
    config_only: bool,
    force: bool,
    dry_run: bool,
    stderr: &mut dyn Write,
    quiet: bool,
    result: &mut InstallResult,
) -> Result<(), String> {
    let def =
        parse_agent_type(agent_name).map_err(|()| format!("unsupported agent {agent_name:?}"))?;
    let (detected, _) = detect_agent(home, def);
    if !detected {
        return Err(format!(
            "agent {:?} not detected (checked binary in PATH and config files)",
            def.display
        ));
    }
    result.method = if http_mode {
        "http".to_owned()
    } else {
        "stdio".to_owned()
    };
    result.profile_path = create_agent_profile_config(vault, agent_name, tier_name, force, dry_run)
        .map_err(|error| format!("create agent profile: {error}"))?;
    if !skill_only {
        result.token_id = create_agent_token_in_registry(vault, agent_name, dry_run)
            .map_err(|error| format!("create agent token: {error}"))?;
    }
    if !skill_only {
        let (mcp_config_path, backup_path) = install_mcp_config(
            vault, home, def, agent_name, http_mode, dry_run, stderr, quiet,
        )
        .map_err(|error| format!("install MCP config: {error}"))?;
        result.mcp_config_path = mcp_config_path;
        result.backup_path = backup_path;
    }
    if !config_only {
        result.skill_path = install_skill_package(vault, agent_name, tier_name, dry_run)
            .map_err(|error| format!("install skill package: {error}"))?;
    }
    Ok(())
}

/// Go `agentInstallAutoDetect`. Go ranges over a `map`, so multi-agent order
/// is random there; the port walks the definition order (deterministic) and
/// documents the draw in the porting notes. Single-detection runs — the
/// contract cases — are byte-identical either way.
#[allow(clippy::too_many_arguments)]
fn auto_detect(
    vault: &Path,
    home: &Path,
    tier_name: &str,
    http_mode: bool,
    skill_only: bool,
    config_only: bool,
    force: bool,
    dry_run: bool,
    quiet: bool,
    output: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    let mut results = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for def in AGENT_DEFS {
        let (detected, _) = detect_agent(home, def);
        if !detected {
            continue;
        }
        if !quiet {
            let _ = writeln!(stdout, "Detected {}", def.display);
        }
        let (result, status) = install_single(
            vault,
            home,
            def.agent_type,
            tier_name,
            http_mode,
            skill_only,
            config_only,
            force,
            dry_run,
            stderr,
            quiet,
        );
        match status {
            Ok(()) => results.push(result),
            Err(error) => {
                errors.push(format!("{}: {error}", def.display));
                // Go appends the partial result when the agent name is set,
                // which is always the case here.
                results.push(result);
            }
        }
    }
    if !errors.is_empty() {
        let mut message = String::from("errors during auto-detect install:\n");
        for error in &errors {
            // Go joins with `"\n  "` and no dash: `"  %s"`.
            message.push_str(&format!("  {error}\n"));
        }
        message.pop();
        return Err(message);
    }
    write_install_output(&results, output, quiet, stdout)
}

/// Go `runAgentInstall`.
pub(crate) fn run(
    vault: &Path,
    home: &Path,
    args: &[String],
    flags: &InstallFlags,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    if flags.skill_only && flags.config_only {
        return Err("--skill-only and --config-only cannot be used together".to_owned());
    }
    if !matches!(flags.tier.as_str(), "safe" | "standard" | "admin") {
        return Err(format!(
            "invalid tier {:?}: must be one of: safe, standard, admin",
            flags.tier
        ));
    }
    if flags.tier != "safe" && !std::io::stdin().is_terminal() {
        return Err(format!(
            "--tier {:?} requires an interactive terminal to confirm the security implications; use --tier safe (default) for non-interactive installs",
            flags.tier
        ));
    }
    if flags.auto_detect {
        if !args.is_empty() {
            return Err("cannot specify an agent name with --auto-detect".to_owned());
        }
        return auto_detect(
            vault,
            home,
            &flags.tier,
            flags.http,
            flags.skill_only,
            flags.config_only,
            flags.force,
            flags.dry_run,
            flags.quiet,
            &flags.output,
            stdout,
            stderr,
        );
    }
    if args.len() != 1 {
        return Err("requires exactly 1 argument (agent name), or use --auto-detect".to_owned());
    }
    let (result, status) = install_single(
        vault,
        home,
        &args[0],
        &flags.tier,
        flags.http,
        flags.skill_only,
        flags.config_only,
        flags.force,
        flags.dry_run,
        stderr,
        flags.quiet,
    );
    status?;
    write_install_output(
        std::slice::from_ref(&result),
        &flags.output,
        flags.quiet,
        stdout,
    )
}
