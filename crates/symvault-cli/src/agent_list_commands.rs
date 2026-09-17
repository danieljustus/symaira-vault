use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use symvault_core::config::Config;

const TOKEN_REGISTRY: &str = "mcp-tokens.json";
const MANAGED_BY: &str = "symaira";

#[derive(Debug, Serialize)]
pub(crate) struct AgentListItem {
    name: String,
    tier: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    token_id: String,
    token_valid: bool,
    skill_installed: bool,
    skill_managed: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_seen: String,
}

#[derive(Debug, Serialize)]
struct AgentListResult {
    agents: Vec<AgentListItem>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct YamlAgentListItem<'a> {
    name: &'a str,
    tier: &'a str,
    #[serde(rename = "tokenid")]
    token_id: &'a str,
    tokenvalid: bool,
    skillinstalled: bool,
    skillmanaged: bool,
    #[serde(rename = "lastseen")]
    last_seen: &'a str,
}

#[derive(Debug, Serialize)]
struct YamlAgentList<'a> {
    agents: Vec<YamlAgentListItem<'a>>,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct TokenRegistryFile {
    #[serde(default)]
    tokens: Option<BTreeMap<String, TokenEntry>>,
}

#[derive(Debug, Deserialize)]
struct TokenEntry {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    agent_name: String,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Deserialize)]
struct SkillManifest {
    #[serde(default)]
    managed_by: String,
}

/// Lists configured agents without unlocking the vault or contacting a
/// server. Token validity follows Go's registry projection: a token is valid
/// when it belongs to the agent, is not revoked, and is not expired. Encrypted
/// `registry.age` files are intentionally outside this no-credential slice,
/// matching Go's plaintext `NewTokenRegistry(...).Load()` call here.
pub(crate) fn list(
    root: &Path,
    home: &Path,
    format: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let config =
        Config::load(root.join("config.yaml")).map_err(|error| format!("load config: {error}"))?;
    let tokens = load_tokens(root)?;
    let mut names: Vec<_> = config.agents.keys().cloned().collect();
    names.sort();

    let agents: Vec<_> = names
        .into_iter()
        .map(|name| {
            let profile = config
                .agents
                .get(&name)
                .expect("agent name came from config map");
            let active: Vec<_> = tokens
                .iter()
                .filter(|token| {
                    !token.hash.is_empty()
                        && token.agent_name == name
                        && !token.revoked
                        && !is_expired(token.expires_at.as_deref())
                })
                .collect();
            // Go iterates the token map in unspecified order when several active
            // tokens exist. Keep Rust output reproducible; the differential
            // fixture uses one active token per agent.
            let token = active.first().copied();
            let last_seen = active
                .iter()
                .filter_map(|token| token.last_used_at.as_deref())
                .max_by_key(|timestamp| timestamp_to_epoch(timestamp));
            let skill = skill_status(home, &profile.skill_path);
            AgentListItem {
                name,
                tier: profile.tier.clone().unwrap_or_default(),
                token_id: token.map_or_else(String::new, |token| token.id.clone()),
                token_valid: token.is_some(),
                skill_installed: skill.0,
                skill_managed: skill.1,
                last_seen: last_seen.map_or_else(String::new, format_timestamp),
            }
        })
        .collect();
    let result = AgentListResult {
        count: agents.len(),
        agents,
    };

    match format {
        "" | "text" => write_text(&result, output),
        "json" => write_json(&result, quiet, output),
        "yaml" => write_yaml(&result, quiet, output),
        // newAgentListCmd falls back to text for an unknown output value.
        _ => write_text(&result, output),
    }
}

fn load_tokens(root: &Path) -> Result<Vec<TokenEntry>, String> {
    let path = root.join(TOKEN_REGISTRY);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("load token registry: {error}")),
    };
    let registry: TokenRegistryFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("load token registry: parse token registry: {error}"))?;
    let tokens: Vec<_> = registry.tokens.unwrap_or_default().into_values().collect();
    for token in &tokens {
        for timestamp in [&token.expires_at, &token.last_used_at]
            .into_iter()
            .flatten()
        {
            if timestamp_to_epoch(timestamp) == i64::MIN {
                return Err(format!(
                    "load token registry: parse token registry: invalid timestamp {timestamp:?}"
                ));
            }
        }
    }
    Ok(tokens)
}

fn skill_status(home: &Path, raw_path: &str) -> (bool, bool) {
    if raw_path.is_empty() {
        return (false, false);
    }
    let path = expand_and_clean(home, raw_path);
    let Ok(data) = fs::read(path) else {
        return (false, false);
    };
    let managed = parse_manifest(&data).is_some_and(|manifest| manifest.managed_by == MANAGED_BY);
    (true, managed)
}

fn expand_and_clean(home: &Path, raw_path: &str) -> PathBuf {
    let expanded = raw_path
        .strip_prefix("~/")
        .map_or_else(|| PathBuf::from(raw_path), |rest| home.join(rest));
    clean_path(&expanded)
}

fn clean_path(path: &Path) -> PathBuf {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let can_pop_normal = clean
                    .components()
                    .next_back()
                    .is_some_and(|last| matches!(last, Component::Normal(_)));
                if can_pop_normal {
                    clean.pop();
                } else if !path.is_absolute() {
                    clean.push(component.as_os_str());
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                clean.push(component.as_os_str());
            }
        }
    }
    clean
}

fn parse_manifest(data: &[u8]) -> Option<SkillManifest> {
    let rest = data
        .strip_prefix(b"---\n")
        .or_else(|| data.strip_prefix(b"---\r\n"))?;
    let close = rest.windows(4).position(|window| window == b"\n---")?;
    serde_yaml_ng::from_slice(&rest[..close]).ok()
}

fn is_expired(timestamp: Option<&str>) -> bool {
    timestamp.is_some_and(|timestamp| timestamp_to_epoch(timestamp) < now_epoch())
}

fn timestamp_to_epoch(timestamp: &str) -> i64 {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
        .map_or(i64::MIN, |value| value.unix_timestamp())
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(i64::MAX, |duration| {
            duration.as_secs().min(i64::MAX as u64) as i64
        })
}

fn format_timestamp(timestamp: &str) -> String {
    timestamp
        .get(..16)
        .map_or_else(|| timestamp.to_owned(), |prefix| prefix.replace('T', " "))
}

fn write_text(result: &AgentListResult, output: &mut impl Write) -> Result<(), String> {
    if result.agents.is_empty() {
        return write!(output, "No agents configured.").map_err(|error| error.to_string());
    }
    writeln!(
        output,
        "{:<14} {:<10} {:<10} {:<12} LAST SEEN",
        "AGENT", "TIER", "TOKEN", "SKILL"
    )
    .map_err(|error| error.to_string())?;
    writeln!(output, "{}", "-".repeat(70)).map_err(|error| error.to_string())?;
    for agent in &result.agents {
        let token = if agent.token_valid {
            "valid"
        } else if !agent.token_id.is_empty() {
            "invalid"
        } else {
            "none"
        };
        let skill = if agent.skill_managed {
            "managed"
        } else if agent.skill_installed {
            "installed"
        } else {
            "missing"
        };
        let last_seen = if agent.last_seen.is_empty() {
            "-"
        } else {
            &agent.last_seen
        };
        writeln!(
            output,
            "{:<14} {:<10} {:<10} {:<12} {}",
            agent.name, agent.tier, token, skill, last_seen
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_json(
    result: &AgentListResult,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    let rendered = serde_json::to_string(result)
        .map_err(|error| error.to_string())?
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    writeln!(output, "{rendered}").map_err(|error| error.to_string())
}

fn write_yaml(
    result: &AgentListResult,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    let yaml = YamlAgentList {
        agents: result
            .agents
            .iter()
            .map(|agent| YamlAgentListItem {
                name: &agent.name,
                tier: &agent.tier,
                token_id: &agent.token_id,
                tokenvalid: agent.token_valid,
                skillinstalled: agent.skill_installed,
                skillmanaged: agent.skill_managed,
                last_seen: &agent.last_seen,
            })
            .collect(),
        count: result.count,
    };
    let rendered = serde_yaml_ng::to_string(&yaml).map_err(|error| error.to_string())?;
    let mut adjusted = String::with_capacity(rendered.len() + result.agents.len() * 4);
    for line in rendered.split_inclusive('\n') {
        if line.starts_with('-') || (line.starts_with("  ") && !line.starts_with("    ")) {
            adjusted.push_str("    ");
        }
        adjusted.push_str(line);
    }
    let adjusted = adjusted
        .lines()
        .map(|line| {
            if let Some(prefix) = line.strip_suffix(": ''") {
                return format!("{prefix}: \"\"");
            }
            line.strip_prefix("      lastseen: \"")
                .and_then(|value| value.strip_suffix('"'))
                .map_or_else(
                    || line.to_owned(),
                    |value| format!("      lastseen: {value}"),
                )
        })
        .collect::<Vec<_>>()
        .join("\n");
    output
        .write_all(adjusted.as_bytes())
        .map_err(|error| error.to_string())?;
    if rendered.ends_with('\n') {
        writeln!(output).map_err(|error| error.to_string())?;
    }
    Ok(())
}
