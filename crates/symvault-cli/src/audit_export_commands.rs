//! Read-only audit evidence export.
//!
//! The store owns JSONL parsing, ordering, redaction, and HMAC status.  This
//! module supplies the CLI's multi-agent discovery, time filter, and Go-shaped
//! JSON/table rendering around that existing implementation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};

use serde::Serialize;
use symvault_store::audit::{self, ExportEntry};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct Options<'a> {
    pub agent: &'a str,
    pub action: &'a str,
    pub since: &'a str,
    pub failed_only: bool,
    pub redact_paths: bool,
    pub format: &'a str,
}

#[derive(Serialize)]
struct ExportOutput {
    entries: Vec<ExportEntry>,
    total: usize,
    verified: usize,
    legacy: usize,
    tampered: usize,
    agent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    since: String,
    #[serde(rename = "failed_only", skip_serializing_if = "is_false")]
    failed_only: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Export local audit logs without unlocking a vault or contacting a remote.
pub fn export(home: &Path, options: &Options<'_>, output: &mut impl Write) -> Result<(), String> {
    let keys = BTreeMap::new();
    export_with_keys(home, options, false, &keys, "", output)
}

/// Export with caller-supplied audit generations.  The production dispatcher
/// obtains these through its existing keyring/session boundary; tests can
/// inject synthetic `AuditKey` values without touching a platform keychain.
pub fn export_with_keys(
    home: &Path,
    options: &Options<'_>,
    verify_hmac: bool,
    keys: &BTreeMap<String, audit::AuditKey>,
    current_kid: &str,
    output: &mut impl Write,
) -> Result<(), String> {
    if verify_hmac && keys.is_empty() {
        return Err("HMAC verification requires a key".into());
    }
    let audit_dir = home.join(".symvault");
    fs::create_dir_all(&audit_dir).map_err(|error| format!("create audit directory: {error}"))?;
    let agents = discover_agents(&audit_dir, options.agent)?;
    let store_options = audit::ExportOptions {
        action: (!options.action.is_empty()).then(|| options.action.to_owned()),
        failed_only: options.failed_only,
        redact_paths: options.redact_paths,
        verify_hmac: false,
    };
    let mut entries = Vec::new();
    let mut verified = 0;
    let mut legacy = 0;
    let mut tampered = 0;
    for agent in agents {
        let result = audit::export_directory(
            &audit_dir,
            &agent,
            &audit::ExportOptions {
                verify_hmac,
                ..store_options.clone()
            },
            keys,
            current_kid,
        )
        .map_err(|error| format!("load agent {agent}: {error}"))?;
        entries.extend(result.entries);
        verified += result.verified;
        legacy += result.legacy;
        tampered += result.tampered;
    }
    if !options.since.is_empty() {
        entries.retain(|entry| since_matches(&entry.entry.timestamp, options.since));
        verified = entries
            .iter()
            .filter(|entry| entry.verify_status == "verified")
            .count();
        legacy = entries
            .iter()
            .filter(|entry| entry.verify_status == "legacy")
            .count();
        tampered = entries
            .iter()
            .filter(|entry| entry.verify_status == "tampered")
            .count();
    }
    entries.sort_by(|left, right| left.entry.timestamp.cmp(&right.entry.timestamp));
    let result = ExportOutput {
        total: entries.len(),
        entries,
        verified,
        legacy,
        tampered,
        agent: options.agent.to_owned(),
        action: options.action.to_owned(),
        since: options.since.to_owned(),
        failed_only: options.failed_only,
    };
    render(&result, options.format, output)
}

fn discover_agents(directory: &Path, requested: &str) -> Result<Vec<String>, String> {
    if !requested.is_empty() && requested != "all" {
        if requested.contains(['/', '\\']) || requested == "." || requested == ".." {
            return Err("invalid agent name".into());
        }
        return Ok(vec![requested.to_owned()]);
    }
    let mut agents = BTreeSet::new();
    for item in fs::read_dir(directory).map_err(|error| format!("read audit directory: {error}"))? {
        let item = item.map_err(|error| format!("read audit directory entry: {error}"))?;
        let name = item.file_name().to_string_lossy().into_owned();
        let Some(name) = name.strip_prefix("audit-") else {
            continue;
        };
        let Some(agent) = name.strip_suffix(".log") else {
            let Some((agent, _)) = name.split_once(".log.rotated.") else {
                continue;
            };
            if !agent.is_empty() {
                agents.insert(agent.to_owned());
            }
            continue;
        };
        if !agent.is_empty() {
            agents.insert(agent.to_owned());
        }
    }
    Ok(agents.into_iter().collect())
}

fn since_matches(timestamp: &str, since: &str) -> bool {
    let Some(duration) = parse_since_nanos(since) else {
        // Go treats an invalid --since value as no time filter.
        return true;
    };
    let Some(stamp) = symvault_sync::GoTime::parse_rfc3339(timestamp)
        .ok()
        .and_then(|value| {
            OffsetDateTime::parse(
                &value.to_rfc3339_nano(),
                &time::format_description::well_known::Rfc3339,
            )
            .ok()
        })
    else {
        return false;
    };
    stamp.unix_timestamp_nanos() >= OffsetDateTime::now_utc().unix_timestamp_nanos() - duration
}

fn parse_since_nanos(value: &str) -> Option<i128> {
    if let Some(days) = value.strip_suffix('d') {
        let days = days.parse::<i64>().ok()?;
        return Some(i128::from(days) * 86_400_000_000_000);
    }
    symvault_core::config::parse_duration_nanos(value)
}

fn render(result: &ExportOutput, format: &str, output: &mut impl Write) -> Result<(), String> {
    match format.to_ascii_lowercase().as_str() {
        "json" => {
            serde_json::to_writer_pretty(&mut *output, result)
                .map_err(|error| error.to_string())?;
            writeln!(output).map_err(|error| error.to_string())
        }
        "table" | "text" | "" => render_table(result, output),
        other => Err(format!("unsupported export format: {other}")),
    }
}

fn render_table(result: &ExportOutput, output: &mut impl Write) -> Result<(), String> {
    if result.entries.is_empty() {
        return writeln!(output, "No audit entries found.").map_err(|error| error.to_string());
    }
    writeln!(
        output,
        "{:<20} {:<12} {:<20} {:<10} {:<8} PATH",
        "TIME", "AGENT", "ACTION", "TRANSPORT", "STATUS"
    )
    .map_err(|error| error.to_string())?;
    writeln!(output, "{}", "-".repeat(90)).map_err(|error| error.to_string())?;
    for row in &result.entries {
        let timestamp = truncate(&row.entry.timestamp, 20);
        let action = truncate(&row.entry.action, 20);
        let path = truncate(
            if row.redacted_path.is_empty() {
                &row.entry.path
            } else {
                &row.redacted_path
            },
            30,
        );
        let status = if row.verify_status.is_empty() {
            if row.entry.ok { "OK" } else { "FAIL" }
        } else {
            row.verify_status.as_str()
        };
        writeln!(
            output,
            "{:<20} {:<12} {:<20} {:<10} {:<8} {}",
            timestamp, row.entry.agent, action, row.entry.transport, status, path
        )
        .map_err(|error| error.to_string())?;
    }
    write!(output, "\nTotal: {} entries", result.total).map_err(|error| error.to_string())?;
    if result.verified > 0 || result.tampered > 0 {
        write!(
            output,
            " (verified: {}, legacy: {}, tampered: {})",
            result.verified, result.legacy, result.tampered
        )
        .map_err(|error| error.to_string())?;
    }
    writeln!(output).map_err(|error| error.to_string())
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    value
        .chars()
        .take(limit.saturating_sub(3))
        .collect::<String>()
        + "..."
}
