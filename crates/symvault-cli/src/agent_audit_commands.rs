//! Read-only audit display for one configured agent.
//!
//! This follows `cmd/mcp/agent_audit.go`, whose command is separate from the
//! top-level `audit` view: it resolves the log below the selected vault,
//! sanitizes the agent name, and uses the compact agent-oriented table.

use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
};

use symvault_core::config::parse_duration_nanos;
use symvault_store::audit::LogEntry;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const SCANNER_MAX_TOKEN: usize = 64 * 1024;

/// Reads and renders one agent's audit log.
///
/// `output` receives table/JSON records. The three no-result messages match
/// Go and are written to `error_output`; they are informational outcomes, not
/// command failures. Go's global quiet flag is not consulted by this command,
/// so the caller should pass the process's normal stderr stream unchanged.
pub(crate) fn view(
    vault: &Path,
    agent: &str,
    limit: i64,
    since: &str,
    format: &str,
    output: &mut impl Write,
    error_output: &mut impl Write,
) -> Result<(), String> {
    let log_path = vault.join(format!("audit-{}.log", sanitize_agent_name(agent)));
    let entries = match read_audit_log(&log_path, limit) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            writeln!(
                error_output,
                "No audit log found for agent {agent:?} at {}",
                log_path.display()
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        Err(error) => return Err(format!("read audit log: {error}")),
    };

    if entries.is_empty() {
        writeln!(error_output, "No audit entries found for agent {agent:?}.")
            .map_err(|error| error.to_string())?;
        return Ok(());
    }

    let entries = filter_since(entries, since);
    if entries.is_empty() {
        writeln!(error_output, "No audit entries match the filter criteria.")
            .map_err(|error| error.to_string())?;
        return Ok(());
    }

    if format == "json" {
        render_json(&entries, output)
    } else {
        render_table(&entries, output)
    }
}

fn sanitize_agent_name(name: &str) -> String {
    // strings.NewReplacer scans left-to-right and prefers the replacement
    // beginning at the current byte. Apply the two-byte traversal marker
    // before separators to preserve that behavior for inputs such as ../x.
    name.replace("..", "_").replace(['/', '\\'], "_")
}

fn read_audit_log(path: &Path, limit: i64) -> io::Result<Vec<LogEntry>> {
    let file = std::fs::File::open(path)?;
    let mut reader = io::BufReader::new(file);
    let mut entries = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader).take(SCANNER_MAX_TOKEN).read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        // bufio.Scanner's default 64 KiB token limit reports ErrTooLong. A
        // newline ending the 64 KiB buffer means the token itself was still
        // below the limit and is accepted.
        if line.len() == SCANNER_MAX_TOKEN && line.last() != Some(&b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bufio.Scanner: token too long",
            ));
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let mut value = match serde_json::from_str::<serde_json::Value>(text) {
            Ok(value) => value,
            Err(_) => continue,
        };
        // json.Unmarshal(null, &entry) leaves a zero-valued struct and
        // returns nil. Deserialize through an empty object for that parity.
        if value.is_null() {
            value = serde_json::json!({});
        }
        if let Some(object) = value.as_object_mut() {
            // json.Unmarshal ignores null for non-pointer struct fields.
            object.retain(|_, value| !value.is_null());
        }
        let Ok(entry) = serde_json::from_value::<LogEntry>(value) else {
            continue;
        };
        entries.push(entry);
    }

    if limit > 0 {
        let keep_from = entries.len().saturating_sub(limit as usize);
        entries.drain(..keep_from);
    }
    Ok(entries)
}

fn filter_since(mut entries: Vec<LogEntry>, since: &str) -> Vec<LogEntry> {
    let Some(duration) = parse_since_duration(since) else {
        return entries;
    };
    let cutoff = OffsetDateTime::now_utc().unix_timestamp_nanos() - duration;
    entries.retain(|entry| {
        symvault_sync::GoTime::parse_rfc3339(&entry.timestamp)
            .ok()
            .and_then(|stamp| OffsetDateTime::parse(&stamp.to_rfc3339_nano(), &Rfc3339).ok())
            .is_some_and(|timestamp| timestamp.unix_timestamp_nanos() >= cutoff)
    });
    entries
}

fn parse_since_duration(value: &str) -> Option<i128> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if matches!(value, "0" | "+0" | "-0") {
        return Some(0);
    }
    if let Some(days) = value.strip_suffix('d') {
        // Go's ParseHumanDuration delegates this branch to fmt.Sscanf("%d"),
        // which consumes a leading signed integer and ignores a trailing
        // suffix (for example, 1.5d is interpreted as one day).
        let end = days
            .char_indices()
            .find(|(index, character)| {
                !character.is_ascii_digit()
                    && !(*index == 0 && matches!(character, '+' | '-'))
            })
            .map_or(days.len(), |(index, _)| index);
        let days = days[..end].parse::<i64>().ok()?;
        return (days >= 0)
            .then_some(i128::from(days))
            .and_then(|days| days.checked_mul(86_400_000_000_000));
    }
    let nanos = parse_duration_nanos(value)?;
    (nanos >= 0).then_some(nanos)
}

fn render_json(entries: &[LogEntry], output: &mut impl Write) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(entries).map_err(|error| error.to_string())?;
    let mut escaped = Vec::new();
    symvault_gojson::GoFormatter
        .write_string_fragment(&mut escaped, &rendered)
        .map_err(|error| error.to_string())?;
    output
        .write_all(&escaped)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|error| error.to_string())
}

fn render_table(entries: &[LogEntry], output: &mut impl Write) -> Result<(), String> {
    writeln!(output, "{:<26} {:<20} {:<8} DETAILS", "TIMESTAMP", "ACTION", "OK")
        .map_err(|error| error.to_string())?;
    for entry in entries {
        let ok = if entry.ok { "✓" } else { "✗" };
        let mut detail = entry.path.clone();
        if !entry.field.is_empty() {
            detail.push(':');
            detail.push_str(&entry.field);
        }
        if !entry.reason.is_empty() {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&entry.reason);
        }
        if detail.is_empty() {
            detail.push('-');
        }
        writeln!(output, "{:<26} {:<20} {:<8} {}", entry.timestamp, entry.action, ok, detail)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_agent_name_like_go() {
        assert_eq!(sanitize_agent_name("../a\\b"), "__a_b");
    }

    #[test]
    fn non_positive_limits_are_unbounded() {
        assert!(read_audit_log(Path::new("/definitely/missing"), 0).is_err());
        assert_eq!(parse_since_duration(" 24h "), Some(86_400_000_000_000));
        assert_eq!(parse_since_duration("1.5d"), Some(86_400_000_000_000));
        assert_eq!(parse_since_duration("-1h"), None);
    }
}
