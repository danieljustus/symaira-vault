//! Read-only audit display; callers supply the home directory explicitly.
use serde_json::ser::Formatter;
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    path::Path,
};
use symvault_core::config::parse_duration_nanos;
use symvault_store::audit::LogEntry;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[allow(clippy::too_many_arguments)] // Direct CLI flag projection.
pub fn view(
    home: &Path,
    agent: &str,
    tail: i64,
    since: &str,
    failed: bool,
    json: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    if agent.contains(['/', '\\']) || agent.contains("..") || agent == "." {
        return Err("invalid agent name".into());
    }
    if tail < 0 {
        return Err("tail must not be negative".into());
    }
    let path = home.join(".symvault").join(format!("audit-{agent}.log"));
    let file = match fs::File::open(path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot open audit log: {error}")),
    };
    let mut entries = Vec::new();
    if let Some(file) = file {
        let mut reader = io::BufReader::new(file);
        let mut line = Vec::new();
        loop {
            line.clear();
            // Go's Scanner stops at its 64 KiB token ceiling, and this caller
            // returns the preceding records without reporting Scanner.Err.
            let read = (&mut reader).take(65_536).read_until(b'\n', &mut line);
            match read {
                Ok(0) | Err(_) => break,
                _ => {}
            }
            if line.len() >= 65_536 && line.last() != Some(&b'\n') {
                break;
            }
            if let Ok(mut value) =
                serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&line))
            {
                if value.is_null() {
                    value = serde_json::json!({});
                }
                if let Some(object) = value.as_object_mut() {
                    object.retain(|_, value| !value.is_null());
                }
                if let Ok(entry) = serde_json::from_value::<LogEntry>(value) {
                    entries.push(entry);
                }
            }
        }
    }
    let start = entries.len().saturating_sub(tail as usize);
    entries.drain(..start);
    let cutoff =
        since_duration(since).map(|nanos| OffsetDateTime::now_utc().unix_timestamp_nanos() - nanos);
    entries.retain(|entry| {
        (!failed || !entry.ok)
            && cutoff.is_none_or(|cutoff| {
                symvault_sync::GoTime::parse_rfc3339(&entry.timestamp)
                    .ok()
                    .and_then(|stamp| {
                        OffsetDateTime::parse(&stamp.to_rfc3339_nano(), &Rfc3339).ok()
                    })
                    .is_some_and(|stamp| stamp.unix_timestamp_nanos() >= cutoff)
            })
    });
    render(&entries, json, output)
}

fn since_duration(text: &str) -> Option<i128> {
    if let Some(days) = text.strip_suffix('d') {
        // fmt.Sscanf("%d") accepts a leading signed integer and ignores suffixes.
        let days = days.trim_start();
        let end = days
            .char_indices()
            .find(|(i, c)| !c.is_ascii_digit() && !(*i == 0 && matches!(c, '+' | '-')))
            .map_or(days.len(), |(i, _)| i);
        let days: i64 = days[..end].parse().ok()?;
        return Some(days.wrapping_mul(86_400_000_000_000) as i128);
    }
    if text == "0" || text == "+0" || text == "-0" {
        return Some(0);
    }
    parse_duration_nanos(text)
        .and_then(|n| i64::try_from(n).ok())
        .map(i128::from)
}

fn render(entries: &[LogEntry], json: bool, output: &mut impl Write) -> Result<(), String> {
    let result = (|| -> io::Result<()> {
        if json {
            let rendered = if entries.is_empty() {
                "null".into()
            } else {
                serde_json::to_string_pretty(entries)?
            };
            symvault_gojson::GoFormatter.write_string_fragment(output, &rendered)?;
            return writeln!(output);
        }
        if entries.is_empty() {
            return writeln!(output, "No audit entries found.");
        }
        writeln!(
            output,
            "{:<20} {:<12} {:<20} {:<10} {:<8} PATH",
            "TIME", "AGENT", "ACTION", "TRANSPORT", "STATUS"
        )?;
        writeln!(output, "{}", "-".repeat(90))?;
        for entry in entries {
            let ts = &entry.timestamp.as_bytes()[..entry.timestamp.len().min(20)];
            let action = truncate(entry.action.as_bytes(), 20, 17);
            let path = truncate(entry.path.as_bytes(), 30, 27);
            column(output, ts, 20)?;
            column(output, entry.agent.as_bytes(), 12)?;
            column(output, &action, 20)?;
            column(output, entry.transport.as_bytes(), 10)?;
            column(output, if entry.ok { b"OK" } else { b"FAIL" }, 8)?;
            output.write_all(&path)?;
            writeln!(output)?;
        }
        writeln!(output, "\nTotal: {} entries", entries.len())
    })();
    result.map_err(|error| error.to_string())
}

fn truncate(value: &[u8], limit: usize, prefix: usize) -> Vec<u8> {
    if value.len() <= limit {
        return value.to_vec();
    }
    [&value[..prefix], b"..."].concat()
}

fn column(output: &mut impl Write, mut bytes: &[u8], width: usize) -> io::Result<()> {
    output.write_all(bytes)?;
    let mut count = 0;
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                count += text.chars().count();
                break;
            }
            Err(error) => {
                count += std::str::from_utf8(&bytes[..error.valid_up_to()])
                    .unwrap()
                    .chars()
                    .count();
                let invalid = error
                    .error_len()
                    .unwrap_or(bytes.len() - error.valid_up_to());
                count += invalid;
                bytes = &bytes[error.valid_up_to() + invalid..];
            }
        }
    }
    output.write_all(" ".repeat(width.saturating_sub(count) + 1).as_bytes())
}
