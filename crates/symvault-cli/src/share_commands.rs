//! Read-only display of MCP share grants.
//!
//! The share store is loaded by `symvault-store`; this module only projects
//! its records into the formats emitted by Go's `share list` command.

use std::{io::Write, path::Path};

use serde::Serialize;
use symvault_store::sharing::{SHARE_STORE_FILE, ShareFilter, ShareGrant, ShareStore};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// List share grants with the same exact filters and output formats as Go.
#[allow(clippy::too_many_arguments)] // Direct projection of the CLI's list flags.
pub(crate) fn list(
    root: &Path,
    format: &str,
    quiet: bool,
    status: &str,
    from: &str,
    to: &str,
    secret_path: &str,
    stdout: &mut impl Write,
) -> Result<(), String> {
    let store = ShareStore::read(root.join(SHARE_STORE_FILE))
        .map_err(|error| format!("load share store: {error}"))?;
    let filter = ShareFilter {
        status: (!status.is_empty()).then(|| status.to_owned()),
        from_agent: from.to_owned(),
        to_agent: to.to_owned(),
        secret_path: secret_path.to_owned(),
    };
    let grants = store.list(
        (filter.status.is_some()
            || !filter.from_agent.is_empty()
            || !filter.to_agent.is_empty()
            || !filter.secret_path.is_empty())
        .then_some(&filter),
    );

    if quiet {
        return Ok(());
    }

    match format {
        "" | "text" => write_text(&grants, status, from, to, secret_path, stdout),
        "json" => write_json(&grants, stdout),
        "yaml" => write_yaml(&grants, stdout),
        // Go routes every non-text output through PrintResult. The top-level
        // parser normally limits this value; retain a fail-closed helper API.
        other => Err(format!(
            "unknown output format: {other:?} (valid: text, json, yaml)"
        )),
    }
}

fn write_text(
    grants: &[ShareGrant],
    status: &str,
    from: &str,
    to: &str,
    secret_path: &str,
    output: &mut impl Write,
) -> Result<(), String> {
    if grants.is_empty() {
        return writeln!(output, "No share grants found.").map_err(|error| error.to_string());
    }

    writeln!(
        output,
        "{:<22} {:<18} {:<18} {:<28} {:<8} {:<10} {:<16} EXPIRES",
        "ID", "FROM", "TO", "PATH", "FIELD", "STATUS", "CREATED"
    )
    .map_err(|error| error.to_string())?;
    for grant in grants {
        let display_status = display_status(grant);
        let field = if grant.secret_field.is_empty() {
            "-"
        } else {
            grant.secret_field.as_str()
        };
        let expires = grant
            .expires_at
            .as_deref()
            .map_or_else(|| "never".to_owned(), display_timestamp);
        writeln!(
            output,
            "{:<22} {:<18} {:<18} {:<28} {:<8} {:<10} {:<16} {}",
            grant.id,
            grant.from_agent,
            grant.to_agent,
            sanitize_terminal(&grant.secret_path),
            field,
            display_status,
            display_timestamp(&grant.created_at),
            expires
        )
        .map_err(|error| error.to_string())?;
    }

    writeln!(output).map_err(|error| error.to_string())?;
    let has_filter =
        !status.is_empty() || !from.is_empty() || !to.is_empty() || !secret_path.is_empty();
    if has_filter {
        writeln!(
            output,
            "{} grant(s) match the current filter.",
            grants.len()
        )
    } else {
        writeln!(output, "{} grant(s) total.", grants.len())
    }
    .map_err(|error| error.to_string())
}

fn write_json(grants: &[ShareGrant], output: &mut impl Write) -> Result<(), String> {
    // share list uses cli.PrintResult's SetEscapeHTML(false), unlike the
    // default encoding/json marshaler used by MCP wire payloads. The Go
    // encoder still escapes JavaScript line separators.
    let encoded = serde_json::to_string(grants)
        .map_err(|error| error.to_string())?
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    writeln!(output, "{encoded}").map_err(|error| error.to_string())
}

#[derive(Serialize)]
struct YamlGrant<'a> {
    id: &'a str,
    fromagent: &'a str,
    toagent: &'a str,
    secretpath: &'a str,
    secretfield: &'a str,
    nonce: &'a str,
    status: &'a str,
    createdat: &'a str,
    expiresat: Option<&'a str>,
    approvedat: Option<&'a str>,
    revokedat: Option<&'a str>,
    approvedby: &'a str,
    ttl: String,
}

fn write_yaml(grants: &[ShareGrant], output: &mut impl Write) -> Result<(), String> {
    let values: Vec<_> = grants
        .iter()
        .map(|grant| YamlGrant {
            id: &grant.id,
            fromagent: &grant.from_agent,
            toagent: &grant.to_agent,
            secretpath: &grant.secret_path,
            secretfield: &grant.secret_field,
            nonce: &grant.nonce,
            status: &grant.status,
            createdat: &grant.created_at,
            expiresat: grant.expires_at.as_deref(),
            approvedat: grant.approved_at.as_deref(),
            revokedat: grant.revoked_at.as_deref(),
            approvedby: &grant.approved_by,
            ttl: format_duration(grant.ttl),
        })
        .collect();
    let encoded = serde_yaml_ng::to_string(&values).map_err(|error| error.to_string())?;
    let encoded = normalize_go_yaml_scalars(&encoded, &values)?;
    output
        .write_all(encoded.as_bytes())
        .map_err(|error| error.to_string())
}

struct YamlScalarFix {
    key: &'static str,
    serde: String,
    go: String,
}

/// `yaml.v3` and `serde_yaml_ng` agree on the document structure but choose
/// different spellings for a few scalar nodes. Apply corrections only to the
/// generated field and scalar that produced the mismatch; this keeps embedded
/// newlines and other scalar content under the dependency's YAML emitter.
fn normalize_go_yaml_scalars(encoded: &str, grants: &[YamlGrant<'_>]) -> Result<String, String> {
    let mut fixes = Vec::with_capacity(grants.len() * 12);
    for grant in grants {
        push_yaml_fix(&mut fixes, "id", grant.id)?;
        push_yaml_fix(&mut fixes, "fromagent", grant.fromagent)?;
        push_yaml_fix(&mut fixes, "toagent", grant.toagent)?;
        push_yaml_fix(&mut fixes, "secretpath", grant.secretpath)?;
        push_yaml_fix(&mut fixes, "secretfield", grant.secretfield)?;
        push_yaml_fix(&mut fixes, "nonce", grant.nonce)?;
        push_yaml_fix(&mut fixes, "status", grant.status)?;
        push_yaml_fix(&mut fixes, "createdat", grant.createdat)?;
        if let Some(value) = grant.expiresat {
            push_yaml_fix(&mut fixes, "expiresat", value)?;
        }
        if let Some(value) = grant.approvedat {
            push_yaml_fix(&mut fixes, "approvedat", value)?;
        }
        if let Some(value) = grant.revokedat {
            push_yaml_fix(&mut fixes, "revokedat", value)?;
        }
        push_yaml_fix(&mut fixes, "approvedby", grant.approvedby)?;
        push_yaml_fix(&mut fixes, "ttl", &grant.ttl)?;
    }

    let mut normalized = String::with_capacity(encoded.len());
    for line in encoded.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let Some(colon) = body.find(": ") else {
            normalized.push_str(line);
            continue;
        };
        let field = &body[..colon];
        // serde_yaml_ng emits this fixed struct with exactly two spaces for
        // mapping fields. Do not trim arbitrary indentation: a continuation
        // line inside a multiline scalar can itself contain `key: value`.
        let key = if let Some(key) = field.strip_prefix("  ") {
            if key.starts_with("  ") {
                continue;
            }
            key
        } else if let Some(key) = field.strip_prefix("- ") {
            key
        } else {
            continue;
        };
        let scalar = &body[colon + 2..];
        if let Some(fix) = fixes
            .iter()
            .find(|fix| fix.key == key && fix.serde == scalar)
        {
            normalized.push_str(&body[..colon + 2]);
            normalized.push_str(&fix.go);
            if line.ends_with('\n') {
                normalized.push('\n');
            }
        } else {
            normalized.push_str(line);
        }
    }
    Ok(normalized)
}

fn push_yaml_fix(
    fixes: &mut Vec<YamlScalarFix>,
    key: &'static str,
    value: &str,
) -> Result<(), String> {
    let serde = serde_yaml_ng::to_string(value)
        .map_err(|error| error.to_string())?
        .strip_suffix('\n')
        .unwrap_or_default()
        .to_owned();
    let mut go = serde.clone();
    if value.is_empty() && go == "''" {
        go = "\"\"".to_owned();
    } else if value
        .chars()
        .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
        && !value.ends_with(' ')
        && go.starts_with('\'')
        && go.ends_with('\'')
    {
        // libyaml pads a quoted scalar after a Unicode line separator. Go's
        // yaml.v3 does not. Remove exactly that emitter padding, preserving
        // any spaces that belong to the source value.
        let closing_quote = go.len() - 1;
        if let Some(trimmed) = go[..closing_quote].strip_suffix("    ") {
            go.truncate(trimmed.len());
            go.push('\'');
        }
    }
    if serde != go {
        fixes.push(YamlScalarFix { key, serde, go });
    }
    Ok(())
}

fn display_status(grant: &ShareGrant) -> String {
    if grant.expires_at.as_deref().is_some_and(|expires| {
        OffsetDateTime::parse(expires, &Rfc3339)
            .is_ok_and(|expires| OffsetDateTime::now_utc() > expires)
    }) {
        "expired".to_owned()
    } else {
        grant.status.clone()
    }
}

fn display_timestamp(timestamp: &str) -> String {
    timestamp
        .get(..16)
        .map_or_else(|| timestamp.to_owned(), |value| value.replace('T', " "))
}

fn format_duration(nanos: i64) -> String {
    if nanos == 0 {
        return "0s".to_owned();
    }
    let sign = if nanos < 0 { "-" } else { "" };
    let nanos = nanos.unsigned_abs();
    let seconds = nanos / 1_000_000_000;
    let fraction = nanos % 1_000_000_000;
    let hours = seconds / 3_600;
    let minutes = seconds % 3_600 / 60;
    let seconds = seconds % 60;
    if hours != 0 {
        return format!(
            "{sign}{hours}h{minutes}m{seconds}{}s",
            format_fraction(fraction)
        );
    }
    if minutes != 0 {
        return format!("{sign}{minutes}m{seconds}{}s", format_fraction(fraction));
    }
    if seconds != 0 {
        return format!("{sign}{seconds}{}s", format_fraction(fraction));
    }
    if nanos >= 1_000_000 {
        let millis = nanos / 1_000_000;
        let fraction = format_fraction((nanos % 1_000_000) * 1_000);
        format!("{sign}{millis}{fraction}ms")
    } else if nanos >= 1_000 {
        let micros = nanos / 1_000;
        let fraction = format_fraction((nanos % 1_000) * 1_000_000);
        format!("{sign}{micros}{fraction}µs")
    } else {
        format!("{sign}{nanos}ns")
    }
}

fn format_fraction(nanos: u64) -> String {
    if nanos == 0 {
        return String::new();
    }
    let mut fraction = format!("{nanos:09}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!(".{fraction}")
}

/// Match Go's terminal renderer for the path column without introducing a
/// second output dependency. JSON/YAML retain the original path bytes.
fn sanitize_terminal(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            match chars.next() {
                Some('[') => {
                    for character in chars.by_ref() {
                        if character.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(character) = chars.next() {
                        if character == '\u{7}' {
                            break;
                        }
                        if character == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) | None => {}
            }
        } else if (character >= '\u{20}' || matches!(character, '\t' | '\n' | '\r'))
            && character != '\u{7f}'
        {
            output.push(character);
        }
    }
    output
}
