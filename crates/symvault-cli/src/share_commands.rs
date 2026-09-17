//! Read-only display of MCP share grants.
//!
//! The share store is loaded by `symvault-store`; this module only projects
//! its records into the formats emitted by Go's `share list` command.

use std::{io::Write, path::Path};

use serde::Serialize;
use symvault_store::sharing::{SHARE_STORE_FILE, ShareFilter, ShareGrant, ShareStore};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// List share grants with the same exact filters and output formats as Go.
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
    let encoded = symvault_gojson::to_string(grants).map_err(|error| error.to_string())?;
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
    output
        .write_all(encoded.as_bytes())
        .map_err(|error| error.to_string())
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
    if nanos % 1_000_000 == 0 {
        format!("{sign}{}ms", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!("{sign}{}µs", nanos / 1_000)
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
