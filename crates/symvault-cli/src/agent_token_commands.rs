//! Scoped-token commands for one agent: read-only listing plus the `new`,
//! `revoke`, and `rotate` mutations.

use std::{io::Write, path::Path};

use symvault_store::token_registry;
use time::{Duration, OffsetDateTime};

use super::agent_list_commands::{TokenEntry, load_tokens};

/// Go's `ResolveTokenTTL` ignores its vault-dir parameter entirely and
/// always falls back to this constant when `--ttl` is absent; the
/// documented "defaults to mcp.scoped_token_ttl from config" behavior is
/// dead code in the Go binary today, so this mirrors what actually runs.
const DEFAULT_TOKEN_TTL: Duration = Duration::hours(24);

/// Lists the plaintext scoped-token registry entries owned by agent.
///
/// The Go command constructs a registry without an identity, so it reads the
/// legacy mcp-tokens.json path. Encrypted registry.age data therefore stays
/// outside this no-unlock command until the CLI has an identity-aware registry
/// adapter. Expired entries are removed from Go's in-memory listing before the
/// command filters by agent; empty-hash entries are discarded at load time.
pub(crate) fn list(
    root: &Path,
    agent: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut tokens: Vec<_> = load_tokens(root)?
        .into_iter()
        .filter(|token| !token.hash.is_empty() && token.agent_name == agent)
        .filter(|token| !is_expired(token))
        .collect();
    // Go ranges a map, whose order is deliberately unspecified. Stable Rust
    // output makes scripts reproducible; the differential normalizes rows.
    tokens.sort_by(|left, right| left.id.cmp(&right.id));

    if quiet {
        return Ok(());
    }
    if tokens.is_empty() {
        return writeln!(output, "No tokens found for agent {agent:?}.")
            .map_err(|error| error.to_string());
    }

    writeln!(
        output,
        "{:<22} {:<16} {:<14} {:<28} {:<20} STATUS",
        "ID", "LABEL", "AGENT", "TOOLS", "EXPIRES AT"
    )
    .map_err(|error| error.to_string())?;
    for token in tokens {
        let label = if token.label.is_empty() {
            "-"
        } else {
            &token.label
        };
        let agent = if token.agent_name.is_empty() {
            "-"
        } else {
            &token.agent_name
        };
        let tools = truncate_tools(
            &token
                .allowed_tools
                .as_deref()
                .unwrap_or_default()
                .join(", "),
        );
        let expires = token
            .expires_at
            .as_deref()
            .map_or_else(|| "never".to_owned(), format_expiry);
        let status = if token.revoked { "revoked" } else { "active" };
        writeln!(
            output,
            "{:<22} {:<16} {:<14} {:<28} {:<20} {}",
            token.id, label, agent, tools, expires, status
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn is_expired(token: &TokenEntry) -> bool {
    token.expires_at.as_deref().is_some_and(|timestamp| {
        super::agent_list_commands::timestamp_to_epoch(timestamp)
            < super::agent_list_commands::now_epoch()
    })
}

fn format_expiry(timestamp: &str) -> String {
    timestamp
        .get(..16)
        .map_or_else(|| timestamp.to_owned(), |prefix| prefix.replace('T', " "))
}

fn truncate_tools(tools: &str) -> String {
    if tools.len() <= 26 {
        return tools.to_owned();
    }
    // Go slices this field by bytes before appending "...". Registry tool
    // names are ASCII in the supported schema, so this preserves that wire
    // behavior without introducing a second formatter.
    tools
        .get(..23)
        .map_or_else(|| tools.to_owned(), |prefix| format!("{prefix}..."))
}

/// Creates a new scoped token for `agent`. Mirrors `newAgentTokenNewCmd`.
pub(crate) fn new(
    root: &Path,
    agent: &str,
    tools: Vec<String>,
    ttl: &str,
    label: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    if tools.is_empty() {
        return Err("at least one tool must be specified (use --tools '*')".to_owned());
    }
    let ttl = resolve_token_ttl(ttl)?;
    let request = token_registry::NewToken {
        label,
        allowed_tools: tools,
        agent_name: agent,
        ttl: Some(ttl),
        tool_registry_hash: "",
    };
    let (record, raw_token) = token_registry::create(root, &request, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    if quiet {
        return Ok(());
    }
    write_token_summary(
        output,
        "Token created successfully.",
        &record,
        &raw_token,
        true,
        true,
    )
}

/// Revokes one token owned by `agent`. Mirrors `newAgentTokenRevokeCmd`.
pub(crate) fn revoke(
    root: &Path,
    agent: &str,
    token_id: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let revoked = token_registry::revoke(root, agent, token_id, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    if !revoked {
        return Err(format!("token {token_id:?} not found or already revoked"));
    }
    if quiet {
        return Ok(());
    }
    writeln!(output, "Token {token_id} revoked successfully.").map_err(|error| error.to_string())
}

/// Revokes every active token for `agent` and creates a new one. Mirrors
/// `newAgentTokenRotateCmd`.
pub(crate) fn rotate(
    root: &Path,
    agent: &str,
    tools: Vec<String>,
    ttl: &str,
    label: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    if tools.is_empty() {
        return Err("at least one tool must be specified (use --tools '*')".to_owned());
    }
    let ttl = resolve_token_ttl(ttl)?;
    let request = token_registry::NewToken {
        label,
        allowed_tools: tools,
        agent_name: agent,
        ttl: Some(ttl),
        tool_registry_hash: "",
    };
    let (record, raw_token) = token_registry::rotate(root, &request, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    if quiet {
        return Ok(());
    }
    write_token_summary(
        output,
        "Token rotated successfully.",
        &record,
        &raw_token,
        false,
        false,
    )
}

fn write_token_summary(
    output: &mut impl Write,
    header: &str,
    record: &token_registry::TokenRecord,
    raw_token: &str,
    conditional_agent_line: bool,
    two_warning_lines: bool,
) -> Result<(), String> {
    let err = |error: std::io::Error| error.to_string();
    writeln!(output, "{header}").map_err(err)?;
    writeln!(output, "  ID:    {}", record.id).map_err(err)?;
    writeln!(output, "  Label: {}", record.label).map_err(err)?;
    if !conditional_agent_line || !record.agent_name.is_empty() {
        writeln!(output, "  Agent: {}", record.agent_name).map_err(err)?;
    }
    let tools = record
        .allowed_tools
        .as_deref()
        .unwrap_or_default()
        .join(", ");
    writeln!(output, "  Tools: {tools}").map_err(err)?;
    match record.expires_at.as_deref() {
        Some(expires_at) => {
            writeln!(output, "  Expires: {}", display_rfc3339(expires_at)).map_err(err)?
        }
        None => writeln!(output, "  Expires: never").map_err(err)?,
    }
    writeln!(output).map_err(err)?;
    writeln!(output, "Raw token (copy now — shown once): {raw_token}").map_err(err)?;
    writeln!(output).map_err(err)?;
    writeln!(
        output,
        "Warning: This is the only time the raw token is displayed."
    )
    .map_err(err)?;
    if two_warning_lines {
        writeln!(
            output,
            "         Store it securely — it cannot be retrieved later."
        )
        .map_err(err)?;
    }
    Ok(())
}

/// Renders the stored RFC3339Nano timestamp the way Go's
/// `time.Time.Format(time.RFC3339)` display call does: second precision,
/// with any sub-second fraction dropped (unlike the nanosecond-preserving
/// JSON storage format).
fn display_rfc3339(value: &str) -> String {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|parsed| {
            let parsed = parsed.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                parsed.year(),
                u8::from(parsed.month()),
                parsed.day(),
                parsed.hour(),
                parsed.minute(),
                parsed.second()
            )
        })
        .unwrap_or_else(|_| value.to_owned())
}

/// Mirrors `ResolveTokenTTL`: an empty `--ttl` always resolves to the
/// hardcoded default, since Go's own config-lookup branch is unreachable
/// dead code in the current binary (see `DEFAULT_TOKEN_TTL`).
fn resolve_token_ttl(ttl_flag: &str) -> Result<Duration, String> {
    if ttl_flag.is_empty() {
        return Ok(DEFAULT_TOKEN_TTL);
    }
    parse_human_duration(ttl_flag).map_err(|error| format!("invalid TTL {ttl_flag:?}: {error}"))
}

/// Mirrors `ParseHumanDuration`: a `d` suffix is Go's own day extension over
/// `time.ParseDuration`, which `parse_duration_nanos` already implements for
/// every other unit.
fn parse_human_duration(text: &str) -> Result<Duration, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_owned());
    }
    if let Some(days_text) = trimmed.strip_suffix('d') {
        let days = parse_days_number(days_text)?;
        if days < 0 {
            return Err("negative duration".to_owned());
        }
        return Ok(Duration::days(days));
    }
    let nanos = symvault_core::config::parse_duration_nanos(trimmed)
        .ok_or_else(|| format!("time: invalid duration {trimmed:?}"))?;
    if nanos < 0 {
        return Err("negative duration".to_owned());
    }
    let nanos = i64::try_from(nanos).map_err(|_| format!("time: invalid duration {trimmed:?}"))?;
    Ok(Duration::nanoseconds(nanos))
}

/// Mirrors Go's `fmt.Sscanf(s, "%d", &n)`: parses a leading optionally
/// signed integer and ignores any trailing text instead of rejecting it.
fn parse_days_number(text: &str) -> Result<i64, String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let negative = bytes.first() == Some(&b'-');
    if negative || bytes.first() == Some(&b'+') {
        index += 1;
    }
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == start {
        return Err(format!("invalid number {text:?}"));
    }
    let magnitude: i64 = text[start..index]
        .parse()
        .map_err(|_| format!("invalid number {text:?}"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_dir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn new_rejects_empty_tools_before_touching_the_vault() {
        let root = vault_dir();
        let mut output = Vec::new();
        let error = new(root.path(), "alpha", Vec::new(), "", "", false, &mut output)
            .expect_err("empty tools must be rejected");
        assert_eq!(
            error,
            "at least one tool must be specified (use --tools '*')"
        );
        assert!(!root.path().join("mcp-tokens.json").exists());
    }

    #[test]
    fn new_prints_go_shaped_summary_and_quiet_suppresses_all_output() {
        let root = vault_dir();
        let mut output = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["list_entries".into(), "get_entry".into()],
            "24h",
            "work",
            false,
            &mut output,
        )
        .expect("create token");
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("Token created successfully.\n"));
        assert!(text.contains("  ID:    tok-"));
        assert!(text.contains("  Label: work\n"));
        assert!(text.contains("  Agent: alpha\n"));
        assert!(text.contains("  Tools: list_entries, get_entry\n"));
        assert!(text.contains("  Expires: "));
        assert!(text.contains("Raw token (copy now — shown once): "));
        assert!(text.contains("Warning: This is the only time the raw token is displayed.\n"));
        assert!(text.contains("         Store it securely — it cannot be retrieved later.\n"));

        let mut quiet_output = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            true,
            &mut quiet_output,
        )
        .expect("quiet create token");
        assert!(quiet_output.is_empty());
    }

    #[test]
    fn new_never_expires_when_ttl_is_zero() {
        let root = vault_dir();
        let mut output = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "0s",
            "",
            false,
            &mut output,
        )
        .expect("create token with zero ttl");
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("  Expires: never\n"));
    }

    #[test]
    fn new_creates_a_second_token_for_the_same_agent_without_error() {
        let root = vault_dir();
        let mut first = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            false,
            &mut first,
        )
        .expect("first token");
        let mut second = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            false,
            &mut second,
        )
        .expect("duplicate agent still succeeds");
        assert_ne!(first, second);
    }

    #[test]
    fn revoke_matches_go_error_text_for_unknown_agent_unknown_token_and_already_revoked() {
        let root = vault_dir();
        let mut created = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            false,
            &mut created,
        )
        .expect("seed token");
        let created_text = String::from_utf8(created).unwrap();
        let token_id = created_text
            .lines()
            .find_map(|line| line.strip_prefix("  ID:    "))
            .expect("token id line")
            .to_owned();

        let mut output = Vec::new();
        let unknown_agent = revoke(root.path(), "beta", &token_id, false, &mut output)
            .expect_err("unknown agent must be rejected");
        assert_eq!(
            unknown_agent,
            format!("token {token_id:?} not found or already revoked")
        );

        let unknown_token = revoke(root.path(), "alpha", "tok-missing", false, &mut output)
            .expect_err("unknown token must be rejected");
        assert_eq!(
            unknown_token,
            "token \"tok-missing\" not found or already revoked"
        );

        revoke(root.path(), "alpha", &token_id, false, &mut output).expect("first revoke succeeds");
        let already_revoked = revoke(root.path(), "alpha", &token_id, false, &mut output)
            .expect_err("second revoke must be rejected");
        assert_eq!(
            already_revoked,
            format!("token {token_id:?} not found or already revoked")
        );
    }

    #[test]
    fn revoke_prints_go_text_and_quiet_suppresses_it() {
        let root = vault_dir();
        let mut created = Vec::new();
        new(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            false,
            &mut created,
        )
        .expect("seed token");
        let created_text = String::from_utf8(created).unwrap();
        let token_id = created_text
            .lines()
            .find_map(|line| line.strip_prefix("  ID:    "))
            .expect("token id line")
            .to_owned();

        let mut output = Vec::new();
        revoke(root.path(), "alpha", &token_id, false, &mut output).expect("revoke succeeds");
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("Token {token_id} revoked successfully.\n")
        );
    }

    #[test]
    fn rotate_output_has_unconditional_agent_line_and_one_warning_line() {
        let root = vault_dir();
        let mut output = Vec::new();
        rotate(
            root.path(),
            "alpha",
            vec!["*".into()],
            "",
            "",
            false,
            &mut output,
        )
        .expect("rotate creates a token for a brand-new agent");
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("Token rotated successfully.\n"));
        assert!(text.contains("  Agent: alpha\n"));
        assert!(text.contains("Warning: This is the only time the raw token is displayed.\n"));
        assert!(!text.contains("Store it securely"));
    }

    #[test]
    fn rotate_rejects_empty_tools_like_new() {
        let root = vault_dir();
        let mut output = Vec::new();
        let error = rotate(root.path(), "alpha", Vec::new(), "", "", false, &mut output)
            .expect_err("empty tools must be rejected");
        assert_eq!(
            error,
            "at least one tool must be specified (use --tools '*')"
        );
    }

    #[test]
    fn resolve_token_ttl_defaults_to_24h_and_wraps_parse_errors_like_go() {
        assert_eq!(resolve_token_ttl("").unwrap(), DEFAULT_TOKEN_TTL);
        assert_eq!(resolve_token_ttl("24h").unwrap(), Duration::hours(24));
        assert_eq!(resolve_token_ttl("7d").unwrap(), Duration::days(7));
        assert_eq!(resolve_token_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(
            resolve_token_ttl("garbage").unwrap_err(),
            "invalid TTL \"garbage\": time: invalid duration \"garbage\""
        );
        assert_eq!(
            resolve_token_ttl("-1h").unwrap_err(),
            "invalid TTL \"-1h\": negative duration"
        );
        assert_eq!(
            resolve_token_ttl("-3d").unwrap_err(),
            "invalid TTL \"-3d\": negative duration"
        );
    }

    #[test]
    fn display_rfc3339_drops_the_fraction_go_keeps_in_storage() {
        assert_eq!(
            display_rfc3339("2026-01-02T03:04:05.123456789Z"),
            "2026-01-02T03:04:05Z"
        );
        assert_eq!(
            display_rfc3339("2026-01-02T03:04:05Z"),
            "2026-01-02T03:04:05Z"
        );
    }
}
