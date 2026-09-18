//! Read-only scoped-token listing for one agent.

use std::{io::Write, path::Path};

use super::agent_list_commands::{TokenEntry, load_tokens};

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
        "{:<22} {:<16} {:<14} {:<28} {:<20} {}",
        "ID", "LABEL", "AGENT", "TOOLS", "EXPIRES AT", "STATUS"
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
