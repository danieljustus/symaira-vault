#![deny(unsafe_code)]

//! Language-neutral domain contracts for the staged Symaira Vault Rust port.

use serde::Serialize;

/// Public binary and protocol tool name.
pub const TOOL_NAME: &str = "symvault";

/// Stable machine-readable version schema.
#[derive(Debug, Serialize)]
struct VersionDocument<'a> {
    tool: &'static str,
    version: &'a str,
    schema_version: u8,
}

/// Renders the exact plain-text version contract.
///
/// ```
/// assert_eq!(symvault_core::render_version_text("dev"), "symvault dev\n");
/// ```
#[must_use]
pub fn render_version_text(version: &str) -> String {
    format!("{TOOL_NAME} {version}\n")
}

/// Renders the exact schema-v1 JSON version contract.
///
/// # Errors
///
/// Returns an error only when JSON serialization fails.
pub fn render_version_json(version: &str) -> Result<String, serde_json::Error> {
    let document = VersionDocument {
        tool: TOOL_NAME,
        version,
        schema_version: 1,
    };
    let mut output = serde_json::to_string(&document)?;
    output.push('\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{render_version_json, render_version_text};

    #[test]
    fn text_contract_is_exact() {
        assert_eq!(render_version_text("v1.2.3"), "symvault v1.2.3\n");
    }

    #[test]
    fn json_contract_is_exact() {
        assert_eq!(
            render_version_json("dev").expect("serialize fixed version document"),
            "{\"tool\":\"symvault\",\"version\":\"dev\",\"schema_version\":1}\n"
        );
    }
}
