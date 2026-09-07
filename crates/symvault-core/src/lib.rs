#![deny(unsafe_code)]

//! Language-neutral domain contracts for the staged Symaira Vault Rust port.

use symaira_core_version::new as new_version;

pub mod error;
pub mod password;
pub mod policy;
pub mod quota;
pub mod redact;
pub mod secret_ref;
pub mod tier;
pub mod totp;

/// Public binary and protocol tool name.
pub const TOOL_NAME: &str = "symvault";

/// Renders the exact plain-text version contract.
///
/// ```
/// assert_eq!(symvault_core::render_version_text("dev"), "symvault dev\n");
/// ```
#[must_use]
pub fn render_version_text(version: &str) -> String {
    format!("{}\n", new_version(TOOL_NAME, version, 1))
}

/// Renders the exact schema-v1 JSON version contract.
///
/// # Errors
///
/// Returns an error only when JSON serialization fails.
pub fn render_version_json(version: &str) -> Result<String, serde_json::Error> {
    let mut output = String::from_utf8(new_version(TOOL_NAME, version, 1).json()?.to_vec())
        .expect("serde_json always returns UTF-8");
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
