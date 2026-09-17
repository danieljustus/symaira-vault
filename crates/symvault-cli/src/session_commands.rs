//! Pure session command operations for the CLI dispatcher.
//!
//! The dispatcher owns vault resolution, initialization checks, and native
//! keyring construction. This module only consumes those resolved values so
//! it can be tested without a real keychain. Interactive unlock remains at
//! that boundary until the platform keyring and secure input are wired into
//! the Rust CLI.

use serde::{Deserialize, Serialize};
use std::path::Path;
use symvault_core::{config::AuthMethod, session::SessionManager};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheStatus {
    pub backend: String,
    pub persistent: bool,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthStatus {
    pub vault: String,
    pub method: String,
    #[serde(rename = "touchIDAvailable")]
    pub touch_id_available: bool,
    pub cache: CacheStatus,
    pub keyring_health: String,
}

/// Builds the status document used by `auth status`.
pub fn auth_status(
    vault: &Path,
    method: AuthMethod,
    cache: CacheStatus,
    touch_id_available: bool,
) -> Result<AuthStatus, String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    let keyring_health = if cache.persistent {
        "available"
    } else {
        "unavailable"
    };
    Ok(AuthStatus {
        vault: vault.to_owned(),
        method: method.as_str().to_owned(),
        touch_id_available,
        cache,
        keyring_health: keyring_health.to_owned(),
    })
}

/// Renders the Go auth-status contract. The Go command treats every format
/// other than JSON as its human-readable status view.
pub fn render_status(
    status: &AuthStatus,
    output_format: &str,
    json_flag: bool,
    quiet: bool,
) -> Result<String, String> {
    if quiet {
        return Ok(String::new());
    }
    if json_flag || output_format == "json" {
        let mut rendered = serde_json::to_string(status).map_err(|e| e.to_string())?;
        rendered.push('\n');
        return Ok(rendered);
    }
    Ok(format!(
        "Vault: {}\nAuth method: {}\nTouch ID available: {}\nSession cache: {} (persistent: {})\nKeyring health: {}\n",
        status.vault,
        status.method,
        status.touch_id_available,
        status.cache.backend,
        status.cache.persistent,
        status.keyring_health,
    ))
}

/// Clears passphrase, identity, and wrapping-key cache entries for a vault.
/// The caller is responsible for clearing any in-memory search index.
pub fn lock(manager: &SessionManager, vault: &Path, quiet: bool) -> Result<String, String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    manager
        .revoke(vault)
        .map_err(|error| format!("cannot clear session: {error}"))?;
    if quiet {
        Ok(String::new())
    } else {
        Ok("Vault locked\n".to_owned())
    }
}

/// Reports whether either cached credential accepted by the Go CLI is active.
#[must_use]
pub fn session_active(manager: &SessionManager, vault: &Path) -> bool {
    let Some(vault) = vault.to_str() else {
        return false;
    };
    !manager.is_session_expired(vault) || !manager.is_identity_expired(vault)
}

/// Implements `unlock --check` without reading or printing credentials.
pub fn check(manager: &SessionManager, vault: &Path) -> Result<(), String> {
    if session_active(manager, vault) {
        Ok(())
    } else {
        Err("no active session".to_owned())
    }
}

/// Interactive unlock needs a real secure input and native keyring adapter.
/// Keeping this explicit prevents a command from claiming authorization after
/// merely reading an unverified string or using the in-memory test backend.
pub const UNLOCK_UNAVAILABLE: &str =
    "interactive unlock is not yet available in the Rust CLI; use the Go CLI";
