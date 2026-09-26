//! Offline dynamic-secret CLI behavior.
//!
//! The Go CLI currently creates a manager with no registered engines, so a
//! valid generate request unlocks the vault and then returns the manager's
//! engine-not-found error. Keep that observable behavior until a real Rust
//! engine backend is available.

use std::path::Path;

use crate::{device, require_initialized, resolve_vault};

pub(crate) fn generate(
    engine: Option<&str>,
    role: Option<&str>,
    _ttl: &str,
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
) -> Result<(), (u8, String, Option<String>)> {
    let mut missing = Vec::new();
    if engine.is_none() {
        missing.push("\"engine\"");
    }
    if role.is_none() {
        missing.push("\"role\"");
    }
    if !missing.is_empty() {
        return Err((
            1,
            format!("required flag(s) {} not set", missing.join(", ")),
            None,
        ));
    }

    let vault = resolve_vault(explicit_vault, profile).map_err(|error| (1, error, None))?;
    require_initialized(&vault).map_err(|error| {
        (
            3,
            error,
            Some(
                "Run 'symvault init' for a quick start, or 'symvault setup' for the guided wizard."
                    .into(),
            ),
        )
    })?;
    device::unlock_vault(&vault).map_err(|error| (1, error, None))?;
    Err((
        1,
        "generate dynamic secret: dynamic secret engine not found".into(),
        None,
    ))
}
