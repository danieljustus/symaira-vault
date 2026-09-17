//! Read-only policy validation and inventory.
//!
//! Policy application and removal remain dispatcher-owned mutations.  These
//! helpers only read YAML and the vault's policy directory, matching the
//! corresponding Go commands without unlocking a vault or contacting a
//! service.

use std::{fs, io::Write, path::Path};

use symvault_core::policy::Policy;

fn load(path: &Path) -> Result<Policy, String> {
    let bytes = fs::read(path).map_err(|error| format!("read policy file: {error}"))?;
    let policy: Policy =
        serde_yaml_ng::from_slice(&bytes).map_err(|error| format!("parse policy file: {error}"))?;
    policy
        .validate()
        .map_err(|error| format!("validate policy: {error}"))?;
    Ok(policy)
}

/// Validates one policy file and writes the Go-shaped human-readable result.
pub fn validate(path: &Path, output: &mut impl Write) -> Result<(), String> {
    let policy = match load(path) {
        Ok(policy) => policy,
        Err(error) => {
            writeln!(output, "❌ Policy validation failed for {}", path.display())
                .map_err(|write_error| write_error.to_string())?;
            return Err(error);
        }
    };

    writeln!(output, "✅ Policy {:?} is valid", policy.version)
        .map_err(|error| error.to_string())?;
    if !policy.description.is_empty() {
        writeln!(output, "   Description: {}", policy.description)
            .map_err(|error| error.to_string())?;
    }
    writeln!(output, "   Rules: {}", policy.rules.len()).map_err(|error| error.to_string())?;
    for rule in &policy.rules {
        writeln!(
            output,
            "   - {} (priority: {}, action: {})",
            rule.name, rule.priority, rule.action
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Lists policy files below `<root>/policies` in Go's sorted directory order.
pub fn list(root: &Path, output: &mut impl Write) -> Result<(), String> {
    let directory = root.join("policies");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            writeln!(output, "No policies directory found.")
                .map_err(|write_error| write_error.to_string())?;
            return Ok(());
        }
        Err(error) => return Err(format!("read policies directory: {error}")),
    };

    let entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read policies directory: {error}"))?;
    if entries.is_empty() {
        writeln!(output, "No policies applied.").map_err(|error| error.to_string())?;
        return Ok(());
    }

    let mut names = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read policies directory entry: {error}"))?;
        if !file_type.is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();

    for name in names {
        writeln!(output, "  - {name}").map_err(|error| error.to_string())?;
    }
    Ok(())
}
