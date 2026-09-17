//! Policy validation, inventory, application, and removal.
//!
//! Policy validation, application, and removal at the CLI boundary. These
//! operations only read policy YAML and mutate the vault's policy directory;
//! they do not unlock a vault or contact a service.

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use symvault_core::policy::Policy;
use symvault_sync::safeio;

fn load(path: &Path) -> Result<(Policy, Vec<u8>), String> {
    let bytes = fs::read(path).map_err(|error| format!("read policy file: {error}"))?;
    let policy: Policy =
        serde_yaml_ng::from_slice(&bytes).map_err(|error| format!("parse policy file: {error}"))?;
    policy
        .validate()
        .map_err(|error| format!("validate policy: {error}"))?;
    Ok((policy, bytes))
}

/// Validates one policy file and writes the Go-shaped human-readable result.
pub fn validate(path: &Path, output: &mut impl Write) -> Result<(), String> {
    let policy = match load(path) {
        Ok((policy, _)) => policy,
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

/// Validates and applies a policy file below the vault's policy directory.
pub fn apply(root: &Path, source: &Path, output: &mut impl Write) -> Result<(), String> {
    let (policy, source_bytes) = match load(source) {
        Ok(loaded) => loaded,
        Err(error) => {
            writeln!(
                output,
                "❌ Policy validation failed for {}",
                source.display()
            )
            .map_err(|write_error| write_error.to_string())?;
            return Err(error);
        }
    };
    let name = source
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "policy source must have a valid file name".to_owned())?;
    let destination = safe_policy_path(&root.join("policies"), name)?;
    ensure_policy_directory(destination.parent().expect("policy destination parent"))?;
    safeio::write_atomic(&destination, &source_bytes)
        .map_err(|error| format!("write policy file: {error}"))?;
    writeln!(
        output,
        "✅ Policy {:?} applied ({} rules)",
        policy.version,
        policy.rules.len()
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Removes one named policy file from the vault's policy directory.
pub fn remove(root: &Path, name: &str, output: &mut impl Write) -> Result<(), String> {
    let directory = root.join("policies");
    let destination = safe_policy_path(&directory, name)?;
    ensure_existing_policy_directory(&directory)?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("remove policy: refusing a symlinked target".to_owned());
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err("remove policy: target is not a regular file".to_owned());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("policy {name:?} not found"));
        }
        Err(error) => return Err(format!("remove policy: {error}")),
    }
    fs::remove_file(&destination).map_err(|error| format!("remove policy: {error}"))?;
    writeln!(output, "✅ Policy {name:?} removed").map_err(|error| error.to_string())?;
    Ok(())
}

fn safe_policy_path(directory: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!(
            "policy name {name:?} must be a bare file name without path separators"
        ));
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(|character| character < ' ')
    {
        return Err(format!(
            "policy name {name:?} must be a bare file name without path separators"
        ));
    }
    let path = Path::new(name);
    if path.file_name() != Some(OsStr::new(name)) {
        return Err(format!(
            "policy name {name:?} must be a bare file name without path separators"
        ));
    }
    let extension = path.extension().and_then(OsStr::to_str).unwrap_or("");
    if !matches!(extension.to_ascii_lowercase().as_str(), "yaml" | "yml") {
        return Err(format!("policy name {name:?} must end in .yaml or .yml"));
    }
    let destination = directory.join(name);
    if destination.parent() != Some(directory) {
        return Err(format!(
            "policy name {name:?} escapes the policies directory"
        ));
    }
    Ok(destination)
}

fn ensure_policy_directory(directory: &Path) -> Result<(), String> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("create policies directory: refusing a symlinked directory".to_owned());
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err("create policies directory: target is not a directory".to_owned());
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("create policies directory: {error}")),
    }
    safeio::create_dir_all(directory)
        .map_err(|error| format!("create policies directory: {error}"))?;
    ensure_existing_policy_directory(directory)
}

fn ensure_existing_policy_directory(directory: &Path) -> Result<(), String> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("policies directory is a symlink".to_owned())
        }
        Ok(_) => Err("policies directory is not a directory".to_owned()),
        Err(error) => Err(format!("read policies directory: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_POLICY: &[u8] =
        b"version: v1\nrules:\n  - name: allow-read\n    priority: 10\n    action: allow\n";

    #[test]
    fn invalid_apply_preserves_existing_policy() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("dev.yaml");
        let destination = fixture.path().join("vault/policies/dev.yaml");
        fs::create_dir_all(destination.parent().expect("policy parent")).expect("policy dir");
        fs::write(&source, b"rules: [").expect("invalid policy");
        fs::write(&destination, b"original policy").expect("existing policy");
        let root = fixture.path().join("vault");

        let result = apply(&root, &source, &mut Vec::new());

        assert!(result.is_err());
        assert_eq!(
            fs::read(destination).expect("existing policy"),
            b"original policy"
        );
    }

    #[test]
    fn policy_destination_names_match_go_safety_contract() {
        let directory = Path::new("vault/policies");
        for name in ["dev.yaml", "dev.yml", "DEV.YAML"] {
            assert!(safe_policy_path(directory, name).is_ok(), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "../identity.age",
            "sub/dev.yaml",
            "/etc/dev.yaml",
            "dev",
            "identity.age",
            "dev\0.yaml",
        ] {
            assert!(safe_policy_path(directory, name).is_err(), "{name:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn apply_rejects_destination_symlink_without_overwriting_target() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("vault");
        let policies = root.join("policies");
        fs::create_dir_all(&policies).expect("policy dir");
        let source = fixture.path().join("dev.yaml");
        fs::write(&source, VALID_POLICY).expect("source policy");
        let outside = fixture.path().join("outside");
        fs::write(&outside, b"sentinel").expect("outside target");
        std::os::unix::fs::symlink(&outside, policies.join("dev.yaml")).expect("destination link");

        let result = apply(&root, &source, &mut Vec::new());

        assert!(result.is_err());
        assert_eq!(fs::read(outside).expect("outside target"), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn remove_unlinks_hardlink_without_rewriting_shared_contents() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("vault");
        let policies = root.join("policies");
        fs::create_dir_all(&policies).expect("policy dir");
        let outside = fixture.path().join("outside");
        let destination = policies.join("dev.yaml");
        fs::write(&outside, b"shared policy bytes").expect("outside file");
        fs::hard_link(&outside, &destination).expect("hard link");

        remove(&root, "dev.yaml", &mut Vec::new()).expect("remove policy");

        assert!(!destination.exists());
        assert_eq!(
            fs::read(outside).expect("outside file"),
            b"shared policy bytes"
        );
    }
}
