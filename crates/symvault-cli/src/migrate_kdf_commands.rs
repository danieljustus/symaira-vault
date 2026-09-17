//! KDF migration for an existing vault identity.
//!
//! The command dispatcher owns prompting and session lookup.  This module is
//! the mutation boundary: it accepts the already-unlocked identity and
//! passphrase, prepares every fallible input first, and only then replaces the
//! encrypted identity and reconciles the config.

use std::{path::Path, str::FromStr};

use symvault_crypto::{
    Argon2idParams, EnvelopeFormat, Identity, SecretBytes, decrypt_identity,
    encrypt_identity_argon2id,
};
use symvault_sync::safeio;

/// Result of inspecting or migrating the on-disk identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationResult {
    /// The identity already uses the current KDF.
    AlreadyArgon2id,
    /// The identity uses the legacy scrypt KDF and needs migration.
    NeedsMigration,
    /// The file did not contain a recognized identity envelope.
    Unsupported,
    /// The legacy scrypt envelope was replaced and verified.
    Migrated,
}

/// Returns the KDF family encoded in `identity.age` without decrypting it.
pub fn inspect_identity(root: &Path) -> Result<MigrationResult, String> {
    let path = root.join("identity.age");
    let raw = safeio::read(&path)
        .map_err(|error| format!("read vault identity ({}): {error}", path.display()))?
        .ok_or_else(|| format!("read vault identity ({}): file not found", path.display()))?;
    Ok(match symvault_crypto::detect_envelope(&raw) {
        EnvelopeFormat::Argon2id => MigrationResult::AlreadyArgon2id,
        EnvelopeFormat::Scrypt => MigrationResult::NeedsMigration,
        EnvelopeFormat::Unknown => MigrationResult::Unsupported,
    })
}

/// Re-encrypts a legacy scrypt identity with Argon2id.
///
/// The returned [`MigrationResult::Migrated`] is emitted only after the new
/// envelope decrypts with the supplied passphrase and the config update has
/// been atomically written.  If a later write fails, the original identity is
/// restored from its in-memory bytes.  The backup is intentionally retained
/// after both success and rollback, matching the Go command's recovery aid.
pub fn migrate_kdf(
    root: &Path,
    identity: &Identity,
    passphrase: &SecretBytes,
) -> Result<MigrationResult, String> {
    let identity_path = root.join("identity.age");
    let original = safeio::read(&identity_path)
        .map_err(|error| format!("read vault identity: {error}"))?
        .ok_or_else(|| "read vault identity: file not found".to_owned())?;
    if symvault_crypto::detect_envelope(&original) != EnvelopeFormat::Scrypt {
        return Ok(match symvault_crypto::detect_envelope(&original) {
            EnvelopeFormat::Argon2id => MigrationResult::AlreadyArgon2id,
            EnvelopeFormat::Scrypt => unreachable!("checked above"),
            EnvelopeFormat::Unknown => MigrationResult::Unsupported,
        });
    }

    // Do not trust a cached identity blindly: the encrypted file is the
    // authority for the key being migrated.  This check also fails closed on
    // a wrong passphrase before creating the backup.
    let on_disk_identity = decrypt_identity(&original, passphrase)
        .map_err(|error| format!("unlock vault identity: {error}"))?;
    if symvault_crypto::recipient_string(&on_disk_identity)
        != symvault_crypto::recipient_string(identity)
    {
        return Err("unlock vault identity: cached identity does not match identity.age".to_owned());
    }

    // Parse and render config before the first identity mutation.  A malformed
    // config therefore cannot leave an identity backup behind or require a
    // best-effort rollback after the vault has already changed.
    let config_path = root.join("config.yaml");
    let config_update = prepare_config_update(&config_path)?;

    let replacement = encrypt_identity_argon2id(identity, passphrase, config_update.params)
        .map_err(|error| format!("encrypt identity with argon2id: {error}"))?;
    let verified = decrypt_identity(&replacement, passphrase)
        .map_err(|error| format!("verify argon2id identity: {error}"))?;
    if symvault_crypto::recipient_string(&verified) != symvault_crypto::recipient_string(identity)
    {
        return Err("verify argon2id identity: identity mismatch".to_owned());
    }

    let backup_path = root.join("identity.age.bak");
    if let Err(error) = safeio::write_atomic(&backup_path, &original) {
        return Err(format!("write identity backup: {error}"));
    }
    if let Err(error) = safeio::write_atomic(&identity_path, &replacement) {
        let restore = safeio::write_atomic(&identity_path, &original);
        return Err(format_write_failure("write migrated identity", error, restore));
    }

    if let Some(config_bytes) = config_update.bytes
        && let Err(error) = safeio::write_atomic(&config_path, &config_bytes)
    {
        let restore = safeio::write_atomic(&identity_path, &original);
        return Err(format_write_failure("write migrated config", error, restore));
    }
    Ok(MigrationResult::Migrated)
}

fn format_write_failure(
    operation: &str,
    error: impl std::fmt::Display,
    restore: Result<(), impl std::fmt::Display>,
) -> String {
    match restore {
        Ok(()) => format!("{operation}: {error}"),
        Err(restore_error) => format!("{operation}: {error}; restore identity: {restore_error}"),
    }
}

struct ConfigUpdate {
    bytes: Option<Vec<u8>>,
    params: Argon2idParams,
}

fn prepare_config_update(path: &Path) -> Result<ConfigUpdate, String> {
    let Some(raw) = safeio::read(path).map_err(|error| format!("read config: {error}"))? else {
        return Ok(ConfigUpdate {
            bytes: None,
            params: Argon2idParams::default(),
        });
    };
    // Use the shared loader as the semantic validator before yaml-edit
    // changes the document.  This also rejects multi-document streams.
    symvault_core::config::Config::load_from_bytes(&raw)
        .map_err(|error| format!("load config: {error}"))?;
    let params = argon2id_params_from_config(&raw)?;
    let source = std::str::from_utf8(&raw)
        .map_err(|error| format!("load config: invalid UTF-8: {error}"))?;
    let file = yaml_edit::YamlFile::from_str(source)
        .map_err(|error| format!("load config: {error}"))?;
    let document = file
        .documents()
        .next()
        .ok_or_else(|| "load config: missing YAML document".to_owned())?;
    use yaml_edit::path::YamlPath;
    if document.try_get_path("vault").is_err() {
        return Ok(ConfigUpdate {
            bytes: Some(raw),
            params,
        });
    }
    document
        .try_set_path("vault.format_version", yaml_edit::ScalarValue::from(2))
        .map_err(|error| format!("set vault.format_version: {error}"))?;
    // The Go writer omits this field after migration.  A missing path is
    // already the desired result, so only propagate errors for malformed
    // parent paths.
    let _ = document.try_remove_path("vault.scrypt_work_factor");
    let mut rendered = document.to_string();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(ConfigUpdate {
        bytes: Some(rendered.into_bytes()),
        params,
    })
}

fn argon2id_params_from_config(raw: &[u8]) -> Result<Argon2idParams, String> {
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_slice(raw)
        .map_err(|error| format!("load config: {error}"))?;
    let Some(root) = document.as_mapping() else {
        return Ok(Argon2idParams::default());
    };
    let Some(vault) = root.get(serde_yaml_ng::Value::String("vault".to_owned())) else {
        return Ok(Argon2idParams::default());
    };
    let Some(vault) = vault.as_mapping() else {
        return Ok(Argon2idParams::default());
    };
    let mut params = Argon2idParams::default();
    params.time = config_u32(vault, "argon2id_time", 2, 16, params.time)?;
    params.memory_kib = config_u32(vault, "argon2id_memory", 19_456, 2_097_152, params.memory_kib)?;
    params.threads = config_u32(vault, "argon2id_threads", 1, 16, params.threads)?;
    if params.memory_kib < 4 * params.threads {
        return Err(format!(
            "invalid vault.argon2id_memory: {} KiB must be at least 4*threads ({})",
            params.memory_kib,
            4 * params.threads
        ));
    }
    Ok(params)
}

fn config_u32(
    vault: &serde_yaml_ng::Mapping,
    name: &str,
    min: u32,
    max: u32,
    default: u32,
) -> Result<u32, String> {
    let Some(value) = vault.get(serde_yaml_ng::Value::String(name.to_owned())) else {
        return Ok(default);
    };
    let value = value
        .as_i64()
        .ok_or_else(|| format!("vault.{name} must be an integer"))?;
    if value == 0 {
        return Ok(default);
    }
    if value < i64::from(min) || value > i64::from(max) {
        return Err(format!(
            "invalid vault.{name}: {value} (expected {min}..={max})"
        ));
    }
    u32::try_from(value).map_err(|_| format!("invalid vault.{name}: {value}"))
}

#[cfg(test)]
#[path = "migrate_kdf_commands_tests.rs"]
mod tests;
