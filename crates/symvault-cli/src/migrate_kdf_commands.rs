//! KDF migration for an existing vault identity.
//!
//! The command dispatcher owns prompting and session lookup.  This module is
//! the mutation boundary: it accepts the already-unlocked identity and
//! passphrase, prepares every fallible input first, and only then replaces the
//! encrypted identity and reconciles the config.

use std::path::Path;

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
    /// Historical Argon2 parameters or write configuration need explicit migration.
    NeedsResourceMigration,
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
        EnvelopeFormat::Argon2id => {
            let needs_header =
                symvault_crypto::inspect_argon2id_policy(&raw).map_err(|e| e.to_string())?;
            let needs_config =
                match safeio::read(&root.join("config.yaml")).map_err(|e| e.to_string())? {
                    Some(raw) => symvault_core::config::Config::load_from_bytes(&raw)
                        .map_err(|e| e.to_string())?
                        .vault
                        .is_some_and(|v| {
                            v.argon2id_time > 4
                                || v.argon2id_memory > 128 * 1024
                                || v.argon2id_threads > 4
                        }),
                    None => false,
                };
            if needs_header || needs_config {
                MigrationResult::NeedsResourceMigration
            } else {
                MigrationResult::AlreadyArgon2id
            }
        }
        EnvelopeFormat::Scrypt => {
            let config = safeio::read(&root.join("config.yaml")).map_err(|e| e.to_string())?;
            if config
                .as_ref()
                .map(|raw| symvault_core::config::Config::load_from_bytes(raw))
                .transpose()
                .map_err(|e| e.to_string())?
                .and_then(|c| c.vault)
                .is_some_and(|v| {
                    v.argon2id_time > 4 || v.argon2id_memory > 128 * 1024 || v.argon2id_threads > 4
                })
            {
                MigrationResult::NeedsResourceMigration
            } else {
                MigrationResult::NeedsMigration
            }
        }
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
            EnvelopeFormat::Argon2id => {
                if inspect_identity(root)? == MigrationResult::NeedsResourceMigration {
                    return Err("argon2id resource policy: use migrate kdf --allow-legacy-kdf for a historical identity".to_owned());
                }
                MigrationResult::AlreadyArgon2id
            }
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
        return Err(
            "unlock vault identity: cached identity does not match identity.age".to_owned(),
        );
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
    if symvault_crypto::recipient_string(&verified) != symvault_crypto::recipient_string(identity) {
        return Err("verify argon2id identity: identity mismatch".to_owned());
    }

    let backup_path = root.join("identity.age.bak");
    if let Err(error) = safeio::write_atomic(&backup_path, &original) {
        return Err(format!("write identity backup: {error}"));
    }
    if let Err(error) = safeio::write_atomic(&identity_path, &replacement) {
        let restore = safeio::write_atomic(&identity_path, &original);
        return Err(format_write_failure(
            "write migrated identity",
            error,
            restore,
        ));
    }

    if let Some(config_bytes) = config_update.bytes
        && let Err(error) = safeio::write_atomic(&config_path, &config_bytes)
    {
        let restore = safeio::write_atomic(&identity_path, &original);
        return Err(format_write_failure(
            "write migrated config",
            error,
            restore,
        ));
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
    // Use the shared loader as the semantic validator before changing the
    // generic YAML value. This also rejects multi-document streams.
    symvault_core::config::Config::load_from_bytes(&raw)
        .map_err(|error| format!("load config: {error}"))?;
    let params = argon2id_params_from_config(&raw)?;
    // Mutate the generic YAML value so flow-style mappings, anchors, and
    // multi-line scalar values cannot be mistaken for a single source line.
    // Unlike the typed Config serializer, this retains unknown configuration
    // fields. Formatting/comments may be normalized, as the Go config writer
    // also serializes the validated configuration rather than patching text.
    let mut expected: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(&raw).map_err(|error| format!("load config: {error}"))?;
    let Some(root) = expected.as_mapping_mut() else {
        return Ok(ConfigUpdate {
            bytes: Some(raw),
            params,
        });
    };
    let Some(vault) = root
        .get_mut("vault")
        .and_then(|value| value.as_mapping_mut())
    else {
        return Ok(ConfigUpdate {
            bytes: Some(raw),
            params,
        });
    };
    vault.remove("scrypt_work_factor");
    vault.insert(
        serde_yaml_ng::Value::String("format_version".to_owned()),
        serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(2)),
    );
    let rendered =
        serde_yaml_ng::to_string(&expected).map_err(|error| format!("render config: {error}"))?;
    let reparsed: serde_yaml_ng::Value = serde_yaml_ng::from_slice(rendered.as_bytes())
        .map_err(|error| format!("validate rendered config: {error}"))?;
    if reparsed != expected {
        return Err("validate rendered config: semantic value changed".to_owned());
    }
    symvault_core::config::Config::load_from_bytes(rendered.as_bytes())
        .map_err(|error| format!("validate rendered config: {error}"))?;
    let mut rendered = rendered;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(ConfigUpdate {
        bytes: Some(rendered.into_bytes()),
        params,
    })
}

fn argon2id_params_from_config(raw: &[u8]) -> Result<Argon2idParams, String> {
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(raw).map_err(|error| format!("load config: {error}"))?;
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
    params.memory_kib = config_u32(
        vault,
        "argon2id_memory",
        19_456,
        2_097_152,
        params.memory_kib,
    )?;
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

/// Explicit local migration: historical reads stay exclusive, defaults remain
/// unchanged, and both original files are retained without replacing old backups.
pub fn migrate_resource_policy(root: &Path, passphrase: &SecretBytes) -> Result<(), String> {
    let lock = safeio::open_append(&root.join(".lock")).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(format!("lock KDF migration: {error}")),
        }
    }
    migrate_resource_policy_locked(root, passphrase, &mut safeio::write_atomic)
}

fn migrate_resource_policy_locked(
    root: &Path,
    passphrase: &SecretBytes,
    replace: &mut impl FnMut(&Path, &[u8]) -> Result<(), safeio::SafeIoError>,
) -> Result<(), String> {
    let identity_path = root.join("identity.age");
    let original = safeio::read_bounded(&identity_path, 1024 * 1024)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "identity.age is missing".to_owned())?;
    let identity = if symvault_crypto::detect_envelope(&original) == EnvelopeFormat::Scrypt {
        decrypt_identity(&original, passphrase)
    } else {
        symvault_crypto::decrypt_identity_for_legacy_kdf_migration(&original, passphrase)
    }
    .map_err(|e| format!("unlock historical identity: {e}"))?;
    let config_path = root.join("config.yaml");
    let config_original =
        safeio::read_bounded(&config_path, 1024 * 1024).map_err(|e| e.to_string())?;
    let config_replacement = config_original
        .as_ref()
        .map(|raw| {
            symvault_core::config::Config::load_from_bytes(raw)
                .map_err(|e| format!("load config: {e}"))?;
            let mut document: serde_yaml_ng::Value =
                serde_yaml_ng::from_slice(raw).map_err(|e| e.to_string())?;
            if document.is_null() {
                document = serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new());
            }
            let root = document
                .as_mapping_mut()
                .ok_or_else(|| "config must be a mapping".to_owned())?;
            let section = root
                .entry(serde_yaml_ng::Value::String("vault".to_owned()))
                .or_insert_with(|| serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new()));
            if section.is_null() {
                *section = serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new());
            }
            let vault = section
                .as_mapping_mut()
                .ok_or_else(|| "config vault must be a mapping".to_owned())?;
            for (name, value) in [
                ("format_version", 2),
                ("argon2id_time", 3),
                ("argon2id_memory", 65536),
                ("argon2id_threads", 4),
            ] {
                vault.insert(
                    serde_yaml_ng::Value::String(name.to_owned()),
                    serde_yaml_ng::Value::Number(value.into()),
                );
            }
            vault.remove("scrypt_work_factor");
            let rendered = serde_yaml_ng::to_string(&document)
                .map_err(|e| e.to_string())?
                .into_bytes();
            symvault_core::config::Config::load_from_bytes(&rendered).map_err(|e| e.to_string())?;
            Ok::<_, String>(rendered)
        })
        .transpose()?;
    let replacement = encrypt_identity_argon2id(&identity, passphrase, Argon2idParams::default())
        .map_err(|e| e.to_string())?;
    let verified = decrypt_identity(&replacement, passphrase).map_err(|e| e.to_string())?;
    if symvault_crypto::recipient_string(&identity) != symvault_crypto::recipient_string(&verified)
    {
        return Err("verify replacement identity failed".to_owned());
    }
    retain_resource_backup(&identity_path.with_extension("age.bak"), &original)?;
    if let Some(raw) = &config_original {
        retain_resource_backup(&root.join("config.yaml.bak"), raw)?;
    }
    if safeio::read(&identity_path)
        .map_err(|e| e.to_string())?
        .as_ref()
        != Some(&original)
        || safeio::read(&config_path).map_err(|e| e.to_string())? != config_original
    {
        return Err("identity or config changed during KDF migration".to_owned());
    }
    replace(&identity_path, &replacement).map_err(|e| e.to_string())?;
    if let Some(rendered) = config_replacement
        && let Err(error) = replace(&config_path, &rendered)
    {
        let restore = replace(&identity_path, &original);
        let config_restore = config_original
            .as_ref()
            .map(|raw| replace(&config_path, raw))
            .transpose();
        let detail = format_write_failure("write migrated config", error, restore);
        return Err(match config_restore {
            Ok(_) => detail,
            Err(error) => format!("{detail}; restore config: {error}"),
        });
    }
    Ok(())
}

fn retain_resource_backup(path: &Path, original: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut staged = tempfile::Builder::new()
        .prefix(".symvault-kdf-backup-")
        .tempfile_in(
            path.parent()
                .ok_or_else(|| "backup parent missing".to_owned())?,
        )
        .map_err(|e| e.to_string())?;
    staged
        .write_all(original)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    match staged.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if safeio::read(path).map_err(|e| e.to_string())?.as_deref() == Some(original) {
                Ok(())
            } else {
                Err("existing KDF migration backup differs; preserve it before retrying".to_owned())
            }
        }
        Err(error) => Err(format!("write migration backup: {error}")),
    }
}
