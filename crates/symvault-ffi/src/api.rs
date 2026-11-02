//! The thirteen `pkg/mobilebind` functions as plain Rust.
//!
//! Errors are the exact texts the Go bridge returns (`Err(String)`); secrets
//! are returned in zeroizing containers.

use symvault_crypto::{
    SecretBytes, decrypt, decrypt_scrypt, encrypt, encrypt_scrypt, fingerprint,
    generate_identity as new_identity, recipient_string,
};
use zeroize::Zeroizing;

use crate::gotext::agehdr::{self, Identity as AgeIdentity};
use crate::gotext::bech32::{validate_identity, validate_recipient};
use crate::gotext::trim_space;
use crate::vault::{self, R, secret_text};

/// Go's default scrypt work factor for `EncryptWithPassphrase(…, 0)`.
const DEFAULT_SCRYPT_WORK_FACTOR: u8 = 18;
const PAYLOAD_PREFIX: &str = "read decrypted data";

/// `GenerateIdentity`.
pub fn generate_identity() -> R<Zeroizing<String>> {
    Ok(secret_text(&new_identity()))
}

/// `IdentityPublicKey`.
pub fn identity_public_key(identity: &str) -> R<String> {
    let identity =
        validate_identity(identity).map_err(|reason| format!("validate identity: {reason}"))?;
    Ok(recipient_string(&identity))
}

/// `PublicKeyFingerprint`.
#[must_use]
pub fn public_key_fingerprint(pubkey: &str) -> String {
    fingerprint(pubkey)
}

/// `EncryptWithPublicKey`.
pub fn encrypt_with_public_key(recipient: &str, plaintext: &[u8]) -> R<Vec<u8>> {
    let recipient =
        validate_recipient(recipient).map_err(|reason| format!("validate recipient: {reason}"))?;
    if plaintext.is_empty() {
        return Err("plaintext is empty".to_owned());
    }
    encrypt(plaintext, &[recipient]).map_err(|error| error.to_string())
}

/// `DecryptWithIdentity`.
pub fn decrypt_with_identity(identity: &str, ciphertext: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    let parsed =
        validate_identity(identity).map_err(|reason| format!("validate identity: {reason}"))?;
    if ciphertext.is_empty() {
        return Err("ciphertext is empty".to_owned());
    }
    match decrypt(ciphertext, &parsed) {
        Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
        Err(_) => {
            let key = trim_space(identity)
                .parse::<age::x25519::Identity>()
                .map_err(|_| "decryption failed".to_owned())?;
            Err(agehdr::explain(
                ciphertext,
                &AgeIdentity::X25519(&key),
                PAYLOAD_PREFIX,
            ))
        }
    }
}

/// `EncryptWithPassphrase`.
pub fn encrypt_with_passphrase(passphrase: &[u8], plaintext: &[u8]) -> R<Vec<u8>> {
    if passphrase.is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    if plaintext.is_empty() {
        return Err("plaintext is empty".to_owned());
    }
    encrypt_scrypt(
        plaintext,
        &SecretBytes::new(passphrase),
        DEFAULT_SCRYPT_WORK_FACTOR,
    )
    .map_err(|error| error.to_string())
}

/// `DecryptWithPassphrase`.
pub fn decrypt_with_passphrase(passphrase: &[u8], ciphertext: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    if passphrase.is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    if ciphertext.is_empty() {
        return Err("ciphertext is empty".to_owned());
    }
    match decrypt_scrypt(ciphertext, &SecretBytes::new(passphrase)) {
        Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
        Err(_) => Err(agehdr::explain(
            ciphertext,
            &AgeIdentity::Passphrase(passphrase),
            PAYLOAD_PREFIX,
        )),
    }
}

/// `InitVault`.
pub fn init_vault(vault_dir: &str, passphrase: &[u8]) -> R<()> {
    vault::init_vault(vault_dir, passphrase)
}

/// Sets (or, with an empty string, clears) the directory for the verified
/// pre-migration backup of a Go-created vault (data-safety decision D1). A
/// host without `$HOME`/`$XDG_STATE_HOME` of its own (the iOS app) must set it
/// before the first write; without it the gate falls back to the environment.
/// The directory is created `0700`; excluding it from iCloud backup is the
/// host's responsibility.
pub fn set_backup_dir(dir: &str) -> R<()> {
    let dir = (!dir.is_empty()).then(|| std::path::PathBuf::from(dir));
    if dir.as_ref().is_some_and(|d| !d.is_absolute()) {
        return Err("backup directory must be an absolute path".to_string());
    }
    symvault_sync::data_safety::set_backup_dir(dir);
    Ok(())
}

/// `OpenVaultWithPassphrase`.
pub fn open_vault_with_passphrase(vault_dir: &str, passphrase: &[u8]) -> R<Zeroizing<String>> {
    vault::open_with_passphrase(vault_dir, passphrase)
}

/// `ReadEntryJSON`.
pub fn read_entry_json(vault_dir: &str, entry_path: &str, identity: &str) -> R<Zeroizing<String>> {
    vault::read_entry_json(vault_dir, entry_path, identity)
}

/// `WriteEntryJSON`.
pub fn write_entry_json(
    vault_dir: &str,
    entry_path: &str,
    entry_json: &str,
    identity: &str,
) -> R<()> {
    vault::write_entry_json(vault_dir, entry_path, entry_json, identity)
}

/// `ListEntriesJSON`.
pub fn list_entries_json(vault_dir: &str, prefix: &str, identity: &str) -> R<String> {
    vault::list_entries_json(vault_dir, prefix, identity)
}

/// `VerifyManifestIntegrity`.
pub fn verify_manifest_integrity(vault_dir: &str, identity: &str) -> R<bool> {
    vault::verify_manifest(vault_dir, identity)
}
