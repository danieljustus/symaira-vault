#![deny(unsafe_code)]

//! Age-compatible cryptographic primitives used before Rust storage exists.
//!
//! This crate deliberately has no filesystem or vault dependencies. It wraps the
//! reference `age` implementation for X25519 and scrypt, and implements the
//! Symaira Vault Argon2id recipient stanza exactly as the Go oracle does.

use std::{
    collections::HashSet,
    fmt,
    io::{Read, Write},
    iter,
};

use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ARGON2ID_TAG: &str = "argon2id";
const ARGON2ID_LABEL: &[u8] = b"symvault-argon2id-v1";
const KEY_BYTES: usize = 32;
const ARGON2ID_SALT_BYTES: usize = 16;
const MAX_ARGON2_TIME: u32 = 16;
const MAX_ARGON2_MEMORY: u32 = 2_097_152;
const MAX_ARGON2_THREADS: u32 = 16;
const MAX_SCRYPT_WORK_FACTOR: u8 = 22;
/// Maximum historical zero-key passphrase length accepted for recovery.
///
/// The legacy bug produced a short, fixed-size all-zero passphrase. Bounding
/// this input before constructing the zero-filled buffer prevents an attacker
/// from turning recovery into an unbounded allocation or Argon2 workload.
pub const MAX_ZERO_KEY_PASSPHRASE_LEN: usize = 1024;

/// Stable failure classifications. Messages never contain a passphrase or plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// The age header or KDF stanza is malformed.
    MalformedEnvelope,
    /// A key or passphrase did not authenticate the envelope.
    WrongPassphraseOrKey,
    /// A supplied KDF parameter exceeds the resource policy.
    ParameterBounds,
    /// The envelope may have been written by the historical zero-key bug.
    ZeroKeyCandidate,
    /// The caller supplied invalid public input.
    InvalidInput,
}

/// Error returned by this crate. It intentionally stores no secret-bearing source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoError {
    class: FailureClass,
    code: &'static str,
}

impl CryptoError {
    const fn new(class: FailureClass, code: &'static str) -> Self {
        Self { class, code }
    }
    /// Returns the non-sensitive failure class.
    #[must_use]
    pub const fn class(self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for CryptoError {}

/// A secret byte buffer which is wiped on drop and never reveals its contents in formatting.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates a zeroizing buffer from bytes.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    /// Borrows the secret for the duration of an operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A parsed age X25519 identity with non-revealing formatting.
pub struct Identity(age::x25519::Identity);
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A parsed age X25519 recipient.
pub struct Recipient(age::x25519::Recipient);
impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({})", self.0)
    }
}
impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Parses an age X25519 identity string.
pub fn parse_identity(value: &str) -> Result<Identity, CryptoError> {
    value
        .parse()
        .map(Identity)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "invalid identity"))
}
/// Parses an age X25519 recipient string.
pub fn parse_recipient(value: &str) -> Result<Recipient, CryptoError> {
    value
        .parse()
        .map(Recipient)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "invalid recipient"))
}
/// Returns the canonical age recipient string for an identity.
#[must_use]
pub fn recipient_string(identity: &Identity) -> String {
    identity.0.to_public().to_string()
}
/// Computes the Go-compatible SHA-256/128 uppercase grouped fingerprint.
#[must_use]
pub fn fingerprint(public_key: &str) -> String {
    let value = public_key.trim();
    if value.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(value.as_bytes());
    digest[..16]
        .chunks(2)
        .map(|chunk| format!("{:02X}", chunk[0]) + &format!("{:02X}", chunk[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

fn encrypt_to_recipients(
    plaintext: &[u8],
    recipients: Vec<Box<dyn age::Recipient>>,
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "plaintext is empty",
        ));
    }
    if recipients.is_empty() {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "no recipients",
        ));
    }
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "invalid recipients"))?;
    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "cannot create encryptor"))?;
    writer
        .write_all(plaintext)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "cannot write plaintext"))?;
    writer
        .finish()
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "cannot finish encryption"))?;
    Ok(output)
}

/// Re-encrypts an age envelope without exposing its plaintext to callers.
///
/// The input is decrypted with `identity`, then encrypted for exactly the
/// supplied X25519 recipients. This is the pure counterpart of Go's
/// `vault.ReencryptAll` per-file operation; it performs no filesystem writes.
pub fn reencrypt(
    ciphertext: &[u8],
    identity: &Identity,
    recipients: &[Recipient],
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = decrypt(ciphertext, identity)?;
    let result = encrypt(&plaintext, recipients);
    let mut plaintext = plaintext;
    plaintext.zeroize();
    result
}

/// Encrypts a non-empty entry for one or more X25519 recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError> {
    encrypt_to_recipients(
        plaintext,
        recipients
            .iter()
            .map(|r| Box::new(r.0.clone()) as Box<dyn age::Recipient>)
            .collect(),
    )
}

/// Decrypts an age entry with an X25519 identity.
pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<Vec<u8>, CryptoError> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity.0 as &dyn age::Identity))
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    Ok(plaintext)
}

/// Encrypts using the legacy age scrypt recipient. `work_factor` is log2(N).
pub fn encrypt_scrypt(
    plaintext: &[u8],
    passphrase: &SecretBytes,
    work_factor: u8,
) -> Result<Vec<u8>, CryptoError> {
    if !(1..=MAX_SCRYPT_WORK_FACTOR).contains(&work_factor) {
        return Err(CryptoError::new(
            FailureClass::ParameterBounds,
            "scrypt work factor out of bounds",
        ));
    }
    let secret = age::secrecy::SecretString::from(
        String::from_utf8_lossy(passphrase.as_bytes()).into_owned(),
    );
    let mut recipient = age::scrypt::Recipient::new(secret);
    recipient.set_work_factor(work_factor);
    encrypt_to_recipients(plaintext, vec![Box::new(recipient)])
}

/// Decrypts a legacy age scrypt envelope with a bounded work factor.
pub fn decrypt_scrypt(ciphertext: &[u8], passphrase: &SecretBytes) -> Result<Vec<u8>, CryptoError> {
    let secret = age::secrecy::SecretString::from(
        String::from_utf8_lossy(passphrase.as_bytes()).into_owned(),
    );
    let mut identity = age::scrypt::Identity::new(secret);
    identity.set_max_work_factor(MAX_SCRYPT_WORK_FACTOR);
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::ExcessiveWork { .. } => CryptoError::new(
                FailureClass::ParameterBounds,
                "scrypt work factor exceeds limit",
            ),
            _ => CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"),
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    Ok(plaintext)
}

/// Argon2id parameters encoded in the age stanza.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2idParams {
    pub time: u32,
    pub memory_kib: u32,
    pub threads: u32,
}
impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            time: 3,
            memory_kib: 64 * 1024,
            threads: 4,
        }
    }
}
impl Argon2idParams {
    fn validate(self) -> Result<Self, CryptoError> {
        if self.time == 0
            || self.time > MAX_ARGON2_TIME
            || self.memory_kib == 0
            || self.memory_kib > MAX_ARGON2_MEMORY
            || self.threads == 0
            || self.threads > MAX_ARGON2_THREADS
            || self.memory_kib < 4 * self.threads
        {
            return Err(CryptoError::new(
                FailureClass::ParameterBounds,
                "argon2id parameters out of bounds",
            ));
        }
        Ok(self)
    }
}

fn derive(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<SecretBytes, CryptoError> {
    let params = params.validate()?;
    if passphrase.is_empty() || salt.len() != ARGON2ID_SALT_BYTES {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "invalid argon2id input",
        ));
    }
    let p = Params::new(
        params.memory_kib,
        params.time,
        params.threads,
        Some(KEY_BYTES),
    )
    .map_err(|_| {
        CryptoError::new(
            FailureClass::ParameterBounds,
            "argon2id parameters out of bounds",
        )
    })?;
    let mut key = vec![0u8; KEY_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| {
            CryptoError::new(FailureClass::ParameterBounds, "argon2id derivation failed")
        })?;
    Ok(SecretBytes(key))
}

fn wrap_key(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<SecretBytes, CryptoError> {
    let derived = derive(passphrase, salt, params)?;
    let hk = Hkdf::<Sha256>::new(Some(salt), derived.as_bytes());
    let mut key = vec![0u8; KEY_BYTES];
    hk.expand(ARGON2ID_LABEL, &mut key)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "hkdf expansion failed"))?;
    Ok(SecretBytes(key))
}

struct ArgonRecipient {
    passphrase: SecretBytes,
    params: Argon2idParams,
}
impl age::Recipient for ArgonRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let mut salt = [0u8; ARGON2ID_SALT_BYTES];
        getrandom::fill(&mut salt).map_err(|_| age::EncryptError::MissingRecipients)?;
        let key = wrap_key(self.passphrase.as_bytes(), &salt, self.params)
            .map_err(|_| age::EncryptError::MissingRecipients)?;
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| age::EncryptError::MissingRecipients)?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| age::EncryptError::MissingRecipients)?;
        let mut body = nonce.to_vec();
        body.extend(
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    file_key.expose_secret().as_slice(),
                )
                .map_err(|_| age::EncryptError::MissingRecipients)?,
        );
        Ok((
            vec![Stanza {
                tag: ARGON2ID_TAG.to_owned(),
                args: vec![
                    STANDARD_NO_PAD.encode(salt),
                    format!(
                        "t={},m={},p={}",
                        self.params.time, self.params.memory_kib, self.params.threads
                    ),
                ],
                body,
            }],
            HashSet::new(),
        ))
    }
}

struct ArgonIdentity {
    passphrase: SecretBytes,
}
impl age::Identity for ArgonIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != ARGON2ID_TAG {
            return None;
        }
        let [salt, encoded] = stanza.args.as_slice() else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let Ok(salt) = STANDARD_NO_PAD.decode(salt) else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let Ok(params) = parse_params(encoded) else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        if stanza.body.len() < 12 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let Ok(key) = wrap_key(self.passphrase.as_bytes(), &salt, params) else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key.as_bytes()) else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let Ok(plain) = cipher.decrypt(Nonce::from_slice(&stanza.body[..12]), &stanza.body[12..])
        else {
            return Some(Err(age::DecryptError::DecryptionFailed));
        };
        if plain.len() != 16 {
            return Some(Err(age::DecryptError::DecryptionFailed));
        }
        let mut file_key = [0u8; 16];
        file_key.copy_from_slice(&plain);
        Some(Ok(FileKey::new(Box::new(file_key))))
    }
}

fn parse_params(value: &str) -> Result<Argon2idParams, CryptoError> {
    let mut result = Argon2idParams {
        time: 0,
        memory_kib: 0,
        threads: 0,
    };
    for part in value.split(',') {
        let (key, number) = part.split_once('=').ok_or(CryptoError::new(
            FailureClass::MalformedEnvelope,
            "malformed argon2id parameters",
        ))?;
        let parsed: u32 = number.parse().map_err(|_| {
            CryptoError::new(
                FailureClass::MalformedEnvelope,
                "malformed argon2id parameters",
            )
        })?;
        match key {
            "t" => result.time = parsed,
            "m" => result.memory_kib = parsed,
            "p" => result.threads = parsed,
            _ => {
                return Err(CryptoError::new(
                    FailureClass::MalformedEnvelope,
                    "malformed argon2id parameters",
                ));
            }
        }
    }
    result.validate()
}

/// Encrypts with the Symaira Vault Argon2id age recipient stanza.
pub fn encrypt_argon2id(
    plaintext: &[u8],
    passphrase: &SecretBytes,
    params: Argon2idParams,
) -> Result<Vec<u8>, CryptoError> {
    let params = params.validate()?;
    encrypt_to_recipients(
        plaintext,
        vec![Box::new(ArgonRecipient {
            passphrase: SecretBytes::new(passphrase.as_bytes()),
            params,
        })],
    )
}
/// Decrypts a Symaira Vault Argon2id age envelope.
pub fn decrypt_argon2id(
    ciphertext: &[u8],
    passphrase: &SecretBytes,
) -> Result<Vec<u8>, CryptoError> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let identity = ArgonIdentity {
        passphrase: SecretBytes::new(passphrase.as_bytes()),
    };
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    Ok(plaintext)
}

/// Identifies the passphrase envelope family without attempting decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeFormat {
    Scrypt,
    Argon2id,
    Unknown,
}
#[must_use]
pub fn detect_envelope(raw: &[u8]) -> EnvelopeFormat {
    if raw
        .windows(b"-> argon2id".len())
        .any(|w| w == b"-> argon2id")
    {
        EnvelopeFormat::Argon2id
    } else if raw.windows(b"-> scrypt".len()).any(|w| w == b"-> scrypt") {
        EnvelopeFormat::Scrypt
    } else {
        EnvelopeFormat::Unknown
    }
}
/// Returns whether a legacy scrypt identity should be migrated.
#[must_use]
pub fn needs_kdf_migration(raw: &[u8]) -> bool {
    detect_envelope(raw) == EnvelopeFormat::Scrypt
}
/// Returns the zero-key recovery classification used by the historical healing path.
#[must_use]
pub fn classify_zero_key_candidate(raw: &[u8]) -> FailureClass {
    if detect_envelope(raw) == EnvelopeFormat::Argon2id {
        FailureClass::ZeroKeyCandidate
    } else {
        FailureClass::MalformedEnvelope
    }
}

fn validate_recovered_identity(identity: &Identity) -> Result<(), CryptoError> {
    let public = recipient_string(identity);
    if public.is_empty() || parse_recipient(&public).map(|r| r.to_string()) != Ok(public.clone()) {
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    let computed = fingerprint(&public);
    let valid_fingerprint = computed.len() == 8 * 4 + 7
        && computed.split(' ').all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        });
    if !valid_fingerprint {
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    Ok(())
}

fn parse_recovered_identity(plaintext: &mut Vec<u8>) -> Result<Identity, CryptoError> {
    let result = (|| {
        let value = std::str::from_utf8(plaintext).map_err(|_| {
            CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
        })?;
        let identity = parse_identity(value.trim()).map_err(|_| {
            CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
        })?;
        validate_recovered_identity(&identity)?;
        Ok(identity)
    })();
    plaintext.zeroize();
    result
}

/// Recovers an identity from the historical Argon2id zero-key envelope.
pub fn recover_zero_key_identity(
    raw: &[u8],
    passphrase_len: usize,
) -> Result<Identity, CryptoError> {
    if passphrase_len == 0 || passphrase_len > MAX_ZERO_KEY_PASSPHRASE_LEN {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key length is invalid",
        ));
    }
    let zeros = SecretBytes(vec![0; passphrase_len]);
    let decryptor = age::Decryptor::new(raw)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let identity = ArgonIdentity { passphrase: zeros };
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
        })?;
    let mut plaintext = Vec::new();
    if reader.read_to_end(&mut plaintext).is_err() {
        plaintext.zeroize();
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    drop(reader);
    parse_recovered_identity(&mut plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ID: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
    const ID2: &str = "AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3";
    const ID3: &str = "AGE-SECRET-KEY-15KR576PHDPLRQS08427S6X2G492S6GTVELZ6WHN8AKMWW90T0HES2KQ597";
    const ORACLE_COMMIT: &str = "caadd5e";
    const ORACLE_RELEASE: &str = "v0.22.1";
    const ORACLE_SOURCE_FILES: &[&str] = &[
        "internal/crypto/age.go",
        "internal/crypto/argon2id.go",
        "internal/crypto/keygen.go",
        "internal/crypto/symmetric.go",
        "internal/vault/reencrypt.go",
    ];
    const ORACLE_GENERATOR_FILES: &[&str] = &[
        "internal/crypto/interop.go",
        "scripts/rust-port/cmd/cryptogen/main.go",
        "scripts/rust-port/cmd/cryptoverify/main.go",
    ];
    const ORACLE_SOURCE_DIGEST: &str =
        "cc99e5efc05aeb3d1dacff8499fa82748f200669f99121b04f512151c44f1d84";
    const ORACLE_GENERATOR_DIGEST: &str =
        "b5dea6caee51f2443b803e92c643cdd58ec82141107a6de73a9fc4f87a90c010";

    #[derive(serde::Deserialize)]
    struct OracleFixture {
        schema_version: u8,
        oracle: OracleMeta,
        identities: Vec<OracleIdentity>,
        age_cases: Vec<OracleAgeCase>,
        scrypt_cases: Vec<OracleEnvelope>,
        argon2id_cases: Vec<OracleEnvelope>,
        zero_key_cases: Vec<OracleZeroKey>,
        reencrypt_cases: Vec<OracleReencrypt>,
        malformed_cases: Vec<OracleMalformed>,
        limit_cases: Vec<OracleLimit>,
        wrong_passphrase_cases: Vec<OracleWrongPassphrase>,
        migration_cases: Vec<OracleMigration>,
    }
    #[derive(serde::Deserialize)]
    struct OracleMeta {
        commit: String,
        release: String,
        source_files: Vec<String>,
        source_digest: String,
        generator_files: Vec<String>,
        generator_digest: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleIdentity {
        name: String,
        identity: String,
        recipient: String,
        fingerprint: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleAgeCase {
        name: String,
        plaintext: String,
        ciphertext: String,
        recipients: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct OracleEnvelope {
        name: String,
        plaintext: String,
        ciphertext: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleZeroKey {
        name: String,
        ciphertext: String,
        passphrase_length: usize,
    }
    #[derive(serde::Deserialize)]
    struct OracleMalformed {
        name: String,
        input: String,
        expected_class: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleLimit {
        name: String,
        kind: String,
        work_factor: u8,
        time: u32,
        memory: u32,
        threads: u8,
        expected_class: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleWrongPassphrase {
        name: String,
        kind: String,
        ciphertext: String,
        expected_class: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleMigration {
        name: String,
        input: String,
        format: String,
        needs_migration: bool,
    }

    #[derive(serde::Deserialize)]
    struct OracleReencrypt {
        name: String,
        plaintext: String,
        source_identity: String,
        source_ciphertext: String,
        source_recipients: Vec<String>,
        reencrypted_ciphertext: String,
        recipients: Vec<String>,
        removed_recipient: String,
        removed_identity: String,
    }

    fn load_fixture() -> (String, OracleFixture) {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/crypto/age-kdf.json"
        ))
        .expect("Go crypto fixture");
        let fixture: OracleFixture = serde_json::from_str(&raw).expect("valid Go crypto fixture");
        (raw, fixture)
    }

    fn assert_names<T>(
        actual: &[T],
        expected: &[&str],
        name: impl Fn(&T) -> &str,
    ) -> Result<(), String> {
        if actual.len() != expected.len() {
            return Err(format!(
                "case cardinality {}, want {}",
                actual.len(),
                expected.len()
            ));
        }
        for (item, expected_name) in actual.iter().zip(expected) {
            if name(item) != *expected_name {
                return Err(format!(
                    "case name/order changed: got {}, want {expected_name}",
                    name(item)
                ));
            }
        }
        Ok(())
    }

    fn validate_fixture(fixture: &OracleFixture) -> Result<(), String> {
        if fixture.schema_version != 1 {
            return Err("schema version changed".to_owned());
        }
        if fixture.oracle.commit != ORACLE_COMMIT || fixture.oracle.release != ORACLE_RELEASE {
            return Err("oracle commit/release changed".to_owned());
        }
        if fixture.oracle.source_digest != ORACLE_SOURCE_DIGEST
            || fixture.oracle.generator_digest != ORACLE_GENERATOR_DIGEST
        {
            return Err("oracle digest changed".to_owned());
        }
        let source_files: Vec<&str> = fixture
            .oracle
            .source_files
            .iter()
            .map(String::as_str)
            .collect();
        let generator_files: Vec<&str> = fixture
            .oracle
            .generator_files
            .iter()
            .map(String::as_str)
            .collect();
        if source_files != ORACLE_SOURCE_FILES || generator_files != ORACLE_GENERATOR_FILES {
            return Err("oracle file provenance changed".to_owned());
        }
        assert_names(
            &fixture.identities,
            &["fixed_1", "fixed_2", "fixed_3"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.age_cases,
            &["two_recipients", "three_recipients"],
            |v| &v.name,
        )?;
        assert_names(&fixture.scrypt_cases, &["legacy_work_factor_12"], |v| {
            &v.name
        })?;
        assert_names(
            &fixture.argon2id_cases,
            &["current_tiny_fixture_params"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.zero_key_cases,
            &["historical_zero_key_length_23"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.reencrypt_cases,
            &["add_recipient", "remove_recipient"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.malformed_cases,
            &["empty", "not_age", "bad_stanza"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.limit_cases,
            &[
                "scrypt_work_factor_zero",
                "scrypt_work_factor_above_max",
                "argon2_time_zero",
                "argon2_time_above_max",
                "argon2_memory_zero",
                "argon2_memory_above_max",
                "argon2_threads_zero",
                "argon2_threads_above_max",
                "argon2_memory_below_threads",
            ],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.wrong_passphrase_cases,
            &[
                "age_wrong_identity",
                "scrypt_wrong_passphrase",
                "argon2id_wrong_passphrase",
            ],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.migration_cases,
            &["legacy_scrypt", "current_argon2id", "unknown_envelope"],
            |v| &v.name,
        )?;
        for item in &fixture.age_cases {
            if item.recipients.len() < 2 || item.ciphertext.is_empty() || item.plaintext.is_empty()
            {
                return Err(format!("incomplete age case {}", item.name));
            }
        }
        Ok(())
    }

    #[test]
    fn x25519_and_fingerprint_vectors_are_all_consumed() {
        let (_, fixture) = load_fixture();
        validate_fixture(&fixture).unwrap();
        let expected = [
            (
                ID,
                "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y",
                "9DC3 A8A0 74CE 0E8A E871 8B96 246D 238B",
            ),
            (
                ID2,
                "age1wxknyar29luhmltc320wnllzxd7n0cjvldxqjunyh9u3l4gpd3kq9r4lgr",
                "F0E9 391C BACE 82B8 FBB0 20BF 299A BD6F",
            ),
            (
                ID3,
                "age1mrfjwn5r0v9zrvgv73fc5880svsky436wp2ygvw6lts5hx8xwavs6vmkcy",
                "1CCA B8D6 58D0 1292 08E2 986C ED65 3CE4",
            ),
        ];
        for (item, (identity, recipient, fingerprint_value)) in
            fixture.identities.iter().zip(expected)
        {
            let parsed = parse_identity(&item.identity).unwrap();
            assert_eq!(item.identity, identity);
            assert_eq!(recipient_string(&parsed), recipient);
            assert_eq!(item.recipient, recipient);
            assert_eq!(fingerprint(&item.recipient), fingerprint_value);
            assert_eq!(item.fingerprint, fingerprint_value);
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn go_vectors_consume_every_positive_negative_and_migration_case() {
        let (_, fixture) = load_fixture();
        validate_fixture(&fixture).unwrap();
        let identities: Vec<Identity> = fixture
            .identities
            .iter()
            .map(|item| parse_identity(&item.identity).unwrap())
            .collect();
        for case in &fixture.age_cases {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&case.ciphertext)
                .unwrap();
            for recipient in &case.recipients {
                let index = fixture
                    .identities
                    .iter()
                    .position(|item| &item.recipient == recipient)
                    .unwrap();
                assert_eq!(
                    decrypt(&ciphertext, &identities[index]).unwrap(),
                    case.plaintext.as_bytes(),
                    "{}",
                    case.name
                );
            }
        }
        let passphrase = SecretBytes::new(b"rust-interop-fixture-passphrase-v1");
        for case in &fixture.scrypt_cases {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&case.ciphertext)
                .unwrap();
            assert_eq!(
                decrypt_scrypt(&ciphertext, &passphrase).unwrap(),
                case.plaintext.as_bytes(),
                "{}",
                case.name
            );
        }
        for case in &fixture.argon2id_cases {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&case.ciphertext)
                .unwrap();
            assert_eq!(
                decrypt_argon2id(&ciphertext, &passphrase).unwrap(),
                case.plaintext.as_bytes(),
                "{}",
                case.name
            );
        }
        for case in &fixture.zero_key_cases {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&case.ciphertext)
                .unwrap();
            let recovered = recover_zero_key_identity(&ciphertext, case.passphrase_length).unwrap();
            assert_eq!(
                recipient_string(&recovered),
                fixture.identities[0].recipient,
                "{}",
                case.name
            );
        }
        for case in &fixture.malformed_cases {
            let result = decrypt(case.input.as_bytes(), &identities[0]);
            assert_eq!(
                result.unwrap_err().class(),
                FailureClass::MalformedEnvelope,
                "{}",
                case.name
            );
            assert_eq!(case.expected_class, "malformed_envelope");
        }
        for case in &fixture.limit_cases {
            let result = if case.kind == "scrypt" {
                encrypt_scrypt(b"limit", &passphrase, case.work_factor)
            } else {
                encrypt_argon2id(
                    b"limit",
                    &passphrase,
                    Argon2idParams {
                        time: case.time,
                        memory_kib: case.memory,
                        threads: u32::from(case.threads),
                    },
                )
            };
            assert_eq!(
                result.unwrap_err().class(),
                FailureClass::ParameterBounds,
                "{}",
                case.name
            );
            assert_eq!(case.expected_class, "parameter_bounds");
        }
        for case in &fixture.wrong_passphrase_cases {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&case.ciphertext)
                .unwrap();
            let result = match case.kind.as_str() {
                "age" => decrypt(&ciphertext, &identities[2]),
                "scrypt" => decrypt_scrypt(&ciphertext, &SecretBytes::new(b"wrong-passphrase")),
                "argon2id" => decrypt_argon2id(&ciphertext, &SecretBytes::new(b"wrong-passphrase")),
                other => panic!("unknown wrong-passphrase case kind {other}"),
            };
            assert_eq!(
                result.unwrap_err().class(),
                FailureClass::WrongPassphraseOrKey,
                "{}",
                case.name
            );
            assert_eq!(case.expected_class, "wrong_passphrase_or_key");
        }
        for case in &fixture.migration_cases {
            let format = detect_envelope(case.input.as_bytes());
            let expected_format = match case.format.as_str() {
                "scrypt" => EnvelopeFormat::Scrypt,
                "argon2id" => EnvelopeFormat::Argon2id,
                "unknown" => EnvelopeFormat::Unknown,
                other => panic!("unknown migration format {other}"),
            };
            assert_eq!(format, expected_format, "{}", case.name);
            assert_eq!(
                needs_kdf_migration(case.input.as_bytes()),
                case.needs_migration,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn fixture_validation_rejects_omission_and_tampered_provenance() {
        let (raw, fixture) = load_fixture();
        validate_fixture(&fixture).unwrap();
        let mut omitted: serde_json::Value = serde_json::from_str(&raw).unwrap();
        omitted["identities"].as_array_mut().unwrap().pop();
        let omitted_fixture: OracleFixture = serde_json::from_value(omitted).unwrap();
        assert!(validate_fixture(&omitted_fixture).is_err());
        let mut tampered: serde_json::Value = serde_json::from_str(&raw).unwrap();
        tampered["oracle"]["source_digest"] = serde_json::Value::String("0".repeat(64));
        let tampered_fixture: OracleFixture = serde_json::from_value(tampered).unwrap();
        assert!(validate_fixture(&tampered_fixture).is_err());
    }

    #[cfg(not(miri))]
    #[test]
    fn reencrypt_vectors_prove_add_remove_and_zero_key_safety() {
        let (_, fixture) = load_fixture();
        validate_fixture(&fixture).unwrap();
        for case in &fixture.reencrypt_cases {
            let source = base64::engine::general_purpose::STANDARD
                .decode(&case.source_ciphertext)
                .unwrap();
            let go_output = base64::engine::general_purpose::STANDARD
                .decode(&case.reencrypted_ciphertext)
                .unwrap();
            let source_identity = parse_identity(&case.source_identity).unwrap();
            let mut source_recipients = Vec::new();
            let mut source_seen = HashSet::new();
            for recipient in &case.source_recipients {
                assert!(source_seen.insert(recipient));
                source_recipients.push(parse_recipient(recipient).unwrap());
            }
            assert!(!source_recipients.is_empty());
            let mut retained = Vec::new();
            let mut retained_seen = HashSet::new();
            for recipient in &case.recipients {
                assert!(retained_seen.insert(recipient));
                retained.push(parse_recipient(recipient).unwrap());
            }
            assert!(!retained.is_empty());
            assert!(!retained_seen.contains(&case.removed_recipient));
            let removed_identity = parse_identity(&case.removed_identity).unwrap();
            assert_eq!(recipient_string(&removed_identity), case.removed_recipient);
            for identity_case in &fixture.identities {
                if case.source_recipients.contains(&identity_case.recipient) {
                    let identity = parse_identity(&identity_case.identity).unwrap();
                    assert_eq!(
                        decrypt(&source, &identity).unwrap(),
                        case.plaintext.as_bytes()
                    );
                }
                if case.recipients.contains(&identity_case.recipient) {
                    let identity = parse_identity(&identity_case.identity).unwrap();
                    assert_eq!(
                        decrypt(&go_output, &identity).unwrap(),
                        case.plaintext.as_bytes()
                    );
                }
            }
            if case.source_recipients.contains(&case.removed_recipient) {
                assert_eq!(
                    decrypt(&source, &removed_identity).unwrap(),
                    case.plaintext.as_bytes()
                );
            }
            assert_eq!(
                decrypt(&go_output, &removed_identity).unwrap_err().class(),
                FailureClass::WrongPassphraseOrKey
            );
            let rust_output = reencrypt(&source, &source_identity, &retained).unwrap();
            for identity_case in &fixture.identities {
                if case.recipients.contains(&identity_case.recipient) {
                    let identity = parse_identity(&identity_case.identity).unwrap();
                    assert_eq!(
                        decrypt(&rust_output, &identity).unwrap(),
                        case.plaintext.as_bytes()
                    );
                }
            }
            assert_eq!(
                decrypt(&rust_output, &removed_identity)
                    .unwrap_err()
                    .class(),
                FailureClass::WrongPassphraseOrKey
            );
        }
        let zero = &fixture.zero_key_cases[0];
        let zero_ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&zero.ciphertext)
            .unwrap();
        assert_eq!(
            recover_zero_key_identity(&zero_ciphertext, 0)
                .unwrap_err()
                .class(),
            FailureClass::InvalidInput
        );
        assert_eq!(
            recover_zero_key_identity(&zero_ciphertext, MAX_ZERO_KEY_PASSPHRASE_LEN + 1)
                .unwrap_err()
                .class(),
            FailureClass::InvalidInput
        );
        assert_eq!(
            recover_zero_key_identity(&zero_ciphertext, zero.passphrase_length + 1)
                .unwrap_err()
                .class(),
            FailureClass::ZeroKeyCandidate
        );
        let zeros = SecretBytes::new(&vec![0; zero.passphrase_length]);
        let malformed_identity = encrypt_argon2id(
            b"not an age identity",
            &zeros,
            Argon2idParams {
                time: 1,
                memory_kib: 32,
                threads: 1,
            },
        )
        .unwrap();
        assert_eq!(
            recover_zero_key_identity(&malformed_identity, zero.passphrase_length)
                .unwrap_err()
                .class(),
            FailureClass::ZeroKeyCandidate
        );
    }

    #[test]
    fn multi_recipient_retention_and_removal() {
        let one = parse_identity(ID).unwrap();
        let two = parse_identity(ID2).unwrap();
        let cipher = encrypt(
            b"retained",
            &[Recipient(one.0.to_public()), Recipient(two.0.to_public())],
        )
        .unwrap();
        assert_eq!(decrypt(&cipher, &one).unwrap(), b"retained");
        assert_eq!(decrypt(&cipher, &two).unwrap(), b"retained");
        let removed = encrypt(b"removed", &[Recipient(one.0.to_public())]).unwrap();
        assert_eq!(decrypt(&removed, &one).unwrap(), b"removed");
        assert_eq!(
            decrypt(&removed, &two).unwrap_err().class(),
            FailureClass::WrongPassphraseOrKey
        );
    }

    #[test]
    fn secret_formatting_is_redacted() {
        let secret = SecretBytes::new(b"do-not-print");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");
    }

    #[cfg(not(miri))]
    proptest::proptest! {
        #[test]
        fn malformed_inputs_never_panic(input in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = detect_envelope(&input);
            let _ = age::Decryptor::new(std::io::Cursor::new(input));
        }
    }
}
