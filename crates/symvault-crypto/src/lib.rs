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
    if !(1..64).contains(&work_factor) {
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

/// Recovers an identity from the historical Argon2id zero-key envelope.
pub fn recover_zero_key_identity(
    raw: &[u8],
    passphrase_len: usize,
) -> Result<Identity, CryptoError> {
    if passphrase_len == 0 {
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
    reader.read_to_end(&mut plaintext).map_err(|_| {
        CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
    })?;
    let value = std::str::from_utf8(&plaintext).map_err(|_| {
        CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
    })?;
    parse_identity(value.trim())
        .map_err(|_| CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    const ID: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
    const ID2: &str = "AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3";

    #[test]
    fn x25519_and_fingerprint_match_go_shape() {
        let id = parse_identity(ID).unwrap();
        assert_eq!(
            recipient_string(&id),
            "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y"
        );
        assert_eq!(
            fingerprint(&recipient_string(&id)),
            "9DC3 A8A0 74CE 0E8A E871 8B96 246D 238B"
        );
    }
    #[cfg(not(miri))]
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
    #[test]
    fn argon2_roundtrip_and_bounds() {
        let pass = SecretBytes::new(b"fixture-passphrase");
        let params = Argon2idParams {
            time: 1,
            memory_kib: 32,
            threads: 1,
        };
        let cipher = encrypt_argon2id(b"value", &pass, params).unwrap();
        assert_eq!(decrypt_argon2id(&cipher, &pass).unwrap(), b"value");
        assert_eq!(
            encrypt_argon2id(b"value", &pass, Argon2idParams { time: 17, ..params })
                .unwrap_err()
                .class(),
            FailureClass::ParameterBounds
        );
    }
    #[derive(serde::Deserialize)]
    struct OracleFixture {
        schema_version: u8,
        oracle: OracleMeta,
        identities: Vec<OracleIdentity>,
        age_cases: Vec<OracleAgeCase>,
        scrypt_cases: Vec<OracleEnvelope>,
        argon2id_cases: Vec<OracleEnvelope>,
        zero_key_cases: Vec<OracleZeroKey>,
    }
    #[derive(serde::Deserialize)]
    struct OracleZeroKey {
        ciphertext: String,
        passphrase_length: usize,
    }
    #[derive(serde::Deserialize)]
    struct OracleMeta {
        source_digest: String,
        generator_digest: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleIdentity {
        identity: String,
        recipient: String,
        fingerprint: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleAgeCase {
        plaintext: String,
        ciphertext: String,
    }
    #[derive(serde::Deserialize)]
    struct OracleEnvelope {
        plaintext: String,
        ciphertext: String,
    }

    #[cfg(not(miri))]
    #[test]
    fn go_generated_vectors_decrypt_in_rust_and_provenance_is_present() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/crypto/age-kdf.json"
        ))
        .expect("Go crypto fixture");
        let fixture: OracleFixture = serde_json::from_str(&raw).expect("valid Go crypto fixture");
        assert_eq!(fixture.schema_version, 1);
        assert_eq!(fixture.oracle.source_digest.len(), 64);
        assert_eq!(fixture.oracle.generator_digest.len(), 64);
        let identity = parse_identity(&fixture.identities[0].identity).unwrap();
        assert_eq!(recipient_string(&identity), fixture.identities[0].recipient);
        assert_eq!(
            fingerprint(&fixture.identities[0].recipient),
            fixture.identities[0].fingerprint
        );
        let age_case = &fixture.age_cases[0];
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&age_case.ciphertext)
            .unwrap();
        assert_eq!(
            decrypt(&ciphertext, &identity).unwrap(),
            age_case.plaintext.as_bytes()
        );
        let zero = &fixture.zero_key_cases[0];
        let zero_ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&zero.ciphertext)
            .unwrap();
        let recovered =
            recover_zero_key_identity(&zero_ciphertext, zero.passphrase_length).unwrap();
        assert_eq!(
            recipient_string(&recovered),
            fixture.identities[0].recipient
        );
        let passphrase = SecretBytes::new(b"rust-interop-fixture-passphrase-v1");
        let scrypt = &fixture.scrypt_cases[0];
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&scrypt.ciphertext)
            .unwrap();
        assert_eq!(
            decrypt_scrypt(&ciphertext, &passphrase).unwrap(),
            scrypt.plaintext.as_bytes()
        );
        let argon = &fixture.argon2id_cases[0];
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&argon.ciphertext)
            .unwrap();
        assert_eq!(
            decrypt_argon2id(&ciphertext, &passphrase).unwrap(),
            argon.plaintext.as_bytes()
        );
        let wrong = SecretBytes::new(b"wrong-passphrase");
        assert_eq!(
            decrypt_scrypt(
                &base64::engine::general_purpose::STANDARD
                    .decode(&scrypt.ciphertext)
                    .unwrap(),
                &wrong
            )
            .unwrap_err()
            .class(),
            FailureClass::WrongPassphraseOrKey
        );
        assert_eq!(
            decrypt_argon2id(
                &base64::engine::general_purpose::STANDARD
                    .decode(&argon.ciphertext)
                    .unwrap(),
                &wrong
            )
            .unwrap_err()
            .class(),
            FailureClass::WrongPassphraseOrKey
        );
        assert_eq!(
            decrypt(b"not an age envelope", &identity)
                .unwrap_err()
                .class(),
            FailureClass::MalformedEnvelope
        );
        let mut tampered = raw.clone();
        tampered = tampered.replacen(&fixture.oracle.source_digest, &"0".repeat(64), 1);
        assert_ne!(tampered, raw, "fixture tamper must be observable");
    }

    #[test]
    fn kdf_migration_and_malformed_classifications_are_stable() {
        assert_eq!(
            detect_envelope(b"-> scrypt abc 12\n"),
            EnvelopeFormat::Scrypt
        );
        assert!(needs_kdf_migration(b"-> scrypt abc 12\n"));
        assert_eq!(
            detect_envelope(b"-> argon2id abc t=1,m=32,p=1\n"),
            EnvelopeFormat::Argon2id
        );
        assert_eq!(
            classify_zero_key_candidate(b"-> argon2id abc t=1,m=32,p=1\n"),
            FailureClass::ZeroKeyCandidate
        );
        assert_eq!(detect_envelope(b"garbage"), EnvelopeFormat::Unknown);
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
