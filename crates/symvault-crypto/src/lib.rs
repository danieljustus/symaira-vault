#![deny(unsafe_code)]

//! Age-compatible cryptographic primitives used before Rust storage exists.
//!
//! This crate deliberately has no filesystem or vault dependencies. It wraps the
//! reference `age` implementation for X25519 and scrypt, and implements the
//! Symaira Vault Argon2id recipient stanza exactly as the Go oracle does.

mod argon2_resources;
pub use argon2_resources::POLICY_VERSION as ARGON2_RESOURCE_POLICY_VERSION;
use argon2_resources::ReadMode;

use std::{
    cell::Cell,
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
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ARGON2ID_TAG: &str = "argon2id";
const ARGON2ID_LABEL: &[u8] = b"symvault-argon2id-v1";
const KEY_BYTES: usize = 32;
const ARGON2ID_SALT_BYTES: usize = 16;
/// Maximum Argon2id budget accepted from an untrusted envelope.
///
/// These maxima are the current Go interoperability contract. Tests validate
/// them through parsing only; no test derives a KDF at these budgets.
const MAX_ARGON2_TIME: u32 = 16;
const MAX_ARGON2_MEMORY: u32 = 2_097_152;
const MAX_ARGON2_THREADS: u32 = 16;
const MAX_ARGON2ID_PARAMS_BYTES: usize = 64;
const MAX_ARGON2ID_PARAM_PARTS: usize = 3;
const ARGON2ID_SALT_B64_BYTES: usize = 22;
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
    /// Historical parameters require an explicitly authorized local migration.
    ResourcePolicy,
    /// The bounded KDF admission queue is exhausted or its deadline elapsed.
    ResourceBusy,
    /// Decrypted output exceeds the caller's explicit resource budget.
    SizeLimit,
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

/// Generates a new random age X25519 identity.
#[must_use]
pub fn generate_identity() -> Identity {
    Identity(age::x25519::Identity::generate())
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

/// Returns the private age identity in a zeroizing buffer for session-cache
/// persistence. Callers should pass the bytes directly to an encrypted cache
/// and let this value drop immediately; formatting remains redacted.
#[must_use]
pub fn identity_string(identity: &Identity) -> SecretBytes {
    SecretBytes::new(identity.0.to_string().expose_secret().as_bytes())
}

/// Encrypts an identity with a passphrase using scrypt and returns the ciphertext.
pub fn encrypt_identity_scrypt(
    identity: &Identity,
    passphrase: &SecretBytes,
    work_factor: u8,
) -> Result<Vec<u8>, CryptoError> {
    let secret = identity.0.to_string();
    let secret_bytes = secret.expose_secret().as_bytes();
    encrypt_scrypt(
        secret_bytes,
        passphrase,
        if work_factor == 0 { 18 } else { work_factor },
    )
}

/// Encrypts an identity with the current Vault Argon2id envelope format.
pub fn encrypt_identity_argon2id(
    identity: &Identity,
    passphrase: &SecretBytes,
    params: Argon2idParams,
) -> Result<Vec<u8>, CryptoError> {
    let secret = identity.0.to_string();
    encrypt_argon2id(secret.expose_secret().as_bytes(), passphrase, params)
}

/// Reads historical Argon2 budgets solely for an explicit local KDF migration.
/// The override is scoped to this call and never changes automatic admission.
pub fn decrypt_identity_for_legacy_kdf_migration(
    ciphertext: &[u8],
    passphrase: &SecretBytes,
) -> Result<Identity, CryptoError> {
    let mut plaintext =
        decrypt_argon2id_with_mode(ciphertext, passphrase, ReadMode::LegacyMigration)?;
    let result = std::str::from_utf8(&plaintext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "invalid utf-8 identity"))
        .and_then(|text| parse_identity(text.trim()));
    plaintext.zeroize();
    result
}

/// Decrypts an identity from an age envelope with a passphrase.
pub fn decrypt_identity(
    ciphertext: &[u8],
    passphrase: &SecretBytes,
) -> Result<Identity, CryptoError> {
    let format = detect_envelope(ciphertext);
    let plaintext = match format {
        EnvelopeFormat::Argon2id => decrypt_argon2id(ciphertext, passphrase)?,
        EnvelopeFormat::Scrypt => decrypt_scrypt(ciphertext, passphrase)?,
        EnvelopeFormat::Unknown => {
            return Err(CryptoError::new(
                FailureClass::MalformedEnvelope,
                "unknown envelope format",
            ));
        }
    };
    let text = std::str::from_utf8(&plaintext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "invalid utf-8 identity"))?;
    parse_identity(text.trim())
}

/// Returns the deterministic storage name used when path pseudonymization is enabled.
/// The private identity string never leaves this function.
#[must_use]
pub fn pseudonymize_path(identity: &Identity, path: &str) -> String {
    let identity_string = identity.0.to_string();
    let identity_digest = Sha256::digest(identity_string.expose_secret().as_bytes());
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&identity_digest)
        .expect("HMAC-SHA256 accepts every key length");
    mac.update(path.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
    let decryptor = entry_decryptor(ciphertext).map_err(|_| entry_header_error())?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity.0 as &dyn age::Identity))
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    Ok(plaintext)
}

/// Decrypts an age X25519 entry while limiting plaintext allocation.
///
/// The reader is allowed to produce one byte beyond `max_plaintext_bytes` so
/// callers can distinguish an exact-boundary payload from an oversized one.
pub fn decrypt_bounded(
    ciphertext: &[u8],
    identity: &Identity,
    max_plaintext_bytes: u64,
) -> Result<Vec<u8>, CryptoError> {
    let decryptor = entry_decryptor(ciphertext).map_err(|_| entry_header_error())?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity.0 as &dyn age::Identity))
        .map_err(|_| CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed"))?;
    let mut plaintext = Vec::with_capacity(max_plaintext_bytes.min(64 * 1024) as usize);
    reader
        .by_ref()
        .take(max_plaintext_bytes.saturating_add(1))
        .read_to_end(&mut plaintext)
        .map_err(|_| {
            plaintext.zeroize();
            CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed")
        })?;
    if plaintext.len() as u64 > max_plaintext_bytes {
        plaintext.zeroize();
        return Err(CryptoError::new(
            FailureClass::SizeLimit,
            "decrypted output exceeds size limit",
        ));
    }
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
    if identity_header_refused(ciphertext) {
        return Err(identity_header_error(ciphertext));
    }
    let decryptor = linear_decryptor(ciphertext)
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
    mode: ReadMode,
) -> Result<SecretBytes, CryptoError> {
    derive_admitted(passphrase, salt, params, mode, &argon2_resources::PROCESS)
}

fn derive_admitted(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2idParams,
    mode: ReadMode,
    admission: &argon2_resources::Admission,
) -> Result<SecretBytes, CryptoError> {
    let params = params.validate()?;
    if passphrase.is_empty() || salt.len() != ARGON2ID_SALT_BYTES {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "invalid argon2id input",
        ));
    }
    argon2_resources::validate(params, mode)?;
    let memory = params.memory_kib.max(8 * params.threads);
    let _reservation = admission.acquire(memory, mode)?;
    let p = if params.memory_kib < 8 * params.threads {
        Params::new_go_legacy_memory(
            params.memory_kib,
            params.time,
            params.threads,
            Some(KEY_BYTES),
        )
    } else {
        Params::new(
            params.memory_kib,
            params.time,
            params.threads,
            Some(KEY_BYTES),
        )
    }
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
    mode: ReadMode,
) -> Result<SecretBytes, CryptoError> {
    let derived = derive(passphrase, salt, params, mode)?;
    let hk = Hkdf::<Sha256>::new(Some(salt), derived.as_bytes());
    let mut key = vec![0u8; KEY_BYTES];
    hk.expand(ARGON2ID_LABEL, &mut key)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "hkdf expansion failed"))?;
    Ok(SecretBytes(key))
}

struct ArgonRecipient {
    key: SecretBytes,
    salt: [u8; ARGON2ID_SALT_BYTES],
    params: Argon2idParams,
}
impl age::Recipient for ArgonRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| age::EncryptError::MissingRecipients)?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| age::EncryptError::MissingRecipients)?;
        let mut body = nonce.to_vec();
        body.extend(
            cipher
                .encrypt((&nonce).into(), file_key.expose_secret().as_slice())
                .map_err(|_| age::EncryptError::MissingRecipients)?,
        );
        Ok((
            vec![Stanza {
                tag: ARGON2ID_TAG.to_owned(),
                args: vec![
                    STANDARD_NO_PAD.encode(self.salt),
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
    mode: ReadMode,
    error: Cell<Option<CryptoError>>,
}

fn malformed_argon2id() -> CryptoError {
    CryptoError::new(FailureClass::MalformedEnvelope, "malformed argon2id stanza")
}

fn preflight_argon2id(stanzas: &[Stanza], mode: ReadMode) -> Result<(), CryptoError> {
    let mut count = 0;
    let mut work = 0u64;
    let limit = if mode == ReadMode::LegacyMigration {
        u64::from(MAX_ARGON2_MEMORY) * u64::from(MAX_ARGON2_TIME)
    } else {
        u64::from(argon2_resources::MAX_MEMORY_KIB) * u64::from(argon2_resources::MAX_TIME)
    };
    for stanza in stanzas.iter().filter(|s| s.tag == ARGON2ID_TAG) {
        count += 1;
        if count > 4 {
            return Err(argon2_resources::policy_error());
        }
        let [salt, encoded] = stanza.args.as_slice() else {
            return Err(malformed_argon2id());
        };
        if salt.len() != ARGON2ID_SALT_B64_BYTES || stanza.body.len() != 44 {
            return Err(malformed_argon2id());
        }
        let decoded = STANDARD_NO_PAD
            .decode(salt)
            .map_err(|_| malformed_argon2id())?;
        if decoded.len() != ARGON2ID_SALT_BYTES {
            return Err(malformed_argon2id());
        }
        let params = parse_params(encoded)?;
        argon2_resources::validate(params, mode)?;
        work += u64::from(params.memory_kib.max(8 * params.threads)) * u64::from(params.time);
        if work > limit {
            return Err(argon2_resources::policy_error());
        }
    }
    Ok(())
}

impl age::Identity for ArgonIdentity {
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        if !stanzas.iter().any(|s| s.tag == ARGON2ID_TAG) {
            return None;
        }
        if let Err(error) = preflight_argon2id(stanzas, self.mode) {
            self.error.set(Some(error));
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        for stanza in stanzas {
            match self.unwrap_stanza(stanza) {
                Some(Ok(key)) => return Some(Ok(key)),
                Some(Err(error)) if self.error.get().is_some() => return Some(Err(error)),
                _ => {}
            }
        }
        Some(Err(age::DecryptError::DecryptionFailed))
    }

    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != ARGON2ID_TAG {
            return None;
        }
        if let Err(error) = preflight_argon2id(std::slice::from_ref(stanza), self.mode) {
            self.error.set(Some(error));
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let salt = STANDARD_NO_PAD.decode(&stanza.args[0]).ok()?;
        let params = parse_params(&stanza.args[1]).ok()?;
        let key = match wrap_key(self.passphrase.as_bytes(), &salt, params, self.mode) {
            Ok(key) => key,
            Err(error) => {
                self.error.set(Some(error));
                return Some(Err(age::DecryptError::InvalidHeader));
            }
        };
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes()).ok()?;
        let Ok(mut plain) = cipher.decrypt(
            <&Nonce>::try_from(&stanza.body[..12]).expect("12-byte nonce"),
            &stanza.body[12..],
        ) else {
            return Some(Err(age::DecryptError::DecryptionFailed));
        };
        if plain.len() != 16 {
            plain.zeroize();
            return Some(Err(age::DecryptError::DecryptionFailed));
        }
        let mut file_key = [0u8; 16];
        file_key.copy_from_slice(&plain);
        plain.zeroize();
        Some(Ok(FileKey::new(Box::new(file_key))))
    }
}

struct ArgonPolicyInspector {
    status: Cell<Option<Result<bool, CryptoError>>>,
}
impl age::Identity for ArgonPolicyInspector {
    fn unwrap_stanza(&self, _: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        None
    }
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let result = if stanzas.iter().any(|s| s.tag == ARGON2ID_TAG) {
            preflight_argon2id(stanzas, ReadMode::LegacyMigration)
                .map(|()| preflight_argon2id(stanzas, ReadMode::Automatic).is_err())
        } else {
            Err(malformed_argon2id())
        };
        self.status.set(Some(result));
        Some(Err(age::DecryptError::InvalidHeader))
    }
}

/// Inspects historical header budgets without a KDF or authenticating its key.
pub fn inspect_argon2id_policy(raw: &[u8]) -> Result<bool, CryptoError> {
    if identity_header_refused(raw) {
        return Err(malformed_argon2id());
    }
    let decryptor = linear_decryptor(raw).map_err(|_| malformed_argon2id())?;
    let inspector = ArgonPolicyInspector {
        status: Cell::new(None),
    };
    let _ = decryptor.decrypt(iter::once(&inspector as &dyn age::Identity));
    inspector.status.get().unwrap_or(Err(malformed_argon2id()))
}

/// Parses the bounded `t=<time>,m=<memory>,p=<threads>` Argon2id stanza value.
///
/// This parser is intentionally strict because the value comes from an untrusted
/// age header. It rejects oversized values, duplicate/unknown fields, and more
/// than the three expected fields before any KDF work is attempted.
pub fn parse_argon2id_params(value: &str) -> Result<Argon2idParams, CryptoError> {
    if value.len() > MAX_ARGON2ID_PARAMS_BYTES {
        return Err(CryptoError::new(
            FailureClass::MalformedEnvelope,
            "malformed argon2id parameters",
        ));
    }
    let mut result = Argon2idParams {
        time: 0,
        memory_kib: 0,
        threads: 0,
    };
    let mut seen = 0u8;
    for (index, part) in value.split(',').enumerate() {
        if index >= MAX_ARGON2ID_PARAM_PARTS {
            return Err(CryptoError::new(
                FailureClass::MalformedEnvelope,
                "malformed argon2id parameters",
            ));
        }
        let (key, number) = part.split_once('=').ok_or(CryptoError::new(
            FailureClass::MalformedEnvelope,
            "malformed argon2id parameters",
        ))?;
        let (bit, slot) = match key {
            "t" => (1, &mut result.time),
            "m" => (2, &mut result.memory_kib),
            "p" => (4, &mut result.threads),
            _ => {
                return Err(CryptoError::new(
                    FailureClass::MalformedEnvelope,
                    "malformed argon2id parameters",
                ));
            }
        };
        if seen & bit != 0 {
            return Err(CryptoError::new(
                FailureClass::MalformedEnvelope,
                "malformed argon2id parameters",
            ));
        }
        if number.is_empty() || !number.bytes().all(|c| c.is_ascii_digit()) {
            return Err(CryptoError::new(
                FailureClass::MalformedEnvelope,
                "malformed argon2id parameters",
            ));
        }
        *slot = number.parse().map_err(|_| {
            CryptoError::new(
                FailureClass::MalformedEnvelope,
                "malformed argon2id parameters",
            )
        })?;
        seen |= bit;
    }
    if seen != (1 | 2 | 4) {
        return Err(CryptoError::new(
            FailureClass::MalformedEnvelope,
            "malformed argon2id parameters",
        ));
    }
    result.validate()
}

fn parse_params(value: &str) -> Result<Argon2idParams, CryptoError> {
    parse_argon2id_params(value)
}

/// Encrypts plaintext with the key derivation used by the encrypted search index.
///
/// The identity remains inside this function; callers never receive key material.
pub fn encrypt_index(
    plaintext: &[u8],
    identity: &Identity,
    salt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut key = derive_index_key(identity, salt);
    let result = encrypt_with_key(plaintext, &key);
    key.zeroize();
    result
}

/// Decrypts ciphertext produced by [`encrypt_index`].
pub fn decrypt_index(
    ciphertext: &[u8],
    identity: &Identity,
    salt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut key = derive_index_key(identity, salt);
    let result = decrypt_with_key(ciphertext, &key);
    key.zeroize();
    result
}

fn derive_index_key(identity: &Identity, salt: &[u8]) -> Vec<u8> {
    let identity_string = identity.0.to_string();
    let identity_bytes = identity_string.expose_secret().as_bytes();
    if salt.is_empty() {
        return Sha256::digest(identity_bytes).to_vec();
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), identity_bytes);
    let mut key = vec![0u8; KEY_BYTES];
    hkdf.expand(b"symvault-search-index-v1", &mut key)
        .expect("HKDF-SHA256 output length is valid");
    key
}

fn encrypt_with_key(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() || key.len() != KEY_BYTES {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "invalid index input",
        ));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "invalid index key"))?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "cannot generate index nonce"))?;
    let mut result = nonce.to_vec();
    result.extend(
        cipher
            .encrypt((&nonce).into(), plaintext)
            .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "cannot encrypt index"))?,
    );
    Ok(result)
}

fn decrypt_with_key(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 12 || key.len() != KEY_BYTES {
        return Err(CryptoError::new(
            FailureClass::MalformedEnvelope,
            "invalid index ciphertext",
        ));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::new(FailureClass::InvalidInput, "invalid index key"))?;
    cipher
        .decrypt(
            <&Nonce>::try_from(&ciphertext[..12]).expect("12-byte nonce"),
            &ciphertext[12..],
        )
        .map_err(|_| {
            CryptoError::new(
                FailureClass::WrongPassphraseOrKey,
                "index decryption failed",
            )
        })
}

/// Encrypts using the Symaira Vault Argon2id age recipient stanza.
pub fn encrypt_argon2id(
    plaintext: &[u8],
    passphrase: &SecretBytes,
    params: Argon2idParams,
) -> Result<Vec<u8>, CryptoError> {
    let params = params.validate()?;
    if plaintext.is_empty() {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "plaintext is empty",
        ));
    }
    let mut salt = [0u8; ARGON2ID_SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|_| {
        CryptoError::new(FailureClass::InvalidInput, "cannot generate argon2id salt")
    })?;
    let key = wrap_key(passphrase.as_bytes(), &salt, params, ReadMode::Automatic)?;
    encrypt_to_recipients(
        plaintext,
        vec![Box::new(ArgonRecipient { key, salt, params })],
    )
}
/// Decrypts a Symaira Vault Argon2id age envelope.
pub fn decrypt_argon2id(
    ciphertext: &[u8],
    passphrase: &SecretBytes,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_argon2id_with_mode(ciphertext, passphrase, ReadMode::Automatic)
}

fn decrypt_argon2id_with_mode(
    ciphertext: &[u8],
    passphrase: &SecretBytes,
    mode: ReadMode,
) -> Result<Vec<u8>, CryptoError> {
    if identity_header_refused(ciphertext) {
        return Err(identity_header_error(ciphertext));
    }
    let decryptor = linear_decryptor(ciphertext)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let identity = ArgonIdentity {
        passphrase: SecretBytes::new(passphrase.as_bytes()),
        mode,
        error: Cell::new(None),
    };
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            identity.error.get().unwrap_or(CryptoError::new(
                FailureClass::WrongPassphraseOrKey,
                "decryption failed",
            ))
        })?;
    let mut plaintext = Vec::new();
    if mode == ReadMode::LegacyMigration {
        reader
            .take(1025)
            .read_to_end(&mut plaintext)
            .map_err(|_| malformed_argon2id())?;
        if plaintext.len() > 1024 {
            plaintext.zeroize();
            return Err(CryptoError::new(
                FailureClass::SizeLimit,
                "historical identity exceeds size limit",
            ));
        }
    } else {
        reader.read_to_end(&mut plaintext).map_err(|_| {
            CryptoError::new(FailureClass::WrongPassphraseOrKey, "decryption failed")
        })?;
    }
    Ok(plaintext)
}

/// age's `format.maxHeaderBytes`.
const MAX_AGE_HEADER_BYTES: usize = 2 << 20;
/// age's `format.maxRecipientStanzas`.
const MAX_AGE_STANZAS: usize = 1024;
/// What the `age` crate is handed for an identity file. A vault identity header
/// is about 150 bytes; the crate's header parser is superlinear in the length
/// of a line (a 64 KiB argument line costs it 17 s, Go's parser microseconds),
/// so anything beyond this is refused without calling it. Go reports such a
/// file as an identity the passphrase does not open, which the caller words.
const IDENTITY_HEADER_BUDGET: usize = 16 * 1024;
const IDENTITY_LINE_BUDGET: usize = 1024;

/// Scans an age header the way `format.Parse` accounts for it, without its
/// validation, and says whether it outgrows `limit` bytes, has a line longer
/// than `line_cap`, or more than `stanza_cap` stanzas. A malformed header makes
/// the scan stop with `false`, leaving the complaint to the real parser.
fn age_header_beyond(raw: &[u8], limit: usize, line_cap: usize, stanza_cap: usize) -> bool {
    // Charges the next line; `None` is "past a bound".
    let line_end = |position: &mut usize| -> Option<(usize, bool)> {
        let rest = &raw[*position..];
        let (length, terminated) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => (end + 1, true),
            None => (rest.len(), false),
        };
        if *position + length > limit || length > line_cap {
            return None;
        }
        let start = *position;
        *position += length;
        Some((start, terminated))
    };
    let mut position = 0;
    match line_end(&mut position) {
        None => return true,
        Some((_, false)) => return false,
        Some(_) => {}
    }
    let mut stanzas = 0;
    loop {
        if position + 3 > limit {
            return true;
        }
        if raw.len() - position < 3 {
            return false;
        }
        if &raw[position..position + 3] == b"---" {
            return line_end(&mut position).is_none();
        }
        stanzas += 1;
        if stanzas > stanza_cap {
            return true;
        }
        // A stanza: its opening line, then body lines up to the first short one.
        for index in 0.. {
            let Some((start, terminated)) = line_end(&mut position) else {
                return true;
            };
            if !terminated {
                return false;
            }
            let length = position - start - 1;
            if index == 0 {
                if !raw[start..position].starts_with(b"->") {
                    return false;
                }
            } else if length != 64 {
                break;
            }
        }
    }
}

/// Whether Go's age header parser would give up on `raw` because the header
/// outgrows 2 MiB (`header exceeds 2 MiB`), without parsing it in full. It
/// keeps an absurdly large identity file linear in the 2 MiB Go may read.
#[must_use]
pub fn age_header_exceeds_limit(raw: &[u8]) -> bool {
    age_header_beyond(raw, MAX_AGE_HEADER_BYTES, usize::MAX, usize::MAX)
}

/// Whether `raw` is not worth handing to the `age` crate as an identity file:
/// Go's 2 MiB cap and 1024-stanza cap, plus the crate's own cost limits.
fn identity_header_refused(raw: &[u8]) -> bool {
    age_header_exceeds_limit(raw)
        || age_header_beyond(
            raw,
            IDENTITY_HEADER_BUDGET,
            IDENTITY_LINE_BUDGET,
            MAX_AGE_STANZAS,
        )
}

/// Where the header of `raw` ends (the offset just past the `--- <mac>` line),
/// by `format.Parse`'s accounting and without its validation: 2 MiB at most,
/// stanza bodies as full 64-column lines up to the first short one. `None` when
/// the header is unterminated, outgrows the cap or is not shaped like one; the
/// real parser then has nothing to complain about that this scan did not.
/// One pass, linear in the bytes it reads.
fn age_header_extent(raw: &[u8]) -> Option<usize> {
    let limit = MAX_AGE_HEADER_BYTES.min(raw.len());
    let mut position = 0;
    let next_line = |position: &mut usize| -> Option<(usize, usize)> {
        let rest = &raw[*position..limit];
        let end = rest.iter().position(|&byte| byte == b'\n')?;
        let start = *position;
        *position += end + 1;
        Some((start, end))
    };
    next_line(&mut position)?;
    loop {
        if raw.get(position..position + 3)? == b"---" {
            next_line(&mut position)?;
            return Some(position);
        }
        for index in 0.. {
            let (start, length) = next_line(&mut position)?;
            if index == 0 {
                if !raw[start..].starts_with(b"->") {
                    return None;
                }
            } else if length != 64 {
                break;
            }
        }
    }
}

/// A reader over an age file that hands the `age` crate its whole header in one
/// `read_until` instead of line by line. The crate re-parses everything read so
/// far after every line it asks for, so a header of `n` lines and `s` bytes costs
/// it `n * s` (a 12 KiB header of 2000 tiny stanzas took 67 s, Go's parser
/// 0.2 s). The extent is found by one linear scan ([`age_header_extent`]);
/// anything the parser still wants beyond it is an incomplete header.
pub struct HeaderReader<'a> {
    data: &'a [u8],
    position: usize,
    header_end: usize,
}

impl std::io::Read for HeaderReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = (&self.data[self.position..]).read(buf)?;
        self.position += count;
        Ok(count)
    }
}

impl std::io::BufRead for HeaderReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(&self.data[self.position..])
    }

    fn consume(&mut self, amount: usize) {
        self.position = (self.position + amount).min(self.data.len());
    }

    fn read_until(&mut self, _byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        if self.position != 0 {
            return Ok(0);
        }
        buf.extend_from_slice(&self.data[..self.header_end]);
        self.position = self.header_end;
        Ok(self.header_end)
    }
}

/// `age::Decryptor::new` without the parser's superlinear header read, for any
/// header the vault itself guards ([`identity_header_refused`]). The error is the
/// crate's `InvalidHeader`, which every caller words as an unreadable envelope.
fn linear_decryptor(raw: &[u8]) -> Result<age::Decryptor<HeaderReader<'_>>, age::DecryptError> {
    let header_end = age_header_extent(raw).ok_or(age::DecryptError::InvalidHeader)?;
    age::Decryptor::new_buffered(HeaderReader {
        data: raw,
        position: 0,
        header_end,
    })
}

/// The longest header line, the most stanzas and the most body lines per stanza
/// the `age` crate is handed for an entry or manifest. Everything this vault
/// (and Go's `age.Encrypt`) writes is `X25519`, `scrypt` or `argon2id`: stanza
/// lines of 55-100 bytes, one body line of 43-59 columns and a 48-byte footer;
/// Go parses at most 1024 recipient stanzas. Entry ciphertext is untrusted (a git
/// pull or rsync can drop a file into `entries/`) and the crate's header parser
/// is superlinear in lines, stanzas and body lines, so a header shaped any other
/// way is refused without calling it. Rust-written entries also carry one grease
/// stanza (see [`entry_header_extent`]).
const ENTRY_LINE_BUDGET: usize = 1024;
/// The body of a grease stanza is 0-99 random bytes: at most 133 base64
/// characters, i.e. two full 64-column lines and a short (or empty) one.
const ENTRY_GREASE_BODY_LINES: usize = 3;

/// Strict, linear validation of an entry or manifest ciphertext header: the
/// exact `age-encryption.org/v1` intro, 1..=1024 stanzas of the types the vault
/// writes (`X25519` with one 43-character argument and a one-line body;
/// `scrypt` with two arguments; `argon2id` with up to four; rust-age's random
/// `*-grease` stanza with a body of up to [`ENTRY_GREASE_BODY_LINES`] lines), each
/// opening line within [`ENTRY_LINE_BUDGET`], bodies as full 64-column lines
/// then a short one, a `--- ` footer of 43 characters and the 2 MiB cap. Returns
/// the offset just past the footer line. Deliberately refuses other stanza types
/// (Go would skip them as unknown) and the pre-1.0 unterminated body, so the
/// parser is only ever handed what it digests in time.
fn entry_header_extent(raw: &[u8]) -> Option<usize> {
    const INTRO: &[u8] = b"age-encryption.org/v1\n";
    let limit = MAX_AGE_HEADER_BYTES.min(raw.len());
    let mut position = INTRO.len();
    if !raw.starts_with(INTRO) {
        return None;
    }
    let line = |position: &mut usize| -> Option<&[u8]> {
        let rest = &raw[*position..limit];
        let end = rest.iter().position(|&byte| byte == b'\n')?;
        if end + 1 > ENTRY_LINE_BUDGET {
            return None;
        }
        let text = &rest[..end];
        *position += end + 1;
        Some(text)
    };
    let mut stanzas = 0;
    loop {
        if raw.get(position..position + 3)? == b"---" {
            let footer = line(&mut position)?;
            let tag = footer.strip_prefix(b"--- ")?;
            return (stanzas > 0 && tag.len() == 43).then_some(position);
        }
        stanzas += 1;
        if stanzas > MAX_AGE_STANZAS {
            return None;
        }
        let opening = line(&mut position)?.strip_prefix(b"-> ")?;
        let mut arguments = opening.split(|&byte| byte == b' ');
        let kind = arguments.next()?;
        let shape: StanzaShape = match kind {
            b"X25519" => StanzaShape::new(1..=1, 43..=43, 1),
            b"scrypt" => StanzaShape::new(2..=2, 1..=64, 1),
            b"argon2id" => StanzaShape::new(1..=4, 1..=64, 1),
            // rust-age appends one random `<1-8 chars>-grease` stanza with up to
            // four 1-8 character arguments and a 0-99 byte body (up to three lines).
            tag if tag.len() <= 64
                && tag.ends_with(b"-grease")
                && tag.iter().all(|byte| (33..=126).contains(byte)) =>
            {
                StanzaShape::new(0..=8, 1..=64, ENTRY_GREASE_BODY_LINES)
            }
            _ => return None,
        };
        let mut count = 0;
        for argument in arguments {
            count += 1;
            if !shape.argument_length.contains(&argument.len())
                || !argument.iter().all(|byte| (33..=126).contains(byte))
            {
                return None;
            }
        }
        if !shape.arguments.contains(&count) {
            return None;
        }
        for index in 1.. {
            if index > shape.body_lines {
                return None;
            }
            if line(&mut position)?.len() != 64 {
                break;
            }
        }
    }
}

/// What a stanza of an admitted type may look like.
struct StanzaShape {
    arguments: std::ops::RangeInclusive<usize>,
    argument_length: std::ops::RangeInclusive<usize>,
    body_lines: usize,
}

impl StanzaShape {
    fn new(
        arguments: std::ops::RangeInclusive<usize>,
        argument_length: std::ops::RangeInclusive<usize>,
        body_lines: usize,
    ) -> Self {
        Self {
            arguments,
            argument_length,
            body_lines,
        }
    }
}

/// Whether `raw` (untrusted entry/manifest ciphertext) must not be handed to the
/// `age` crate: see [`entry_header_extent`]. Every caller that feeds the crate
/// bytes it did not just produce goes through [`entry_decryptor`].
#[must_use]
pub fn entry_header_refused(raw: &[u8]) -> bool {
    entry_header_extent(raw).is_none()
}

/// `age::Decryptor::new` for untrusted entry/manifest ciphertext: refuses a
/// header [`entry_header_extent`] does not admit, and reads an admitted one in a
/// single linear pass. The error is the crate's `InvalidHeader`.
pub fn entry_decryptor(raw: &[u8]) -> Result<age::Decryptor<HeaderReader<'_>>, age::DecryptError> {
    let header_end = entry_header_extent(raw).ok_or(age::DecryptError::InvalidHeader)?;
    age::Decryptor::new_buffered(HeaderReader {
        data: raw,
        position: 0,
        header_end,
    })
}

/// The error for a refused entry header: the same class and text as any other
/// envelope the `age` crate cannot parse.
fn entry_header_error() -> CryptoError {
    CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope")
}

/// The error for a refused identity header. An `argon2id` stanza whose line is
/// too long to be one is Go's `ErrArgon2Malformed` (a resource-class error that
/// is reported as it is); any other oversized header is simply an envelope the
/// passphrase does not open.
fn identity_header_error(raw: &[u8]) -> CryptoError {
    // Go's parser fails on a header past 2 MiB before it looks at any stanza.
    if age_header_exceeds_limit(raw) {
        return CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope");
    }
    let scanned = &raw[..raw.len().min(MAX_AGE_HEADER_BYTES)];
    if scanned
        .split(|&byte| byte == b'\n')
        .any(|line| line.len() > IDENTITY_LINE_BUDGET && line.starts_with(b"-> argon2id "))
    {
        return malformed_argon2id();
    }
    CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope")
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

/// Independent public authority used to validate a recovered zero-key identity.
///
/// At least one value must come from outside the encrypted plaintext. A
/// recipient contract is preferred; a fingerprint can be used when that is the
/// authority available to the caller. Supplying both values additionally checks
/// that the contract is internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroKeyAuthority<'a> {
    recipient: Option<&'a str>,
    fingerprint: Option<&'a str>,
}

impl<'a> ZeroKeyAuthority<'a> {
    /// Uses a canonical age recipient as the independent authority.
    #[must_use]
    pub const fn recipient(value: &'a str) -> Self {
        Self {
            recipient: Some(value),
            fingerprint: None,
        }
    }

    /// Uses a Go-compatible fingerprint as the independent authority.
    #[must_use]
    pub const fn fingerprint(value: &'a str) -> Self {
        Self {
            recipient: None,
            fingerprint: Some(value),
        }
    }

    /// Requires both an expected recipient and its independent fingerprint.
    #[must_use]
    pub const fn both(recipient: &'a str, fingerprint: &'a str) -> Self {
        Self {
            recipient: Some(recipient),
            fingerprint: Some(fingerprint),
        }
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 8 * 4 + 7
        && value.split(' ').all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
        })
}

fn validate_zero_key_authority(authority: ZeroKeyAuthority<'_>) -> Result<(), CryptoError> {
    let Some(value) = authority.recipient.or(authority.fingerprint) else {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key authority is missing",
        ));
    };
    if value.trim().is_empty() {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key authority is invalid",
        ));
    }
    if let Some(expected_recipient) = authority.recipient {
        let expected_recipient = expected_recipient.trim();
        let parsed = parse_recipient(expected_recipient).map_err(|_| {
            CryptoError::new(FailureClass::InvalidInput, "zero-key authority is invalid")
        })?;
        if parsed.to_string() != expected_recipient {
            return Err(CryptoError::new(
                FailureClass::InvalidInput,
                "zero-key authority is invalid",
            ));
        }
        if let Some(expected_fingerprint) = authority.fingerprint
            && (!valid_fingerprint(expected_fingerprint)
                || fingerprint(expected_recipient) != expected_fingerprint)
        {
            return Err(CryptoError::new(
                FailureClass::InvalidInput,
                "zero-key authority is invalid",
            ));
        }
    } else if let Some(expected_fingerprint) = authority.fingerprint
        && !valid_fingerprint(expected_fingerprint)
    {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key authority is invalid",
        ));
    }
    Ok(())
}

fn validate_recovered_identity(
    identity: &Identity,
    authority: ZeroKeyAuthority<'_>,
) -> Result<(), CryptoError> {
    let public = recipient_string(identity);
    if public.is_empty() || parse_recipient(&public).map(|r| r.to_string()) != Ok(public.clone()) {
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    let computed = fingerprint(&public);
    if !valid_fingerprint(&computed) {
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    if authority
        .recipient
        .is_some_and(|expected| expected.trim() != public)
        || authority
            .fingerprint
            .is_some_and(|expected| expected != computed)
    {
        return Err(CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed",
        ));
    }
    Ok(())
}

fn parse_recovered_identity(
    plaintext: &mut Vec<u8>,
    authority: ZeroKeyAuthority<'_>,
) -> Result<Identity, CryptoError> {
    let result = (|| {
        let value = std::str::from_utf8(plaintext).map_err(|_| {
            CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
        })?;
        let identity = parse_identity(value.trim()).map_err(|_| {
            CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed")
        })?;
        validate_recovered_identity(&identity, authority)?;
        Ok(identity)
    })();
    plaintext.zeroize();
    result
}

/// Recovers an identity from the historical Argon2id zero-key envelope.
///
/// The zero-key bug makes the passphrase length an unwrap hint, not proof of
/// identity. The caller must supply an independent recipient and/or fingerprint
/// contract; a self-consistent identity decrypted from `raw` is not sufficient.
pub fn recover_zero_key_identity(
    raw: &[u8],
    passphrase_len: usize,
    authority: ZeroKeyAuthority<'_>,
) -> Result<Identity, CryptoError> {
    validate_zero_key_authority(authority)?;
    if passphrase_len == 0 || passphrase_len > MAX_ZERO_KEY_PASSPHRASE_LEN {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key length is invalid",
        ));
    }
    let zeros = SecretBytes(vec![0; passphrase_len]);
    if identity_header_refused(raw) {
        return Err(identity_header_error(raw));
    }
    let decryptor = linear_decryptor(raw)
        .map_err(|_| CryptoError::new(FailureClass::MalformedEnvelope, "malformed age envelope"))?;
    let identity = ArgonIdentity {
        passphrase: zeros,
        mode: ReadMode::Automatic,
        error: Cell::new(None),
    };
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            identity.error.get().unwrap_or(CryptoError::new(
                FailureClass::ZeroKeyCandidate,
                "zero-key recovery failed",
            ))
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
    parse_recovered_identity(&mut plaintext, authority)
}

/// Go's `RecoverZeroKeyIdentityWithAuthorities`: one zero-key KDF run, then the
/// recovered identity is checked against every independently trusted authority.
///
/// The error text is Go's: an unwrap that fails is
/// `zero-key recovery failed: decryption failed`; a plaintext that is unreadable,
/// is not an identity or matches no authority is `zero-key recovery failed`; a
/// resource-policy refusal keeps its own class.
pub fn recover_zero_key_identity_with_authorities(
    raw: &[u8],
    passphrase_len: usize,
    authorities: &[ZeroKeyAuthority<'_>],
) -> Result<Identity, CryptoError> {
    if authorities.is_empty() {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key authority is invalid",
        ));
    }
    for authority in authorities {
        validate_zero_key_authority(*authority)?;
    }
    if passphrase_len == 0 || passphrase_len > MAX_ZERO_KEY_PASSPHRASE_LEN {
        return Err(CryptoError::new(
            FailureClass::InvalidInput,
            "zero-key length is invalid",
        ));
    }
    let unwrap_failed = || {
        CryptoError::new(
            FailureClass::ZeroKeyCandidate,
            "zero-key recovery failed: decryption failed",
        )
    };
    let recovery_failed =
        || CryptoError::new(FailureClass::ZeroKeyCandidate, "zero-key recovery failed");
    let zeros = SecretBytes(vec![0; passphrase_len]);
    if identity_header_refused(raw) {
        let error = identity_header_error(raw);
        return Err(if error.to_string() == "malformed argon2id stanza" {
            error
        } else {
            unwrap_failed()
        });
    }
    let decryptor = linear_decryptor(raw).map_err(|_| unwrap_failed())?;
    let identity = ArgonIdentity {
        passphrase: zeros,
        mode: ReadMode::Automatic,
        error: Cell::new(None),
    };
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| identity.error.get().unwrap_or_else(unwrap_failed))?;
    let mut plaintext = Vec::new();
    if reader.read_to_end(&mut plaintext).is_err() {
        plaintext.zeroize();
        return Err(recovery_failed());
    }
    drop(reader);
    let result = (|| {
        let value = std::str::from_utf8(&plaintext).map_err(|_| recovery_failed())?;
        let parsed = parse_identity(value.trim()).map_err(|_| recovery_failed())?;
        if authorities
            .iter()
            .any(|authority| validate_recovered_identity(&parsed, *authority).is_ok())
        {
            Ok(parsed)
        } else {
            Err(recovery_failed())
        }
    })();
    plaintext.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn chacha_cipher_preserves_key_zeroization() {
        fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        require_zeroize_on_drop::<ChaCha20Poly1305>();
    }

    const ID: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
    const ID2: &str = "AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3";
    const ID3: &str = "AGE-SECRET-KEY-15KR576PHDPLRQS08427S6X2G492S6GTVELZ6WHN8AKMWW90T0HES2KQ597";

    #[test]
    fn bounded_age_decrypt_accepts_exact_plaintext_limit_and_rejects_one_over() {
        let identity = parse_identity(ID).unwrap();
        let exact_ciphertext = encrypt(b"12345", &[Recipient(identity.0.to_public())]).unwrap();
        assert_eq!(
            decrypt_bounded(&exact_ciphertext, &identity, 5).unwrap(),
            b"12345"
        );

        let oversized_ciphertext =
            encrypt(b"123456", &[Recipient(identity.0.to_public())]).unwrap();
        assert_eq!(
            decrypt_bounded(&oversized_ciphertext, &identity, 5)
                .unwrap_err()
                .class(),
            FailureClass::SizeLimit
        );
    }

    #[test]
    fn entry_read_v1_plaintext_ceiling_fits_ciphertext_budget() {
        const MAX_ENTRY_PLAINTEXT_BYTES_V1: usize = 16 * 1024 * 1024;
        const MAX_ENTRY_CIPHERTEXT_BYTES_V1: usize = 24 * 1024 * 1024;
        let identity = parse_identity(ID).unwrap();
        let plaintext = vec![b'x'; MAX_ENTRY_PLAINTEXT_BYTES_V1];
        let ciphertext = encrypt(&plaintext, &[Recipient(identity.0.to_public())]).unwrap();
        assert!(ciphertext.len() <= MAX_ENTRY_CIPHERTEXT_BYTES_V1);
        assert_eq!(
            decrypt_bounded(&ciphertext, &identity, MAX_ENTRY_PLAINTEXT_BYTES_V1 as u64).unwrap(),
            plaintext
        );
    }
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
        "ca4bbd74bb522310093157aaed280121be2b1a0aa003af5ee7ac5cd8cc224623";

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
        reencrypt_all_cases: Vec<OracleReencryptAll>,
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
        expected_recipient: String,
        expected_fingerprint: String,
        expected_class: String,
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
    #[derive(serde::Deserialize)]
    struct OracleReencryptAll {
        name: String,
        source_identity: String,
        source_recipients: Vec<String>,
        recipients: Vec<String>,
        removed_recipient: String,
        removed_identity: String,
        before_manifest: OracleManifest,
        after_manifest: OracleManifest,
        files: Vec<OracleReencryptFile>,
    }

    #[derive(serde::Deserialize)]
    struct OracleManifest {
        entries: Vec<OracleManifestEntry>,
    }

    #[derive(serde::Deserialize)]
    struct OracleManifestEntry {
        path: String,
        sha256: String,
        size: i64,
    }

    #[derive(serde::Deserialize)]
    struct OracleReencryptFile {
        path: String,
        plaintext: String,
        before_ciphertext: String,
        after_ciphertext: String,
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
            &[
                "historical_zero_key_length_23",
                "zero_key_length_exact_max",
                "zero_key_length_over_max",
                "zero_key_wrong_authority",
            ],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.reencrypt_cases,
            &["add_recipient", "remove_recipient"],
            |v| &v.name,
        )?;
        assert_names(
            &fixture.reencrypt_all_cases,
            &["filesystem_add_recipient", "filesystem_remove_recipient"],
            |v| &v.name,
        )?;
        for item in &fixture.reencrypt_all_cases {
            if item.source_identity.is_empty()
                || item.source_recipients.is_empty()
                || item.recipients.len() < 2
                || item.files.is_empty()
                || item.before_manifest.entries.len() != item.files.len()
                || item.after_manifest.entries.len() != item.files.len()
            {
                return Err(format!(
                    "incomplete filesystem re-encryption case {}",
                    item.name
                ));
            }
            for file in &item.files {
                if file.path.is_empty()
                    || file.plaintext.is_empty()
                    || file.before_ciphertext.is_empty()
                    || file.after_ciphertext.is_empty()
                {
                    return Err(format!(
                        "incomplete filesystem re-encryption file {}",
                        file.path
                    ));
                }
            }
        }
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
        for item in &fixture.zero_key_cases {
            if item.ciphertext.is_empty()
                || item.passphrase_length == 0
                || item.expected_recipient.is_empty()
                || item.expected_fingerprint.is_empty()
                || !matches!(
                    item.expected_class.as_str(),
                    "ok" | "invalid_input" | "zero_key_candidate"
                )
            {
                return Err(format!("incomplete zero-key case {}", item.name));
            }
        }
        Ok(())
    }

    fn sha256_hex(value: &[u8]) -> String {
        Sha256::digest(value)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[cfg(not(miri))]
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
            let result = recover_zero_key_identity(
                &ciphertext,
                case.passphrase_length,
                ZeroKeyAuthority::both(&case.expected_recipient, &case.expected_fingerprint),
            );
            match case.expected_class.as_str() {
                "ok" => {
                    let recovered = result.unwrap();
                    assert_eq!(
                        recipient_string(&recovered),
                        case.expected_recipient,
                        "{}",
                        case.name
                    );
                }
                "invalid_input" => assert_eq!(
                    result.unwrap_err().class(),
                    FailureClass::InvalidInput,
                    "{}",
                    case.name
                ),
                "zero_key_candidate" => assert_eq!(
                    result.unwrap_err().class(),
                    FailureClass::ZeroKeyCandidate,
                    "{}",
                    case.name
                ),
                other => panic!("unknown zero-key class {other}"),
            }
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

    #[cfg(not(miri))]
    #[test]
    fn fixture_validation_rejects_omission_and_tampered_provenance() {
        let (raw, fixture) = load_fixture();
        validate_fixture(&fixture).unwrap();
        for key in [
            "identities",
            "age_cases",
            "scrypt_cases",
            "argon2id_cases",
            "zero_key_cases",
            "reencrypt_cases",
            "reencrypt_all_cases",
            "malformed_cases",
            "limit_cases",
            "wrong_passphrase_cases",
            "migration_cases",
        ] {
            let mut omitted: serde_json::Value = serde_json::from_str(&raw).unwrap();
            omitted[key].as_array_mut().unwrap().pop();
            let omitted_fixture: OracleFixture = serde_json::from_value(omitted).unwrap();
            assert!(validate_fixture(&omitted_fixture).is_err(), "{key}");
        }
        for key in ["reencrypt_cases", "reencrypt_all_cases"] {
            let mut tampered: serde_json::Value = serde_json::from_str(&raw).unwrap();
            tampered[key][0]["name"] = serde_json::Value::String("tampered".to_owned());
            let tampered_fixture: OracleFixture = serde_json::from_value(tampered).unwrap();
            assert!(validate_fixture(&tampered_fixture).is_err(), "{key}");
        }
        for key in ["source_digest", "generator_digest"] {
            let mut tampered: serde_json::Value = serde_json::from_str(&raw).unwrap();
            tampered["oracle"][key] = serde_json::Value::String("0".repeat(64));
            let tampered_fixture: OracleFixture = serde_json::from_value(tampered).unwrap();
            assert!(validate_fixture(&tampered_fixture).is_err(), "{key}");
        }
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
        for case in &fixture.reencrypt_all_cases {
            let source = parse_identity(&case.source_identity).unwrap();
            let removed_identity = parse_identity(&case.removed_identity).unwrap();
            assert_eq!(recipient_string(&removed_identity), case.removed_recipient);
            let retained: Vec<Recipient> = case
                .recipients
                .iter()
                .map(|recipient| parse_recipient(recipient).unwrap())
                .collect();
            assert!(retained.len() >= 2);
            let before_manifest: std::collections::HashMap<_, _> = case
                .before_manifest
                .entries
                .iter()
                .map(|entry| (&entry.path, entry))
                .collect();
            let after_manifest: std::collections::HashMap<_, _> = case
                .after_manifest
                .entries
                .iter()
                .map(|entry| (&entry.path, entry))
                .collect();
            let root = std::env::temp_dir().join(format!(
                "symvault-crypto-reencrypt-all-{}",
                std::process::id()
            ));
            let entries_root = root.join("entries");
            std::fs::create_dir_all(&entries_root).unwrap();
            for file in &case.files {
                let plaintext = base64::engine::general_purpose::STANDARD
                    .decode(&file.plaintext)
                    .unwrap();
                let before = base64::engine::general_purpose::STANDARD
                    .decode(&file.before_ciphertext)
                    .unwrap();
                let after = base64::engine::general_purpose::STANDARD
                    .decode(&file.after_ciphertext)
                    .unwrap();
                assert_eq!(decrypt(&before, &source).unwrap(), plaintext);
                for identity_case in &fixture.identities {
                    if case.recipients.contains(&identity_case.recipient) {
                        let identity = parse_identity(&identity_case.identity).unwrap();
                        assert_eq!(decrypt(&after, &identity).unwrap(), plaintext);
                    }
                }
                assert_eq!(
                    decrypt(&after, &removed_identity).unwrap_err().class(),
                    FailureClass::WrongPassphraseOrKey
                );
                let before_entry = before_manifest.get(&file.path).unwrap();
                let after_entry = after_manifest.get(&file.path).unwrap();
                assert_eq!(before_entry.size, before.len() as i64);
                assert_eq!(after_entry.size, after.len() as i64);
                assert_eq!(before_entry.sha256, sha256_hex(&before));
                assert_eq!(after_entry.sha256, sha256_hex(&after));
                let path = entries_root.join(format!("{}.age", file.path));
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(&path, &after).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), after);
            }
            std::fs::remove_dir_all(&root).unwrap();
            let _ = retained;
        }

        let zero = &fixture.zero_key_cases[0];
        let zero_ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&zero.ciphertext)
            .unwrap();
        assert_eq!(
            recover_zero_key_identity(
                &zero_ciphertext,
                0,
                ZeroKeyAuthority::recipient(&fixture.identities[0].recipient),
            )
            .unwrap_err()
            .class(),
            FailureClass::InvalidInput
        );
        assert_eq!(
            recover_zero_key_identity(
                &zero_ciphertext,
                MAX_ZERO_KEY_PASSPHRASE_LEN + 1,
                ZeroKeyAuthority::recipient(&fixture.identities[0].recipient),
            )
            .unwrap_err()
            .class(),
            FailureClass::InvalidInput
        );
        assert_eq!(
            recover_zero_key_identity(
                &zero_ciphertext,
                MAX_ZERO_KEY_PASSPHRASE_LEN,
                ZeroKeyAuthority::recipient(&fixture.identities[0].recipient),
            )
            .unwrap_err()
            .class(),
            FailureClass::ZeroKeyCandidate
        );
        assert_eq!(
            recover_zero_key_identity(
                &zero_ciphertext,
                zero.passphrase_length + 1,
                ZeroKeyAuthority::recipient(&fixture.identities[0].recipient),
            )
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
            recover_zero_key_identity(
                &malformed_identity,
                zero.passphrase_length,
                ZeroKeyAuthority::recipient(&fixture.identities[0].recipient),
            )
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
    fn zero_key_recovery_requires_independent_authority() {
        let expected = parse_identity(ID).unwrap();
        let attacker = parse_identity(ID2).unwrap();
        let zeros = SecretBytes::new(&[0; 23]);
        let ciphertext = encrypt_argon2id(
            ID2.as_bytes(),
            &zeros,
            Argon2idParams {
                time: 1,
                memory_kib: 32,
                threads: 1,
            },
        )
        .unwrap();
        let error = recover_zero_key_identity(
            &ciphertext,
            23,
            ZeroKeyAuthority::recipient(&recipient_string(&expected)),
        )
        .unwrap_err();
        assert_eq!(error.class(), FailureClass::ZeroKeyCandidate);
        assert_eq!(error.to_string(), "zero-key recovery failed");
        assert!(!format!("{error:?}").contains(ID2));

        let expected_fingerprint = fingerprint(&recipient_string(&expected));
        let recovered = recover_zero_key_identity(
            &ciphertext,
            23,
            ZeroKeyAuthority::fingerprint(&fingerprint(&recipient_string(&attacker))),
        )
        .unwrap();
        assert_eq!(recipient_string(&recovered), recipient_string(&attacker));
        assert_ne!(
            expected_fingerprint,
            fingerprint(&recipient_string(&recovered))
        );

        let invalid_authority = recover_zero_key_identity(
            &ciphertext,
            23,
            ZeroKeyAuthority::both(&recipient_string(&expected), "not a fingerprint"),
        )
        .unwrap_err();
        assert_eq!(invalid_authority.class(), FailureClass::InvalidInput);
    }

    #[test]
    fn recovery_with_authorities_derives_once_and_words_failures_like_go() {
        let expected = parse_identity(ID).unwrap();
        let other = parse_identity(ID2).unwrap();
        let params = Argon2idParams {
            time: 1,
            memory_kib: 32,
            threads: 1,
        };
        let zeros = SecretBytes::new(&[0; 23]);
        let ciphertext = encrypt_argon2id(ID.as_bytes(), &zeros, params).unwrap();
        let (right, wrong) = (recipient_string(&expected), recipient_string(&other));

        // Any listed authority that matches recovers the identity.
        let recovered = recover_zero_key_identity_with_authorities(
            &ciphertext,
            23,
            &[
                ZeroKeyAuthority::recipient(&wrong),
                ZeroKeyAuthority::recipient(&right),
            ],
        )
        .unwrap();
        assert_eq!(recipient_string(&recovered), right);

        // Nothing matches: Go's bare `ErrZeroKeyRecovery`.
        let mismatch = recover_zero_key_identity_with_authorities(
            &ciphertext,
            23,
            &[ZeroKeyAuthority::recipient(&wrong)],
        )
        .unwrap_err();
        assert_eq!(mismatch.to_string(), "zero-key recovery failed");

        // A key of another length does not unwrap: `ErrZeroKeyRecovery: ErrDecryptionFailed`.
        let unwrap = recover_zero_key_identity_with_authorities(
            &ciphertext,
            22,
            &[ZeroKeyAuthority::recipient(&right)],
        )
        .unwrap_err();
        assert_eq!(
            unwrap.to_string(),
            "zero-key recovery failed: decryption failed"
        );

        // Authorities are checked before the length, the length before the KDF.
        let invalid =
            recover_zero_key_identity_with_authorities(&ciphertext, 1025, &[]).unwrap_err();
        assert_eq!(invalid.class(), FailureClass::InvalidInput);
        let too_long = recover_zero_key_identity_with_authorities(
            &ciphertext,
            MAX_ZERO_KEY_PASSPHRASE_LEN + 1,
            &[ZeroKeyAuthority::recipient(&right)],
        )
        .unwrap_err();
        assert_eq!(too_long.to_string(), "zero-key length is invalid");
    }

    #[test]
    fn age_header_limit_follows_go_byte_accounting() {
        let intro = b"age-encryption.org/v1\n";
        let footer = [b"--- ".as_slice(), &[b'A'; 43], b"\n"].concat();
        let header = |pad: usize| {
            [
                intro.as_slice(),
                b"-> scrypt AAAAAAAAAAAAAAAAAAAAAA 15 ",
                &vec![b'z'; pad],
                b"\nAAAA\n",
                &footer,
            ]
            .concat()
        };
        let base = header(0).len();
        // The header, closing line included, may be exactly 2 MiB.
        assert!(!age_header_exceeds_limit(&header(
            MAX_AGE_HEADER_BYTES - base
        )));
        assert!(age_header_exceeds_limit(&header(
            MAX_AGE_HEADER_BYTES - base + 1
        )));
        // Payload after the closing line is not charged.
        let mut with_payload = header(0);
        with_payload.extend_from_slice(&vec![0; 3 << 20]);
        assert!(!age_header_exceeds_limit(&with_payload));
        // No newline at all: charged up to the limit.
        assert!(age_header_exceeds_limit(
            &[intro.as_slice(), &vec![b'x'; 3 << 20]].concat()
        ));
        assert!(!age_header_exceeds_limit(b"garbage"));
        // A header the `age` crate would chew on for minutes is refused, with
        // Go's resource-class error for an argon2id stanza that long.
        let long = [
            intro.as_slice(),
            b"-> argon2id AAAAAAAAAAAAAAAAAAAAAA ",
            &vec![b'z'; 64 * 1024],
            b"\nAAAA\n",
            &footer,
        ]
        .concat();
        assert!(!age_header_exceeds_limit(&long));
        assert!(identity_header_refused(&long));
        assert_eq!(
            identity_header_error(&long).to_string(),
            "malformed argon2id stanza"
        );
        let started = std::time::Instant::now();
        let error = decrypt_identity(&long, &SecretBytes::new(b"passphrase")).unwrap_err();
        assert_eq!(error.to_string(), "malformed argon2id stanza");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// `age-encryption.org/v1`, `stanzas`, then a 43-character MAC and a payload
    /// that is long enough for the nonce.
    fn crafted_header(stanzas: &[u8]) -> Vec<u8> {
        let mut raw = b"age-encryption.org/v1\n".to_vec();
        raw.extend_from_slice(stanzas);
        raw.extend_from_slice(b"--- ");
        raw.extend(std::iter::repeat_n(b'A', 43));
        raw.push(b'\n');
        raw.extend_from_slice(&[0; 64]);
        raw
    }

    fn repeated(unit: &[u8], count: usize) -> Vec<u8> {
        unit.repeat(count)
    }

    /// The hostile header shapes of the SET-004c review, each cheap to build and
    /// each minutes of work for the `age` crate's header parser (measured in a
    /// debug build: 2000 tiny stanzas 67 s, one stanza of 200 body lines 21 s,
    /// 32 stanzas of 1 KiB lines 15 s, a 2 MiB header more than 100 s).
    fn hostile_headers() -> Vec<(&'static str, Vec<u8>)> {
        let kilo_line = [b"-> X25519 ".as_slice(), &[b'z'; 1000], b"\nAAAA\n"].concat();
        let mut two_mib_of_lines = Vec::new();
        while two_mib_of_lines.len() < (2 << 20) - 2000 {
            two_mib_of_lines.extend_from_slice(&kilo_line);
        }
        let mut two_mib_of_tiny = Vec::new();
        while two_mib_of_tiny.len() < (2 << 20) - 2000 {
            two_mib_of_tiny.extend_from_slice(b"-> a\n\n");
        }
        let body_lines = [
            b"-> X25519 ".as_slice(),
            &[b'A'; 43],
            b"\n",
            &repeated(&[&[b'A'; 64][..], b"\n"].concat(), 200),
            b"\n",
        ]
        .concat();
        let x25519 = [b"-> X25519 ".as_slice(), &[b'A'; 43], b"\nAAAA\n"].concat();
        vec![
            (
                "2000 tiny stanzas",
                crafted_header(&repeated(b"-> a\n\n", 2000)),
            ),
            (
                "1000 tiny stanzas",
                crafted_header(&repeated(b"-> a\n\n", 1000)),
            ),
            ("2 MiB of tiny stanzas", crafted_header(&two_mib_of_tiny)),
            ("one stanza of 200 body lines", crafted_header(&body_lines)),
            (
                "32 stanzas of 1 KiB lines",
                crafted_header(&repeated(&kilo_line, 32)),
            ),
            (
                "2 MiB of sub-1-KiB lines",
                crafted_header(&two_mib_of_lines),
            ),
            (
                "1025 valid-looking X25519 stanzas",
                crafted_header(&repeated(&x25519, 1025)),
            ),
            (
                "unknown stanza type",
                crafted_header(&[b"-> mystery ".as_slice(), &[b'A'; 43], b"\nAAAA\n"].concat()),
            ),
            (
                "X25519 with a second argument",
                crafted_header(&[b"-> X25519 ".as_slice(), &[b'A'; 43], b" x\nAAAA\n"].concat()),
            ),
            ("no stanza at all", crafted_header(b"")),
            (
                "unterminated stanza body",
                [
                    b"age-encryption.org/v1\n-> X25519 ".as_slice(),
                    &[b'A'; 43],
                    b"\nAAAA",
                ]
                .concat(),
            ),
            (
                "grease body of four lines",
                crafted_header(
                    &[
                        b"-> x-grease\n".as_slice(),
                        &repeated(&[&[b'A'; 64][..], b"\n"].concat(), 3),
                        b"\n",
                    ]
                    .concat(),
                ),
            ),
        ]
    }

    #[test]
    fn entry_header_validator_accepts_everything_the_vault_writes() {
        let identity = generate_identity();
        let own = || parse_recipient(&recipient_string(&identity)).unwrap();
        let single = encrypt(b"payload", &[own()]).unwrap();
        assert!(!entry_header_refused(&single));

        // 171 recipients (a header over 16 KiB) and Go's 1024-stanza limit.
        for count in [171, 1023] {
            let recipients: Vec<Recipient> = std::iter::once(own())
                .chain(
                    (1..count)
                        .map(|_| parse_recipient(&recipient_string(&generate_identity())).unwrap()),
                )
                .collect();
            let wide = encrypt(b"payload", &recipients).unwrap();
            let header_end = wide
                .windows(5)
                .position(|window| window == b"\n--- ")
                .unwrap();
            assert!(count != 171 || header_end > IDENTITY_HEADER_BUDGET);
            assert!(!entry_header_refused(&wide), "{count} recipients");
            assert_eq!(decrypt(&wide, &identity).unwrap(), b"payload");
            assert_eq!(decrypt_bounded(&wide, &identity, 64).unwrap(), b"payload");
        }

        let scrypt = encrypt_scrypt(b"payload", &SecretBytes::new(b"pw"), 4).unwrap();
        assert!(!entry_header_refused(&scrypt));
        let argon = encrypt_argon2id(
            b"payload",
            &SecretBytes::new(b"pw"),
            Argon2idParams {
                time: 1,
                memory_kib: 32,
                threads: 1,
            },
        )
        .unwrap();
        assert!(!entry_header_refused(&argon));
        assert_eq!(
            decrypt_argon2id(&argon, &SecretBytes::new(b"pw")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn rust_age_grease_stanzas_of_every_size_are_admitted() {
        // The crate appends one random `*-grease` stanza: tag and up to four
        // arguments of 1-8 characters, a 0-99 byte body (up to three lines).
        let identity = generate_identity();
        let recipient = parse_recipient(&recipient_string(&identity)).unwrap();
        for _ in 0..300 {
            let ciphertext = encrypt(b"payload", std::slice::from_ref(&recipient)).unwrap();
            assert!(!entry_header_refused(&ciphertext));
            assert_eq!(decrypt(&ciphertext, &identity).unwrap(), b"payload");
        }
    }

    #[test]
    fn hostile_entry_headers_are_refused_in_microseconds_by_every_entry_decrypt() {
        let identity = generate_identity();
        for (name, header) in hostile_headers() {
            assert!(entry_header_refused(&header), "{name}");
            let started = std::time::Instant::now();
            for result in [
                decrypt(&header, &identity),
                decrypt_bounded(&header, &identity, 1024),
            ] {
                let error = result.unwrap_err();
                assert_eq!(error.class(), FailureClass::MalformedEnvelope, "{name}");
                assert_eq!(error.to_string(), "malformed age envelope", "{name}");
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "{name}: the age parser was reached: {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn oversized_identity_header_line_is_refused_quickly_by_every_identity_decrypt() {
        let mut evil = b"age-encryption.org/v1\n-> X25519 ".to_vec();
        evil.extend(vec![b'z'; 64 * 1024]);
        evil.extend_from_slice(b"\nAAAA\n--- ");
        evil.extend(vec![b'A'; 43]);
        evil.push(b'\n');
        evil.extend_from_slice(&[0; 64]);
        let started = std::time::Instant::now();
        let error = decrypt_scrypt(&evil, &SecretBytes::new(b"passphrase")).unwrap_err();
        assert_eq!(error.class(), FailureClass::MalformedEnvelope);
        assert_eq!(error.to_string(), "malformed age envelope");
        assert_eq!(
            inspect_argon2id_policy(&evil).unwrap_err().to_string(),
            "malformed argon2id stanza"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the age parser was reached: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn identity_files_get_their_header_in_one_linear_pass() {
        // `identity_header_refused` lets 1024 stanzas and 16 KiB through; handed to
        // the crate line by line they cost it 10-20 s (debug) however few the
        // bytes. Every such shape must now be an ordinary refusal or a failed
        // unwrap in well under that.
        let passphrase = SecretBytes::new(b"passphrase");
        let body_lines = crafted_header(
            &[
                b"-> scrypt AAAAAAAAAAAAAAAAAAAAAA 10\n".as_slice(),
                &repeated(&[&[b'A'; 64][..], b"\n"].concat(), 200),
                b"\n",
            ]
            .concat(),
        );
        for (name, header) in [
            (
                "1000 tiny stanzas",
                crafted_header(&repeated(b"-> a\n\n", 1000)),
            ),
            ("200 body lines", body_lines),
        ] {
            let started = std::time::Instant::now();
            assert!(decrypt_scrypt(&header, &passphrase).is_err(), "{name}");
            assert!(inspect_argon2id_policy(&header).is_err(), "{name}");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{name}: {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn header_extent_stops_at_the_footer_and_leaves_the_payload_alone() {
        let identity = generate_identity();
        let recipient = parse_recipient(&recipient_string(&identity)).unwrap();
        let ciphertext = encrypt(&vec![7u8; 200_000], &[recipient]).unwrap();
        let end = age_header_extent(&ciphertext).unwrap();
        assert_eq!(end, entry_header_extent(&ciphertext).unwrap());
        assert_eq!(ciphertext[end - 1], b'\n');
        assert_eq!(decrypt(&ciphertext, &identity).unwrap(), vec![7u8; 200_000]);
        // A header without its footer line has no extent.
        assert_eq!(age_header_extent(&ciphertext[..end - 1]), None);
        assert!(entry_decryptor(&ciphertext[..end - 1]).is_err());
    }

    #[test]
    fn secret_formatting_is_redacted() {
        let secret = SecretBytes::new(b"do-not-print");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");
    }

    #[test]
    fn argon2id_limits_accept_exact_budget_and_reject_over_limit() {
        for value in [
            format!("t={MAX_ARGON2_TIME},m=32,p=1"),
            format!("t=1,m={MAX_ARGON2_MEMORY},p=1"),
            format!("t=1,m=64,p={MAX_ARGON2_THREADS}"),
        ] {
            assert!(parse_argon2id_params(&value).is_ok(), "{value}");
        }
        for value in [
            format!("t={},m=32,p=1", MAX_ARGON2_TIME + 1),
            format!("t=1,m={},p=1", MAX_ARGON2_MEMORY + 1),
            format!("t=1,m=64,p={}", MAX_ARGON2_THREADS + 1),
        ] {
            assert_eq!(
                parse_argon2id_params(&value).unwrap_err().class(),
                FailureClass::ParameterBounds,
                "{value}"
            );
        }
    }

    #[test]
    fn argon2id_parameter_parser_rejects_ambiguous_and_oversized_values() {
        assert_eq!(
            parse_argon2id_params("t=1,m=32,p=1").unwrap(),
            Argon2idParams {
                time: 1,
                memory_kib: 32,
                threads: 1,
            }
        );
        for value in [
            "t=1,t=1,m=32,p=1",
            "t=1,m=32,p=1,extra=1",
            "t=1,m=32",
            "t=1,m=32,p=1,",
        ] {
            assert_eq!(
                parse_argon2id_params(value).unwrap_err().class(),
                FailureClass::MalformedEnvelope,
                "{value}"
            );
        }
        let oversized = format!("t=1,m=32,p=1,{}", "x".repeat(MAX_ARGON2ID_PARAMS_BYTES));
        assert_eq!(
            parse_argon2id_params(&oversized).unwrap_err().class(),
            FailureClass::MalformedEnvelope
        );
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

#[cfg(test)]
mod kdf_policy_tests;
