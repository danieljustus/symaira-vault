//! Session cache contracts with injected keyring and clock boundaries.
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroize;

pub const SESSION_ACCOUNT: &str = "session";
pub const IDENTITY_ACCOUNT: &str = "identity";
pub const WRAP_KEY_ACCOUNT: &str = "wrap-key";
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
const GO_ZERO_NANOS: i128 = -62_135_596_800_000_000_000;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("keyring unavailable: {0}")]
    Keyring(String),
    #[error("session not found")]
    NotFound,
    #[error("session is expired: {0}")]
    Expired(&'static str),
    #[error("session payload is malformed: {0}")]
    Malformed(String),
    #[error("session uses legacy plaintext format")]
    LegacyPlaintext,
    #[error("session cryptography failed: {0}")]
    Crypto(String),
}

/// Splits a composite keyring key into its service and account halves.
///
/// This is the pure seam the SESSION-002 contract pins: no filesystem, no
/// keychain, no platform. The Go side is `session.SplitKeyringKey`.
///
/// `None` means the key carries no `"service|account"` separator at all. Such a
/// key cannot name a native keychain item -- it would be stored under an empty
/// service, where every separator-less key collides -- so native backends
/// refuse it. In-memory backends have no such hazard and key by the whole
/// string, so they keep accepting it.
///
/// The split is taken at the LAST separator, so a service that itself contains
/// `'|'` (a vault directory may) still resolves to the intended account.
#[must_use]
pub fn split_keyring_key(key: &str) -> Option<(&str, &str)> {
    let index = key.rfind('|')?;
    Some((&key[..index], &key[index + 1..]))
}

/// Every keyring side effect crosses this trait. Native implementations are separate.
pub trait Keyring: Send + Sync {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError>;
    fn delete(&self, key: &str) -> Result<(), SessionError>;
}

#[derive(Default)]
pub struct MemoryKeyring {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
}
impl MemoryKeyring {
    pub fn new() -> Self {
        Self::default()
    }
}
impl Keyring for MemoryKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        self.values
            .lock()
            .map_err(|_| SessionError::Keyring("keyring mutex poisoned".into()))?
            .get(key)
            .cloned()
            .ok_or(SessionError::NotFound)
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        self.values
            .lock()
            .map_err(|_| SessionError::Keyring("keyring mutex poisoned".into()))?
            .insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), SessionError> {
        self.values
            .lock()
            .map_err(|_| SessionError::Keyring("keyring mutex poisoned".into()))?
            .remove(key);
        Ok(())
    }
}

/// Native keychain access is a platform feature, not a fake fallback.
#[derive(Default)]
pub struct NativeKeyring;
impl Keyring for NativeKeyring {
    fn get(&self, _: &str) -> Result<Vec<u8>, SessionError> {
        Err(SessionError::Keyring(
            "native keyring backend unavailable".into(),
        ))
    }
    fn set(&self, _: &str, _: &[u8]) -> Result<(), SessionError> {
        Err(SessionError::Keyring(
            "native keyring backend unavailable".into(),
        ))
    }
    fn delete(&self, _: &str) -> Result<(), SessionError> {
        Err(SessionError::Keyring(
            "native keyring backend unavailable".into(),
        ))
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}
#[derive(Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Timestamp {
    Text(String),
}
impl Timestamp {
    fn nanos(&self) -> Result<i128, SessionError> {
        match self {
            Self::Text(v) => parse_timestamp(v)
                .ok_or_else(|| SessionError::Malformed(format!("invalid timestamp {v:?}"))),
        }
    }
    fn is_go_zero(&self) -> bool {
        self.nanos().is_ok_and(|nanos| nanos == GO_ZERO_NANOS)
    }
}
fn timestamp(t: SystemTime) -> Result<Timestamp, SessionError> {
    let d = t
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SessionError::Malformed(e.to_string()))?;
    let s = d.as_secs();
    let days = s / 86_400;
    let rem = s % 86_400;
    let z = days as i64 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    y += if month <= 2 { 1 } else { 0 };
    let frac = d.subsec_nanos();
    let suffix = if frac == 0 {
        String::new()
    } else {
        let mut f = format!("{frac:09}");
        while f.ends_with('0') {
            f.pop();
        }
        format!(".{f}")
    };
    Ok(Timestamp::Text(format!(
        "{y:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{suffix}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )))
}
fn parse_timestamp(v: &str) -> Option<i128> {
    let b = v.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let n = |a: usize, z: usize| {
        let digits = b.get(a..z)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse::<u64>().ok()
    };
    let y = n(0, 4)? as i64;
    let m = n(5, 7)? as i64;
    let d = n(8, 10)? as i64;
    let h = n(11, 13)?;
    let min = n(14, 16)?;
    let sec = n(17, 19)?;
    if m == 0 || m > 12 || d == 0 || d > 31 || h > 23 || min > 59 || sec > 60 {
        return None;
    };
    let leap_year = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = match m {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if d > days_in_month {
        return None;
    }
    let (frac, end) = if b[19] == b'.' || b[19] == b',' {
        let end = 20
            + b[20..]
                .iter()
                .position(|x| *x == b'Z' || *x == b'+' || *x == b'-')
                .unwrap_or(b.len() - 20);
        let digits = &b[20..end];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let width = digits.len().min(9);
        let f = std::str::from_utf8(&digits[..width])
            .ok()?
            .parse::<u64>()
            .ok()?;
        (f * 10u64.pow(9 - width as u32), end)
    } else {
        (0, 19)
    };
    let offset = match b.get(end)? {
        b'Z' if end + 1 == b.len() => 0i128,
        sign @ (b'+' | b'-') if end + 6 == b.len() && b[end + 3] == b':' => {
            let hours = n(end + 1, end + 3)?;
            let minutes = n(end + 4, end + 6)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let seconds = (hours * 60 + minutes) as i128 * 60;
            if *sign == b'+' { seconds } else { -seconds }
        }
        _ => return None,
    };
    let (mut yy, mm) = (y, m);
    if mm <= 2 {
        yy -= 1;
    }
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (mm + if mm > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    i128::from(days)
        .checked_mul(86400)?
        .checked_add((h * 3600 + min * 60 + sec) as i128)?
        .checked_sub(offset)?
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(frac))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSession {
    saved_at: Timestamp,
    last_access: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    ttl_ns: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    max_lifetime_ns: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredIdentity {
    saved_at: Timestamp,
    last_access: Timestamp,
    encrypted_identity: String,
    nonce: String,
    ttl_ns: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    max_lifetime_ns: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

pub struct SessionManager {
    keyring: Arc<dyn Keyring>,
    clock: Arc<dyn Clock>,
}
impl SessionManager {
    pub fn new(keyring: Arc<dyn Keyring>, clock: Arc<dyn Clock>) -> Self {
        Self { keyring, clock }
    }
    pub fn with_system_clock(keyring: Arc<dyn Keyring>) -> Self {
        Self::new(keyring, Arc::new(SystemClock))
    }
    fn key(vault: &str, account: &str) -> String {
        format!("symvault:{vault}|{account}")
    }
    fn now(&self) -> Result<(i128, Timestamp), SessionError> {
        let t = self.clock.now();
        Ok((
            t.duration_since(UNIX_EPOCH)
                .map_err(|e| SessionError::Malformed(e.to_string()))?
                .as_nanos()
                .min(i128::MAX as u128) as i128,
            timestamp(t)?,
        ))
    }
    fn wrap_key(&self, vault: &str, create: bool) -> Result<[u8; 32], SessionError> {
        match self.keyring.get(&Self::key(vault, WRAP_KEY_ACCOUNT)) {
            Ok(raw) => raw
                .try_into()
                .map_err(|_| SessionError::Malformed("wrap key must be 32 bytes".into())),
            Err(SessionError::NotFound) if create => {
                let mut raw = [0; 32];
                fill(&mut raw).map_err(|e| SessionError::Crypto(e.to_string()))?;
                self.keyring
                    .set(&Self::key(vault, WRAP_KEY_ACCOUNT), &raw)?;
                Ok(raw)
            }
            Err(e) => Err(e),
        }
    }
    fn encrypt(&self, vault: &str, value: &[u8]) -> Result<(String, String), SessionError> {
        let key = self.wrap_key(vault, true)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let mut nonce = [0; 12];
        fill(&mut nonce).map_err(|e| SessionError::Crypto(e.to_string()))?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), value)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        Ok((B64.encode(encrypted), B64.encode(nonce)))
    }
    fn decrypt(&self, vault: &str, encrypted: &str, nonce: &str) -> Result<Vec<u8>, SessionError> {
        let key = self.wrap_key(vault, false)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let payload = B64
            .decode(encrypted)
            .map_err(|e| SessionError::Malformed(e.to_string()))?;
        let nonce = B64
            .decode(nonce)
            .map_err(|e| SessionError::Malformed(e.to_string()))?;
        if nonce.len() != 12 {
            return Err(SessionError::Malformed("nonce must be 12 bytes".into()));
        }
        cipher
            .decrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .map_err(|e| SessionError::Crypto(e.to_string()))
    }
    pub fn save_passphrase(
        &self,
        vault: &str,
        passphrase: &[u8],
        ttl: Duration,
        max: Duration,
    ) -> Result<(), SessionError> {
        let (_, t) = self.now()?;
        let (e, n) = self.encrypt(vault, passphrase)?;
        let s = StoredSession {
            saved_at: t.clone(),
            last_access: t,
            passphrase: None,
            encrypted_passphrase: Some(e),
            nonce: Some(n),
            ttl_ns: duration_ns(ttl),
            max_lifetime_ns: duration_ns(max),
        };
        self.keyring.set(
            &Self::key(vault, SESSION_ACCOUNT),
            &serde_json::to_vec(&s).map_err(|e| SessionError::Malformed(e.to_string()))?,
        )?;
        Ok(())
    }
    pub fn save_identity(
        &self,
        vault: &str,
        identity: &[u8],
        ttl: Duration,
        max: Duration,
    ) -> Result<(), SessionError> {
        let (_, t) = self.now()?;
        let (mut saved_at, mut ttl, mut max) = (t.clone(), duration_ns(ttl), duration_ns(max));
        if let Ok(Some(session)) = self.session_metadata(vault) {
            if !session.saved_at.is_go_zero() {
                saved_at = session.saved_at;
            }
            if session.ttl_ns > 0 {
                ttl = session.ttl_ns;
            }
            if session.max_lifetime_ns > 0 {
                max = session.max_lifetime_ns;
            }
        }
        let (e, n) = self.encrypt(vault, identity)?;
        let s = StoredIdentity {
            saved_at,
            last_access: t,
            encrypted_identity: e,
            nonce: n,
            ttl_ns: ttl,
            max_lifetime_ns: max,
        };
        self.keyring.set(
            &Self::key(vault, IDENTITY_ACCOUNT),
            &serde_json::to_vec(&s).map_err(|e| SessionError::Malformed(e.to_string()))?,
        )
    }
    fn session_metadata(&self, vault: &str) -> Result<Option<StoredSession>, SessionError> {
        match self.keyring.get(&Self::key(vault, SESSION_ACCOUNT)) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| SessionError::Malformed(e.to_string())),
            Err(SessionError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn expired(saved: i128, last: i128, ttl: i64, max: i64, now: i128) -> bool {
        if ttl <= 0 || saved == GO_ZERO_NANOS {
            return true;
        }
        let last = if last == GO_ZERO_NANOS { saved } else { last };
        now.saturating_sub(last) > i128::from(ttl)
            || now.saturating_sub(saved)
                > if max > 0 {
                    i128::from(max)
                } else {
                    DEFAULT_MAX_LIFETIME.as_nanos() as i128
                }
    }
    pub fn load_passphrase(&self, vault: &str) -> Result<Vec<u8>, SessionError> {
        let raw = self.keyring.get(&Self::key(vault, SESSION_ACCOUNT))?;
        let mut s: StoredSession =
            serde_json::from_slice(&raw).map_err(|e| SessionError::Malformed(e.to_string()))?;
        let (now, t) = self.now()?;
        if s.ttl_ns <= 0 {
            return Err(SessionError::Expired("TTL is zero or negative"));
        }
        if Self::expired(
            s.saved_at.nanos()?,
            s.last_access.nanos()?,
            s.ttl_ns,
            s.max_lifetime_ns,
            now,
        ) {
            let _ = self.revoke(vault);
            return Err(SessionError::Expired("idle or maximum lifetime"));
        }
        if s.passphrase
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(SessionError::LegacyPlaintext);
        }
        let value = self.decrypt(
            vault,
            s.encrypted_passphrase
                .as_deref()
                .ok_or(SessionError::Expired("passphrase missing"))?,
            s.nonce
                .as_deref()
                .ok_or(SessionError::Malformed("nonce missing".into()))?,
        )?;
        s.last_access = t;
        if let Ok(payload) = serde_json::to_vec(&s) {
            let _ = self
                .keyring
                .set(&Self::key(vault, SESSION_ACCOUNT), &payload);
        }
        Ok(value)
    }
    pub fn load_identity(&self, vault: &str, refresh: bool) -> Result<Vec<u8>, SessionError> {
        let raw = self.keyring.get(&Self::key(vault, IDENTITY_ACCOUNT))?;
        let mut i: StoredIdentity =
            serde_json::from_slice(&raw).map_err(|e| SessionError::Malformed(e.to_string()))?;
        let session = self.session_metadata(vault)?;
        let (saved_at, last_access, ttl, max_lifetime) = if let Some(session) = &session {
            (
                session.saved_at.nanos()?,
                session.last_access.nanos()?,
                session.ttl_ns,
                session.max_lifetime_ns,
            )
        } else {
            (
                i.saved_at.nanos()?,
                i.last_access.nanos()?,
                i.ttl_ns,
                i.max_lifetime_ns,
            )
        };
        let (now, t) = self.now()?;
        if Self::expired(saved_at, last_access, ttl, max_lifetime, now) {
            if refresh {
                let _ = self.revoke(vault);
            }
            return Err(SessionError::Expired("idle or maximum lifetime"));
        }
        let value = self.decrypt(vault, &i.encrypted_identity, &i.nonce)?;
        if refresh {
            i.last_access = t.clone();
            // The Go manager returns the decrypted identity even if renewal
            // fails, and only renews the shared session after the identity.
            if self
                .keyring
                .set(
                    &Self::key(vault, IDENTITY_ACCOUNT),
                    &serde_json::to_vec(&i).map_err(|e| SessionError::Malformed(e.to_string()))?,
                )
                .is_ok()
                && let Some(mut session) = session
            {
                session.last_access = t;
                if let Ok(payload) = serde_json::to_vec(&session) {
                    let _ = self
                        .keyring
                        .set(&Self::key(vault, SESSION_ACCOUNT), &payload);
                }
            }
        }
        Ok(value)
    }
    pub fn is_identity_expired(&self, vault: &str) -> bool {
        self.keyring
            .get(&Self::key(vault, IDENTITY_ACCOUNT))
            .ok()
            .and_then(|v| serde_json::from_slice::<StoredIdentity>(&v).ok())
            .map(|i| {
                if i.ttl_ns <= 0 || i.encrypted_identity.is_empty() || i.nonce.is_empty() {
                    return true;
                }
                let session = match self.session_metadata(vault) {
                    Ok(session) => session,
                    Err(_) => return true,
                };
                let (saved, last, ttl, max) = if let Some(session) = session {
                    (
                        session.saved_at,
                        session.last_access,
                        session.ttl_ns,
                        session.max_lifetime_ns,
                    )
                } else {
                    (i.saved_at, i.last_access, i.ttl_ns, i.max_lifetime_ns)
                };
                match (self.now(), saved.nanos(), last.nanos()) {
                    (Ok((now, _)), Ok(saved), Ok(last)) => {
                        Self::expired(saved, last, ttl, max, now)
                    }
                    _ => true,
                }
            })
            .unwrap_or(true)
    }
    pub fn is_session_expired(&self, vault: &str) -> bool {
        self.keyring
            .get(&Self::key(vault, SESSION_ACCOUNT))
            .ok()
            .and_then(|v| serde_json::from_slice::<StoredSession>(&v).ok())
            .map(
                |s| match (self.now(), s.saved_at.nanos(), s.last_access.nanos()) {
                    (Ok((now, _)), Ok(saved), Ok(last)) => {
                        Self::expired(saved, last, s.ttl_ns, s.max_lifetime_ns, now)
                    }
                    _ => true,
                },
            )
            .unwrap_or(true)
    }
    pub fn revoke(&self, vault: &str) -> Result<(), SessionError> {
        for a in [SESSION_ACCOUNT, IDENTITY_ACCOUNT, WRAP_KEY_ACCOUNT] {
            self.keyring.delete(&Self::key(vault, a))?;
        }
        Ok(())
    }

    /// Reports whether the cached session still holds a plaintext passphrase.
    ///
    /// Mirrors Go's `Manager.HasLegacyPlaintextSession`: a missing cache entry is
    /// "no legacy session", not an error. An empty plaintext field does not count
    /// — only a non-empty one is the pre-encryption format.
    pub fn has_legacy_plaintext_session(&self, vault: &str) -> Result<bool, SessionError> {
        match self.keyring.get(&Self::key(vault, SESSION_ACCOUNT)) {
            Ok(raw) => {
                let session: StoredSession = serde_json::from_slice(&raw)
                    .map_err(|e| SessionError::Malformed(e.to_string()))?;
                Ok(session
                    .passphrase
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()))
            }
            Err(SessionError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Upgrades a cached plaintext session to the encrypted form.
    ///
    /// Returns `Ok(false)` when there is nothing to do, matching Go: no entry, an
    /// empty plaintext field, or an already-encrypted session are all no-ops. The
    /// wrap key is created on demand, the passphrase is encrypted under it, the
    /// plaintext is dropped, and `max_lifetime_ns` is defaulted when unset. The
    /// rewritten payload replaces the cache entry only after it is fully built.
    pub fn migrate_session(&self, vault: &str) -> Result<bool, SessionError> {
        let raw = match self.keyring.get(&Self::key(vault, SESSION_ACCOUNT)) {
            Ok(raw) => raw,
            Err(SessionError::NotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        let mut session: StoredSession =
            serde_json::from_slice(&raw).map_err(|e| SessionError::Malformed(e.to_string()))?;
        let plaintext = match session.passphrase.as_deref() {
            Some(value) if !value.is_empty() => value.to_owned(),
            _ => return Ok(false),
        };
        let (encrypted, nonce) = self.encrypt(vault, plaintext.as_bytes())?;
        session.encrypted_passphrase = Some(encrypted);
        session.nonce = Some(nonce);
        if session.max_lifetime_ns <= 0 {
            session.max_lifetime_ns = duration_ns(DEFAULT_MAX_LIFETIME);
        }
        // Drop the plaintext before the payload is serialised so it cannot leak
        // into the stored JSON; `zeroize` clears the heap copy we no longer need.
        let mut plaintext = plaintext;
        plaintext.zeroize();
        session.passphrase = None;
        let payload =
            serde_json::to_vec(&session).map_err(|e| SessionError::Malformed(e.to_string()))?;
        self.keyring
            .set(&Self::key(vault, SESSION_ACCOUNT), &payload)?;
        Ok(true)
    }
}
fn duration_ns(d: Duration) -> i64 {
    d.as_nanos().min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FakeClock(Mutex<SystemTime>);
    impl Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
    }
    #[test]
    fn round_trip_and_touch() {
        let k = Arc::new(MemoryKeyring::new());
        let c = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let m = SessionManager::new(k, c.clone());
        m.save_passphrase(
            "v",
            b"secret",
            Duration::from_secs(10),
            Duration::from_secs(100),
        )
        .unwrap();
        assert_eq!(m.load_passphrase("v").unwrap(), b"secret");
        *c.0.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(111);
        assert!(matches!(
            m.load_passphrase("v"),
            Err(SessionError::Expired(_))
        ));
    }
    #[test]
    fn zero_and_elapsed_ttl_precede_legacy_and_match_eviction() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let payload = br#"{"saved_at":"1970-01-01T00:01:40Z","last_access":"1970-01-01T00:01:40Z","passphrase":"legacy","ttl_ns":0}"#;
        keyring.set(&key, payload).unwrap();
        assert!(matches!(
            manager.load_passphrase("v"),
            Err(SessionError::Expired(_))
        ));
        assert_eq!(keyring.get(&key).unwrap(), payload);

        let payload = br#"{"saved_at":"1970-01-01T00:01:00Z","last_access":"1970-01-01T00:01:00Z","passphrase":"legacy","ttl_ns":1}"#;
        keyring.set(&key, payload).unwrap();
        assert!(matches!(
            manager.load_passphrase("v"),
            Err(SessionError::Expired(_))
        ));
        assert!(matches!(keyring.get(&key), Err(SessionError::NotFound)));
    }
    #[test]
    fn identity_ignores_nonpositive_session_metadata() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let payload = br#"{"saved_at":"0001-01-01T00:00:00Z","last_access":"0001-01-01T00:00:00Z","ttl_ns":0,"max_lifetime_ns":0}"#;
        keyring
            .set(&SessionManager::key("v", SESSION_ACCOUNT), payload)
            .unwrap();
        manager
            .save_identity(
                "v",
                b"identity",
                Duration::from_secs(60),
                Duration::from_secs(120),
            )
            .unwrap();
        let raw = keyring
            .get(&SessionManager::key("v", IDENTITY_ACCOUNT))
            .unwrap();
        let stored: StoredIdentity = serde_json::from_slice(&raw).unwrap();
        assert_eq!(stored.saved_at.nanos().unwrap(), 100_000_000_000);
        assert_eq!(stored.ttl_ns, 60_000_000_000);
        assert_eq!(stored.max_lifetime_ns, 120_000_000_000);
    }
    #[test]
    fn unix_epoch_is_not_go_zero_time() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let payload = br#"{"saved_at":"1970-01-01T00:00:00Z","last_access":"1970-01-01T00:00:00Z","ttl_ns":1,"max_lifetime_ns":1}"#;
        keyring
            .set(&SessionManager::key("v", SESSION_ACCOUNT), payload)
            .unwrap();
        manager
            .save_identity(
                "v",
                b"identity",
                Duration::from_secs(60),
                Duration::from_secs(120),
            )
            .unwrap();
        let raw = keyring
            .get(&SessionManager::key("v", IDENTITY_ACCOUNT))
            .unwrap();
        let stored: StoredIdentity = serde_json::from_slice(&raw).unwrap();
        assert_eq!(stored.saved_at.nanos().unwrap(), 0);
        assert_eq!(stored.ttl_ns, 1);
        assert_eq!(stored.max_lifetime_ns, 1);
    }
    #[test]
    fn epoch_legacy_session_is_not_prematurely_evicted() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let payload = br#"{"saved_at":"1970-01-01T00:00:00Z","last_access":"1970-01-01T00:00:00Z","passphrase":"legacy","ttl_ns":120000000000,"max_lifetime_ns":120000000000}"#;
        keyring.set(&key, payload).unwrap();
        assert!(matches!(
            manager.load_passphrase("v"),
            Err(SessionError::LegacyPlaintext)
        ));
        assert_eq!(keyring.get(&key).unwrap(), payload);
    }
    #[test]
    fn go_zero_last_access_uses_saved_at_before_eviction() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let payload = br#"{"saved_at":"1970-01-01T00:01:00Z","last_access":"0001-01-01T00:00:00Z","passphrase":"legacy","ttl_ns":1,"max_lifetime_ns":120000000000}"#;
        keyring.set(&key, payload).unwrap();
        assert!(matches!(
            manager.load_passphrase("v"),
            Err(SessionError::Expired(_))
        ));
        assert!(matches!(keyring.get(&key), Err(SessionError::NotFound)));
    }
    #[test]
    fn malformed_last_access_fails_closed_in_both_expiry_probes() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let payload = br#"{"saved_at":"1970-01-01T00:01:40Z","last_access":"1970-01-01T00:00:00++1:00","ttl_ns":120000000000,"max_lifetime_ns":120000000000}"#;
        keyring.set(&key, payload).unwrap();
        assert!(manager.is_session_expired("v"));
        manager
            .save_identity(
                "v",
                b"identity",
                Duration::from_secs(120),
                Duration::from_secs(120),
            )
            .unwrap();
        assert!(manager.is_identity_expired("v"));
        assert_eq!(
            keyring.get(&key).unwrap(),
            payload,
            "read-only probes must not evict"
        );
    }
    #[test]
    fn identity_inherits_pre_epoch_session_origin() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        let payload = br#"{"saved_at":"1969-12-31T23:59:59Z","last_access":"1969-12-31T23:59:59Z","ttl_ns":1,"max_lifetime_ns":1}"#;
        keyring
            .set(&SessionManager::key("v", SESSION_ACCOUNT), payload)
            .unwrap();
        manager
            .save_identity(
                "v",
                b"identity",
                Duration::from_secs(60),
                Duration::from_secs(120),
            )
            .unwrap();
        let raw = keyring
            .get(&SessionManager::key("v", IDENTITY_ACCOUNT))
            .unwrap();
        let stored: StoredIdentity = serde_json::from_slice(&raw).unwrap();
        assert!(
            matches!(stored.saved_at, Timestamp::Text(ref value) if value == "1969-12-31T23:59:59Z")
        );
    }
    struct FailRefreshKeyring {
        inner: MemoryKeyring,
        fail: std::sync::atomic::AtomicBool,
    }
    impl Keyring for FailRefreshKeyring {
        fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) && key.ends_with("|session") {
                return Err(SessionError::Keyring("refresh refused".into()));
            }
            self.inner.set(key, value)
        }
        fn delete(&self, key: &str) -> Result<(), SessionError> {
            self.inner.delete(key)
        }
    }
    #[test]
    fn passphrase_survives_refresh_write_error() {
        let keyring = Arc::new(FailRefreshKeyring {
            inner: MemoryKeyring::new(),
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock.clone());
        manager
            .save_passphrase(
                "v",
                b"secret",
                Duration::from_secs(10),
                Duration::from_secs(100),
            )
            .unwrap();
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let before = keyring.get(&key).unwrap();
        *clock.0.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(101);
        keyring
            .fail
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(manager.load_passphrase("v").unwrap(), b"secret");
        assert_eq!(
            keyring.get(&key).unwrap(),
            before,
            "failed refresh must not change cache"
        );
    }
    #[test]
    fn revoke_is_idempotent() {
        let m = SessionManager::with_system_clock(Arc::new(MemoryKeyring::new()));
        m.revoke("missing").unwrap();
    }
    #[test]
    fn timestamp_roundtrip() {
        let Timestamp::Text(text) =
            timestamp(UNIX_EPOCH + Duration::from_secs(1_735_689_600)).unwrap();
        assert_eq!(parse_timestamp(&text), Some(1_735_689_600_000_000_000));
        assert_eq!(parse_timestamp("0001-01-01T00:00:00Z"), Some(GO_ZERO_NANOS));
        assert_eq!(
            parse_timestamp("0001-01-01T01:00:00+01:00"),
            Some(GO_ZERO_NANOS)
        );
        assert_eq!(
            parse_timestamp("1969-12-31T23:59:59Z"),
            Some(-1_000_000_000)
        );
        assert_eq!(
            parse_timestamp("1970-01-01T00:00:00.1234567891Z"),
            Some(123_456_789)
        );
        assert_eq!(parse_timestamp("1970-01-01T00:00:00,000Z"), Some(0));
        assert_eq!(parse_timestamp("2026-09-23T12:00:00++1:00"), None);
        assert!(parse_timestamp("2024-02-29T00:00:00Z").is_some());
        assert_eq!(parse_timestamp("2023-02-29T00:00:00Z"), None);
        assert_eq!(parse_timestamp("2099-02-30T00:00:00Z"), None);
    }
    #[test]
    fn identity_round_trip_and_max_lifetime() {
        let k = Arc::new(MemoryKeyring::new());
        let c = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let m = SessionManager::new(k, c.clone());
        m.save_identity(
            "v",
            b"identity",
            Duration::from_secs(100),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(m.load_identity("v", false).unwrap(), b"identity");
        *c.0.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(106);
        assert!(matches!(
            m.load_identity("v", false),
            Err(SessionError::Expired(_))
        ));
    }

    #[test]
    fn empty_legacy_field_is_not_classified_as_plaintext_session() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        manager
            .save_passphrase(
                "v",
                b"secret",
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
        let key = SessionManager::key("v", SESSION_ACCOUNT);
        let mut value: serde_json::Value =
            serde_json::from_slice(&keyring.get(&key).unwrap()).unwrap();
        value["passphrase"] = serde_json::Value::String(String::new());
        keyring
            .set(&key, &serde_json::to_vec(&value).unwrap())
            .unwrap();
        assert_eq!(manager.load_passphrase("v").unwrap(), b"secret");
    }

    #[test]
    fn identity_uses_existing_session_lifetime_metadata() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring, clock.clone());
        manager
            .save_passphrase(
                "v",
                b"secret",
                Duration::from_secs(10),
                Duration::from_secs(100),
            )
            .unwrap();
        *clock.0.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(105);
        manager
            .save_identity(
                "v",
                b"identity",
                Duration::from_secs(100),
                Duration::from_secs(100),
            )
            .unwrap();
        *clock.0.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(111);
        assert!(matches!(
            manager.load_identity("v", false),
            Err(SessionError::Expired(_))
        ));
    }

    #[test]
    fn numeric_timestamp_is_rejected_like_go_time_time() {
        let raw = br#"{"saved_at":1,"last_access":"2099-01-01T00:00:00Z","ttl_ns":1}"#;
        assert!(serde_json::from_slice::<StoredSession>(raw).is_err());
    }

    /// Writes a legacy plaintext session into the keyring by hand, the way an
    /// older Symaira Vault build would have left it.
    fn seed_legacy_session(keyring: &MemoryKeyring, vault: &str, plaintext: &str) {
        let key = SessionManager::key(vault, SESSION_ACCOUNT);
        // Timestamps sit at the fake clock's epoch-plus-100s, so the seeded
        // session is fresh for a FakeClock parked there.
        let payload = serde_json::json!({
            "saved_at": "1970-01-01T00:01:40Z",
            "last_access": "1970-01-01T00:01:40Z",
            "passphrase": plaintext,
            "ttl_ns": 1_000_000_000_000i64,
            "max_lifetime_ns": 0i64,
        });
        keyring
            .set(&key, &serde_json::to_vec(&payload).unwrap())
            .unwrap();
    }

    #[test]
    fn migrate_session_encrypts_the_plaintext_and_is_idempotent() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);
        seed_legacy_session(&keyring, "v", "legacy-secret");

        assert!(manager.has_legacy_plaintext_session("v").unwrap());
        assert!(manager.migrate_session("v").unwrap(), "first run migrates");

        // The upgraded payload must no longer carry the plaintext, and the
        // encrypted form must round-trip back to the original bytes.
        assert!(!manager.has_legacy_plaintext_session("v").unwrap());
        assert_eq!(manager.load_passphrase("v").unwrap(), b"legacy-secret");
        let stored: serde_json::Value = serde_json::from_slice(
            &keyring
                .get(&SessionManager::key("v", SESSION_ACCOUNT))
                .unwrap(),
        )
        .unwrap();
        assert!(
            stored["passphrase"].is_null(),
            "plaintext survived the migration: {stored}"
        );
        assert_eq!(
            stored["max_lifetime_ns"], 28_800_000_000_000i64,
            "unset max lifetime must default to 8h like Go"
        );

        // A second run is a no-op and must not disturb the encrypted payload.
        let before = keyring
            .get(&SessionManager::key("v", SESSION_ACCOUNT))
            .unwrap();
        assert!(
            !manager.migrate_session("v").unwrap(),
            "second run reported work"
        );
        assert_eq!(
            keyring
                .get(&SessionManager::key("v", SESSION_ACCOUNT))
                .unwrap(),
            before
        );
    }

    #[test]
    fn migrate_session_is_a_noop_without_a_legacy_entry() {
        let keyring = Arc::new(MemoryKeyring::new());
        let clock = Arc::new(FakeClock(Mutex::new(UNIX_EPOCH + Duration::from_secs(100))));
        let manager = SessionManager::new(keyring.clone(), clock);

        // No cache entry at all.
        assert!(!manager.has_legacy_plaintext_session("v").unwrap());
        assert!(!manager.migrate_session("v").unwrap());

        // An already-encrypted session.
        manager
            .save_passphrase(
                "v",
                b"secret",
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
        assert!(!manager.has_legacy_plaintext_session("v").unwrap());
        assert!(!manager.migrate_session("v").unwrap());

        // An empty plaintext field is not the legacy format.
        seed_legacy_session(&keyring, "w", "");
        assert!(!manager.has_legacy_plaintext_session("w").unwrap());
        assert!(!manager.migrate_session("w").unwrap());
    }
}
