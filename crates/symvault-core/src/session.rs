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

pub const SESSION_ACCOUNT: &str = "session";
pub const IDENTITY_ACCOUNT: &str = "identity";
pub const WRAP_KEY_ACCOUNT: &str = "wrap-key";
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);

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
    fn nanos(&self) -> Result<u64, SessionError> {
        match self {
            Self::Text(v) => parse_timestamp(v)
                .ok_or_else(|| SessionError::Malformed(format!("invalid timestamp {v:?}"))),
        }
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
fn parse_timestamp(v: &str) -> Option<u64> {
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
    let n = |a: usize, z: usize| std::str::from_utf8(&b[a..z]).ok()?.parse::<u64>().ok();
    let y = n(0, 4)? as i64;
    let m = n(5, 7)? as i64;
    let d = n(8, 10)? as i64;
    let h = n(11, 13)?;
    let min = n(14, 16)?;
    let sec = n(17, 19)?;
    if m == 0 || m > 12 || d == 0 || d > 31 || h > 23 || min > 59 || sec > 60 {
        return None;
    };
    let frac = if b[19] == b'.' {
        let end = 20
            + b[20..]
                .iter()
                .position(|x| *x == b'Z' || *x == b'+' || *x == b'-')
                .unwrap_or(b.len() - 20);
        let f = std::str::from_utf8(&b[20..end]).ok()?.parse::<u64>().ok()?;
        f * 10u64.saturating_pow(9u32.saturating_sub((end - 20) as u32))
    } else {
        0
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
    u64::try_from(days)
        .ok()?
        .checked_mul(86400)?
        .checked_add(h * 3600 + min * 60 + sec)?
        .checked_mul(1_000_000_000)?
        .checked_add(frac)
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
    fn now(&self) -> Result<(u64, Timestamp), SessionError> {
        let t = self.clock.now();
        Ok((
            t.duration_since(UNIX_EPOCH)
                .map_err(|e| SessionError::Malformed(e.to_string()))?
                .as_nanos()
                .min(u64::MAX as u128) as u64,
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
        let (saved_at, ttl, max) = match self.session_metadata(vault) {
            Ok(Some(session)) => (session.saved_at, session.ttl_ns, session.max_lifetime_ns),
            Ok(None) | Err(SessionError::NotFound) => {
                (t.clone(), duration_ns(ttl), duration_ns(max))
            }
            Err(_) => (t.clone(), duration_ns(ttl), duration_ns(max)),
        };
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
    fn expired(saved: u64, last: u64, ttl: i64, max: i64, now: u64) -> bool {
        if ttl <= 0 || saved == 0 {
            return true;
        }
        let last = if last == 0 { saved } else { last };
        now.saturating_sub(last) > ttl as u64
            || now.saturating_sub(saved)
                > if max > 0 {
                    max as u64
                } else {
                    DEFAULT_MAX_LIFETIME.as_nanos() as u64
                }
    }
    pub fn load_passphrase(&self, vault: &str) -> Result<Vec<u8>, SessionError> {
        let raw = self.keyring.get(&Self::key(vault, SESSION_ACCOUNT))?;
        let mut s: StoredSession =
            serde_json::from_slice(&raw).map_err(|e| SessionError::Malformed(e.to_string()))?;
        if s.passphrase
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(SessionError::LegacyPlaintext);
        }
        let (now, t) = self.now()?;
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
        self.keyring.set(
            &Self::key(vault, SESSION_ACCOUNT),
            &serde_json::to_vec(&s).map_err(|e| SessionError::Malformed(e.to_string()))?,
        )?;
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
                self.now().map_or(true, |(n, _)| {
                    Self::expired(
                        saved.nanos().unwrap_or(0),
                        last.nanos().unwrap_or(0),
                        ttl,
                        max,
                        n,
                    )
                })
            })
            .unwrap_or(true)
    }
    pub fn is_session_expired(&self, vault: &str) -> bool {
        self.keyring
            .get(&Self::key(vault, SESSION_ACCOUNT))
            .ok()
            .and_then(|v| serde_json::from_slice::<StoredSession>(&v).ok())
            .map(|s| {
                self.now().map_or(true, |(n, _)| {
                    Self::expired(
                        s.saved_at.nanos().unwrap_or(0),
                        s.last_access.nanos().unwrap_or(0),
                        s.ttl_ns,
                        s.max_lifetime_ns,
                        n,
                    )
                })
            })
            .unwrap_or(true)
    }
    pub fn revoke(&self, vault: &str) -> Result<(), SessionError> {
        for a in [SESSION_ACCOUNT, IDENTITY_ACCOUNT, WRAP_KEY_ACCOUNT] {
            self.keyring.delete(&Self::key(vault, a))?;
        }
        Ok(())
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
    fn revoke_is_idempotent() {
        let m = SessionManager::with_system_clock(Arc::new(MemoryKeyring::new()));
        m.revoke("missing").unwrap();
    }
    #[test]
    fn timestamp_roundtrip() {
        let Timestamp::Text(text) =
            timestamp(UNIX_EPOCH + Duration::from_secs(1_735_689_600)).unwrap();
        assert_eq!(parse_timestamp(&text), Some(1_735_689_600_000_000_000));
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
}
