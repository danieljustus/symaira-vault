//! Persistent approval-device sessions with hashed bearer tokens.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::pairing::{GoTime, PairingError, generate_token};
use crate::safeio::{self, SafeIoError};

pub const DEFAULT_SESSION_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSession {
    pub prefix: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Debug)]
pub enum DeviceSessionError {
    Io(std::io::Error),
    SafeIo(SafeIoError),
    Json(serde_json::Error),
    Token(PairingError),
    Time(String),
    Poisoned,
}

impl std::fmt::Display for DeviceSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::SafeIo(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::Token(error) => write!(f, "{error}"),
            Self::Time(error) => write!(f, "{error}"),
            Self::Poisoned => write!(f, "device session store lock poisoned"),
        }
    }
}
impl std::error::Error for DeviceSessionError {}
impl From<std::io::Error> for DeviceSessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<SafeIoError> for DeviceSessionError {
    fn from(e: SafeIoError) -> Self {
        Self::SafeIo(e)
    }
}
impl From<serde_json::Error> for DeviceSessionError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<PairingError> for DeviceSessionError {
    fn from(e: PairingError) -> Self {
        Self::Token(e)
    }
}

/// Store rooted at `<vault>/.symvault/device-sessions.json`; `None` is in-memory.
pub struct DeviceSessionStore {
    path: Option<PathBuf>,
    sessions: Mutex<BTreeMap<String, DeviceSession>>,
}

impl DeviceSessionStore {
    pub fn new(vault_dir: Option<&Path>) -> Result<Self, DeviceSessionError> {
        let mut store = Self {
            path: vault_dir.map(|root| root.join(".symvault/device-sessions.json")),
            sessions: Mutex::new(BTreeMap::new()),
        };
        store.load()?;
        Ok(store)
    }

    pub fn enroll(
        &self,
        device_id: &str,
        name: &str,
        public_key: &str,
    ) -> Result<String, DeviceSessionError> {
        let token = generate_token()?;
        let created_at = GoTime::now().to_rfc3339_nano();
        self.enroll_with_token(device_id, name, public_key, &token, &created_at)?;
        Ok(token)
    }

    fn enroll_with_token(
        &self,
        device_id: &str,
        name: &str,
        public_key: &str,
        token: &str,
        created_at: &str,
    ) -> Result<(), DeviceSessionError> {
        let created = GoTime::parse_rfc3339(created_at)?;
        let expires = OffsetDateTime::from_unix_timestamp_nanos(
            created.unix_timestamp_nanos()?
                + i128::from(DEFAULT_SESSION_TTL_SECONDS) * 1_000_000_000,
        )
        .map_err(|error| DeviceSessionError::Time(error.to_string()))?;
        let expires_at = GoTime::from_offset_datetime(expires).to_rfc3339_nano();
        let session = DeviceSession {
            prefix: token.chars().take(4).collect(),
            device_id: device_id.to_owned(),
            name: name.to_owned(),
            public_key: public_key.to_owned(),
            created_at: created_at.to_owned(),
            expires_at,
            revoked: false,
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        let before = sessions.clone();
        sessions.insert(hash_token(token), session);
        if let Err(error) = self.save_locked(&sessions) {
            *sessions = before;
            return Err(error);
        }
        Ok(())
    }

    pub fn validate(&self, token: &str) -> Result<Option<String>, DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        self.merge_revocations(&mut sessions)?;
        let Some(session) = sessions.get(&hash_token(token)) else {
            return Ok(None);
        };
        if session.revoked {
            return Ok(None);
        }
        let expires = GoTime::parse_rfc3339(&session.expires_at)?.unix_timestamp_nanos()?;
        if OffsetDateTime::now_utc().unix_timestamp_nanos() > expires {
            return Ok(None);
        }
        Ok(Some(session.device_id.clone()))
    }

    pub fn list(&self) -> Result<Vec<DeviceSession>, DeviceSessionError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?
            .values()
            .cloned()
            .collect())
    }

    pub fn revoke(&self, device_id: &str) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        let mut changed = self.merge_revocations(&mut sessions)?;
        for session in sessions.values_mut().filter(|s| s.device_id == device_id) {
            if !session.revoked {
                session.revoked = true;
                changed = true;
            }
        }
        if changed {
            self.save_locked(&sessions)?;
        }
        Ok(())
    }

    pub fn revoke_all(&self) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        self.merge_revocations(&mut sessions)?;
        for session in sessions.values_mut() {
            session.revoked = true;
        }
        self.save_locked(&sessions)
    }

    pub fn cleanup_expired(&self) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        let mut changed = self.merge_revocations(&mut sessions)?;
        let now = OffsetDateTime::now_utc().unix_timestamp_nanos();
        sessions.retain(|_, session| {
            let keep = GoTime::parse_rfc3339(&session.expires_at)
                .and_then(GoTime::unix_timestamp_nanos)
                .is_ok_and(|expires| now <= expires);
            changed |= !keep;
            keep
        });
        if changed {
            self.save_locked(&sessions)?;
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), DeviceSessionError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        self.save_locked(&sessions)
    }

    fn load(&mut self) -> Result<(), DeviceSessionError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let Some(data) = safeio::read(path)? else {
            return self.save_locked(&BTreeMap::new());
        };
        let raw: BTreeMap<String, Option<DeviceSession>> = serde_json::from_slice(&data)?;
        let mut sessions = BTreeMap::new();
        let mut migrated = false;
        for (key, entry) in raw {
            let Some(mut entry) = entry else { continue };
            GoTime::parse_rfc3339(&entry.created_at)?;
            GoTime::parse_rfc3339(&entry.expires_at)?;
            if looks_like_sha256_hex(&key) {
                sessions.insert(key, entry);
            } else {
                if entry.prefix.is_empty() {
                    entry.prefix = key.chars().take(4).collect();
                }
                sessions.insert(hash_token(&key), entry);
                migrated = true;
            }
        }
        *self
            .sessions
            .get_mut()
            .map_err(|_| DeviceSessionError::Poisoned)? = sessions;
        if migrated {
            self.save()?;
        }
        Ok(())
    }

    fn save_locked(
        &self,
        sessions: &BTreeMap<String, DeviceSession>,
    ) -> Result<(), DeviceSessionError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        safeio::create_dir_all(path.parent().expect("session file has parent"))?;
        safeio::write_atomic(path, &serde_json::to_vec_pretty(sessions)?)?;
        Ok(())
    }

    fn merge_revocations(
        &self,
        sessions: &mut BTreeMap<String, DeviceSession>,
    ) -> Result<bool, DeviceSessionError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(false);
        };
        let Some(data) = safeio::read(path)? else {
            return Ok(false);
        };
        let disk: BTreeMap<String, Option<DeviceSession>> = serde_json::from_slice(&data)?;
        let mut changed = false;
        for (key, value) in disk {
            if !value.is_some_and(|entry| entry.revoked) {
                continue;
            }
            if let Some(memory) = sessions.get_mut(&key)
                && !memory.revoked
            {
                memory.revoked = true;
                changed = true;
            }
        }
        Ok(changed)
    }
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn looks_like_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
