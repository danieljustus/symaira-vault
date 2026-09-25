//! Persistent approval-device sessions with hashed bearer tokens.
//!
//! Port of `internal/pairing/devicesession.go`. What is contract here, as
//! measured against that file rather than inferred:
//!
//! - The store lives at `<vault>/.symvault/device-sessions.json`, created with
//!   `0700` on the directory and `0600` on the file, keyed by
//!   `sha256hex(raw_token)`. The raw bearer token is never persisted — only
//!   the four-character `prefix` that `approval-list` displays survives.
//! - [`DeviceSessionStore::save`] renders bytes exactly as Go's
//!   `json.MarshalIndent(map, "", "  ")`: keys in sorted order, two-space
//!   indent, `name` omitted when empty, timestamps as `time.Time::MarshalJSON`
//!   writes them, and Go's HTML escaping: `<`, `>` and `&` become `\u003c`,
//!   `\u003e` and `\u0026`, and U+2028/U+2029 become `\u2028`/`\u2029`,
//!   so the file stays safe to inline in a page or a script.
//! - The revocation merge has no mtime guard on purpose (coarse filesystem
//!   timestamps can replace a same-size file without advancing the observed
//!   mtime): it re-reads the file, only ever moves `false -> true`, and treats
//!   a read or parse failure as "no new revocations observed". That is what
//!   stops this instance's next save from undoing the revocation written by a
//!   second store — precisely the `approval-revoke` CLI.
//! - **Not a contract:** Go's `List` iterates a map, so its order is
//!   non-deterministic. [`DeviceSessionStore::list`] returns storage-key order
//!   as a deliberate difference; compare listings as sets.
//! - **Classified difference:** Go's `Revoke`, `RevokeAll` and
//!   `CleanupExpired` discard the `save` error (`_ = s.save()`); this store
//!   returns it. Memory is updated before the write is attempted in both, so
//!   the file state a caller observes is the same — callers that want Go's
//!   best-effort shape ignore the result.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::pairing::{GoTime, PairingError, encode_go_string, generate_token};
use crate::safeio::{self, SafeIoError};

pub const DEFAULT_SESSION_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

/// One enrolled session. Every field decodes the way Go's `DeviceSession`
/// does: a field the JSON omits takes the value Go's zero value would, and a
/// missing timestamp becomes the zero `time.Time` (which `MarshalJSON` writes
/// back as `0001-01-01T00:00:00Z`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceSession {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub device_id: String,
    /// `json:"name,omitempty"` — absent from the file when empty.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default = "go_zero_time")]
    pub created_at: String,
    #[serde(default = "go_zero_time")]
    pub expires_at: String,
    #[serde(default)]
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

    /// Enrolls a device and returns the raw bearer token. Only its hash and a
    /// display prefix reach the disk; a failed save puts the store back the
    /// way Go's `Enroll` does (`delete(s.sessions, hash)`).
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
        let created = OffsetDateTime::parse(created_at, &Rfc3339)
            .map_err(|e| DeviceSessionError::Time(e.to_string()))?;
        let expires_at = GoTime::from_offset_datetime(
            created + time::Duration::seconds(DEFAULT_SESSION_TTL_SECONDS),
        )
        .to_rfc3339_nano();
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
        let key = hash_token(token);
        sessions.insert(key.clone(), session);
        if let Err(error) = self.save_locked(&sessions) {
            sessions.remove(&key);
            return Err(error);
        }
        Ok(())
    }

    /// Returns the device ID of a live session, or `None` when the token is
    /// unknown, revoked or expired — the three ways Go's `Validate` answers
    /// `("", false)`.
    pub fn validate(&self, token: &str) -> Result<Option<String>, DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        self.merge_revocations(&mut sessions);
        let Some(session) = sessions.get(&hash_token(token)) else {
            return Ok(None);
        };
        if session.revoked {
            return Ok(None);
        }
        let expires = OffsetDateTime::parse(&session.expires_at, &Rfc3339)
            .map_err(|e| DeviceSessionError::Time(e.to_string()))?;
        if OffsetDateTime::now_utc() > expires {
            return Ok(None);
        }
        Ok(Some(session.device_id.clone()))
    }

    /// A snapshot of every session, revoked and expired ones included, exactly
    /// like Go's `List`. Order is storage-key order — a deliberate difference
    /// from Go's non-deterministic map iteration, so compare as a set.
    pub fn list(&self) -> Result<Vec<DeviceSession>, DeviceSessionError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?
            .values()
            .cloned()
            .collect())
    }

    /// Revokes every session of `device_id`, persisting only when something
    /// changed.
    pub fn revoke(&self, device_id: &str) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        let mut changed = self.merge_revocations(&mut sessions);
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

    /// Revokes every session in the store.
    pub fn revoke_all(&self) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        self.merge_revocations(&mut sessions);
        for session in sessions.values_mut() {
            session.revoked = true;
        }
        self.save_locked(&sessions)
    }

    /// Drops sessions whose `expires_at` has passed, saving only when the
    /// store changed.
    pub fn cleanup_expired(&self) -> Result<(), DeviceSessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| DeviceSessionError::Poisoned)?;
        let mut changed = self.merge_revocations(&mut sessions);
        let now = OffsetDateTime::now_utc();
        sessions.retain(|_, session| {
            let keep = OffsetDateTime::parse(&session.expires_at, &Rfc3339)
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
            // Decode the timestamps with Go's own grammar and keep the
            // rendered form, so a later save rewrites them exactly as Go's
            // in-memory `time.Time` would.
            entry.created_at = go_time(&entry.created_at)?.to_rfc3339_nano();
            entry.expires_at = go_time(&entry.expires_at)?.to_rfc3339_nano();
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
        safeio::write_atomic(path, marshal_sessions(sessions)?.as_bytes())?;
        Ok(())
    }

    /// Applies revocations found on disk onto the in-memory copy and reports
    /// whether anything changed.
    ///
    /// Deliberately not guarded by the file's mtime (coarse filesystem
    /// timestamps can replace a same-size JSON file without advancing it), and
    /// deliberately best-effort: a missing, unreadable or unparsable store file
    /// means "no new revocations observed", not an error — which is how Go's
    /// `mergeRevocationsFromDisk` behaves. Revocation only ever moves from
    /// `false` to `true`, so a concurrent writer's decision is never undone.
    fn merge_revocations(&self, sessions: &mut BTreeMap<String, DeviceSession>) -> bool {
        let Some(path) = self.path.as_ref() else {
            return false;
        };
        let Ok(Some(data)) = safeio::read(path) else {
            return false;
        };
        let Ok(disk) = serde_json::from_slice::<BTreeMap<String, Option<DeviceSession>>>(&data)
        else {
            return false;
        };
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
        changed
    }
}

/// Renders `sessions` exactly as Go's `json.MarshalIndent(sessions, "", "  ")`:
/// sorted keys, two-space indent, `name` dropped when empty, timestamps through
/// `time.Time::MarshalJSON`, and HTML escaping on every string. An empty store
/// is `{}`.
///
/// Timestamps are re-decoded here so an instant Go refuses to marshal (a zone
/// of `+24:00`, say) fails this save the way it fails Go's `save`.
fn marshal_sessions(
    sessions: &BTreeMap<String, DeviceSession>,
) -> Result<String, DeviceSessionError> {
    if sessions.is_empty() {
        return Ok("{}".to_owned());
    }
    let mut out = String::from("{\n");
    for (index, (key, session)) in sessions.iter().enumerate() {
        out.push_str("  ");
        encode_go_string(key, &mut out);
        out.push_str(": {\n");
        let mut fields: Vec<(&str, String)> = vec![
            ("prefix", quoted(&session.prefix)),
            ("device_id", quoted(&session.device_id)),
        ];
        if !session.name.is_empty() {
            fields.push(("name", quoted(&session.name)));
        }
        fields.push(("public_key", quoted(&session.public_key)));
        fields.push(("created_at", timestamp_literal(&session.created_at)?));
        fields.push(("expires_at", timestamp_literal(&session.expires_at)?));
        fields.push((
            "revoked",
            if session.revoked { "true" } else { "false" }.to_owned(),
        ));
        for (position, (name, value)) in fields.iter().enumerate() {
            out.push_str("    ");
            encode_go_string(name, &mut out);
            out.push_str(": ");
            out.push_str(value);
            if position + 1 < fields.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  }");
        if index + 1 < sessions.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push('}');
    Ok(out)
}

/// A JSON string literal rendered the way `encoding/json` renders one.
fn quoted(value: &str) -> String {
    let mut out = String::new();
    encode_go_string(value, &mut out);
    out
}

/// A stored timestamp as `time.Time::MarshalJSON` would write it, refusals
/// included.
fn timestamp_literal(value: &str) -> Result<String, DeviceSessionError> {
    go_time(value)?
        .to_go_json()
        .map_err(|error| DeviceSessionError::Time(error.to_string()))
}

/// Parses a timestamp with the grammar Go's JSON decoder accepts.
fn go_time(value: &str) -> Result<GoTime, DeviceSessionError> {
    GoTime::parse_rfc3339(value).map_err(|error| DeviceSessionError::Time(error.to_string()))
}

/// What Go decodes a missing timestamp into: the zero `time.Time`.
fn go_zero_time() -> String {
    GoTime::ZERO.to_rfc3339_nano()
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
