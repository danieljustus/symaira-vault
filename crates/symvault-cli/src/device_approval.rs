//! `symvault device approval-list` and `device approval-revoke`, plus the
//! file-backed device-session registry they share. Pair-code minting lives in
//! `approval_commands` because it talks to the running Go server.
//!
//! Ported from `cmd/device_approval.go` (the two commands) and
//! `internal/pairing/devicesession.go` (the store); oracle pin `3232e31f`.
//! Only the store surface those two commands exercise is ported: `Enroll`,
//! `Validate` and `CleanupExpired` are called by the Go server's approval
//! enrollment path (`internal/approval/enroll.go`), not by the CLI, and are
//! still unported (APPROVAL-001 / RUST-011).
//!
//! Measured, not guessed, about the oracle:
//! - The store lives at `<vault>/.symvault/device-sessions.json`, keys are
//!   `sha256hex(raw_token)` and only the first four characters of the raw token
//!   survive as `prefix`. The raw token is never persisted.
//! - `save` writes `MarshalIndent(..., "", "  ")` through a `.tmp` file and a
//!   rename, with a `0700` directory and a `0600` file.
//! - `mergeRevocationsFromDisk` has no mtime guard on purpose (coarse filesystem
//!   timestamps): it re-reads the file and only ever moves `false -> true`, so
//!   this instance cannot undo the revocation written by a second, concurrent
//!   store — precisely the `approval-revoke` CLI.
//! - **Not a contract:** Go's `List` iterates a map, so its order is
//!   non-deterministic; `BTreeMap` order (by storage key) is used here as a
//!   deliberate, documented difference. Compare these listings as sets.
//! - **Classified difference:** Go's `encoding/json` escapes `<`, `>` and `&`
//!   inside strings as `\u003c`, `\u003e`, `\u0026`; `serde_json` writes them
//!   literally. The bytes can only differ for a `name` or `public_key`
//!   containing one of those three characters.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use symvault_store::sha256_hex;
use symvault_sync::GoTime;
use symvault_sync::pairing::generate_token;
use symvault_sync::safeio;

/// Go `pairing.DefaultSessionTTL`: 90 days.
const SESSION_TTL_DAYS: i64 = 90;
/// Go `pairing.tokenPrefixLen`: characters of the raw token kept for display.
const TOKEN_PREFIX_LEN: usize = 4;
/// Go `config.DefaultVaultSubdir`.
const VAULT_SUBDIR: &str = ".symvault";
/// The store file inside that subdirectory.
const STORE_FILE: &str = "device-sessions.json";

/// One enrolled device session, as Go's `json.MarshalIndent` lays it out: field
/// order and the `name,omitempty` tag are part of the on-disk contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DeviceSession {
    pub prefix: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

/// The on-disk device-session registry.
#[derive(Debug)]
pub(crate) struct DeviceSessionStore {
    path: Option<PathBuf>,
    sessions: BTreeMap<String, DeviceSession>,
}

impl DeviceSessionStore {
    /// Loads the store from `vault_dir`, creating the file when it is absent.
    ///
    /// Error layering mirrors Go: `load device session store: <load error>`
    /// here, and the CLI adds `load approval device store: ` on top.
    pub(crate) fn new(vault_dir: &Path) -> Result<Self, String> {
        let mut store = Self {
            path: None,
            sessions: BTreeMap::new(),
        };
        if vault_dir.as_os_str().is_empty() {
            return Ok(store);
        }
        store.path = Some(vault_dir.join(VAULT_SUBDIR).join(STORE_FILE));
        store
            .load()
            .map_err(|error| format!("load device session store: {error}"))?;
        Ok(store)
    }

    /// Every session, revoked and expired ones included, exactly like Go's
    /// `List`.
    pub(crate) fn list(&self) -> Vec<DeviceSession> {
        self.sessions.values().cloned().collect()
    }

    /// Revokes every session of `device_id`.
    ///
    /// Go ignores the save error here and lets the caller's explicit `Save`
    /// report it, so this stays best-effort too.
    pub(crate) fn revoke(&mut self, device_id: &str) {
        let mut changed = self.merge_revocations_from_disk();
        for session in self.sessions.values_mut() {
            if session.device_id == device_id && !session.revoked {
                session.revoked = true;
                changed = true;
            }
        }
        if changed {
            let _ = self.save();
        }
    }

    /// Persists the store, reporting the error the CLI surfaces as
    /// `save approval device store: …`.
    pub(crate) fn save(&self) -> Result<(), String> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let data = serde_json::to_string_pretty(&self.sessions)
            .map_err(|error| format!("marshal device sessions: {error}"))?;
        if let Some(parent) = path.parent() {
            safeio::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        safeio::write_atomic(path, data.as_bytes()).map_err(|error| error.to_string())
    }

    fn load(&mut self) -> Result<(), String> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let Some(data) = safeio::read(path).map_err(|error| error.to_string())? else {
            return self.save();
        };
        let raw: BTreeMap<String, Option<DeviceSession>> = serde_json::from_slice(&data)
            .map_err(|error| format!("parse device sessions: {error}"))?;
        for session in raw.values().flatten() {
            for (field, stamp) in [
                ("created_at", session.created_at.as_str()),
                ("expires_at", session.expires_at.as_str()),
            ] {
                GoTime::parse_rfc3339(stamp).map_err(|_| {
                    format!("parse device sessions: invalid {field} timestamp {stamp:?}")
                })?;
            }
        }

        // Migrate legacy entries keyed by the raw bearer token (from before
        // tokens were hashed at rest) onto hash-keyed entries. A legacy key is
        // the base32 session token itself, which never looks like a SHA-256 hex
        // digest.
        let mut migrated = false;
        let mut sessions = BTreeMap::new();
        for (key, session) in raw {
            let Some(mut session) = session else {
                continue;
            };
            if looks_like_sha256_hex(&key) {
                sessions.insert(key, session);
                continue;
            }
            if session.prefix.is_empty() {
                session.prefix = token_prefix(&key);
            }
            sessions.insert(hash_token(&key), session);
            migrated = true;
        }
        self.sessions = sessions;
        if migrated { self.save() } else { Ok(()) }
    }

    /// Re-reads the on-disk store and applies any revocation found there onto
    /// the in-memory copy.
    ///
    /// Deliberately does not use the file's modification time as a read guard:
    /// filesystems with coarse timestamps can replace a same-size JSON file
    /// without advancing the observed mtime. Revocation only ever moves from
    /// false to true, so a concurrent writer can never have its revocation
    /// silently undone by this instance's next save. Read and parse failures are
    /// ignored, exactly like Go.
    fn merge_revocations_from_disk(&mut self) -> bool {
        let Some(path) = self.path.as_ref() else {
            return false;
        };
        let Ok(Some(data)) = safeio::read(path) else {
            return false;
        };
        let Ok(on_disk) = serde_json::from_slice::<BTreeMap<String, Option<DeviceSession>>>(&data)
        else {
            return false;
        };
        let mut changed = false;
        for (key, disk_session) in on_disk {
            let Some(disk_session) = disk_session else {
                continue;
            };
            if !disk_session.revoked {
                continue;
            }
            if let Some(session) = self.sessions.get_mut(&key)
                && !session.revoked
            {
                session.revoked = true;
                changed = true;
            }
        }
        changed
    }
}

/// Go `pairing.hashToken`, which delegates to `internal/mcp/auth.SHA256Hex`.
fn hash_token(raw_token: &str) -> String {
    sha256_hex(raw_token.as_bytes())
}

/// Go `pairing.tokenPrefix`: the short, non-secret display prefix.
fn token_prefix(raw_token: &str) -> String {
    raw_token.chars().take(TOKEN_PREFIX_LEN).collect()
}

/// Go `pairing.looksLikeSHA256Hex`: 64 lowercase hex characters.
fn looks_like_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Go `time.Now().After(expiresAt)` for an RFC3339 timestamp read from the
/// store.
fn is_expired(expires_at: &str) -> bool {
    match OffsetDateTime::parse(expires_at, &Rfc3339) {
        Ok(expires) => OffsetDateTime::now_utc() > expires,
        Err(_) => false,
    }
}

/// Go's `time.Time.Format("2006-01-02 15:04")`: the stored wall clock as
/// written. Slicing the RFC3339 literal is exact, because `Format` renders the
/// value in its own location, which is the offset already present in the
/// string.
fn display_minutes(stamp: &str) -> String {
    if stamp.len() >= 16 && stamp.as_bytes()[10] == b'T' {
        format!("{} {}", &stamp[0..10], &stamp[11..16])
    } else {
        stamp.to_owned()
    }
}

/// `device approval-list`.
pub(crate) fn list(vault: &Path, quiet: bool) -> Result<(), String> {
    let store = DeviceSessionStore::new(vault)
        .map_err(|error| format!("load approval device store: {error}"))?;
    let sessions = store.list();
    if sessions.is_empty() {
        crate::println_quiet_aware(quiet, "No approval devices enrolled.");
        return Ok(());
    }
    crate::println_quiet_aware(
        quiet,
        &format!(
            "{:<24} {:<6} {:<24} {:<20} {:<20} {}",
            "DEVICE ID", "TOKEN", "NAME", "ENROLLED", "EXPIRES", "STATUS"
        ),
    );
    for session in sessions {
        let status = if session.revoked {
            "revoked"
        } else if is_expired(&session.expires_at) {
            "expired"
        } else {
            "active"
        };
        let name = if session.name.is_empty() {
            "(unnamed)"
        } else {
            &session.name
        };
        crate::println_quiet_aware(
            quiet,
            &format!(
                "{:<24} {:<6} {:<24} {:<20} {:<20} {}",
                session.device_id,
                format!("{}…", session.prefix),
                name,
                display_minutes(&session.created_at),
                display_minutes(&session.expires_at),
                status
            ),
        );
    }
    Ok(())
}

/// `device approval-revoke <device-id>`.
pub(crate) fn revoke(vault: &Path, device_id: &str, yes: bool, quiet: bool) -> Result<(), String> {
    let mut store = DeviceSessionStore::new(vault)
        .map_err(|error| format!("load approval device store: {error}"))?;

    if !store.list().iter().any(|s| s.device_id == device_id) {
        return Err(format!("approval device {device_id:?} not found"));
    }

    if !yes {
        let _ = write!(
            io::stderr(),
            "This will revoke approval device {device_id:?}. Continue? [y/N]: "
        );
        let _ = io::stderr().flush();
        let mut answer = String::new();
        let _ = io::stdin().read_line(&mut answer);
        if answer.trim().to_lowercase() != "y" {
            let _ = writeln!(io::stderr(), "Canceled");
            return Ok(());
        }
    }

    store.revoke(device_id);
    store
        .save()
        .map_err(|error| format!("save approval device store: {error}"))?;
    crate::println_quiet_aware(quiet, &format!("Approval device {device_id:?} revoked."));
    Ok(())
}

/// Creates a session for `device_id`, returning the raw token for the caller to
/// hand out. Nothing usable is persisted: only the SHA-256 hash and the display
/// prefix reach the file.
///
/// Nothing in the CLI calls this yet — the Go server's enrollment handler does
/// (`internal/approval/enroll.go`), and that path is still unported.
#[allow(dead_code)]
pub(crate) fn enroll(
    vault: &Path,
    device_id: &str,
    name: &str,
    public_key: &str,
) -> Result<String, String> {
    let mut store = DeviceSessionStore::new(vault)
        .map_err(|error| format!("load approval device store: {error}"))?;
    let raw_token = generate_token().map_err(|error| format!("generate session token: {error}"))?;
    let now = OffsetDateTime::now_utc();
    let created_at = GoTime::from_offset_datetime(now).to_rfc3339_nano();
    let expires_at = GoTime::from_offset_datetime(now + time::Duration::days(SESSION_TTL_DAYS))
        .to_rfc3339_nano();
    store.sessions.insert(
        hash_token(&raw_token),
        DeviceSession {
            prefix: token_prefix(&raw_token),
            device_id: device_id.to_owned(),
            name: name.to_owned(),
            public_key: public_key.to_owned(),
            created_at,
            expires_at,
            revoked: false,
        },
    );
    store
        .save()
        .map_err(|error| format!("persist device session: {error}"))?;
    Ok(raw_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_file(vault: &Path) -> PathBuf {
        vault.join(VAULT_SUBDIR).join(STORE_FILE)
    }

    fn write_store(vault: &Path, body: &str) {
        let path = store_file(vault);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(&path, body).expect("write");
    }

    fn session(device_id: &str, expires_at: &str, revoked: bool) -> DeviceSession {
        DeviceSession {
            prefix: "ABCD".to_owned(),
            device_id: device_id.to_owned(),
            name: "phone".to_owned(),
            public_key: "key".to_owned(),
            created_at: "2026-01-02T03:04:05Z".to_owned(),
            expires_at: expires_at.to_owned(),
            revoked,
        }
    }

    #[test]
    fn new_creates_an_empty_store_file_like_go() {
        let vault = tempfile::TempDir::new().expect("vault");
        let store = DeviceSessionStore::new(vault.path()).expect("store");
        assert!(store.list().is_empty());
        let body = std::fs::read_to_string(store_file(vault.path())).expect("read");
        assert_eq!(body, "{}");
    }

    #[test]
    fn new_reports_go_shaped_parse_errors() {
        let vault = tempfile::TempDir::new().expect("vault");
        write_store(vault.path(), "not json");
        let error = DeviceSessionStore::new(vault.path()).expect_err("must fail");
        assert!(
            error.starts_with("load device session store: parse device sessions: "),
            "{error}"
        );
    }

    #[test]
    fn enroll_persists_only_the_hash_and_prefix() {
        let vault = tempfile::TempDir::new().expect("vault");
        let raw_token =
            enroll(vault.path(), "dev-abc123", "phone", "ssh-ed25519 KEY").expect("enroll");
        assert_eq!(raw_token.len(), 32);

        let body = std::fs::read_to_string(store_file(vault.path())).expect("read");
        assert!(!body.contains(&raw_token), "raw token persisted: {body}");
        let parsed: BTreeMap<String, DeviceSession> = serde_json::from_str(&body).expect("parse");
        let (key, stored) = parsed.iter().next().expect("one session");
        assert_eq!(key, &hash_token(&raw_token));
        assert_eq!(stored.prefix, raw_token[..4]);
        assert_eq!(stored.device_id, "dev-abc123");
        assert!(!stored.revoked);
    }

    #[test]
    fn revoke_marks_every_session_of_the_device_and_keeps_others() {
        let vault = tempfile::TempDir::new().expect("vault");
        let mut store = DeviceSessionStore::new(vault.path()).expect("store");
        store.sessions.insert(
            "a".repeat(64),
            session("dev-abc123", "2999-01-01T00:00:00Z", false),
        );
        store.sessions.insert(
            "b".repeat(64),
            session("dev-abc123", "2999-01-01T00:00:00Z", false),
        );
        store.sessions.insert(
            "c".repeat(64),
            session("dev-other", "2999-01-01T00:00:00Z", false),
        );

        store.revoke("dev-abc123");
        let reloaded = DeviceSessionStore::new(vault.path()).expect("reload");
        let revoked: Vec<_> = reloaded
            .list()
            .into_iter()
            .filter(|s| s.revoked)
            .map(|s| s.device_id)
            .collect();
        assert_eq!(revoked, vec!["dev-abc123".to_owned(); 2]);
    }

    #[test]
    fn merge_keeps_a_concurrent_revocation_from_being_undone() {
        let vault = tempfile::TempDir::new().expect("vault");
        let first = DeviceSessionStore::new(vault.path()).expect("store");
        let key = "d".repeat(64);
        let mut stale = {
            let mut store = DeviceSessionStore::new(vault.path()).expect("store");
            store.sessions.insert(
                key.clone(),
                session("dev-abc123", "2999-01-01T00:00:00Z", false),
            );
            store.save().expect("save");
            store
        };

        // A second store instance — the `approval-revoke` CLI — revokes it.
        let mut revoker = DeviceSessionStore::new(vault.path()).expect("store");
        revoker.revoke("dev-abc123");

        // The stale instance revokes someone else, which triggers its own save.
        stale.revoke("dev-nobody");
        assert!(
            stale.sessions[&key].revoked,
            "stale instance dropped revocation"
        );
        drop(first);

        let reloaded = DeviceSessionStore::new(vault.path()).expect("reload");
        assert!(reloaded.sessions[&key].revoked);
    }

    #[test]
    fn load_migrates_legacy_raw_token_keys() {
        let vault = tempfile::TempDir::new().expect("vault");
        let raw_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let legacy = format!(
            "{{\n  \"{raw_token}\": {{\n    \"prefix\": \"\",\n    \"device_id\": \"dev-old\",\n    \"public_key\": \"key\",\n    \"created_at\": \"2026-01-02T03:04:05Z\",\n    \"expires_at\": \"2999-01-01T00:00:00Z\",\n    \"revoked\": false\n  }}\n}}"
        );
        write_store(vault.path(), &legacy);

        let store = DeviceSessionStore::new(vault.path()).expect("store");
        let migrated = store.list();
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].prefix, "ABCD");
        let body = std::fs::read_to_string(store_file(vault.path())).expect("read");
        assert!(body.contains(&hash_token(raw_token)), "{body}");
        assert!(!body.contains(raw_token), "{body}");
    }

    #[test]
    fn status_prefers_revoked_over_expired_and_dates_render_like_go() {
        assert_eq!(
            display_minutes("2026-01-02T03:04:05.5Z"),
            "2026-01-02 03:04"
        );
        assert_eq!(display_minutes("nonsense"), "nonsense");
        assert!(is_expired("2000-01-01T00:00:00Z"));
        assert!(!is_expired("2999-01-01T00:00:00Z"));
        assert!(!is_expired("nonsense"));
    }

    #[test]
    fn token_prefix_and_sha_shape_helper_match_go() {
        assert_eq!(token_prefix("ABCDEFGH"), "ABCD");
        assert_eq!(token_prefix("AB"), "AB");
        assert!(looks_like_sha256_hex(&"a".repeat(64)));
        assert!(!looks_like_sha256_hex(&"A".repeat(64)));
        assert!(!looks_like_sha256_hex("abcdef"));
    }
}
