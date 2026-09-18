//! Agent-scoped MCP token registry mutations (`new`, `revoke`, `rotate`).
//!
//! Mirrors `internal/mcp/auth/token.go`'s `Create`/`Revoke`/`Save`. The Go
//! `agent token` subcommands construct `auth.NewTokenRegistry` without an age
//! identity, so `mcp-tokens.json` is always read and written in plaintext
//! here — the encrypted `registry.age` path is out of scope for this
//! no-unlock command family, matching `agent_list_commands::load_tokens` on
//! the Rust side and Go's own command wiring.
//!
//! Persistence reuses the same write lock and atomic publication primitives
//! `sharing.rs` uses. Unlike Go's single in-memory `Load`-then-`Save`, every
//! mutation here reloads the file under the write lock before mutating, so a
//! concurrent writer's entries are never clobbered by a stale snapshot — a
//! deliberate safety improvement over the Go oracle's process-local map that
//! does not change single-writer observable behavior.

use std::{collections::BTreeMap, fs, io, path::Path};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{StoreError, read_open_regular_with_metadata, sha256_hex};

/// The Go token registry file name used below a vault directory.
pub const TOKEN_REGISTRY_FILE: &str = "mcp-tokens.json";
const TOKEN_REGISTRY_VERSION: i64 = 2;

/// One on-disk token registry entry, matching Go's `TokenData` JSON layout
/// field-for-field so unrelated entries (including fields this command
/// family never sets, like refresh tokens) round-trip unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    pub hash: String,
    pub prefix: String,
    #[serde(rename = "allowed_tools", default)]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(
        rename = "tool_registry_hash",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub tool_registry_hash: String,
    #[serde(
        rename = "agent_name",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub agent_name: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(
        rename = "expires_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<String>,
    #[serde(
        rename = "last_used_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(
        rename = "revoked_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<String>,
    #[serde(
        rename = "refresh_token_hash",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub refresh_token_hash: String,
    #[serde(
        rename = "refresh_expires_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_expires_at: Option<String>,
}

/// Inputs for a freshly minted token, shared by `create` and `rotate`.
pub struct NewToken<'a> {
    pub label: &'a str,
    pub allowed_tools: Vec<String>,
    pub agent_name: &'a str,
    /// `None` (or `Some(Duration::ZERO)`) means the token never expires,
    /// matching Go's `if ttl > 0` guard on `ExpiresAt`.
    pub ttl: Option<time::Duration>,
    pub tool_registry_hash: &'a str,
}

#[derive(Default, Deserialize)]
struct RawFile {
    #[serde(default)]
    tokens: Option<BTreeMap<String, TokenRecord>>,
}

#[derive(Serialize)]
struct WireFile<'a> {
    version: i64,
    tokens: &'a BTreeMap<String, TokenRecord>,
}

/// Creates a new scoped token and atomically persists the whole registry.
/// Mirrors Go's `newAgentTokenNewCmd`: `Load` then `Create` (append, no
/// expired-token sweep — Go's `Create` never calls `List`).
pub fn create(
    root: &Path,
    new: &NewToken<'_>,
    now: OffsetDateTime,
) -> Result<(TokenRecord, String), StoreError> {
    let root_cap = open_root(root)?;
    let _lock = crate::open_root_write_lock(&root_cap, root)?;
    let target = root.join(TOKEN_REGISTRY_FILE);
    let mut entries = read(&target)?;
    let (record, raw_token) = new_record(new, now)?;
    entries.insert(record.id.clone(), record.clone());
    write(&root_cap, &target, &entries)?;
    Ok((record, raw_token))
}

/// Revokes one token owned by `agent_name`. Returns `false` when no such
/// non-revoked token exists (unknown agent, unknown token ID, or a token
/// already revoked) — the caller renders Go's exact "not found or already
/// revoked" message for that case.
///
/// Mirrors Go's `newAgentTokenRevokeCmd`, which calls `reg.List()` (an
/// expired-token sweep of the in-memory map) before checking ownership; that
/// sweep is only ever persisted when the revoke itself succeeds, because Go
/// returns early without calling `Save` otherwise.
pub fn revoke(
    root: &Path,
    agent_name: &str,
    token_id: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let root_cap = open_root(root)?;
    let _lock = crate::open_root_write_lock(&root_cap, root)?;
    let target = root.join(TOKEN_REGISTRY_FILE);
    let mut entries = read(&target)?;
    purge_expired(&mut entries, now);

    let owned = entries
        .values()
        .any(|entry| entry.id == token_id && entry.agent_name == agent_name);
    if !owned {
        return Ok(false);
    }
    let Some(entry) = entries
        .values_mut()
        .find(|entry| entry.id == token_id && !entry.revoked)
    else {
        return Ok(false);
    };
    entry.revoked = true;
    entry.revoked_at = Some(go_rfc3339(now));
    write(&root_cap, &target, &entries)?;
    Ok(true)
}

/// Revokes every active token owned by `agent_name`, then creates a new one,
/// all under one lock and one atomic publish. Mirrors Go's
/// `newAgentTokenRotateCmd`: `List` (expired sweep) + per-token `Revoke`,
/// then `Create` — both of which persist through the same in-memory map, so
/// collapsing them into a single write here produces the identical final
/// file Go's two sequential `Save` calls do.
pub fn rotate(
    root: &Path,
    new: &NewToken<'_>,
    now: OffsetDateTime,
) -> Result<(TokenRecord, String), StoreError> {
    let root_cap = open_root(root)?;
    let _lock = crate::open_root_write_lock(&root_cap, root)?;
    let target = root.join(TOKEN_REGISTRY_FILE);
    let mut entries = read(&target)?;
    purge_expired(&mut entries, now);
    for entry in entries.values_mut() {
        if entry.agent_name == new.agent_name && !entry.revoked {
            entry.revoked = true;
            entry.revoked_at = Some(go_rfc3339(now));
        }
    }
    let (record, raw_token) = new_record(new, now)?;
    entries.insert(record.id.clone(), record.clone());
    write(&root_cap, &target, &entries)?;
    Ok((record, raw_token))
}

fn new_record(
    new: &NewToken<'_>,
    now: OffsetDateTime,
) -> Result<(TokenRecord, String), StoreError> {
    let mut token_bytes = [0_u8; 32];
    getrandom::fill(&mut token_bytes)
        .map_err(|error| StoreError::Config(format!("create token: generate token: {error}")))?;
    let raw_token = encode_hex(&token_bytes);

    let mut id_bytes = [0_u8; 4];
    getrandom::fill(&mut id_bytes)
        .map_err(|error| StoreError::Config(format!("create token: generate token: {error}")))?;
    let id = format!(
        "tok-{:04}{:02}{:02}-{}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        encode_hex(&id_bytes)
    );

    let expires_at = new
        .ttl
        .filter(|ttl| *ttl > time::Duration::ZERO)
        .map(|ttl| go_rfc3339(now + ttl));

    let record = TokenRecord {
        id,
        label: new.label.to_owned(),
        hash: sha256_hex(raw_token.as_bytes()),
        prefix: raw_token[..4].to_owned(),
        allowed_tools: Some(new.allowed_tools.clone()),
        tool_registry_hash: new.tool_registry_hash.to_owned(),
        agent_name: new.agent_name.to_owned(),
        created_at: go_rfc3339(now),
        expires_at,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
        refresh_token_hash: String::new(),
        refresh_expires_at: None,
    };
    Ok((record, raw_token))
}

fn purge_expired(entries: &mut BTreeMap<String, TokenRecord>, now: OffsetDateTime) {
    entries.retain(|_, entry| !is_expired(entry, now));
}

fn is_expired(entry: &TokenRecord, now: OffsetDateTime) -> bool {
    entry
        .expires_at
        .as_deref()
        .is_some_and(|value| parse_rfc3339(value).is_ok_and(|expires_at| now > expires_at))
}

fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
}

fn open_root(root: &Path) -> Result<fs::File, StoreError> {
    crate::open_directory_nofollow(root).map_err(|source| StoreError::Read {
        path: root.to_path_buf(),
        source,
    })
}

fn read(path: &Path) -> Result<BTreeMap<String, TokenRecord>, StoreError> {
    #[cfg(unix)]
    let file = crate::open_nofollow_kind(path, false);
    #[cfg(not(unix))]
    let file = crate::open_nofollow(path);
    let bytes = match file {
        Ok(file) => read_open_regular_with_metadata(file, path)?.0,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(StoreError::Config(format!(
                "load token registry: read token registry: {source}"
            )));
        }
    };
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    let raw: RawFile = serde_json::from_slice(&bytes).map_err(|error| {
        StoreError::Config(format!(
            "load token registry: parse token registry: {error}"
        ))
    })?;
    Ok(raw.tokens.unwrap_or_default())
}

fn write(
    root_cap: &fs::File,
    target: &Path,
    entries: &BTreeMap<String, TokenRecord>,
) -> Result<(), StoreError> {
    let mut bytes = serde_json::to_vec_pretty(&WireFile {
        version: TOKEN_REGISTRY_VERSION,
        tokens: entries,
    })
    .map_err(|error| StoreError::Config(format!("save token registry: {error}")))?;
    bytes.push(b'\n');
    crate::publication::replace(target, &bytes, root_cap)
        .map_err(|error| StoreError::Config(format!("save token registry: {error}")))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Renders the way Go's `time.Time::MarshalJSON` does (without quotes):
/// RFC3339 with trailing fraction zeros stripped and the fraction omitted
/// entirely when it is zero. `now` is always UTC here (`time.Now().UTC()` in
/// Go), so the zone is always `Z`.
fn go_rfc3339(value: OffsetDateTime) -> String {
    let value = value.to_offset(time::UtcOffset::UTC);
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    let nanosecond = value.nanosecond();
    if nanosecond != 0 {
        let mut fraction = format!("{nanosecond:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        out.push('.');
        out.push_str(&fraction);
    }
    out.push('Z');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn vault_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = root.path().to_path_buf();
        (root, path)
    }

    fn new_token<'a>(agent: &'a str) -> NewToken<'a> {
        NewToken {
            label: "work",
            allowed_tools: vec!["list_entries".into(), "get_entry".into()],
            agent_name: agent,
            ttl: Some(time::Duration::hours(24)),
            tool_registry_hash: "",
        }
    }

    #[test]
    fn create_persists_hashed_token_with_private_permissions_and_never_logs_raw() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let (record, raw_token) = create(&path, &new_token("alpha"), now).expect("create token");
        assert_eq!(record.agent_name, "alpha");
        assert_eq!(record.hash, sha256_hex(raw_token.as_bytes()));
        assert_eq!(record.prefix, raw_token[..4]);
        assert!(!record.revoked);
        assert_eq!(
            record.expires_at.as_deref(),
            Some(go_rfc3339(now + time::Duration::hours(24))).as_deref()
        );

        let bytes = fs::read(path.join(TOKEN_REGISTRY_FILE)).expect("read registry");
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains(&raw_token),
            "raw token must never be persisted"
        );
        assert!(text.contains(&record.hash));
        assert!(text.contains("\"version\": 2"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path.join(TOKEN_REGISTRY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn create_appends_second_token_for_same_agent_without_touching_the_first() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let (first, _) = create(&path, &new_token("alpha"), now).expect("first token");
        let (second, _) = create(&path, &new_token("alpha"), now).expect("second token");
        assert_ne!(first.id, second.id);
        assert_ne!(first.hash, second.hash);

        let stored = read(&path.join(TOKEN_REGISTRY_FILE)).expect("read back");
        assert_eq!(stored.len(), 2);
        assert!(!stored[&first.id].revoked);
        assert!(!stored[&second.id].revoked);
    }

    #[test]
    fn revoke_rejects_unknown_agent_and_unknown_or_already_revoked_token() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let (record, _) = create(&path, &new_token("alpha"), now).expect("create token");

        assert!(!revoke(&path, "beta", &record.id, now).expect("unknown agent"));
        assert!(!revoke(&path, "alpha", "tok-missing", now).expect("unknown token"));
        assert!(revoke(&path, "alpha", &record.id, now).expect("revoke succeeds"));
        assert!(!revoke(&path, "alpha", &record.id, now).expect("already revoked"));

        let stored = read(&path.join(TOKEN_REGISTRY_FILE)).expect("read back");
        assert!(stored[&record.id].revoked);
        assert_eq!(
            stored[&record.id].revoked_at.as_deref(),
            Some(go_rfc3339(now)).as_deref()
        );
    }

    #[test]
    fn revoke_of_missing_registry_file_reports_no_owned_token() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert!(!revoke(&path, "alpha", "tok-missing", now).expect("empty registry"));
        assert!(!path.join(TOKEN_REGISTRY_FILE).exists());
    }

    #[test]
    fn rotate_revokes_only_the_agents_active_tokens_and_creates_one_new_token() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let (alpha_first, _) = create(&path, &new_token("alpha"), now).expect("alpha token");
        let (beta_token, _) = create(&path, &new_token("beta"), now).expect("beta token");

        let later = now + time::Duration::minutes(5);
        let (rotated, raw_rotated) = rotate(&path, &new_token("alpha"), later).expect("rotate");
        assert_ne!(rotated.id, alpha_first.id);
        assert_eq!(rotated.hash, sha256_hex(raw_rotated.as_bytes()));

        let stored = read(&path.join(TOKEN_REGISTRY_FILE)).expect("read back");
        assert!(stored[&alpha_first.id].revoked, "old alpha token revoked");
        assert!(!stored[&rotated.id].revoked, "new alpha token active");
        assert!(!stored[&beta_token.id].revoked, "unrelated agent untouched");
    }

    #[test]
    fn rotate_of_agent_with_no_existing_tokens_still_creates_one() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let (created, _) =
            rotate(&path, &new_token("fresh-agent"), now).expect("rotate unknown agent");
        assert_eq!(created.agent_name, "fresh-agent");
        assert!(!created.revoked);
    }

    #[test]
    fn revoke_purges_expired_tokens_only_when_the_revoke_itself_succeeds() {
        let (_root, path) = vault_dir();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut expiring = new_token("alpha");
        expiring.ttl = Some(time::Duration::seconds(1));
        let (expiring_record, _) = create(&path, &expiring, now).expect("expiring token");
        let (live_record, _) = create(&path, &new_token("alpha"), now).expect("live token");

        let later = now + time::Duration::hours(1);
        assert!(
            !revoke(&path, "someone-else", "does-not-exist", later)
                .expect("failed revoke does not persist a sweep")
        );
        let unaffected = read(&path.join(TOKEN_REGISTRY_FILE)).expect("read back");
        assert!(
            unaffected.contains_key(&expiring_record.id),
            "no sweep on failure"
        );

        assert!(revoke(&path, "alpha", &live_record.id, later).expect("revoke live token"));
        let stored = read(&path.join(TOKEN_REGISTRY_FILE)).expect("read back");
        assert!(
            !stored.contains_key(&expiring_record.id),
            "expired token swept"
        );
        assert!(stored[&live_record.id].revoked);
    }

    #[test]
    fn go_rfc3339_matches_go_time_marshal_json_fraction_trimming() {
        let zero_fraction = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(go_rfc3339(zero_fraction), "2023-11-14T22:13:20Z");
        let with_fraction = zero_fraction + time::Duration::nanoseconds(120_000_000);
        assert_eq!(go_rfc3339(with_fraction), "2023-11-14T22:13:20.12Z");
    }
}
