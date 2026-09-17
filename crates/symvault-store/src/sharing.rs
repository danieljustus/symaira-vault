//! MCP share grant storage.
//!
//! The Go MCP server stores grants in `mcp-shares.json`.  This module only
//! reads that file and verifies cryptographically bound IDs with an injected
//! signing key.  The only mutation here is the bounded revoke operation,
//! which uses the store's existing lock and atomic publication primitives.

use std::{collections::BTreeMap, io, path::Path};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Store, StoreError, read_open_regular_with_metadata};

/// The Go share-store file name used below a vault directory.
pub const SHARE_STORE_FILE: &str = "mcp-shares.json";
const SHARE_STORE_VERSION: i64 = 1;

/// A grant lifecycle state as serialized by the Go server.
pub type ShareStatus = String;

/// JSON-compatible metadata for one share grant.
///
/// Go encodes `time.Duration` as an integer number of nanoseconds.  Keeping
/// timestamps as RFC3339 strings keeps them independent of a platform clock
/// type while load canonicalizes them like Go's `time.Time` JSON marshaler.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareGrant {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub id: String,
    #[serde(
        rename = "from_agent",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub from_agent: String,
    #[serde(
        rename = "to_agent",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub to_agent: String,
    #[serde(
        rename = "secret_path",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub secret_path: String,
    #[serde(
        rename = "secret_field",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub secret_field: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub nonce: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub status: ShareStatus,
    #[serde(
        rename = "created_at",
        default = "zero_timestamp",
        deserialize_with = "deserialize_go_timestamp"
    )]
    pub created_at: String,
    #[serde(
        rename = "expires_at",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_timestamp"
    )]
    pub expires_at: Option<String>,
    #[serde(
        rename = "approved_at",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_timestamp"
    )]
    pub approved_at: Option<String>,
    #[serde(
        rename = "revoked_at",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_timestamp"
    )]
    pub revoked_at: Option<String>,
    #[serde(
        rename = "approved_by",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub approved_by: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "is_zero"
    )]
    pub ttl: i64,
}

/// Exact filters accepted by Go `ShareStore.List` and `list_shares`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareFilter {
    pub status: Option<ShareStatus>,
    pub from_agent: String,
    pub to_agent: String,
    pub secret_path: String,
}

/// A parsed share store snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareStore {
    pub version: i64,
    grants: Vec<ShareGrant>,
}

impl Default for ShareStore {
    fn default() -> Self {
        Self {
            version: SHARE_STORE_VERSION,
            grants: Vec::new(),
        }
    }
}

impl ShareStore {
    /// Reads a Go `mcp-shares.json` file.
    ///
    /// A missing file is the same empty-store result as Go `Load`.  Reads use
    /// the store's no-follow and `MAX_FILE_BYTES` bounded helper.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        #[cfg(unix)]
        let file = crate::open_nofollow_kind(path, false);
        #[cfg(not(unix))]
        let file = crate::open_nofollow(path);
        let bytes = match file {
            Ok(file) => read_open_regular_with_metadata(file, path)?.0,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(StoreError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };

        let raw: Option<RawShareStore> = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::Config(format!("invalid share store: {error}")))?;
        let Some(raw) = raw else {
            // encoding/json.Unmarshal("null", &struct) leaves the zero value.
            return Ok(Self::default());
        };

        let mut grants_by_id = BTreeMap::new();
        for grant in raw
            .grants
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .filter(|grant| !grant.id.is_empty())
        {
            // Go stores grants in a map keyed by ID, so duplicate IDs are
            // replaced by the last JSON array element.
            let grant = grant.validate()?;
            grants_by_id.insert(grant.id.clone(), grant);
        }
        let grants = grants_by_id.into_values().collect();
        // This is an opt-in integrity check.  Plain list semantics remain
        // compatible with Go, which loads and lists forged metadata, while
        // callers checking the signed identity fields can use `verified_grants`.
        let _ = raw.version;
        Ok(Self {
            version: SHARE_STORE_VERSION,
            grants,
        })
    }

    /// Reads a store and rejects any signed grant that cannot be verified.
    /// Legacy unsigned IDs remain accepted for Go backwards compatibility and
    /// therefore are not cryptographically trusted by this method.
    pub fn read_verified(
        path: impl AsRef<Path>,
        signing_key: Option<&[u8]>,
    ) -> Result<Self, StoreError> {
        let store = Self::read(path)?;
        store.verified_grants(signing_key)?;
        Ok(store)
    }

    /// Revokes one grant in the store-owned `mcp-shares.json` file.
    ///
    /// The current file is reloaded after acquiring the vault write lock, so a
    /// stale snapshot cannot overwrite grants created by another process.
    /// Go permits revocation of every status except `revoked` and `rejected`;
    /// the same exact status predicate is retained here. `now` is injected so
    /// tests and callers do not depend on the host clock.
    pub fn revoke(
        &mut self,
        store: &Store,
        grant_id: &str,
        now: &str,
    ) -> Result<ShareGrant, StoreError> {
        let now = time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid revoke clock: {error}")))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid revoke clock: {error}")))?;
        let _lock = store.acquire_write_lock()?;
        let path = store.root().join(SHARE_STORE_FILE);
        let mut current = Self::read(&path)?;
        let position = current
            .grants
            .iter()
            .position(|grant| grant.id == grant_id)
            .ok_or_else(|| StoreError::Config(format!("share grant {grant_id} not found")))?;
        if matches!(
            current.grants[position].status.as_str(),
            "revoked" | "rejected"
        ) {
            return Err(StoreError::Config(format!(
                "share grant {grant_id} cannot be revoked (status: {})",
                current.grants[position].status
            )));
        }
        current.grants[position].status = "revoked".into();
        current.grants[position].revoked_at = Some(now);
        let revoked = current.grants[position].clone();
        let bytes = encode_store(&current)?;
        let target = store.root().join(SHARE_STORE_FILE);
        crate::publication::replace(&target, &bytes, &store.root_cap)?;
        *self = current;
        Ok(revoked)
    }

    /// Returns grants where `agent` is either the source or target agent.
    /// The matching is exact, as in Go `ListForAgent`.
    #[must_use]
    pub fn list_for_agent(&self, agent: &str) -> Vec<ShareGrant> {
        self.list_for_agent_filtered(agent, None)
    }

    /// Returns all grants matching the exact Go list filters.
    #[must_use]
    pub fn list(&self, filter: Option<&ShareFilter>) -> Vec<ShareGrant> {
        self.grants
            .iter()
            .filter(|grant| matches_filter(grant, filter))
            .cloned()
            .collect()
    }

    /// Applies Go's agent visibility rule before the optional exact filters.
    #[must_use]
    pub fn list_for_agent_filtered(
        &self,
        agent: &str,
        filter: Option<&ShareFilter>,
    ) -> Vec<ShareGrant> {
        self.grants
            .iter()
            .filter(|grant| {
                (grant.from_agent == agent || grant.to_agent == agent)
                    && matches_filter(grant, filter)
            })
            .cloned()
            .collect()
    }

    /// Returns all loaded grants, preserving the Go loader's empty-ID filter.
    #[must_use]
    pub fn grants(&self) -> &[ShareGrant] {
        &self.grants
    }

    /// Verifies HMAC-format IDs over their bound identity fields.
    /// Go does not include lifecycle status or expiry in this signature;
    /// this method does not authenticate those fields.
    /// Legacy IDs without `:` retain Go's backwards-compatible behavior and
    /// are included without a cryptographic check.
    pub fn verified_grants(
        &self,
        signing_key: Option<&[u8]>,
    ) -> Result<Vec<ShareGrant>, StoreError> {
        self.grants
            .iter()
            .map(|grant| {
                verify_grant_id(grant, signing_key)?;
                Ok(grant.clone())
            })
            .collect()
    }

    /// Applies Go's exact agent/path/access predicates and HMAC verification.
    pub fn check_access(
        &self,
        to_agent: &str,
        secret_path: &str,
        signing_key: Option<&[u8]>,
        now: &str,
    ) -> Result<Option<ShareGrant>, StoreError> {
        let now = time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid access clock: {error}")))?;
        for grant in &self.grants {
            if grant.to_agent != to_agent
                || grant.secret_path != secret_path
                || grant.status != "approved"
                || grant.is_expired(now)?
            {
                continue;
            }
            // Go CheckAccess skips a malformed or forged signed grant and
            // continues looking for another matching grant.
            if verify_grant_id(grant, signing_key).is_err() {
                continue;
            }
            return Ok(Some(grant.clone()));
        }
        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
struct RawShareStore {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    version: i64,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    grants: Option<Vec<Option<ShareGrant>>>,
}

impl ShareGrant {
    fn validate(mut self) -> Result<Self, StoreError> {
        validate_timestamp(&self.created_at, "created_at")?;
        if !self.created_at.is_empty() {
            self.created_at = canonical_timestamp(&self.created_at);
        }
        for (name, value) in [
            ("expires_at", &mut self.expires_at),
            ("approved_at", &mut self.approved_at),
            ("revoked_at", &mut self.revoked_at),
        ] {
            if let Some(value) = value {
                validate_timestamp(value, name)?;
                *value = canonical_timestamp(value);
            }
        }
        Ok(self)
    }

    fn is_expired(&self, now: time::OffsetDateTime) -> Result<bool, StoreError> {
        let Some(expires_at) = self.expires_at.as_deref() else {
            return Ok(false);
        };
        let expires_at =
            time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
                .map_err(|error| StoreError::Config(format!("invalid expires_at: {error}")))?;
        Ok(now > expires_at)
    }
}

fn validate_timestamp(value: &str, field: &str) -> Result<(), StoreError> {
    if value.is_empty() {
        return Ok(());
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|_| ())
        .map_err(|error| StoreError::Config(format!("invalid share {field}: {error}")))
}

fn matches_filter(grant: &ShareGrant, filter: Option<&ShareFilter>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    filter
        .status
        .as_ref()
        .is_none_or(|status| grant.status == *status)
        && (filter.from_agent.is_empty() || grant.from_agent == filter.from_agent)
        && (filter.to_agent.is_empty() || grant.to_agent == filter.to_agent)
        && (filter.secret_path.is_empty() || grant.secret_path == filter.secret_path)
}

fn verify_grant_id(grant: &ShareGrant, signing_key: Option<&[u8]>) -> Result<(), StoreError> {
    let Some((nonce, encoded)) = grant.id.split_once(':') else {
        return Ok(());
    };
    let key = signing_key
        .filter(|key| !key.is_empty())
        .ok_or_else(|| StoreError::Config("cannot verify HMAC share without signing key".into()))?;
    decode_hex(nonce).ok_or_else(|| StoreError::Config("invalid share nonce".into()))?;
    let expected =
        decode_hex(encoded).ok_or_else(|| StoreError::Config("invalid share HMAC".into()))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| StoreError::Config("invalid share signing key".into()))?;
    mac.update(canonical_grant_fields(grant, nonce).as_bytes());
    if mac.verify_slice(&expected).is_err() {
        return Err(StoreError::Config(
            "share grant HMAC verification failed".into(),
        ));
    }
    Ok(())
}

fn canonical_grant_fields(grant: &ShareGrant, nonce: &str) -> String {
    let mut value = format!(
        "{{\"from_agent\":{},\"to_agent\":{},\"secret_path\":{}",
        go_json_string(&grant.from_agent),
        go_json_string(&grant.to_agent),
        go_json_string(&grant.secret_path),
    );
    if !grant.secret_field.is_empty() {
        value.push_str(&format!(
            ",\"secret_field\":{}",
            go_json_string(&grant.secret_field)
        ));
    }
    value.push_str(&format!(
        ",\"created_at\":{},\"nonce\":{}}}",
        go_json_string(&canonical_timestamp(&grant.created_at)),
        go_json_string(nonce),
    ));
    value
}

fn canonical_timestamp(value: &str) -> String {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| value.to_owned())
}

fn go_json_string(value: &str) -> String {
    let mut encoded = serde_json::to_string(value).expect("a string is always JSON serializable");
    for (from, to) in [
        ('<', "\\u003c"),
        ('>', "\\u003e"),
        ('&', "\\u0026"),
        ('\u{2028}', "\\u2028"),
        ('\u{2029}', "\\u2029"),
    ] {
        encoded = encoded.replace(from, to);
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| Some((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn encode_store(store: &ShareStore) -> Result<Vec<u8>, StoreError> {
    #[derive(Serialize)]
    struct ShareStoreFile<'a> {
        version: i64,
        grants: &'a [ShareGrant],
    }
    let mut bytes = serde_json::to_vec_pretty(&ShareStoreFile {
        version: SHARE_STORE_VERSION,
        grants: &store.grants,
    })
    .map_err(|error| StoreError::Config(format!("encode share store: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_null_vec<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<Option<ShareGrant>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<Option<ShareGrant>>>::deserialize(deserializer)
}

fn zero_timestamp() -> String {
    "0001-01-01T00:00:00Z".into()
}

fn deserialize_go_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?.unwrap_or_else(zero_timestamp);
    if value.is_empty() {
        return Err(serde::de::Error::custom("empty timestamp"));
    }
    validate_timestamp(&value, "created_at").map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_optional_timestamp<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = value.as_deref() {
        if value.is_empty() {
            return Err(serde::de::Error::custom("empty timestamp"));
        }
        validate_timestamp(value, "timestamp").map_err(serde::de::Error::custom)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use tempfile::TempDir;

    // Provenance: internal/crypto/hmac.go and internal/mcp/sharing_store.go
    // at the pinned Go oracle fca3f894.  The vector uses Go's declared JSON
    // field order and SHA-256 HMAC, with synthetic fixture-only values.
    const GO_KEY: &[u8] = b"go-fixture-key";
    const GO_ID: &str = "00112233445566778899aabbccddeeff:6cd0030a08ef6997baead9105a98e1606f0f7f956b79e91dcba41a865a6a524c";

    fn fixture_path() -> (TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("fixture directory");
        let path = root.path().canonicalize().unwrap().join(SHARE_STORE_FILE);
        (root, path)
    }

    fn store_fixture() -> (TempDir, Store, PathBuf) {
        let root = tempfile::tempdir().expect("vault directory");
        fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 1\n",
        )
        .expect("vault config");
        fs::write(root.path().join("identity.age"), b"fixture identity marker")
            .expect("identity marker");
        fs::create_dir(root.path().join("entries")).expect("entries directory");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).expect("open vault");
        let path = root.path().join(SHARE_STORE_FILE);
        (root, store, path)
    }

    #[test]
    fn reads_go_fixture_filters_empty_ids_and_preserves_duration() {
        let (_root, path) = fixture_path();
        fs::write(&path, r#"{"version":1,"grants":[null,{"id":"","from_agent":"ignored"},{"id":"legacy-1","from_agent":"source","to_agent":"target","secret_path":"prod/api","status":"pending","created_at":"2026-01-02T03:04:05Z","ttl":60000000000}]}"#).expect("write fixture");
        let store = ShareStore::read(&path).expect("read Go-shaped fixture");
        assert_eq!(store.version, 1);
        assert_eq!(store.grants().len(), 1);
        assert_eq!(store.list_for_agent("target")[0].ttl, 60_000_000_000);
        assert_eq!(
            store
                .list_for_agent_filtered(
                    "target",
                    Some(&ShareFilter {
                        status: Some("pending".into()),
                        secret_path: "prod/api".into(),
                        ..ShareFilter::default()
                    }),
                )
                .len(),
            1
        );
    }

    #[test]
    fn missing_and_null_files_match_go_load_empty_store() {
        let (_root, missing) = fixture_path();
        assert_eq!(
            ShareStore::read(&missing)
                .expect("missing is empty")
                .version,
            1
        );
        fs::write(&missing, b"null").expect("write null fixture");
        let null_store = ShareStore::read(&missing).expect("null is empty");
        assert_eq!(null_store.version, 1);
        assert!(null_store.grants().is_empty());
    }

    #[test]
    fn duplicate_grant_ids_are_last_write_wins_like_go_map_load() {
        let (_root, path) = fixture_path();
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"duplicate","from_agent":"old","to_agent":"target","secret_path":"old","created_at":"2026-01-02T03:04:05Z"},{"id":"duplicate","from_agent":"new","to_agent":"target","secret_path":"new","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write duplicate fixture");
        let store = ShareStore::read(&path).expect("read duplicate fixture");
        assert_eq!(store.grants().len(), 1);
        assert_eq!(store.grants()[0].from_agent, "new");
        assert_eq!(store.grants()[0].secret_path, "new");
    }

    #[test]
    fn absent_and_null_created_at_use_go_zero_time() {
        for data in [r#"{"id":"legacy"}"#, r#"{"id":"legacy","created_at":null}"#] {
            let grant: ShareGrant = serde_json::from_str(data).unwrap();
            assert_eq!(grant.created_at, "0001-01-01T00:00:00Z");
        }
    }

    #[test]
    fn malformed_go_timestamp_is_rejected_at_load() {
        let (_root, path) = fixture_path();
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"legacy","created_at":""}]}"#,
        )
        .expect("write malformed fixture");
        assert!(ShareStore::read(&path).is_err());
    }

    #[test]
    fn verifies_go_hmac_vector_and_rejects_tampering() {
        let (_root, path) = fixture_path();
        fs::write(&path, format!(r#"{{"version":1,"grants":[{{"id":"{GO_ID}","from_agent":"source","to_agent":"target","secret_path":"prod/api","secret_field":"password","nonce":"00112233445566778899aabbccddeeff","status":"approved","created_at":"2026-01-02T03:04:05Z"}}]}}"#)).expect("write fixture");
        let store = ShareStore::read(&path).expect("read Go HMAC fixture");
        assert_eq!(
            store
                .verified_grants(Some(GO_KEY))
                .expect("valid HMAC")
                .len(),
            1
        );
        assert!(store.verified_grants(Some(b"wrong-key")).is_err());
    }

    #[test]
    fn check_access_matches_go_approved_path_and_expiry_predicates() {
        let (_root, path) = fixture_path();
        fs::write(&path, format!(r#"{{"version":1,"grants":[{{"id":"{GO_ID}","from_agent":"source","to_agent":"target","secret_path":"prod/api","secret_field":"password","status":"approved","created_at":"2026-01-02T03:04:05Z","expires_at":"2026-01-02T04:04:05Z"}},{{"id":"legacy-revoked","from_agent":"source","to_agent":"target","secret_path":"prod/api","status":"revoked","created_at":"2026-01-02T03:04:05Z"}}]}}"#)).expect("write fixture");
        let store = ShareStore::read(&path).expect("read fixture");
        assert_eq!(store.grants().len(), 2);
        assert_eq!(
            store
                .list(Some(&ShareFilter {
                    status: Some("revoked".into()),
                    ..ShareFilter::default()
                }))
                .len(),
            1
        );
        assert!(
            store
                .check_access("target", "prod/api", Some(GO_KEY), "2026-01-02T03:30:00Z")
                .expect("access check")
                .is_some()
        );
        assert!(
            store
                .check_access("target", "prod/api", Some(GO_KEY), "2026-01-02T04:04:05Z")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .check_access("other", "prod/api", Some(GO_KEY), "2026-01-02T03:30:00Z")
                .expect("scope check")
                .is_none()
        );
        assert!(
            store
                .check_access("target", "prod/api", Some(GO_KEY), "2026-01-02T05:00:00Z")
                .expect("expiry check")
                .is_none()
        );
    }

    #[test]
    fn access_skips_forged_signed_grant_and_non_ascii_hex_cannot_panic() {
        let (_root, path) = fixture_path();
        let forged_id = "00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"grants":[{{"id":"{forged_id}","to_agent":"target","secret_path":"prod/api","status":"approved","created_at":"2026-01-02T03:04:05Z"}},{{"id":"{GO_ID}","from_agent":"source","to_agent":"target","secret_path":"prod/api","secret_field":"password","status":"approved","created_at":"2026-01-02T03:04:05Z"}}]}}"#
            ),
        )
        .expect("write forged fixture");
        let store = ShareStore::read(&path).expect("read forged fixture");
        assert!(
            store
                .check_access("target", "prod/api", Some(GO_KEY), "2026-01-02T03:30:00Z")
                .expect("forged grant is skipped")
                .is_some()
        );

        fs::write(
            &path,
            r#"{"version":1,"grants":[{"id":"aéa:","created_at":"2026-01-02T03:04:05Z"}]}"#
                .as_bytes(),
        )
        .expect("write non-ascii fixture");
        let store = ShareStore::read(&path).expect("read non-ascii fixture");
        assert!(store.verified_grants(Some(GO_KEY)).is_err());
    }

    #[test]
    fn revoke_reloads_current_file_and_preserves_concurrent_grants() {
        let (_root, store, path) = store_fixture();
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write initial shares");
        let mut snapshot = ShareStore::read(&path).expect("read initial shares");
        // Simulate another writer adding a grant after this caller's snapshot.
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"},{"id":"grant-b","from_agent":"other","to_agent":"target","secret_path":"prod/b","status":"approved","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write concurrent share");

        let revoked = snapshot
            .revoke(&store, "grant-a", "2026-01-02T04:00:00Z")
            .expect("revoke current grant");
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.revoked_at.as_deref(), Some("2026-01-02T04:00:00Z"));
        let persisted = ShareStore::read(&path).expect("read persisted shares");
        assert_eq!(persisted.grants().len(), 2);
        assert_eq!(persisted.list(None)[0].status, "revoked");
        assert!(persisted.grants().iter().any(|grant| grant.id == "grant-b"));
        assert_eq!(snapshot.grants(), persisted.grants());
    }

    #[test]
    fn revoke_matches_go_not_found_and_terminal_status_errors_without_writing() {
        let (_root, store, path) = store_fixture();
        let original = br#"{"version":1,"grants":[{"id":"done","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"revoked","created_at":"2026-01-02T03:04:05Z","revoked_at":"2026-01-02T03:30:00Z"}]}"#;
        fs::write(&path, original).expect("write terminal share");
        let mut snapshot = ShareStore::read(&path).expect("read terminal share");
        let missing = snapshot
            .revoke(&store, "missing", "2026-01-02T04:00:00Z")
            .expect_err("missing grant must fail");
        assert!(missing.to_string().contains("not found"));
        assert_eq!(fs::read(&path).expect("read unchanged shares"), original);
        let terminal = snapshot
            .revoke(&store, "done", "2026-01-02T04:00:00Z")
            .expect_err("revoked grant must fail");
        assert!(terminal.to_string().contains("cannot be revoked"));
        assert_eq!(fs::read(&path).expect("read unchanged shares"), original);
    }
}
