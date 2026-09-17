//! MCP share grant storage.
//!
//! The Go MCP server stores grants in `mcp-shares.json`.  This module only
//! reads that file and verifies cryptographically bound IDs with an injected
//! signing key.  The only mutation here is the bounded revoke operation,
//! which uses the store's existing lock and atomic publication primitives.

use std::{collections::BTreeMap, fs, io, path::Path};

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
        let _lock = store.acquire_write_lock()?;
        self.revoke_locked(store.root(), &store.root_cap, grant_id, now, None)
    }

    /// Revokes a grant using only a no-follow vault root capability.
    ///
    /// This is the metadata-only path used by commands such as `share revoke`;
    /// it does not require an initialized [`Store`], an identity, or an unlock
    /// operation. The caller still gets the same lock and atomic publication
    /// guarantees as [`Self::revoke`].
    pub fn revoke_at(
        &mut self,
        root: impl AsRef<Path>,
        grant_id: &str,
        now: &str,
    ) -> Result<ShareGrant, StoreError> {
        let root = root.as_ref();
        let root_cap = crate::open_directory_nofollow(root).map_err(|source| StoreError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let _lock = crate::open_root_write_lock(&root_cap, root)?;
        self.revoke_locked(root, &root_cap, grant_id, now, None)
    }

    /// Revokes a grant only when its source agent still matches the caller.
    ///
    /// The source check runs after the file is reloaded under the mutation
    /// lock, closing the stale-snapshot authorization window in MCP revoke.
    pub fn revoke_at_for_agent(
        &mut self,
        root: impl AsRef<Path>,
        grant_id: &str,
        expected_from_agent: &str,
        now: &str,
    ) -> Result<ShareGrant, StoreError> {
        let root = root.as_ref();
        let root_cap = crate::open_directory_nofollow(root).map_err(|source| StoreError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let _lock = crate::open_root_write_lock(&root_cap, root)?;
        self.revoke_locked(root, &root_cap, grant_id, now, Some(expected_from_agent))
    }

    /// Creates a pending grant and atomically persists it to the Go share
    /// store. The current file is reloaded after taking the root mutation
    /// lock, so a stale in-memory snapshot cannot discard a concurrent grant.
    /// `ttl_ns` uses Go's `time.Duration` representation. A non-empty signing
    /// key produces the HMAC-bound `nonce:hmac` ID; an absent or empty key
    /// retains Go's legacy random hexadecimal ID format.
    #[allow(clippy::too_many_arguments)] // Direct Go grant fields plus explicit storage, clock, and key.
    pub fn create_at(
        &mut self,
        root: impl AsRef<Path>,
        from_agent: &str,
        to_agent: &str,
        secret_path: &str,
        secret_field: &str,
        ttl_ns: i64,
        created_at: &str,
        signing_key: Option<&[u8]>,
    ) -> Result<ShareGrant, StoreError> {
        let root = root.as_ref();
        let root_cap = crate::open_directory_nofollow(root).map_err(|source| StoreError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let _lock = crate::open_root_write_lock(&root_cap, root)?;
        self.create_locked(
            root,
            &root_cap,
            from_agent,
            to_agent,
            secret_path,
            secret_field,
            ttl_ns,
            created_at,
            signing_key,
            None,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn create_at_with_nonce(
        &mut self,
        root: impl AsRef<Path>,
        from_agent: &str,
        to_agent: &str,
        secret_path: &str,
        secret_field: &str,
        ttl_ns: i64,
        created_at: &str,
        signing_key: Option<&[u8]>,
        nonce: [u8; 16],
    ) -> Result<ShareGrant, StoreError> {
        let root = root.as_ref();
        let root_cap = crate::open_directory_nofollow(root).map_err(|source| StoreError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let _lock = crate::open_root_write_lock(&root_cap, root)?;
        self.create_locked(
            root,
            &root_cap,
            from_agent,
            to_agent,
            secret_path,
            secret_field,
            ttl_ns,
            created_at,
            signing_key,
            Some(nonce),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_locked(
        &mut self,
        root: &Path,
        root_cap: &fs::File,
        from_agent: &str,
        to_agent: &str,
        secret_path: &str,
        secret_field: &str,
        ttl_ns: i64,
        created_at: &str,
        signing_key: Option<&[u8]>,
        injected_nonce: Option<[u8; 16]>,
    ) -> Result<ShareGrant, StoreError> {
        if ttl_ns < 0 {
            return Err(StoreError::Config("ttl must be a positive duration".into()));
        }
        let created =
            time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
                .map_err(|error| StoreError::Config(format!("invalid created_at: {error}")))?;
        let created_at = created
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid created_at: {error}")))?;
        let expires_at = if ttl_ns > 0 {
            let expires = created
                .checked_add(time::Duration::nanoseconds(ttl_ns))
                .ok_or_else(|| StoreError::Config("ttl exceeds timestamp range".into()))?;
            Some(
                expires
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| StoreError::Config(format!("invalid expires_at: {error}")))?,
            )
        } else {
            None
        };

        let mut current = Self::read(root.join(SHARE_STORE_FILE))?;
        let mut grant = ShareGrant {
            id: String::new(),
            from_agent: from_agent.into(),
            to_agent: to_agent.into(),
            secret_path: secret_path.into(),
            secret_field: secret_field.into(),
            nonce: String::new(),
            status: "pending".into(),
            created_at,
            expires_at,
            approved_at: None,
            revoked_at: None,
            approved_by: String::new(),
            ttl: ttl_ns,
        };
        let nonce = if let Some(nonce) = injected_nonce {
            nonce
        } else {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce)
                .map_err(|error| StoreError::Config(format!("generate grant ID: {error}")))?;
            nonce
        };
        if let Some(key) = signing_key.filter(|key| !key.is_empty()) {
            let nonce_hex = encode_hex(&nonce);
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|_| StoreError::Config("invalid share signing key".into()))?;
            mac.update(canonical_grant_fields(&grant, &nonce_hex).as_bytes());
            grant.nonce = nonce_hex.clone();
            grant.id = format!("{nonce_hex}:{}", encode_hex(&mac.finalize().into_bytes()));
        } else {
            grant.id = encode_hex(&nonce);
        }
        if let Some(existing) = current
            .grants
            .iter_mut()
            .find(|existing| existing.id == grant.id)
        {
            *existing = grant.clone();
        } else {
            current.grants.push(grant.clone());
        }
        current.grants.sort_by(|left, right| left.id.cmp(&right.id));
        let bytes = encode_store(&current)?;
        let target = root.join(SHARE_STORE_FILE);
        crate::publication::replace(&target, &bytes, root_cap)?;
        *self = current;
        Ok(grant)
    }

    fn revoke_locked(
        &mut self,
        root: &Path,
        root_cap: &fs::File,
        grant_id: &str,
        now: &str,
        expected_from_agent: Option<&str>,
    ) -> Result<ShareGrant, StoreError> {
        let now = time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid revoke clock: {error}")))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| StoreError::Config(format!("invalid revoke clock: {error}")))?;
        let path = root.join(SHARE_STORE_FILE);
        let mut current = Self::read(&path)?;
        let position = current
            .grants
            .iter()
            .position(|grant| grant.id == grant_id)
            .ok_or_else(|| StoreError::Config(format!("share grant {grant_id} not found")))?;
        if let Some(expected_from_agent) = expected_from_agent
            && current.grants[position].from_agent != expected_from_agent
        {
            return Err(StoreError::Config(format!(
                "only the source agent {} can revoke this share",
                go_json_string(&current.grants[position].from_agent)
            )));
        }
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
        let target = root.join(SHARE_STORE_FILE);
        crate::publication::replace(&target, &bytes, root_cap)?;
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

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
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
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
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
        let canonical_root = root
            .path()
            .canonicalize()
            .expect("canonical vault directory");
        let path = canonical_root.join(SHARE_STORE_FILE);
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

    #[test]
    fn revoke_at_requires_no_identity_or_initialized_store() {
        let root = tempfile::tempdir().expect("metadata-only root");
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let path = canonical_root.join(SHARE_STORE_FILE);
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write metadata fixture");
        let mut snapshot = ShareStore::read(&path).expect("read metadata fixture");

        let revoked = snapshot
            .revoke_at(&canonical_root, "grant-a", "2026-01-02T04:00:00Z")
            .expect("metadata-only revoke");
        assert_eq!(revoked.status, "revoked");
        assert_eq!(
            ShareStore::read(&path)
                .expect("read revoked fixture")
                .grants()[0]
                .status,
            "revoked"
        );
    }

    #[test]
    fn revoke_at_for_agent_checks_reloaded_source_before_writing() {
        let root = tempfile::tempdir().expect("metadata-only root");
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let path = canonical_root.join(SHARE_STORE_FILE);
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"old-source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write initial share fixture");
        let mut snapshot = ShareStore::read(&path).expect("read initial share fixture");
        let before = snapshot.clone();
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"new-source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("replace current share fixture");

        let error = snapshot
            .revoke_at_for_agent(
                &canonical_root,
                "grant-a",
                "old-source",
                "2026-01-02T04:00:00Z",
            )
            .expect_err("stale source must not revoke");
        assert_eq!(
            error.to_string(),
            "invalid vault config: only the source agent \"new-source\" can revoke this share"
        );
        assert_eq!(snapshot.grants(), before.grants());
        let persisted = ShareStore::read(&path).expect("read unchanged current share");
        assert_eq!(persisted.grants()[0].from_agent, "new-source");
        assert_eq!(persisted.grants()[0].status, "pending");
    }

    #[test]
    fn create_matches_go_hmac_vector_and_persists_pending_fields() {
        let (_root, path) = fixture_path();
        let vault_root = path.parent().expect("fixture root");
        let mut snapshot = ShareStore::read(&path).expect("read empty fixture");
        let grant = snapshot
            .create_at_with_nonce(
                vault_root,
                "source",
                "target",
                "prod/api",
                "password",
                60_000_000_000,
                "2026-01-02T03:04:05Z",
                Some(GO_KEY),
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
            )
            .expect("create signed Go-compatible grant");
        assert_eq!(grant.id, GO_ID);
        assert_eq!(grant.nonce, "00112233445566778899aabbccddeeff");
        assert_eq!(grant.status, "pending");
        assert_eq!(grant.ttl, 60_000_000_000);
        assert_eq!(grant.expires_at.as_deref(), Some("2026-01-02T03:05:05Z"));

        let persisted = ShareStore::read(&path).expect("read persisted grant");
        assert_eq!(persisted.grants(), std::slice::from_ref(&grant));
        assert_eq!(
            persisted
                .verified_grants(Some(GO_KEY))
                .expect("verify generated HMAC")
                .as_slice(),
            std::slice::from_ref(&grant)
        );
    }

    #[test]
    fn create_legacy_id_uses_secure_random_hex_and_reloads_concurrent_grants() {
        let (_root, path) = fixture_path();
        let vault_root = path.parent().expect("fixture root");
        let mut snapshot = ShareStore::read(&path).expect("read empty fixture");
        let first = snapshot
            .create_at(
                vault_root,
                "source",
                "target",
                "prod/one",
                "",
                0,
                "2026-01-02T03:04:05Z",
                None,
            )
            .expect("create legacy grant");
        assert_eq!(first.id.len(), 32);
        assert!(first.id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(first.nonce.is_empty());

        fs::write(
            &path,
            format!(
                r#"{{"version":1,"grants":[{{"id":"{}","from_agent":"source","to_agent":"target","secret_path":"prod/one","status":"pending","created_at":"2026-01-02T03:04:05Z"}},{{"id":"external","from_agent":"other","to_agent":"target","secret_path":"prod/two","status":"pending","created_at":"2026-01-02T03:04:05Z"}}]}}"#,
                first.id
            ),
        )
        .expect("write concurrent external grant");
        let second = snapshot
            .create_at(
                vault_root,
                "source",
                "target",
                "prod/three",
                "",
                0,
                "2026-01-02T03:04:05Z",
                None,
            )
            .expect("create after concurrent update");
        let persisted = ShareStore::read(&path).expect("read merged grants");
        assert_eq!(persisted.grants().len(), 3);
        assert!(
            persisted
                .grants()
                .iter()
                .any(|grant| grant.id == "external")
        );
        assert!(persisted.grants().iter().any(|grant| grant.id == second.id));
        assert_eq!(snapshot.grants(), persisted.grants());
    }

    #[test]
    fn create_rejects_negative_or_overflow_ttl_without_mutating_snapshot() {
        let (_root, path) = fixture_path();
        let vault_root = path.parent().expect("fixture root");
        let mut snapshot = ShareStore::read(&path).expect("read empty fixture");
        let negative = snapshot
            .create_at(
                vault_root,
                "source",
                "target",
                "prod/api",
                "",
                -1,
                "2026-01-02T03:04:05Z",
                None,
            )
            .expect_err("negative TTL");
        assert_eq!(
            negative.to_string(),
            "invalid vault config: ttl must be a positive duration"
        );
        assert!(snapshot.grants().is_empty());
        assert!(!path.exists());

        let overflow = snapshot
            .create_at(
                vault_root,
                "source",
                "target",
                "prod/api",
                "",
                1,
                "9999-12-31T23:59:59.999999999Z",
                None,
            )
            .expect_err("overflow TTL");
        assert!(overflow.to_string().contains("ttl exceeds timestamp range"));
        assert!(snapshot.grants().is_empty());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn revoke_rejects_share_symlink_without_mutating_referent_or_snapshot() {
        let root = tempfile::tempdir().expect("metadata-only root");
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let path = canonical_root.join(SHARE_STORE_FILE);
        let grant = br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#;
        fs::write(&path, grant).expect("write share fixture");
        let mut snapshot = ShareStore::read(&path).expect("read share fixture");
        let before = snapshot.clone();
        let referent = canonical_root.join("share-referent");
        let referent_bytes = b"referent must remain unchanged";
        fs::write(&referent, referent_bytes).expect("write referent");
        fs::remove_file(&path).expect("remove share fixture");
        symlink(&referent, &path).expect("create share symlink");

        assert!(
            snapshot
                .revoke_at(&canonical_root, "grant-a", "2026-01-02T04:00:00Z")
                .is_err()
        );
        assert_eq!(snapshot.grants(), before.grants());
        assert_eq!(fs::read(&referent).expect("read referent"), referent_bytes);
    }

    #[test]
    fn revoke_rejects_invalid_target_without_mutating_referent_or_snapshot() {
        let root = tempfile::tempdir().expect("metadata-only root");
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let path = canonical_root.join(SHARE_STORE_FILE);
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write share fixture");
        let mut snapshot = ShareStore::read(&path).expect("read share fixture");
        let before = snapshot.clone();
        let referent = canonical_root.join("invalid-target-referent");
        let referent_bytes = b"referent must remain unchanged";
        fs::write(&referent, referent_bytes).expect("write referent");
        fs::remove_file(&path).expect("remove share fixture");
        fs::create_dir(&path).expect("create invalid target");

        assert!(
            snapshot
                .revoke_at(&canonical_root, "grant-a", "2026-01-02T04:00:00Z")
                .is_err()
        );
        assert_eq!(snapshot.grants(), before.grants());
        assert_eq!(fs::read(&referent).expect("read referent"), referent_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn revoke_rejects_lock_symlink_without_mutating_referent_or_snapshot() {
        let root = tempfile::tempdir().expect("metadata-only root");
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let path = canonical_root.join(SHARE_STORE_FILE);
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write share fixture");
        let mut snapshot = ShareStore::read(&path).expect("read share fixture");
        let before = snapshot.clone();
        let referent = canonical_root.join("lock-referent");
        let referent_bytes = b"referent must remain unchanged";
        fs::write(&referent, referent_bytes).expect("write referent");
        symlink(&referent, canonical_root.join(".lock")).expect("create lock symlink");

        assert!(
            snapshot
                .revoke_at(&canonical_root, "grant-a", "2026-01-02T04:00:00Z")
                .is_err()
        );
        assert_eq!(snapshot.grants(), before.grants());
        assert_eq!(fs::read(&referent).expect("read referent"), referent_bytes);
    }
}
