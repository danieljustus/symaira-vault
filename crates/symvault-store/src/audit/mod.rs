//! Pure keyed audit-chain primitives shared by future storage and adapters.
//!
//! The Go audit logger writes one `LogEntry` JSON object per line. When an HMAC
//! key is available, the `kid` field identifies the key generation and the
//! `hmac` field authenticates the previous raw HMAC bytes followed by the
//! compact JSON object with `hmac` omitted. This module deliberately operates
//! on caller-owned bytes and entries only; key persistence, file rotation, and
//! CLI/MCP integration remain outside this slice.

use std::{collections::BTreeMap, fmt};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Errors produced by the pure audit-chain operations.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("hmac key is empty")]
    EmptyKey,
    #[error("no hmac keys provided")]
    NoKeys,
    #[error("failed to serialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// A JSONL audit record with the same field names, order, and omission rules
/// as Go's `internal/audit.LogEntry`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogEntry {
    #[serde(rename = "ts", default, deserialize_with = "deserialize_null_default")]
    pub timestamp: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub agent: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub action: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub field: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub transport: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub reason: String,
    #[serde(
        rename = "share_id",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub share_id: String,
    #[serde(
        rename = "from_agent",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub from_agent: String,
    #[serde(
        rename = "to_agent",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub to_agent: String,
    #[serde(
        rename = "share_action",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub share_action: String,
    #[serde(
        rename = "dur_ms",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "is_zero"
    )]
    pub dur_ms: i64,
    #[serde(
        rename = "token_id",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub token_id: String,
    #[serde(
        rename = "req_id",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub request_id: String,
    #[serde(
        rename = "sess_id",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub session_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub kid: String,
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub hmac: String,
    #[serde(
        rename = "argv_hash",
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub argv_hash: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub ok: bool,
}

/// Alias that makes the audit purpose explicit at call sites.
pub type AuditLogEntry = LogEntry;

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// The result counters returned by Go's `VerifyLogAgainstKeys` equivalent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyResult {
    pub valid: bool,
    pub total: usize,
    pub verified: usize,
    pub legacy: usize,
    pub tampered: usize,
    pub unverifiable: usize,
    /// Zero-based index of the first tampered entry, or `-1` when none exists.
    pub first_bad_idx: i64,
}

/// Computes the Go `KeyFingerprint`: the first four SHA-256 bytes as lowercase
/// hexadecimal, used as the audit entry's key-generation ID (`kid`).
#[must_use]
pub fn key_fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    encode_hex(&digest[..4])
}

/// Serializes an entry exactly as the Go logger does before HMAC computation.
/// The `hmac` field is cleared and therefore omitted by its `omitempty` rule.
pub fn canonical_json(entry: &LogEntry) -> Result<Vec<u8>, AuditError> {
    let mut unsigned = entry.clone();
    unsigned.hmac.clear();
    serialize_go_json(&unsigned).map_err(AuditError::from)
}

/// Computes the lowercase hexadecimal HMAC-SHA256 for one chain entry.
/// `previous_hmac` is the raw decoded HMAC bytes from the preceding record;
/// an empty slice represents the first record or a legacy prefix reset.
pub fn compute_hmac(
    key: &[u8],
    previous_hmac: &[u8],
    entry: &LogEntry,
) -> Result<String, AuditError> {
    Ok(encode_hex(&compute_hmac_bytes(key, previous_hmac, entry)?))
}

fn compute_hmac_bytes(
    key: &[u8],
    previous_hmac: &[u8],
    entry: &LogEntry,
) -> Result<[u8; 32], AuditError> {
    let canonical = canonical_json(entry)?;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts every key length");
    mac.update(previous_hmac);
    mac.update(&canonical);
    let digest = mac.finalize().into_bytes();
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

/// A deterministic in-memory signer for one JSONL audit chain.
pub struct AuditChain {
    key: Vec<u8>,
    kid: String,
    previous_hmac: Vec<u8>,
}

impl fmt::Debug for AuditChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditChain")
            .field("kid", &self.kid)
            .field("has_previous_hmac", &(!self.previous_hmac.is_empty()))
            .finish_non_exhaustive()
    }
}

impl AuditChain {
    /// Starts a new chain and computes its `kid` from `key`.
    pub fn new(key: &[u8]) -> Result<Self, AuditError> {
        Self::with_previous_hmac(key, &[])
    }

    /// Starts a chain whose next record links to `previous_hmac`, as needed by
    /// a caller reopening an existing log. No filesystem or parsing is done.
    pub fn with_previous_hmac(key: &[u8], previous_hmac: &[u8]) -> Result<Self, AuditError> {
        if key.is_empty() {
            return Err(AuditError::EmptyKey);
        }
        Ok(Self {
            key: key.to_vec(),
            kid: key_fingerprint(key),
            previous_hmac: previous_hmac.to_vec(),
        })
    }

    /// Returns the key-generation ID written into signed records.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// Returns the raw HMAC bytes used as the next record's predecessor.
    #[must_use]
    pub fn previous_hmac(&self) -> Option<&[u8]> {
        (!self.previous_hmac.is_empty()).then_some(self.previous_hmac.as_slice())
    }

    /// Signs an entry, replacing any caller-supplied `kid` and `hmac` exactly
    /// as the Go logger does before writing it.
    pub fn sign_entry(&mut self, mut entry: LogEntry) -> Result<LogEntry, AuditError> {
        entry.kid.clone_from(&self.kid);
        let digest = compute_hmac_bytes(&self.key, &self.previous_hmac, &entry)?;
        entry.hmac = encode_hex(&digest);
        self.previous_hmac = digest.to_vec();
        Ok(entry)
    }

    /// Signs an entry and returns one complete JSONL record, including its
    /// terminating newline.
    pub fn append(&mut self, entry: LogEntry) -> Result<Vec<u8>, AuditError> {
        let signed = self.sign_entry(entry)?;
        let mut line = serialize_go_json(&signed).map_err(AuditError::from)?;
        line.push(b'\n');
        Ok(line)
    }
}

impl Drop for AuditChain {
    fn drop(&mut self) {
        self.key.zeroize();
        self.previous_hmac.zeroize();
    }
}

/// Verifies JSONL bytes against one HMAC key.
pub fn verify_jsonl(data: &[u8], key: &[u8]) -> Result<VerifyResult, AuditError> {
    if key.is_empty() {
        return Err(AuditError::EmptyKey);
    }
    let kid = key_fingerprint(key);
    let mut keys = BTreeMap::new();
    keys.insert(kid.clone(), key.to_vec());
    verify_jsonl_against_keys(data, &keys, &kid)
}

/// Verifies JSONL bytes against known key generations.
///
/// Records with a `kid` use that key directly. Records without a `kid` try
/// `current_kid` first and then the remaining IDs in lexical order, matching
/// the Go verifier's deterministic fallback. A missing key is unverifiable,
/// not tampered. A legacy record before the first HMAC is accepted; a missing
/// HMAC after the chain starts is a tamper/reset signal.
pub fn verify_jsonl_against_keys(
    data: &[u8],
    keys: &BTreeMap<String, Vec<u8>>,
    current_kid: &str,
) -> Result<VerifyResult, AuditError> {
    if keys.is_empty() {
        return Err(AuditError::NoKeys);
    }

    let entries = parse_entries(data);
    let trial_kids = trial_kid_order(keys, current_kid);
    let mut result = VerifyResult {
        valid: true,
        total: entries.len(),
        verified: 0,
        legacy: 0,
        tampered: 0,
        unverifiable: 0,
        first_bad_idx: -1,
    };
    let mut previous_hmac = Vec::new();
    let mut chain_started = false;

    for (index, entry) in entries.iter().enumerate() {
        if entry.hmac.is_empty() {
            if chain_started {
                mark_tampered(&mut result, index);
            } else {
                result.legacy += 1;
                previous_hmac.clear();
            }
            continue;
        }

        let Some(entry_hmac) = decode_hex(&entry.hmac) else {
            mark_tampered(&mut result, index);
            continue;
        };

        let (matched, known) = if !entry.kid.is_empty() {
            match keys.get(&entry.kid) {
                Some(key) => (
                    constant_time_equal(
                        &compute_hmac_bytes(key, &previous_hmac, entry)?,
                        &entry_hmac,
                    ),
                    true,
                ),
                None => (false, false),
            }
        } else {
            let mut matched = false;
            let mut known = false;
            for kid in &trial_kids {
                let expected = compute_hmac_bytes(
                    keys.get(kid).expect("trial key ID came from the key map"),
                    &previous_hmac,
                    entry,
                )?;
                if constant_time_equal(&expected, &entry_hmac) {
                    matched = true;
                    known = true;
                    break;
                }
            }
            (matched, known)
        };

        match (matched, known) {
            (true, _) => result.verified += 1,
            (false, true) => mark_tampered(&mut result, index),
            (false, false) => result.unverifiable += 1,
        }

        // Match Go's forward-link behavior: later records use the literal
        // stored HMAC even when this record was tampered or unverifiable.
        previous_hmac = entry_hmac;
        chain_started = true;
    }

    Ok(result)
}

fn mark_tampered(result: &mut VerifyResult, index: usize) {
    result.tampered += 1;
    result.valid = false;
    if result.first_bad_idx < 0 {
        result.first_bad_idx = i64::try_from(index).expect("audit index fits in i64");
    }
}

fn trial_kid_order(keys: &BTreeMap<String, Vec<u8>>, current_kid: &str) -> Vec<String> {
    let mut order = Vec::with_capacity(keys.len());
    if keys.contains_key(current_kid) {
        order.push(current_kid.to_owned());
    }
    order.extend(
        keys.keys()
            .filter(|kid| kid.as_str() != current_kid)
            .cloned(),
    );
    order
}

fn parse_entries(data: &[u8]) -> Vec<LogEntry> {
    data.split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let line = String::from_utf8_lossy(line);
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            // Go's json.Unmarshal("null", &entry) leaves a zero LogEntry and
            // reports success; Option preserves that small compatibility edge.
            serde_json::from_str::<Option<LogEntry>>(line)
                .ok()
                .map(|entry| entry.unwrap_or_default())
        })
        .collect()
}

fn serialize_go_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let raw = serde_json::to_vec(value)?;
    Ok(escape_go_json_html(&raw))
}

// encoding/json escapes these characters even inside otherwise ordinary JSON
// strings. serde_json intentionally does not, so apply the Go-compatible
// escaping after compact serialization while leaving JSON syntax untouched.
fn escape_go_json_html(raw: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped_character = false;
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if !in_string {
            escaped.push(byte);
            if byte == b'"' {
                in_string = true;
            }
            index += 1;
            continue;
        }

        if escaped_character {
            escaped.push(byte);
            escaped_character = false;
            index += 1;
            continue;
        }

        match byte {
            b'\\' => {
                escaped.push(byte);
                escaped_character = true;
                index += 1;
            }
            b'"' => {
                escaped.push(byte);
                in_string = false;
                index += 1;
            }
            b'<' => {
                escaped.extend_from_slice(b"\\u003c");
                index += 1;
            }
            b'>' => {
                escaped.extend_from_slice(b"\\u003e");
                index += 1;
            }
            b'&' => {
                escaped.extend_from_slice(b"\\u0026");
                index += 1;
            }
            0xe2 if index + 2 < raw.len() && raw[index + 1] == 0x80 && raw[index + 2] == 0xa8 => {
                escaped.extend_from_slice(b"\\u2028");
                index += 3;
            }
            0xe2 if index + 2 < raw.len() && raw[index + 1] == 0x80 && raw[index + 2] == 0xa9 => {
                escaped.extend_from_slice(b"\\u2029");
                index += 3;
            }
            _ => {
                escaped.push(byte);
                index += 1;
            }
        }
    }
    escaped
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, remainder) = bytes.as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
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

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
