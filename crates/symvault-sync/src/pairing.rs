//! Transport-independent device-pairing handshake (`PAIRING-001`).
//!
//! The Go oracle is `internal/pairing` at the frozen baseline commit. Two JSON
//! artifacts carry the exchange over any channel — a git remote, a synced
//! folder, or a manual copy:
//!
//! 1. the existing device writes `<token>.json` ([`PairingFile`]);
//! 2. the joining device answers with [`JoinResponse`], stored as
//!    `<token>-joined.json` on the git transport and `<token>-response.json`
//!    elsewhere — [`response_filenames`] returns both, in lookup order;
//! 3. `device accept <token>` reads either name and re-encrypts for the new
//!    recipient (that re-encryption is `CRYPTO-004`, not this module).
//!
//! Nothing here performs transport I/O, and nothing here holds a wall clock:
//! [`TokenStore`] takes the current time as an explicit millisecond argument so
//! expiry and cooldown are reproducible.
//!
//! Byte parity with Go is deliberate and load-bearing. The encoder reproduces
//! `encoding/json`'s HTML escaping and `time.Time`'s RFC3339Nano shape, and the
//! decoder reproduces `encoding/json`'s field matching — exact name first, then
//! ASCII-case-insensitive, later keys overwriting earlier ones, unknown keys
//! ignored, `null` leaving a field untouched.

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

/// Time-to-live applied to a stored pairing token, matching Go's
/// `pairing.TokenTTL` default of five minutes.
pub const DEFAULT_TOKEN_TTL_MS: i64 = 5 * 60 * 1000;

/// Failed validation attempts tolerated before every attempt is rejected,
/// matching Go's `maxFailedAttempts`.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Cooldown applied once [`MAX_FAILED_ATTEMPTS`] is reached, matching Go's
/// `failedAttemptCooldown`.
pub const FAILED_ATTEMPT_COOLDOWN_MS: i64 = 30 * 1000;

/// Longest pairing token `validate_pairing_token` accepts, matching Go.
pub const MAX_TOKEN_LEN: usize = 64;

/// Errors raised by the handshake artifact codec and token validation.
///
/// The messages are deliberately Rust-native: the register binds this seam to
/// Go's accept/reject decision and parsed field values, not to Go's error
/// prose, which is recorded in the fixture for reference only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// The payload is not a JSON object, or is not valid JSON at all.
    Json(String),
    /// A recognized field carried a JSON type the Go struct cannot hold.
    FieldType { field: &'static str, got: String },
    /// `created_at` was not a strict RFC3339 timestamp.
    Time(String),
    /// The token cannot be used to build a handshake artifact filename.
    InvalidToken,
    /// The timestamp falls outside the range Go's `time.Time` can marshal.
    UnmarshalableTime,
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(detail) => write!(f, "parse handshake artifact: {detail}"),
            Self::FieldType { field, got } => {
                write!(
                    f,
                    "parse handshake artifact: cannot unmarshal {got} into {field}"
                )
            }
            Self::Time(detail) => write!(f, "parse handshake artifact: {detail}"),
            Self::InvalidToken => write!(f, "invalid pairing token format"),
            Self::UnmarshalableTime => write!(f, "time outside the range Go can marshal"),
        }
    }
}

impl std::error::Error for PairingError {}

// ---------------------------------------------------------------------------
// Go-compatible timestamps
// ---------------------------------------------------------------------------

/// A timestamp with the exact semantics Go's `time.Time` shows across JSON.
///
/// The UTC offset survives a round trip the way Go's does: a parsed `+02:00`
/// is re-emitted as `+02:00`, while `+00:00` normalizes to `Z`, because Go's
/// RFC3339 parser maps a zero offset onto `time.UTC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoTime {
    /// Civil date and time-of-day as written, before the offset is applied.
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
    /// Offset from UTC in seconds; zero is rendered as `Z`.
    offset_seconds: i32,
}

impl GoTime {
    /// Go's zero `time.Time`, which marshals as `0001-01-01T00:00:00Z`.
    pub const ZERO: Self = Self {
        year: 1,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        nanosecond: 0,
        offset_seconds: 0,
    };

    /// Parses the strict RFC3339 grammar Go's `time.Time::UnmarshalJSON` accepts.
    ///
    /// Strict means uppercase `T` and `Z` only, a mandatory zone, and no leap
    /// second: Go's JSON decoder rejects everything its lenient `time.Parse`
    /// would otherwise allow. A fraction longer than nine digits is truncated
    /// to nanoseconds rather than rejected, exactly as Go does.
    pub fn parse_rfc3339(value: &str) -> Result<Self, PairingError> {
        let bad = || PairingError::Time(format!("parsing time {value:?} as RFC3339"));
        let bytes = value.as_bytes();
        if bytes.len() < 20 {
            return Err(bad());
        }
        let digits = |from: usize, to: usize| -> Option<u32> {
            let mut out: u32 = 0;
            for &byte in &bytes[from..to] {
                if !byte.is_ascii_digit() {
                    return None;
                }
                out = out * 10 + u32::from(byte - b'0');
            }
            Some(out)
        };
        if bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
        {
            return Err(bad());
        }
        let year = digits(0, 4).ok_or_else(bad)?;
        let month = digits(5, 7).ok_or_else(bad)?;
        let day = digits(8, 10).ok_or_else(bad)?;
        let hour = digits(11, 13).ok_or_else(bad)?;
        let minute = digits(14, 16).ok_or_else(bad)?;
        let second = digits(17, 19).ok_or_else(bad)?;

        let mut rest = &bytes[19..];
        let mut nanosecond = 0u32;
        if matches!(rest.first(), Some(&b'.') | Some(&b',')) {
            let mut end = 1;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            if end == 1 {
                return Err(bad());
            }
            // Go caps the fraction at nine significant digits and drops the rest.
            let kept = &rest[1..end.min(10)];
            let mut scaled = 0u32;
            for &byte in kept {
                scaled = scaled * 10 + u32::from(byte - b'0');
            }
            for _ in kept.len()..9 {
                scaled *= 10;
            }
            nanosecond = scaled;
            rest = &rest[end..];
        }

        let offset_seconds = match rest {
            [b'Z'] => 0,
            [sign @ (b'+' | b'-'), rest @ ..] if rest.len() == 5 && rest[2] == b':' => {
                let hours = i32::try_from(
                    (rest[0].is_ascii_digit() && rest[1].is_ascii_digit())
                        .then(|| u32::from(rest[0] - b'0') * 10 + u32::from(rest[1] - b'0'))
                        .ok_or_else(bad)?,
                )
                .map_err(|_| bad())?;
                let minutes = i32::try_from(
                    (rest[3].is_ascii_digit() && rest[4].is_ascii_digit())
                        .then(|| u32::from(rest[3] - b'0') * 10 + u32::from(rest[4] - b'0'))
                        .ok_or_else(bad)?,
                )
                .map_err(|_| bad())?;
                // Deliberately unchecked: Go's RFC3339 parser accepts any
                // two-digit pair here and simply folds it into a fixed zone, so
                // "+01:60" becomes "+02:00" and "+24:00" is only refused later,
                // by the marshaller.
                let magnitude = (hours * 60 + minutes) * 60;
                if *sign == b'-' { -magnitude } else { magnitude }
            }
            _ => return Err(bad()),
        };

        if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
            return Err(bad());
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err(bad());
        }

        Ok(Self {
            year: i32::try_from(year).map_err(|_| bad())?,
            month: u8::try_from(month).map_err(|_| bad())?,
            day: u8::try_from(day).map_err(|_| bad())?,
            hour: u8::try_from(hour).map_err(|_| bad())?,
            minute: u8::try_from(minute).map_err(|_| bad())?,
            second: u8::try_from(second).map_err(|_| bad())?,
            nanosecond,
            offset_seconds,
        })
    }

    /// Renders the value the way Go's `time.Time::MarshalJSON` does, without
    /// the surrounding quotes: RFC3339 with trailing zeros stripped from the
    /// fraction and the fraction omitted entirely when it is zero.
    pub fn to_rfc3339_nano(self) -> String {
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if self.nanosecond != 0 {
            let mut fraction = format!("{:09}", self.nanosecond);
            while fraction.ends_with('0') {
                fraction.pop();
            }
            out.push('.');
            out.push_str(&fraction);
        }
        if self.offset_seconds == 0 {
            out.push('Z');
        } else {
            let magnitude = self.offset_seconds.abs();
            out.push(if self.offset_seconds < 0 { '-' } else { '+' });
            out.push_str(&format!(
                "{:02}:{:02}",
                magnitude / 3600,
                (magnitude % 3600) / 60
            ));
        }
        out
    }

    /// Renders the value exactly as Go's `time.Time::MarshalJSON` does,
    /// quotes included, or reports the same refusals Go reports.
    ///
    /// Go's parser is strictly more permissive than its marshaller: a
    /// timestamp carrying a zone of `+24:00` parses but cannot be written
    /// back out. That asymmetry is part of the contract, not a rounding of it.
    pub fn to_go_json(self) -> Result<String, PairingError> {
        self.check_marshalable()?;
        Ok(format!("\"{}\"", self.to_rfc3339_nano()))
    }

    /// Rejects what Go's `time.Time::MarshalJSON` refuses to encode: a year
    /// outside `[0,9999]` and a zone whose hour leaves `[0,23]`.
    fn check_marshalable(self) -> Result<(), PairingError> {
        if !(0..=9999).contains(&self.year) {
            return Err(PairingError::UnmarshalableTime);
        }
        if self.offset_seconds.abs() / 3600 >= 24 {
            return Err(PairingError::UnmarshalableTime);
        }
        Ok(())
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Handshake artifacts
// ---------------------------------------------------------------------------

/// The invitation artifact written by the existing device (`device pair`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingFile {
    /// Pairing token; also the artifact's filename stem.
    pub token: String,
    /// The inviting device's age public key.
    pub public_key: String,
    /// When the invitation was created.
    pub created_at: GoTime,
}

impl Default for PairingFile {
    fn default() -> Self {
        Self {
            token: String::new(),
            public_key: String::new(),
            created_at: GoTime::ZERO,
        }
    }
}

/// The response artifact written by the joining device (`device join`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinResponse {
    /// The token this response answers.
    pub token: String,
    /// Human-readable device name; omitted from Go's output when empty is
    /// *not* the case here — Go tags it `omitempty`-free, so it is always present.
    pub name: String,
    /// The joining device's age public key.
    pub public_key: String,
    /// When the response was created.
    pub created_at: GoTime,
}

impl Default for JoinResponse {
    fn default() -> Self {
        Self {
            token: String::new(),
            name: String::new(),
            public_key: String::new(),
            created_at: GoTime::ZERO,
        }
    }
}

/// Serializes a [`PairingFile`] exactly as `pairing.MarshalPairingFile` does.
pub fn marshal_pairing_file(file: &PairingFile) -> Result<Vec<u8>, PairingError> {
    file.created_at.check_marshalable()?;
    Ok(marshal_object(&[
        ("token", Field::Str(&file.token)),
        ("public_key", Field::Str(&file.public_key)),
        ("created_at", Field::Time(file.created_at)),
    ]))
}

/// Serializes a [`JoinResponse`] exactly as `cmd/device.go` writes it through
/// `savePairingFile`, which is `json.MarshalIndent` with a two-space indent.
pub fn marshal_join_response(response: &JoinResponse) -> Result<Vec<u8>, PairingError> {
    response.created_at.check_marshalable()?;
    Ok(marshal_object(&[
        ("token", Field::Str(&response.token)),
        ("name", Field::Str(&response.name)),
        ("public_key", Field::Str(&response.public_key)),
        ("created_at", Field::Time(response.created_at)),
    ]))
}

enum Field<'a> {
    Str(&'a str),
    Time(GoTime),
}

fn marshal_object(fields: &[(&str, Field<'_>)]) -> Vec<u8> {
    let mut out = String::from("{\n");
    for (index, (name, value)) in fields.iter().enumerate() {
        out.push_str("  ");
        encode_go_string(name, &mut out);
        out.push_str(": ");
        match value {
            Field::Str(text) => encode_go_string(text, &mut out),
            Field::Time(instant) => encode_go_string(&instant.to_rfc3339_nano(), &mut out),
        }
        if index + 1 < fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push('}');
    out.into_bytes()
}

/// Writes a JSON string literal the way `encoding/json` does with HTML
/// escaping left on: `<`, `>` and `&` become numeric escapes so the artifact is
/// safe to embed in a page, and U+2028/U+2029 are escaped so it stays valid
/// JavaScript. `/` is deliberately not escaped, matching Go, and neither is
/// DEL. Go has short escapes for backspace and form feed as well as for the
/// three whitespace controls; every other character below U+0020 falls through
/// to the `\u00xx` form. The set is frozen by
/// `marshal/pairing-file-backspace-and-formfeed` and
/// `marshal/pairing-file-control-chars`, not assumed.
pub(crate) fn encode_go_string(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            control if (control as u32) < 0x20 => {
                let byte = control as u32;
                out.push_str("\\u00");
                out.push(char::from(HEX[((byte >> 4) & 0xF) as usize]));
                out.push(char::from(HEX[(byte & 0xF) as usize]));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Parses an invitation artifact received over any channel.
pub fn parse_pairing_file(data: &[u8]) -> Result<PairingFile, PairingError> {
    let mut file = PairingFile::default();
    for (key, value) in ordered_entries(data)? {
        match match_field(&key, &["token", "public_key", "created_at"]) {
            Some("token") => assign_string(&mut file.token, "PairingFile.token", &value)?,
            Some("public_key") => {
                assign_string(&mut file.public_key, "PairingFile.public_key", &value)?;
            }
            Some("created_at") => {
                assign_time(&mut file.created_at, "PairingFile.created_at", &value)?;
            }
            _ => {}
        }
    }
    Ok(file)
}

/// Parses a response artifact received over any channel.
pub fn parse_join_response(data: &[u8]) -> Result<JoinResponse, PairingError> {
    let mut response = JoinResponse::default();
    for (key, value) in ordered_entries(data)? {
        match match_field(&key, &["token", "name", "public_key", "created_at"]) {
            Some("token") => assign_string(&mut response.token, "JoinResponse.token", &value)?,
            Some("name") => assign_string(&mut response.name, "JoinResponse.name", &value)?,
            Some("public_key") => {
                assign_string(&mut response.public_key, "JoinResponse.public_key", &value)?;
            }
            Some("created_at") => {
                assign_time(&mut response.created_at, "JoinResponse.created_at", &value)?;
            }
            _ => {}
        }
    }
    Ok(response)
}

/// Go matches an incoming key against a field by exact name first and then by
/// folded name, so `Created_At` reaches `created_at` while an unknown key is
/// simply skipped.
fn match_field(key: &str, fields: &'static [&'static str]) -> Option<&'static str> {
    if let Some(field) = fields.iter().find(|field| **field == key) {
        return Some(field);
    }
    let folded = fold_name(key)?;
    fields
        .iter()
        .find(|field| fold_name(field).is_some_and(|candidate| candidate == folded))
        .copied()
}

/// Reproduces `encoding/json`'s `foldName`: ASCII is upper-cased, and any other
/// rune is replaced by the smallest member of its Unicode simple-fold orbit.
///
/// Every field name in this module is ASCII, so a key can only match when each
/// of its runes folds to ASCII. Exactly two non-ASCII runes do: U+212A KELVIN
/// SIGN folds onto `K`, and U+017F LATIN SMALL LETTER LONG S folds onto `S`.
/// Handling just those two is therefore complete here, not an approximation,
/// and it avoids pulling a full case-folding table into the crate. Any other
/// non-ASCII rune makes the key unmatchable, which is reported as `None` rather
/// than as a folded string that could collide with something.
///
/// Pinned by `parse/pairing-file-kelvin-sign-key`,
/// `parse/pairing-file-kelvin-sign-in-second-field`,
/// `parse/pairing-file-long-s-folds-to-s-not-k` and
/// `parse/pairing-file-non-folding-non-ascii-key`.
fn fold_name(name: &str) -> Option<String> {
    let mut folded = String::with_capacity(name.len());
    for character in name.chars() {
        let mapped = match character {
            ascii if ascii.is_ascii() => ascii.to_ascii_uppercase(),
            '\u{212A}' => 'K',
            '\u{17F}' => 'S',
            _ => return None,
        };
        folded.push(mapped);
    }
    Some(folded)
}

/// A JSON `null` leaves the field at its previous value, exactly as Go's
/// decoder does; any non-string value is a type error.
fn assign_string(
    target: &mut String,
    field: &'static str,
    value: &Value,
) -> Result<(), PairingError> {
    match value {
        Value::Null => Ok(()),
        Value::String(text) => {
            *target = text.clone();
            Ok(())
        }
        other => Err(PairingError::FieldType {
            field,
            got: json_kind(other).to_owned(),
        }),
    }
}

fn assign_time(
    target: &mut GoTime,
    field: &'static str,
    value: &Value,
) -> Result<(), PairingError> {
    match value {
        Value::Null => Ok(()),
        Value::String(text) => {
            *target = GoTime::parse_rfc3339(text)?;
            Ok(())
        }
        other => Err(PairingError::FieldType {
            field,
            got: json_kind(other).to_owned(),
        }),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Decodes a JSON object into its entries in document order, keeping duplicate
/// keys. `serde_json::Map` would collapse them, which would lose Go's
/// later-key-wins rule for `{"token":"a","Token":"b"}`.
fn ordered_entries(data: &[u8]) -> Result<Vec<(String, Value)>, PairingError> {
    struct Entries(Vec<(String, Value)>);

    impl<'de> serde::Deserialize<'de> for Entries {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct EntriesVisitor;

            impl<'de> Visitor<'de> for EntriesVisitor {
                type Value = Entries;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a JSON object")
                }

                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                    let mut entries = Vec::new();
                    while let Some(entry) = map.next_entry::<String, Value>()? {
                        entries.push(entry);
                    }
                    Ok(Entries(entries))
                }
            }

            deserializer.deserialize_map(EntriesVisitor)
        }
    }

    serde_json::from_slice::<Entries>(data)
        .map(|entries| entries.0)
        .map_err(|error| PairingError::Json(error.to_string()))
}

/// Canonical filenames a join response may be found under, in lookup order:
/// the git transport writes `<token>-joined.json`, other transports
/// `<token>-response.json`, and `device accept` reads either.
pub fn response_filenames(token: &str) -> [String; 2] {
    [
        format!("{token}-joined.json"),
        format!("{token}-response.json"),
    ]
}

/// Rejects any token that is unsafe to splice into a handshake filename.
///
/// Accepts only the base32-hex alphabet `GenerateToken` emits (`0`–`9`,
/// `A`–`V`, `a`–`v`) up to [`MAX_TOKEN_LEN`] characters, so path separators,
/// NUL, control characters, `..` and every non-ASCII character are refused.
pub fn validate_pairing_token(token: &str) -> Result<(), PairingError> {
    // Byte length, not character count: Go's gate is `len(token) > 64` on the
    // raw string. The two agree for everything Go accepts, but matching the
    // literal comparison keeps the bound from drifting if the alphabet ever
    // widens.
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(PairingError::InvalidToken);
    }
    for character in token.chars() {
        let accepted = character.is_ascii_digit()
            || ('A'..='V').contains(&character)
            || ('a'..='v').contains(&character);
        if !accepted {
            return Err(PairingError::InvalidToken);
        }
    }
    Ok(())
}

/// Formats a token as human-readable four-character blocks, matching Go's
/// `Token.Display`.
///
/// Go slices the token by raw byte offsets, which is lossless for it because a
/// Go string is just bytes — a block boundary landing inside a multi-byte
/// sequence still round-trips. Rust's `String` cannot hold that, and silently
/// substituting `U+FFFD` would invent a behaviour Go does not have, so a
/// non-ASCII token is refused instead. Nothing is lost: every token
/// [`validate_pairing_token`] accepts is ASCII by construction, and
/// `GenerateToken` only ever emits base32-hex.
pub fn display_token(token: &str) -> Result<String, PairingError> {
    if !token.is_ascii() {
        return Err(PairingError::InvalidToken);
    }
    let blocks: Vec<&str> = token
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("ASCII chunks are valid UTF-8"))
        .collect();
    Ok(blocks.join("-"))
}

// ---------------------------------------------------------------------------
// Single-use token store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TokenEntry {
    public_key: String,
    expires_at_ms: i64,
}

/// In-memory store of single-use pairing tokens with expiry and a global
/// brute-force cooldown.
///
/// Time is a parameter rather than a wall clock: every method takes the caller's
/// current Unix time in milliseconds, so expiry and cooldown are reproducible
/// and testable without sleeping. A negative `ttl_ms` stores an already-expired
/// token, which is how the Go oracle's expiry vectors are expressed.
#[derive(Debug, Clone)]
pub struct TokenStore {
    ttl_ms: i64,
    tokens: HashMap<String, TokenEntry>,
    failed_count: u32,
    cooldown_until_ms: i64,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new(DEFAULT_TOKEN_TTL_MS)
    }
}

impl TokenStore {
    /// Creates an empty store whose tokens live for `ttl_ms` milliseconds.
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            ttl_ms,
            tokens: HashMap::new(),
            failed_count: 0,
            cooldown_until_ms: i64::MIN,
        }
    }

    /// Replaces the time-to-live applied to tokens stored from now on, the
    /// Rust counterpart of assigning Go's exported `pairing.TokenTTL`.
    pub fn set_ttl_ms(&mut self, ttl_ms: i64) {
        self.ttl_ms = ttl_ms;
    }

    /// Saves `public_key` under `token`, expiring `ttl_ms` after `now_ms`.
    /// Storing an existing token replaces it, as in Go.
    pub fn store(&mut self, token: &str, public_key: &str, now_ms: i64) {
        self.tokens.insert(
            token.to_owned(),
            TokenEntry {
                public_key: public_key.to_owned(),
                expires_at_ms: now_ms.saturating_add(self.ttl_ms),
            },
        );
    }

    /// Consumes `token` and returns its public key when it is live.
    ///
    /// Tokens are single use: a successful validation removes the token, so a
    /// replay fails. A miss or an expired token counts as a failed attempt, and
    /// once [`MAX_FAILED_ATTEMPTS`] is reached every attempt — including one
    /// carrying a genuinely valid token — is rejected until the cooldown ends.
    pub fn validate(&mut self, token: &str, now_ms: i64) -> Option<String> {
        if self.failed_count >= MAX_FAILED_ATTEMPTS && now_ms < self.cooldown_until_ms {
            return None;
        }
        if self.failed_count >= MAX_FAILED_ATTEMPTS && now_ms > self.cooldown_until_ms {
            self.failed_count = 0;
        }

        let Some(entry) = self.tokens.get(token).cloned() else {
            self.record_failure(now_ms);
            return None;
        };

        if now_ms > entry.expires_at_ms {
            self.tokens.remove(token);
            self.record_failure(now_ms);
            return None;
        }

        self.tokens.remove(token);
        self.failed_count = 0;
        self.cooldown_until_ms = i64::MIN;
        Some(entry.public_key)
    }

    /// Drops every expired token and clears the failure counter once the
    /// cooldown has elapsed.
    pub fn cleanup_expired(&mut self, now_ms: i64) {
        self.tokens.retain(|_, entry| now_ms <= entry.expires_at_ms);
        if self.failed_count >= MAX_FAILED_ATTEMPTS && now_ms > self.cooldown_until_ms {
            self.failed_count = 0;
        }
    }

    /// Number of tokens currently held, expired ones included.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the store holds no tokens at all.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    fn record_failure(&mut self, now_ms: i64) {
        self.failed_count += 1;
        if self.failed_count >= MAX_FAILED_ATTEMPTS {
            self.cooldown_until_ms = now_ms.saturating_add(FAILED_ATTEMPT_COOLDOWN_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_789_000_000_000;

    /// `CleanupExpired` dropping entries is invisible through Go's exported
    /// surface — `Validate` rejects an expired token whether or not it is still
    /// in the map, and the Go store exposes no size — so the frozen
    /// differential cannot distinguish it. This pins the behaviour directly.
    #[test]
    fn cleanup_expired_actually_drops_the_entry() {
        let mut store = TokenStore::new(-1000);
        store.store("EXPIRED", "key", NOW);
        store.set_ttl_ms(DEFAULT_TOKEN_TTL_MS);
        store.store("LIVE", "key", NOW);
        assert_eq!(store.len(), 2);

        store.cleanup_expired(NOW);

        assert_eq!(store.len(), 1, "expired entry survived cleanup");
        assert_eq!(store.validate("LIVE", NOW).as_deref(), Some("key"));
        assert!(store.is_empty());
    }

    /// The Go source resets the failure counter once the cooldown has passed,
    /// but no Go test exercises that branch — reaching it would mean sleeping
    /// out the unexported 30s `failedAttemptCooldown`. This is therefore a
    /// Rust-side guard against the documented Go behaviour, not a differential
    /// claim against a Go run.
    #[test]
    fn cooldown_lapses_after_the_documented_window() {
        let mut store = TokenStore::default();
        store.store("LIVE", "key", NOW);
        for index in 0..MAX_FAILED_ATTEMPTS {
            assert!(store.validate(&format!("WRONG{index}"), NOW).is_none());
        }
        assert!(
            store.validate("LIVE", NOW).is_none(),
            "a valid token must burn while the cooldown is active"
        );

        let after = NOW + FAILED_ATTEMPT_COOLDOWN_MS + 1;
        assert_eq!(store.validate("LIVE", after).as_deref(), Some("key"));
    }

    /// Exactly at the cooldown boundary Go takes neither the reject branch nor
    /// the reset branch, leaving the counter at the limit and the attempt
    /// falling through to a normal lookup.
    #[test]
    fn cooldown_boundary_falls_through_to_a_normal_lookup() {
        let mut store = TokenStore::default();
        store.store("LIVE", "key", NOW);
        for index in 0..MAX_FAILED_ATTEMPTS {
            assert!(store.validate(&format!("WRONG{index}"), NOW).is_none());
        }
        let boundary = NOW + FAILED_ATTEMPT_COOLDOWN_MS;
        assert_eq!(store.validate("LIVE", boundary).as_deref(), Some("key"));
    }

    #[test]
    fn artifacts_round_trip_through_their_own_encoding() {
        let file = PairingFile {
            token: "C5H7GJK9M2N4P6Q8R0S1T3V5U7A9B1D3".into(),
            public_key: "age1<&>\u{2028}key".into(),
            created_at: GoTime::parse_rfc3339("2026-09-14T20:45:00.5+02:00").unwrap(),
        };
        let encoded = marshal_pairing_file(&file).unwrap();
        assert_eq!(parse_pairing_file(&encoded).unwrap(), file);

        let response = JoinResponse {
            token: "ABCD".into(),
            name: "büro-mac".into(),
            public_key: "age1joining".into(),
            created_at: GoTime::ZERO,
        };
        let encoded = marshal_join_response(&response).unwrap();
        assert_eq!(parse_join_response(&encoded).unwrap(), response);
    }

    /// Go folds a key onto a field name before giving up on it, and exactly
    /// two non-ASCII runes fold onto ASCII. Anything else must not match.
    #[test]
    fn field_folding_matches_only_what_go_folds() {
        let with_kelvin = format!("to{}en", '\u{212A}');
        let parsed = parse_pairing_file(format!("{{\"{with_kelvin}\":\"folded\"}}").as_bytes())
            .expect("a folded key is still valid JSON");
        assert_eq!(parsed.token, "folded");

        let with_kappa = format!("to{}en", '\u{3BA}');
        let parsed = parse_pairing_file(format!("{{\"{with_kappa}\":\"ignored\"}}").as_bytes())
            .expect("an unknown key is skipped, not an error");
        assert_eq!(parsed.token, "", "Greek kappa must not fold onto ASCII k");

        let with_long_s = format!("public_{}ey", '\u{17F}');
        let parsed = parse_pairing_file(format!("{{\"{with_long_s}\":\"ignored\"}}").as_bytes())
            .expect("an unknown key is skipped, not an error");
        assert_eq!(parsed.public_key, "", "long s folds onto S, never onto K");
    }

    /// A non-ASCII token is refused by `display_token` rather than rendered
    /// lossily; Go's byte-slicing has no faithful `String` equivalent.
    #[test]
    fn display_refuses_a_token_it_cannot_render_faithfully() {
        assert_eq!(display_token("büro"), Err(PairingError::InvalidToken));
        assert!(validate_pairing_token("büro").is_err());
        assert_eq!(display_token("ABCDEFG").as_deref(), Ok("ABCD-EFG"));
    }

    /// Every token `validate_pairing_token` accepts must be safe to splice into
    /// both handshake filenames — no separator, no traversal, no NUL.
    #[test]
    fn accepted_tokens_cannot_escape_the_pairing_directory() {
        for token in [
            "C5H7GJK9M2N4P6Q8R0S1T3V5U7A9B1D3",
            "0",
            "v",
            "V",
            "0123456789ABCDEFGHIJKLMNOPQRSTUV0123456789ABCDEFGHIJKLMNOPQRSTUV",
        ] {
            validate_pairing_token(token).expect("token from the generated alphabet");
            for name in response_filenames(token) {
                assert!(!name.contains('/'), "{name} carries a separator");
                assert!(!name.contains('\\'), "{name} carries a separator");
                assert!(!name.contains(".."), "{name} carries a traversal");
                assert!(!name.contains('\0'), "{name} carries a NUL");
                assert_eq!(std::path::Path::new(&name).components().count(), 1);
            }
        }
    }

    #[test]
    fn an_unmarshalable_zone_fails_the_whole_artifact() {
        let created_at = GoTime::parse_rfc3339("2026-09-14T18:45:00+24:00")
            .expect("Go's parser accepts this zone");
        assert!(created_at.to_go_json().is_err());
        assert_eq!(
            marshal_pairing_file(&PairingFile {
                created_at,
                ..PairingFile::default()
            }),
            Err(PairingError::UnmarshalableTime)
        );
    }
}
