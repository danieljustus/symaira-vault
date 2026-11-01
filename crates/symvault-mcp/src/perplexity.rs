//! `perplexity_search` / `perplexity_ask` transport and result shaping, ported
//! from `internal/mcp/server/tools_perplexity.go`.
//!
//! The production endpoint is the constant [`DEFAULT_BASE_URL`]. As in Go, the
//! only way to retarget it is `mcp.perplexity.base_url` in the vault config,
//! which must be HTTPS and still passes the SSRF target validation; Go's
//! config loader drops `allow_private`, so a config file can never enable
//! private targets. Tests inject a fixture trust root and `allow_private`
//! through [`PerplexityRuntimeConfig`] and [`crate::broker::ApiTransportOptions`],
//! mirroring Go tests that assign `srv.vault.Config` and swap the HTTP client.

use crate::{
    RequestContext,
    broker::{self, ApiResponseBounds, ApiTemplate, ApiTransportOptions},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use symvault_core::go_quote;

pub const DEFAULT_BASE_URL: &str = "https://api.perplexity.ai";
const CHAT_ENDPOINT: &str = "/chat/completions";
pub const DEFAULT_MODEL: &str = "sonar-pro";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_RATE_LIMIT: i64 = 10;
const MAX_TOKENS: u32 = 2048;
const RESPONSE_LIMIT: usize = 1024 * 1024;
/// Vault entry consulted when `mcp.perplexity.api_key` is not configured.
pub const API_KEY_ENTRY: &str = "perplexity";

pub const SEARCH_SYSTEM_PROMPT: &str = "You are a search assistant. Synthesize search results for the user's query. Provide accurate, up-to-date information with citations where applicable. Be concise and direct.";
pub const ASK_SYSTEM_PROMPT: &str = "You are a helpful AI assistant. Answer the user's question clearly and accurately. Provide citations for your answers where applicable.";
pub const ASK_CONTEXT_SYSTEM_PROMPT: &str = "You are a helpful AI assistant with access to the user's vault entries as context. Use the provided vault context to answer the user's question. If the vault context is insufficient, supplement with your own knowledge and cite sources. Provide citations for your answers where applicable.";

/// Go's `config.PerplexityConfig` as the runtime consumes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerplexityRuntimeConfig {
    pub api_key: String,
    pub base_url: String,
    pub rate_limit_per_min: i64,
    pub allow_private: bool,
}

#[derive(Deserialize, Default)]
struct RawPerplexity {
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    rate_limit_per_min: Option<i64>,
}

#[derive(Deserialize, Default)]
struct RawMcp {
    #[serde(default)]
    perplexity: Option<RawPerplexity>,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    mcp: Option<RawMcp>,
}

/// Loads `mcp.perplexity` from the vault config with Go's merge rules: empty
/// strings and non-positive limits keep the defaults and `allow_private` is
/// never read (`mergeMCPConfig` ignores it).
#[must_use]
pub fn load_perplexity_config(config_path: &Path) -> Option<PerplexityRuntimeConfig> {
    let bytes = std::fs::read(config_path).ok()?;
    let raw: RawConfig = serde_yaml_ng::from_slice(&bytes).ok()?;
    let perplexity = raw.mcp?.perplexity?;
    Some(PerplexityRuntimeConfig {
        api_key: perplexity.api_key.unwrap_or_default(),
        base_url: perplexity.base_url.unwrap_or_default(),
        rate_limit_per_min: perplexity
            .rate_limit_per_min
            .filter(|v| *v > 0)
            .unwrap_or(0),
        allow_private: false,
    })
}

// ---------------------------------------------------------------------------
// Process-global fixed-window rate limiter (`globalPerplexityRL`)
// ---------------------------------------------------------------------------

struct RateLimiter {
    count: i64,
    reset_at: Option<Instant>,
}

static RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter {
    count: 0,
    reset_at: None,
});

fn rate_limit_allow(max_per_minute: i64) -> bool {
    let Ok(mut limiter) = RATE_LIMITER.lock() else {
        return false;
    };
    let now = Instant::now();
    if limiter.reset_at.is_none_or(|reset_at| now > reset_at) {
        limiter.count = 0;
        limiter.reset_at = Some(now + Duration::from_secs(60));
    }
    limiter.count += 1;
    limiter.count <= max_per_minute
}

/// Test hook equivalent to Go tests assigning `globalPerplexityRL`.
#[doc(hidden)]
pub fn reset_rate_limiter_for_tests() {
    if let Ok(mut limiter) = RATE_LIMITER.lock() {
        limiter.count = 0;
        limiter.reset_at = None;
    }
}

// ---------------------------------------------------------------------------
// Request/response shapes
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
}

/// The fields of `perplexityChatResponse` the tools use.
#[derive(Debug, Default)]
pub(crate) struct ChatResponse {
    pub model: String,
    pub first_answer: Option<String>,
    pub citations: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct SearchResult<'a> {
    pub query: &'a str,
    pub answer: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub model: &'a str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub citations: &'a [String],
}

#[derive(Serialize)]
pub(crate) struct AskResult<'a> {
    pub question: &'a str,
    pub answer: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub model: &'a str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub citations: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub context: &'a [String],
}

// ---------------------------------------------------------------------------
// Target validation (url.Parse + ssrf.ValidateURL, up to DNS)
// ---------------------------------------------------------------------------

/// Go `url.Parse` prefix: control characters, scheme extraction and the
/// scheme-less colon rule. Returns the lower-cased scheme and the rest.
fn go_parse_scheme(raw: &str) -> Result<(String, &str), String> {
    let fail = |reason: &str| format!("parse {}: {reason}", go_quote(raw));
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(fail("net/url: invalid control character in URL"));
    }
    let mut scheme_end = None;
    for (index, character) in raw.char_indices() {
        match character {
            'a'..='z' | 'A'..='Z' => {}
            '0'..='9' | '+' | '-' | '.' => {
                if index == 0 {
                    break;
                }
            }
            ':' => {
                if index == 0 {
                    return Err(fail("missing protocol scheme"));
                }
                scheme_end = Some(index);
                break;
            }
            _ => break,
        }
    }
    match scheme_end {
        Some(index) => Ok((raw[..index].to_ascii_lowercase(), &raw[index + 1..])),
        None => {
            if !raw.starts_with('/')
                && raw
                    .split('/')
                    .next()
                    .is_some_and(|segment| segment.contains(':'))
            {
                return Err(fail("first path segment in URL cannot contain colon"));
            }
            Ok((String::new(), raw))
        }
    }
}

/// `u.Host` for an `https` URL: the authority without userinfo.
fn go_url_host(rest: &str) -> String {
    let Some(after) = rest.strip_prefix("//") else {
        return String::new();
    };
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .to_owned()
}

/// `apitemplates.IsPrivateHost` for `u.Host` (which may carry a port).
fn go_is_private_host(host: &str) -> bool {
    let host = split_host_port(host).unwrap_or(host);
    if host == "localhost" || host == "localhost.localdomain" {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(go_is_private_ip)
}

/// `net.SplitHostPort` host part, `None` when Go would return an error.
fn split_host_port(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return (!port.contains(':')).then_some(host);
    }
    let (host, port) = value.rsplit_once(':')?;
    (!host.contains(':') && !port.contains(':')).then_some(host)
}

/// `apitemplates.IsPrivateIP`.
fn go_is_private_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_multicast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return go_is_private_ip(IpAddr::V4(mapped));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || first & 0xffc0 == 0xfe80
                || first & 0xfe00 == 0xfc00
        }
    }
}

/// Validates the base URL exactly as `callPerplexityChat` does before any
/// credential is placed on a request.
fn validate_base_url(base_url: &str, allow_private: bool) -> Result<(), String> {
    let (scheme, rest) = go_parse_scheme(base_url)
        .map_err(|error| format!("invalid perplexity base URL: {error}"))?;
    if scheme != "https" {
        return Err(format!(
            "perplexity base URL must use HTTPS, got {}",
            go_quote(&scheme)
        ));
    }
    if allow_private {
        return Ok(());
    }
    let host = go_url_host(rest);
    let hostname = host
        .strip_prefix('[')
        .and_then(|bracketed| bracketed.split_once(']').map(|(inner, _)| inner))
        .map_or_else(
            || {
                host.rsplit_once(':')
                    .map_or(host.as_str(), |(name, _)| name)
                    .to_owned()
            },
            str::to_owned,
        );
    if hostname.is_empty() {
        return Err("blocked request target: URL host is required".into());
    }
    if go_is_private_host(&host) {
        return Err(format!(
            "blocked request target {}: private or local network address",
            go_quote(&host)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response decoding (encoding/json semantics for perplexityChatResponse)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanState {
    BeginValue,
    BeginValueOrEmpty,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    InStringEscU(u8),
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    Exp,
    ExpSign,
    Exp0,
    Literal(&'static [u8], usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParseContext {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

/// Go's `strconv.Quote`-based `quoteChar` for a scanner byte.
fn go_quote_char(byte: u8) -> String {
    match byte {
        b'\'' => "'\\''".to_owned(),
        b'"' => "'\"'".to_owned(),
        0x20..=0x7e => format!("'{}'", byte as char),
        0x80..=0xa0 | 0xad => format!("'\\u{byte:04x}'"),
        0x7f => "'\\x7f'".to_owned(),
        0x00..=0x1f => match byte {
            0x07 => "'\\a'".to_owned(),
            0x08 => "'\\b'".to_owned(),
            0x09 => "'\\t'".to_owned(),
            0x0a => "'\\n'".to_owned(),
            0x0b => "'\\v'".to_owned(),
            0x0c => "'\\f'".to_owned(),
            0x0d => "'\\r'".to_owned(),
            _ => format!("'\\x{byte:02x}'"),
        },
        _ => format!("'{}'", byte as char),
    }
}

/// Port of `encoding/json`'s `checkValid` scanner. Returns Go's syntax error
/// text for the first offending byte.
fn go_check_valid(data: &[u8]) -> Result<(), String> {
    let mut state = ScanState::BeginValue;
    let mut stack: Vec<ParseContext> = Vec::new();
    let mut ended = false;
    let bad = |byte: u8, context: &str| {
        Err(format!(
            "invalid character {} {context}",
            go_quote_char(byte)
        ))
    };
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n');

    // `pop` and `end_value` are expressed inline through this helper closure
    // set; the machine is small enough to keep as one loop.
    fn after_value(stack: &[ParseContext], ended: &mut bool) -> ScanState {
        if stack.is_empty() {
            *ended = true;
            ScanState::EndTop
        } else {
            ScanState::EndValue
        }
    }

    let mut index = 0;
    // `None` stands for the synthetic space Go feeds at end of input.
    while index <= data.len() {
        let eof = index == data.len();
        let byte = if eof { b' ' } else { data[index] };
        // Re-dispatch loop: some states hand the same byte to another state.
        loop {
            match state {
                ScanState::BeginValueOrEmpty => {
                    if is_space(byte) {
                        break;
                    }
                    if byte == b']' {
                        state = ScanState::EndValue;
                        continue;
                    }
                    state = ScanState::BeginValue;
                    continue;
                }
                ScanState::BeginValue => {
                    if is_space(byte) {
                        break;
                    }
                    match byte {
                        b'{' => {
                            state = ScanState::BeginStringOrEmpty;
                            stack.push(ParseContext::ObjectKey);
                        }
                        b'[' => {
                            state = ScanState::BeginValueOrEmpty;
                            stack.push(ParseContext::ArrayValue);
                        }
                        b'"' => state = ScanState::InString,
                        b'-' => state = ScanState::Neg,
                        b'0' => state = ScanState::Zero,
                        b'1'..=b'9' => state = ScanState::One,
                        b't' => state = ScanState::Literal(b"true", 1),
                        b'f' => state = ScanState::Literal(b"false", 1),
                        b'n' => state = ScanState::Literal(b"null", 1),
                        _ => return bad(byte, "looking for beginning of value"),
                    }
                    break;
                }
                ScanState::BeginStringOrEmpty => {
                    if is_space(byte) {
                        break;
                    }
                    if byte == b'}' {
                        if let Some(top) = stack.last_mut() {
                            *top = ParseContext::ObjectValue;
                        }
                        state = ScanState::EndValue;
                        continue;
                    }
                    state = ScanState::BeginString;
                    continue;
                }
                ScanState::BeginString => {
                    if is_space(byte) {
                        break;
                    }
                    if byte == b'"' {
                        state = ScanState::InString;
                        break;
                    }
                    return bad(byte, "looking for beginning of object key string");
                }
                ScanState::EndValue => {
                    let Some(&context) = stack.last() else {
                        ended = true;
                        state = ScanState::EndTop;
                        continue;
                    };
                    if is_space(byte) {
                        break;
                    }
                    match context {
                        ParseContext::ObjectKey => {
                            if byte == b':' {
                                if let Some(top) = stack.last_mut() {
                                    *top = ParseContext::ObjectValue;
                                }
                                state = ScanState::BeginValue;
                                break;
                            }
                            return bad(byte, "after object key");
                        }
                        ParseContext::ObjectValue => {
                            if byte == b',' {
                                if let Some(top) = stack.last_mut() {
                                    *top = ParseContext::ObjectKey;
                                }
                                state = ScanState::BeginString;
                                break;
                            }
                            if byte == b'}' {
                                stack.pop();
                                state = after_value(&stack, &mut ended);
                                break;
                            }
                            return bad(byte, "after object key:value pair");
                        }
                        ParseContext::ArrayValue => {
                            if byte == b',' {
                                state = ScanState::BeginValue;
                                break;
                            }
                            if byte == b']' {
                                stack.pop();
                                state = after_value(&stack, &mut ended);
                                break;
                            }
                            return bad(byte, "after array element");
                        }
                    }
                }
                ScanState::EndTop => {
                    if !is_space(byte) {
                        return bad(byte, "after top-level value");
                    }
                    break;
                }
                ScanState::InString => {
                    match byte {
                        b'"' => state = ScanState::EndValue,
                        b'\\' => state = ScanState::InStringEsc,
                        0..=0x1f => return bad(byte, "in string literal"),
                        _ => {}
                    }
                    break;
                }
                ScanState::InStringEsc => {
                    match byte {
                        b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                            state = ScanState::InString;
                        }
                        b'u' => state = ScanState::InStringEscU(0),
                        _ => return bad(byte, "in string escape code"),
                    }
                    break;
                }
                ScanState::InStringEscU(count) => {
                    if !byte.is_ascii_hexdigit() {
                        return bad(byte, "in \\u hexadecimal character escape");
                    }
                    state = if count == 3 {
                        ScanState::InString
                    } else {
                        ScanState::InStringEscU(count + 1)
                    };
                    break;
                }
                ScanState::Neg => {
                    match byte {
                        b'0' => state = ScanState::Zero,
                        b'1'..=b'9' => state = ScanState::One,
                        _ => return bad(byte, "in numeric literal"),
                    }
                    break;
                }
                ScanState::One => {
                    if byte.is_ascii_digit() {
                        break;
                    }
                    state = ScanState::Zero;
                    continue;
                }
                ScanState::Zero => {
                    match byte {
                        b'.' => state = ScanState::Dot,
                        b'e' | b'E' => state = ScanState::Exp,
                        _ => {
                            state = ScanState::EndValue;
                            continue;
                        }
                    }
                    break;
                }
                ScanState::Dot => {
                    if byte.is_ascii_digit() {
                        state = ScanState::Dot0;
                        break;
                    }
                    return bad(byte, "after decimal point in numeric literal");
                }
                ScanState::Dot0 => {
                    if byte.is_ascii_digit() {
                        break;
                    }
                    if matches!(byte, b'e' | b'E') {
                        state = ScanState::Exp;
                        break;
                    }
                    state = ScanState::EndValue;
                    continue;
                }
                ScanState::Exp => {
                    if matches!(byte, b'+' | b'-') {
                        state = ScanState::ExpSign;
                        break;
                    }
                    state = ScanState::ExpSign;
                    continue;
                }
                ScanState::ExpSign => {
                    if byte.is_ascii_digit() {
                        state = ScanState::Exp0;
                        break;
                    }
                    return bad(byte, "in exponent of numeric literal");
                }
                ScanState::Exp0 => {
                    if byte.is_ascii_digit() {
                        break;
                    }
                    state = ScanState::EndValue;
                    continue;
                }
                ScanState::Literal(word, position) => {
                    if byte != word[position] {
                        return bad(
                            byte,
                            &format!(
                                "in literal {} (expecting {})",
                                String::from_utf8_lossy(word),
                                go_quote_char(word[position])
                            ),
                        );
                    }
                    state = if position + 1 == word.len() {
                        ScanState::EndValue
                    } else {
                        ScanState::Literal(word, position + 1)
                    };
                    break;
                }
            }
        }
        if eof {
            break;
        }
        index += 1;
    }
    if ended || state == ScanState::EndTop {
        Ok(())
    } else {
        Err("unexpected end of JSON input".into())
    }
}

/// Source-ordered JSON tree so the first type error is the one Go reports.
#[derive(Debug)]
enum Node {
    Null,
    Bool,
    Number(String),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodeVisitor;
        impl<'de> serde::de::Visitor<'de> for NodeVisitor {
            type Value = Node;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> Result<Node, E> {
                Ok(Node::Null)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Node, E> {
                Ok(Node::Bool)
            }
            fn visit_i64<E>(self, value: i64) -> Result<Node, E> {
                Ok(Node::Number(value.to_string()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Node, E> {
                Ok(Node::Number(value.to_string()))
            }
            fn visit_f64<E>(self, value: f64) -> Result<Node, E> {
                Ok(Node::Number(
                    serde_json::Number::from_f64(value)
                        .map_or_else(|| value.to_string(), |number| number.to_string()),
                ))
            }
            fn visit_str<E>(self, value: &str) -> Result<Node, E> {
                Ok(Node::Str(value.to_owned()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Node::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, Node>()? {
                    entries.push(entry);
                }
                // With serde_json's number-precision feature on, every number
                // arrives as this one-key map holding the literal text.
                if let [(key, Node::Str(text))] = entries.as_slice()
                    && key == "$serde_json::private::Number"
                {
                    return Ok(Node::Number(text.clone()));
                }
                Ok(Node::Object(entries))
            }
        }
        deserializer.deserialize_any(NodeVisitor)
    }
}

impl Node {
    fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Number(_) => "number",
            Self::Str(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

const ROOT: &str = "perplexityChatResponse";

/// `UnmarshalTypeError.Error()` as rendered by the pinned Go toolchain: the
/// innermost struct type plus the dotted JSON key path from the root (slice
/// indices are not part of the path).
fn field_error(kind: &str, owner: &str, path: &str, go_type: &str) -> String {
    format!("json: cannot unmarshal {kind} into Go struct field {owner}.{path} of type {go_type}")
}

fn decode_string(node: &Node, owner: &str, path: &str) -> Result<String, String> {
    match node {
        Node::Null => Ok(String::new()),
        Node::Str(text) => Ok(text.clone()),
        other => Err(field_error(other.kind(), owner, path, "string")),
    }
}

fn decode_int(node: &Node, owner: &str, path: &str) -> Result<(), String> {
    match node {
        Node::Null => Ok(()),
        Node::Number(text) if text.parse::<i64>().is_ok() => Ok(()),
        Node::Number(text) => Err(field_error(&format!("number {text}"), owner, path, "int")),
        other => Err(field_error(other.kind(), owner, path, "int")),
    }
}

/// Go's exact-then-case-insensitive struct field match.
fn field_name(key: &str, names: &[&'static str]) -> Option<&'static str> {
    names.iter().copied().find(|name| *name == key).or_else(|| {
        names
            .iter()
            .copied()
            .find(|name| name.eq_ignore_ascii_case(key))
    })
}

pub(crate) fn parse_chat_response(body: &[u8]) -> Result<ChatResponse, String> {
    go_check_valid(body)?;
    let root: Node = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    let entries = match root {
        Node::Null => return Ok(ChatResponse::default()),
        Node::Object(entries) => entries,
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type server.perplexityChatResponse",
                other.kind()
            ));
        }
    };
    let mut response = ChatResponse::default();
    for (key, node) in &entries {
        let Some(name) = field_name(key, &["id", "model", "choices", "citations", "usage"]) else {
            continue;
        };
        match name {
            "id" => {
                decode_string(node, ROOT, "id")?;
            }
            "model" => response.model = decode_string(node, ROOT, "model")?,
            "choices" => match node {
                Node::Null => {
                    response.first_answer = None;
                }
                Node::Array(items) => {
                    let mut first = None;
                    for (index, item) in items.iter().enumerate() {
                        let content = decode_choice(item)?;
                        if index == 0 {
                            first = Some(content);
                        }
                    }
                    response.first_answer = first;
                }
                other => {
                    return Err(field_error(
                        other.kind(),
                        ROOT,
                        "choices",
                        "[]server.perplexityChatChoice",
                    ));
                }
            },
            "citations" => match node {
                Node::Null => response.citations = Vec::new(),
                Node::Array(items) => {
                    let mut citations = Vec::with_capacity(items.len());
                    for item in items {
                        citations.push(match item {
                            Node::Str(text) => text.clone(),
                            Node::Null => String::new(),
                            other => {
                                return Err(field_error(other.kind(), ROOT, "citations", "string"));
                            }
                        });
                    }
                    response.citations = citations;
                }
                other => return Err(field_error(other.kind(), ROOT, "citations", "[]string")),
            },
            _ => decode_usage(node)?,
        }
    }
    Ok(response)
}

fn decode_usage(node: &Node) -> Result<(), String> {
    match node {
        Node::Null => Ok(()),
        Node::Object(entries) => {
            for (key, value) in entries {
                if let Some(name) =
                    field_name(key, &["prompt_tokens", "completion_tokens", "total_tokens"])
                {
                    decode_int(value, "perplexityUsage", &format!("usage.{name}"))?;
                }
            }
            Ok(())
        }
        other => Err(field_error(
            other.kind(),
            ROOT,
            "usage",
            "server.perplexityUsage",
        )),
    }
}

fn decode_choice(node: &Node) -> Result<String, String> {
    const CHOICE: &str = "perplexityChatChoice";
    const MESSAGE: &str = "perplexityMessage";
    let entries = match node {
        Node::Null => return Ok(String::new()),
        Node::Object(entries) => entries,
        other => {
            return Err(field_error(
                other.kind(),
                ROOT,
                "choices",
                "server.perplexityChatChoice",
            ));
        }
    };
    let mut content = String::new();
    for (key, value) in entries {
        match field_name(key, &["index", "message", "finish_reason"]) {
            Some("index") => decode_int(value, CHOICE, "choices.index")?,
            Some("finish_reason") => {
                decode_string(value, CHOICE, "choices.finish_reason")?;
            }
            Some(_) => match value {
                Node::Null => {}
                Node::Object(message) => {
                    for (key, value) in message {
                        match field_name(key, &["role", "content"]) {
                            Some("role") => {
                                decode_string(value, MESSAGE, "choices.message.role")?;
                            }
                            Some(_) => {
                                content = decode_string(value, MESSAGE, "choices.message.content")?;
                            }
                            None => {}
                        }
                    }
                }
                other => {
                    return Err(field_error(
                        other.kind(),
                        CHOICE,
                        "choices.message",
                        "server.perplexityMessage",
                    ));
                }
            },
            None => {}
        }
    }
    Ok(content)
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// `callPerplexityChat`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn call_chat(
    api_key: &str,
    base_url: &str,
    messages: &[(&str, &str)],
    allow_private: bool,
    rate_limit: i64,
    options: &ApiTransportOptions,
    context: &RequestContext,
) -> Result<ChatResponse, String> {
    if !rate_limit_allow(rate_limit) {
        return Err(format!(
            "perplexity rate limit exceeded: max {rate_limit} requests per minute"
        ));
    }
    validate_base_url(base_url, allow_private)?;

    let request = ChatRequest {
        model: DEFAULT_MODEL,
        messages: messages
            .iter()
            .map(|(role, content)| ChatMessage { role, content })
            .collect(),
        max_tokens: MAX_TOKENS,
    };
    let body = symvault_gojson::to_string(&request)
        .map_err(|error| format!("marshal request: {error}"))?;

    let request_url = format!("{}{CHAT_ENDPOINT}", base_url.trim_end_matches('/'));
    let template = ApiTemplate {
        base_url: base_url.to_owned(),
        allowed_endpoints: Vec::new(),
        allowed_methods: Vec::new(),
        default_headers: BTreeMap::new(),
        allow_private,
    };
    let headers = BTreeMap::from([
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Authorization".to_owned(), format!("Bearer {api_key}")),
        ("Accept".to_owned(), "application/json".to_owned()),
    ]);
    let response = broker::execute_http_for_api(
        &template,
        "POST",
        CHAT_ENDPOINT,
        &request_url,
        &headers,
        body.as_bytes(),
        ApiResponseBounds {
            timeout: DEFAULT_TIMEOUT,
            response_limit: RESPONSE_LIMIT,
            context: context.clone(),
            options,
        },
    )
    .map_err(|error| format!("perplexity API call failed: {error}"))?;

    if response.status != 200 {
        return Err(format!(
            "perplexity API returned status {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    parse_chat_response(&response.body).map_err(|error| format!("parse response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_validation_uses_go_wording() {
        assert_eq!(
            validate_base_url("http://example.com", false).unwrap_err(),
            "perplexity base URL must use HTTPS, got \"http\""
        );
        assert_eq!(
            validate_base_url("example.com/x", false).unwrap_err(),
            "perplexity base URL must use HTTPS, got \"\""
        );
        assert_eq!(
            validate_base_url("://x", false).unwrap_err(),
            "invalid perplexity base URL: parse \"://x\": missing protocol scheme"
        );
        assert_eq!(
            validate_base_url("https://127.0.0.1:8443", false).unwrap_err(),
            "blocked request target \"127.0.0.1:8443\": private or local network address"
        );
        assert_eq!(
            validate_base_url("https://localhost", false).unwrap_err(),
            "blocked request target \"localhost\": private or local network address"
        );
        assert_eq!(
            validate_base_url("https://", false).unwrap_err(),
            "blocked request target: URL host is required"
        );
        assert!(validate_base_url("https://127.0.0.1:8443", true).is_ok());
        assert!(validate_base_url(DEFAULT_BASE_URL, false).is_ok());
    }

    #[test]
    fn response_decoding_matches_encoding_json_shapes() {
        let ok = parse_chat_response(
            br#"{"id":"x","model":"sonar-pro","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],"citations":["a","b"],"usage":{"total_tokens":3}}"#,
        )
        .unwrap();
        assert_eq!(ok.model, "sonar-pro");
        assert_eq!(ok.first_answer.as_deref(), Some("hi"));
        assert_eq!(ok.citations, ["a", "b"]);
        assert_eq!(
            parse_chat_response(b"").unwrap_err(),
            "unexpected end of JSON input"
        );
        assert_eq!(
            parse_chat_response(b"<html>").unwrap_err(),
            "invalid character '<' looking for beginning of value"
        );
        assert_eq!(
            parse_chat_response(b"[]").unwrap_err(),
            "json: cannot unmarshal array into Go value of type server.perplexityChatResponse"
        );
        assert!(parse_chat_response(b"null").unwrap().first_answer.is_none());
    }

    #[test]
    fn number_nodes_survive_serde_json_features() {
        let node: Node = serde_json::from_str("1.5").unwrap();
        assert!(
            matches!(&node, Node::Number(text) if text == "1.5"),
            "{node:?}"
        );
        let node: Node = serde_json::from_str("7").unwrap();
        assert!(
            matches!(&node, Node::Number(text) if text == "7"),
            "{node:?}"
        );
    }

    #[test]
    fn private_ip_matches_go_definition() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(go_is_private_ip(private.parse().unwrap()), "{private}");
        }
        // Go's IsPrivate/IsMulticast do not cover broadcast or CGNAT.
        for public in ["255.255.255.255", "100.64.0.1", "8.8.8.8", "2606:4700::1"] {
            assert!(!go_is_private_ip(public.parse().unwrap()), "{public}");
        }
    }
}
