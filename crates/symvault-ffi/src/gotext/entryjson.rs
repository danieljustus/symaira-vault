//! `json.Unmarshal(entryJSON, &vault.Entry)` as the Go bridge performs it:
//! `encoding/json`'s syntax errors, its `UnmarshalTypeError` wording for the
//! `Entry` schema, and its decoding quirks (case-insensitive field names,
//! repeated keys merging into one map, numbers always becoming `float64`).

use std::collections::BTreeMap;

use serde_json::{Map, Number, Value};
use symvault_store::{AttachmentInfo, Entry, EntryMetadata, SecretMetadata, WriteRecord};
use zeroize::{Zeroize, Zeroizing};

use super::quote;
use super::timefmt::canonical_rfc3339;

// ---------------------------------------------------------------------------
// Syntax: a port of the error behavior of encoding/json's scanner.
// ---------------------------------------------------------------------------

fn quote_char(byte: u8) -> String {
    match byte {
        b'\'' => "'\\''".to_owned(),
        b'"' => "'\"'".to_owned(),
        _ => {
            // strconv.Quote(string(rune(byte))) with the outer quotes swapped.
            let quoted = quote(&char::from(byte).to_string());
            format!("'{}'", &quoted[1..quoted.len() - 1])
        }
    }
}

struct Syntax<'a> {
    data: &'a [u8],
    position: usize,
}

type Check = Result<(), String>;

impl Syntax<'_> {
    fn eof() -> String {
        "unexpected end of JSON input".to_owned()
    }

    fn bad(&self, byte: u8, context: &str) -> String {
        format!("invalid character {} {context}", quote_char(byte))
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn next(&mut self) -> Result<u8, String> {
        let byte = self.peek().ok_or_else(Self::eof)?;
        self.position += 1;
        Ok(byte)
    }

    fn literal(&mut self, rest: &[u8], name: &str) -> Check {
        for expected in rest {
            let byte = self.next()?;
            if byte != *expected {
                return Err(self.bad(
                    byte,
                    &format!("in literal {name} (expecting {})", quote_char(*expected)),
                ));
            }
        }
        Ok(())
    }

    fn string(&mut self) -> Check {
        loop {
            match self.next()? {
                b'"' => return Ok(()),
                b'\\' => match self.next()? {
                    b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {}
                    b'u' => {
                        for _ in 0..4 {
                            let byte = self.next()?;
                            if !byte.is_ascii_hexdigit() {
                                return Err(self.bad(byte, "in \\u hexadecimal character escape"));
                            }
                        }
                    }
                    other => return Err(self.bad(other, "in string escape code")),
                },
                byte if byte < 0x20 => return Err(self.bad(byte, "in string literal")),
                _ => {}
            }
        }
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }

    fn number(&mut self) -> Check {
        if self.peek() == Some(b'-') {
            self.position += 1;
            match self.peek() {
                Some(b'0'..=b'9') => {}
                Some(byte) => return Err(self.bad(byte, "in numeric literal")),
                None => return Err(Self::eof()),
            }
        }
        if self.peek() == Some(b'0') {
            self.position += 1;
        } else {
            self.digits();
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            match self.peek() {
                Some(b'0'..=b'9') => self.digits(),
                Some(byte) => {
                    return Err(self.bad(byte, "after decimal point in numeric literal"));
                }
                None => return Err(Self::eof()),
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            match self.peek() {
                Some(b'0'..=b'9') => self.digits(),
                Some(byte) => return Err(self.bad(byte, "in exponent of numeric literal")),
                None => return Err(Self::eof()),
            }
        }
        Ok(())
    }

    /// One JSON value, without recursion: open containers live on `open`
    /// (a heap `Vec`), so no input can consume more native stack than a
    /// constant. `encoding/json`'s scanner refuses more than
    /// [`MAX_NESTING_DEPTH`] open containers with `exceeded max depth`.
    fn document(&mut self) -> Check {
        let mut open: Vec<Container> = Vec::new();
        loop {
            // A value starts here.
            self.skip_space();
            let byte = self.next()?;
            let complete = match byte {
                b'{' | b'[' => {
                    if open.len() >= MAX_NESTING_DEPTH {
                        return Err(self.bad(byte, "exceeded max depth"));
                    }
                    self.skip_space();
                    let closer = if byte == b'{' { b'}' } else { b']' };
                    if self.peek() == Some(closer) {
                        self.position += 1;
                        true
                    } else {
                        if byte == b'{' {
                            self.object_key()?;
                            open.push(Container::Object);
                        } else {
                            open.push(Container::Array);
                        }
                        false
                    }
                }
                b'"' => {
                    self.string()?;
                    true
                }
                b'-' | b'0'..=b'9' => {
                    self.position -= 1;
                    self.number()?;
                    true
                }
                b't' => {
                    self.literal(b"rue", "true")?;
                    true
                }
                b'f' => {
                    self.literal(b"alse", "false")?;
                    true
                }
                b'n' => {
                    self.literal(b"ull", "null")?;
                    true
                }
                other => return Err(self.bad(other, "looking for beginning of value")),
            };
            if !complete {
                continue;
            }
            // Close every container this value finishes; stop at the first
            // separator that announces another value.
            loop {
                match open.last() {
                    None => {
                        self.skip_space();
                        return match self.peek() {
                            Some(byte) => Err(self.bad(byte, "after top-level value")),
                            None => Ok(()),
                        };
                    }
                    Some(Container::Array) => {
                        self.skip_space();
                        match self.next()? {
                            b',' => break,
                            b']' => {
                                open.pop();
                            }
                            other => return Err(self.bad(other, "after array element")),
                        }
                    }
                    Some(Container::Object) => {
                        self.skip_space();
                        match self.next()? {
                            b',' => {
                                self.object_key()?;
                                break;
                            }
                            b'}' => {
                                open.pop();
                            }
                            other => return Err(self.bad(other, "after object key:value pair")),
                        }
                    }
                }
            }
        }
    }

    /// `"key" :` of an object member.
    fn object_key(&mut self) -> Check {
        self.skip_space();
        match self.next()? {
            b'"' => self.string()?,
            other => {
                return Err(self.bad(other, "looking for beginning of object key string"));
            }
        }
        self.skip_space();
        match self.next()? {
            b':' => Ok(()),
            other => Err(self.bad(other, "after object key")),
        }
    }
}

/// `encoding/json`'s `maxNestingDepth`.
const MAX_NESTING_DEPTH: usize = 10_000;

#[derive(Clone, Copy)]
enum Container {
    Array,
    Object,
}

fn check_valid(data: &[u8]) -> Check {
    Syntax { data, position: 0 }.document()
}

// ---------------------------------------------------------------------------
// A syntax tree that keeps repeated keys, because Go's decoder merges them.
// ---------------------------------------------------------------------------

enum Node {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl Drop for Node {
    /// Dropping a deeply nested tree member by member would recurse once per
    /// level; hand the children to a work list instead. Every text, number
    /// literal and object key passes through [`scrub`] first: the tree holds
    /// the plaintext of the entry being written.
    fn drop(&mut self) {
        let mut pending: Vec<Node> = Vec::new();
        scrub(self, &mut pending);
        while let Some(mut node) = pending.pop() {
            scrub(&mut node, &mut pending);
        }
    }
}

fn scrub(node: &mut Node, children: &mut Vec<Node>) {
    match node {
        Node::Text(text) | Node::Number(text) => text.zeroize(),
        Node::Array(items) => children.append(items),
        Node::Object(members) => children.extend(members.drain(..).map(|(mut key, child)| {
            key.zeroize();
            child
        })),
        Node::Null | Node::Bool(_) => {}
    }
}

impl Node {
    fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::Text(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

struct Builder<'a> {
    data: &'a [u8],
    position: usize,
}

impl Builder<'_> {
    fn skip_space(&mut self) {
        while matches!(
            self.data.get(self.position),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.position += 1;
        }
    }

    /// Builds the tree of an already validated document without recursion.
    fn node(&mut self) -> Node {
        enum Open {
            Array(Vec<Node>),
            Object(Vec<(String, Node)>, String),
        }
        let mut open: Vec<Open> = Vec::new();
        loop {
            self.skip_space();
            let mut finished = match self.data[self.position] {
                b'{' => {
                    self.position += 1;
                    self.skip_space();
                    if self.data[self.position] == b'}' {
                        self.position += 1;
                        Some(Node::Object(Vec::new()))
                    } else {
                        let key = self.member_key();
                        open.push(Open::Object(Vec::new(), key));
                        None
                    }
                }
                b'[' => {
                    self.position += 1;
                    self.skip_space();
                    if self.data[self.position] == b']' {
                        self.position += 1;
                        Some(Node::Array(Vec::new()))
                    } else {
                        open.push(Open::Array(Vec::new()));
                        None
                    }
                }
                _ => Some(self.scalar()),
            };
            while let Some(node) = finished.take() {
                match open.last_mut() {
                    None => return node,
                    Some(Open::Array(items)) => {
                        items.push(node);
                        self.skip_space();
                        let separator = self.data[self.position];
                        self.position += 1;
                        if separator == b']'
                            && let Some(Open::Array(items)) = open.pop()
                        {
                            finished = Some(Node::Array(items));
                        }
                    }
                    Some(Open::Object(members, key)) => {
                        members.push((std::mem::take(key), node));
                        self.skip_space();
                        let separator = self.data[self.position];
                        self.position += 1;
                        if separator == b'}' {
                            if let Some(Open::Object(members, _)) = open.pop() {
                                finished = Some(Node::Object(members));
                            }
                        } else {
                            *key = self.member_key();
                        }
                    }
                }
            }
        }
    }

    /// `"key" :` of an object member; returns the decoded key.
    fn member_key(&mut self) -> String {
        self.skip_space();
        self.position += 1;
        let key = self.string_body();
        self.skip_space();
        self.position += 1;
        key
    }

    fn scalar(&mut self) -> Node {
        match self.data[self.position] {
            b'"' => {
                self.position += 1;
                Node::Text(self.string_body())
            }
            b't' => {
                self.position += 4;
                Node::Bool(true)
            }
            b'f' => {
                self.position += 5;
                Node::Bool(false)
            }
            b'n' => {
                self.position += 4;
                Node::Null
            }
            _ => {
                let start = self.position;
                while self.position < self.data.len()
                    && matches!(
                        self.data[self.position],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.position += 1;
                }
                Node::Number(String::from_utf8_lossy(&self.data[start..self.position]).into_owned())
            }
        }
    }

    fn hex4(&mut self) -> u32 {
        let text = std::str::from_utf8(&self.data[self.position..self.position + 4]).unwrap_or("0");
        self.position += 4;
        u32::from_str_radix(text, 16).unwrap_or(0xfffd)
    }

    /// Decodes a string body (opening quote already consumed) like Go:
    /// invalid UTF-8 and lone surrogates become U+FFFD.
    fn string_body(&mut self) -> String {
        let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        loop {
            let byte = self.data[self.position];
            self.position += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = self.data[self.position];
                    self.position += 1;
                    match escape {
                        b'b' => raw.push(8),
                        b'f' => raw.push(12),
                        b'n' => raw.push(b'\n'),
                        b'r' => raw.push(b'\r'),
                        b't' => raw.push(b'\t'),
                        b'u' => {
                            let mut unit = self.hex4();
                            let mut ch = char::from_u32(unit).unwrap_or('\u{fffd}');
                            if (0xd800..0xdc00).contains(&unit) {
                                let pair = self.data.get(self.position..self.position + 6);
                                let low = pair
                                    .filter(|bytes| bytes.starts_with(b"\\u"))
                                    .and_then(|bytes| std::str::from_utf8(&bytes[2..]).ok())
                                    .and_then(|text| u32::from_str_radix(text, 16).ok())
                                    .filter(|low| (0xdc00..0xe000).contains(low));
                                if let Some(low) = low {
                                    self.position += 6;
                                    unit = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                                    ch = char::from_u32(unit).unwrap_or('\u{fffd}');
                                } else {
                                    ch = '\u{fffd}';
                                }
                            }
                            let mut buffer = [0u8; 4];
                            raw.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                        }
                        other => raw.push(other),
                    }
                }
                other => raw.push(other),
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }
}

// ---------------------------------------------------------------------------
// Typed decoding of vault.Entry.
// ---------------------------------------------------------------------------

/// The first recoverable error (`UnmarshalTypeError`) and the abort error.
struct Decoder {
    saved: Option<String>,
}

impl Decoder {
    fn save(&mut self, message: String) {
        if self.saved.is_none() {
            self.saved = Some(message);
        }
    }

    fn mismatch(&mut self, value: &str, structure: &str, field: &str, go_type: &str) {
        self.save(format!(
            "json: cannot unmarshal {value} into Go struct field {structure}.{field} of type {go_type}"
        ));
    }
}

fn field_matches(key: &str, name: &str) -> bool {
    key == name || key.to_lowercase() == name
}

/// The store refuses a data value nested deeper than this (Go's
/// `maxEntryDepth`, `symvault_store::MAX_ENTRY_DEPTH`). Everything beyond one
/// level past it is replaced by `null`: the store rejects the entry at the
/// first node deeper than the limit, so the discarded part is never persisted,
/// and building it would cost native stack and memory for nothing. The
/// discarded part is still *scanned* (iteratively) because Go reports a number
/// that does not fit `float64` wherever it appears.
const MATERIALIZED_DEPTH: usize = symvault_store::MAX_ENTRY_DEPTH + 1;

fn number_value_or_mismatch(decoder: &mut Decoder, literal: &str, field: &str) -> Value {
    match literal.parse::<f64>() {
        Ok(number) if number.is_finite() => number_value(number),
        _ => {
            decoder.mismatch(&format!("number {literal}"), "alias", field, "float64");
            Value::Null
        }
    }
}

/// Reports the number errors of a subtree that is not materialized, in
/// document order, without recursion.
fn scan_numbers(decoder: &mut Decoder, root: &Node, field: &str) {
    let mut pending: Vec<&Node> = vec![root];
    while let Some(node) = pending.pop() {
        match node {
            Node::Number(literal) => {
                let _ = number_value_or_mismatch(decoder, literal, field);
            }
            Node::Array(items) => pending.extend(items.iter().rev()),
            Node::Object(members) => pending.extend(members.iter().rev().map(|(_, child)| child)),
            _ => {}
        }
    }
}

/// `depth` is the nesting level the store assigns to the value (1 for a value
/// directly under `data`), so recursion is bounded by [`MATERIALIZED_DEPTH`].
fn any_value(decoder: &mut Decoder, node: &Node, field: &str, depth: usize) -> Value {
    if depth > MATERIALIZED_DEPTH {
        scan_numbers(decoder, node, field);
        return Value::Null;
    }
    match node {
        Node::Null => Value::Null,
        Node::Bool(flag) => Value::Bool(*flag),
        Node::Text(text) => Value::String(text.clone()),
        Node::Number(literal) => number_value_or_mismatch(decoder, literal, field),
        Node::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| any_value(decoder, item, field, depth + 1))
                .collect(),
        ),
        Node::Object(members) => {
            let mut map = Map::new();
            for (key, value) in members {
                map.insert(key.clone(), any_value(decoder, value, field, depth + 1));
            }
            Value::Object(map)
        }
    }
}

/// A JSON number as Go prints a `float64` (`strconv` `'f'`/`'e'` rule, `-0`
/// kept), so the stored plaintext is the text Go writes. `serde_json` keeps the
/// literal (`arbitrary_precision` is enabled workspace-wide).
pub(crate) fn number_value(number: f64) -> Value {
    let text = crate::marshal::go_float(number);
    // serde_json reads the integer literal `-0` as 0 and loses the sign, but
    // keeps `-0.0`; Go reads both as float64 -0.
    let text = if text == "-0" {
        "-0.0".to_owned()
    } else {
        text
    };
    serde_json::from_str::<Number>(&text).map_or(Value::Null, Value::Number)
}

fn decode_int(
    decoder: &mut Decoder,
    node: &Node,
    structure: &str,
    field: &str,
    go_type: &str,
) -> Option<i64> {
    match node {
        Node::Null => None,
        Node::Number(literal) => match literal.parse::<i64>() {
            Ok(value) => Some(value),
            Err(_) => {
                decoder.mismatch(&format!("number {literal}"), structure, field, go_type);
                None
            }
        },
        other => {
            decoder.mismatch(other.kind(), structure, field, go_type);
            None
        }
    }
}

fn decode_string(
    decoder: &mut Decoder,
    node: &Node,
    structure: &str,
    field: &str,
    go_type: &str,
) -> Option<String> {
    match node {
        Node::Null => None,
        Node::Text(text) => Some(text.clone()),
        other => {
            decoder.mismatch(other.kind(), structure, field, go_type);
            None
        }
    }
}

fn decode_bool(decoder: &mut Decoder, node: &Node, structure: &str, field: &str) -> Option<bool> {
    match node {
        Node::Null => None,
        Node::Bool(flag) => Some(*flag),
        other => {
            decoder.mismatch(other.kind(), structure, field, "bool");
            None
        }
    }
}

/// `time.Time.UnmarshalJSON`: an abort error, not a recoverable one.
fn decode_time(node: &Node) -> Result<Option<String>, String> {
    match node {
        Node::Null => Ok(None),
        Node::Text(text) => canonical_rfc3339(text).map(Some),
        _ => Err("Time.UnmarshalJSON: input is not a JSON string".to_owned()),
    }
}

fn decode_write_record(
    decoder: &mut Decoder,
    node: &Node,
    prefix: &str,
) -> Result<WriteRecord, String> {
    let mut record = WriteRecord::default();
    let Node::Object(members) = node else {
        if !matches!(node, Node::Null) {
            decoder.mismatch(node.kind(), "WriteRecord", prefix, "vault.WriteRecord");
        }
        return Ok(record);
    };
    for (key, value) in members {
        if field_matches(key, "timestamp") {
            if let Some(stamp) = decode_time(value)? {
                record.timestamp = stamp;
            }
        } else if field_matches(key, "field") {
            if let Some(text) = decode_string(
                decoder,
                value,
                "WriteRecord",
                &format!("{prefix}.field"),
                "string",
            ) {
                record.field = text;
            }
        } else if field_matches(key, "action")
            && let Some(text) = decode_string(
                decoder,
                value,
                "WriteRecord",
                &format!("{prefix}.action"),
                "string",
            )
        {
            record.action = text;
        }
    }
    Ok(record)
}

fn decode_metadata(
    decoder: &mut Decoder,
    node: &Node,
    metadata: &mut EntryMetadata,
) -> Result<(), String> {
    let Node::Object(members) = node else {
        if !matches!(node, Node::Null) {
            decoder.mismatch(node.kind(), "alias", "meta", "vault.EntryMetadata");
        }
        return Ok(());
    };
    for (key, value) in members {
        if field_matches(key, "created") {
            if let Some(stamp) = decode_time(value)? {
                metadata.created = stamp;
            }
        } else if field_matches(key, "updated") {
            if let Some(stamp) = decode_time(value)? {
                metadata.updated = stamp;
            }
        } else if field_matches(key, "version") {
            if let Some(version) =
                decode_int(decoder, value, "EntryMetadata", "meta.version", "int")
            {
                metadata.version = version;
            }
        } else if field_matches(key, "tags") {
            match value {
                Node::Null => metadata.tags = Vec::new(),
                Node::Array(items) => {
                    metadata.tags = items
                        .iter()
                        .map(|item| {
                            decode_string(decoder, item, "EntryMetadata", "meta.tags", "string")
                                .unwrap_or_default()
                        })
                        .collect();
                }
                other => decoder.mismatch(other.kind(), "EntryMetadata", "meta.tags", "[]string"),
            }
        } else if field_matches(key, "write_history") {
            match value {
                Node::Null => metadata.write_history = Vec::new(),
                Node::Array(items) => {
                    let mut history = Vec::with_capacity(items.len());
                    for item in items {
                        history.push(decode_write_record(decoder, item, "meta.write_history")?);
                    }
                    metadata.write_history = history;
                }
                other => decoder.mismatch(
                    other.kind(),
                    "EntryMetadata",
                    "meta.write_history",
                    "[]vault.WriteRecord",
                ),
            }
        }
    }
    Ok(())
}

fn decode_secret_metadata(
    decoder: &mut Decoder,
    node: &Node,
    secret: &mut SecretMetadata,
) -> Result<(), String> {
    let Node::Object(members) = node else {
        if !matches!(node, Node::Null) {
            decoder.mismatch(node.kind(), "alias", "secret_meta", "vault.SecretMetadata");
        }
        return Ok(());
    };
    for (key, value) in members {
        if field_matches(key, "type") {
            if let Some(text) = decode_string(
                decoder,
                value,
                "SecretMetadata",
                "secret_meta.type",
                "vault.SecretType",
            ) {
                secret.secret_type = text;
            }
        } else if field_matches(key, "usage_hint") {
            if let Some(text) = decode_string(
                decoder,
                value,
                "SecretMetadata",
                "secret_meta.usage_hint",
                "string",
            ) {
                secret.usage_hint = text;
            }
        } else if field_matches(key, "auto_rotate") {
            if let Some(flag) =
                decode_bool(decoder, value, "SecretMetadata", "secret_meta.auto_rotate")
            {
                secret.auto_rotate = flag;
            }
        } else if field_matches(key, "expires_at") {
            secret.expires_at = decode_time(value)?.or(secret.expires_at.take());
        } else if field_matches(key, "attachments") {
            match value {
                Node::Null => secret.attachments = BTreeMap::new(),
                Node::Object(files) => {
                    for (name, info) in files {
                        let mut attachment = AttachmentInfo::default();
                        if let Node::Object(fields) = info {
                            for (field, entry) in fields {
                                let path = "secret_meta.attachments";
                                if field_matches(field, "filename") {
                                    if let Some(text) = decode_string(
                                        decoder,
                                        entry,
                                        "AttachmentInfo",
                                        &format!("{path}.filename"),
                                        "string",
                                    ) {
                                        attachment.filename = text;
                                    }
                                } else if field_matches(field, "size") {
                                    if let Some(size) = decode_int(
                                        decoder,
                                        entry,
                                        "AttachmentInfo",
                                        &format!("{path}.size"),
                                        "int64",
                                    ) {
                                        attachment.size = size;
                                    }
                                } else if field_matches(field, "sha256")
                                    && let Some(text) = decode_string(
                                        decoder,
                                        entry,
                                        "AttachmentInfo",
                                        &format!("{path}.sha256"),
                                        "string",
                                    )
                                {
                                    attachment.sha256 = text;
                                }
                            }
                        } else if !matches!(info, Node::Null) {
                            decoder.mismatch(
                                info.kind(),
                                "SecretMetadata",
                                "secret_meta.attachments",
                                "vault.AttachmentInfo",
                            );
                        }
                        secret.attachments.insert(name.clone(), attachment);
                    }
                }
                other => decoder.mismatch(
                    other.kind(),
                    "SecretMetadata",
                    "secret_meta.attachments",
                    "map[string]vault.AttachmentInfo",
                ),
            }
        }
    }
    Ok(())
}

/// Decodes `text` as Go's `json.Unmarshal([]byte(text), &entry)`; the error is
/// the text Go returns (the bridge prefixes it with `unmarshal entry: `).
pub(crate) fn decode_entry(text: &str) -> Result<Entry, String> {
    check_valid(text.as_bytes())?;
    let mut builder = Builder {
        data: text.as_bytes(),
        position: 0,
    };
    let root = builder.node();
    let mut decoder = Decoder { saved: None };
    let mut entry = Entry::default();
    match &root {
        Node::Null => {}
        Node::Object(members) => {
            for (key, value) in members {
                if field_matches(key, "path") {
                    if let Some(path) =
                        decode_string(&mut decoder, value, "alias", "path", "string")
                    {
                        entry.path = path;
                    }
                } else if field_matches(key, "data") {
                    match value {
                        Node::Null => {}
                        Node::Object(items) => {
                            for (name, item) in items {
                                let decoded = any_value(&mut decoder, item, "data", 1);
                                entry.data.insert(name.clone(), decoded);
                            }
                        }
                        other => decoder.mismatch(
                            other.kind(),
                            "alias",
                            "data",
                            "map[string]interface {}",
                        ),
                    }
                } else if field_matches(key, "meta") {
                    decode_metadata(&mut decoder, value, &mut entry.metadata)?;
                } else if field_matches(key, "secret_meta") {
                    decode_secret_metadata(&mut decoder, value, &mut entry.secret_metadata)?;
                } else if field_matches(key, "classification") {
                    if let Some(class) = decode_int(
                        &mut decoder,
                        value,
                        "alias",
                        "classification",
                        "taint.Classification",
                    ) {
                        match i32::try_from(class) {
                            Ok(class) => entry.classification = class,
                            Err(_) => decoder.mismatch(
                                &format!("number {class}"),
                                "alias",
                                "classification",
                                "taint.Classification",
                            ),
                        }
                    }
                } else if field_matches(key, "canary")
                    && let Some(flag) = decode_bool(&mut decoder, value, "alias", "canary")
                {
                    entry.canary = flag;
                }
            }
        }
        other => {
            decoder.save(format!(
                "json: cannot unmarshal {} into Go value of type vault.alias",
                other.kind()
            ));
        }
    }
    match decoder.saved {
        Some(message) => {
            scrub_entry(&mut entry);
            Err(message)
        }
        None => Ok(entry),
    }
}

/// Overwrites the plaintext of an entry's data before it is dropped: `serde_json`
/// values do not zeroize themselves. Recursion is bounded by the store's nesting
/// limit (values deeper than that are never materialized, see `any_value`).
pub(crate) fn scrub_entry(entry: &mut Entry) {
    for (mut key, mut value) in std::mem::take(&mut entry.data) {
        key.zeroize();
        scrub_value(&mut value);
    }
}

fn scrub_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub_value),
        Value::Object(map) => {
            for (mut key, mut item) in std::mem::take(map) {
                key.zeroize();
                scrub_value(&mut item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_errors_match_go() {
        assert_eq!(
            check_valid(b"").unwrap_err(),
            "unexpected end of JSON input"
        );
        assert_eq!(
            check_valid(b"{} x").unwrap_err(),
            "invalid character 'x' after top-level value"
        );
        assert_eq!(
            check_valid(b"{\"data\":tru}").unwrap_err(),
            "invalid character '}' in literal true (expecting 'e')"
        );
        assert_eq!(
            check_valid(b"{\"a\":\"\\q\"}").unwrap_err(),
            "invalid character 'q' in string escape code"
        );
        assert_eq!(
            check_valid("\u{feff}{}".as_bytes()).unwrap_err(),
            "invalid character 'ï' looking for beginning of value"
        );
    }

    #[test]
    fn repeated_data_keys_merge_and_names_fold_case() {
        let entry = decode_entry(r#"{"data":{"k":"first","k":"second"},"DATA":{"z":1}}"#).unwrap();
        assert_eq!(entry.data["k"], "second");
        assert_eq!(entry.data["z"], 1);
    }

    /// The syntax check, the tree builder, the converter and the destructor
    /// are all iterative: 10 000 nested levels (Go's limit) fit a 128 KiB stack.
    #[test]
    fn nesting_up_to_gos_limit_needs_no_native_recursion() {
        let outcome = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let nested = |levels: usize, open: &str, close: &str| {
                    format!("{}1{}", open.repeat(levels), close.repeat(levels))
                };
                assert_eq!(check_valid(nested(10_000, "[", "]").as_bytes()), Ok(()));
                assert_eq!(
                    check_valid(nested(10_001, "[", "]").as_bytes()),
                    Err("invalid character '[' exceeded max depth".to_owned())
                );
                assert_eq!(
                    check_valid(nested(10_001, "{\"a\":", "}").as_bytes()),
                    Err("invalid character '{' exceeded max depth".to_owned())
                );
                // 9 998 arrays below the data object: valid JSON, far too deep
                // for the store, which refuses it (see the fixture replay).
                let document = format!("{{\"data\":{{\"k\":{}}}}}", nested(9_998, "[", "]"));
                let entry = decode_entry(&document).expect("decodes");
                assert!(entry.data.contains_key("k"));
                // The tree of a 9 999-level document is dropped without recursion.
                let tree = Builder {
                    data: nested(9_999, "[", "]").as_bytes(),
                    position: 0,
                }
                .node();
                drop(tree);
            })
            .expect("spawn")
            .join();
        assert!(outcome.is_ok());
    }

    #[test]
    fn scrub_overwrites_entry_plaintext() {
        // Strings are overwritten in place; objects are emptied key by key.
        let mut value: Value = serde_json::from_str(r#"["secret",["hunter2"],{"b":"x"}]"#).unwrap();
        scrub_value(&mut value);
        assert_eq!(value.to_string(), r#"["",[""],{}]"#);
    }

    #[test]
    fn type_errors_name_struct_field_and_type() {
        assert_eq!(
            decode_entry(r#"{"meta":{"version":1.5}}"#).unwrap_err(),
            "json: cannot unmarshal number 1.5 into Go struct field EntryMetadata.meta.version of type int"
        );
        assert_eq!(
            decode_entry("[]").unwrap_err(),
            "json: cannot unmarshal array into Go value of type vault.alias"
        );
    }
}
