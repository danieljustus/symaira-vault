//! `encoding/json` decoding semantics for the Bitwarden importer.
//!
//! Go decodes `json.NewDecoder(r).Decode(&export)` into typed structs, which
//! differs from serde in ways the importer contract exposes: JSON `null` is a
//! no-op, struct keys match case-insensitively (exact match first), duplicate
//! keys merge into the same value, slices reuse their existing elements, only
//! the first value of the stream is read, and the diagnostics have Go's exact
//! wording. This module reproduces that behavior: [`parse_document`] ports the
//! scanner (syntax errors and the max-depth rule) and [`GoDecode`] ports the
//! type-driven decode (first `UnmarshalTypeError` wins, with its struct/field
//! context).
//!
//! Like Go's `decodeState`, the decode walks the bytes the scanner already
//! validated: values under unknown keys and values whose type does not match
//! the target are skipped without recursion or allocation, and only values
//! bound to struct fields are materialised. No generic document tree exists.

use super::go_string_from_bytes;

/// Go's `maxNestingDepth`.
const MAX_NESTING_DEPTH: usize = 10_000;

/// The JSON kind of the next value; `name` is the word Go uses in
/// `UnmarshalTypeError` for non-number kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Null => "null",
            Kind::Bool => "bool",
            Kind::Number => "number",
            Kind::String => "string",
            Kind::Array => "array",
            Kind::Object => "object",
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner (port of encoding/json scanner.go + Decoder.readValue)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Parse {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

#[derive(Clone, Copy)]
enum Step {
    BeginValue,
    BeginValueOrEmpty,
    BeginStringOrEmpty,
    BeginString,
    InString,
    InStringEsc,
    InStringEscU(u8),
    Neg,
    Zero,
    Digits,
    Dot,
    DotDigits,
    Exp,
    ExpSign,
    ExpDigits,
    Literal(&'static str, usize),
    EndValue,
}

enum Fed {
    Continue,
    /// The byte ended the top-level value and belongs to it.
    DoneInclusive,
    /// The value ended before this byte.
    DoneExclusive,
    Error(String),
}

struct Scanner {
    step: Step,
    stack: Vec<Parse>,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// `strconv.Quote` of a single character, re-quoted with single quotes.
fn quote_char(c: u8) -> String {
    // Go converts the byte with `string(c)`, i.e. the Latin-1 code point.
    let ch = char::from(c);
    match ch {
        '\'' => "'\\''".into(),
        '"' => "'\"'".into(),
        '\\' => "'\\\\'".into(),
        '\x07' => "'\\a'".into(),
        '\x08' => "'\\b'".into(),
        '\x0c' => "'\\f'".into(),
        '\n' => "'\\n'".into(),
        '\r' => "'\\r'".into(),
        '\t' => "'\\t'".into(),
        '\x0b' => "'\\v'".into(),
        // Printable ASCII and the printable part of Latin-1.
        ' '..='~' | '\u{a1}'..='\u{ac}' | '\u{ae}'..='\u{ff}' => format!("'{ch}'"),
        // Control characters below 0x80 use \x; 0x80..=0xa0 and 0xad use \u.
        c if (c as u32) < 0x80 => format!("'\\x{:02x}'", c as u32),
        c => format!("'\\u{:04x}'", c as u32),
    }
}

impl Scanner {
    fn new() -> Self {
        Self {
            step: Step::BeginValue,
            stack: Vec::new(),
        }
    }

    fn error(c: u8, context: &str) -> Fed {
        Fed::Error(format!("invalid character {} {context}", quote_char(c)))
    }

    fn push(&mut self, c: u8, parse: Parse) -> Fed {
        self.stack.push(parse);
        if self.stack.len() <= MAX_NESTING_DEPTH {
            Fed::Continue
        } else {
            Self::error(c, "exceeded max depth")
        }
    }

    fn pop(&mut self) -> Fed {
        self.stack.pop();
        self.step = Step::EndValue;
        if self.stack.is_empty() {
            Fed::DoneInclusive
        } else {
            Fed::Continue
        }
    }

    fn feed(&mut self, c: u8) -> Fed {
        match self.step {
            Step::BeginValueOrEmpty => {
                if is_space(c) {
                    Fed::Continue
                } else if c == b']' {
                    self.end_value(c)
                } else {
                    self.begin_value(c)
                }
            }
            Step::BeginValue => self.begin_value(c),
            Step::BeginStringOrEmpty => {
                if is_space(c) {
                    Fed::Continue
                } else if c == b'}' {
                    if let Some(top) = self.stack.last_mut() {
                        *top = Parse::ObjectValue;
                    }
                    self.end_value(c)
                } else {
                    self.begin_string(c)
                }
            }
            Step::BeginString => self.begin_string(c),
            Step::InString => {
                match c {
                    b'"' => self.step = Step::EndValue,
                    b'\\' => self.step = Step::InStringEsc,
                    c if c < 0x20 => return Self::error(c, "in string literal"),
                    _ => {}
                }
                Fed::Continue
            }
            Step::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.step = Step::InString;
                    Fed::Continue
                }
                b'u' => {
                    self.step = Step::InStringEscU(0);
                    Fed::Continue
                }
                _ => Self::error(c, "in string escape code"),
            },
            Step::InStringEscU(seen) => {
                if c.is_ascii_hexdigit() {
                    self.step = if seen == 3 {
                        Step::InString
                    } else {
                        Step::InStringEscU(seen + 1)
                    };
                    Fed::Continue
                } else {
                    Self::error(c, "in \\u hexadecimal character escape")
                }
            }
            Step::Neg => match c {
                b'0' => {
                    self.step = Step::Zero;
                    Fed::Continue
                }
                b'1'..=b'9' => {
                    self.step = Step::Digits;
                    Fed::Continue
                }
                _ => Self::error(c, "in numeric literal"),
            },
            Step::Digits if c.is_ascii_digit() => Fed::Continue,
            Step::Digits | Step::Zero => match c {
                b'.' => {
                    self.step = Step::Dot;
                    Fed::Continue
                }
                b'e' | b'E' => {
                    self.step = Step::Exp;
                    Fed::Continue
                }
                _ => self.end_value(c),
            },
            Step::Dot => {
                if c.is_ascii_digit() {
                    self.step = Step::DotDigits;
                    Fed::Continue
                } else {
                    Self::error(c, "after decimal point in numeric literal")
                }
            }
            Step::DotDigits => match c {
                b'0'..=b'9' => Fed::Continue,
                b'e' | b'E' => {
                    self.step = Step::Exp;
                    Fed::Continue
                }
                _ => self.end_value(c),
            },
            Step::Exp => {
                if c == b'+' || c == b'-' {
                    self.step = Step::ExpSign;
                    Fed::Continue
                } else {
                    self.exp_sign(c)
                }
            }
            Step::ExpSign => self.exp_sign(c),
            Step::ExpDigits => {
                if c.is_ascii_digit() {
                    Fed::Continue
                } else {
                    self.end_value(c)
                }
            }
            Step::Literal(word, index) => {
                if word.as_bytes()[index] == c {
                    self.step = if index + 1 == word.len() {
                        Step::EndValue
                    } else {
                        Step::Literal(word, index + 1)
                    };
                    Fed::Continue
                } else {
                    Self::error(
                        c,
                        &format!(
                            "in literal {word} (expecting '{}')",
                            char::from(word.as_bytes()[index])
                        ),
                    )
                }
            }
            Step::EndValue => self.end_value(c),
        }
    }

    fn exp_sign(&mut self, c: u8) -> Fed {
        if c.is_ascii_digit() {
            self.step = Step::ExpDigits;
            Fed::Continue
        } else {
            Self::error(c, "in exponent of numeric literal")
        }
    }

    fn begin_value(&mut self, c: u8) -> Fed {
        if is_space(c) {
            return Fed::Continue;
        }
        match c {
            b'{' => {
                self.step = Step::BeginStringOrEmpty;
                self.push(c, Parse::ObjectKey)
            }
            b'[' => {
                self.step = Step::BeginValueOrEmpty;
                self.push(c, Parse::ArrayValue)
            }
            b'"' => {
                self.step = Step::InString;
                Fed::Continue
            }
            b'-' => {
                self.step = Step::Neg;
                Fed::Continue
            }
            b'0' => {
                self.step = Step::Zero;
                Fed::Continue
            }
            b'1'..=b'9' => {
                self.step = Step::Digits;
                Fed::Continue
            }
            b't' => {
                self.step = Step::Literal("true", 1);
                Fed::Continue
            }
            b'f' => {
                self.step = Step::Literal("false", 1);
                Fed::Continue
            }
            b'n' => {
                self.step = Step::Literal("null", 1);
                Fed::Continue
            }
            _ => Self::error(c, "looking for beginning of value"),
        }
    }

    fn begin_string(&mut self, c: u8) -> Fed {
        if is_space(c) {
            Fed::Continue
        } else if c == b'"' {
            self.step = Step::InString;
            Fed::Continue
        } else {
            Self::error(c, "looking for beginning of object key string")
        }
    }

    fn end_value(&mut self, c: u8) -> Fed {
        let Some(&top) = self.stack.last() else {
            return Fed::DoneExclusive;
        };
        if is_space(c) {
            self.step = Step::EndValue;
            return Fed::Continue;
        }
        let last = self.stack.len() - 1;
        match top {
            Parse::ObjectKey => {
                if c == b':' {
                    self.stack[last] = Parse::ObjectValue;
                    self.step = Step::BeginValue;
                    Fed::Continue
                } else {
                    Self::error(c, "after object key")
                }
            }
            Parse::ObjectValue => match c {
                b',' => {
                    self.stack[last] = Parse::ObjectKey;
                    self.step = Step::BeginString;
                    Fed::Continue
                }
                b'}' => self.pop(),
                _ => Self::error(c, "after object key:value pair"),
            },
            Parse::ArrayValue => match c {
                b',' => {
                    self.step = Step::BeginValue;
                    Fed::Continue
                }
                b']' => self.pop(),
                _ => Self::error(c, "after array element"),
            },
        }
    }
}

/// Validates the first JSON value of `bytes` exactly like
/// `json.NewDecoder(r).Decode`: leading whitespace is skipped, bytes after the
/// first value are never inspected, and the error text is Go's. The returned
/// reader walks only the validated value.
pub(super) fn parse_document(bytes: &[u8]) -> Result<Reader<'_>, String> {
    let mut scanner = Scanner::new();
    let mut end = None;
    for (index, &c) in bytes.iter().enumerate() {
        match scanner.feed(c) {
            Fed::Continue => {}
            Fed::DoneInclusive => {
                end = Some(index + 1);
                break;
            }
            Fed::DoneExclusive => {
                end = Some(index);
                break;
            }
            Fed::Error(message) => return Err(message),
        }
    }
    let end = match end {
        Some(end) => end,
        // End of input: a literal or number at the top level is complete if a
        // trailing space would end it.
        None => match scanner.feed(b' ') {
            Fed::DoneExclusive => bytes.len(),
            _ if bytes.iter().any(|&c| !is_space(c)) => return Err("unexpected EOF".into()),
            _ => return Err("EOF".into()),
        },
    };
    Ok(Reader {
        bytes: &bytes[..end],
        index: 0,
        key: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Reader over a value the scanner already validated
// ---------------------------------------------------------------------------

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    index: usize,
    /// Scratch buffer for object keys, reused so a key costs no allocation.
    key: String,
}

impl<'a> Reader<'a> {
    fn skip_space(&mut self) {
        while self.bytes.get(self.index).is_some_and(|&c| is_space(c)) {
            self.index += 1;
        }
    }

    /// The kind of the next value, without consuming it.
    fn kind(&mut self) -> Kind {
        self.skip_space();
        match self.bytes[self.index] {
            b'{' => Kind::Object,
            b'[' => Kind::Array,
            b'"' => Kind::String,
            b't' | b'f' => Kind::Bool,
            b'n' => Kind::Null,
            _ => Kind::Number,
        }
    }

    /// Consumes the next value without decoding it.
    fn skip_value(&mut self) {
        match self.kind() {
            Kind::Object | Kind::Array => self.skip_container(),
            Kind::String => self.skip_string(),
            Kind::Bool => self.index += if self.bytes[self.index] == b't' { 4 } else { 5 },
            Kind::Null => self.index += 4,
            Kind::Number => {
                self.number();
            }
        }
    }

    /// The literal of the next number, borrowed from the input.
    fn number(&mut self) -> &'a str {
        let start = self.index;
        while self
            .bytes
            .get(self.index)
            .is_some_and(|&c| matches!(c, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.index += 1;
        }
        // A top-level number may be followed by an ignored tail, but the
        // slice handed to the reader ends at the value.
        std::str::from_utf8(&self.bytes[start..self.index]).expect("number literals are ASCII")
    }

    fn skip_string(&mut self) {
        self.index += 1; // opening quote
        while self.bytes[self.index] != b'"' {
            if self.bytes[self.index] == b'\\' {
                self.index += 1;
            }
            self.index += 1;
        }
        self.index += 1;
    }

    /// Skips a validated container without recursion.
    fn skip_container(&mut self) {
        let mut depth = 0usize;
        while let Some(&c) = self.bytes.get(self.index) {
            match c {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        self.index += 1;
                        return;
                    }
                }
                b'"' => {
                    self.index += 1;
                    while self.bytes[self.index] != b'"' {
                        if self.bytes[self.index] == b'\\' {
                            self.index += 1;
                        }
                        self.index += 1;
                    }
                }
                _ => {}
            }
            self.index += 1;
        }
    }

    /// Go's `unquote`: escapes decoded, surrogate pairs joined, a lone
    /// surrogate and every invalid UTF-8 byte become U+FFFD.
    fn string(&mut self) -> String {
        let mut out = String::new();
        self.string_capped(&mut out, usize::MAX);
        out
    }

    /// Decodes the next string into `out`, but stops growing `out` once the
    /// decoded text would exceed `cap` bytes. Returns whether the whole string
    /// fit. Either way the string is consumed.
    fn string_capped(&mut self, out: &mut String, cap: usize) -> bool {
        self.index += 1; // opening quote
        let mut fits = true;
        let mut run_start = self.index;
        loop {
            match self.bytes[self.index] {
                b'"' => {
                    Self::push_run(out, &self.bytes[run_start..self.index], cap, &mut fits);
                    self.index += 1;
                    return fits;
                }
                b'\\' => {
                    Self::push_run(out, &self.bytes[run_start..self.index], cap, &mut fits);
                    self.index += 1;
                    let escape = self.bytes[self.index];
                    self.index += 1;
                    let decoded = match escape {
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let unit = self.hex4(self.index);
                            self.index += 4;
                            self.code_point(unit)
                        }
                        other => char::from(other),
                    };
                    if fits && out.len() + decoded.len_utf8() <= cap {
                        out.push(decoded);
                    } else {
                        fits = false;
                    }
                    run_start = self.index;
                }
                _ => self.index += 1,
            }
        }
    }

    /// Appends a raw run. Decoding never shrinks a run, so a run longer than
    /// the remaining room is rejected without converting it.
    fn push_run(out: &mut String, run: &[u8], cap: usize, fits: &mut bool) {
        if !*fits {
            return;
        }
        if run.len() > cap.saturating_sub(out.len()) {
            *fits = false;
            return;
        }
        out.push_str(&go_string_from_bytes(run));
        if out.len() > cap {
            *fits = false;
        }
    }

    /// Consumes an object key and returns the index of the field it selects
    /// (exact match first, then Go's case folding). A key too long to match
    /// any field is scanned but never buffered.
    fn key_index(&mut self, fields: &[&str]) -> Option<usize> {
        // Folded characters are ASCII, U+017F (2 bytes) or U+212A (3 bytes).
        let cap = 3 * fields.iter().map(|name| name.len()).max().unwrap_or(0);
        let mut key = std::mem::take(&mut self.key);
        key.clear();
        let found = if self.string_capped(&mut key, cap) {
            lookup(fields, &key)
        } else {
            None
        };
        self.key = key;
        found
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let digits = self.bytes.get(at..at + 4)?;
        digits
            .iter()
            .try_fold(0u32, |acc, &c| Some(acc * 16 + char::from(c).to_digit(16)?))
    }

    fn code_point(&mut self, unit: Option<u32>) -> char {
        let unit = unit.unwrap_or(0xFFFD);
        match unit {
            0xD800..=0xDBFF => {
                // A high surrogate joins only an immediately following \u low.
                if self.bytes.get(self.index) == Some(&b'\\')
                    && self.bytes.get(self.index + 1) == Some(&b'u')
                    && let Some(low @ 0xDC00..=0xDFFF) = self.hex4(self.index + 2)
                {
                    self.index += 6;
                    return char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
                        .unwrap_or('\u{FFFD}');
                }
                '\u{FFFD}'
            }
            0xDC00..=0xDFFF => '\u{FFFD}',
            other => char::from_u32(other).unwrap_or('\u{FFFD}'),
        }
    }
}

// ---------------------------------------------------------------------------
// Type-driven decode (port of decodeState semantics for the importer types)
// ---------------------------------------------------------------------------

/// Decode context mirroring `decodeState.errorContext` plus the first saved
/// error.
#[derive(Default)]
pub(super) struct Context {
    struct_name: &'static str,
    path: Vec<&'static str>,
    error: Option<String>,
}

impl Context {
    pub(super) fn into_error(self) -> Option<String> {
        self.error
    }

    /// Whether an error is already saved (later ones are dropped, so callers
    /// skip building their text).
    fn failed(&self) -> bool {
        self.error.is_some()
    }

    fn type_error(&mut self, value: &str, target: impl FnOnce() -> String) {
        if self.failed() {
            return;
        }
        let target = target();
        self.error = Some(if self.struct_name.is_empty() && self.path.is_empty() {
            format!("json: cannot unmarshal {value} into Go value of type {target}")
        } else {
            format!(
                "json: cannot unmarshal {value} into Go struct field {}.{} of type {target}",
                self.struct_name,
                self.path.join(".")
            )
        });
    }
}

pub(super) trait GoDecode {
    /// `reflect.Type.String()` of the Go target.
    fn go_type(&self) -> String;
    /// Decodes (and consumes) the next value of `reader` into `self`.
    fn decode(&mut self, reader: &mut Reader<'_>, context: &mut Context);
}

impl GoDecode for String {
    fn go_type(&self) -> String {
        "string".into()
    }

    fn decode(&mut self, reader: &mut Reader<'_>, context: &mut Context) {
        match reader.kind() {
            Kind::Null => reader.skip_value(),
            Kind::String => *self = reader.string(),
            other => {
                context.type_error(other.name(), || "string".into());
                reader.skip_value();
            }
        }
    }
}

impl GoDecode for i64 {
    fn go_type(&self) -> String {
        "int".into()
    }

    fn decode(&mut self, reader: &mut Reader<'_>, context: &mut Context) {
        match reader.kind() {
            Kind::Null => reader.skip_value(),
            Kind::Number => {
                let literal = reader.number();
                match literal.parse::<i64>() {
                    Ok(value) => *self = value,
                    Err(_) if context.failed() => {}
                    Err(_) => context.type_error(&format!("number {literal}"), || "int".into()),
                }
            }
            other => {
                context.type_error(other.name(), || "int".into());
                reader.skip_value();
            }
        }
    }
}

impl<T: GoDecode + Default> GoDecode for Vec<T> {
    fn go_type(&self) -> String {
        format!("[]{}", T::default().go_type())
    }

    fn decode(&mut self, reader: &mut Reader<'_>, context: &mut Context) {
        match reader.kind() {
            // `null` resets a slice to nil.
            Kind::Null => {
                reader.skip_value();
                self.clear();
            }
            Kind::Array => {
                reader.index += 1;
                // Go decodes into the existing elements first and only then
                // grows or truncates, so earlier duplicate keys leak through.
                //
                // Not reproduced on purpose: Go's `SetLen` shrink keeps the
                // backing array, so with three or more duplicate keys a later
                // longer array re-exposes stale elements that the earlier
                // truncation dropped (the capacity is reused, not zeroed).
                // Here truncation really drops them. That divergence needs a
                // key repeated 3+ times with shrinking then growing arrays,
                // which no real Bitwarden export produces.
                let mut count = 0usize;
                loop {
                    reader.skip_space();
                    match reader.bytes[reader.index] {
                        b']' => {
                            reader.index += 1;
                            break;
                        }
                        b',' => reader.index += 1,
                        _ => {
                            if count >= self.len() {
                                self.push(T::default());
                            }
                            self[count].decode(reader, context);
                            count += 1;
                        }
                    }
                }
                self.truncate(count);
            }
            other => {
                context.type_error(other.name(), || self.go_type());
                reader.skip_value();
            }
        }
    }
}

/// A Go struct with JSON-tagged fields.
pub(super) trait GoStruct: GoDecode {
    const NAME: &'static str;
    /// JSON key of each field, in index order. Field names are ASCII.
    const FIELDS: &'static [&'static str];
    fn field(&mut self, key: &str) -> &mut dyn GoDecode;
}

/// Implements [`GoDecode`] and [`GoStruct`] for a struct from its Go type name
/// and `"json key" => rust_field` table.
macro_rules! go_struct {
    ($ty:ident, $go:literal, { $($key:literal => $field:ident),+ $(,)? }) => {
        impl GoDecode for $ty {
            fn go_type(&self) -> String {
                concat!("importer.", $go).into()
            }

            fn decode(&mut self, reader: &mut Reader<'_>, context: &mut Context) {
                decode_struct(self, reader, context);
            }
        }

        impl GoStruct for $ty {
            const NAME: &'static str = $go;
            const FIELDS: &'static [&'static str] = &[$($key),+];

            fn field(&mut self, key: &str) -> &mut dyn GoDecode {
                match key {
                    $($key => &mut self.$field,)+
                    _ => unreachable!("lookup only returns declared fields"),
                }
            }
        }
    };
}
pub(super) use go_struct;

/// `foldName` for ASCII field names: the only non-ASCII runes whose simple
/// case folding lands on an ASCII letter are U+017F (S) and U+212A (K).
fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{17f}' => 'S',
            '\u{212a}' => 'K',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

/// Exact match first, then the case-folded one. The key is folded once; a
/// name of a different length is rejected before any character comparison.
fn lookup(fields: &[&str], key: &str) -> Option<usize> {
    fields.iter().position(|name| *name == key).or_else(|| {
        let folded = fold(key);
        // Names are ASCII, so equal folds are exactly ASCII-case-insensitive
        // equality with the folded key (non-ASCII folded chars never match).
        fields
            .iter()
            .position(|name| name.eq_ignore_ascii_case(&folded))
    })
}

pub(super) fn decode_struct<S: GoStruct>(
    value: &mut S,
    reader: &mut Reader<'_>,
    context: &mut Context,
) {
    debug_assert!(S::FIELDS.iter().all(|name| name.is_ascii()));
    match reader.kind() {
        Kind::Null => reader.skip_value(),
        Kind::Object => {
            reader.index += 1;
            loop {
                reader.skip_space();
                match reader.bytes[reader.index] {
                    b'}' => {
                        reader.index += 1;
                        return;
                    }
                    b',' => reader.index += 1,
                    _ => {
                        let selected = reader.key_index(S::FIELDS);
                        reader.skip_space();
                        reader.index += 1; // ':'
                        let Some(index) = selected else {
                            reader.skip_value();
                            continue;
                        };
                        let outer = context.struct_name;
                        context.struct_name = S::NAME;
                        context.path.push(S::FIELDS[index]);
                        value.field(S::FIELDS[index]).decode(reader, context);
                        context.path.pop();
                        context.struct_name = outer;
                    }
                }
            }
        }
        other => {
            context.type_error(other.name(), || value.go_type());
            reader.skip_value();
        }
    }
}

/// Runs a full `Decode`: the scanner, then the typed decode, returning the
/// first error with Go's wording.
pub(super) fn decode_document<S: GoStruct>(bytes: &[u8], target: &mut S) -> Result<(), String> {
    let mut reader = parse_document(bytes)?;
    let mut context = Context::default();
    target.decode(&mut reader, &mut context);
    context.into_error().map_or(Ok(()), Err)
}
