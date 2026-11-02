//! yaml.v3's typed-decode errors of `config.Config`, for `config set`.
//!
//! After writing the file, Go's `config set` reloads it with
//! `yaml.Unmarshal` into the typed `config.Config`; every field whose YAML
//! value cannot become the Go field type contributes one line of
//! `yaml: unmarshal errors:\n  line N: cannot unmarshal !!tag `value` into
//! <go type>`. This module builds a node tree of the rendered document
//! (tag, value, line and style as `parser.node` sets them) and walks it
//! against the field types of the Go structs (`config_schema.rs`, generated
//! from the Go source) with a port of `decode.go`:
//!
//! * a string field takes any scalar; a bool field takes `true`/`false` and the
//!   YAML 1.1 spellings `y/n/yes/no/on/off`; an int field takes an int or a
//!   float (truncated); a `time.Duration` takes only a string that
//!   `time.ParseDuration` accepts, so `12`, `1.5` and `true` are errors;
//! * `null` decodes to the zero value everywhere;
//! * a scalar for a struct, slice or map, and a collection for a scalar field,
//!   is an error naming the Go type (`[]string`, `config.VaultConfig`, ...);
//! * an alias decodes its anchored node (the error carries the line of the
//!   anchor); a `<<` merge key decodes its mapping, or each mapping of a
//!   sequence, after the mapping's own keys, which win;
//! * an explicit tag decides how a scalar resolves: `!!str 12` is the string
//!   `"12"` (so a Duration rejects it), `!!int 12` the int, and a scalar its
//!   tag cannot represent (`!!int abc`) aborts the whole decode;
//! * a `time.Time` field takes a mapping (whose keys it ignores), a plain
//!   timestamp, and any other scalar only when `time.Parse(RFC3339)` accepts
//!   it; otherwise the decode aborts with the `*time.ParseError` text;
//! * a value longer than ten bytes is cut to its first seven BYTES plus `...`,
//!   which can end inside a UTF-8 sequence, so errors are bytes, not strings.
//!
//! Known gaps (not probed against the oracle): an anchor redefined within one
//! document resolves every alias to its last definition, and an anchor that
//! is separated from its collection by a comment reports the line of the
//! collection instead of the anchor's.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use base64::Engine as _;
use symvault_gojson::resolve::{Resolved, resolve};
use symvault_gojson::rfc3339;
use yaml_edit::anchor_resolution::{AnchorRegistry, DocumentResolvedExt};
use yaml_edit::{ScalarStyle, ScalarValue, YamlNode};

use crate::config_schema::GO_CONFIG_STRUCTS;

/// What aborts a decode (`failf`/`fail` panic): the error text, no line list.
type Fatal = Vec<u8>;
type Res<T> = Result<T, Fatal>;

const MERGE_REQUIRES_MAP: &str = "yaml: map merge requires map or sequence of maps as the value";

/// The `yaml: unmarshal errors:` block yaml.v3 returns for `source`, or `None`
/// when every field decodes. A decode that aborts (`!!int abc`, an
/// unparsable `time.Time`, a merge of a non-mapping, ...) returns its own text
/// instead. Bytes, because the truncated value may split a multi-byte
/// character.
pub fn unmarshal_errors(source: &str) -> Option<Vec<u8>> {
    let (mut decoder, root) = Decoder::for_source(source)?;
    if let Err(fatal) = decoder.unmarshal(root, "Config") {
        return Some(fatal);
    }
    if decoder.terrors.is_empty() {
        return None;
    }
    let mut message = b"yaml: unmarshal errors:".to_vec();
    for error in decoder.terrors {
        message.extend_from_slice(b"\n  ");
        message.extend_from_slice(&error);
    }
    Some(message)
}

/// Mapping key under which [`coerced_document`] records the keys a mapping
/// wrote itself, as a sequence of strings.
///
/// Go's loader finds which fields an operator wrote by walking the node tree
/// (`loadSectionFields`, `loadAgentFields`, `loadTopLevelFields`): only keys
/// of a mapping reached without an alias or a `<<` merge on the way down count,
/// while the decoded values include everything a merge supplies. The tree
/// keeps both views. The bookkeeping key is a YAML `null`, which no decoded
/// entry can use: every entry the coercion inserts is keyed by a string, so no
/// operator key (a double-quoted `"\0own"` included) can collide with it.
pub fn own_keys_key() -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::Null
}

/// The document as yaml.v3's typed decode of `config.Config` leaves it, for
/// the loader's per-section merge.
///
/// This is the one place the Go coercions live, so the section parsers read
/// values exactly as Go's merge sees them instead of repeating the rules:
///
/// * a string field holds the scalar's source text (`12`, `0x10`, `true`,
///   `1.5` and `1e3` stay as written; a quoted scalar is its unescaped text);
/// * a bool field holds the decoded boolean (`yes`/`on`/`y` and their
///   inverses included), an int field the int (a float is truncated, `017`
///   is octal, `1_000` drops its underscores), a `time.Duration` its
///   nanoseconds (negative ones too);
/// * `null` is `Null` wherever it appears; a `[]string` drops a null item the
///   way yaml.v3 does (a `string` cannot hold it);
/// * struct fields the Go type does not name are dropped; keys of a `<<`
///   merge fill in what the mapping did not write itself, the earliest
///   operand first, as `mergedFields` does;
/// * every struct and map mapping reached directly carries [`own_keys_key`].
///
/// Only call this for a document [`unmarshal_errors`] accepted.
pub fn coerced_document(source: &str) -> Option<serde_yaml_ng::Value> {
    let (mut decoder, root) = Decoder::for_source(source)?;
    decoder.coerce(root, "Config", true)
}

/// yaml.v3 gives a plain `<<` scalar the tag `!!merge`, and its encoder keeps
/// a tag the plain text would not resolve to (`<<` resolves to `!!str`), so
/// `config set` writes every plain `<<` back as `!!merge <<`: keys and values,
/// at any depth. A quoted `'<<'` or an explicitly tagged one is left alone.
pub fn tag_merge_keys(rendered: &str) -> String {
    fn collect(node: &YamlNode, starts: &mut Vec<usize>) {
        match node {
            YamlNode::Scalar(scalar) => {
                if scalar.as_string() == "<<"
                    && ScalarValue::from_scalar(scalar).style() == ScalarStyle::Plain
                {
                    starts.push(node.byte_range().start as usize);
                }
            }
            YamlNode::Mapping(mapping) => {
                for (key, value) in mapping.iter() {
                    collect(&key, starts);
                    collect(&value, starts);
                }
            }
            YamlNode::Sequence(sequence) => {
                for item in sequence.values() {
                    collect(&item, starts);
                }
            }
            YamlNode::TaggedNode(tagged) => {
                if let Some(mapping) = tagged.as_mapping() {
                    collect(&YamlNode::Mapping(mapping), starts);
                } else if let Some(sequence) = tagged.as_sequence() {
                    collect(&YamlNode::Sequence(sequence), starts);
                }
            }
            YamlNode::Alias(_) => {}
        }
    }
    let Some(document) = yaml_edit::YamlFile::from_str(rendered)
        .ok()
        .and_then(|file| file.documents().next())
    else {
        return rendered.to_owned();
    };
    let root = if let Some(mapping) = document.as_mapping() {
        YamlNode::Mapping(mapping)
    } else if let Some(sequence) = document.as_sequence() {
        YamlNode::Sequence(sequence)
    } else {
        return rendered.to_owned();
    };
    let mut starts = Vec::new();
    collect(&root, &mut starts);
    let mut out = rendered.to_owned();
    for start in starts.into_iter().rev() {
        if out.is_char_boundary(start) {
            out.insert_str(start, "!!merge ");
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Scalar,
    Mapping,
    Sequence,
    Alias,
}

/// `yaml.Node` as `parser.node` fills it.
struct Node {
    kind: Kind,
    /// `Node.Tag` in its short form: the explicit tag, else the default of the
    /// kind (`!!map`, `!!seq`, `!!str` for a quoted scalar, `!!merge` for a
    /// plain `<<`) or what `resolve` makes of a plain scalar.
    tag: String,
    /// The scalar text, or the anchor name of an alias.
    value: String,
    /// `Node.indicatedString()`.
    indicated_string: bool,
    line: usize,
    /// Key, value, key, value... of a mapping; the items of a sequence.
    children: Vec<usize>,
}

/// A scalar after `d.scalar` resolved it.
enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Time,
    Str(String),
}

/// A key as `d.unmarshal(key, interface{})` stores it in `mergedFields`.
#[derive(PartialEq, Eq, Hash)]
enum Key {
    Str(String),
    Other(String),
}

struct Decoder<'a> {
    source: &'a str,
    newlines: Vec<usize>,
    /// Offset of the first `#` on each line (`usize::MAX` if none), so the
    /// comment check in `line` costs O(log n) instead of a rescan.
    first_hash: Vec<usize>,
    /// `token_start[i]`: where the whitespace-free run ending at `i` begins,
    /// so `line` finds a token in O(1) on long flow lines.
    token_start: Vec<usize>,
    registry: AnchorRegistry,
    nodes: Vec<Node>,
    by_range: HashMap<(usize, usize), usize>,
    terrors: Vec<Vec<u8>>,
    /// `d.aliases`: the aliases being decoded, to catch an anchor that
    /// contains itself.
    aliases: Vec<usize>,
    merged_fields: Option<HashSet<Key>>,
    decode_count: usize,
    alias_count: usize,
    alias_depth: usize,
}

fn struct_fields(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    GO_CONFIG_STRUCTS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, fields)| *fields)
}

/// `reflect.Type.String()` of a field type: struct names live in package
/// `config`, `time.Duration` and `time.Time` already carry their package.
fn display_type(go_type: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            if struct_fields(word).is_some() {
                out.push_str("config.");
            }
            out.push_str(word);
            word.clear();
        }
    };
    for character in go_type.chars() {
        if character.is_alphanumeric() || character == '_' {
            word.push(character);
        } else if character == '.' {
            // `time.Duration`: the package qualifier stays, the name is not a config struct.
            out.push_str(&word);
            out.push('.');
            word.clear();
        } else {
            flush(&mut word, &mut out);
            out.push(character);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// `shortTag`: the `tag:yaml.org,2002:` namespace spelled `!!`.
fn short_tag(tag: &str) -> String {
    let inner = tag
        .strip_prefix("!<")
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or(tag);
    match inner.strip_prefix("tag:yaml.org,2002:") {
        Some(rest) => format!("!!{rest}"),
        None => inner.to_owned(),
    }
}

/// `allowedAliasRatio`.
fn allowed_alias_ratio(decode_count: usize) -> f64 {
    const LOW: usize = 400_000;
    const HIGH: usize = 4_000_000;
    if decode_count <= LOW {
        0.99
    } else if decode_count >= HIGH {
        0.10
    } else {
        0.99 - 0.89 * ((decode_count - LOW) as f64 / (HIGH - LOW) as f64)
    }
}

fn is_white(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Entry `i` (for `i` in `0..=len`) is the start of the whitespace-free run
/// that ends at `i`; it equals `i` right after whitespace or at the start.
fn token_starts(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut starts = Vec::with_capacity(bytes.len() + 1);
    starts.push(0);
    for (index, byte) in bytes.iter().enumerate() {
        let previous = starts[index];
        starts.push(if is_white(*byte) { index + 1 } else { previous });
    }
    starts
}

fn first_hash_per_line(source: &str) -> Vec<usize> {
    let mut lines = vec![usize::MAX];
    for (index, byte) in source.bytes().enumerate() {
        match byte {
            b'\n' => lines.push(usize::MAX),
            b'#' => {
                let last = lines.last_mut().expect("one entry per line");
                *last = (*last).min(index);
            }
            _ => {}
        }
    }
    lines
}

/// An explicit tag other than the non-specific `!` replaces the default.
fn explicit(tag: Option<String>) -> Option<String> {
    tag.filter(|tag| !tag.is_empty() && tag != "!")
}

impl<'a> Decoder<'a> {
    fn new(source: &'a str, registry: AnchorRegistry) -> Self {
        Self {
            source,
            newlines: source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index))
                .collect(),
            first_hash: first_hash_per_line(source),
            token_start: token_starts(source),
            registry,
            nodes: Vec::new(),
            by_range: HashMap::new(),
            terrors: Vec::new(),
            aliases: Vec::new(),
            merged_fields: None,
            decode_count: 0,
            alias_count: 0,
            alias_depth: 0,
        }
    }

    /// The decoder over the first document of `source`, and its root node.
    fn for_source(source: &str) -> Option<(Decoder<'_>, usize)> {
        // Go reads the first document and never looks at a later one that
        // does not decode, so a syntax error further down must not hide the
        // first document: take the (possibly partial) tree.
        let file = yaml_edit::YamlFile::parse(source).tree();
        let document = file.documents().next()?;
        let root = if let Some(mapping) = document.as_mapping() {
            YamlNode::Mapping(mapping)
        } else if let Some(sequence) = document.as_sequence() {
            YamlNode::Sequence(sequence)
        } else if let Some(tagged) = document.as_tagged() {
            YamlNode::TaggedNode(tagged)
        } else {
            YamlNode::Scalar(document.as_scalar()?)
        };
        let mut decoder = Decoder::new(source, document.build_anchor_registry());
        let root = decoder.build(&root, false);
        Some((decoder, root))
    }

    /// yaml.v3's `Node.Line` (1-based): the event starts at the first of the
    /// node's anchor and tag, which `yaml_edit`'s ranges leave out when the
    /// anchor sits on an earlier line.
    ///
    /// A key of a block mapping never takes an anchor or tag from an earlier
    /// line: there it belongs to the mapping itself (`a: &d` then the keys).
    fn line(&self, start: usize, block_key: bool) -> usize {
        let bytes = self.source.as_bytes();
        let mut at = start.min(bytes.len());
        loop {
            let mut end = at;
            while end > 0 && is_white(bytes[end - 1]) {
                end -= 1;
            }
            let begin = self.token_start[end];
            let token = &bytes[begin..end];
            if !(token.len() > 1 && matches!(token[0], b'&' | b'!')) {
                break;
            }
            let line = self.newlines.partition_point(|position| *position < begin);
            if self.first_hash[line] < begin || (block_key && bytes[end..at].contains(&b'\n')) {
                break;
            }
            at = begin;
        }
        1 + self.newlines.partition_point(|position| *position < at)
    }

    fn push(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn build(&mut self, node: &YamlNode, block_key: bool) -> usize {
        let range = node.byte_range();
        let (start, end) = (range.start as usize, range.end as usize);
        let line = self.line(start, block_key);
        let id = match node {
            YamlNode::Scalar(scalar) => self.build_scalar(scalar, None, line),
            YamlNode::Alias(alias) => self.push(Node {
                kind: Kind::Alias,
                tag: String::new(),
                value: alias.name(),
                indicated_string: false,
                line,
                children: Vec::new(),
            }),
            YamlNode::Mapping(mapping) => self.build_mapping(mapping, None, line),
            YamlNode::Sequence(sequence) => self.build_sequence(sequence, None, line),
            YamlNode::TaggedNode(tagged) => {
                let tag = short_tag(&tagged.tag().unwrap_or_default());
                if let Some(scalar) = tagged.value() {
                    self.build_scalar(&scalar, Some(tag), line)
                } else if let Some(mapping) = tagged.as_mapping() {
                    self.build_mapping(&mapping, Some(tag), line)
                } else if let Some(sequence) = tagged.as_sequence() {
                    self.build_sequence(&sequence, Some(tag), line)
                } else {
                    self.push(Node {
                        kind: Kind::Scalar,
                        tag,
                        value: String::new(),
                        indicated_string: false,
                        line,
                        children: Vec::new(),
                    })
                }
            }
        };
        self.by_range.insert((start, end), id);
        id
    }

    fn build_scalar(
        &mut self,
        scalar: &yaml_edit::Scalar,
        tag: Option<String>,
        line: usize,
    ) -> usize {
        let value = scalar.as_string();
        let plain = ScalarValue::from_scalar(scalar).style() == ScalarStyle::Plain;
        let (tag, indicated_string) = match explicit(tag) {
            Some(tag) => {
                let indicated = tag == "!!str";
                (tag, indicated)
            }
            None if !plain => ("!!str".to_owned(), true),
            None if value == "<<" => ("!!merge".to_owned(), false),
            None => (resolve(&value).tag().to_owned(), false),
        };
        self.push(Node {
            kind: Kind::Scalar,
            tag,
            value,
            indicated_string,
            line,
            children: Vec::new(),
        })
    }

    fn build_mapping(
        &mut self,
        mapping: &yaml_edit::Mapping,
        tag: Option<String>,
        line: usize,
    ) -> usize {
        let mut children = Vec::new();
        let range = mapping.byte_range();
        let block = self.source.as_bytes().get(range.start as usize) != Some(&b'{');
        for (key, value) in mapping.iter() {
            children.push(self.build(&key, block));
            children.push(self.build(&value, false));
        }
        self.push(Node {
            kind: Kind::Mapping,
            tag: explicit(tag).unwrap_or_else(|| "!!map".to_owned()),
            value: String::new(),
            indicated_string: false,
            line,
            children,
        })
    }

    fn build_sequence(
        &mut self,
        sequence: &yaml_edit::Sequence,
        tag: Option<String>,
        line: usize,
    ) -> usize {
        let mut children = Vec::new();
        for item in sequence.values() {
            children.push(self.build(&item, false));
        }
        self.push(Node {
            kind: Kind::Sequence,
            tag: explicit(tag).unwrap_or_else(|| "!!seq".to_owned()),
            value: String::new(),
            indicated_string: false,
            line,
            children,
        })
    }

    /// The node an alias refers to (`Node.Alias`).
    fn alias_target(&self, alias: usize) -> Option<usize> {
        let node = self.registry.resolve(&self.nodes[alias].value)?;
        let range = node.text_range();
        self.by_range
            .get(&(usize::from(range.start()), usize::from(range.end())))
            .copied()
    }

    /// Follows aliases to the node they end at.
    fn target_of(&self, mut id: usize) -> Option<usize> {
        for _ in 0..64 {
            if self.nodes[id].kind != Kind::Alias {
                return Some(id);
            }
            id = self.alias_target(id)?;
        }
        None
    }

    /// The kind of a merge operand, looking through an alias.
    fn operand_kind(&self, id: usize) -> Option<Kind> {
        self.target_of(id).map(|target| self.nodes[target].kind)
    }

    /// `Node.ShortTag`.
    fn short_tag_of(&self, id: usize) -> &str {
        let node = &self.nodes[id];
        if node.indicated_string {
            "!!str"
        } else {
            &node.tag
        }
    }

    /// `isMerge`.
    fn is_merge(&self, id: usize) -> bool {
        let node = &self.nodes[id];
        node.kind == Kind::Scalar && node.value == "<<" && node.tag == "!!merge"
    }

    fn terror(&mut self, id: usize, go_type: &str) {
        let node = &self.nodes[id];
        let tag = &node.tag;
        let mut line = format!("line {}: cannot unmarshal {tag}", node.line).into_bytes();
        if tag != "!!seq" && tag != "!!map" {
            line.extend_from_slice(b" `");
            if node.value.len() > 10 {
                // Go: value[:7] on bytes.
                line.extend_from_slice(&node.value.as_bytes()[..7]);
                line.extend_from_slice(b"...");
            } else {
                line.extend_from_slice(node.value.as_bytes());
            }
            line.push(b'`');
        }
        line.extend_from_slice(format!(" into {}", display_type(go_type)).as_bytes());
        self.terrors.push(line);
    }

    fn unmarshal(&mut self, id: usize, go_type: &str) -> Res<bool> {
        self.decode_count += 1;
        if self.alias_depth > 0 {
            self.alias_count += 1;
        }
        if self.alias_count > 100
            && self.decode_count > 1000
            && self.alias_count as f64 / self.decode_count as f64
                > allowed_alias_ratio(self.decode_count)
        {
            return Err(b"yaml: document contains excessive aliasing".to_vec());
        }
        if self.nodes[id].kind == Kind::Alias {
            return self.alias(id, go_type);
        }
        // `d.prepare`: a null node is left alone, anything else dereferences.
        let go_type = if self.short_tag_of(id) == "!!null" {
            go_type
        } else {
            go_type.trim_start_matches('*')
        };
        match self.nodes[id].kind {
            Kind::Scalar => self.scalar(id, go_type),
            Kind::Mapping => self.mapping(id, go_type),
            Kind::Sequence => self.sequence(id, go_type),
            Kind::Alias => Ok(false),
        }
    }

    fn alias(&mut self, id: usize, go_type: &str) -> Res<bool> {
        if self.aliases.contains(&id) {
            return Err(format!(
                "yaml: anchor '{}' value contains itself",
                self.nodes[id].value
            )
            .into_bytes());
        }
        self.aliases.push(id);
        self.alias_depth += 1;
        let good = match self.alias_target(id) {
            Some(target) => self.unmarshal(target, go_type),
            None => Ok(false),
        };
        self.alias_depth -= 1;
        self.aliases.pop();
        good
    }

    /// `d.null`: only a pointer, map or slice takes the zero value.
    fn null(go_type: &str) -> bool {
        go_type.starts_with('*') || go_type.starts_with("[]") || go_type.starts_with("map[")
    }

    /// `resolve(tag, in)` of `resolve.go`, with the `defer` that rejects a
    /// scalar the explicit tag cannot represent.
    fn resolve_tagged(tag: &str, input: &str) -> Res<(String, Val)> {
        if !matches!(
            tag,
            "" | "!!str" | "!!bool" | "!!int" | "!!float" | "!!null" | "!!timestamp"
        ) {
            return Ok((tag.to_owned(), Val::Str(input.to_owned())));
        }
        let mut resolved = if tag == "!!str" {
            Resolved::Str
        } else {
            resolve(input)
        };
        // Only an untagged or `!!timestamp` scalar is tried as a timestamp.
        if matches!(resolved, Resolved::Timestamp) && !matches!(tag, "" | "!!timestamp") {
            resolved = Resolved::Str;
        }
        let rtag = resolved.tag();
        let value = match resolved {
            Resolved::Null => Val::Null,
            Resolved::Bool(flag) => Val::Bool(flag),
            Resolved::Int(value) => Val::Int(value),
            Resolved::Uint(value) => Val::Uint(value),
            Resolved::Float(value) => Val::Float(value),
            Resolved::Timestamp => Val::Time,
            Resolved::Str => Val::Str(input.to_owned()),
        };
        if tag.is_empty() || tag == rtag || tag == "!!str" {
            return Ok((rtag.to_owned(), value));
        }
        if tag == "!!float" {
            match value {
                Val::Int(number) => return Ok((tag.to_owned(), Val::Float(number as f64))),
                Val::Uint(number) => return Ok((tag.to_owned(), Val::Float(number as f64))),
                _ => {}
            }
        }
        Err(format!("yaml: cannot decode {rtag} `{input}` as a {tag}").into_bytes())
    }

    /// The decoded bytes of a `!!binary` scalar (Go's `StdEncoding` ignores
    /// line breaks and accepts non-zero trailing bits).
    fn binary_text(input: &str) -> Res<String> {
        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        );
        let compact: String = input
            .chars()
            .filter(|character| !matches!(character, '\r' | '\n'))
            .collect();
        engine
            .decode(compact)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .map_err(|_| b"yaml: !!binary value contains invalid base64 data".to_vec())
    }

    /// The tag and value `d.scalar` computes for a scalar node.
    fn scalar_value(&self, id: usize) -> Res<(String, Val)> {
        let node = &self.nodes[id];
        if node.indicated_string {
            return Ok(("!!str".to_owned(), Val::Str(node.value.clone())));
        }
        let (tag, value) = Self::resolve_tagged(&node.tag, &node.value)?;
        if tag == "!!binary" {
            return Ok((tag, Val::Str(Self::binary_text(&node.value)?)));
        }
        Ok((tag, value))
    }

    fn scalar(&mut self, id: usize, go_type: &str) -> Res<bool> {
        let (tag, value) = self.scalar_value(id)?;
        if matches!(value, Val::Null) {
            return Ok(Self::null(go_type));
        }
        // The resolved value already has the field's type.
        if matches!(
            (go_type, &value),
            ("string", Val::Str(_))
                | ("bool", Val::Bool(_))
                | ("int", Val::Int(_))
                | ("time.Time", Val::Time)
        ) {
            return Ok(true);
        }
        if go_type == "time.Time" {
            // `encoding.TextUnmarshaler` takes the node's own text.
            let text = match (tag.as_str(), &value) {
                ("!!binary", Val::Str(decoded)) => decoded.clone(),
                _ => self.nodes[id].value.clone(),
            };
            return match rfc3339::parse_error(&text) {
                Some(message) => Err(message.into_bytes()),
                None => Ok(true),
            };
        }
        let accepted = match go_type {
            "string" => true,
            "bool" => match &value {
                Val::Bool(_) => true,
                Val::Str(word) => matches!(
                    word.as_str(),
                    "y" | "Y"
                        | "yes"
                        | "Yes"
                        | "YES"
                        | "on"
                        | "On"
                        | "ON"
                        | "n"
                        | "N"
                        | "no"
                        | "No"
                        | "NO"
                        | "off"
                        | "Off"
                        | "OFF"
                ),
                _ => false,
            },
            "int" | "int64" => match &value {
                Val::Int(_) => true,
                Val::Uint(number) => *number <= i64::MAX as u64,
                // A float is truncated unless it exceeds int64 (NaN compares false).
                Val::Float(number) => *number <= 9.223_372_036_854_776e18,
                _ => false,
            },
            "time.Duration" => match &value {
                Val::Str(text) => crate::config::parse_go_duration(text).is_ok(),
                _ => false,
            },
            // A Go type this table does not model decodes any scalar.
            _ => {
                !(go_type.starts_with("[]")
                    || go_type.starts_with("map[")
                    || struct_fields(go_type).is_some())
            }
        };
        if !accepted {
            self.terror(id, go_type);
        }
        Ok(accepted)
    }

    fn sequence(&mut self, id: usize, go_type: &str) -> Res<bool> {
        let Some(element) = go_type.strip_prefix("[]") else {
            self.terror(id, go_type);
            return Ok(false);
        };
        for item in self.nodes[id].children.clone() {
            self.unmarshal(item, element)?;
        }
        Ok(true)
    }

    fn mapping(&mut self, id: usize, go_type: &str) -> Res<bool> {
        // `uniqueKeys`: two keys of the same kind and text.
        let before = self.terrors.len();
        let children = self.nodes[id].children.clone();
        for i in (0..children.len()).step_by(2) {
            for j in ((i + 2)..children.len()).step_by(2) {
                let (first, second) = (&self.nodes[children[i]], &self.nodes[children[j]]);
                if first.kind == second.kind && first.value == second.value {
                    let message = format!(
                        "line {}: mapping key {} already defined at line {}",
                        second.line,
                        crate::go_quote(&second.value),
                        first.line
                    );
                    self.terrors.push(message.into_bytes());
                }
            }
        }
        if self.terrors.len() > before {
            return Ok(false);
        }
        if let Some(fields) = struct_fields(go_type) {
            return self.mapping_struct(id, go_type, fields);
        }
        if go_type == "time.Time" {
            // A struct without exported fields: every key is ignored.
            return self.mapping_struct(id, go_type, &[]);
        }
        let Some(element) = go_type.strip_prefix("map[string]") else {
            self.terror(id, go_type);
            return Ok(false);
        };
        let mut merged_fields = self.merged_fields.take();
        let mut merge_node = None;
        for pair in children.chunks(2) {
            let (key, value) = (pair[0], pair[1]);
            if self.is_merge(key) {
                merge_node = Some(value);
                continue;
            }
            let Some(name) = self.string_key(key)? else {
                continue;
            };
            if let Some(seen) = merged_fields.as_mut()
                && !seen.insert(Key::Str(name))
            {
                continue;
            }
            self.unmarshal(value, element)?;
        }
        self.merged_fields = merged_fields;
        if let Some(merge) = merge_node {
            self.merge(id, merge, go_type)?;
        }
        Ok(true)
    }

    fn mapping_struct(
        &mut self,
        id: usize,
        go_type: &str,
        fields: &'static [(&'static str, &'static str)],
    ) -> Res<bool> {
        let mut merged_fields = self.merged_fields.take();
        let mut merge_node = None;
        let mut done = HashSet::new();
        let children = self.nodes[id].children.clone();
        for pair in children.chunks(2) {
            let (key, value) = (pair[0], pair[1]);
            if self.is_merge(key) {
                merge_node = Some(value);
                continue;
            }
            let Some(name) = self.string_key(key)? else {
                continue;
            };
            if let Some(seen) = merged_fields.as_mut()
                && !seen.insert(Key::Str(name.clone()))
            {
                continue;
            }
            if let Some(position) = fields.iter().position(|(field, _)| *field == name) {
                if !done.insert(position) {
                    let line = self.nodes[key].line;
                    self.terrors.push(
                        format!(
                            "line {line}: field {name} already set in type {}",
                            display_type(go_type)
                        )
                        .into_bytes(),
                    );
                    continue;
                }
                self.unmarshal(value, fields[position].1)?;
            }
        }
        self.merged_fields = merged_fields;
        if let Some(merge) = merge_node {
            self.merge(id, merge, go_type)?;
        }
        Ok(true)
    }

    /// `d.unmarshal(key, name)` into a `string`: the key text when it decoded.
    fn string_key(&mut self, key: usize) -> Res<Option<String>> {
        if !self.unmarshal(key, "string")? {
            return Ok(None);
        }
        let Some(target) = self.target_of(key) else {
            return Ok(None);
        };
        if self.nodes[target].kind != Kind::Scalar {
            return Ok(None);
        }
        Ok(match self.scalar_value(target)? {
            (_, Val::Str(text)) => Some(text),
            _ => Some(self.nodes[target].value.clone()),
        })
    }

    /// `d.unmarshal(key, interface{})` for a key of the parent mapping; only
    /// scalar keys are modelled.
    fn interface_key(&self, key: usize) -> Res<Option<Key>> {
        let Some(target) = self.target_of(key) else {
            return Ok(None);
        };
        if self.nodes[target].kind != Kind::Scalar {
            return Ok(None);
        }
        let (tag, value) = self.scalar_value(target)?;
        Ok(Some(match value {
            Val::Str(text) => Key::Str(text),
            _ => Key::Other(format!("{tag}\u{0}{}", self.nodes[target].value)),
        }))
    }

    /// `d.merge`: decode the merged mapping(s) into the same value, skipping
    /// the keys the parent mapping (or an earlier merge) already set.
    fn merge(&mut self, parent: usize, merge: usize, go_type: &str) -> Res<()> {
        let outer = self.merged_fields.take();
        let had_outer = outer.is_some();
        let seen = match outer {
            Some(seen) => seen,
            None => {
                let mut seen = HashSet::new();
                for pair in self.nodes[parent].children.chunks(2) {
                    if let Some(key) = self.interface_key(pair[0])? {
                        seen.insert(key);
                    }
                }
                seen
            }
        };
        self.merged_fields = Some(seen);
        let result = self.merge_operands(merge, go_type);
        let after = self.merged_fields.take();
        self.merged_fields = if had_outer { after } else { None };
        result
    }

    fn merge_operands(&mut self, merge: usize, go_type: &str) -> Res<()> {
        let fail = || Err(MERGE_REQUIRES_MAP.as_bytes().to_vec());
        match self.nodes[merge].kind {
            Kind::Mapping => {
                self.unmarshal(merge, go_type)?;
            }
            Kind::Alias => {
                if self
                    .operand_kind(merge)
                    .is_some_and(|kind| kind != Kind::Mapping)
                {
                    return fail();
                }
                self.unmarshal(merge, go_type)?;
            }
            Kind::Sequence => {
                for item in self.nodes[merge].children.clone() {
                    let kind = self.nodes[item].kind;
                    let wrong = match kind {
                        Kind::Alias => self
                            .operand_kind(item)
                            .is_some_and(|target| target != Kind::Mapping),
                        other => other != Kind::Mapping,
                    };
                    if wrong {
                        return fail();
                    }
                    self.unmarshal(item, go_type)?;
                }
            }
            Kind::Scalar => return fail(),
        }
        Ok(())
    }
    /// The text of a mapping key as `d.unmarshal(key, string)` stores it, or
    /// `None` for a key that does not decode into a string.
    fn key_text(&self, key: usize) -> Option<String> {
        let target = self.target_of(key)?;
        if self.nodes[target].kind != Kind::Scalar {
            return None;
        }
        match self.scalar_value(target).ok()? {
            (_, Val::Null) => None,
            (_, Val::Str(text)) => Some(text),
            _ => Some(self.nodes[target].value.clone()),
        }
    }

    /// The value of node `id` decoded into Go type `go_type`, or `None` when
    /// yaml.v3 would leave the target untouched (a node of the wrong shape).
    /// `direct` says the node is reached through plain mappings and sequences
    /// only, which is what makes its keys count as written by the operator.
    fn coerce(&mut self, id: usize, go_type: &str, direct: bool) -> Option<serde_yaml_ng::Value> {
        use serde_yaml_ng::Value;
        if self.nodes[id].kind == Kind::Alias {
            if self.aliases.contains(&id) {
                return None;
            }
            self.aliases.push(id);
            let target = self.alias_target(id);
            let value = target.and_then(|target| self.coerce(target, go_type, false));
            self.aliases.pop();
            return value;
        }
        let go_type = go_type.trim_start_matches('*');
        match self.nodes[id].kind {
            Kind::Scalar => self.coerce_scalar(id, go_type),
            Kind::Sequence => {
                let element = go_type.strip_prefix("[]")?;
                let mut items = Vec::new();
                for item in self.nodes[id].children.clone() {
                    match self.coerce(item, element, direct) {
                        Some(Value::Null) if !Self::null(element) => {}
                        Some(value) => items.push(value),
                        None => {}
                    }
                }
                Some(Value::Sequence(items))
            }
            Kind::Mapping => {
                let mut out = serde_yaml_ng::Mapping::new();
                let mut seen = HashSet::new();
                let mut own = Vec::new();
                self.coerce_mapping(id, go_type, direct, &mut seen, &mut out, &mut own)?;
                if direct {
                    out.insert(
                        own_keys_key(),
                        Value::Sequence(own.into_iter().map(Value::String).collect()),
                    );
                }
                Some(Value::Mapping(out))
            }
            Kind::Alias => None,
        }
    }

    fn coerce_scalar(&self, id: usize, go_type: &str) -> Option<serde_yaml_ng::Value> {
        use serde_yaml_ng::Value;
        let (_, value) = self.scalar_value(id).ok()?;
        let text = match &value {
            Val::Str(text) => text.clone(),
            _ => self.nodes[id].value.clone(),
        };
        Some(match (go_type, value) {
            (_, Val::Null) => Value::Null,
            ("bool", Val::Bool(flag)) => Value::Bool(flag),
            ("bool", Val::Str(word)) => Value::Bool(matches!(
                word.as_str(),
                "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON"
            )),
            ("int" | "int64", Val::Int(number)) => Value::Number(number.into()),
            ("int" | "int64", Val::Uint(number)) => {
                Value::Number(i64::try_from(number).ok()?.into())
            }
            ("int" | "int64", Val::Float(number)) => Value::Number((number as i64).into()),
            ("time.Duration", Val::Str(word)) => {
                Value::Number(crate::config::parse_go_duration(&word).ok()?.into())
            }
            ("bool" | "int" | "int64" | "time.Duration", _) => return None,
            _ => Value::String(text),
        })
    }

    /// `mappingStruct` / `mapping` into a struct or a `map[string]T`: the
    /// node's own keys first, then the `<<` operands, none of which may
    /// replace a key that is already in `seen`.
    fn coerce_mapping(
        &mut self,
        id: usize,
        go_type: &str,
        direct: bool,
        seen: &mut HashSet<String>,
        out: &mut serde_yaml_ng::Mapping,
        own: &mut Vec<String>,
    ) -> Option<()> {
        enum Shape {
            Struct(&'static [(&'static str, &'static str)]),
            Map(String),
            Time,
        }
        let shape = if let Some(fields) = struct_fields(go_type) {
            Shape::Struct(fields)
        } else if go_type == "time.Time" {
            Shape::Time
        } else {
            Shape::Map(go_type.strip_prefix("map[string]")?.to_owned())
        };
        let mut merge_node = None;
        for pair in self.nodes[id].children.clone().chunks(2) {
            let (key, value) = (pair[0], pair[1]);
            if self.is_merge(key) {
                merge_node = Some(value);
                continue;
            }
            if direct {
                own.push(self.nodes[key].value.clone());
            }
            let Some(name) = self.key_text(key) else {
                continue;
            };
            // Go's walk names a key by its node's `.Value`, which for an alias
            // is the anchor name. An alias that resolves to another text
            // therefore credits its fields to a name nothing looks up: they
            // stay decoded but unwritten.
            let key_direct =
                direct && !(self.nodes[key].kind == Kind::Alias && self.nodes[key].value != name);
            if !seen.insert(name.clone()) {
                continue;
            }
            let element = match &shape {
                Shape::Struct(fields) => fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, field_type)| (*field_type).to_owned()),
                Shape::Map(element) => Some(element.clone()),
                Shape::Time => None,
            };
            let Some(element) = element else {
                continue;
            };
            if let Some(coerced) = self.coerce(value, &element, key_direct) {
                out.insert(serde_yaml_ng::Value::String(name), coerced);
            }
        }
        if let Some(merge) = merge_node {
            let operands = match self.nodes[merge].kind {
                Kind::Sequence => self.nodes[merge].children.clone(),
                _ => vec![merge],
            };
            for operand in operands {
                let target = self.target_of(operand)?;
                if self.nodes[target].kind != Kind::Mapping {
                    continue;
                }
                let mut ignored = Vec::new();
                self.coerce_mapping(target, go_type, false, seen, out, &mut ignored)?;
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(source: &str) -> String {
        String::from_utf8_lossy(&unmarshal_errors(source).unwrap_or_default()).into_owned()
    }

    #[test]
    fn durations_take_only_parseable_strings() {
        assert_eq!(errors("sessionTimeout: 20m\n"), "");
        assert_eq!(errors("sessionTimeout: \"0\"\n"), "");
        assert_eq!(errors("sessionTimeout: null\n"), "");
        for (text, tag, shown) in [
            ("12", "!!int", "12"),
            ("0", "!!int", "0"),
            ("1.5", "!!float", "1.5"),
            ("true", "!!bool", "true"),
            ("2026-10-31", "!!timestamp", "2026-10-31"),
            ("not-a-duration", "!!str", "not-a-d..."),
            ("abcdefgh", "!!str", "abcdefgh"),
        ] {
            assert_eq!(
                errors(&format!("sessionTimeout: {text}\n")),
                format!(
                    "yaml: unmarshal errors:\n  line 1: cannot unmarshal {tag} `{shown}` into time.Duration"
                ),
                "{text}"
            );
        }
        assert_eq!(
            errors("sessionTimeout: [1]\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!seq into time.Duration"
        );
        assert_eq!(
            errors("sessionTimeout:\n  a: 1\n"),
            "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!map into time.Duration"
        );
    }

    #[test]
    fn long_values_are_cut_at_seven_bytes_even_inside_a_character() {
        let bytes = unmarshal_errors("sessionTimeout: ééééééééééé\n").expect("error");
        let text = [
            &b"yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `"[..],
            &[0xC3, 0xA9, 0xC3, 0xA9, 0xC3, 0xA9, 0xC3],
            &b"...` into time.Duration"[..],
        ]
        .concat();
        assert_eq!(bytes, text);
    }

    #[test]
    fn other_typed_fields_follow_decode_go() {
        assert_eq!(errors("useTouchID: yes\ngit:\n  auto_push: off\n"), "");
        assert_eq!(errors("authMethod: 12\ndefaultAgent: true\n"), "");
        assert_eq!(errors("clipboard:\n  auto_clear_duration: 1.5\n"), "");
        assert_eq!(
            errors("useTouchID: 12\nmcp:\n  port: abc\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!int `12` into bool\n  line 3: cannot unmarshal !!str `abc` into int"
        );
        assert_eq!(
            errors(
                "mcp:\n  trusted_proxy_ips: x\nagents:\n  cli:\n    allowedPaths: y\n    approvalTimeout: 30\n"
            ),
            "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!str `x` into []string\n  line 5: cannot unmarshal !!str `y` into []string\n  line 6: cannot unmarshal !!int `30` into time.Duration"
        );
        assert_eq!(
            errors("vault: 5\nagents: x\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!int `5` into config.VaultConfig\n  line 2: cannot unmarshal !!str `x` into map[string]config.AgentProfile"
        );
    }

    const HEAD: &str = "yaml: unmarshal errors:";

    #[test]
    fn a_block_key_does_not_take_the_parent_mappings_anchor_or_tag_line() {
        // Recorded with the pinned Go CLI (`config set vaultDir /y`).
        for source in [
            "agents:\n  a: &d\n    approvalTimeout: 5m\n    approvalTimeout: 6m\n",
            "agents:\n  a: !!map\n    approvalTimeout: 5m\n    approvalTimeout: 6m\n",
            "agents:\n  a:\n    &k approvalTimeout: 5m\n    approvalTimeout: 6m\n",
        ] {
            assert_eq!(
                errors(source),
                format!(
                    "{HEAD}\n  line 4: mapping key \"approvalTimeout\" already defined at line 3"
                ),
                "{source}"
            );
        }
        assert_eq!(
            errors("agents: {a: &d {approvalTimeout: 5m, approvalTimeout: 6m}}\n"),
            format!("{HEAD}\n  line 1: mapping key \"approvalTimeout\" already defined at line 1")
        );
    }

    #[test]
    fn token_starts_match_a_backward_scan() {
        let source = "a: &x\n  b: [x,&y z,!!str w]  # c\n\t!t v";
        let bytes = source.as_bytes();
        let starts = token_starts(source);
        assert_eq!(starts.len(), bytes.len() + 1);
        for (end, start) in starts.iter().enumerate() {
            let mut begin = end;
            while begin > 0 && !is_white(bytes[begin - 1]) {
                begin -= 1;
            }
            assert_eq!(*start, begin, "{end}");
        }
    }

    #[test]
    fn an_alias_decodes_its_anchored_node_and_reports_the_anchor_line() {
        // Every expectation below was produced by the pinned Go CLI.
        assert_eq!(
            errors("a: &x 12\nsessionTimeout: *x\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!int `12` into time.Duration")
        );
        assert_eq!(
            errors("a: &a\n  p: 1\nsessionTimeout: *a\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!map into time.Duration")
        );
        assert_eq!(
            errors("sessionTimeout: &a\n  p: 1\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!map into time.Duration")
        );
        assert_eq!(
            errors("sessionTimeout: &t !!str 12\nsessionMaxLifetime: *t\n"),
            format!(
                "{HEAD}\n  line 1: cannot unmarshal !!str `12` into time.Duration\n  line 1: cannot unmarshal !!str `12` into time.Duration"
            )
        );
        // A null decodes to the zero value through an alias as well.
        assert_eq!(
            errors("n: &n ~\nmcp:\n  port: *n\n  read_timeout: *n\n"),
            ""
        );
        // An alias to a key the struct does not know is never decoded.
        assert_eq!(errors("a: &a [*a]\n"), "");
    }

    #[test]
    fn merge_keys_decode_after_the_own_keys_which_win() {
        assert_eq!(
            errors("b: &b\n  port: abc\nmcp:\n  <<: *b\n"),
            format!("{HEAD}\n  line 2: cannot unmarshal !!str `abc` into int")
        );
        assert_eq!(
            errors("b: &b {port: abc}\nmcp: {<<: *b}\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!str `abc` into int")
        );
        assert_eq!(
            errors("b: &b\n  port: abc\nmcp:\n  port: 3\n  <<: *b\n"),
            ""
        );
        // The first mapping of a merge sequence wins over the later ones.
        assert_eq!(
            errors("m: &m {port: abc}\nmcp:\n  <<: [*m, {port: x}]\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!str `abc` into int")
        );
        assert_eq!(
            errors(
                "p: &p\n  approvalTimeout: 5\nagents:\n  a:\n    <<: *p\n  b:\n    <<: *p\n    approvalTimeout: 7s\n"
            ),
            format!("{HEAD}\n  line 2: cannot unmarshal !!int `5` into time.Duration")
        );
        for operand in ["5", "[1]"] {
            assert_eq!(
                errors(&format!("mcp:\n  <<: {operand}\n")),
                "yaml: map merge requires map or sequence of maps as the value",
                "{operand}"
            );
        }
        assert_eq!(
            errors("p: &p [1]\nmcp:\n  <<: *p\n"),
            "yaml: map merge requires map or sequence of maps as the value"
        );
        assert_eq!(
            errors("vaultDir: a\nvaultDir: b\n"),
            format!("{HEAD}\n  line 2: mapping key \"vaultDir\" already defined at line 1")
        );
    }

    #[test]
    fn an_explicit_tag_decides_how_the_scalar_resolves() {
        let one = |text: &str| errors(&format!("sessionTimeout: {text}\n"));
        assert_eq!(
            one("!!int 12"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!int `12` into time.Duration")
        );
        // F2: a string tag keeps `12` a string, which no Duration parses.
        assert_eq!(
            one("!!str 12"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!str `12` into time.Duration")
        );
        assert_eq!(one("!!str 5m"), "");
        assert_eq!(
            one("!custom 5"),
            format!("{HEAD}\n  line 1: cannot unmarshal !custom `5` into time.Duration")
        );
        assert_eq!(
            one("!!binary MTI="),
            format!("{HEAD}\n  line 1: cannot unmarshal !!binary `MTI=` into time.Duration")
        );
        // Text the tag cannot represent aborts the decode.
        assert_eq!(
            one("!!int abc"),
            "yaml: cannot decode !!str `abc` as a !!int"
        );
        assert_eq!(
            one("!!null foo"),
            "yaml: cannot decode !!str `foo` as a !!null"
        );
        assert_eq!(
            errors("mcp:\n  port: !!int 1.5\n"),
            "yaml: cannot decode !!float `1.5` as a !!int"
        );
        assert_eq!(
            errors("sessionTimeout: !!map [1]\n"),
            format!("{HEAD}\n  line 1: cannot unmarshal !!map into time.Duration")
        );
    }

    #[test]
    fn a_time_field_takes_a_mapping_a_timestamp_or_rfc3339_text() {
        let time = |text: &str| errors(&format!("vault:\n  last_rotated: {text}\n"));
        assert_eq!(time("{a: 1}"), "");
        assert_eq!(time("{}"), "");
        assert_eq!(time("2026-10-31"), "");
        assert_eq!(time("~"), "");
        assert_eq!(time("\"2026-10-31T1:00:00Z\""), "");
        assert_eq!(
            time("[1]"),
            format!("{HEAD}\n  line 2: cannot unmarshal !!seq into time.Time")
        );
        assert_eq!(
            time("12"),
            "parsing time \"12\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"12\" as \"2006\""
        );
        assert_eq!(
            time("\"2026-10-31\""),
            "parsing time \"2026-10-31\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"T\""
        );
        assert_eq!(
            time("!!str 2026-10-31"),
            "parsing time \"2026-10-31\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"T\""
        );
    }

    #[test]
    fn plain_merge_keys_are_written_with_their_tag() {
        assert_eq!(
            tag_merge_keys("b: &b {p: 1}\nm: {<<: *b}\nn:\n  <<: *b\nq: [<<, \"<<\", !!str <<]\n"),
            "b: &b {p: 1}\nm: {!!merge <<: *b}\nn:\n  !!merge <<: *b\nq: [!!merge <<, \"<<\", !!str <<]\n"
        );
    }
    fn coerced(source: &str) -> serde_yaml_ng::Value {
        assert_eq!(errors(source), "", "{source}");
        coerced_document(source).expect("coerced tree")
    }

    fn at<'a>(value: &'a serde_yaml_ng::Value, path: &str) -> &'a serde_yaml_ng::Value {
        path.split('.').fold(value, |node, name| {
            node.get(name).unwrap_or_else(|| panic!("{name} in {path}"))
        })
    }

    #[test]
    fn coerced_strings_are_the_source_text() {
        let tree = coerced(
            "vault:\n  path: 0x10\ngit:\n  commit_template: true\nmcp:\n  bind: 1e3\n  tls_cert_file: \"a\\tb\"\n  tls_key_file: 1.50\n",
        );
        assert_eq!(at(&tree, "vault.path").as_str(), Some("0x10"));
        assert_eq!(at(&tree, "git.commit_template").as_str(), Some("true"));
        assert_eq!(at(&tree, "mcp.bind").as_str(), Some("1e3"));
        assert_eq!(at(&tree, "mcp.tls_cert_file").as_str(), Some("a\tb"));
        assert_eq!(at(&tree, "mcp.tls_key_file").as_str(), Some("1.50"));
    }

    #[test]
    fn coerced_ints_truncate_floats_and_read_yaml_11_spellings() {
        for (text, expected) in [
            ("1.5", 1),
            ("-1.5", -1),
            ("1e3", 1000),
            ("1_000", 1000),
            ("017", 15),
            ("0o17", 15),
            ("0x1F", 31),
            ("-0.5", 0),
        ] {
            let tree = coerced(&format!("mcp:\n  port: {text}\n"));
            assert_eq!(at(&tree, "mcp.port").as_i64(), Some(expected), "{text}");
        }
    }

    #[test]
    fn coerced_bools_durations_and_nulls() {
        let tree = coerced(
            "git:\n  auto_push: yes\n  auto_pull: Off\n  auto_pull_interval: -1500ms\nagents:\n  x:\n    canWrite: null\n    allowedPaths: [a, null, 5]\n",
        );
        assert_eq!(at(&tree, "git.auto_push").as_bool(), Some(true));
        assert_eq!(at(&tree, "git.auto_pull").as_bool(), Some(false));
        assert_eq!(
            at(&tree, "git.auto_pull_interval").as_i64(),
            Some(-1_500_000_000)
        );
        assert!(at(&tree, "agents.x.canWrite").is_null());
        // yaml.v3 cannot put a null into a `string`, so the item is dropped.
        let paths: Vec<_> = at(&tree, "agents.x.allowedPaths")
            .as_sequence()
            .expect("sequence")
            .iter()
            .filter_map(serde_yaml_ng::Value::as_str)
            .collect();
        assert_eq!(paths, ["a", "5"]);
    }

    /// The keys the mapping at `path` wrote itself.
    fn own(tree: &serde_yaml_ng::Value, path: &str) -> Vec<String> {
        at(tree, path)
            .get(own_keys_key())
            .and_then(serde_yaml_ng::Value::as_sequence)
            .map(|keys| {
                keys.iter()
                    .filter_map(serde_yaml_ng::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn coerced_mappings_separate_written_keys_from_merged_ones() {
        let tree = coerced(
            "base: &base\n  port: 7\n  bind: merged\nmcp:\n  <<: *base\n  bind: own\n  extra: 1\nupdate: *base\n",
        );
        // The mapping's own key wins over the merge; the merge fills the rest.
        assert_eq!(at(&tree, "mcp.bind").as_str(), Some("own"));
        assert_eq!(at(&tree, "mcp.port").as_i64(), Some(7));
        // Only `bind` and `extra` were written by `mcp` itself (Go's walk lists
        // every key, known or not), and an alias writes nothing.
        assert_eq!(own(&tree, "mcp"), ["bind", "extra"]);
        assert!(own(&tree, "update").is_empty());
        // Fields the Go type does not name are dropped.
        assert!(at(&tree, "mcp").get("extra").is_none());
    }

    #[test]
    fn a_quoted_nul_own_key_is_an_ordinary_entry() {
        // The bookkeeping key is not a string, so an agent whose name spells
        // the old marker keeps its entry and its own-key list.
        let tree = coerced("agents:\n  \"\\0own\":\n    canWrite: true\n");
        let agents = at(&tree, "agents");
        assert_eq!(
            agents
                .get("\u{0}own")
                .and_then(|agent| agent.get("canWrite")),
            Some(&serde_yaml_ng::Value::Bool(true))
        );
        assert_eq!(own(&tree, "agents"), ["\u{0}own"]);
        assert!(
            agents.as_mapping().is_some_and(|map| map
                .keys()
                .filter(|key| !key.is_string())
                .count()
                == 1)
        );
    }

    #[test]
    fn an_alias_key_that_resolves_to_another_name_writes_nothing() {
        // Go lists a key by its node's Value, the anchor name for an alias:
        // `*authMethod` is a written `authMethod` that decodes as `path`.
        let tree = coerced("k: &authMethod path\nvault:\n  *authMethod : /y\n");
        assert_eq!(own(&tree, "vault"), ["authMethod"]);
        assert_eq!(at(&tree, "vault.path").as_str(), Some("/y"));
        // The same alias naming a section (or an agent) credits its fields to
        // a name nothing looks up: they decode but stay unwritten.
        let tree = coerced("s: &git vault\n*git :\n  authMethod: ' Bogus '\n");
        assert_eq!(at(&tree, "vault.authMethod").as_str(), Some(" Bogus "));
        assert!(own(&tree, "vault").is_empty());
        let tree = coerced("n: &a x\nagents:\n  *a :\n    approvalMode: bogus\n");
        assert!(own(&tree, "agents.x").is_empty());
        // An alias that names what it resolves to keeps the fields written.
        let tree = coerced("s: &vault vault\n*vault :\n  authMethod: touchid\n");
        assert_eq!(own(&tree, "vault"), ["authMethod"]);
    }
}
