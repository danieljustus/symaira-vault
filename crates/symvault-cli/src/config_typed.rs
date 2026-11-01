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
pub(crate) fn unmarshal_errors(source: &str) -> Option<Vec<u8>> {
    let file = yaml_edit::YamlFile::from_str(source).ok()?;
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
    let root = decoder.build(&root);
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

/// yaml.v3 gives a plain `<<` scalar the tag `!!merge`, and its encoder keeps
/// a tag the plain text would not resolve to (`<<` resolves to `!!str`), so
/// `config set` writes every plain `<<` back as `!!merge <<`: keys and values,
/// at any depth. A quoted `'<<'` or an explicitly tagged one is left alone.
pub(crate) fn tag_merge_keys(rendered: &str) -> String {
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
    Bool,
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

    /// yaml.v3's `Node.Line` (1-based): the event starts at the first of the
    /// node's anchor and tag, which `yaml_edit`'s ranges leave out when the
    /// anchor sits on an earlier line.
    fn line(&self, start: usize) -> usize {
        let bytes = self.source.as_bytes();
        let mut at = start.min(bytes.len());
        loop {
            let mut end = at;
            while end > 0 && is_white(bytes[end - 1]) {
                end -= 1;
            }
            let mut begin = end;
            while begin > 0 && !is_white(bytes[begin - 1]) {
                begin -= 1;
            }
            let token = &bytes[begin..end];
            let line_start = bytes[..begin]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |position| position + 1);
            let in_comment = bytes[line_start..begin].contains(&b'#');
            if token.len() > 1 && matches!(token[0], b'&' | b'!') && !in_comment {
                at = begin;
            } else {
                break;
            }
        }
        1 + self.newlines.partition_point(|position| *position < at)
    }

    fn push(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn build(&mut self, node: &YamlNode) -> usize {
        let range = node.byte_range();
        let (start, end) = (range.start as usize, range.end as usize);
        let line = self.line(start);
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
        for (key, value) in mapping.iter() {
            children.push(self.build(&key));
            children.push(self.build(&value));
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
            children.push(self.build(&item));
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
            Resolved::Bool(_) => Val::Bool,
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
                | ("bool", Val::Bool)
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
                Val::Bool => true,
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
                Val::Str(text) => symvault_core::config::parse_go_duration(text).is_ok(),
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
                        symvault_core::go_quote(&second.value),
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
}
