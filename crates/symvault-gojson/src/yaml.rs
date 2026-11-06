//! `gopkg.in/yaml.v3` compatible block-style emission for the CLI's
//! `--output yaml`.
//!
//! The Go CLI marshals plain structs and maps with the library defaults:
//! four-space indentation, mapping keys in declaration order (structs) or
//! sorted (maps), a sequence under a mapping key indented by one level, a
//! sequence of mappings written `- key: value` with the continuation lines two
//! columns in, and empty collections as `[]`/`{}`.
//!
//! Strings are not guessed: this is a port of the parts of yaml.v3's encoder
//! (`encode.go` `stringv`) and emitter (`emitterc.go`: `analyze_scalar`,
//! `select_scalar_style`, the plain/single-quoted/double-quoted/literal
//! writers, `write_indent`, `write_indicator`) that a block document of
//! scalars, sequences and mappings reaches, including their quirks (an
//! astral character forces double quotes, `is_bom` looks at the first byte of
//! the value instead of the current one, a line break other than `\n` is
//! written raw and restarts the column). The emitter state (`column`,
//! `whitespace`, `indention`, `indent`) is tracked like the original because
//! the block styles and the quoted line breaks depend on it. The corpus in
//! `testdata/port/cli/yaml-scalars.json` is recorded from the pinned
//! yaml.v3 and replayed by `tests/yaml_scalars.rs`.
//!
//! This is intentionally not a general YAML library: only the value shapes the
//! CLI renders (null, bool, integers, strings, sequences, mappings) are
//! supported, with `best_width` unlimited (yaml.v3's default for `Marshal`).

use serde_json::Value;

use crate::resolve::{Resolved, is_base60_float, is_old_bool, resolve};

/// An ordered YAML value.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    /// Convert a JSON value keeping `serde_json`'s map iteration order (sorted
    /// unless the workspace enables `preserve_order`), which is what a Go map
    /// marshals to.
    pub fn from_json(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Number(number) => number
                .as_i64()
                .map(Self::Int)
                .or_else(|| number.as_f64().map(Self::Float))
                .unwrap_or(Self::Null),
            Value::String(text) => Self::Str(text.clone()),
            Value::Array(items) => Self::Seq(items.iter().map(Self::from_json).collect()),
            Value::Object(map) => Self::Map(
                map.iter()
                    .map(|(key, value)| (key.clone(), Self::from_json(value)))
                    .collect(),
            ),
        }
    }
}

/// Marshal `node` like `yaml.Marshal`.
pub fn to_string(node: &Node) -> String {
    let mut emitter = Emitter::new();
    emitter.document(node);
    emitter.out
}

/// A string as the value of an entry of a block mapping whose emitter
/// indentation is `mapping_indent` (the column its keys sit at), as it follows
/// `key:` — without the separating space and without the final line break, so
/// a caller writes `format!("{key}: {value}\n")`. A multi-line string comes
/// back as a literal block whose content is indented like yaml.v3 does.
pub fn string_in_mapping(text: &str, mapping_indent: i32) -> String {
    string_value(
        text,
        scalar_indent(mapping_indent, Parent::MappingValue),
        mapping_indent,
    )
}

/// A string as an item of a block sequence whose emitter indentation is
/// `sequence_indent` (the column of its `-`); see [`string_in_mapping`].
pub fn string_in_sequence(text: &str, sequence_indent: i32) -> String {
    string_value(
        text,
        scalar_indent(sequence_indent, Parent::SequenceItem),
        sequence_indent,
    )
}

/// `parent_indent` is the indentation of the collection holding the scalar.
///
/// Two yaml.v3 defects make a literal block unsafe for a config file that is
/// read back, so those strings are written double-quoted instead (every parser
/// reads them back equal):
///
///  - a value that starts with a line break loses it: the emitter writes the
///    break once, where the block scalar needs the header's break plus an empty
///    line;
///  - a value that starts with a space or break gets an indentation indicator
///    of `4`, which a parser reads relative to the parent's column, while the
///    content sits at the collection's emitter indent. The two agree only when
///    the content is exactly four columns deeper (every sequence item and a
///    mapping nested in one breaks: the file no longer parses);
///  - a value that starts with a TAB: yaml.v3 writes the tab as the first
///    content character of the block, and its scanner (and every other one)
///    rejects it as indentation (`found a tab character where an indentation
///    space is expected`).
fn string_value(text: &str, content_indent: i32, parent_indent: i32) -> String {
    let mut emitter = Emitter::new();
    emitter.indention = false;
    emitter.literal_parent = Some(parent_indent);
    emitter.string(text, false, content_indent);
    let mut out = emitter.out;
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// A mapping key of a block mapping whose emitter indentation is
/// `mapping_indent`, up to and including the `:` (a key that is multi-line or
/// longer than 128 bytes takes the `? key` / `:` form). A caller writes
/// `format!("{key} {value}\n")` or `format!("{key}\n")`.
pub fn mapping_key(key: &str, mapping_indent: i32) -> String {
    let mut emitter = Emitter::new();
    emitter.column = mapping_indent;
    if is_simple_key(key) {
        emitter.string(key, true, mapping_indent);
        emitter.write_indicator(":", false, false, false);
    } else {
        emitter.write_indicator("?", true, false, true);
        // The same yaml.v3 literal-block defects as `string_value`: a key that
        // starts with a line break loses it (so `"\na\nb"` and `"a\nb"` would
        // collide on reload), and one that starts with a space needs the
        // indentation indicator to match the content column.
        emitter.literal_parent = Some(mapping_indent);
        emitter.string(
            key,
            false,
            scalar_indent(mapping_indent, Parent::MappingValue),
        );
        emitter.write_indent(mapping_indent);
        emitter.write_indicator(":", true, false, true);
    }
    emitter.out
}

/// yaml.v3's `best_indent` for `Marshal`.
const BEST_INDENT: i32 = 4;

/// The writer state of yaml.v3's emitter that scalars and block collections
/// depend on.
struct Emitter {
    out: String,
    column: i32,
    whitespace: bool,
    indention: bool,
    /// See [`string_value`]: set only for scalars written into a config file.
    literal_parent: Option<i32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
}

/// Where a collection node sits: it decides the indentation of what it holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    /// The document root (`indent` is `-1`).
    Root,
    /// A value of a block mapping.
    MappingValue,
    /// An item of a block sequence.
    SequenceItem,
}

impl Emitter {
    fn new() -> Self {
        Self {
            out: String::new(),
            column: 0,
            whitespace: true,
            indention: true,
            literal_parent: None,
        }
    }

    fn put(&mut self, character: char) {
        self.out.push(character);
        self.column += 1;
    }

    fn put_break(&mut self) {
        self.out.push('\n');
        self.column = 0;
        self.indention = true;
    }

    /// `write`: copy one character.
    fn write(&mut self, character: char) {
        self.out.push(character);
        self.column += 1;
    }

    /// `write_break`: `\n` is a real line break, any other break character is
    /// copied and only resets the column.
    fn write_break(&mut self, character: char) {
        if character == '\n' {
            self.put_break();
        } else {
            self.out.push(character);
            self.column = 0;
            self.indention = true;
        }
    }

    fn write_indent(&mut self, indent: i32) {
        let indent = indent.max(0);
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.put_break();
        }
        while self.column < indent {
            self.put(' ');
        }
        self.whitespace = true;
    }

    fn write_indicator(
        &mut self,
        indicator: &str,
        need_whitespace: bool,
        is_whitespace: bool,
        is_indention: bool,
    ) {
        if need_whitespace && !self.whitespace {
            self.put(' ');
        }
        for character in indicator.chars() {
            self.write(character);
        }
        self.whitespace = is_whitespace;
        self.indention = self.indention && is_indention;
    }

    fn document(&mut self, node: &Node) {
        self.node(node, -1, Parent::Root);
        // yaml_emitter_emit_document_end: terminate the last line.
        self.write_indent(-1);
    }

    /// One node; `indent` is the emitter's current indentation (the enclosing
    /// collection's, `-1` at the root).
    fn node(&mut self, node: &Node, indent: i32, parent: Parent) {
        match node {
            Node::Map(entries) if !entries.is_empty() => {
                let inner = collection_indent(indent, parent);
                self.mapping(entries, inner);
            }
            Node::Seq(items) if !items.is_empty() => {
                let inner = collection_indent(indent, parent);
                self.sequence(items, inner);
            }
            Node::Str(text) => {
                let scalar_indent = scalar_indent(indent, parent);
                self.string(text, false, scalar_indent);
            }
            other => {
                let text = plain_text(other);
                self.write_plain(&text);
            }
        }
    }

    fn mapping(&mut self, entries: &[(String, Node)], indent: i32) {
        for (key, value) in entries {
            self.write_indent(indent);
            if is_simple_key(key) {
                self.string(key, true, indent);
                self.write_indicator(":", false, false, false);
            } else {
                self.write_indicator("?", true, false, true);
                self.string(key, false, scalar_indent(indent, Parent::MappingValue));
                self.write_indent(indent);
                self.write_indicator(":", true, false, true);
            }
            self.node(value, indent, Parent::MappingValue);
        }
    }

    fn sequence(&mut self, items: &[Node], indent: i32) {
        for item in items {
            self.write_indent(indent);
            self.write_indicator("-", true, false, true);
            self.node(item, indent, Parent::SequenceItem);
        }
    }

    fn write_plain(&mut self, text: &str) {
        if !text.is_empty() && !self.whitespace {
            self.put(' ');
        }
        for character in text.chars() {
            self.write(character);
        }
        if !text.is_empty() {
            self.whitespace = false;
        }
        self.indention = false;
    }

    /// `stringv` + `select_scalar_style` + `process_scalar` for a string.
    fn string(&mut self, text: &str, simple_key: bool, indent: i32) {
        let can_use_plain =
            matches!(resolve(text), Resolved::Str) && !(is_base60_float(text) || is_old_bool(text));
        let analysis = analyze(text);
        let mut style = if text.contains('\n') {
            Style::Literal
        } else if can_use_plain {
            Style::Plain
        } else {
            Style::DoubleQuoted
        };
        if simple_key && analysis.multiline {
            style = Style::DoubleQuoted;
        }
        if style == Style::Plain {
            if !analysis.block_plain_allowed {
                style = Style::SingleQuoted;
            }
            if text.is_empty() && simple_key {
                style = Style::SingleQuoted;
            }
        }
        if style == Style::SingleQuoted && !analysis.single_quoted_allowed {
            style = Style::DoubleQuoted;
        }
        if style == Style::Literal && (!analysis.block_allowed || simple_key) {
            style = Style::DoubleQuoted;
        }
        if style == Style::Literal
            && let Some(parent) = self.literal_parent
        {
            let first = text.chars().next();
            if first.is_some_and(is_break)
                || first == Some('\t')
                || (first == Some(' ') && indent != parent + BEST_INDENT)
            {
                style = Style::DoubleQuoted;
            }
        }
        match style {
            Style::Plain => self.write_plain(text),
            Style::SingleQuoted => self.write_single_quoted(text, indent),
            Style::DoubleQuoted => self.write_double_quoted(text),
            Style::Literal => self.write_literal(text, indent),
        }
    }

    fn write_single_quoted(&mut self, text: &str, indent: i32) {
        self.write_indicator("'", true, false, false);
        let mut breaks = false;
        for character in text.chars() {
            if character == ' ' {
                self.write(character);
                breaks = false;
            } else if is_break(character) {
                if !breaks && character == '\n' {
                    self.put_break();
                }
                self.write_break(character);
                breaks = true;
            } else {
                if breaks {
                    self.write_indent(indent);
                }
                if character == '\'' {
                    self.put('\'');
                }
                self.write(character);
                self.indention = false;
                breaks = false;
            }
        }
        self.write_indicator("'", false, false, false);
        self.whitespace = false;
        self.indention = false;
    }

    fn write_double_quoted(&mut self, text: &str) {
        self.write_indicator("\"", true, false, false);
        // yaml.v3's `is_bom(value, i)` reads the first bytes of the value, not
        // the ones at `i`: a value that starts with U+FEFF escapes every
        // character.
        let starts_with_bom = text.starts_with('\u{feff}');
        for character in text.chars() {
            if !is_printable(character)
                || starts_with_bom
                || is_break(character)
                || character == '"'
                || character == '\\'
            {
                self.put('\\');
                let value = character as u32;
                let escaped = match value {
                    0x00 => "0".to_owned(),
                    0x07 => "a".to_owned(),
                    0x08 => "b".to_owned(),
                    0x09 => "t".to_owned(),
                    0x0A => "n".to_owned(),
                    0x0B => "v".to_owned(),
                    0x0C => "f".to_owned(),
                    0x0D => "r".to_owned(),
                    0x1B => "e".to_owned(),
                    0x22 => "\"".to_owned(),
                    0x5C => "\\".to_owned(),
                    0x85 => "N".to_owned(),
                    0xA0 => "_".to_owned(),
                    0x2028 => "L".to_owned(),
                    0x2029 => "P".to_owned(),
                    v if v <= 0xFF => format!("x{v:02X}"),
                    v if v <= 0xFFFF => format!("u{v:04X}"),
                    v => format!("U{v:08X}"),
                };
                for escape in escaped.chars() {
                    self.put(escape);
                }
            } else {
                self.write(character);
            }
        }
        self.write_indicator("\"", false, false, false);
        self.whitespace = false;
        self.indention = false;
    }

    fn write_literal(&mut self, text: &str, indent: i32) {
        self.write_indicator("|", true, false, false);
        // yaml_emitter_write_block_scalar_hints
        let first = text.chars().next();
        if first.is_some_and(|c| c == ' ' || is_break(c)) {
            self.write_indicator(&BEST_INDENT.to_string(), false, false, false);
        }
        let mut reversed = text.chars().rev();
        let chomp = match reversed.next() {
            None => Some("-"),
            Some(last) if !is_break(last) => Some("-"),
            Some(_) if text.chars().count() == 1 => Some("+"),
            Some(_) if reversed.next().is_some_and(is_break) => Some("+"),
            Some(_) => None,
        };
        if let Some(hint) = chomp {
            self.write_indicator(hint, false, false, false);
        }
        self.whitespace = true;
        let mut breaks = true;
        for character in text.chars() {
            if is_break(character) {
                self.write_break(character);
                breaks = true;
            } else {
                if breaks {
                    self.write_indent(indent);
                }
                self.write(character);
                self.indention = false;
                breaks = false;
            }
        }
    }
}

/// `yaml_emitter_increase_indent` for a collection node.
fn collection_indent(indent: i32, parent: Parent) -> i32 {
    match parent {
        Parent::Root => 0,
        Parent::SequenceItem => indent + 2,
        Parent::MappingValue => BEST_INDENT * ((indent + BEST_INDENT) / BEST_INDENT),
    }
}

/// The indentation of a scalar's block content. `yaml_emitter_emit_scalar`
/// asks for a FLOW increase, which only differs at the document root: there the
/// indentation becomes `best_indent`, not `0`.
fn scalar_indent(indent: i32, parent: Parent) -> i32 {
    if parent == Parent::Root {
        BEST_INDENT
    } else {
        collection_indent(indent, parent)
    }
}

/// `yaml_emitter_check_simple_key` for a string key: a single line of at most
/// 128 bytes.
fn is_simple_key(key: &str) -> bool {
    !analyze(key).multiline && key.len() <= 128
}

fn plain_text(node: &Node) -> String {
    match node {
        Node::Null => "null".to_owned(),
        Node::Bool(true) => "true".to_owned(),
        Node::Bool(false) => "false".to_owned(),
        Node::Int(number) => number.to_string(),
        Node::Float(number) => format_float(*number),
        Node::Seq(_) => "[]".to_owned(),
        Node::Map(_) => "{}".to_owned(),
        Node::Str(_) => unreachable!("strings take the scalar path"),
    }
}

fn format_float(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e15 {
        format!("{number:.1}")
    } else {
        number.to_string()
    }
}

/// `is_break`: CR, LF, NEL, LS, PS.
fn is_break(character: char) -> bool {
    matches!(character, '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// `is_printable`: `\n`, U+0020..U+007E, U+00A0..U+D7FF and U+E000..U+FFFD
/// except U+FEFF. Control characters, U+007F..U+009F, surrogates' neighbours
/// U+FFFE/U+FFFF, U+FEFF and every astral character are not.
fn is_printable(character: char) -> bool {
    let value = character as u32;
    value == 0x0A
        || (0x20..=0x7E).contains(&value)
        || (0xA0..=0xD7FF).contains(&value)
        || ((0xE000..=0xFFFD).contains(&value) && value != 0xFEFF)
}

/// The fields of `yaml_emitter_analyze_scalar` the block writer uses.
struct Analysis {
    multiline: bool,
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
    block_allowed: bool,
}

fn analyze(text: &str) -> Analysis {
    if text.is_empty() {
        return Analysis {
            multiline: false,
            block_plain_allowed: true,
            single_quoted_allowed: true,
            block_allowed: false,
        };
    }
    let characters: Vec<char> = text.chars().collect();
    let mut block_indicators = false;
    let mut line_breaks = false;
    let mut special_characters = false;
    let mut tab_characters = false;
    let mut leading_space = false;
    let mut leading_break = false;
    let mut trailing_space = false;
    let mut trailing_break = false;
    let mut break_space = false;
    let mut space_break = false;
    let mut previous_space = false;
    let mut previous_break = false;
    let mut preceded_by_whitespace = true;

    if text.starts_with("---") || text.starts_with("...") {
        block_indicators = true;
    }
    let blank = |character: char| character == ' ' || character == '\t';
    for (index, &character) in characters.iter().enumerate() {
        let followed_by_whitespace = characters.get(index + 1).is_none_or(|next| blank(*next));
        if index == 0 {
            match character {
                '#' | ',' | '[' | ']' | '{' | '}' | '&' | '*' | '!' | '|' | '>' | '\'' | '"'
                | '%' | '@' | '`' => block_indicators = true,
                '?' | ':' | '-' if followed_by_whitespace => block_indicators = true,
                _ => {}
            }
        } else {
            match character {
                ':' if followed_by_whitespace => block_indicators = true,
                '#' if preceded_by_whitespace => block_indicators = true,
                _ => {}
            }
        }
        if character == '\t' {
            tab_characters = true;
        } else if !is_printable(character) {
            special_characters = true;
        }
        let last = index + 1 == characters.len();
        if character == ' ' {
            if index == 0 {
                leading_space = true;
            }
            if last {
                trailing_space = true;
            }
            if previous_break {
                break_space = true;
            }
            previous_space = true;
            previous_break = false;
        } else if is_break(character) {
            line_breaks = true;
            if index == 0 {
                leading_break = true;
            }
            if last {
                trailing_break = true;
            }
            if previous_space {
                space_break = true;
            }
            previous_space = false;
            previous_break = true;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = blank(character) || is_break(character);
    }

    let mut block_plain_allowed = true;
    let mut single_quoted_allowed = true;
    let mut block_allowed = true;
    if leading_space || leading_break || trailing_space || trailing_break {
        block_plain_allowed = false;
    }
    if trailing_space {
        block_allowed = false;
    }
    if break_space {
        block_plain_allowed = false;
        single_quoted_allowed = false;
    }
    if space_break || tab_characters || special_characters {
        block_plain_allowed = false;
        single_quoted_allowed = false;
    }
    if space_break || special_characters {
        block_allowed = false;
    }
    if line_breaks {
        block_plain_allowed = false;
    }
    if block_indicators {
        block_plain_allowed = false;
    }
    Analysis {
        multiline: line_breaks,
        block_plain_allowed,
        single_quoted_allowed,
        block_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(value: Value) -> String {
        to_string(&Node::from_json(&value))
    }

    #[test]
    fn mappings_and_sequences_use_four_space_indentation() {
        assert_eq!(
            render(json!({"recipients": ["age1abc"], "count": 1})),
            "count: 1\nrecipients:\n    - age1abc\n"
        );
        assert_eq!(
            to_string(&Node::Seq(vec![
                Node::Map(vec![
                    ("path".into(), Node::Str("a/first".into())),
                    ("has".into(), Node::Bool(true)),
                ]),
                Node::Map(vec![("path".into(), Node::Str("b".into()))]),
            ])),
            "- path: a/first\n  has: true\n- path: b\n"
        );
        assert_eq!(
            to_string(&Node::Map(vec![(
                "matches".into(),
                Node::Seq(vec![Node::Map(vec![
                    ("path".into(), Node::Str("work/example".into())),
                    ("fields".into(), Node::Seq(vec![Node::Str("url".into())])),
                    (
                        "meta".into(),
                        Node::Map(vec![("k".into(), Node::Str("v".into()))])
                    ),
                ])])
            )])),
            "matches:\n    - path: work/example\n      fields:\n        - url\n      meta:\n        k: v\n"
        );
        assert_eq!(render(json!({"deleted": true})), "deleted: true\n");
        assert_eq!(render(json!([])), "[]\n");
        assert_eq!(render(json!({"a": []})), "a: []\n");
        assert_eq!(
            render(json!({"fields": {"notes": "a,b"}, "totp": null})),
            "fields:\n    notes: a,b\ntotp: null\n"
        );
    }

    #[test]
    fn config_file_scalars_follow_the_depth_they_are_written_at() {
        // A multi-line map value at mapping depth 4 / 8 / a sequence at 12.
        assert_eq!(string_in_mapping("a\nb", 4), "|-\n        a\n        b");
        assert_eq!(
            string_in_mapping("a\nb\n", 8),
            "|\n            a\n            b"
        );
        assert_eq!(
            string_in_sequence("a\nb", 12),
            "|-\n              a\n              b"
        );
        assert_eq!(string_in_sequence("plain", 12), "plain");
        assert_eq!(string_in_mapping("a: b", 4), "'a: b'");
        // Scalars that would read back as another type are quoted.
        assert_eq!(string_in_mapping("2026-01-02", 4), "\"2026-01-02\"");
        assert_eq!(string_in_mapping("&amp", 4), "'&amp'");
        assert_eq!(string_in_mapping("\u{1F600}", 4), "\"\\U0001F600\"");
        // yaml.v3's own output for these cannot be read back (a sequence item,
        // a mapping inside one) or loses the break: double-quoted instead.
        assert_eq!(string_in_sequence(" a\nb", 12), "\" a\\nb\"");
        assert_eq!(string_in_mapping(" a\nb", 6), "\" a\\nb\"");
        assert_eq!(string_in_mapping("\na", 4), "\"\\na\"");
        // A leading TAB cannot start a literal block's content.
        assert_eq!(string_in_mapping("\ta\nb", 4), "\"\\ta\\nb\"");
        assert_eq!(string_in_sequence("\ta\nb", 12), "\"\\ta\\nb\"");
        assert_eq!(string_in_mapping("a\n\tb", 4), "|-\n        a\n        \tb");
        // At depth 4 the indentation indicator is right and is kept.
        assert_eq!(string_in_mapping(" a\nb", 4), "|4-\n         a\n        b");
        // Keys: simple, quoted, and the `? key` form of a multi-line key.
        assert_eq!(mapping_key("get", 8), "get:");
        assert_eq!(mapping_key("yes", 8), "\"yes\":");
        assert_eq!(
            mapping_key("k\nj", 12),
            "? |-\n                k\n                j\n            :"
        );
        // A key that starts with a line break would lose it as a literal
        // block (`? |4-` reloads as `a\nb`): double-quoted instead.
        assert_eq!(mapping_key("\na\nb", 8), "? \"\\na\\nb\"\n        :");
        assert_eq!(mapping_key("\n", 4), "? \"\\n\"\n    :");
        assert_eq!(mapping_key("\ta\nb", 8), "? \"\\ta\\nb\"\n        :");
        // A leading space needs the indicator, which matches at this depth.
        assert_eq!(
            mapping_key(" a\nb", 4),
            "? |4-\n         a\n        b\n    :"
        );
    }

    /// Spot checks of the styles; the full corpus (every position, 400+
    /// strings recorded from yaml.v3) is `tests/yaml_scalars.rs`.
    #[test]
    fn strings_are_emitted_like_yaml_v3() {
        for (input, want) in [
            ("***", "k: '***'\n"),
            ("", "k: \"\"\n"),
            ("true", "k: \"true\"\n"),
            ("null", "k: \"null\"\n"),
            ("yes", "k: \"yes\"\n"),
            ("12", "k: \"12\"\n"),
            ("1.5", "k: \"1.5\"\n"),
            ("2026-10-31", "k: \"2026-10-31\"\n"),
            ("2026-10-31T10:00:00Z", "k: \"2026-10-31T10:00:00Z\"\n"),
            ("2026-10-31 22:01", "k: 2026-10-31 22:01\n"),
            ("a: b", "k: 'a: b'\n"),
            ("it's: x", "k: 'it''s: x'\n"),
            (" lead", "k: ' lead'\n"),
            ("Val-Alpha-001", "k: Val-Alpha-001\n"),
            ("https://example.test", "k: https://example.test\n"),
            ("a,b", "k: a,b\n"),
            ("tab\there", "k: \"tab\\there\"\n"),
            // BEL is `\a`, not `\x07`.
            ("bell\u{7}", "k: \"bell\\a\"\n"),
            // `<<` is a plain string for the encoder's resolver.
            ("<<", "k: <<\n"),
            // Astral characters are not printable for yaml.v3's emitter.
            ("\u{1F600}", "k: \"\\U0001F600\"\n"),
            // A leading line break needs an indentation hint.
            ("\na", "k: |4-\n    a\n"),
            // A break other than `\n` is written raw and restarts the column.
            ("a\u{2028}b", "k: 'a\u{2028}    b'\n"),
            ("a\nb", "k: |-\n    a\n    b\n"),
            ("a\nb\n", "k: |\n    a\n    b\n"),
        ] {
            assert_eq!(render(json!({"k": input})), want, "{input:?}");
        }
    }
}
