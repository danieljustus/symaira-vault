//! The nesting limits of Go's `gopkg.in/yaml.v3` scanner.
//!
//! yaml.v3 (`scannerc.go`) bounds two counters independently, both at
//! [`MAX_DEPTH`] = 10000, and fails the scan the moment either is exceeded:
//!
//! - `max_flow_level`: the number of open flow collections (`[` and `{`), checked
//!   in `yaml_parser_increase_flow_level`;
//! - `max_indents`: the length of the block indentation stack, checked in
//!   `yaml_parser_roll_indent`. One entry is pushed for every block sequence
//!   (`- `), explicit key (`? `) or block mapping (a key followed by `:`) that
//!   opens at a column to the right of the current indentation, and popped when
//!   a token appears further left.
//!
//! Both fail with the scanner problem `exceeded max depth of 10000`. The two
//! counters do not add up: 10000 open flow collections inside 10000 nested block
//! collections are accepted.
//!
//! `serde_yaml_ng` (a libyaml port) has no such limit, so the document the Go
//! loader refuses would otherwise be read in full. This module reproduces only
//! the two counters and the position the failure is reported at; everything
//! else about the document stays with the libyaml-backed checks in
//! [`crate::go_yaml`], and the caller decides which of two competing failures
//! comes first by byte offset.
//!
//! The scan follows the yaml.v3 token rules closely enough to count the same
//! structures (quoted and block scalars, comments, plain scalars that continue
//! on the next line, anchors, tags, compact `- - x` and `? - x` nesting, flow
//! collections used as keys). Inputs that cannot reach either limit are not
//! scanned at all: a push needs one of `-`, `?` or `:`, a flow level needs one
//! of `[` or `{`, and no document has to be walked unless one of those bytes
//! occurs more than [`MAX_DEPTH`] times.

/// Go's `max_flow_level` and `max_indents`.
pub const MAX_DEPTH: usize = 10_000;

const PROBLEM: &str = "exceeded max depth of 10000";

/// Where a document first exceeds a limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepthViolation {
    /// Byte offset of the token that pushes the counter over the limit.
    pub offset: usize,
    /// The line yaml.v3 prints, one-based; `0` prints no `line N:` part.
    pub line: usize,
}

impl DepthViolation {
    /// The failure the way `yaml.Unmarshal` words it.
    #[must_use]
    pub fn message(&self) -> String {
        if self.line == 0 {
            format!("yaml: {PROBLEM}")
        } else {
            format!("yaml: line {}: {PROBLEM}", self.line)
        }
    }
}

/// The first place in the first document of `bytes` where yaml.v3's scanner
/// would stop with `exceeded max depth of 10000`.
#[must_use]
pub fn first_violation(bytes: &[u8]) -> Option<DepthViolation> {
    violation_in_document(bytes, 0)
}

/// Like [`first_violation`] for the zero-based `document` of the stream.
#[must_use]
pub fn violation_in_document(bytes: &[u8], document: usize) -> Option<DepthViolation> {
    let flow = bytes.iter().filter(|b| matches!(b, b'[' | b'{')).count();
    let block = bytes
        .iter()
        .filter(|b| matches!(b, b'-' | b'?' | b':'))
        .count();
    if flow <= MAX_DEPTH && block <= MAX_DEPTH {
        return None;
    }
    // The reader drops a byte order mark; offsets stay relative to the input.
    let bom = if bytes.starts_with(b"\xEF\xBB\xBF") {
        3
    } else {
        0
    };
    Scan::new(&bytes[bom..], document)
        .run()
        .map(|mut violation| {
            violation.offset += bom;
            violation
        })
}

struct Scan<'a> {
    /// The document whose limits are reported, and the one being read.
    target: usize,
    document: usize,
    bytes: &'a [u8],
    pos: usize,
    /// Zero-based line and column (in characters) of `pos`.
    line: usize,
    col: usize,
    flow: usize,
    indent: i64,
    indents: Vec<i64>,
    /// A token other than a document marker or directive has been read in the
    /// current document.
    seen_content: bool,
    /// Column of a token that becomes a simple key if a `:` follows on the same
    /// line.
    candidate: Option<usize>,
    /// Line of the last token yaml.v3 saved as a possible simple key; the
    /// failure's context mark.
    saved_line: usize,
    /// yaml.v3's `simple_key_allowed`.
    allowed: bool,
    /// The previous token was a plain scalar that ended at a line break and
    /// may continue on the next line.
    plain_open: bool,
}

impl<'a> Scan<'a> {
    fn new(bytes: &'a [u8], target: usize) -> Self {
        Self {
            target,
            document: 0,
            bytes,
            pos: 0,
            line: 0,
            col: 0,
            flow: 0,
            indent: -1,
            indents: Vec::new(),
            seen_content: false,
            candidate: None,
            saved_line: 0,
            allowed: true,
            plain_open: false,
        }
    }

    fn peek(&self, ahead: usize) -> Option<u8> {
        self.bytes.get(self.pos + ahead).copied()
    }

    /// Whether the byte `ahead` positions on is a blank, a line break or the
    /// end of the stream (yaml.v3's `is_blankz`).
    fn blank_at(&self, ahead: usize) -> bool {
        matches!(self.peek(ahead), None | Some(b' ' | b'\t' | b'\r' | b'\n'))
    }

    fn at_break(&self) -> bool {
        matches!(self.peek(0), Some(b'\r' | b'\n'))
    }

    /// Consumes one character; a line break starts a new line.
    fn advance(&mut self) {
        let Some(byte) = self.peek(0) else { return };
        self.pos += 1;
        match byte {
            b'\n' => self.new_line(),
            b'\r' => {
                if self.peek(0) == Some(b'\n') {
                    self.pos += 1;
                }
                self.new_line();
            }
            // Continuation bytes belong to the character already counted.
            0x80..=0xBF => {}
            _ => self.col += 1,
        }
    }

    fn new_line(&mut self) {
        self.line += 1;
        self.col = 0;
        self.candidate = None;
        if self.flow == 0 {
            self.allowed = true;
        }
    }

    fn unroll(&mut self, column: usize) {
        if self.flow > 0 {
            return;
        }
        let column = i64::try_from(column).unwrap_or(i64::MAX);
        while self.indent > column {
            self.indent = self.indents.pop().unwrap_or(-1);
        }
    }

    /// yaml.v3's `yaml_parser_roll_indent`; `true` when the stack outgrows the
    /// limit.
    fn roll(&mut self, column: usize) -> bool {
        if self.flow > 0 {
            return false;
        }
        let column = i64::try_from(column).unwrap_or(i64::MAX);
        if self.indent < column {
            self.indents.push(self.indent);
            self.indent = column;
            return self.indents.len() > MAX_DEPTH;
        }
        false
    }

    /// The failure for a token at `offset` on the current line.
    ///
    /// yaml.v3 prints the line of the failure's context mark, the last
    /// possible simple key saved at the current flow level, and falls back to
    /// the line of the token itself when that mark is on the first line. A new
    /// flow level pushes a fresh entry marked at its own bracket, so for the
    /// flow limit the context is always the bracket.
    fn violation(&self, offset: usize, in_flow_limit: bool) -> DepthViolation {
        let context = if in_flow_limit { 0 } else { self.saved_line };
        let line = if context != 0 {
            context + 1
        } else if self.line != 0 {
            self.line + 1
        } else {
            0
        };
        DepthViolation { offset, line }
    }

    /// Records the current token as a possible simple key, as
    /// `yaml_parser_save_simple_key` does when one is allowed.
    fn save_key(&mut self) {
        if self.allowed && self.flow == 0 {
            self.saved_line = self.line;
            if self.candidate.is_none() {
                self.candidate = Some(self.col);
            }
        }
    }

    /// Skips blanks, line breaks and comments up to the next token.
    fn skip_to_token(&mut self) {
        while let Some(byte) = self.peek(0) {
            match byte {
                b' ' | b'\t' => self.advance(),
                b'\r' | b'\n' => self.advance(),
                b'#' => {
                    // A comment ends a plain scalar that was still open.
                    self.plain_open = false;
                    while self.peek(0).is_some() && !self.at_break() {
                        self.advance();
                    }
                }
                _ => break,
            }
        }
    }

    fn run(mut self) -> Option<DepthViolation> {
        loop {
            self.skip_to_token();
            let byte = self.peek(0)?;
            let column = self.col;
            let offset = self.pos;
            if self.flow == 0 {
                if self.plain_open && i64::try_from(column).is_ok_and(|c| c > self.indent) {
                    let marker = column == 0 && self.document_marker().is_some();
                    if !marker {
                        self.skip_line();
                        continue;
                    }
                }
                self.plain_open = false;
                self.unroll(column);
                if column == 0 {
                    if let Some(marker) = self.document_marker() {
                        // `...` ends the document; `---` ends it only when it
                        // already has content.
                        if marker == b'.' || self.seen_content {
                            if self.document >= self.target {
                                return None;
                            }
                            self.next_document();
                        }
                        for _ in 0..3 {
                            self.advance();
                        }
                        self.allowed = true;
                        continue;
                    }
                    if byte == b'%' && !self.seen_content {
                        self.skip_line();
                        continue;
                    }
                }
            }
            self.seen_content = true;
            match byte {
                b'[' | b'{' => {
                    self.save_key();
                    self.flow += 1;
                    if self.flow > MAX_DEPTH && self.document == self.target {
                        return Some(self.violation(offset, true));
                    }
                    self.advance();
                    self.allowed = true;
                }
                b']' | b'}' => {
                    self.advance();
                    if self.flow > 0 {
                        self.flow -= 1;
                    }
                    self.allowed = self.flow > 0;
                }
                b',' if self.flow > 0 => {
                    self.advance();
                    self.allowed = true;
                }
                b'-' | b'?' if self.flow == 0 && self.blank_at(1) => {
                    if self.roll(column) && self.document == self.target {
                        return Some(self.violation(offset, false));
                    }
                    self.candidate = None;
                    self.advance();
                    self.allowed = true;
                }
                b':' if self.blank_at(1) || self.flow > 0 => {
                    if self.flow == 0 {
                        let key = self.candidate.take();
                        if self.roll(key.unwrap_or(column)) && self.document == self.target {
                            return Some(self.violation(offset, false));
                        }
                        self.allowed = key.is_none();
                    }
                    self.advance();
                }
                b'\'' | b'"' => {
                    self.save_key();
                    self.quoted(byte);
                    self.allowed = false;
                }
                b'|' | b'>' if self.flow == 0 => self.block_scalar(),
                b'&' | b'*' => {
                    self.save_key();
                    self.advance();
                    while self
                        .peek(0)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    {
                        self.advance();
                    }
                    self.allowed = false;
                }
                b'!' => {
                    self.save_key();
                    while self.peek(0).is_some_and(|b| {
                        !matches!(b, b' ' | b'\t' | b'\r' | b'\n')
                            && !(self.flow > 0 && matches!(b, b',' | b'[' | b']' | b'{' | b'}'))
                    }) {
                        self.advance();
                    }
                    self.allowed = false;
                }
                _ => self.plain(),
            }
        }
    }

    fn next_document(&mut self) {
        self.document += 1;
        self.flow = 0;
        self.indent = -1;
        self.indents.clear();
        self.seen_content = false;
        self.candidate = None;
        self.saved_line = 0;
        self.plain_open = false;
    }

    /// A `---` or `...` document marker at the current position (the caller
    /// has checked column zero).
    fn document_marker(&self) -> Option<u8> {
        let first = self.peek(0)?;
        if matches!(first, b'-' | b'.')
            && self.peek(1) == Some(first)
            && self.peek(2) == Some(first)
            && self.blank_at(3)
        {
            Some(first)
        } else {
            None
        }
    }

    fn skip_line(&mut self) {
        while self.peek(0).is_some() && !self.at_break() {
            self.advance();
        }
    }

    fn quoted(&mut self, quote: u8) {
        self.advance();
        while let Some(byte) = self.peek(0) {
            if quote == b'"' && byte == b'\\' {
                self.advance();
                self.advance();
            } else if byte == quote {
                if quote == b'\'' && self.peek(1) == Some(b'\'') {
                    self.advance();
                    self.advance();
                } else {
                    self.advance();
                    return;
                }
            } else {
                self.advance();
            }
        }
    }

    /// A literal or folded scalar: the header line and every following line that
    /// is blank or indented deeper than the enclosing block.
    fn block_scalar(&mut self) {
        let parent = self.indent;
        self.skip_line();
        self.plain_open = false;
        let content = (parent + 1).max(1);
        loop {
            let mut probe = self.pos;
            // Step over the line break that ends the current line.
            match self.bytes.get(probe) {
                Some(b'\r') if self.bytes.get(probe + 1) == Some(&b'\n') => probe += 2,
                Some(b'\r' | b'\n') => probe += 1,
                _ => return,
            }
            let mut spaces = 0_i64;
            while self.bytes.get(probe + usize::try_from(spaces).unwrap_or(0)) == Some(&b' ') {
                spaces += 1;
            }
            let after = probe + usize::try_from(spaces).unwrap_or(0);
            let blank = matches!(self.bytes.get(after), None | Some(b'\r' | b'\n'));
            if !blank && spaces < content {
                return;
            }
            while self.pos < probe {
                self.advance();
            }
            self.skip_line();
        }
    }

    fn plain(&mut self) {
        self.save_key();
        let in_flow = self.flow > 0;
        let mut ended_at_break = false;
        loop {
            match self.peek(0) {
                None => break,
                Some(b'\r' | b'\n') => {
                    ended_at_break = true;
                    break;
                }
                Some(b':') if !in_flow && self.blank_at(1) => break,
                Some(b' ' | b'\t') if self.hash_follows() => break,
                Some(b',' | b'[' | b']' | b'{' | b'}') if in_flow => break,
                Some(b':') if in_flow && self.flow_indicator_at(1) => break,
                Some(_) => self.advance(),
            }
        }
        self.allowed = false;
        self.plain_open = !in_flow && ended_at_break;
    }

    /// Blanks followed by `#`, where a comment starts.
    fn hash_follows(&self) -> bool {
        let mut at = 0;
        while matches!(self.peek(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        self.peek(at) == Some(b'#')
    }

    fn flow_indicator_at(&self, ahead: usize) -> bool {
        matches!(
            self.peek(ahead),
            None | Some(b' ' | b'\t' | b'\r' | b'\n' | b',' | b'[' | b']' | b'{' | b'}')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(depth: usize) -> Vec<u8> {
        format!("a: {}{}\n", "[".repeat(depth), "]".repeat(depth)).into_bytes()
    }

    #[test]
    fn flow_limit_is_the_ten_thousandth_open_collection() {
        assert_eq!(first_violation(&flow(10_000)), None);
        let violation = first_violation(&flow(10_001)).expect("10001 levels exceed the limit");
        assert_eq!(violation.line, 0);
        assert_eq!(violation.message(), "yaml: exceeded max depth of 10000");
        // `a: ` and 10000 brackets precede the one that fails.
        assert_eq!(violation.offset, 3 + MAX_DEPTH);
    }

    #[test]
    fn flow_mappings_count_like_sequences() {
        let deep = |n: usize| format!("a: {}1{}\n", "{k: ".repeat(n), "}".repeat(n)).into_bytes();
        assert_eq!(first_violation(&deep(10_000)), None);
        assert!(first_violation(&deep(10_001)).is_some());
    }

    #[test]
    fn a_later_line_is_reported_as_its_one_based_number() {
        let mut document = b"a: 1\nb: 2\nc: ".to_vec();
        document.extend(flow(10_001).split_off(3));
        let violation = first_violation(&document).expect("exceeds");
        assert_eq!(violation.line, 3);
        assert_eq!(
            violation.message(),
            "yaml: line 3: exceeded max depth of 10000"
        );
    }

    #[test]
    fn compact_block_sequences_push_one_entry_per_dash() {
        let dashes = |n: usize| format!("{}x\n", "- ".repeat(n)).into_bytes();
        assert_eq!(first_violation(&dashes(10_000)), None);
        assert!(first_violation(&dashes(10_001)).is_some());
        let questions = |n: usize| format!("{}x\n", "? ".repeat(n)).into_bytes();
        assert_eq!(first_violation(&questions(10_000)), None);
        assert!(first_violation(&questions(10_001)).is_some());
    }

    #[test]
    fn a_block_mapping_counts_as_one_more_level() {
        let nested = |n: usize| format!("{}k: x\n", "- ".repeat(n)).into_bytes();
        assert_eq!(first_violation(&nested(9_999)), None);
        assert!(first_violation(&nested(10_000)).is_some());
    }

    #[test]
    fn flow_and_block_counters_are_independent() {
        let mixed = format!(
            "{}{}{}\n",
            "- ".repeat(9_999),
            "[".repeat(10_000),
            "]".repeat(10_000)
        );
        assert_eq!(first_violation(mixed.as_bytes()), None);
        let block_over = format!("{}[]\n", "- ".repeat(10_001));
        assert!(first_violation(block_over.as_bytes()).is_some());
    }

    #[test]
    fn deeply_indented_mappings_are_counted_by_column() {
        let mut document = String::new();
        for level in 0..10_001 {
            document.push_str(&" ".repeat(level));
            document.push_str("k:\n");
        }
        let violation = first_violation(document.as_bytes()).expect("10001 nested mappings");
        // Every mapping opens on its own line; the failing `:` is on line 10001
        // and the last saved key sits on the same line.
        assert_eq!(violation.line, 10_001);
        let mut shallow = String::new();
        for level in 0..10_000 {
            shallow.push_str(&" ".repeat(level));
            shallow.push_str("k:\n");
        }
        assert_eq!(first_violation(shallow.as_bytes()), None);
    }

    #[test]
    fn brackets_in_quotes_comments_and_block_scalars_are_text() {
        let many = "[".repeat(10_001);
        for document in [
            format!("a: \"{many}\"\n"),
            format!("a: '{many}'\n"),
            format!("a: x # {many}\n"),
            format!("a: |\n  {many}\n"),
            format!("a: >-\n  {many}\nb: 1\n"),
            format!("a: x{many}\n"),
        ] {
            assert_eq!(first_violation(document.as_bytes()), None, "{document:.30}");
        }
    }

    #[test]
    fn long_flat_documents_do_not_accumulate_depth() {
        let mut document = String::new();
        for index in 0..30_000 {
            document.push_str(&format!("key{index}:\n  - a\n  - b: [1, 2]\n"));
        }
        assert_eq!(first_violation(document.as_bytes()), None);
        let sequence = "- a\n".repeat(30_000);
        assert_eq!(first_violation(sequence.as_bytes()), None);
    }

    #[test]
    fn each_document_is_counted_on_its_own() {
        let mut document = b"a: 1\n---\n".to_vec();
        document.extend(flow(10_001));
        assert_eq!(first_violation(&document), None);
        assert!(violation_in_document(&document, 1).is_some());
        assert_eq!(violation_in_document(&document, 2), None);
        let mut earlier = flow(10_001);
        earlier.extend(b"---\na: 1\n");
        assert!(first_violation(&earlier).is_some());
        assert_eq!(violation_in_document(&earlier, 1), None);
        let mut ended = flow(10_000);
        ended.extend(b"...\n");
        ended.extend(flow(10_001));
        assert_eq!(first_violation(&ended), None);
        assert!(violation_in_document(&ended, 1).is_some());
        let mut leading = b"---\n".to_vec();
        leading.extend(flow(10_001));
        assert!(first_violation(&leading).is_some());
    }

    #[test]
    fn plain_scalars_continue_onto_deeper_indented_lines() {
        // The second line is a continuation of the plain scalar, not a
        // sequence entry.
        let mut document = String::from("a: text\n");
        for _ in 0..10_001 {
            document.push_str("  - more\n");
        }
        assert_eq!(first_violation(document.as_bytes()), None);
    }

    #[test]
    fn small_documents_are_not_scanned() {
        assert_eq!(first_violation(b"a: [[[[1]]]]\n"), None);
        assert_eq!(first_violation(b""), None);
    }
}
