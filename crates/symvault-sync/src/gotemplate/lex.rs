//! Port of `text/template/parse/lex.go` (Go 1.26): the pull lexer.

use super::gofmt::sprintf;
use super::gostr::{Bytes, decode_last_rune, decode_rune, index_of, is_digit, is_letter};
use super::value::Value;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ItemType {
    Error,
    Bool,
    Char,
    CharConstant,
    Comment,
    Complex,
    Assign,
    Declare,
    Eof,
    Field,
    Identifier,
    LeftDelim,
    LeftParen,
    Number,
    Pipe,
    RawString,
    RightDelim,
    RightParen,
    Space,
    String,
    Text,
    Variable,
    // Keywords appear after this.
    Keyword,
    Block,
    Break,
    Continue,
    Dot,
    Define,
    Else,
    End,
    If,
    Nil,
    Range,
    Template,
    With,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub typ: ItemType,
    pub pos: usize,
    pub val: Bytes,
    pub line: i64,
}

impl Item {
    pub fn eof_placeholder() -> Self {
        Item {
            typ: ItemType::Eof,
            pos: 0,
            val: Vec::new(),
            line: 0,
        }
    }

    /// `item.String()`, used as a `%s` operand in parse errors.
    pub fn string(&self) -> Bytes {
        match self.typ {
            ItemType::Eof => b"EOF".to_vec(),
            ItemType::Error => self.val.clone(),
            t if t > ItemType::Keyword => {
                let mut out = vec![b'<'];
                out.extend_from_slice(&self.val);
                out.push(b'>');
                out
            }
            _ if self.val.len() > 10 => sprintf(b"%.10q...", &[Value::Str(self.val.clone())]),
            _ => sprintf(b"%q", &[Value::Str(self.val.clone())]),
        }
    }
}

fn keyword(word: &[u8]) -> Option<ItemType> {
    Some(match word {
        b"." => ItemType::Dot,
        b"block" => ItemType::Block,
        b"break" => ItemType::Break,
        b"continue" => ItemType::Continue,
        b"define" => ItemType::Define,
        b"else" => ItemType::Else,
        b"end" => ItemType::End,
        b"if" => ItemType::If,
        b"range" => ItemType::Range,
        b"nil" => ItemType::Nil,
        b"template" => ItemType::Template,
        b"with" => ItemType::With,
        _ => return None,
    })
}

const EOF: i64 = -1;
const LEFT_DELIM: &[u8] = b"{{";
const RIGHT_DELIM: &[u8] = b"}}";
const LEFT_COMMENT: &[u8] = b"/*";
const RIGHT_COMMENT: &[u8] = b"*/";
const TRIM_MARKER_LEN: usize = 2;

#[derive(Clone, Copy)]
enum State {
    Text,
    LeftDelim,
    Comment,
    RightDelim,
    InsideAction,
    Space,
    Identifier,
    Field,
    Variable,
    Char,
    Number,
    Quote,
    RawQuote,
}

pub struct Lexer {
    input: Bytes,
    pos: usize,
    start: usize,
    at_eof: bool,
    paren_depth: i64,
    line: i64,
    start_line: i64,
    item: Item,
    inside_action: bool,
}

fn is_space(r: i64) -> bool {
    r == 0x20 || r == 0x09 || r == 0x0D || r == 0x0A
}

fn is_alpha_numeric(r: i64) -> bool {
    if r < 0 {
        return false;
    }
    let r = r as u32;
    r == u32::from(b'_') || is_letter(r) || is_digit(r)
}

fn has_left_trim_marker(s: &[u8]) -> bool {
    s.len() >= 2 && s[0] == b'-' && is_space(i64::from(s[1]))
}

fn has_right_trim_marker(s: &[u8]) -> bool {
    s.len() >= 2 && is_space(i64::from(s[0])) && s[1] == b'-'
}

fn trim_right_len(s: &[u8]) -> usize {
    s.len()
        - s.iter()
            .rposition(|&c| !is_space(i64::from(c)))
            .map_or(0, |i| i + 1)
}

fn trim_left_len(s: &[u8]) -> usize {
    s.iter().take_while(|&&c| is_space(i64::from(c))).count()
}

fn count_newlines(s: &[u8]) -> i64 {
    s.iter().filter(|&&c| c == b'\n').count() as i64
}

impl Lexer {
    pub fn new(input: &[u8]) -> Self {
        Lexer {
            input: input.to_vec(),
            pos: 0,
            start: 0,
            at_eof: false,
            paren_depth: 0,
            line: 1,
            start_line: 1,
            item: Item::eof_placeholder(),
            inside_action: false,
        }
    }

    fn next(&mut self) -> i64 {
        if self.pos >= self.input.len() {
            self.at_eof = true;
            return EOF;
        }
        let (r, w) = decode_rune(&self.input[self.pos..]);
        self.pos += w;
        if r == 0x0A {
            self.line += 1;
        }
        i64::from(r)
    }

    fn peek(&mut self) -> i64 {
        let r = self.next();
        self.backup();
        r
    }

    fn backup(&mut self) {
        if !self.at_eof && self.pos > 0 {
            let (r, w) = decode_last_rune(&self.input[..self.pos]);
            self.pos -= w;
            if r == 0x0A {
                self.line -= 1;
            }
        }
    }

    fn this_item(&mut self, t: ItemType) -> Item {
        let i = Item {
            typ: t,
            pos: self.start,
            val: self.input[self.start..self.pos].to_vec(),
            line: self.start_line,
        };
        self.start = self.pos;
        self.start_line = self.line;
        i
    }

    fn emit(&mut self, t: ItemType) -> Option<State> {
        let i = self.this_item(t);
        self.emit_item(i)
    }

    fn emit_item(&mut self, i: Item) -> Option<State> {
        self.item = i;
        None
    }

    fn ignore(&mut self) {
        self.line += count_newlines(&self.input[self.start..self.pos]);
        self.start = self.pos;
        self.start_line = self.line;
    }

    fn accept(&mut self, valid: &[u8]) -> bool {
        let r = self.next();
        if (0..0x80).contains(&r) && valid.contains(&(r as u8)) {
            return true;
        }
        self.backup();
        false
    }

    fn accept_run(&mut self, valid: &[u8]) {
        loop {
            let r = self.next();
            if !((0..0x80).contains(&r) && valid.contains(&(r as u8))) {
                break;
            }
        }
        self.backup();
    }

    fn errorf(&mut self, msg: Bytes) -> Option<State> {
        self.item = Item {
            typ: ItemType::Error,
            pos: self.start,
            val: msg,
            line: self.start_line,
        };
        self.start = 0;
        self.pos = 0;
        self.input.clear();
        None
    }

    pub fn next_item(&mut self) -> Item {
        self.item = Item {
            typ: ItemType::Eof,
            pos: self.pos,
            val: b"EOF".to_vec(),
            line: self.start_line,
        };
        let mut state = if self.inside_action {
            State::InsideAction
        } else {
            State::Text
        };
        loop {
            let next = match state {
                State::Text => self.lex_text(),
                State::LeftDelim => self.lex_left_delim(),
                State::Comment => self.lex_comment(),
                State::RightDelim => self.lex_right_delim(),
                State::InsideAction => self.lex_inside_action(),
                State::Space => self.lex_space(),
                State::Identifier => self.lex_identifier(),
                State::Field => self.lex_field_or_variable(ItemType::Field),
                State::Variable => self.lex_variable(),
                State::Char => self.lex_char(),
                State::Number => self.lex_number(),
                State::Quote => self.lex_quote(),
                State::RawQuote => self.lex_raw_quote(),
            };
            match next {
                Some(s) => state = s,
                None => return self.item.clone(),
            }
        }
    }

    fn lex_text(&mut self) -> Option<State> {
        if let Some(x) = index_of(&self.input[self.pos..], LEFT_DELIM) {
            if x > 0 {
                self.pos += x;
                let mut trim_length = 0;
                let delim_end = self.pos + LEFT_DELIM.len();
                if has_left_trim_marker(&self.input[delim_end..]) {
                    trim_length = trim_right_len(&self.input[self.start..self.pos]);
                }
                self.pos -= trim_length;
                self.line += count_newlines(&self.input[self.start..self.pos]);
                let i = self.this_item(ItemType::Text);
                self.pos += trim_length;
                self.ignore();
                if !i.val.is_empty() {
                    return self.emit_item(i);
                }
            }
            return Some(State::LeftDelim);
        }
        self.pos = self.input.len();
        if self.pos > self.start {
            self.line += count_newlines(&self.input[self.start..self.pos]);
            return self.emit(ItemType::Text);
        }
        self.emit(ItemType::Eof)
    }

    fn at_right_delim(&self) -> (bool, bool) {
        let rest = &self.input[self.pos..];
        if has_right_trim_marker(rest) && rest[TRIM_MARKER_LEN..].starts_with(RIGHT_DELIM) {
            return (true, true);
        }
        if rest.starts_with(RIGHT_DELIM) {
            return (true, false);
        }
        (false, false)
    }

    fn lex_left_delim(&mut self) -> Option<State> {
        self.pos += LEFT_DELIM.len();
        let trim_space = has_left_trim_marker(&self.input[self.pos..]);
        let after_marker = if trim_space { TRIM_MARKER_LEN } else { 0 };
        if self.input[self.pos + after_marker..].starts_with(LEFT_COMMENT) {
            self.pos += after_marker;
            self.ignore();
            return Some(State::Comment);
        }
        let i = self.this_item(ItemType::LeftDelim);
        self.inside_action = true;
        self.pos += after_marker;
        self.ignore();
        self.paren_depth = 0;
        self.emit_item(i)
    }

    fn lex_comment(&mut self) -> Option<State> {
        self.pos += LEFT_COMMENT.len();
        let Some(x) = index_of(&self.input[self.pos..], RIGHT_COMMENT) else {
            return self.errorf(b"unclosed comment".to_vec());
        };
        self.pos += x + RIGHT_COMMENT.len();
        let (delim, trim_space) = self.at_right_delim();
        if !delim {
            return self.errorf(b"comment ends before closing delimiter".to_vec());
        }
        self.line += count_newlines(&self.input[self.start..self.pos]);
        let _ = self.this_item(ItemType::Comment);
        if trim_space {
            self.pos += TRIM_MARKER_LEN;
        }
        self.pos += RIGHT_DELIM.len();
        if trim_space {
            self.pos += trim_left_len(&self.input[self.pos..]);
        }
        self.ignore();
        // Comments are not emitted (ParseComments is off).
        Some(State::Text)
    }

    fn lex_right_delim(&mut self) -> Option<State> {
        let (_, trim_space) = self.at_right_delim();
        if trim_space {
            self.pos += TRIM_MARKER_LEN;
            self.ignore();
        }
        self.pos += RIGHT_DELIM.len();
        let i = self.this_item(ItemType::RightDelim);
        if trim_space {
            self.pos += trim_left_len(&self.input[self.pos..]);
            self.ignore();
        }
        self.inside_action = false;
        self.emit_item(i)
    }

    fn lex_inside_action(&mut self) -> Option<State> {
        let (delim, _) = self.at_right_delim();
        if delim {
            if self.paren_depth == 0 {
                return Some(State::RightDelim);
            }
            return self.errorf(b"unclosed left paren".to_vec());
        }
        let r = self.next();
        if r == EOF {
            return self.errorf(b"unclosed action".to_vec());
        }
        if is_space(r) {
            self.backup();
            return Some(State::Space);
        }
        let c = if (0..0x80).contains(&r) { r as u8 } else { 0 };
        match r {
            _ if r == i64::from(b'=') => return self.emit(ItemType::Assign),
            _ if r == i64::from(b':') => {
                if self.next() != i64::from(b'=') {
                    return self.errorf(b"expected :=".to_vec());
                }
                return self.emit(ItemType::Declare);
            }
            _ if r == i64::from(b'|') => return self.emit(ItemType::Pipe),
            _ if r == i64::from(b'"') => return Some(State::Quote),
            _ if r == i64::from(b'`') => return Some(State::RawQuote),
            _ if r == i64::from(b'$') => return Some(State::Variable),
            _ if r == i64::from(b'\'') => return Some(State::Char),
            _ => {}
        }
        if r == i64::from(b'.') {
            if self.pos < self.input.len() {
                let nx = self.input[self.pos];
                if !nx.is_ascii_digit() {
                    return Some(State::Field);
                }
            }
            self.backup();
            return Some(State::Number);
        }
        if r == i64::from(b'+') || r == i64::from(b'-') || (c.is_ascii_digit() && r < 0x80) {
            self.backup();
            return Some(State::Number);
        }
        if is_alpha_numeric(r) {
            self.backup();
            return Some(State::Identifier);
        }
        if r == i64::from(b'(') {
            self.paren_depth += 1;
            return self.emit(ItemType::LeftParen);
        }
        if r == i64::from(b')') {
            self.paren_depth -= 1;
            if self.paren_depth < 0 {
                return self.errorf(b"unexpected right paren".to_vec());
            }
            return self.emit(ItemType::RightParen);
        }
        if (0x20..0x7F).contains(&r) {
            return self.emit(ItemType::Char);
        }
        let msg = sprintf(b"unrecognized character in action: %#U", &[Value::Int(r)]);
        self.errorf(msg)
    }

    fn lex_space(&mut self) -> Option<State> {
        let mut num_spaces = 0;
        loop {
            let r = self.peek();
            if !is_space(r) {
                break;
            }
            self.next();
            num_spaces += 1;
        }
        if has_right_trim_marker(&self.input[self.pos - 1..])
            && self.input[self.pos - 1 + TRIM_MARKER_LEN..].starts_with(RIGHT_DELIM)
        {
            self.backup();
            if num_spaces == 1 {
                return Some(State::RightDelim);
            }
        }
        self.emit(ItemType::Space)
    }

    fn lex_identifier(&mut self) -> Option<State> {
        loop {
            let r = self.next();
            if is_alpha_numeric(r) {
                continue;
            }
            self.backup();
            let word = self.input[self.start..self.pos].to_vec();
            if !self.at_terminator() {
                let msg = sprintf(b"bad character %#U", &[Value::Int(r)]);
                return self.errorf(msg);
            }
            if let Some(kw) = keyword(&word) {
                return self.emit(kw);
            }
            if word.first() == Some(&b'.') {
                return self.emit(ItemType::Field);
            }
            if word == b"true" || word == b"false" {
                return self.emit(ItemType::Bool);
            }
            return self.emit(ItemType::Identifier);
        }
    }

    fn lex_variable(&mut self) -> Option<State> {
        if self.at_terminator() {
            return self.emit(ItemType::Variable);
        }
        self.lex_field_or_variable(ItemType::Variable)
    }

    fn lex_field_or_variable(&mut self, typ: ItemType) -> Option<State> {
        if self.at_terminator() {
            if typ == ItemType::Variable {
                return self.emit(ItemType::Variable);
            }
            return self.emit(ItemType::Dot);
        }
        let mut r;
        loop {
            r = self.next();
            if !is_alpha_numeric(r) {
                self.backup();
                break;
            }
        }
        if !self.at_terminator() {
            let msg = sprintf(b"bad character %#U", &[Value::Int(r)]);
            return self.errorf(msg);
        }
        self.emit(typ)
    }

    fn at_terminator(&mut self) -> bool {
        let r = self.peek();
        if is_space(r) {
            return true;
        }
        if r == EOF
            || r == i64::from(b'.')
            || r == i64::from(b',')
            || r == i64::from(b'|')
            || r == i64::from(b':')
            || r == i64::from(b')')
            || r == i64::from(b'(')
        {
            return true;
        }
        self.input[self.pos..].starts_with(RIGHT_DELIM)
    }

    fn lex_char(&mut self) -> Option<State> {
        loop {
            let r = self.next();
            if r == i64::from(b'\\') {
                let r2 = self.next();
                if r2 != EOF && r2 != i64::from(b'\n') {
                    continue;
                }
                return self.errorf(b"unterminated character constant".to_vec());
            }
            if r == EOF || r == i64::from(b'\n') {
                return self.errorf(b"unterminated character constant".to_vec());
            }
            if r == i64::from(b'\'') {
                break;
            }
        }
        self.emit(ItemType::CharConstant)
    }

    fn lex_number(&mut self) -> Option<State> {
        if !self.scan_number() {
            let msg = sprintf(
                b"bad number syntax: %q",
                &[Value::Str(self.input[self.start..self.pos].to_vec())],
            );
            return self.errorf(msg);
        }
        let sign = self.peek();
        if sign == i64::from(b'+') || sign == i64::from(b'-') {
            if !self.scan_number() || self.input[self.pos - 1] != b'i' {
                let msg = sprintf(
                    b"bad number syntax: %q",
                    &[Value::Str(self.input[self.start..self.pos].to_vec())],
                );
                return self.errorf(msg);
            }
            return self.emit(ItemType::Complex);
        }
        self.emit(ItemType::Number)
    }

    fn scan_number(&mut self) -> bool {
        self.accept(b"+-");
        let mut digits: &[u8] = b"0123456789_";
        if self.accept(b"0") {
            if self.accept(b"xX") {
                digits = b"0123456789abcdefABCDEF_";
            } else if self.accept(b"oO") {
                digits = b"01234567_";
            } else if self.accept(b"bB") {
                digits = b"01_";
            }
        }
        self.accept_run(digits);
        if self.accept(b".") {
            self.accept_run(digits);
        }
        if digits.len() == 10 + 1 && self.accept(b"eE") {
            self.accept(b"+-");
            self.accept_run(b"0123456789_");
        }
        if digits.len() == 16 + 6 + 1 && self.accept(b"pP") {
            self.accept(b"+-");
            self.accept_run(b"0123456789_");
        }
        self.accept(b"i");
        if is_alpha_numeric(self.peek()) {
            self.next();
            return false;
        }
        true
    }

    fn lex_quote(&mut self) -> Option<State> {
        loop {
            let r = self.next();
            if r == i64::from(b'\\') {
                let r2 = self.next();
                if r2 != EOF && r2 != i64::from(b'\n') {
                    continue;
                }
                return self.errorf(b"unterminated quoted string".to_vec());
            }
            if r == EOF || r == i64::from(b'\n') {
                return self.errorf(b"unterminated quoted string".to_vec());
            }
            if r == i64::from(b'"') {
                break;
            }
        }
        self.emit(ItemType::String)
    }

    fn lex_raw_quote(&mut self) -> Option<State> {
        loop {
            let r = self.next();
            if r == EOF {
                return self.errorf(b"unterminated raw quoted string".to_vec());
            }
            if r == i64::from(b'`') {
                break;
            }
        }
        self.emit(ItemType::RawString)
    }
}
