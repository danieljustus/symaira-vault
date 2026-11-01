//! Interactive `add` form, ported from Go's `internal/ui/forms/add_form.go`
//! (a Bubble Tea model built from `textinput` and `textarea` widgets).
//!
//! The model ([`AddForm`]) is terminal-free so its state machine can be tested
//! directly; [`run_add_form`] drives it on a raw-mode inline terminal.
//!
//! Behaviour kept from the Go oracle (including its quirks):
//! * ten fields in fixed order; Tab/Shift+Tab/Enter navigate, Enter on the last
//!   field submits, Ctrl+C cancels (`canceled`), Esc is a no-op;
//! * Backspace/Ctrl+H on an empty field jumps to the previous field;
//! * Enter inside "Usage Hint" and "Notes" inserts a newline;
//! * password strength is advisory only (never blocks submit), `--force` hides it;
//! * typing a password auto-detects the secret type (when blank) and the usage
//!   hint (when blank); touching the type field refreshes a blank usage hint;
//! * stray cursor-blink ticks reach the focused widget like in Bubble Tea, which
//!   is observable through the usage-hint refresh above.
//!
//! Intentional difference: Go sets a `submitted` flag on Enter at the last field
//! and only quits on the *next* message (a blink tick or key press), so the
//! program can sit idle after Enter; this port submits immediately.

use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    queue,
    terminal::{disable_raw_mode, enable_raw_mode},
};
use serde_json::Value;
use symvault_core::password::assess_password_strength;
use symvault_store::{SecretType, detect_secret_type};
use zeroize::Zeroize;

const FIELD_USERNAME: usize = 0;
const FIELD_PASSWORD: usize = 1;
const FIELD_TYPE: usize = 2;
const FIELD_USAGE_HINT: usize = 3;
const FIELD_AUTO_ROTATE: usize = 4;
const FIELD_URL: usize = 5;
const FIELD_NOTES: usize = 6;
const FIELD_TOTP_SECRET: usize = 7;
const FIELD_TOTP_ISSUER: usize = 8;
const FIELD_TOTP_ACCOUNT: usize = 9;
const FIELD_COUNT: usize = 10;

/// Bubbles' default cursor blink period.
const BLINK_SPEED: Duration = Duration::from_millis(530);
/// Bubbles `textarea.DefaultMaxHeight`.
const TEXTAREA_MAX_HEIGHT: usize = 99;

/// Default values handed to the form (Go's `buildFormDefaults` map).
#[derive(Clone, Debug, Default)]
pub struct FormDefaults {
    pub username: String,
    pub url: String,
    pub notes: String,
    pub secret_type: String,
    pub usage_hint: String,
    pub auto_rotate: bool,
    /// Only honoured when `totp_secret` is non-empty.
    pub totp_secret: String,
    pub totp_issuer: String,
    pub totp_account: String,
}

/// Collected form output: entry data plus the secret metadata fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormResult {
    pub data: BTreeMap<String, Value>,
    pub secret_type: String,
    pub usage_hint: String,
    pub auto_rotate: bool,
}

/// What the form wants the driver to do after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Submit,
    Cancel,
}

fn is_space(c: char) -> bool {
    c.is_whitespace()
}

/// Mirrors `runeutil.Sanitizer`: drops U+FFFD and control characters, replaces
/// tabs and (when `newline` is `None`) newlines.
fn sanitize(input: &[char], tab: &str, newline: Option<&str>) -> Vec<char> {
    let mut out = Vec::with_capacity(input.len());
    for &c in input {
        match c {
            '\u{FFFD}' => {}
            '\r' | '\n' => out.extend(newline.unwrap_or("\n").chars()),
            '\t' => out.extend(tab.chars()),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Single-line input (bubbles/textinput)
// ---------------------------------------------------------------------------

struct TextInput {
    value: Vec<char>,
    pos: usize,
    char_limit: usize,
    password: bool,
    placeholder: &'static str,
    focused: bool,
}

impl TextInput {
    fn new(placeholder: &'static str, char_limit: usize) -> Self {
        Self {
            value: Vec::new(),
            pos: 0,
            char_limit,
            password: false,
            placeholder,
            focused: false,
        }
    }

    fn text(&self) -> String {
        self.value.iter().collect()
    }

    fn set_value(&mut self, s: &str) {
        let runes = sanitize(&s.chars().collect::<Vec<_>>(), " ", Some(" "));
        let empty = self.value.is_empty();
        self.value = if self.char_limit > 0 && runes.len() > self.char_limit {
            runes[..self.char_limit].to_vec()
        } else {
            runes
        };
        if (self.pos == 0 && empty) || self.pos > self.value.len() {
            self.pos = self.value.len();
        }
    }

    fn set_cursor(&mut self, pos: usize) {
        self.pos = pos.min(self.value.len());
    }

    fn insert(&mut self, runes: &[char]) {
        let paste = sanitize(runes, " ", Some(" "));
        let mut paste = paste;
        if self.char_limit > 0 {
            let avail = self.char_limit.saturating_sub(self.value.len());
            if avail == 0 {
                return;
            }
            paste.truncate(avail);
        }
        let tail = self.value.split_off(self.pos);
        self.pos += paste.len();
        self.value.extend(paste);
        self.value.extend(tail);
    }

    fn delete_before_cursor(&mut self) {
        self.value.drain(..self.pos);
        self.pos = 0;
    }

    fn delete_after_cursor(&mut self) {
        self.value.truncate(self.pos);
        self.pos = self.value.len();
    }

    fn delete_word_backward(&mut self) {
        if self.pos == 0 || self.value.is_empty() {
            return;
        }
        if self.password {
            self.delete_before_cursor();
            return;
        }
        let old = self.pos;
        self.set_cursor(self.pos - 1);
        while is_space(self.value[self.pos]) {
            if self.pos == 0 {
                break;
            }
            self.set_cursor(self.pos - 1);
        }
        while self.pos > 0 {
            if !is_space(self.value[self.pos]) {
                self.set_cursor(self.pos - 1);
            } else {
                self.set_cursor(self.pos + 1);
                break;
            }
        }
        if old > self.value.len() {
            self.value.truncate(self.pos);
        } else {
            self.value.drain(self.pos..old);
        }
    }

    fn delete_word_forward(&mut self) {
        if self.pos >= self.value.len() || self.value.is_empty() {
            return;
        }
        if self.password {
            self.delete_after_cursor();
            return;
        }
        let old = self.pos;
        self.set_cursor(self.pos + 1);
        while self.pos < self.value.len() && is_space(self.value[self.pos]) {
            self.set_cursor(self.pos + 1);
            if self.pos >= self.value.len() {
                break;
            }
        }
        while self.pos < self.value.len() {
            if !is_space(self.value[self.pos]) {
                self.set_cursor(self.pos + 1);
            } else {
                break;
            }
        }
        if self.pos > self.value.len() {
            self.value.truncate(old);
        } else {
            self.value.drain(old..self.pos);
        }
        self.set_cursor(old);
    }

    fn word_backward(&mut self) {
        if self.pos == 0 || self.value.is_empty() {
            return;
        }
        if self.password {
            self.pos = 0;
            return;
        }
        let mut i = self.pos as isize - 1;
        while i >= 0 && is_space(self.value[i as usize]) {
            self.set_cursor(self.pos - 1);
            i -= 1;
        }
        while i >= 0 && !is_space(self.value[i as usize]) {
            self.set_cursor(self.pos - 1);
            i -= 1;
        }
    }

    fn word_forward(&mut self) {
        if self.pos >= self.value.len() || self.value.is_empty() {
            return;
        }
        if self.password {
            self.pos = self.value.len();
            return;
        }
        let mut i = self.pos;
        while i < self.value.len() && is_space(self.value[i]) {
            self.set_cursor(self.pos + 1);
            i += 1;
        }
        while i < self.value.len() && !is_space(self.value[i]) {
            self.set_cursor(self.pos + 1);
            i += 1;
        }
    }

    /// Applies one key; returns whether the cursor position changed (which
    /// restarts the widget's blink timer in Bubble Tea).
    fn update(&mut self, name: &str, runes: &[char]) -> bool {
        let old = self.pos;
        match name {
            "alt+backspace" | "ctrl+w" => self.delete_word_backward(),
            "backspace" | "ctrl+h" => {
                if !self.value.is_empty() && self.pos > 0 {
                    self.value.remove(self.pos - 1);
                    self.pos -= 1;
                }
            }
            "alt+left" | "ctrl+left" | "alt+b" => self.word_backward(),
            "left" | "ctrl+b" => {
                if self.pos > 0 {
                    self.pos -= 1;
                }
            }
            "alt+right" | "ctrl+right" | "alt+f" => self.word_forward(),
            "right" | "ctrl+f" => {
                if self.pos < self.value.len() {
                    self.pos += 1;
                }
            }
            "home" | "ctrl+a" => self.pos = 0,
            "delete" | "ctrl+d" => {
                if !self.value.is_empty() && self.pos < self.value.len() {
                    self.value.remove(self.pos);
                }
            }
            "end" | "ctrl+e" => self.pos = self.value.len(),
            "ctrl+k" => self.delete_after_cursor(),
            "ctrl+u" => self.delete_before_cursor(),
            // Paste reads the OS clipboard in Go; bracketed paste is not wired here.
            "ctrl+v" => {}
            "alt+delete" | "alt+d" => self.delete_word_forward(),
            // Suggestion navigation: no suggestions configured.
            "down" | "ctrl+n" | "up" | "ctrl+p" => {}
            _ => self.insert(runes),
        }
        self.pos != old
    }

    fn view(&self, cursor_on: bool) -> String {
        let reverse = |c: char| format!("\x1b[7m{c}\x1b[0m");
        let gray = |s: &str| format!("\x1b[38;5;240m{s}\x1b[0m");
        if self.value.is_empty() {
            let mut chars = self.placeholder.chars();
            let first = chars.next();
            let rest: String = chars.collect();
            let head = match (first, self.focused && cursor_on) {
                (Some(c), true) => reverse(c),
                (Some(c), false) => gray(&c.to_string()),
                (None, _) => String::new(),
            };
            return format!("> {head}{}", gray(&rest));
        }
        let shown: Vec<char> = if self.password {
            vec!['\u{2022}'; self.value.len()]
        } else {
            self.value.clone()
        };
        let before: String = shown[..self.pos].iter().collect();
        let after: String = if self.pos < shown.len() {
            shown[self.pos + 1..].iter().collect()
        } else {
            String::new()
        };
        let at = if self.focused && cursor_on {
            reverse(shown.get(self.pos).copied().unwrap_or(' '))
        } else {
            shown.get(self.pos).map(char::to_string).unwrap_or_default()
        };
        format!("> {before}{at}{after}")
    }
}

impl Drop for TextInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Multi-line input (bubbles/textarea)
// ---------------------------------------------------------------------------

struct TextArea {
    lines: Vec<Vec<char>>,
    row: usize,
    col: usize,
    char_limit: usize,
    height: usize,
    placeholder: &'static str,
    focused: bool,
}

impl TextArea {
    fn new(placeholder: &'static str, height: usize, char_limit: usize) -> Self {
        Self {
            lines: vec![Vec::new()],
            row: 0,
            col: 0,
            char_limit,
            height,
            placeholder,
            focused: false,
        }
    }

    fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn is_empty(&self) -> bool {
        self.text().is_empty()
    }

    /// Go's `Length()`: characters plus one per line break.
    fn length(&self) -> usize {
        self.lines.iter().map(Vec::len).sum::<usize>() + self.lines.len() - 1
    }

    fn set_value(&mut self, s: &str) {
        self.lines = vec![Vec::new()];
        self.row = 0;
        self.col = 0;
        self.insert(&s.chars().collect::<Vec<_>>());
    }

    fn insert(&mut self, runes: &[char]) {
        let mut runes = sanitize(runes, "    ", None);
        if self.char_limit > 0 {
            let avail = self.char_limit as isize - self.length() as isize;
            if avail <= 0 {
                return;
            }
            runes.truncate(avail as usize);
        }
        let mut new_lines: Vec<Vec<char>> =
            runes.split(|c| *c == '\n').map(<[char]>::to_vec).collect();
        if new_lines.is_empty() {
            return;
        }
        // Obey the maximum line limit like bubbles' `maxLines` (10000).
        let max_lines = 10_000usize;
        if self.lines.len() + new_lines.len() - 1 > max_lines {
            let allowed = max_lines.saturating_sub(self.lines.len()) + 1;
            new_lines.truncate(allowed);
        }
        let tail = self.lines[self.row].split_off(self.col);
        let first = new_lines.remove(0);
        self.col += first.len();
        self.lines[self.row].extend(first);
        for line in new_lines {
            self.row += 1;
            self.col = line.len();
            self.lines.insert(self.row, line);
        }
        self.lines[self.row].extend(tail);
        self.col = self.col.min(self.lines[self.row].len());
    }

    fn row_len(&self) -> usize {
        self.lines[self.row].len()
    }

    fn merge_line_below(&mut self, row: usize) {
        if row + 1 >= self.lines.len() {
            return;
        }
        let next = self.lines.remove(row + 1);
        self.lines[row].extend(next);
    }

    fn merge_line_above(&mut self, row: usize) {
        if row == 0 {
            return;
        }
        self.col = self.lines[row - 1].len();
        self.row -= 1;
        let cur = self.lines.remove(row);
        self.lines[row - 1].extend(cur);
    }

    fn character_right(&mut self) {
        if self.col < self.row_len() {
            self.col += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = 0;
        }
    }

    fn character_left(&mut self, inside_line: bool) {
        if self.col == 0 && self.row != 0 {
            self.row -= 1;
            self.col = self.row_len();
            if !inside_line {
                return;
            }
        }
        if self.col > 0 {
            self.col -= 1;
        }
    }

    fn word_left(&mut self) {
        loop {
            self.character_left(true);
            if self.col < self.row_len() && !is_space(self.lines[self.row][self.col]) {
                break;
            }
            if self.row == 0 && self.col == 0 {
                break;
            }
        }
        while self.col > 0 {
            if is_space(self.lines[self.row][self.col - 1]) {
                break;
            }
            self.col -= 1;
        }
    }

    fn do_word_right(&mut self, mut f: impl FnMut(&mut Vec<char>, usize, usize)) {
        while self.col >= self.row_len() || is_space(self.lines[self.row][self.col]) {
            if self.row + 1 == self.lines.len() && self.col == self.row_len() {
                break;
            }
            self.character_right();
        }
        let mut idx = 0;
        while self.col < self.row_len() {
            if is_space(self.lines[self.row][self.col]) {
                break;
            }
            let col = self.col;
            f(&mut self.lines[self.row], idx, col);
            self.col += 1;
            idx += 1;
        }
    }

    fn delete_word_left(&mut self) {
        if self.col == 0 || self.row_len() == 0 {
            return;
        }
        let old = self.col;
        self.col -= 1;
        while is_space(self.lines[self.row][self.col]) {
            if self.col == 0 {
                break;
            }
            self.col -= 1;
        }
        while self.col > 0 {
            if !is_space(self.lines[self.row][self.col]) {
                self.col -= 1;
            } else {
                self.col += 1;
                break;
            }
        }
        if old > self.row_len() {
            let col = self.col;
            self.lines[self.row].truncate(col);
        } else {
            let col = self.col;
            self.lines[self.row].drain(col..old);
        }
    }

    fn delete_word_right(&mut self) {
        if self.col >= self.row_len() || self.row_len() == 0 {
            return;
        }
        let old = self.col;
        while self.col < self.row_len() && is_space(self.lines[self.row][self.col]) {
            self.col += 1;
        }
        while self.col < self.row_len() {
            if !is_space(self.lines[self.row][self.col]) {
                self.col += 1;
            } else {
                break;
            }
        }
        let col = self.col;
        if col > self.row_len() {
            self.lines[self.row].truncate(old);
        } else {
            self.lines[self.row].drain(old..col);
        }
        self.col = old.min(self.row_len());
    }

    fn transpose_left(&mut self) {
        if self.col == 0 || self.row_len() < 2 {
            return;
        }
        if self.col >= self.row_len() {
            self.col -= 1;
        }
        let col = self.col;
        self.lines[self.row].swap(col - 1, col);
        if self.col < self.row_len() {
            self.col += 1;
        }
    }

    /// Applies one key; returns whether the cursor moved or text changed
    /// position (blink restart in Bubble Tea).
    fn update(&mut self, name: &str, runes: &[char]) -> bool {
        let (old_row, old_col) = (self.row, self.col);
        self.col = self.col.min(self.row_len());
        match name {
            "ctrl+k" => {
                if self.col >= self.row_len() {
                    self.merge_line_below(self.row);
                } else {
                    let col = self.col;
                    self.lines[self.row].truncate(col);
                    self.col = self.row_len();
                }
            }
            "ctrl+u" => {
                if self.col == 0 {
                    self.merge_line_above(self.row);
                } else {
                    let col = self.col;
                    self.lines[self.row].drain(..col);
                    self.col = 0;
                }
            }
            "backspace" | "ctrl+h" => {
                if self.col == 0 {
                    self.merge_line_above(self.row);
                } else if self.row_len() > 0 {
                    let col = self.col;
                    self.lines[self.row].remove(col - 1);
                    self.col -= 1;
                }
            }
            "delete" | "ctrl+d" => {
                if self.row_len() > 0 && self.col < self.row_len() {
                    let col = self.col;
                    self.lines[self.row].remove(col);
                }
                if self.col >= self.row_len() {
                    self.merge_line_below(self.row);
                }
            }
            "alt+backspace" | "ctrl+w" => {
                if self.col == 0 {
                    self.merge_line_above(self.row);
                } else {
                    self.delete_word_left();
                }
            }
            "alt+delete" | "alt+d" => {
                if self.col >= self.row_len() {
                    self.merge_line_below(self.row);
                } else {
                    self.delete_word_right();
                }
            }
            "enter" | "ctrl+m" => {
                if self.lines.len() >= TEXTAREA_MAX_HEIGHT {
                    return false;
                }
                let tail = self.lines[self.row].split_off(self.col);
                self.lines.insert(self.row + 1, tail);
                self.col = 0;
                self.row += 1;
            }
            "end" | "ctrl+e" => self.col = self.row_len(),
            "home" | "ctrl+a" => self.col = 0,
            "right" | "ctrl+f" => self.character_right(),
            "down" | "ctrl+n" => {
                // Logical-line approximation of Bubble's soft-wrapped movement.
                if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = self.col.min(self.row_len());
                } else {
                    self.col = self.row_len();
                }
            }
            "alt+right" | "alt+f" => self.do_word_right(|_, _, _| {}),
            "ctrl+v" => {}
            "left" | "ctrl+b" => self.character_left(false),
            "up" | "ctrl+p" => {
                if self.row > 0 {
                    self.row -= 1;
                    self.col = self.col.min(self.row_len());
                } else {
                    self.col = 0;
                }
            }
            "alt+left" | "alt+b" => self.word_left(),
            "alt+<" | "ctrl+home" => {
                self.row = 0;
                self.col = 0;
            }
            "alt+>" | "ctrl+end" => {
                self.row = self.lines.len() - 1;
                self.col = self.row_len();
            }
            "alt+l" => self.do_word_right(|line, _, i| {
                line[i] = line[i].to_lowercase().next().unwrap_or(line[i]);
            }),
            "alt+u" => self.do_word_right(|line, _, i| {
                line[i] = line[i].to_uppercase().next().unwrap_or(line[i]);
            }),
            "alt+c" => self.do_word_right(|line, idx, i| {
                if idx == 0 {
                    line[i] = line[i].to_uppercase().next().unwrap_or(line[i]);
                }
            }),
            "ctrl+t" => self.transpose_left(),
            _ => self.insert(runes),
        }
        (self.row, self.col) != (old_row, old_col)
    }

    fn view(&self, cursor_on: bool) -> Vec<String> {
        let gray = |s: &str| format!("\x1b[38;5;240m{s}\x1b[0m");
        let mut out = Vec::with_capacity(self.height);
        if self.is_empty() {
            let mut chars = self.placeholder.chars();
            let first = chars.next();
            let rest: String = chars.collect();
            let head = match (first, self.focused && cursor_on) {
                (Some(c), true) => format!("\x1b[7m{c}\x1b[0m"),
                (Some(c), false) => gray(&c.to_string()),
                (None, _) => String::new(),
            };
            out.push(format!("\u{2503} {head}{}", gray(&rest)));
            while out.len() < self.height {
                out.push("\u{2503}".to_owned());
            }
            return out;
        }
        // Keep the cursor row inside the `height`-line window.
        let first = (self.row + 1).saturating_sub(self.height);
        for (i, line) in self.lines.iter().enumerate().skip(first).take(self.height) {
            let mut text = String::new();
            for (c, ch) in line.iter().enumerate() {
                if self.focused && cursor_on && i == self.row && c == self.col {
                    text.push_str(&format!("\x1b[7m{ch}\x1b[0m"));
                } else {
                    text.push(*ch);
                }
            }
            if self.focused && cursor_on && i == self.row && self.col >= line.len() {
                text.push_str("\x1b[7m \x1b[0m");
            }
            out.push(format!("\u{2503} {text}"));
        }
        while out.len() < self.height {
            out.push("\u{2503}".to_owned());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Form model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Tick {
    due: Instant,
    field: usize,
}

pub struct AddForm {
    username: TextInput,
    password: TextInput,
    secret_type: TextInput,
    usage_hint: TextArea,
    auto_rotate: TextInput,
    url: TextInput,
    notes: TextArea,
    totp_secret: TextInput,
    totp_issuer: TextInput,
    totp_account: TextInput,
    focused: usize,
    force: bool,
    canceled: bool,
    password_err: Option<String>,
    width: u16,
    ticks: Vec<Tick>,
}

/// Go's `UsageHintForType`.
///
/// `SecretType::usage_hint` in `symvault-store` stores a literal run of
/// asterisks where Go has the `<token>`, `<key>` and `<encoded>` placeholders
/// (three hints), so those are restated here until the store is corrected.
pub fn usage_hint_for(secret_type: SecretType) -> &'static str {
    match secret_type {
        SecretType::ApiKey => {
            "Set as header or query parameter depending on API documentation. Common: X-API-Key: <key> or ?api_key=<key>"
        }
        SecretType::BearerToken => "Set Header Authorization: Bearer <token>",
        SecretType::BasicAuth => {
            "Encode as base64(user:pass) and set Header Authorization: Basic <encoded>"
        }
        other => other.usage_hint(),
    }
}

pub fn secret_type_from_string(s: &str) -> SecretType {
    SecretType::from_name(&s.to_lowercase()).unwrap_or(SecretType::Custom)
}

fn secret_type_icon(t: SecretType) -> &'static str {
    match t {
        SecretType::ApiKey => "\u{1F511}",
        SecretType::BearerToken => "\u{1F3AB}",
        SecretType::BasicAuth => "\u{1F510}",
        SecretType::SshKey => "\u{1F512}",
        SecretType::Password => "\u{1F5DD}\u{FE0F}",
        SecretType::Certificate => "\u{1F4DC}",
        SecretType::DatabaseUrl => "\u{1F5C4}\u{FE0F}",
        SecretType::TotpSeed => "\u{23F1}\u{FE0F}",
        SecretType::Payment => "\u{1F4B3}",
        SecretType::Custom => "\u{1F4E6}",
    }
}

/// `key.String()` as Bubble Tea names it, for the subset of keys that matter.
fn key_name(ev: &KeyEvent) -> String {
    let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
    let alt = ev.modifiers.contains(KeyModifiers::ALT);
    let shift = ev.modifiers.contains(KeyModifiers::SHIFT);
    let with_mods = |base: &str| -> String {
        let mut s = String::new();
        if ctrl {
            s.push_str("ctrl+");
        }
        if alt {
            s.push_str("alt+");
        }
        if shift && !matches!(base, "tab") {
            s.push_str("shift+");
        }
        s.push_str(base);
        s
    };
    match ev.code {
        KeyCode::Char(c) => {
            if ctrl {
                with_mods(&c.to_ascii_lowercase().to_string())
            } else if alt {
                format!("alt+{c}")
            } else {
                c.to_string()
            }
        }
        KeyCode::Enter => with_mods("enter"),
        KeyCode::Tab => with_mods("tab"),
        KeyCode::BackTab => "shift+tab".to_owned(),
        KeyCode::Backspace => with_mods("backspace"),
        KeyCode::Delete => with_mods("delete"),
        KeyCode::Left => with_mods("left"),
        KeyCode::Right => with_mods("right"),
        KeyCode::Up => with_mods("up"),
        KeyCode::Down => with_mods("down"),
        KeyCode::Home => with_mods("home"),
        KeyCode::End => with_mods("end"),
        KeyCode::Esc => with_mods("esc"),
        KeyCode::PageUp => with_mods("pgup"),
        KeyCode::PageDown => with_mods("pgdown"),
        _ => String::from("unknown"),
    }
}

fn key_runes(ev: &KeyEvent) -> Vec<char> {
    match ev.code {
        KeyCode::Char(c) if !ev.modifiers.contains(KeyModifiers::CONTROL) => vec![c],
        _ => Vec::new(),
    }
}

impl AddForm {
    /// Go's `NewAddEntryForm`.
    pub fn new(force: bool) -> Self {
        let mut password = TextInput::new("required", 1024);
        password.password = true;
        let mut auto_rotate = TextInput::new("no", 3);
        auto_rotate.set_value("no");
        let mut form = Self {
            username: TextInput::new("optional", 256),
            password,
            secret_type: TextInput::new("auto-detect", 32),
            usage_hint: TextArea::new("auto-generated from type", 2, 512),
            auto_rotate,
            url: TextInput::new("optional", 2048),
            notes: TextArea::new("optional", 3, 4096),
            totp_secret: TextInput::new("optional", 256),
            totp_issuer: TextInput::new("optional", 256),
            totp_account: TextInput::new("optional", 256),
            focused: 0,
            force,
            canceled: false,
            password_err: None,
            width: 0,
            ticks: Vec::new(),
        };
        form.focus_field(0);
        form
    }

    /// Go's `SetDefaults` over the typed [`FormDefaults`].
    pub fn set_defaults(&mut self, d: &FormDefaults) {
        if !d.username.is_empty() {
            self.username.set_value(&d.username);
        }
        if !d.secret_type.is_empty() {
            self.secret_type.set_value(&d.secret_type);
            self.update_usage_hint_from_type();
        }
        if !d.usage_hint.is_empty() {
            self.usage_hint.set_value(&d.usage_hint);
        }
        if d.auto_rotate {
            self.auto_rotate.set_value("yes");
        }
        if !d.url.is_empty() {
            self.url.set_value(&d.url);
        }
        if !d.notes.is_empty() {
            self.notes.set_value(&d.notes);
        }
        if !d.totp_secret.is_empty() {
            self.totp_secret.set_value(&d.totp_secret);
            if !d.totp_issuer.is_empty() {
                self.totp_issuer.set_value(&d.totp_issuer);
            }
            if !d.totp_account.is_empty() {
                self.totp_account.set_value(&d.totp_account);
            }
        }
    }

    /// Starts the blink chain that Bubble Tea's `Init` kicks off on the first field.
    pub fn start(&mut self, now: Instant) {
        self.ticks.push(Tick {
            due: now + BLINK_SPEED,
            field: FIELD_USERNAME,
        });
    }

    /// Test-facing accessor.
    #[allow(dead_code)]
    pub fn canceled(&self) -> bool {
        self.canceled
    }

    /// Test-facing accessor.
    #[allow(dead_code)]
    pub fn focused_field(&self) -> usize {
        self.focused
    }

    pub fn set_width(&mut self, width: u16) {
        self.width = width;
    }

    fn auto_detect_type(&mut self, password: &str) {
        if !self.secret_type.value.is_empty() {
            return;
        }
        let detected = detect_secret_type(password);
        self.secret_type.set_value(detected.as_str());
        self.update_usage_hint_from_type();
    }

    fn update_usage_hint_from_type(&mut self) {
        if !self.usage_hint.is_empty() {
            return;
        }
        let hint = usage_hint_for(secret_type_from_string(&self.secret_type.text()));
        if !hint.is_empty() {
            self.usage_hint.set_value(hint);
        }
    }

    fn validate_password(&mut self) {
        let password = self.password.text();
        self.password_err = None;
        if password.is_empty() || self.force {
            return;
        }
        let strength = assess_password_strength(&password);
        if strength.weak {
            self.password_err = Some(format!(
                "{} (weak \u{2014} press Enter to continue)",
                strength.message
            ));
        }
    }

    fn focus_field(&mut self, idx: usize) {
        self.focused = idx;
        self.username.focused = idx == FIELD_USERNAME;
        self.password.focused = idx == FIELD_PASSWORD;
        self.secret_type.focused = idx == FIELD_TYPE;
        self.usage_hint.focused = idx == FIELD_USAGE_HINT;
        self.auto_rotate.focused = idx == FIELD_AUTO_ROTATE;
        self.url.focused = idx == FIELD_URL;
        self.notes.focused = idx == FIELD_NOTES;
        self.totp_secret.focused = idx == FIELD_TOTP_SECRET;
        self.totp_issuer.focused = idx == FIELD_TOTP_ISSUER;
        self.totp_account.focused = idx == FIELD_TOTP_ACCOUNT;
    }

    fn next_field(&mut self) {
        if self.focused < FIELD_COUNT - 1 {
            self.focus_field(self.focused + 1);
        }
    }

    fn prev_field(&mut self) {
        if self.focused > 0 {
            self.focus_field(self.focused - 1);
        }
    }

    fn is_field_empty(&self) -> bool {
        let input = |t: &TextInput| t.value.is_empty() && t.pos == 0;
        match self.focused {
            FIELD_USERNAME => input(&self.username),
            FIELD_PASSWORD => input(&self.password),
            FIELD_TYPE => input(&self.secret_type),
            FIELD_USAGE_HINT => self.usage_hint.is_empty(),
            FIELD_AUTO_ROTATE => input(&self.auto_rotate),
            FIELD_URL => input(&self.url),
            FIELD_NOTES => self.notes.is_empty(),
            FIELD_TOTP_SECRET => input(&self.totp_secret),
            FIELD_TOTP_ISSUER => input(&self.totp_issuer),
            FIELD_TOTP_ACCOUNT => input(&self.totp_account),
            _ => false,
        }
    }

    /// Delivers a message to the focused widget the way Bubble Tea's `Update`
    /// does after the key special-cases; `key` is `None` for non-key messages
    /// (blink ticks).
    fn route(&mut self, key: Option<(&str, &[char])>) -> bool {
        let (name, runes) = key.unwrap_or(("", &[]));
        let is_key = key.is_some();
        let mut moved = false;
        macro_rules! input {
            ($f:expr) => {
                if is_key {
                    moved = $f.update(name, runes);
                }
            };
        }
        match self.focused {
            FIELD_USERNAME => input!(self.username),
            FIELD_PASSWORD => {
                input!(self.password);
                self.validate_password();
                let password = self.password.text();
                if !password.is_empty() {
                    self.auto_detect_type(&password);
                }
            }
            FIELD_TYPE => {
                input!(self.secret_type);
                self.update_usage_hint_from_type();
            }
            FIELD_USAGE_HINT => {
                if is_key {
                    moved = self.usage_hint.update(name, runes);
                }
            }
            FIELD_AUTO_ROTATE => input!(self.auto_rotate),
            FIELD_URL => input!(self.url),
            FIELD_NOTES => {
                if is_key {
                    moved = self.notes.update(name, runes);
                }
            }
            FIELD_TOTP_SECRET => input!(self.totp_secret),
            FIELD_TOTP_ISSUER => input!(self.totp_issuer),
            FIELD_TOTP_ACCOUNT => input!(self.totp_account),
            _ => {}
        }
        moved
    }

    /// Handles one key event (Go's `Update` for `tea.KeyMsg`).
    pub fn key(&mut self, ev: &KeyEvent, now: Instant) -> Flow {
        self.input(&key_name(ev), &key_runes(ev), now)
    }

    /// Handles a run of printable characters delivered as a single message.
    /// Bubble Tea groups the plain runes of one terminal read (typed fast or
    /// pasted) into one `KeyRunes` message, so password auto-detection sees
    /// the whole run at once; the message's name is the text itself.
    pub fn text(&mut self, runes: &[char], now: Instant) -> Flow {
        let name: String = runes.iter().collect();
        self.input(&name, runes, now)
    }

    fn input(&mut self, name: &str, runes: &[char], now: Instant) -> Flow {
        match name {
            "ctrl+c" => {
                self.canceled = true;
                return Flow::Cancel;
            }
            "tab" => {
                self.next_field();
                return Flow::Continue;
            }
            "shift+tab" => {
                self.prev_field();
                return Flow::Continue;
            }
            "enter" => {
                if self.focused != FIELD_USAGE_HINT && self.focused != FIELD_NOTES {
                    if self.focused == FIELD_COUNT - 1 {
                        return Flow::Submit;
                    }
                    self.next_field();
                    return Flow::Continue;
                }
                // Textareas take Enter as a newline; fall through to routing.
            }
            "backspace" | "ctrl+h" if self.is_field_empty() => {
                self.prev_field();
                return Flow::Continue;
            }
            _ => {}
        }
        if self.route(Some((name, runes))) {
            // A moved cursor restarts that widget's blink timer.
            let field = self.focused;
            self.ticks.retain(|t| t.field != field);
            self.ticks.push(Tick {
                due: now + BLINK_SPEED,
                field,
            });
        }
        Flow::Continue
    }

    /// Next instant a blink tick is due, if any.
    pub fn next_tick(&self) -> Option<Instant> {
        self.ticks.iter().map(|t| t.due).min()
    }

    /// Delivers all due blink ticks. A tick keeps blinking only while its
    /// widget is still focused; otherwise the chain ends after this message,
    /// but the message itself still reaches the focused widget.
    pub fn run_due_ticks(&mut self, now: Instant) {
        while let Some(idx) = self.ticks.iter().position(|t| t.due <= now) {
            let tick = self.ticks.remove(idx);
            self.route(None);
            if tick.field == self.focused {
                self.ticks.push(Tick {
                    due: tick.due + BLINK_SPEED,
                    field: tick.field,
                });
            }
        }
    }

    /// Go's `Data()`.
    pub fn data(&self) -> BTreeMap<String, Value> {
        let mut data = BTreeMap::new();
        let username = self.username.text().trim().to_owned();
        if !username.is_empty() {
            data.insert("username".to_owned(), Value::String(username));
        }
        let password = self.password.text();
        if !password.is_empty() {
            data.insert("password".to_owned(), Value::String(password));
        }
        let url = self.url.text().trim().to_owned();
        if !url.is_empty() {
            data.insert("url".to_owned(), Value::String(url));
        }
        let notes = self.notes.text().trim().to_owned();
        if !notes.is_empty() {
            data.insert("notes".to_owned(), Value::String(notes));
        }
        let secret = self.totp_secret.text().trim().to_owned();
        if !secret.is_empty() {
            let mut totp = serde_json::Map::new();
            totp.insert("secret".to_owned(), Value::String(secret));
            let issuer = self.totp_issuer.text().trim().to_owned();
            if !issuer.is_empty() {
                totp.insert("issuer".to_owned(), Value::String(issuer));
            }
            let account = self.totp_account.text().trim().to_owned();
            if !account.is_empty() {
                totp.insert("account_name".to_owned(), Value::String(account));
            }
            data.insert("totp".to_owned(), Value::Object(totp));
        }
        data
    }

    /// Go's `SecretMetadata()`, flattened into [`FormResult`].
    pub fn result(&self) -> FormResult {
        let secret_type = self.secret_type.text();
        FormResult {
            data: self.data(),
            secret_type: if secret_type.is_empty() {
                String::new()
            } else {
                secret_type_from_string(&secret_type).as_str().to_owned()
            },
            usage_hint: self.usage_hint.text(),
            auto_rotate: self.auto_rotate.text() == "yes",
        }
    }

    /// Renders the form as terminal lines (no trailing newline).
    pub fn view(&self, now: Instant) -> Vec<String> {
        // Bubbles toggles the cursor every blink period; the exact phase is not
        // observable state, so keep it solid.
        let _ = now;
        let cursor_on = true;
        let bold = |code: &str, s: &str| format!("\x1b[1;38;5;{code}m{s}\x1b[0m");
        let mut lines = vec![bold("212", "Add New Entry"), String::new()];
        let selected = secret_type_from_string(&self.secret_type.text());
        let type_view = format!(
            "{} \x1b[1;38;5;39m{} {}\x1b[0m",
            self.secret_type.view(cursor_on),
            secret_type_icon(selected),
            selected.as_str()
        );
        let fields: Vec<(&str, Vec<String>)> = vec![
            ("Username", vec![self.username.view(cursor_on)]),
            ("Password", vec![self.password.view(cursor_on)]),
            ("Type", vec![type_view]),
            ("Usage Hint", self.usage_hint.view(cursor_on)),
            ("Auto Rotate", vec![self.auto_rotate.view(cursor_on)]),
            ("URL", vec![self.url.view(cursor_on)]),
            ("Notes", self.notes.view(cursor_on)),
            ("TOTP Secret", vec![self.totp_secret.view(cursor_on)]),
            ("TOTP Issuer", vec![self.totp_issuer.view(cursor_on)]),
            ("TOTP Account", vec![self.totp_account.view(cursor_on)]),
        ];
        for (i, (label, view)) in fields.into_iter().enumerate() {
            let text = format!("{label}:");
            let label = if i == self.focused {
                bold("86", &text)
            } else {
                format!("{text:>14}")
            };
            let mut view = view.into_iter();
            lines.push(format!("{label} {}", view.next().unwrap_or_default()));
            lines.extend(view);
            if i == FIELD_PASSWORD && !self.password.value.is_empty() {
                let strength = match &self.password_err {
                    Some(err) => format!("\x1b[38;5;203mStrength: {err}\x1b[0m"),
                    None => "\x1b[38;5;82mStrength: OK\x1b[0m".to_owned(),
                };
                lines.push(format!("{}{strength}", " ".repeat(16)));
            }
        }
        lines.push(String::new());
        let mut help = String::from(
            "Tab/Shift+Tab: navigate \u{00B7} Enter: next/submit \u{00B7} Ctrl+C: cancel",
        );
        if self.focused == FIELD_USAGE_HINT || self.focused == FIELD_NOTES {
            help.push_str(" \u{00B7} Enter: new line");
        }
        lines.push(format!("\x1b[38;5;240m{help}\x1b[0m"));
        lines
    }
}

// ---------------------------------------------------------------------------
// Terminal driver
// ---------------------------------------------------------------------------

fn char_width(c: char) -> usize {
    match c as u32 {
        0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Truncates a styled line to `cols` display columns, keeping SGR escapes whole.
fn fit_to_width(line: &str, cols: usize) -> String {
    let mut out = String::new();
    let mut width = 0;
    let mut chars = line.chars().peekable();
    let mut truncated = false;
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for n in chars.by_ref() {
                out.push(n);
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        let w = char_width(c);
        if width + w > cols {
            truncated = true;
            break;
        }
        width += w;
        out.push(c);
    }
    if truncated {
        out.push_str("\x1b[0m");
    }
    out
}

struct TerminalMode {
    active: bool,
}

impl TerminalMode {
    fn enter(out: &mut impl Write) -> io::Result<Self> {
        enable_raw_mode()?;
        let mode = Self { active: true };
        queue!(out, Hide)?;
        out.flush()?;
        Ok(mode)
    }

    fn leave(&mut self) {
        if self.active {
            self.active = false;
            let mut out = io::stdout();
            let _ = queue!(out, Show);
            let _ = out.flush();
            let _ = disable_raw_mode();
        }
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        self.leave();
    }
}

/// Redraws the form in place below the prompt. Only changed lines are
/// rewritten (like Bubble Tea's standard renderer) so a keystroke costs a few
/// bytes instead of a full repaint.
struct InlineRenderer {
    last: Vec<String>,
}

impl InlineRenderer {
    fn draw(&mut self, out: &mut impl Write, lines: &[String], cols: usize) -> io::Result<()> {
        let fitted: Vec<String> = lines.iter().map(|l| fit_to_width(l, cols)).collect();
        if self.last.len() > 1 {
            write!(out, "\x1b[{}A", self.last.len() - 1)?;
        }
        write!(out, "\r")?;
        for (i, line) in fitted.iter().enumerate() {
            if i > 0 {
                write!(out, "\r\n")?;
            }
            // The last line is always rewritten so the cursor ends on it.
            if self.last.get(i) != Some(line) || i + 1 == fitted.len() {
                write!(out, "\x1b[2K{line}")?;
            }
        }
        write!(out, "\x1b[J")?;
        self.last = fitted;
        out.flush()
    }
}

fn terminal_columns() -> usize {
    crossterm::terminal::size().map_or(80, |(w, _)| usize::from(w).max(1))
}

/// One terminal read as Bubble Tea would deliver it.
enum Message {
    Key(KeyEvent),
    /// A run of printable characters from a single read.
    Text(Vec<char>),
    Resize(u16),
}

/// Bubble Tea reads the terminal in 256-byte chunks.
const READ_CHUNK_BYTES: usize = 256;

fn plain_char(key: &KeyEvent) -> Option<char> {
    match key.code {
        KeyCode::Char(c)
            if key.kind != KeyEventKind::Release
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            Some(c)
        }
        _ => None,
    }
}

/// Reads the next message, merging already-queued printable keys into one
/// `Text` run. A non-printable event that ended a run is kept in `pending`.
fn read_message(pending: &mut Option<Event>) -> Result<Option<Message>, String> {
    let fail = |e: io::Error| format!("form error: {e}");
    let first = match pending.take() {
        Some(event) => event,
        None => event::read().map_err(fail)?,
    };
    match first {
        Event::Key(key) if key.kind == KeyEventKind::Release => Ok(None),
        Event::Key(key) => {
            let Some(first) = plain_char(&key) else {
                return Ok(Some(Message::Key(key)));
            };
            let mut runes = vec![first];
            let mut bytes = first.len_utf8();
            while bytes < READ_CHUNK_BYTES && event::poll(Duration::ZERO).map_err(fail)? {
                let next = event::read().map_err(fail)?;
                if let Event::Key(k) = &next
                    && let Some(c) = plain_char(k)
                {
                    runes.push(c);
                    bytes += c.len_utf8();
                    continue;
                }
                *pending = Some(next);
                break;
            }
            Ok(Some(Message::Text(runes)))
        }
        Event::Resize(width, _) => Ok(Some(Message::Resize(width))),
        _ => Ok(None),
    }
}

/// SIGTERM/SIGINT flags. Bubble Tea turns SIGTERM into a normal quit (the form
/// is *submitted* with what has been typed) and SIGINT into
/// `program was interrupted`.
struct SignalFlags {
    terminate: std::sync::Arc<std::sync::atomic::AtomicBool>,
    interrupt: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(unix)]
    ids: Vec<signal_hook::SigId>,
}

impl SignalFlags {
    fn install() -> Self {
        use std::sync::{Arc, atomic::AtomicBool};
        let terminate = Arc::new(AtomicBool::new(false));
        let interrupt = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        let ids = [
            (signal_hook::consts::SIGTERM, &terminate),
            (signal_hook::consts::SIGINT, &interrupt),
        ]
        .into_iter()
        .filter_map(|(signal, flag)| signal_hook::flag::register(signal, Arc::clone(flag)).ok())
        .collect();
        Self {
            terminate,
            interrupt,
            #[cfg(unix)]
            ids,
        }
    }

    fn terminated(&self) -> bool {
        self.terminate.load(std::sync::atomic::Ordering::Acquire)
    }

    fn interrupted(&self) -> bool {
        self.interrupt.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for SignalFlags {
    fn drop(&mut self) {
        #[cfg(unix)]
        for id in self.ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// Runs the interactive form on the controlling terminal. A cancelled form
/// returns the Go error text `canceled`.
pub fn run_add_form(force: bool, defaults: &FormDefaults) -> Result<FormResult, String> {
    if !io::stdin().is_terminal() {
        return Err("form error: stdin is not a terminal".to_owned());
    }
    let fail = |e: io::Error| format!("form error: {e}");
    let mut form = AddForm::new(force);
    form.set_defaults(defaults);
    let mut out = io::stdout();
    let mut mode = TerminalMode::enter(&mut out).map_err(fail)?;
    let mut renderer = InlineRenderer { last: Vec::new() };
    form.set_width(terminal_columns() as u16);
    form.start(Instant::now());
    let signals = SignalFlags::install();
    let mut pending: Option<Event> = None;
    let flow = loop {
        if signals.interrupted() {
            let _ = write!(out, "\r\n");
            let _ = out.flush();
            mode.leave();
            return Err("form error: program was killed: program was interrupted".to_owned());
        }
        if signals.terminated() {
            break Flow::Submit;
        }
        let now = Instant::now();
        form.run_due_ticks(now);
        renderer
            .draw(&mut out, &form.view(now), terminal_columns())
            .map_err(fail)?;
        if pending.is_none() {
            let wait = form.next_tick().map_or(Duration::from_millis(50), |due| {
                due.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50))
            });
            if !event::poll(wait).map_err(fail)? {
                continue;
            }
        }
        let flow = match read_message(&mut pending)? {
            Some(Message::Key(key)) => form.key(&key, Instant::now()),
            Some(Message::Text(runes)) => form.text(&runes, Instant::now()),
            Some(Message::Resize(width)) => {
                form.set_width(width);
                Flow::Continue
            }
            None => Flow::Continue,
        };
        if flow != Flow::Continue {
            break flow;
        }
    };
    renderer
        .draw(&mut out, &form.view(Instant::now()), terminal_columns())
        .map_err(fail)?;
    let _ = write!(out, "\r\n");
    let _ = out.flush();
    mode.leave();
    match flow {
        Flow::Cancel => Err("canceled".to_owned()),
        _ => Ok(form.result()),
    }
}
