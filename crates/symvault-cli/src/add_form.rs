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
    fmt,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::Value;
use symvault_core::password::assess_password_strength;
use symvault_store::{SecretType, detect_secret_type};
use zeroize::{Zeroize, Zeroizing};

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
#[derive(Clone, Default)]
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

/// `Debug` names the fields but never prints the TOTP secret.
impl fmt::Debug for FormDefaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormDefaults")
            .field("username", &self.username)
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("secret_type", &self.secret_type)
            .field("usage_hint", &self.usage_hint)
            .field("auto_rotate", &self.auto_rotate)
            .field("totp_secret", &redacted(&self.totp_secret))
            .field("totp_issuer", &self.totp_issuer)
            .field("totp_account", &self.totp_account)
            .finish()
    }
}

fn redacted(secret: &str) -> &'static str {
    if secret.is_empty() { "" } else { "<redacted>" }
}

/// Collected form output: entry data plus the secret metadata fields.
///
/// `data` carries the password and TOTP secret, so the value is wiped on drop
/// and `Debug` lists only the data keys.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FormResult {
    pub data: BTreeMap<String, Value>,
    pub secret_type: String,
    pub usage_hint: String,
    pub auto_rotate: bool,
}

impl fmt::Debug for FormResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormResult")
            .field("data_keys", &self.data.keys().collect::<Vec<_>>())
            .field("secret_type", &self.secret_type)
            .field("usage_hint", &self.usage_hint)
            .field("auto_rotate", &self.auto_rotate)
            .finish()
    }
}

impl Drop for FormResult {
    fn drop(&mut self) {
        for value in self.data.values_mut() {
            zeroize_value(value);
        }
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        Value::Object(map) => map.iter_mut().for_each(|(_, v)| zeroize_value(v)),
        _ => {}
    }
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

    /// The typed text; wiped when the caller drops it (the field may hold a
    /// password or TOTP secret).
    fn text(&self) -> Zeroizing<String> {
        Zeroizing::new(self.value.iter().collect())
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
    /// Index of the focused field (read by the model tests).
    pub focused: usize,
    force: bool,
    password_err: Option<String>,
    ticks: Vec<Tick>,
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
            password_err: None,
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
        let hint = secret_type_from_string(&self.secret_type.text()).usage_hint();
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
            "ctrl+c" => return Flow::Cancel,
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
            data.insert("password".to_owned(), Value::String(password.to_string()));
        }
        let url = self.url.text().trim().to_owned();
        if !url.is_empty() {
            data.insert("url".to_owned(), Value::String(url));
        }
        let notes = self.notes.text().trim().to_owned();
        if !notes.is_empty() {
            data.insert("notes".to_owned(), Value::String(notes));
        }
        let secret = Zeroizing::new(self.totp_secret.text().trim().to_owned());
        if !secret.is_empty() {
            let mut totp = serde_json::Map::new();
            totp.insert("secret".to_owned(), Value::String(secret.to_string()));
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
            auto_rotate: self.auto_rotate.text().as_str() == "yes",
        }
    }

    /// Renders the form as terminal lines (no trailing newline).
    pub fn view(&self) -> Vec<String> {
        // Bubbles toggles the cursor every blink period; the exact phase is not
        // observable state, so keep it solid.
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
