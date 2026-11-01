//! Key names and the two text widgets the wizard uses
//! (`bubbles/textinput`, `bubbles/textarea`).
//!
//! Steps match on [`Key::as_str`], which uses bubbletea's `KeyMsg.String()`
//! spelling (`"enter"`, `"ctrl+c"`, `" "`, the typed rune, ...), so the step
//! logic reads like the Go it was ported from.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A key press named the way bubbletea names it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Key(String);

impl Key {
    #[cfg(test)]
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The runes this key inserts into a text widget, if it is printable.
    pub(crate) fn runes(&self) -> Option<&str> {
        let mut chars = self.0.chars();
        let first = chars.next()?;
        if chars.next().is_some() {
            // Multi-character names are special keys, except a pasted run of
            // runes which has no special-key spelling (contains no '+').
            if self.0.chars().count() > 1 && is_special_name(&self.0) {
                return None;
            }
            return Some(&self.0);
        }
        (!first.is_control()).then_some(self.0.as_str())
    }

    pub(crate) fn from_event(event: &KeyEvent) -> Option<Self> {
        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
        let alt = event.modifiers.contains(KeyModifiers::ALT);
        let shift = event.modifiers.contains(KeyModifiers::SHIFT);
        let base = match event.code {
            KeyCode::Enter => "enter".to_owned(),
            KeyCode::Esc => "esc".to_owned(),
            KeyCode::Tab => "tab".to_owned(),
            KeyCode::BackTab => "shift+tab".to_owned(),
            KeyCode::Backspace => "backspace".to_owned(),
            KeyCode::Delete => "delete".to_owned(),
            KeyCode::Home => "home".to_owned(),
            KeyCode::End => "end".to_owned(),
            KeyCode::Up => "up".to_owned(),
            KeyCode::Down => "down".to_owned(),
            KeyCode::Left => "left".to_owned(),
            KeyCode::Right => "right".to_owned(),
            KeyCode::Char(c) => {
                if ctrl {
                    return Some(Self(format!("ctrl+{}", c.to_ascii_lowercase())));
                }
                if alt {
                    return Some(Self(format!("alt+{c}")));
                }
                return Some(Self(c.to_string()));
            }
            _ => return None,
        };
        let mut name = String::new();
        if ctrl && !matches!(event.code, KeyCode::BackTab) {
            name.push_str("ctrl+");
        } else if alt {
            name.push_str("alt+");
        } else if shift
            && matches!(
                event.code,
                KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right
            )
        {
            name.push_str("shift+");
        }
        name.push_str(&base);
        Some(Self(name))
    }
}

fn is_special_name(name: &str) -> bool {
    matches!(
        name,
        "enter"
            | "esc"
            | "tab"
            | "shift+tab"
            | "backspace"
            | "delete"
            | "home"
            | "end"
            | "up"
            | "down"
            | "left"
            | "right"
    ) || name.starts_with("ctrl+")
        || name.starts_with("alt+")
        || name.starts_with("shift+")
}

/// Mirrors `textinput.insertRunesFromUserInput`: line breaks and tabs become
/// spaces, other control characters are dropped.
fn sanitize(text: &str) -> Vec<char> {
    text.chars()
        .filter_map(|c| match c {
            '\r' | '\n' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect()
}

pub(crate) const CURSOR_ON: &str = "\u{1b}[7m";
pub(crate) const CURSOR_OFF: &str = "\u{1b}[27m";

/// `bubbles/textinput` with the default key map.
#[derive(Clone, Debug)]
pub(crate) struct TextInput {
    value: Vec<char>,
    pos: usize,
    placeholder: String,
    password: bool,
    char_limit: usize,
    focused: bool,
}

impl TextInput {
    pub(crate) fn new(placeholder: &str, password: bool, char_limit: usize) -> Self {
        Self {
            value: Vec::new(),
            pos: 0,
            placeholder: placeholder.to_owned(),
            password,
            char_limit,
            focused: false,
        }
    }

    pub(crate) fn value(&self) -> String {
        self.value.iter().collect()
    }

    /// `SetValue`: truncates to the character limit and moves the cursor to
    /// the end.
    pub(crate) fn set_value(&mut self, text: &str) {
        let mut runes = sanitize(text);
        if self.char_limit > 0 {
            runes.truncate(self.char_limit);
        }
        self.value = runes;
        self.pos = self.value.len();
    }

    pub(crate) fn focus(&mut self) {
        self.focused = true;
    }

    pub(crate) fn blur(&mut self) {
        self.focused = false;
    }

    /// Returns whether the key edited or moved within the widget.
    pub(crate) fn update(&mut self, key: &Key) -> bool {
        if !self.focused {
            return false;
        }
        match key.as_str() {
            "right" | "ctrl+f" => self.pos = (self.pos + 1).min(self.value.len()),
            "left" | "ctrl+b" => self.pos = self.pos.saturating_sub(1),
            "alt+right" | "ctrl+right" | "alt+f" => self.word_forward(),
            "alt+left" | "ctrl+left" | "alt+b" => self.word_backward(),
            "alt+backspace" | "ctrl+w" => self.delete_word_backward(),
            "alt+delete" | "alt+d" => self.delete_word_forward(),
            "ctrl+k" => self.value.truncate(self.pos),
            "ctrl+u" => {
                self.value.drain(..self.pos);
                self.pos = 0;
            }
            "backspace" | "ctrl+h" => {
                if self.pos > 0 {
                    self.value.remove(self.pos - 1);
                    self.pos -= 1;
                }
            }
            "delete" | "ctrl+d" => {
                if self.pos < self.value.len() {
                    self.value.remove(self.pos);
                }
            }
            "home" | "ctrl+a" => self.pos = 0,
            "end" | "ctrl+e" => self.pos = self.value.len(),
            "tab" | "ctrl+v" => {}
            _ => match key.runes() {
                Some(text) => self.insert(text),
                None => return false,
            },
        }
        true
    }

    fn insert(&mut self, text: &str) {
        let mut runes = sanitize(text);
        if self.char_limit > 0 {
            let room = self.char_limit.saturating_sub(self.value.len());
            runes.truncate(room);
        }
        let count = runes.len();
        self.value.splice(self.pos..self.pos, runes);
        self.pos += count;
    }

    fn word_forward(&mut self) {
        let mut i = self.pos;
        while i < self.value.len() && self.value[i].is_whitespace() {
            i += 1;
        }
        while i < self.value.len() && !self.value[i].is_whitespace() {
            i += 1;
        }
        self.pos = i;
    }

    fn word_backward(&mut self) {
        let mut i = self.pos;
        while i > 0 && self.value[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !self.value[i - 1].is_whitespace() {
            i -= 1;
        }
        self.pos = i;
    }

    fn delete_word_backward(&mut self) {
        let end = self.pos;
        self.word_backward();
        self.value.drain(self.pos..end);
    }

    fn delete_word_forward(&mut self) {
        let start = self.pos;
        self.word_forward();
        let end = self.pos;
        self.value.drain(start..end);
        self.pos = start;
    }

    /// `> value` with a reverse-video cursor cell while focused.
    pub(crate) fn view(&self, dim: impl Fn(&str) -> String) -> String {
        let prompt = "> ";
        if self.value.is_empty() && !self.placeholder.is_empty() {
            let mut chars = self.placeholder.chars();
            let first = chars.next().unwrap_or(' ');
            let rest: String = chars.collect();
            return if self.focused {
                format!("{prompt}{CURSOR_ON}{first}{CURSOR_OFF}{}", dim(&rest))
            } else {
                format!("{prompt}{}", dim(&format!("{first}{rest}")))
            };
        }
        let shown: Vec<char> = if self.password {
            vec!['*'; self.value.len()]
        } else {
            self.value.clone()
        };
        let before: String = shown[..self.pos].iter().collect();
        if !self.focused {
            return format!(
                "{prompt}{before}{}",
                shown[self.pos..].iter().collect::<String>()
            );
        }
        if self.pos < shown.len() {
            let at = shown[self.pos];
            let after: String = shown[self.pos + 1..].iter().collect();
            format!("{prompt}{before}{CURSOR_ON}{at}{CURSOR_OFF}{after}")
        } else {
            format!("{prompt}{before}{CURSOR_ON} {CURSOR_OFF}")
        }
    }
}

/// `bubbles/textarea`, reduced to the editing keys the recipients step can
/// receive. `Enter` inserts a newline, exactly as the Go widget does.
#[derive(Clone, Debug)]
pub(crate) struct TextArea {
    lines: Vec<Vec<char>>,
    row: usize,
    col: usize,
    placeholder: String,
    width: usize,
    height: usize,
}

impl TextArea {
    pub(crate) fn new(placeholder: &str, width: usize, height: usize) -> Self {
        Self {
            lines: vec![Vec::new()],
            row: 0,
            col: 0,
            placeholder: placeholder.to_owned(),
            width,
            height,
        }
    }

    pub(crate) fn value(&self) -> String {
        self.lines
            .iter()
            .map(|line| line.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn update(&mut self, key: &Key) {
        match key.as_str() {
            "enter" | "ctrl+m" => {
                let tail = self.lines[self.row].split_off(self.col);
                self.lines.insert(self.row + 1, tail);
                self.row += 1;
                self.col = 0;
            }
            "backspace" | "ctrl+h" => {
                if self.col > 0 {
                    self.lines[self.row].remove(self.col - 1);
                    self.col -= 1;
                } else if self.row > 0 {
                    let current = self.lines.remove(self.row);
                    self.row -= 1;
                    self.col = self.lines[self.row].len();
                    self.lines[self.row].extend(current);
                }
            }
            "delete" | "ctrl+d" => {
                if self.col < self.lines[self.row].len() {
                    self.lines[self.row].remove(self.col);
                } else if self.row + 1 < self.lines.len() {
                    let next = self.lines.remove(self.row + 1);
                    self.lines[self.row].extend(next);
                }
            }
            "left" | "ctrl+b" => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.lines[self.row].len();
                }
            }
            "right" | "ctrl+f" => {
                if self.col < self.lines[self.row].len() {
                    self.col += 1;
                } else if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = 0;
                }
            }
            "up" | "ctrl+p" => {
                if self.row > 0 {
                    self.row -= 1;
                    self.col = self.col.min(self.lines[self.row].len());
                }
            }
            "down" | "ctrl+n" => {
                if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = self.col.min(self.lines[self.row].len());
                }
            }
            "home" | "ctrl+a" => self.col = 0,
            "end" | "ctrl+e" => self.col = self.lines[self.row].len(),
            "ctrl+k" => self.lines[self.row].truncate(self.col),
            "ctrl+u" => {
                self.lines[self.row].drain(..self.col);
                self.col = 0;
            }
            _ => {
                if let Some(text) = key.runes() {
                    for c in sanitize(text) {
                        self.lines[self.row].insert(self.col, c);
                        self.col += 1;
                    }
                }
            }
        }
    }

    pub(crate) fn view(&self, dim: impl Fn(&str) -> String) -> String {
        let mut out = Vec::new();
        let empty = self.lines.len() == 1 && self.lines[0].is_empty();
        let first_visible = (self.row + 1).saturating_sub(self.height);
        for index in first_visible..(first_visible + self.height) {
            let number = format!("{:>3} ", index + 1);
            let body = if index < self.lines.len() {
                let line: String = self.lines[index].iter().collect();
                if index == self.row {
                    let before: String = self.lines[index][..self.col].iter().collect();
                    if self.col < self.lines[index].len() {
                        let at = self.lines[index][self.col];
                        let after: String = self.lines[index][self.col + 1..].iter().collect();
                        format!("{before}{CURSOR_ON}{at}{CURSOR_OFF}{after}")
                    } else if empty && !self.placeholder.is_empty() {
                        let mut chars = self.placeholder.chars();
                        let first = chars.next().unwrap_or(' ');
                        format!(
                            "{CURSOR_ON}{first}{CURSOR_OFF}{}",
                            dim(&chars.collect::<String>())
                        )
                    } else {
                        format!("{before}{CURSOR_ON} {CURSOR_OFF}")
                    }
                } else {
                    line
                }
            } else {
                String::new()
            };
            let mut line = format!("{}{}", dim(&number), body);
            if self.width == 0 {
                line.clear();
            }
            out.push(line);
        }
        out.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> Key {
        Key::new(name)
    }

    #[test]
    fn text_input_edits_like_the_default_key_map() {
        let mut input = TextInput::new("", false, 0);
        input.focus();
        for c in "hello world".chars() {
            input.update(&Key::new(c.to_string()));
        }
        assert_eq!(input.value(), "hello world");
        input.update(&key("ctrl+w"));
        assert_eq!(input.value(), "hello ");
        input.update(&key("ctrl+a"));
        input.update(&key("delete"));
        assert_eq!(input.value(), "ello ");
        input.update(&key("ctrl+e"));
        input.update(&key("backspace"));
        assert_eq!(input.value(), "ello");
        input.update(&key("ctrl+u"));
        assert_eq!(input.value(), "");
    }

    #[test]
    fn text_input_honours_the_character_limit_and_focus() {
        let mut input = TextInput::new("", false, 3);
        input.update(&key("a"));
        assert_eq!(input.value(), "", "a blurred input ignores keys");
        input.focus();
        for c in "abcdef".chars() {
            input.update(&Key::new(c.to_string()));
        }
        assert_eq!(input.value(), "abc");
        input.set_value("0123456789");
        assert_eq!(input.value(), "012");
    }

    #[test]
    fn password_view_masks_and_shows_a_cursor_cell() {
        let mut input = TextInput::new("min 12", true, 0);
        input.focus();
        input.set_value("secret");
        let rendered = input.view(str::to_owned);
        assert!(rendered.starts_with("> ******"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn text_area_enter_splits_lines() {
        let mut area = TextArea::new("", 60, 5);
        for c in "age1x".chars() {
            area.update(&Key::new(c.to_string()));
        }
        area.update(&key("enter"));
        area.update(&Key::new("y"));
        assert_eq!(area.value(), "age1x\ny");
        area.update(&key("backspace"));
        area.update(&key("backspace"));
        assert_eq!(area.value(), "age1x");
    }
}
