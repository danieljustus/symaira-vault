//! Terminal driver: raw mode, alternate screen, one redraw per event.
//!
//! The wizard owns the whole screen, as the bubbletea program does with
//! `tea.WithAltScreen()`. Rendering is a full repaint of the view's lines;
//! pixel-identical output to bubbletea's diffing renderer is not a goal.

use std::io::{self, Write};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyEventKind},
    execute, queue,
    terminal::{
        self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};

use super::{
    input::Key,
    model::{Flow, WizardModel},
};

/// Restores the terminal on every exit path, including panics.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

fn draw(model: &mut WizardModel, size: (u16, u16)) -> io::Result<()> {
    model.set_width(usize::from(size.0));
    let view = model.view();
    let (width, height) = (usize::from(size.0).max(1), usize::from(size.1).max(1));
    let mut lines: Vec<&str> = view.split('\n').collect();
    if lines.len() > height {
        // Like bubbletea's renderer: keep the bottom of an over-tall view.
        lines.drain(..lines.len() - height);
    }
    let mut out = io::stdout().lock();
    queue!(out, MoveTo(0, 0))?;
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.write_all(b"\r\n")?;
        }
        out.write_all(truncate_to_width(line, width).as_bytes())?;
        queue!(out, Clear(ClearType::UntilNewLine))?;
    }
    queue!(out, Clear(ClearType::FromCursorDown))?;
    out.flush()
}

/// Cuts a styled line at `width` visible columns, keeping escape sequences.
fn truncate_to_width(line: &str, width: usize) -> String {
    let mut out = String::with_capacity(line.len());
    let mut visible = 0usize;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            out.push(c);
            if chars.peek() == Some(&'[') {
                for next in chars.by_ref() {
                    out.push(next);
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if visible >= width {
            continue;
        }
        out.push(c);
        visible += 1;
    }
    out
}

fn terminal_size() -> (u16, u16) {
    terminal::size().unwrap_or((80, 24))
}

/// Runs the interactive loop until the model quits.
pub(super) fn run(model: &mut WizardModel) -> Result<(), String> {
    let _guard = TerminalGuard::enter().map_err(|error| format!("{error}"))?;
    let mut size = terminal_size();
    draw(model, size).map_err(|error| error.to_string())?;
    loop {
        let event = event::read().map_err(|error| error.to_string())?;
        let flow = match event {
            Event::Resize(width, height) => {
                size = (width, height);
                Flow::Continue
            }
            Event::Key(key) if key.kind != KeyEventKind::Release => match Key::from_event(&key) {
                Some(key) => model.handle_key(&key),
                None => Flow::Continue,
            },
            _ => Flow::Continue,
        };
        if flow == Flow::Quit {
            return Ok(());
        }
        draw(model, size).map_err(|error| error.to_string())?;
        while model.apply_pending() {
            let flow = model.apply_next();
            if flow == Flow::Quit {
                return Ok(());
            }
            draw(model, size).map_err(|error| error.to_string())?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_to_width;

    #[test]
    fn truncation_counts_visible_columns_only() {
        let styled = "\u{1b}[1;38;5;212mhello world\u{1b}[0m";
        assert_eq!(
            truncate_to_width(styled, 5),
            "\u{1b}[1;38;5;212mhello\u{1b}[0m"
        );
        assert_eq!(truncate_to_width("abc", 10), "abc");
    }
}
