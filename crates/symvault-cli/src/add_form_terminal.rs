//! Terminal driver for the interactive `add` form: raw mode, in-place
//! rendering, input reading and the signal behaviour of Bubble Tea's program.
//! The form's state machine lives in [`super::add_form`] so it can be tested
//! without a terminal.

use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    queue,
    terminal::{disable_raw_mode, enable_raw_mode},
};

use super::add_form::{AddForm, Flow, FormDefaults, FormResult};

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
    Resize,
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
        Event::Resize(..) => Ok(Some(Message::Resize)),
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
    // Handlers go in before raw mode so a signal arriving in between cannot
    // kill the process with the terminal left raw.
    let signals = SignalFlags::install();
    let mut mode = TerminalMode::enter(&mut out).map_err(fail)?;
    let mut renderer = InlineRenderer { last: Vec::new() };
    form.start(Instant::now());
    let mut pending: Option<Event> = None;
    let mut dirty = true;
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
        if form.next_tick().is_some_and(|due| due <= now) {
            form.run_due_ticks(now);
            dirty = true;
        }
        if dirty {
            renderer
                .draw(&mut out, &form.view(), terminal_columns())
                .map_err(fail)?;
            dirty = false;
        }
        if pending.is_none() {
            let wait = form.next_tick().map_or(Duration::from_millis(50), |due| {
                due.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50))
            });
            if !event::poll(wait).map_err(fail)? {
                continue;
            }
        }
        dirty = true;
        let flow = match read_message(&mut pending)? {
            Some(Message::Key(key)) => form.key(&key, Instant::now()),
            Some(Message::Text(runes)) => form.text(&runes, Instant::now()),
            Some(Message::Resize) => Flow::Continue,
            None => Flow::Continue,
        };
        if flow != Flow::Continue {
            break flow;
        }
    };
    renderer
        .draw(&mut out, &form.view(), terminal_columns())
        .map_err(fail)?;
    let _ = write!(out, "\r\n");
    let _ = out.flush();
    mode.leave();
    match flow {
        Flow::Cancel => Err("canceled".to_owned()),
        _ => Ok(form.result()),
    }
}
