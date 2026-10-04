//! Vault-browser composition. Store, credential and native side effects retain
//! their existing owners; terminal and clipboard cleanup are scoped here.
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use symvault_core::platform::Clipboard;
use symvault_crypto::Identity;
use symvault_store::{Entry, EntryMetadata, Store};
use zeroize::{Zeroize, Zeroizing};

const KEYBINDINGS: &[(&str, &str)] = &[
    ("↑/↓ or k/j", "Move selection"),
    ("Enter", "Copy selected field to clipboard"),
    ("r", "Toggle reveal/redact sensitive fields"),
    ("e", "Edit selected entry in $EDITOR"),
    ("d", "Delete selected entry (confirm)"),
    ("g", "Generate new password for entry"),
    ("s", "Cycle sort mode (name/updated, asc/desc)"),
    ("t", "Filter by tag"),
    ("/", "Filter by name"),
    ("Esc", "Clear filter / cancel input"),
    ("?", "Toggle full keybinding help"),
    ("q or Ctrl+C", "Quit the TUI"),
];

pub fn print_keybindings(output: &mut impl Write) -> io::Result<()> {
    let terminal_width = if io::stderr().is_terminal() {
        terminal_size::terminal_size_of(io::stderr()).map_or(80, |(w, _)| usize::from(w.0))
    } else {
        80
    };
    let cap = (terminal_width.saturating_sub(3) / 2).max(8);
    let widths = [
        KEYBINDINGS
            .iter()
            .map(|(key, _)| key.len())
            .max()
            .unwrap_or(3)
            .min(cap),
        KEYBINDINGS
            .iter()
            .map(|(_, action)| action.len())
            .max()
            .unwrap_or(6)
            .min(cap),
    ];
    let mut row = |cells: [&str; 2]| -> io::Result<()> {
        for (index, cell) in cells.iter().enumerate() {
            let cell = if cell.len() > widths[index] {
                format!("{}…", &cell[..widths[index] - 1])
            } else {
                (*cell).to_owned()
            };
            write!(output, "{cell:width$}", width = widths[index])?;
            if index == 0 {
                write!(output, "  ")?;
            }
        }
        writeln!(output)
    };
    row(["Key", "Action"])?;
    row([&"-".repeat(widths[0]), &"-".repeat(widths[1])])?;
    for (key, action) in KEYBINDINGS {
        row([key, action])?;
    }
    Ok(())
}

struct TerminalMode(bool);
impl TerminalMode {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut mode = Self(true);
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            mode.leave();
            return Err(error);
        }
        Ok(mode)
    }
    fn leave(&mut self) {
        if self.0 {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
            self.0 = false;
        }
    }
}
impl Drop for TerminalMode {
    fn drop(&mut self) {
        self.leave();
    }
}

pub fn run(root: &Path, identity: &Identity) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("ui requires an interactive terminal".into());
    }
    let config =
        symvault_core::config::Config::load(root.join("config.yaml")).map_err(|e| e.to_string())?;
    let ttl = config.clipboard.as_ref().map_or(30, |c| {
        if c.auto_clear_duration < 0 {
            30
        } else {
            c.auto_clear_duration as u64
        }
    });
    let clipboard = symvault_platform::native_text_clipboard();
    let mut model = Model::new(root, identity, clipboard, Duration::from_secs(ttl))?;
    let stopping = Arc::new(AtomicBool::new(false));
    let signal = stopping.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Release);
    })
    .map_err(|_| "install UI signal handler")?;
    let mut mode = TerminalMode::enter().map_err(|e| format!("enter UI terminal: {e}"))?;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| e.to_string())?;
    let result = (|| {
        loop {
            model.tick();
            terminal
                .draw(|frame| model.draw(frame))
                .map_err(|e| e.to_string())?;
            if stopping.load(Ordering::Acquire) {
                break;
            }
            if !event::poll(Duration::from_millis(50)).map_err(|e| e.to_string())? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(|e| e.to_string())? else {
                continue;
            };
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match model.key(key) {
                Action::Quit => break,
                Action::None => {}
                Action::Edit { path, new_entry } => {
                    // The editor owns its foreground terminal until it returns.
                    terminal.clear().map_err(|e| e.to_string())?;
                    mode.leave();
                    let edited = if new_entry {
                        crate::edit_commands::add_from_editor(root, identity, &path)
                    } else {
                        crate::edit_commands::edit(
                            root,
                            identity,
                            &crate::edit_commands::EditOptions {
                                path: path.clone(),
                                editor: String::new(),
                            },
                        )
                    };
                    mode = TerminalMode::enter().map_err(|e| e.to_string())?;
                    terminal.clear().map_err(|e| e.to_string())?;
                    match edited {
                        Ok(_) => {
                            model.cache.remove(&path);
                            model.refresh(Some(&path))?;
                            model.status =
                                format!("{} {path}", if new_entry { "Added" } else { "Updated" });
                        }
                        Err(error) => {
                            model.status = format!(
                                "{} failed: {}",
                                if new_entry { "Add" } else { "Edit" },
                                terminal_text(&error)
                            )
                        }
                    }
                }
            }
        }
        model.clear_clipboard();
        // Overwrite the alternate screen before returning to the caller.
        terminal
            .draw(|frame| frame.render_widget(Paragraph::new(""), frame.area()))
            .map_err(|e| e.to_string())?;
        terminal.clear().map_err(|e| e.to_string())?;
        Ok(())
    })();
    model.clear_clipboard();
    mode.leave();
    result
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Normal,
    Name,
    Tag,
    Add,
    Generate,
    Delete,
    Edit,
}
enum Action {
    None,
    Quit,
    Edit { path: String, new_entry: bool },
}
struct SecretEntry(Entry);
impl Drop for SecretEntry {
    fn drop(&mut self) {
        for value in self.0.data.values_mut() {
            erase(value);
        }
    }
}
fn erase(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(erase),
        Value::Object(o) => o.values_mut().for_each(erase),
        _ => {}
    }
}

struct Model<'a> {
    store: Store,
    identity: &'a Identity,
    entries: Vec<String>,
    filtered: Vec<String>,
    selected: usize,
    detail: Option<SecretEntry>,
    cache: BTreeMap<String, (EntryMetadata, String)>,
    mode: Mode,
    input: String,
    name_query: String,
    tag_query: String,
    sort: usize,
    revealed: bool,
    help: bool,
    symbols: bool,
    status: String,
    clipboard: symvault_platform::OwnedTextClipboard,
    clipboard_ttl: Duration,
}
impl<'a> Model<'a> {
    fn new(
        root: &Path,
        identity: &'a Identity,
        clipboard: Arc<dyn Clipboard>,
        clipboard_ttl: Duration,
    ) -> Result<Self, String> {
        let store = Store::open_with_legacy_migration(root, identity).map_err(|e| e.to_string())?;
        let mut model = Self {
            store,
            identity,
            entries: vec![],
            filtered: vec![],
            selected: 0,
            detail: None,
            cache: BTreeMap::new(),
            mode: Mode::Normal,
            input: String::new(),
            name_query: String::new(),
            tag_query: String::new(),
            sort: 0,
            revealed: false,
            help: false,
            symbols: true,
            status: String::new(),
            clipboard: symvault_platform::OwnedTextClipboard::new(clipboard)
                .map_err(|e| e.to_string())?,
            clipboard_ttl,
        };
        model.refresh(None)?;
        Ok(model)
    }
    fn path(&self) -> Option<&str> {
        self.filtered.get(self.selected).map(String::as_str)
    }
    fn refresh(&mut self, selected: Option<&str>) -> Result<(), String> {
        self.entries = self
            .store
            .read_session(self.identity)
            .list()
            .map_err(|e| e.to_string())?;
        self.entries.sort();
        self.apply_filter()?;
        if let Some(path) = selected {
            self.selected = self
                .filtered
                .iter()
                .position(|p| p == path)
                .unwrap_or(self.selected);
        }
        self.load();
        Ok(())
    }
    fn ensure_metadata(&mut self) -> Result<(), String> {
        let mut used = self
            .cache
            .iter()
            .map(|(p, (m, t))| p.len() + t.len() + serde_json::to_vec(m).map_or(0, |v| v.len()))
            .sum::<usize>();
        let reader = self.store.read_session(self.identity);
        for path in &self.entries {
            if self.cache.contains_key(path) {
                continue;
            }
            let entry = match reader.get(path) {
                Ok(e) => SecretEntry(e),
                Err(e) if e.is_resource_failure() => return Err(e.to_string()),
                Err(_) => continue,
            };
            let meta = entry.0.metadata.clone();
            let kind = if entry.0.secret_metadata.secret_type.is_empty() {
                "custom".to_owned()
            } else {
                entry.0.secret_metadata.secret_type.clone()
            };
            used = used.saturating_add(
                path.len()
                    + kind.len()
                    + serde_json::to_vec(&meta).map_err(|e| e.to_string())?.len(),
            );
            if used > 16 * 1024 * 1024 {
                return Err("vault resource limit exceeded".into());
            }
            self.cache.insert(path.clone(), (meta, kind));
        }
        Ok(())
    }
    fn apply_filter(&mut self) -> Result<(), String> {
        if !self.tag_query.is_empty() || self.sort >= 2 {
            self.ensure_metadata()?;
        }
        self.filtered = self
            .entries
            .iter()
            .filter(|p| {
                fuzzy_match(&self.name_query, p)
                    && (self.tag_query.is_empty()
                        || self.cache.get(*p).is_some_and(|(m, _)| {
                            m.tags.iter().any(|t| {
                                t.to_lowercase().starts_with(&self.tag_query.to_lowercase())
                            })
                        }))
            })
            .cloned()
            .collect();
        let cache = &self.cache;
        let sort = self.sort;
        self.filtered.sort_by(|a, b| match sort {
            0 => a.cmp(b),
            1 => b.cmp(a),
            2 | 3 => {
                let order = cache
                    .get(a)
                    .and_then(|(m, _)| parsed_time(&m.updated))
                    .cmp(&cache.get(b).and_then(|(m, _)| parsed_time(&m.updated)));
                if sort == 2 { order } else { order.reverse() }
            }
            _ => {
                let order = type_rank(cache.get(a).map(|(_, t)| t.as_str()))
                    .cmp(&type_rank(cache.get(b).map(|(_, t)| t.as_str())));
                let order = if sort == 5 { order.reverse() } else { order };
                order.then_with(|| a.cmp(b))
            }
        });
        self.selected = self.selected.min(self.filtered.len().saturating_sub(1));
        self.load();
        Ok(())
    }
    fn load(&mut self) {
        self.detail = None;
        if let Some(path) = self.path() {
            match self.store.read_session(self.identity).get(path) {
                Ok(entry) => self.detail = Some(SecretEntry(entry)),
                Err(error) => {
                    self.status = format!(
                        "Could not read entry: {}",
                        terminal_text(&error.to_string())
                    )
                }
            }
        }
    }
    fn set_filter(&mut self) {
        if self.mode == Mode::Name {
            self.name_query = self.input.clone();
        } else if self.mode == Mode::Tag {
            self.tag_query = self.input.trim().to_owned();
        }
        if let Err(error) = self.apply_filter() {
            self.status = terminal_text(&error);
        }
    }
    fn key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if matches!(self.mode, Mode::Delete | Mode::Edit) {
            match key.code {
                KeyCode::Char('y' | 'Y') => {
                    let Some(path) = self.path().map(str::to_owned) else {
                        self.mode = Mode::Normal;
                        return Action::None;
                    };
                    let edit = self.mode == Mode::Edit;
                    self.mode = Mode::Normal;
                    if edit {
                        return Action::Edit {
                            path,
                            new_entry: false,
                        };
                    }
                    match self.store.delete_entry_with_identity(&path, self.identity) {
                        Ok(()) => {
                            crate::write_commands::auto_commit(
                                &self.store,
                                self.identity,
                                &path,
                                "Delete",
                            );
                            self.cache.remove(&path);
                            if let Err(error) = self.refresh(None) {
                                self.status = terminal_text(&error);
                            } else {
                                self.status = format!("Deleted {path}");
                            }
                        }
                        Err(error) => {
                            self.status =
                                format!("Delete failed: {}", terminal_text(&error.to_string()))
                        }
                    }
                }
                KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                    self.mode = Mode::Normal;
                    self.status = "Canceled".into();
                }
                _ => {}
            }
            return Action::None;
        }
        if self.mode != Mode::Normal {
            match key.code {
                KeyCode::Esc => {
                    if self.mode == Mode::Tag {
                        self.tag_query.clear();
                        self.input.clear();
                        self.set_filter();
                    }
                    self.mode = Mode::Normal;
                    self.load();
                }
                KeyCode::Enter => {
                    match self.mode {
                        Mode::Add => {
                            let path = self.input.trim().to_owned();
                            if path.is_empty() {
                                self.status = "Path cannot be empty".into();
                                return Action::None;
                            }
                            self.mode = Mode::Normal;
                            return Action::Edit {
                                path,
                                new_entry: true,
                            };
                        }
                        Mode::Generate => {
                            let length = if self.input.trim().is_empty() {
                                20
                            } else {
                                match self.input.trim().parse::<isize>() {
                                    Ok(n) if (1..=512).contains(&n) => n,
                                    _ => {
                                        self.status = "Invalid length (1-512)".into();
                                        return Action::None;
                                    }
                                }
                            };
                            match symvault_core::password::generate_password(length, self.symbols) {
                                Ok(password) => self.copy(
                                    password.as_str().as_bytes(),
                                    "Generated password copied to clipboard".into(),
                                ),
                                Err(_) => self.status = "Password generation failed".into(),
                            };
                        }
                        _ => self.set_filter(),
                    }
                    self.mode = Mode::Normal;
                    self.load();
                }
                KeyCode::Char('s') if self.mode == Mode::Generate => self.symbols = !self.symbols,
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    let limit = if self.mode == Mode::Generate { 4 } else { 256 };
                    if self.input.chars().count() < limit {
                        self.input.push(c);
                        if matches!(self.mode, Mode::Name | Mode::Tag) {
                            self.set_filter();
                        }
                    }
                }
                KeyCode::Backspace => {
                    self.input.pop();
                    if matches!(self.mode, Mode::Name | Mode::Tag) {
                        self.set_filter();
                    }
                }
                _ => {}
            }
            return Action::None;
        }
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Char('?') => self.help = !self.help,
            KeyCode::Char('r') => self.revealed = !self.revealed,
            KeyCode::Char('/') => {
                self.mode = Mode::Name;
                self.input = self.name_query.clone();
            }
            KeyCode::Char('t') => {
                self.mode = Mode::Tag;
                self.input = self.tag_query.clone();
                if let Err(e) = self.ensure_metadata() {
                    self.status = terminal_text(&e);
                }
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Add;
                self.input.clear();
            }
            KeyCode::Char('g') => {
                self.mode = Mode::Generate;
                self.input.clear();
            }
            KeyCode::Char('d') if self.path().is_some() => self.mode = Mode::Delete,
            KeyCode::Char('e') if self.path().is_some() => self.mode = Mode::Edit,
            KeyCode::Char('s') => {
                self.sort = (self.sort + 1) % 6;
                if let Err(e) = self.apply_filter() {
                    self.status = terminal_text(&e);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                self.load();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(self.filtered.len().saturating_sub(1));
                self.load();
            }
            KeyCode::Home => {
                self.selected = 0;
                self.load();
            }
            KeyCode::End => {
                self.selected = self.filtered.len().saturating_sub(1);
                self.load();
            }
            KeyCode::Enter => self.copy_selected(),
            _ => {}
        }
        Action::None
    }
    fn copy_selected(&mut self) {
        let Some(path) = self.path().map(str::to_owned) else {
            return;
        };
        let entry = match self.store.read_session(self.identity).get(&path) {
            Ok(e) => SecretEntry(e),
            Err(_) => {
                self.status = "Could not read entry for copying".into();
                return;
            }
        };
        let Some((name, value)) = copy_field(&entry.0.data) else {
            self.status = "no fields found in entry".into();
            return;
        };
        let text = Zeroizing::new(crate::run_commands::format_go_value(value));
        self.copy(text.as_bytes(), format!("Copied {name} for {path}"));
    }
    fn copy(&mut self, text: &[u8], message: String) {
        match self.clipboard.copy(text, self.clipboard_ttl) {
            Ok(()) => self.status = message,
            Err(_) => self.status = "Copy failed: native clipboard unavailable".into(),
        }
    }
    fn tick(&mut self) {
        if let Some(result) = self.clipboard.take_clear_result() {
            self.status = if result.is_ok() {
                "Clipboard cleared"
            } else {
                "Clipboard clear failed"
            }
            .into();
        }
    }
    fn clear_clipboard(&mut self) {
        if self.clipboard.clear().is_err() {
            self.status = "Clipboard clear failed".into();
        }
    }
    fn draw(&self, frame: &mut Frame) {
        let vertical = Layout::vertical([
            Constraint::Min(4),
            Constraint::Length(if self.help { 15 } else { 3 }),
        ])
        .split(frame.area());
        let panes = Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(vertical[0]);
        let sort = ["name↑", "name↓", "updated↑", "updated↓", "type↑", "type↓"][self.sort];
        let query = match self.mode {
            Mode::Name => format!("/ {}", terminal_text(&self.input)),
            Mode::Tag => format!("t: {}", terminal_text(&self.input)),
            Mode::Add => format!("a: {}", terminal_text(&self.input)),
            Mode::Generate => format!(
                "length: {} s: symbols [{}]",
                terminal_text(&self.input),
                if self.symbols { "on" } else { "off" }
            ),
            _ => format!(
                "Filter: {} Tag: {}",
                terminal_text(&self.name_query),
                terminal_text(&self.tag_query)
            ),
        };
        let list = List::new(
            self.filtered
                .iter()
                .map(|p| ListItem::new(terminal_text(p))),
        )
        .block(Block::bordered().title(format!(
            "Entries [{}/{}] [sort: {sort}] {query}",
            if self.filtered.is_empty() {
                0
            } else {
                self.selected + 1
            },
            self.filtered.len()
        )))
        .highlight_style(Style::default().bg(Color::Blue))
        .highlight_symbol("> ");
        let mut state = ListState::default().with_selected(if self.filtered.is_empty() {
            None
        } else {
            Some(self.selected)
        });
        frame.render_stateful_widget(list, panes[0], &mut state);
        let mut details = Zeroizing::new(String::new());
        if let Some(entry) = &self.detail {
            details.push_str(&format!(
                "Updated: {}\n\n",
                terminal_text(&entry.0.metadata.updated)
            ));
            let rows = usize::from(panes[1].height.saturating_sub(6).max(1));
            for (index, (name, value)) in entry.0.data.iter().enumerate() {
                if index >= rows {
                    details.push_str("...\n");
                    break;
                }
                let text = if !self.revealed && sensitive(name) {
                    Zeroizing::new("••••".into())
                } else {
                    Zeroizing::new(terminal_text(&crate::run_commands::format_go_value(value)))
                };
                details.push_str(&format!("{}: {}\n", terminal_text(name), *text));
            }
        } else {
            details.push_str(if self.filtered.is_empty() {
                "No entries"
            } else {
                "Could not read entry"
            });
        }
        frame.render_widget(
            Paragraph::new(details.as_str()).block(
                Block::bordered().title(self.path().map_or("Details".into(), terminal_text)),
            ),
            panes[1],
        );
        let footer = if self.help {
            format!(
                "Help\n{}\na: Add entry\nHome/End: First/last entry",
                KEYBINDINGS
                    .iter()
                    .map(|(k, a)| format!("{k}: {a}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else if matches!(self.mode, Mode::Edit | Mode::Delete) {
            format!(
                "{} {}? y/N",
                if self.mode == Mode::Delete {
                    "Delete"
                } else {
                    "Edit"
                },
                terminal_text(self.path().unwrap_or(""))
            )
        } else {
            format!(
                "↑/↓ select · Enter copy · r reveal · a add · e edit · d delete · g gen · s sort · t tag · / filter · ? help · q quit\n{}",
                terminal_text(&self.status)
            )
        };
        frame.render_widget(Paragraph::new(footer), vertical[1]);
    }
}
impl Drop for Model<'_> {
    fn drop(&mut self) {
        self.clear_clipboard();
    }
}
fn sensitive(name: &str) -> bool {
    let name = name.to_lowercase();
    [
        "pass", "secret", "token", "key", "otp", "pin", "backup", "seed",
    ]
    .iter()
    .any(|s| name.contains(s))
}
fn copy_field(data: &BTreeMap<String, Value>) -> Option<(&str, &Value)> {
    for name in [
        "password",
        "secret",
        "token",
        "seed_phrase",
        "api_key",
        "private_key",
    ] {
        if let Some((key, value)) = data.get_key_value(name) {
            return Some((key, value));
        }
    }
    data.first_key_value()
        .map(|(key, value)| (key.as_str(), value))
}
fn fuzzy_match(query: &str, value: &str) -> bool {
    let query = query.trim().to_lowercase();
    let value = value.to_lowercase();
    let mut chars = query.chars();
    let mut wanted = chars.next();
    for c in value.chars() {
        if wanted == Some(c) {
            wanted = chars.next();
        }
    }
    wanted.is_none()
}
fn type_rank(kind: Option<&str>) -> usize {
    match kind.unwrap_or("custom") {
        "api_key" => 0,
        "bearer_token" => 1,
        "ssh_key" => 2,
        "password" => 3,
        "database_url" => 4,
        "certificate" => 5,
        "totp_seed" => 6,
        "basic_auth" => 7,
        "custom" => 8,
        _ => 0,
    }
}
fn parsed_time(value: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}
fn terminal_text(text: &str) -> String {
    let mut chars = text.chars().peekable();
    let mut output = String::new();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if !c.is_control() {
            output.push(c);
        } else if matches!(c, '\n' | '\r' | '\t') {
            output.push(' ');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::{fs, sync::Mutex};
    #[derive(Default)]
    struct TestClipboard {
        values: Mutex<Vec<Vec<u8>>>,
        changed: std::sync::Condvar,
    }
    impl Clipboard for TestClipboard {
        fn set(&self, text: &[u8]) -> Result<(), symvault_core::platform::PlatformError> {
            self.values.lock().unwrap().push(text.to_vec());
            Ok(())
        }
        fn clear(&self) -> Result<(), symvault_core::platform::PlatformError> {
            self.values.lock().unwrap().push(vec![]);
            self.changed.notify_all();
            Ok(())
        }
    }
    fn fixture() -> (tempfile::TempDir, Identity) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("entries")).unwrap();
        fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 2\n",
        )
        .unwrap();
        fs::write(root.path().join("identity.age"), b"private fixture marker").unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).unwrap();
        for path in ["alpha/login", "beta/api"] {
            let mut entry = Entry {
                path: path.into(),
                ..Entry::default()
            };
            entry
                .data
                .insert("password".into(), Value::String(format!("canary-{path}")));
            entry
                .data
                .insert("username".into(), Value::String("public-user".into()));
            entry.metadata.tags = vec![if path.starts_with("alpha") {
                "work".into()
            } else {
                "home".into()
            }];
            store.write_entry(path, &entry, &identity).unwrap();
        }
        (root, identity)
    }
    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn screen(model: &Model<'_>) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal.draw(|frame| model.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
    #[test]
    fn encrypted_browser_masks_sensitive_values_until_explicit_reveal() {
        let (root, id) = fixture();
        let mut m = Model::new(
            root.path(),
            &id,
            Arc::new(TestClipboard::default()),
            Duration::from_secs(30),
        )
        .unwrap();
        let view = screen(&m);
        assert!(view.contains("public-user"));
        assert!(view.contains("••••"));
        assert!(!view.contains("canary-"));
        m.key(key('r'));
        assert!(screen(&m).contains("canary-alpha/login"));
        m.key(key('r'));
        assert!(!screen(&m).contains("canary-"));
    }
    #[test]
    fn browser_filters_navigation_and_canceled_delete_preserve_encrypted_entries() {
        let (root, id) = fixture();
        let mut m = Model::new(
            root.path(),
            &id,
            Arc::new(TestClipboard::default()),
            Duration::from_secs(30),
        )
        .unwrap();
        m.key(key('j'));
        assert_eq!(m.path(), Some("beta/api"));
        m.key(key('d'));
        m.key(key('n'));
        assert_eq!(m.entries.len(), 2);
        m.key(key('/'));
        for c in "alp".chars() {
            m.key(key(c));
        }
        m.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(m.filtered, ["alpha/login"]);
        m.key(key('d'));
        m.key(key('y'));
        assert!(m.store.get("alpha/login", &id).is_err());
        assert!(m.store.get("beta/api", &id).is_ok());
    }
    #[test]
    fn successful_copy_owns_ttl_and_quit_cleanup_even_with_disabled_timer() {
        let (root, id) = fixture();
        let clipboard = Arc::new(TestClipboard::default());
        {
            let mut m = Model::new(root.path(), &id, clipboard.clone(), Duration::ZERO).unwrap();
            m.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            assert_eq!(clipboard.values.lock().unwrap()[0], b"canary-alpha/login");
            assert!(m.clipboard.take_clear_result().is_none());
            assert!(!screen(&m).contains("canary-"));
        }
        assert_eq!(
            clipboard.values.lock().unwrap().last().unwrap(),
            &Vec::<u8>::new()
        );
        let mut m = Model::new(
            root.path(),
            &id,
            clipboard.clone(),
            Duration::from_millis(5),
        )
        .unwrap();
        m.copy_selected();
        let lock = clipboard.values.lock().unwrap();
        let (rows, _) = clipboard
            .changed
            .wait_timeout_while(lock, Duration::from_secs(1), |rows| {
                rows.last().is_none_or(|v| !v.is_empty())
            })
            .unwrap();
        assert!(
            rows.last().unwrap().is_empty(),
            "expiry must proceed without UI event pumping"
        );
        drop(rows);
        m.tick();
        assert_eq!(m.status, "Clipboard cleared");
    }
    #[test]
    fn all_sensitive_fields_and_terminal_escape_surfaces_remain_masked() {
        for name in [
            "Password",
            "secret_value",
            "TOKEN",
            "api_key",
            "totp_seed",
            "pin",
            "backup_code",
        ] {
            assert!(sensitive(name));
        }
        assert!(!sensitive("username"));
        assert_eq!(
            terminal_text("a\x1b[2Jb\x1b]8;;https://bad\x07c\x1b]8;;\x1b\\\x00"),
            "abc"
        );
        let data = BTreeMap::from([
            ("z".into(), Value::Null),
            ("token".into(), Value::String("fixture".into())),
            ("password".into(), Value::String("preferred".into())),
        ]);
        assert_eq!(copy_field(&data).unwrap().0, "password");
    }
    #[test]
    fn updated_sort_compares_instants_and_generator_does_not_write_entry() {
        assert!(parsed_time("2026-10-04T10:00:00+02:00") < parsed_time("2026-10-04T09:00:00Z"));
        let (root, id) = fixture();
        let clipboard = Arc::new(TestClipboard::default());
        let mut m = Model::new(root.path(), &id, clipboard.clone(), Duration::ZERO).unwrap();
        let before = m.store.get("alpha/login", &id).unwrap();
        m.key(key('g'));
        m.key(key('8'));
        m.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(clipboard.values.lock().unwrap()[0].len(), 8);
        assert_eq!(m.store.get("alpha/login", &id).unwrap(), before);
    }
}
