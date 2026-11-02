//! The wizard's lipgloss styles (`internal/ui/theme`), dark-background
//! palette. Colour is skipped when `NO_COLOR` is set or the terminal is
//! `dumb`, as lipgloss' colour-profile detection would.

use std::sync::OnceLock;

fn color_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
            && std::env::var("TERM").map_or(true, |term| term != "dumb")
    })
}

fn paint(text: &str, sgr: &str) -> String {
    if text.is_empty() || !color_enabled() {
        return text.to_owned();
    }
    format!("\u{1b}[{sgr}m{text}\u{1b}[0m")
}

/// `TitleStyle`: bold, colour 212.
pub(super) fn title(text: &str) -> String {
    paint(text, "1;38;5;212")
}

/// `FocusedStyle`: bold, colour 86.
pub(super) fn focused(text: &str) -> String {
    paint(text, "1;38;5;86")
}

/// `ErrorStyle`: colour 203.
pub(super) fn error(text: &str) -> String {
    paint(text, "38;5;203")
}

/// `DimStyle`/`helpStyle`: colour 245.
pub(super) fn dim(text: &str) -> String {
    paint(text, "38;5;245")
}

/// `WarnStyle`: colour 220.
pub(super) fn warn(text: &str) -> String {
    paint(text, "38;5;220")
}

/// `SuccessStyle`: colour 82.
pub(super) fn success(text: &str) -> String {
    paint(text, "38;5;82")
}

/// The wizard header: bold, colour 240.
pub(super) fn header(text: &str) -> String {
    paint(text, "1;38;5;240")
}

/// The spinner: colour 86.
pub(super) fn spinner(text: &str) -> String {
    paint(text, "38;5;86")
}
