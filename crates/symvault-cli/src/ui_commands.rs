use std::{io::Write, process::ExitCode};

const KEYBINDINGS: [(&str, &str); 14] = [
    ("Key", "Action"),
    ("--------------", "--------------------------------------"),
    ("↑/↓ or k/j", "Move selection"),
    ("Enter", "Copy selected field to clipboard"),
    ("r", "Toggle reveal/redact sensitive fields"),
    ("e", "Edit selected entry in $EDITOR"),
    ("d", "Delete selected entry (confirm)"),
    ("g", "Generate new password for entry"),
    ("s", "Cycle sort mode (name/updated, asc/de…"),
    ("t", "Filter by tag"),
    ("/", "Filter by name"),
    ("Esc", "Clear filter / cancel input"),
    ("?", "Toggle full keybinding help"),
    ("q or Ctrl+C", "Quit the TUI"),
];

pub fn run<W: Write, E: Write>(
    print_keybindings: bool,
    extra: &[String],
    output: &mut W,
    errors: &mut E,
) -> ExitCode {
    if let Some(argument) = extra.first() {
        let message = if argument.starts_with('-') {
            format!("unknown flag: {argument}")
        } else {
            format!("unknown command {argument:?} for \"symvault ui\"")
        };
        let _ = writeln!(errors, "Error: {message}\nError: {message}");
        return ExitCode::from(1);
    }

    if print_keybindings {
        return match write_keybindings(output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(errors, "Error: write keybindings: {error}");
                ExitCode::from(1)
            }
        };
    }

    let _ = writeln!(
        errors,
        "Error: interactive UI is not implemented in the Rust CLI yet"
    );
    ExitCode::from(1)
}

fn write_keybindings(output: &mut impl Write) -> std::io::Result<()> {
    for (key, action) in KEYBINDINGS {
        writeln!(output, "{key:<14}  {action:<38}")?;
    }
    Ok(())
}
