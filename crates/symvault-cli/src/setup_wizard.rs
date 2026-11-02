//! `symvault setup`: the interactive setup wizard
//! (`cmd/admin/setup.go`, `internal/ui/wizard`).
//!
//! The wizard is a sequence of screens driven by a key-event loop. The port
//! keeps Go's step list, defaults, validation messages, the resume file and
//! the apply/rollback order; only the terminal rendering is native.
//!
//! Behaviours that look like bugs in the Go oracle are reproduced because the
//! resulting files and exit codes depend on them. Each is called out where it
//! happens: the stale summary screen, "Go back" skipping a step, a vault-init
//! failure being ignored, every agent install failing, and a git-synced new
//! vault ending in a nil-pointer panic.

mod apply;
mod input;
mod model;
mod persist;
mod recipient;
mod state;
mod steps;
mod theme;
mod ui;

use std::io::{IsTerminal, Write};

pub(crate) use apply::Environment;
use model::WizardModel;

/// WIZ-15: the guard `cmd/admin/setup.go` runs before anything else.
pub(crate) const NON_TTY_ERROR: &str =
    "setup needs a TTY; use `symvault init` for non-interactive vault initialization";

/// Whether stdin is a terminal (`term.IsTerminal(os.Stdin.Fd())`).
pub(crate) fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Go's `wizard.Run`: the error text `ExecuteRoot` prints after the program
/// ends. `Ok` means the wizard finished (or finished without an apply error).
pub(crate) fn run(
    vault_dir: &str,
    keep_on_error: bool,
    no_resume: bool,
    env: Environment,
) -> Result<(), String> {
    let mut model = WizardModel::new(vault_dir, keep_on_error, no_resume, env);
    ui::run(&mut model).map_err(|error| format!("wizard: {error}"))?;
    finish(&model)
}

fn finish(model: &WizardModel) -> Result<(), String> {
    if model.panicked {
        // Bubbletea recovers the panic, restores the terminal, prints the
        // panic and a stack trace, and `Run` returns this error.
        let mut stderr = std::io::stderr().lock();
        let _ = write!(
            stderr,
            "Caught panic:\n\nruntime error: invalid memory address or nil pointer dereference\n\nRestoring terminal...\n\n"
        );
        return Err("wizard: program was killed: program experienced a panic".to_owned());
    }
    if model.canceled {
        // The resume state was already saved after each completed step; tell
        // the user how to pick it up again.
        if let Some(notice) = model.pause_notice() {
            print!("{notice}");
        }
        return Err("setup canceled".to_owned());
    }
    match &model.apply_err {
        Some(error) => Err(error.clone()),
        None => Ok(()),
    }
}
