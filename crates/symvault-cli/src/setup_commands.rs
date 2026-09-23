use std::{io::Write, process::ExitCode};

const NON_TTY_ERROR: &str =
    "setup needs a TTY; use `symvault init` for non-interactive vault initialization";

pub fn run<W: Write>(
    _no_resume: bool,
    _keep_on_error: bool,
    stdin_is_terminal: bool,
    errors: &mut W,
) -> ExitCode {
    if stdin_is_terminal {
        let _ = writeln!(
            errors,
            "Error: interactive setup wizard is not implemented in the Rust CLI yet"
        );
    } else {
        let _ = writeln!(errors, "Error: {NON_TTY_ERROR}\nError: {NON_TTY_ERROR}");
    }
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::{NON_TTY_ERROR, run};
    use std::process::ExitCode;

    #[test]
    fn non_tty_matches_go_error_and_exit() {
        let mut stderr = Vec::new();
        assert_eq!(run(false, false, false, &mut stderr), ExitCode::from(1));
        assert_eq!(
            stderr,
            format!("Error: {NON_TTY_ERROR}\nError: {NON_TTY_ERROR}\n").as_bytes()
        );
    }

    #[test]
    fn tty_reports_the_unimplemented_interactive_wizard() {
        let mut stderr = Vec::new();
        assert_eq!(run(true, true, true, &mut stderr), ExitCode::from(1));
        assert_eq!(
            stderr,
            b"Error: interactive setup wizard is not implemented in the Rust CLI yet\n"
        );
    }
}
