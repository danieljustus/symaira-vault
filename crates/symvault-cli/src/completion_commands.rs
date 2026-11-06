use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

const SHELLS: [&str; 4] = ["bash", "zsh", "fish", "powershell"];

/// Cobra's word handling for `symvault completion <word>...` when every word
/// after `completion` is positional (no flag, so no value-taking global flag can
/// swallow one):
///
/// - `completion` is a command group, so a first word that names no shell
///   (`foo`, `-`, `help`, `Bash`) prints the group help and exits 0;
/// - a shell command takes no argument: the first extra word fails with
///   `unknown command "<word>" for "symvault completion <shell>"`, printed twice
///   (cobra, then the root handler) with exit 1 and no usage.
///
/// Anything else (flags, a bare shell) is left to the regular parser.
pub fn go_argument_shapes(args: &[OsString]) -> Option<ExitCode> {
    if args.get(1)?.to_str()? != "completion" {
        return None;
    }
    let words: Vec<&str> = args[2..]
        .iter()
        .map(|word| word.to_str())
        .collect::<Option<_>>()?;
    if words
        .iter()
        .any(|word| word.starts_with('-') && *word != "-")
    {
        return None;
    }
    let first = *words.first()?;
    if SHELLS.contains(&first) {
        let extra = *words.get(1)?;
        let message =
            format!("Error: unknown command \"{extra}\" for \"symvault completion {first}\"");
        eprintln!("{message}\n{message}");
        return Some(ExitCode::from(1));
    }
    Some(generate(None, false, clap::Command::new("symvault")))
}

pub fn generate(shell: Option<&str>, no_descriptions: bool, _command: clap::Command) -> ExitCode {
    let content = match shell {
        None => crate::cli_artifacts::DATA.help.get("symvault completion"),
        Some(shell) => crate::cli_artifacts::DATA.completions.get(&format!(
            "{shell}/{}",
            if no_descriptions {
                "plain"
            } else {
                "descriptions"
            }
        )),
    };
    let Some(content) = content else {
        eprintln!(
            "unsupported completion shell: {}",
            shell.unwrap_or_default()
        );
        return ExitCode::from(1);
    };
    if io::stdout().lock().write_all(content.as_bytes()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
