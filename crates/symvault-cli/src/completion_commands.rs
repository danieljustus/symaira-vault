use std::{
    io::{self, Write},
    process::ExitCode,
};

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
