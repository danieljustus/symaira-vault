use std::io::{self, Write};
use std::process::ExitCode;

use clap_complete::{Shell, generate as generate_script};

pub fn generate(
    shell: Option<&str>,
    no_descriptions: bool,
    mut command: clap::Command,
) -> ExitCode {
    let Some(shell) = shell else {
        let mut stdout = io::stdout().lock();
        return match command.find_subcommand_mut("completion") {
            Some(completion) => {
                if completion.write_long_help(&mut stdout).is_ok() && writeln!(stdout).is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            None => ExitCode::FAILURE,
        };
    };
    let shell = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        _ => {
            let _ = writeln!(io::stderr(), "unsupported completion shell: {shell}");
            return ExitCode::from(2);
        }
    };

    if no_descriptions {
        command = strip_descriptions(command);
    }
    let mut script = Vec::new();
    generate_script(shell, &mut command, "symvault", &mut script);
    let mut stdout = io::stdout().lock();
    if let Err(error) = stdout.write_all(&script) {
        let _ = writeln!(io::stderr(), "write completion script: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn strip_descriptions(command: clap::Command) -> clap::Command {
    command
        .about(None)
        .long_about(None)
        .mut_args(|arg| arg.help(None).long_help(None))
        .mut_subcommands(strip_descriptions)
}
