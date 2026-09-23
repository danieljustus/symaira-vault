use std::io::{self, Write};
use std::process::ExitCode;

use clap_complete::{Shell, generate as generate_script};

pub fn generate(shell: &str, mut command: clap::Command) -> ExitCode {
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

    let mut script = Vec::new();
    generate_script(shell, &mut command, "symvault", &mut script);
    let mut stdout = io::stdout().lock();
    if let Err(error) = stdout.write_all(&script) {
        let _ = writeln!(io::stderr(), "write completion script: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
