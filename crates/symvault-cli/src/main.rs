#![deny(unsafe_code)]

use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use symvault_core::{render_version_json, render_version_text};

const VERSION: &str = match option_env!("SYMVAULT_VERSION") {
    Some(version) => version,
    None => "dev",
};

#[derive(Debug, Parser)]
#[command(
    name = "symvault",
    about = "Symaira Vault is a Go CLI password manager",
    disable_help_subcommand = true,
    disable_version_flag = true
)]
struct Cli {
    #[arg(long, global = true, default_value = "~/.symvault")]
    _vault: String,
    #[arg(long, global = true)]
    _quiet: bool,
    #[arg(long, global = true)]
    _profile: Option<String>,
    #[arg(long, global = true, default_value = "text")]
    output: String,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    _no_pipe_warning: bool,
    #[arg(long, global = true, default_value = "auto")]
    _color: String,
    #[arg(long, global = true)]
    _theme: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the version of Symaira Vault.
    Version(VersionArgs),
}

#[derive(Debug, Args)]
struct VersionArgs {
    #[arg(value_name = "ARG", num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
    _extra: Vec<OsString>,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    if has_unescaped_version_flag(&args) {
        return write_unknown_version_flag();
    }

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return ExitCode::from(1);
        }
    };

    match cli.command {
        Some(Command::Version(_)) => write_version(&cli.output, cli.json),
        None => ExitCode::SUCCESS,
    }
}

fn has_unescaped_version_flag(args: &[OsString]) -> bool {
    for value in args.iter().skip(1) {
        if value == OsStr::new("--") {
            return false;
        }
        if value == OsStr::new("--version") {
            return true;
        }
    }
    false
}

fn write_version(output_format: &str, json: bool) -> ExitCode {
    let rendered = if json || output_format == "json" {
        match render_version_json(VERSION) {
            Ok(output) => output,
            Err(_) => return ExitCode::from(1),
        }
    } else {
        render_version_text(VERSION)
    };
    if io::stdout().write_all(rendered.as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn write_unknown_version_flag() -> ExitCode {
    let message = b"Error: unknown flag: --version\nError: unknown flag: --version\n";
    if io::stderr().write_all(message).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(1)
}
