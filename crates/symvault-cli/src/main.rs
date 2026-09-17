#![deny(unsafe_code)]

mod config;
mod device;
mod session_commands;

use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::{Args, Parser, Subcommand};
use symaira_core_version::new as new_version;
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
use symvault_core::session::MemoryKeyring;
use symvault_core::{
    TOOL_NAME,
    config::{Config, PathResolver},
    session::SessionManager,
};
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
use symvault_platform::OsKeyring;

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
    #[arg(long, global = true)]
    vault: Option<std::path::PathBuf>,
    #[arg(long, global = true)]
    quiet: bool,
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
    /// Manage paired devices for multi-device vault access.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Inspect the YAML configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Lock the vault by clearing its cached session.
    Lock,
    /// Unlock the vault or check whether a cached session is active.
    Unlock {
        #[arg(long)]
        check: bool,
    },
    /// Manage vault authentication and session status.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the raw configuration file.
    List {
        #[arg(long)]
        file: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Show authentication method and session-cache status.
    Status,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Generate a pairing token for a new device.
    Pair {
        #[arg(value_name = "ARG", num_args = 0..)]
        _extra: Vec<OsString>,
    },
    /// Join an existing vault as a new device.
    Join {
        /// Name for this device (defaults to hostname).
        #[arg(long)]
        name: Option<String>,
        /// Join without a git remote: path to the <token>.json invitation artifact.
        #[arg(long = "pairing-file")]
        pairing_file: Option<std::path::PathBuf>,
        /// Arguments: either `<remote-url> <token>` or `<token>` (with --pairing-file).
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
    /// Accept a join request and re-encrypt entries for the new device.
    Accept {
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
    /// List registered devices and unmanaged recipients.
    List {
        #[arg(value_name = "ARG", num_args = 0..)]
        _extra: Vec<OsString>,
    },
    /// Add this device to an existing multi-device vault.
    Add {
        /// Pair with an existing device using QR data.
        #[arg(long)]
        pair: bool,
        /// Name for this device (defaults to hostname).
        #[arg(long)]
        name: Option<String>,
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
    /// Revoke a device and re-encrypt all entries.
    Revoke {
        /// Skip confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
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
            let code = if error.use_stderr() { 1 } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    match cli.command {
        Some(Command::Version(_)) => write_version(&cli.output, cli.json),
        Some(Command::Lock) => run_lock(cli.vault.as_deref(), cli._profile.as_deref(), cli.quiet),
        Some(Command::Unlock { check }) => run_unlock(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            check,
            cli.quiet,
        ),
        Some(Command::Auth { command }) => match command {
            AuthCommand::Status => run_auth_status(
                cli.vault.as_deref(),
                cli._profile.as_deref(),
                &cli.output,
                cli.json,
                cli.quiet,
            ),
        },
        Some(Command::Device { command }) => {
            let vault = match cli.vault.as_deref() {
                Some(v) => v,
                None => {
                    let _ = writeln!(
                        io::stderr(),
                        "Error: device commands currently require explicit --vault; config/profile resolution is not yet ported"
                    );
                    return ExitCode::from(1);
                }
            };
            let result = match command {
                DeviceCommand::Pair { .. } => device::pair(vault, cli.quiet),
                DeviceCommand::Join {
                    name,
                    pairing_file,
                    args,
                } => device::join(vault, &args, name, pairing_file, cli.quiet),
                DeviceCommand::Accept { args } => {
                    if args.len() != 1 {
                        Err(format!("accepts 1 arg(s), received {}", args.len()))
                    } else {
                        device::accept(vault, &args[0], cli.quiet)
                    }
                }
                DeviceCommand::List { .. } => device::list(vault, &cli.output, cli.json, cli.quiet),
                DeviceCommand::Add { pair, name, args } => device::add(vault, pair, &args, name),
                DeviceCommand::Revoke { yes, args } => {
                    if args.len() != 1 {
                        Err(format!("accepts 1 arg(s), received {}", args.len()))
                    } else {
                        device::revoke(vault, &args[0], yes, cli.quiet)
                    }
                }
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "Error: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Some(Command::Config { command }) => {
            let path = match command {
                ConfigCommand::List { file } => match config::resolve_path(file.map(Into::into)) {
                    Ok(path) => path,
                    Err(error) => {
                        let _ = writeln!(io::stderr(), "Error: {error}");
                        return ExitCode::from(1);
                    }
                },
            };
            match config::list(&path, cli.quiet) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "Error: {error}");
                    ExitCode::from(6)
                }
            }
        }
        None => ExitCode::SUCCESS,
    }
}

fn run_lock(explicit_vault: Option<&Path>, profile: Option<&str>, quiet: bool) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let (manager, _) = runtime_session_manager();
        let output = session_commands::lock(&manager, &vault, quiet)?;
        if !output.is_empty() {
            eprint!("{output}");
        }
        Ok::<(), String>(())
    })();
    finish_session_result(result, false, 3)
}

fn run_unlock(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    check: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let (manager, _) = runtime_session_manager();
        if check {
            session_commands::check(&manager, &vault)?;
            if !quiet {
                eprintln!("Session active");
            }
            return Ok::<(), String>(());
        }
        Err::<(), String>(
            "interactive unlock is not yet available in the Rust CLI; use the Go CLI".to_owned(),
        )
    })();
    finish_session_result(result, true, 3)
}

fn run_auth_status(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let config = Config::load(vault.join("config.yaml"))
            .map_err(|error| format!("load config: {error}"))?;
        let (_, cache) = runtime_session_manager();
        let status =
            session_commands::auth_status(&vault, config.effective_auth_method(), cache, false)?;
        let rendered = session_commands::render_status(&status, output_format, json, quiet)?;
        if !rendered.is_empty() {
            print!("{rendered}");
        }
        Ok::<(), String>(())
    })();
    finish_session_result(result, false, 1)
}

fn finish_session_result(
    result: Result<(), String>,
    locked_error: bool,
    not_initialized_code: u8,
) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "Error: {error}");
            if error.contains("vault not initialized") {
                ExitCode::from(not_initialized_code)
            } else if locked_error && error == "no active session" {
                ExitCode::from(4)
            } else {
                ExitCode::from(1)
            }
        }
    }
}

fn require_initialized(vault: &Path) -> Result<(), String> {
    if vault.join("identity.age").is_file() && vault.join("config.yaml").is_file() {
        Ok(())
    } else {
        Err("vault not initialized. Run 'symvault init' first".to_owned())
    }
}

fn resolve_vault(explicit: Option<&Path>, profile: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return expand_vault_path(path);
    }
    if let Some(raw) = std::env::var_os("SYMVAULT_VAULT").filter(|value| !value.is_empty()) {
        return expand_vault_path(Path::new(&raw));
    }

    let resolver = PathResolver::new();
    let config = Config::load(resolver.config_path()).ok();
    let requested_profile = profile
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("SYMVAULT_PROFILE")
                .ok()
                .filter(|v| !v.trim().is_empty())
        });
    if let Some(name) = requested_profile.as_deref() {
        let config = config
            .as_ref()
            .ok_or_else(|| "cannot load config for profile resolution".to_owned())?;
        let profile = config
            .profile_for_name(name)
            .ok_or_else(|| format!("profile {name:?} not found"))?;
        return expand_vault_path(Path::new(&profile.vault_path));
    }
    if let Some(config) = config.as_ref()
        && !config.default_profile.is_empty()
        && let Some(profile) = config.profile_for_name(&config.default_profile)
    {
        return expand_vault_path(Path::new(&profile.vault_path));
    }
    if !resolver.vault_data_dir().as_os_str().is_empty() {
        return Ok(resolver.vault_data_dir().to_path_buf());
    }
    Err("cannot determine vault path".to_owned())
}

fn expand_vault_path(path: &Path) -> Result<PathBuf, String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "vault path must be UTF-8".to_owned())?
        .trim();
    if raw == "~" || raw.starts_with("~/") {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        return Ok(PathBuf::from(home).join(raw.strip_prefix("~/").unwrap_or("")));
    }
    Ok(PathBuf::from(raw))
}

fn runtime_session_manager() -> (SessionManager, session_commands::CacheStatus) {
    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let available = OsKeyring::is_available();
        let cache = session_commands::CacheStatus {
            backend: "os-keyring".to_owned(),
            persistent: available,
            message: if available {
                "OS keyring session cache is available.".to_owned()
            } else {
                "OS keyring unavailable. Sessions cannot be persisted.".to_owned()
            },
        };
        return (
            SessionManager::with_system_clock(Arc::new(OsKeyring)),
            cache,
        );
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        (
            SessionManager::with_system_clock(Arc::new(MemoryKeyring::new())),
            session_commands::CacheStatus {
                backend: "memory".to_owned(),
                persistent: false,
                message: "This build uses a memory-only session cache.".to_owned(),
            },
        )
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
    let info = new_version(TOOL_NAME, VERSION, 1);
    let mut stdout = io::stdout().lock();
    let result = if json || output_format == "json" {
        info.write(&mut stdout).map_err(|_| ())
    } else {
        writeln!(stdout, "{info}").map_err(|_| ())
    };
    if result.is_err() {
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
