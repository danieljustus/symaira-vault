#![deny(unsafe_code)]

mod config;
mod device;
mod session_commands;
#[path = "device_input.rs"]
mod session_input;

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::{Args, Parser, Subcommand};
use symaira_core_version::new as new_version;
#[cfg(target_os = "macos")]
use symvault_core::platform::TouchId;
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
use symvault_crypto::{SecretBytes, decrypt_identity};
use symvault_platform::FallbackKeyring;
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
        let runtime = runtime_session_manager();
        let output = session_commands::lock(&runtime.manager, &vault, quiet)?;
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
        let runtime = runtime_session_manager();
        if check {
            session_commands::check(&runtime.manager, &vault)?;
            if !quiet {
                eprintln!("Session active");
            }
            return Ok::<(), String>(());
        }
        let config = Config::load(vault.join("config.yaml"))
            .map_err(|error| format!("load config: {error}"))?;
        let config_bytes =
            fs::read(vault.join("config.yaml")).map_err(|error| format!("read config: {error}"))?;
        let identity_bytes = fs::read(vault.join("identity.age"))
            .map_err(|error| format!("read identity: {error}"))?;
        let passphrase = session_input::unlock_passphrase(&config_bytes)?;
        let secret = SecretBytes::new(passphrase.as_bytes());
        decrypt_identity(&identity_bytes, &secret)
            .map_err(|error| format!("unlock vault: {error}"))?;
        let ttl = if config.session_timeout.is_zero() {
            std::time::Duration::from_secs(15 * 60)
        } else {
            config.session_timeout
        };
        let max_lifetime = if config.session_max_lifetime.is_zero() {
            std::time::Duration::from_secs(8 * 60 * 60)
        } else {
            config.session_max_lifetime
        };
        let vault_string = vault
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
        runtime
            .manager
            .save_passphrase(vault_string, passphrase.as_bytes(), ttl, max_lifetime)
            .map_err(|error| format!("save session: {error}"))?;
        if !runtime.cache_status().persistent {
            return Err(
                "session cache is memory-only; 'symvault unlock' cannot unlock future serve processes. Start serve with SYMVAULT_PASSPHRASE or use a build with OS keyring support".to_owned(),
            );
        }
        if !quiet {
            eprintln!("Vault unlocked (session TTL: {})", format_duration(ttl));
        }
        Ok::<(), String>(())
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
        let runtime = runtime_session_manager();
        let cache = runtime.cache_status();
        let status = session_commands::auth_status(
            &vault,
            config.effective_auth_method(),
            cache,
            touch_id_available(),
        )?;
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
            } else if locked_error
                && (error == "no active session"
                    || error.starts_with("session cache is memory-only"))
            {
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
        let raw = raw
            .to_str()
            .ok_or_else(|| "vault path must be UTF-8".to_owned())?
            .trim()
            .to_owned();
        if !raw.is_empty() {
            return expand_vault_path(Path::new(&raw));
        }
    }

    let resolver = PathResolver::new();
    // Go's VaultPath deliberately ignores a malformed default config while it
    // falls back to the resolver's data directory. A requested profile is a
    // different contract: its config error must be surfaced by the caller.
    let config_result = Config::load(resolver.config_path());
    let requested_profile = profile
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
        .or_else(|| {
            std::env::var("SYMVAULT_PROFILE")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        });
    if let Some(name) = requested_profile.as_deref() {
        let config = config_result
            .as_ref()
            .map_err(|error| format!("cannot load config for profile resolution: {error}"))?;
        let profile = config
            .profile_for_name(name)
            .ok_or_else(|| format!("profile {name:?} not found"))?;
        return expand_vault_path(Path::new(&profile.vault_path));
    }
    if let Some(config) = config_result.as_ref().ok()
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

fn touch_id_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        symvault_platform::MacOsTouchId.is_available()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn expand_vault_path(path: &Path) -> Result<PathBuf, String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "vault path must be UTF-8".to_owned())?;
    if raw == "~" || raw.starts_with("~/") {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        return Ok(PathBuf::from(home).join(raw.strip_prefix("~/").unwrap_or("")));
    }
    Ok(PathBuf::from(raw))
}

struct RuntimeSession {
    manager: SessionManager,
    keyring: Option<Arc<FallbackKeyring>>,
    memory_only: bool,
}

impl RuntimeSession {
    fn cache_status(&self) -> session_commands::CacheStatus {
        if self.memory_only
            || self
                .keyring
                .as_ref()
                .is_some_and(|keyring| keyring.is_fallback_active())
        {
            session_commands::CacheStatus {
                backend: "memory".to_owned(),
                persistent: false,
                message: if self.memory_only {
                    "This build uses a memory-only session cache.".to_owned()
                } else {
                    "OS keyring unavailable. Sessions are stored in process memory only.".to_owned()
                },
            }
        } else {
            session_commands::CacheStatus {
                backend: "os-keyring".to_owned(),
                persistent: true,
                message: "OS keyring session cache is available.".to_owned(),
            }
        }
    }
}

fn runtime_session_manager() -> RuntimeSession {
    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let start_in_fallback = std::env::var_os("CI").is_some()
            || std::env::var_os("GITHUB_ACTIONS").is_some()
            || std::env::var_os("HEADLESS").is_some()
            || std::env::var("SYMVAULT_TEST_KEYRING").as_deref() == Ok("memory");
        let keyring = FallbackKeyring::new(Arc::new(OsKeyring), start_in_fallback);
        RuntimeSession {
            manager: SessionManager::with_system_clock(keyring.clone()),
            keyring: Some(keyring),
            memory_only: false,
        }
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
        RuntimeSession {
            manager: SessionManager::with_system_clock(Arc::new(MemoryKeyring::new())),
            keyring: None,
            memory_only: true,
        }
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
