#![deny(unsafe_code)]

mod config;
mod device;
mod export_commands;
mod history_commands;
mod import_commands;
mod mcp_commands;
mod recipients_commands;
mod search_commands;
mod session_commands;
#[path = "device_input.rs"]
mod session_input;
mod utility_commands;
mod vault_commands;
mod write_commands;

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
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
use symvault_store::Store;
use symvault_sync::GitRepository;
use zeroize::Zeroizing;

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
    #[arg(long, global = true)]
    output: Option<String>,
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
    /// Initialize a new password vault.
    Init {
        #[arg(value_name = "VAULT_DIR")]
        vault_dir: Option<PathBuf>,
        #[arg(long, default_value = "ask")]
        auth: String,
    },
    /// List password entries.
    List {
        #[arg(value_name = "PREFIX")]
        prefix: Option<String>,
    },
    /// Get a password entry or field.
    Get {
        #[arg(value_name = "PATH[.FIELD]")]
        query: String,
        #[arg(short, long)]
        _print: bool,
    },
    /// Search entry paths and contents.
    #[command(alias = "search")]
    Find {
        #[arg(value_name = "QUERY")]
        query: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    /// Generate a secure password.
    #[command(alias = "gen")]
    Generate {
        #[arg(short = 'l', long, default_value_t = 20)]
        length: i64,
        #[arg(short = 's', long)]
        symbols: bool,
        #[arg(long)]
        store: Option<String>,
        #[arg(long)]
        reveal: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// Run a read-only Git history operation.
    Git {
        action: String,
        path: Option<String>,
    },
    /// Manage vault recipients.
    Recipients {
        #[command(subcommand)]
        command: RecipientsCommand,
    },
    /// Export vault entries to CSV or JSON.
    Export {
        #[arg(long, value_name = "FORMAT", required = true)]
        format: String,
        #[arg(long, default_value = "")]
        mapping: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Start the MCP server for agent access.
    Mcp {
        /// Agent profile used by the stdio server.
        #[arg(long)]
        agent: Option<String>,
        /// Run the MCP protocol over stdin/stdout.
        #[arg(long)]
        stdio: bool,
        /// Permit a locked vault (unsupported by the native stdio runtime).
        #[arg(long)]
        allow_locked: bool,
    },
    /// Set a password entry or field.
    Set {
        #[arg(value_name = "PATH[.FIELD]")]
        query: String,
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
        #[arg(long)]
        stdin_value: bool,
        #[arg(long)]
        allow_empty: bool,
        #[arg(long)]
        force: bool,
    },
    /// Delete a password entry.
    #[command(alias = "rm", alias = "remove")]
    Delete {
        #[arg(value_name = "PATH")]
        path: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Import entries from another password manager.
    Import {
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        skip_existing: bool,
        #[arg(long)]
        overwrite: bool,
        #[arg(long, default_value = "")]
        mapping: String,
    },
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
        /// Session duration override (for example, 30m or 1h).
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,
    },
    /// Manage vault authentication and session status.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RecipientsCommand {
    /// List recipients configured for the vault.
    List,
    /// Add a recipient public key.
    Add {
        recipient: String,
        #[arg(long)]
        reencrypt: bool,
    },
    /// Remove a recipient public key.
    #[command(alias = "rm")]
    Remove {
        recipient: String,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        no_reencrypt: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Get a value using dotted path notation.
    Get {
        #[arg(value_name = "DOTTED.PATH")]
        key: String,
        #[arg(long)]
        file: Option<String>,
    },
    /// Set a value using dotted path notation.
    Set {
        #[arg(value_name = "DOTTED.PATH")]
        key: String,
        #[arg(value_name = "VALUE")]
        value: String,
        #[arg(long)]
        file: Option<String>,
    },
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
        Some(Command::Init { vault_dir, auth }) => {
            run_init(cli.vault.as_deref(), vault_dir.as_deref(), &auth, cli.quiet)
        }
        Some(Command::List { prefix }) => run_list(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            prefix.as_deref().unwrap_or(""),
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Get { query, .. }) => run_get(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &query,
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Find { query, url }) => run_find(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            query.as_deref(),
            url.as_deref(),
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Generate {
            length,
            symbols,
            store,
            reveal,
            quiet,
        }) => run_generate(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            length,
            symbols,
            store.as_deref(),
            reveal,
            quiet,
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Git { action, path }) => run_git(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &action,
            path.as_deref(),
            cli.quiet,
        ),
        Some(Command::Recipients { command }) => run_recipients(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            command,
            cli.quiet,
        ),
        Some(Command::Export {
            format,
            mapping,
            yes,
        }) => run_export(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &format,
            &mapping,
            cli.output.as_deref().map(Path::new),
            yes,
            cli.quiet,
        ),
        Some(Command::Mcp {
            agent,
            stdio,
            allow_locked,
        }) => run_mcp(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            agent.as_deref(),
            stdio,
            allow_locked,
            cli.quiet,
        ),
        Some(Command::Set {
            query,
            value,
            stdin_value,
            allow_empty,
            force,
        }) => run_set(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &query,
            value,
            stdin_value,
            allow_empty,
            force,
            cli.quiet,
        ),
        Some(Command::Delete { path, yes }) => run_delete(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &path,
            yes,
            cli.json || cli.output.as_deref() == Some("json"),
            cli.quiet,
        ),
        Some(Command::Import {
            source,
            format,
            dry_run,
            prefix,
            skip_existing,
            overwrite,
            mapping,
        }) => run_import(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &source,
            format.as_deref(),
            dry_run,
            &prefix,
            skip_existing,
            overwrite,
            &mapping,
            cli.quiet,
        ),
        Some(Command::Version(_)) => {
            write_version(cli.output.as_deref().unwrap_or("text"), cli.json)
        }
        Some(Command::Lock) => run_lock(cli.vault.as_deref(), cli._profile.as_deref(), cli.quiet),
        Some(Command::Unlock { check, ttl }) => run_unlock(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            check,
            ttl.as_deref(),
            cli.quiet,
        ),
        Some(Command::Auth { command }) => match command {
            AuthCommand::Status => run_auth_status(
                cli.vault.as_deref(),
                cli._profile.as_deref(),
                cli.output.as_deref().unwrap_or("text"),
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
                DeviceCommand::List { .. } => device::list(
                    vault,
                    cli.output.as_deref().unwrap_or("text"),
                    cli.json,
                    cli.quiet,
                ),
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
            let (path, operation) = match command {
                ConfigCommand::Get { key, file } => {
                    let path = match config::resolve_path(file.map(Into::into)) {
                        Ok(path) => path,
                        Err(error) => {
                            let _ = writeln!(io::stderr(), "Error: {error}");
                            return ExitCode::from(1);
                        }
                    };
                    (path, ConfigOperation::Get { key })
                }
                ConfigCommand::List { file } => {
                    let path = match config::resolve_path(file.map(Into::into)) {
                        Ok(path) => path,
                        Err(error) => {
                            let _ = writeln!(io::stderr(), "Error: {error}");
                            return ExitCode::from(1);
                        }
                    };
                    (path, ConfigOperation::List)
                }
                ConfigCommand::Set { key, value, file } => {
                    let path = match config::resolve_path(file.map(Into::into)) {
                        Ok(path) => path,
                        Err(error) => {
                            let _ = writeln!(io::stderr(), "Error: {error}");
                            return ExitCode::from(1);
                        }
                    };
                    (path, ConfigOperation::Set { key, value })
                }
            };
            let result = match operation {
                ConfigOperation::Get { key } => config::get(
                    &path,
                    &key,
                    if cli.json {
                        "json"
                    } else {
                        cli.output.as_deref().unwrap_or("text")
                    },
                    cli.quiet,
                ),
                ConfigOperation::List => config::list(&path, cli.quiet),
                ConfigOperation::Set { key, value } => config::set(&path, &key, &value, cli.quiet),
            };
            match result {
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

fn run_init(
    explicit_vault: Option<&Path>,
    positional_vault: Option<&Path>,
    auth: &str,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        if !matches!(
            auth.trim().to_ascii_lowercase().as_str(),
            "ask" | "passphrase"
        ) {
            return Err("Touch ID unlock is not yet integrated in the Rust CLI".to_owned());
        }
        let vault = if let Some(path) = positional_vault.or(explicit_vault) {
            expand_vault_path(path)?
        } else {
            resolve_vault(None, None)?
        };
        if vault.join("config.yaml").is_file() {
            return Err(format!("vault already initialized at {}", vault.display()));
        }
        let passphrase = init_passphrase()?;
        if passphrase.len() < 12 {
            return Err("passphrase must be at least 12 characters".to_owned());
        }
        let secret = SecretBytes::new(passphrase.as_bytes());
        let identity = vault_commands::initialize(&vault, &secret)?;
        let repository = GitRepository::init(&vault)
            .map_err(|error| format!("cannot initialize git: {error}"))?;
        repository
            .create_gitignore()
            .map_err(|error| format!("cannot create .gitignore: {error}"))?;
        if !quiet {
            println!("Vault initialized at {}", vault.display());
            println!(
                "Public key: {}",
                symvault_crypto::recipient_string(&identity)
            );
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn init_passphrase() -> Result<Zeroizing<String>, String> {
    if let Ok(passphrase) = std::env::var("SYMVAULT_PASSPHRASE")
        && !passphrase.is_empty()
    {
        let opt_in = std::env::var("SYMVAULT_ALLOW_ENV_PASSPHRASE").unwrap_or_default();
        if !matches!(opt_in.as_str(), "1" | "true" | "yes") {
            return Err(
                "environment passphrase is disabled; opt in with SYMVAULT_ALLOW_ENV_PASSPHRASE=1"
                    .to_owned(),
            );
        }
        return Ok(Zeroizing::new(passphrase));
    }
    session_input::read_passphrase("Enter passphrase: ")
}

fn run_list(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    prefix: &str,
    output: &str,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let entries = vault_commands::list(&vault, &identity, prefix)?;
        let format = if json { "json" } else { output };
        vault_commands::write_list(&mut io::stdout().lock(), &entries, format, quiet)
    })();
    finish_vault_result(result)
}

fn run_get(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    query: &str,
    output: &str,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let result = vault_commands::get(&vault, &identity, query)?;
        let format = if json { "json" } else { output };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs() as i64;
        vault_commands::write_get_at(
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
            &result,
            format,
            quiet,
            now,
        )
    })();
    finish_vault_result(result)
}

fn run_find(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    query: Option<&str>,
    url_filter: Option<&str>,
    output: &str,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let query = query.unwrap_or("");
        if query.is_empty() && url_filter.unwrap_or("").is_empty() {
            return Err("accepts 1 arg(s), received 0".to_owned());
        }
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let matches = search_commands::find(&vault, &identity, query, url_filter)?;
        if matches.is_empty() {
            eprintln!("No matches found");
            return Ok::<(), String>(());
        }
        if quiet {
            return Ok(());
        }
        if json || output == "json" {
            let value = serde_json::json!({ "matches": matches });
            serde_json::to_writer(io::stdout().lock(), &value)
                .map_err(|error| error.to_string())?;
            println!();
            return Ok(());
        }
        if output != "text" {
            return Err(format!(
                "unknown output format: {output:?} (valid: text, json)"
            ));
        }
        let mut stdout = io::stdout().lock();
        for item in matches {
            write!(stdout, "{}", item.path).map_err(|error| error.to_string())?;
            if !item.fields.is_empty() {
                write!(stdout, " (matches: {})", item.fields.join(", "))
                    .map_err(|error| error.to_string())?;
            }
            writeln!(stdout).map_err(|error| error.to_string())?;
        }
        Ok(())
    })();
    finish_vault_result(result)
}

fn finish_vault_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "Error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_git(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    action: &str,
    path: Option<&str>,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        if action != "log" {
            return Err(format!("unknown action: {action} (use push, pull, or log)"));
        }
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let commits = history_commands::log(&vault, path, 0)
            .map_err(|error| format!("cannot get log: {error}"))?;
        history_commands::write_log(&mut io::stdout().lock(), &commits, quiet)
    })();
    finish_vault_result(result)
}

fn run_recipients(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    command: RecipientsCommand,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        match command {
            RecipientsCommand::List => {
                Err("recipients list helper is pending integration".to_owned())
            }
            RecipientsCommand::Add {
                recipient,
                reencrypt,
            } => {
                let identity = device::unlock_vault(&vault)?;
                recipients_commands::add(
                    &vault,
                    &identity,
                    &recipient,
                    reencrypt,
                    quiet,
                    &mut io::stdout().lock(),
                )
            }
            RecipientsCommand::Remove {
                recipient,
                yes,
                no_reencrypt,
            } => {
                let identity = device::unlock_vault(&vault)?;
                if !yes {
                    eprint!("Remove recipient {recipient}? (y/N): ");
                    io::stderr()
                        .flush()
                        .map_err(|error| format!("recipient confirmation prompt: {error}"))?;
                    let mut answer = String::new();
                    io::stdin()
                        .read_line(&mut answer)
                        .map_err(|error| format!("recipient confirmation: {error}"))?;
                    if !answer.trim().eq_ignore_ascii_case("y") {
                        if !quiet {
                            eprintln!("Canceled");
                        }
                        return Ok::<(), String>(());
                    }
                }
                recipients_commands::remove(
                    &vault,
                    &identity,
                    &recipient,
                    no_reencrypt,
                    quiet,
                    &mut io::stdout().lock(),
                )
            }
        }
    })();
    finish_vault_result(result)
}

#[allow(clippy::too_many_arguments)]
fn run_generate(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    length: i64,
    symbols: bool,
    store_path: Option<&str>,
    reveal: bool,
    command_quiet: bool,
    output: &str,
    json: bool,
    global_quiet: bool,
) -> ExitCode {
    let result = (|| {
        let password = utility_commands::generate_password(length, symbols)?;
        let Some(store_path) = store_path.filter(|path| !path.is_empty()) else {
            return utility_commands::render_password(
                &mut io::stdout().lock(),
                password.as_str(),
                utility_commands::OutputOptions {
                    format: output,
                    json,
                    quiet: global_quiet,
                },
            );
        };
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        write_commands::set_fields(
            &vault,
            &identity,
            store_path,
            BTreeMap::from([(
                String::from("password"),
                serde_json::Value::String(password.to_string()),
            )]),
        )?;
        let store = Store::open(&vault, &identity).map_err(|error| error.to_string())?;
        let file = store
            .configured_entry_path(store_path, &identity)
            .map_err(|error| error.to_string())?;
        let file = file.to_string_lossy();
        utility_commands::render_stored(
            &mut io::stdout().lock(),
            store_path,
            &file,
            password.as_str(),
            utility_commands::OutputOptions {
                format: output,
                json,
                quiet: command_quiet || global_quiet,
            },
            reveal,
        )
    })();
    finish_vault_result(result)
}

fn run_export(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    format: &str,
    mapping: &str,
    output: Option<&Path>,
    yes: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        let format = export_commands::ExportFormat::parse(format)?;
        let mapping = export_commands::parse_mapping(mapping)?;
        let options = export_commands::ExportOptions {
            format,
            mapping,
            output: output.map(Path::to_path_buf),
            yes,
            quiet,
        };
        let exported = export_commands::run_export(
            &vault,
            &options,
            confirm_export,
            || {
                require_initialized(&vault)?;
                device::unlock_vault(&vault)
            },
            |root, _entries| {
                let runtime = runtime_session_manager();
                let keyring = runtime
                    .keyring
                    .as_deref()
                    .ok_or_else(|| "audit keyring unavailable".to_owned())?;
                export_commands::audit_export(root, keyring)
            },
        )?;
        if exported.canceled {
            return Ok::<(), String>(());
        }
        if !exported.wrote_output {
            if !quiet {
                println!("No entries found in vault.");
            }
        } else if !quiet {
            println!("Exported {} entries", exported.entries);
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_mcp(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    agent: Option<&str>,
    stdio: bool,
    allow_locked: bool,
    _quiet: bool,
) -> ExitCode {
    let result = (|| {
        if !stdio {
            return Err("native MCP currently supports only --stdio".to_owned());
        }
        if allow_locked {
            return Err("--allow-locked is not supported by the native MCP runtime".to_owned());
        }
        let agent = agent
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "--agent is required in --stdio mode".to_owned())?;
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let runtime = runtime_session_manager();
        let keyring = runtime
            .keyring
            .as_deref()
            .ok_or_else(|| "MCP audit keyring unavailable".to_owned())?;
        mcp_commands::run(&vault, agent, identity, keyring)
    })();
    finish_vault_result(result)
}

#[allow(clippy::too_many_arguments)] // Direct dispatch of CLI flags.
fn run_set(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    query: &str,
    value: Option<String>,
    stdin_value: bool,
    allow_empty: bool,
    force: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let value = if stdin_value {
            let mut line = String::new();
            io::stdin()
                .read_line(&mut line)
                .map_err(|error| format!("read --stdin-value: {error}"))?;
            if line.is_empty() {
                return Err("read --stdin-value: EOF".to_owned());
            }
            line.trim_end_matches(['\r', '\n']).to_owned()
        } else if let Some(value) = value {
            value
        } else {
            interactive_set_value(query, allow_empty)?
        };
        let path = write_commands::set_value(&vault, &identity, query, value, allow_empty, force)?;
        if !quiet {
            println!("Entry saved: {path}");
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn interactive_set_value(query: &str, allow_empty: bool) -> Result<String, String> {
    let field = query
        .rsplit_once('.')
        .map(|(_, field)| if field.is_empty() { "password" } else { field })
        .unwrap_or("password");
    let value = session_input::read_passphrase(&format!("Enter value for {field}: "))?.to_string();
    if write_commands::sensitive_field(field) && !value.is_empty() {
        let confirmation = session_input::read_passphrase(&format!("Confirm value for {field}: "))?;
        if confirmation.as_str() != value {
            return Err("values do not match".to_owned());
        }
    }
    if value.is_empty() && write_commands::sensitive_field(field) && !allow_empty {
        return Err(format!(
            "cannot set empty value for sensitive field {field:?} (use --allow-empty to override)"
        ));
    }
    Ok(value)
}

fn run_delete(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    path: &str,
    yes: bool,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        if !yes {
            eprint!("Delete {path}? (y/N): ");
            io::stderr()
                .flush()
                .map_err(|error| format!("delete confirmation prompt: {error}"))?;
            let mut answer = String::new();
            io::stdin()
                .read_line(&mut answer)
                .map_err(|error| format!("delete confirmation: {error}"))?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"deleted": false, "path": path, "canceled": true})
                    );
                } else if !quiet {
                    eprintln!("Canceled");
                }
                return Ok::<(), String>(());
            }
        }
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        write_commands::delete(&vault, &identity, path)?;
        if json {
            println!("{}", serde_json::json!({"deleted": true, "path": path}));
        } else if !quiet {
            println!("Deleted: {path}");
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

#[allow(clippy::too_many_arguments)] // Direct dispatch of CLI flags.
fn run_import(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    source: &Path,
    format: Option<&str>,
    dry_run: bool,
    prefix: &str,
    skip_existing: bool,
    overwrite: bool,
    mapping: &str,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let result = import_commands::run_import(
            &vault,
            &identity,
            &import_commands::ImportOptions {
                source: source.to_owned(),
                format: format.map(str::to_owned),
                dry_run,
                prefix: prefix.to_owned(),
                skip_existing,
                overwrite,
                mapping: mapping.to_owned(),
            },
            write_commands::import_fields,
            write_commands::replace_fields,
            |root, identity, path, secret_type| {
                write_commands::set_secret_type(root, identity, path, secret_type)
            },
        )?;
        if !quiet {
            println!(
                "Import summary: {} imported, {} skipped",
                result.imported, result.skipped
            );
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn confirm_export() -> Result<bool, String> {
    eprint!("Export all vault entries as plaintext? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| format!("export confirmation prompt: {error}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("export confirmation: {error}"))?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn run_unlock(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    check: bool,
    ttl_override: Option<&str>,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let runtime = runtime_session_manager();
        // Parse before --check so an invalid override is an input error even
        // when no session lookup is needed.
        let ttl_override = ttl_override
            .map(session_commands::parse_ttl_override)
            .transpose()?
            .flatten();
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
        let passphrase = unlock_passphrase(&config_bytes, &config, &vault, &runtime)?;
        let secret = SecretBytes::new(passphrase.as_bytes());
        let decrypted_identity = decrypt_identity(&identity_bytes, &secret)
            .map_err(|error| format!("unlock vault: {error}"))?;
        let configured_ttl = if config.session_timeout.is_zero() {
            std::time::Duration::from_secs(15 * 60)
        } else {
            config.session_timeout
        };
        let ttl = ttl_override.unwrap_or(configured_ttl);
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
        // Go treats identity-cache persistence as best effort after saving the
        // passphrase session. Keep the parsed identity alive and persist its
        // canonical zeroizing representation.
        let identity_string = symvault_crypto::identity_string(&decrypted_identity);
        let _ = runtime.manager.save_identity(
            vault_string,
            identity_string.as_bytes(),
            ttl,
            max_lifetime,
        );
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

fn unlock_passphrase(
    config_bytes: &[u8],
    config: &Config,
    vault: &Path,
    runtime: &RuntimeSession,
) -> Result<Zeroizing<String>, String> {
    let vault_string = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    // An explicit unlock first reuses a valid cached passphrase. This mirrors
    // Go's session resolver and avoids prompting or invoking Touch ID when a
    // persistent session is already available.
    if let Ok(bytes) = runtime.manager.load_passphrase(vault_string)
        && !bytes.is_empty()
    {
        return String::from_utf8(bytes)
            .map(Zeroizing::new)
            .map_err(|_| "cached session passphrase is not valid UTF-8".to_owned());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (config, vault, runtime);
    #[cfg(target_os = "macos")]
    if config.effective_auth_method() == symvault_core::config::AuthMethod::Touchid
        && session_commands::gui_session_available()
        && !is_test_or_ci()
        && let Some(keyring) = runtime.keyring.as_deref()
    {
        let touch_id = symvault_platform::MacOsTouchId;
        if let Ok(bytes) = session_commands::load_touch_id_passphrase(vault, keyring, &touch_id) {
            let passphrase = String::from_utf8(bytes.to_vec())
                .map_err(|_| "Touch ID passphrase is not valid UTF-8".to_owned())?;
            return Ok(Zeroizing::new(passphrase));
        }
    }
    session_input::unlock_passphrase_for_session(config_bytes)
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
        let start_in_fallback =
            is_test_or_ci() || std::env::var("SYMVAULT_TEST_KEYRING").as_deref() == Ok("memory");
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

fn is_test_or_ci() -> bool {
    ["CI", "GITHUB_ACTIONS", "HEADLESS"]
        .into_iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
        || std::env::var("SYMVAULT_TEST_KEYRING").as_deref() == Ok("memory")
}

enum ConfigOperation {
    Get { key: String },
    List,
    Set { key: String, value: String },
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
