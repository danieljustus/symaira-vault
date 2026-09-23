#![deny(unsafe_code)]

mod add_commands;
mod agent_audit_commands;
mod agent_doctor_commands;
mod agent_install_commands;
mod agent_list_commands;
mod agent_profile_commands;
mod agent_skill_commands;
mod agent_token_commands;
mod agent_uninstall_commands;
mod agent_upgrade_commands;
mod agent_whoami_commands;
mod audit_commands;
mod audit_export_commands;
mod backup_commands;
mod config;
mod daemon_commands;
mod device;
mod device_approval;
mod doctor_commands;
mod edit_commands;
mod export_commands;
mod file_commands;
mod history_commands;
mod import_commands;
mod import_review_commands;
mod mcp_commands;
mod migrate_kdf_commands;
mod path_migration_commands;
mod policy_commands;
mod profile_commands;
mod recipients_commands;
mod remote_commands;
mod run_commands;
mod search_commands;
mod session_commands;
#[path = "device_input.rs"]
mod session_input;
mod share_commands;
mod sync_commands;
mod template_commands;
mod update_commands;
mod utility_commands;
mod vault_commands;
mod verify_commands;
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
    config::{AuthMethod, Config, PathResolver, VaultConfig},
    session::SessionManager,
};
use symvault_crypto::{SecretBytes, decrypt_identity, encrypt_identity_scrypt};
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
use symvault_sync::{CommitOptions, GitError, GitRepository, GoTime};
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
    /// Run a command with secrets injected as environment variables.
    Run {
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        #[arg(short = 'f', long)]
        env_file: Vec<PathBuf>,
        #[arg(long)]
        passthrough: Vec<String>,
        #[arg(short = 'C', long)]
        working_dir: Option<PathBuf>,
        #[arg(short = 't', long)]
        timeout: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage secret sharing between agents.
    Share {
        #[command(subcommand)]
        command: ShareCommand,
    },
    /// Inspect declarative policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage agent profiles.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Initialize a new password vault.
    Init {
        #[arg(value_name = "VAULT_DIR")]
        vault_dir: Option<PathBuf>,
        #[arg(long, default_value = "ask")]
        auth: String,
    },
    /// Add a new password entry.
    #[command(alias = "new", alias = "create")]
    Add {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
        #[arg(long)]
        stdin_value: bool,
        #[arg(long)]
        stdin_totp_secret: bool,
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: i64,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        totp_secret: Option<String>,
        #[arg(long)]
        totp_issuer: Option<String>,
        #[arg(long)]
        totp_account: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        allow_empty: bool,
        #[arg(long = "type")]
        secret_type: Option<String>,
        #[arg(long)]
        usage_hint: Option<String>,
        #[arg(long)]
        auto_rotate: bool,
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// Edit an entry using an external editor.
    #[command(alias = "modify")]
    Edit {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long)]
        editor: Option<String>,
    },
    /// List password entries.
    #[command(alias = "ls")]
    List {
        #[arg(value_name = "PREFIX")]
        prefix: Option<String>,
    },
    /// Get a password entry or field.
    #[command(alias = "show", alias = "cat")]
    Get {
        #[arg(value_name = "PATH[.FIELD]")]
        query: String,
        #[arg(short, long)]
        _print: bool,
        #[arg(long)]
        length: bool,
        #[arg(long)]
        digest: bool,
        #[arg(long)]
        metadata: bool,
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
    /// Check vault health and configuration
    Doctor {
        /// Skip checks that require network access
        #[arg(long)]
        no_network: bool,
        /// Return non-zero exit code for warnings (7) or failures (8)
        #[arg(long)]
        strict: bool,
        /// Only run checks matching these glob patterns (comma-separated, e.g. vault.*)
        #[arg(long, value_delimiter = ',')]
        only: Option<Vec<String>>,
        /// Skip checks matching these glob patterns (comma-separated)
        #[arg(long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,
        /// Auto-repair safe issues (permissions, gitignore, git init)
        #[arg(long)]
        fix: bool,
        /// Log what --fix would do without modifying anything
        #[arg(long)]
        fix_dry_run: bool,
        /// Skip slow checks
        #[arg(long)]
        quick: bool,
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
    /// Migrate vault storage formats.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// Generate configuration files from built-in templates.
    Template {
        #[command(subcommand)]
        command: TemplateCommand,
    },
    /// Create a compressed vault backup archive.
    Backup {
        #[arg(value_name = "ARCHIVE_PATH")]
        archive: PathBuf,
        #[arg(long)]
        exclude_git: bool,
    },
    /// Restore a vault from a backup archive.
    Restore {
        #[arg(value_name = "ARCHIVE_PATH")]
        archive: PathBuf,
    },
    /// Add or export binary file attachments.
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    /// Verify or rebuild the vault entry manifest.
    Verify {
        #[arg(long)]
        rebuild: bool,
        #[arg(long = "rebuild-only")]
        rebuild_only: bool,
    },
    /// Synchronize encrypted vault files with the Git remote.
    Sync {
        #[arg(long, short = 'p')]
        push: bool,
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Inspect the vault Git remote.
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    /// List configured vault profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// View MCP audit log entries.
    Audit {
        #[command(subcommand)]
        command: Option<AuditCommand>,
        #[arg(short = 'n', long, default_value_t = 20)]
        tail: i64,
        #[arg(short = 'j', long)]
        audit_json: bool,
        #[arg(short = 'a', long, default_value = "default")]
        agent: String,
        #[arg(short = 's', long, default_value = "")]
        since: String,
        #[arg(long)]
        failed: bool,
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
        #[command(subcommand)]
        action: Option<McpAction>,
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
    /// Deprecated: use `symvault agent install <agent> --config-only`.
    ///
    /// Kept as a hidden compatibility command because `cmd/mcp/mcp_config.go`
    /// exposes it in the oracle; it only prints the deprecation notice.
    #[command(name = "mcp-config", hide = true)]
    McpConfig {
        #[arg(value_name = "AGENT", num_args = 0..)]
        _args: Vec<String>,
    },
    /// Deprecated: use `symvault agent token rotate <name>`.
    #[command(name = "mcp-token-rotate", hide = true)]
    McpTokenRotate {
        #[arg(num_args = 0..)]
        _args: Vec<String>,
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
        #[arg(long)]
        totp_secret: Option<String>,
        #[arg(long)]
        totp_issuer: Option<String>,
        #[arg(long)]
        totp_account: Option<String>,
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
        /// Catch-all: cobra validates exact-1-arg on the parent, and the
        /// first non-flag word may name the `review` group (Find semantics).
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<OsString>,
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
        #[arg(
            long,
            help = "Import entries into quarantine/<import-id>/ for human review"
        )]
        quarantine: bool,
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
    /// Check for Symaira Vault updates or show installation-method info.
    Update {
        /// Catch-all: cobra Find dispatches on the first non-flag word
        /// (`info`); unknown words reach the runner for byte-exact errors.
        #[arg(value_name = "COMMAND", num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Manage vault authentication and session status.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

/// The Go CLI exposes `mcp` as both a server and a service-installer command
/// group; `serve` is accepted there as an alias for the bare `mcp` form.
#[derive(Debug, Subcommand)]
enum McpAction {
    /// Run the MCP server over the selected transport.
    Serve {
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
    /// Install MCP server as a background service.
    Install,
    /// Show MCP server service status.
    Status,
    /// Remove the MCP server background service.
    Uninstall,
    /// Deprecated: use `symvault agent token <action> <name>`.
    ///
    /// Deliberately a catch-all instead of clap subcommands: the oracle's
    /// `mcp token <unknown>` still runs the group handler (Cobra falls through
    /// to the parent `RunE`), so the words after `token` are dispatched here.
    #[command(hide = true)]
    Token {
        #[arg(value_name = "ARGS", num_args = 0..)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Validate { file: PathBuf },
    Apply { file: PathBuf },
    Remove { name: String },
    List,
}

#[derive(Debug, Subcommand)]
enum ShareCommand {
    /// Revoke a share grant.
    Revoke { grant_id: String },
    /// List share grants.
    List {
        #[arg(long, default_value = "")]
        status: String,
        #[arg(long, default_value = "")]
        from: String,
        #[arg(long, default_value = "")]
        to: String,
        #[arg(long, default_value = "")]
        path: String,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    List,
    Doctor {
        name: String,
    },
    Audit {
        name: String,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value = "")]
        since: String,
        #[arg(long, default_value = "table")]
        format: String,
    },
    Token {
        #[command(subcommand)]
        command: AgentTokenCommand,
    },
    Whoami {
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    Profile {
        #[command(subcommand)]
        command: AgentProfileCommand,
    },
    Uninstall {
        name: String,
        /// Don't remove the skill file.
        #[arg(long)]
        keep_skill: bool,
        /// Don't modify the agent config file.
        #[arg(long)]
        keep_config: bool,
        /// Skip confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Upgrade an agent's security tier with interactive confirmation.
    Upgrade {
        /// Validated by hand so the message matches Cobra's `ExactArgs(1)`.
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
        /// Target security tier (safe, standard, admin; 'read-only' accepted as alias for 'safe').
        #[arg(long, default_value = "")]
        tier: String,
        /// Show diff without applying changes.
        #[arg(long)]
        dry_run: bool,
        /// Non-interactive mode (requires --reason).
        #[arg(long)]
        yes: bool,
        /// Audit reason for the upgrade (required with --yes).
        #[arg(long, default_value = "")]
        reason: String,
        /// Rotate the agent's MCP token on upgrade.
        #[arg(long)]
        rotate_token: bool,
        /// Skip biometric verification (not recommended).
        #[arg(long)]
        no_biometric: bool,
    },
    /// Export or refresh embedded skill packages for AI agents.
    Skill {
        /// Omitted entirely: the oracle prints the command group's help and
        /// exits 0 (`AgentSkillCommand` is optional on purpose).
        #[command(subcommand)]
        command: Option<AgentSkillCommand>,
    },
    /// Install the MCP server entry, skill package and token for an AI agent.
    Install {
        /// Validated by hand so the messages match Cobra's arg validator
        /// (exact-1-arg or `--auto-detect` without a name).
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
        /// Install every supported agent that is detected on this machine.
        #[arg(long)]
        auto_detect: bool,
        /// Permission tier: safe, standard or admin (default safe).
        #[arg(long, default_value = "safe")]
        tier: String,
        /// Use HTTP transport instead of stdio.
        #[arg(long)]
        http: bool,
        /// Validate and render, but do not write anything.
        #[arg(long)]
        dry_run: bool,
        /// Skip the agent's MCP config file and only install the skill.
        #[arg(long)]
        skill_only: bool,
        /// Skip the skill file and only update the agent's MCP config.
        #[arg(long)]
        config_only: bool,
        /// Overwrite an existing agent profile in the vault config.
        #[arg(long)]
        force: bool,
        /// Suppress the success line.
        #[arg(long)]
        quiet: bool,
        /// Output format: text, json or yaml (default text).
        #[arg(long, default_value = "text")]
        output: String,
    },
}

#[derive(Debug, Subcommand)]
enum AgentSkillCommand {
    /// Write the skill package as a tar.gz archive.
    Export {
        /// Output file (default symvault-<agent>-skill.tar.gz).
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Validated by hand so the message matches Cobra's `ExactArgs(1)`.
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
    /// Re-render an installed skill file in place.
    Refresh {
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AgentTokenCommand {
    List {
        name: String,
    },
    New {
        name: String,
        #[arg(
            long,
            use_value_delimiter = true,
            value_delimiter = ',',
            default_value = "*"
        )]
        tools: Vec<String>,
        #[arg(long, default_value = "")]
        ttl: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    Revoke {
        name: String,
        token_id: String,
    },
    Rotate {
        name: String,
        #[arg(
            long,
            use_value_delimiter = true,
            value_delimiter = ',',
            default_value = "*"
        )]
        tools: Vec<String>,
        #[arg(long, default_value = "")]
        ttl: String,
        #[arg(long, default_value = "")]
        label: String,
    },
}

#[derive(Debug, Subcommand)]
enum AgentProfileCommand {
    Edit {
        name: String,
    },
    Export {
        name: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    Show {
        name: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Rotate the audit log HMAC key.
    RotateKey,
    /// Export local audit evidence.
    Export {
        #[arg(long, default_value = "")]
        agent: String,
        #[arg(long, default_value = "")]
        action: String,
        #[arg(long, default_value = "")]
        since: String,
        #[arg(long)]
        failed: bool,
        #[arg(short = 'o', long)]
        output: Option<String>,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        verify_hmac: bool,
        #[arg(long)]
        redact_paths: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RemoteCommand {
    Init {
        target: String,
        #[arg(short = 'n', long, default_value = "origin")]
        name: String,
        #[arg(short = 'p', long)]
        path: Option<String>,
        #[arg(long)]
        push: bool,
    },
    Status,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    List,
    Add { name: String },
    Use { name: String },
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
enum FileCommand {
    /// Attach a source file to an entry field.
    Add {
        #[arg(value_name = "PATH")]
        path: String,
        #[arg(long)]
        field: String,
        #[arg(long = "from")]
        source: PathBuf,
        #[arg(long = "type", default_value = "certificate")]
        secret_type: String,
        #[arg(long, default_value_t = file_commands::DEFAULT_MAX_ATTACHMENT_SIZE)]
        max_size: u64,
        #[arg(long)]
        shred: bool,
    },
    /// Export a stored file attachment.
    Get {
        #[arg(value_name = "PATH[#FIELD]")]
        query: String,
        #[arg(long)]
        field: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run a command with an attachment materialized to a private temporary file.
    Use {
        #[arg(value_name = "PATH[#FIELD]")]
        query: String,
        #[arg(long)]
        field: Option<String>,
        #[arg(long = "as")]
        as_name: Option<String>,
        #[arg(short, long)]
        timeout: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate the configuration file.
    Validate {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        #[arg(long)]
        fix: bool,
    },
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
    /// Set the vault unlock authentication method.
    Set {
        #[arg(value_name = "passphrase|touchid")]
        method: String,
    },
    /// Change the vault master passphrase.
    RotatePassphrase {
        #[arg(
            long,
            default_value_t = true,
            num_args = 0..=1,
            require_equals = true,
            action = clap::ArgAction::Set,
            default_missing_value = "true"
        )]
        reencrypt: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
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
    /// List devices enrolled as approval devices.
    ApprovalList {
        #[arg(value_name = "ARG", num_args = 0..)]
        _extra: Vec<OsString>,
    },
    /// Revoke an approval device's ability to approve/deny requests.
    ApprovalRevoke {
        /// Skip confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        #[arg(value_name = "ARG", num_args = 0..)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Preview legacy-to-XDG paths without writing.
    #[command(alias = "xdg")]
    Paths,
    /// Migrate vault entries to pseudonymized storage paths.
    Pseudonymize {
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Re-encrypt a legacy scrypt identity using Argon2id.
    Kdf {
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Migrate agent profiles and config to the v4.0 tier format.
    V4 {
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Upgrade a cached session from the legacy plaintext format.
    Session {
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TemplateCommand {
    Generate {
        #[arg(long = "type")]
        kind: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "app")]
        name: String,
        #[arg(long, default_value = "")]
        prefix: String,
        refs: Vec<String>,
    },
}

#[derive(Debug, Args)]
struct VersionArgs {
    #[arg(value_name = "ARG", num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
    _extra: Vec<OsString>,
}

/// Windows gives the main thread a 1 MiB stack. Building and parsing the generated
/// clap command tree (45+ subcommands) exceeds that in a debug build — reproduced
/// locally as `ulimit -s 1024` aborting even on `--help`. Run the CLI on a thread
/// with an explicit stack so every platform behaves the same; the Windows
/// device-list differential is the regression check for this.
const CLI_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> ExitCode {
    match std::thread::Builder::new()
        .name("symvault".to_string())
        .stack_size(CLI_STACK_SIZE)
        .spawn(run_cli)
    {
        Ok(handle) => handle.join().unwrap_or_else(|_| ExitCode::from(101)),
        // Thread creation is not expected to fail; running inline keeps the CLI usable.
        Err(_) => run_cli(),
    }
}

fn run_cli() -> ExitCode {
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

    session_input::set_quiet(cli.quiet);

    match cli.command {
        Some(Command::Init { vault_dir, auth }) => {
            run_init(cli.vault.as_deref(), vault_dir.as_deref(), &auth, cli.quiet)
        }
        Some(Command::Add {
            name,
            value,
            stdin_value,
            stdin_totp_secret,
            generate,
            length,
            username,
            url,
            notes,
            totp_secret,
            totp_issuer,
            totp_account,
            force,
            allow_empty,
            secret_type,
            usage_hint,
            auto_rotate,
            expires_at,
        }) => run_add(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            add_commands::AddOptions {
                path: name,
                value,
                generate,
                length,
                username: username.unwrap_or_default(),
                url: url.unwrap_or_default(),
                notes: notes.unwrap_or_default(),
                totp_secret: totp_secret.unwrap_or_default(),
                totp_issuer: totp_issuer.unwrap_or_default(),
                totp_account: totp_account.unwrap_or_default(),
                force,
                allow_empty,
                secret_type: secret_type.unwrap_or_default(),
                usage_hint: usage_hint.unwrap_or_default(),
                auto_rotate,
                expires_at: expires_at.unwrap_or_default(),
            },
            stdin_value,
            stdin_totp_secret,
            cli.quiet,
        ),
        Some(Command::Edit { name, editor }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                require_initialized(&vault)?;
                let identity = device::unlock_vault(&vault)?;
                edit_commands::edit(
                    &vault,
                    &identity,
                    &edit_commands::EditOptions {
                        path: name.clone(),
                        editor: editor.unwrap_or_default(),
                    },
                )?;
                if !cli.quiet {
                    println!("Entry updated: {name}");
                }
                Ok::<(), String>(())
            })();
            finish_vault_result(result)
        }
        Some(Command::List { prefix }) => run_list(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            prefix.as_deref().unwrap_or(""),
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Get {
            query,
            _print,
            length,
            digest,
            metadata,
        }) => run_get(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &query,
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            _print,
            length,
            digest,
            metadata,
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
        Some(Command::Doctor {
            no_network,
            strict,
            only,
            exclude,
            fix,
            fix_dry_run,
            quick,
        }) => run_doctor(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            no_network,
            strict,
            only,
            exclude,
            fix,
            fix_dry_run,
            quick,
            cli.output.as_deref(),
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
            cli.output.as_deref().unwrap_or("text"),
            cli.json,
            cli.quiet,
        ),
        Some(Command::Backup {
            archive,
            exclude_git,
        }) => run_backup(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &archive,
            exclude_git,
            cli.quiet,
        ),
        Some(Command::Restore { archive }) => run_restore(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &archive,
            cli.quiet,
        ),
        Some(Command::File { command }) => run_file(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            command,
            cli.quiet,
        ),
        Some(Command::Verify {
            rebuild,
            rebuild_only,
        }) => run_verify(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            rebuild,
            rebuild_only,
            cli.quiet,
        ),
        Some(Command::Sync { push, force }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                require_initialized(&vault)?;
                sync_commands::sync(
                    &vault,
                    push,
                    force,
                    cli.quiet,
                    &mut io::stdout().lock(),
                    &mut io::stderr().lock(),
                )
            })();
            finish_vault_result(result)
        }
        Some(Command::Remote {
            command:
                RemoteCommand::Init {
                    target,
                    name,
                    path,
                    push,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let home = cli_home_directory()?;
                remote_commands::init(
                    &vault,
                    &home,
                    &target,
                    &name,
                    path.as_deref(),
                    push,
                    cli.quiet,
                    &mut io::stdout().lock(),
                    &mut io::stderr().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }

        Some(Command::Remote {
            command: RemoteCommand::Status,
        }) => run_remote_status(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            if cli.json {
                "json"
            } else {
                cli.output.as_deref().unwrap_or("text")
            },
            cli.quiet,
        ),
        Some(Command::Profile { command }) => {
            run_profile(&command, cli.vault.as_deref(), cli.quiet)
        }
        Some(Command::Run {
            env,
            env_file,
            passthrough,
            working_dir,
            timeout,
            command,
        }) => {
            let result = (|| {
                let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                require_initialized(&root)?;
                let identity = device::unlock_vault(&root)?;
                let environment =
                    run_commands::build_secret_environment(&env, &env_file, |reference| {
                        run_commands::resolve_secret_ref(&root, &identity, reference)
                    })?;
                let timeout = timeout
                    .as_deref()
                    .map(session_commands::parse_ttl_override)
                    .transpose()?
                    .flatten();
                let redactions: Vec<_> = environment
                    .values
                    .values()
                    .map(|value| value.as_bytes().to_vec())
                    .collect();
                let result = run_commands::run_process(run_commands::ProcessOptions {
                    command: &command,
                    environment: &environment.values,
                    extra_environment: &[],
                    generic_redaction: true,
                    passthrough: &passthrough,
                    working_directory: working_dir
                        .as_deref()
                        .filter(|path| !path.as_os_str().is_empty()),
                    timeout,
                    redactions: &redactions,
                    whitelist: run_commands::RUN_ENV_WHITELIST,
                })?;
                if result.timed_out {
                    return Err(format!(
                        "command timed out after {}",
                        run_commands::format_timeout(timeout.unwrap_or_default())
                    ));
                }
                print!("{}", result.stdout);
                eprint!("{}", result.stderr);
                if result.exit_code != 0 {
                    return Err(format!("command exited with code {}", result.exit_code));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Share {
            command: ShareCommand::Revoke { grant_id },
        }) => {
            let result = (|| {
                use symvault_store::sharing::{SHARE_STORE_FILE, ShareStore};
                let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let mut shares = ShareStore::read(root.join(SHARE_STORE_FILE))
                    .map_err(|error| format!("load share store: {error}"))?;
                let now = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| error.to_string())?;
                shares.revoke_at(&root, &grant_id, &now).map_err(|error| {
                    let message = match error {
                        symvault_store::StoreError::Config(message) => message,
                        error => error.to_string(),
                    };
                    format!("revoke share grant: {message}")
                })?;
                if !cli.quiet {
                    println!("Share grant {grant_id} revoked successfully.");
                }
                Ok(())
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Share {
            command:
                ShareCommand::List {
                    status,
                    from,
                    to,
                    path,
                },
        }) => {
            let result = (|| {
                let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let format = if cli.json {
                    "json"
                } else {
                    cli.output.as_deref().unwrap_or("text")
                };
                share_commands::list(
                    &root,
                    format,
                    cli.quiet,
                    &status,
                    &from,
                    &to,
                    &path,
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Policy { command }) => {
            let result = (|| {
                let mut output = io::stderr().lock();
                match command {
                    PolicyCommand::Validate { file } => {
                        policy_commands::validate(&expand_policy_path(&file)?, &mut output)
                    }
                    PolicyCommand::Apply { file } => {
                        let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                        policy_commands::apply(&root, &expand_policy_path(&file)?, &mut output)
                    }
                    PolicyCommand::Remove { name } => {
                        let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                        policy_commands::remove(&root, &name, &mut output)
                    }
                    PolicyCommand::List => {
                        let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                        policy_commands::list(&root, &mut output)
                    }
                }
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command: AgentCommand::Whoami { output },
        }) => {
            let result = (|| {
                let root = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let agent = std::env::var("SYMVAULT_AGENT").unwrap_or_default();
                agent_whoami_commands::whoami(
                    &root,
                    &agent,
                    output.as_deref().unwrap_or("text"),
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command: AgentCommand::List,
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let home = cli_home_directory()?;
                let format = if cli.json {
                    "json"
                } else {
                    cli.output.as_deref().unwrap_or("text")
                };
                if matches!(format, "json" | "yaml") {
                    agent_list_commands::list(
                        &vault,
                        &home,
                        format,
                        cli.quiet,
                        &mut io::stdout().lock(),
                    )
                } else {
                    agent_list_commands::list(
                        &vault,
                        &home,
                        format,
                        cli.quiet,
                        &mut io::stderr().lock(),
                    )
                }
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Token {
                    command: AgentTokenCommand::List { name },
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_token_commands::list(&vault, &name, cli.quiet, &mut io::stdout().lock())
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Token {
                    command:
                        AgentTokenCommand::New {
                            name,
                            tools,
                            ttl,
                            label,
                        },
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_token_commands::new(
                    &vault,
                    &name,
                    tools,
                    &ttl,
                    &label,
                    cli.quiet,
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Token {
                    command: AgentTokenCommand::Revoke { name, token_id },
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_token_commands::revoke(
                    &vault,
                    &name,
                    &token_id,
                    cli.quiet,
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Token {
                    command:
                        AgentTokenCommand::Rotate {
                            name,
                            tools,
                            ttl,
                            label,
                        },
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_token_commands::rotate(
                    &vault,
                    &name,
                    tools,
                    &ttl,
                    &label,
                    cli.quiet,
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Audit {
                    name,
                    limit,
                    since,
                    format,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_audit_commands::view(
                    &vault,
                    &name,
                    limit,
                    &since,
                    &format,
                    &mut io::stdout().lock(),
                    &mut io::stderr().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command: AgentCommand::Doctor { name },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_doctor_commands::doctor(
                    &vault,
                    &name,
                    option_env!("SYMVAULT_VERSION").unwrap_or("dev"),
                    &mut io::stdout().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command: AgentCommand::Skill { command },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                match command {
                    Some(AgentSkillCommand::Export { output, args }) => {
                        if args.len() != 1 {
                            Err(format!("accepts 1 arg(s), received {}", args.len()))
                        } else {
                            agent_skill_commands::export(&vault, &args[0], output.as_deref())
                        }
                    }
                    Some(AgentSkillCommand::Refresh { args }) => {
                        if args.len() != 1 {
                            Err(format!("accepts 1 arg(s), received {}", args.len()))
                        } else {
                            agent_skill_commands::refresh(&vault, &args[0])
                        }
                    }
                    // The oracle prints the Cobra help here and exits 0. Cobra's
                    // help rendering is a documented non-goal of this port (same
                    // class as `symvault help`), so the exit status is matched and
                    // the help text stays empty.
                    None => Ok(()),
                }
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Install {
                    args,
                    auto_detect,
                    tier,
                    http,
                    dry_run,
                    skill_only,
                    config_only,
                    force,
                    quiet,
                    output,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let home = cli_home_directory()?;
                let mut output_stream = io::stdout().lock();
                agent_install_commands::run(
                    &vault,
                    &home,
                    &args,
                    &agent_install_commands::InstallFlags {
                        auto_detect,
                        tier,
                        http,
                        dry_run,
                        skill_only,
                        config_only,
                        force,
                        quiet,
                        output,
                    },
                    &mut output_stream,
                    &mut io::stderr().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Upgrade {
                    args,
                    tier,
                    dry_run,
                    yes,
                    reason,
                    rotate_token,
                    no_biometric,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let stdin = io::stdin();
                agent_upgrade_commands::run(
                    &vault,
                    &args,
                    &agent_upgrade_commands::UpgradeFlags {
                        tier,
                        dry_run,
                        yes,
                        reason,
                        rotate_token,
                        no_biometric,
                    },
                    &mut stdin.lock(),
                    &mut io::stderr().lock(),
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command:
                AgentCommand::Uninstall {
                    name,
                    keep_skill,
                    keep_config,
                    yes,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                agent_uninstall_commands::uninstall(
                    &vault,
                    &name,
                    &agent_uninstall_commands::Options {
                        keep_config,
                        keep_skill,
                        yes,
                    },
                )
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Agent {
            command: AgentCommand::Profile { command },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                let mut output_stream = io::stdout().lock();
                match command {
                    AgentProfileCommand::Edit { name } => agent_profile_commands::edit(
                        &vault,
                        &name,
                        None,
                        &mut output_stream,
                        &mut io::stderr().lock(),
                    ),
                    AgentProfileCommand::Show { name, output } => agent_profile_commands::show(
                        &vault,
                        &name,
                        output.as_deref(),
                        &mut output_stream,
                    ),
                    AgentProfileCommand::Export { name, output } => agent_profile_commands::export(
                        &vault,
                        &name,
                        output.as_deref().map(Path::new),
                        &mut output_stream,
                    ),
                }
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Audit {
            command: Some(AuditCommand::RotateKey),
            ..
        }) => run_audit_rotate_key(cli.vault.as_deref(), cli._profile.as_deref()),
        Some(Command::Audit {
            command:
                Some(AuditCommand::Export {
                    agent,
                    action,
                    since,
                    failed,
                    output,
                    format,
                    verify_hmac,
                    redact_paths,
                }),
            ..
        }) => run_audit_export(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &audit_export_commands::Options {
                agent: &agent,
                action: &action,
                since: &since,
                failed_only: failed,
                redact_paths,
                format: &format,
            },
            verify_hmac,
            output.as_deref(),
        ),
        Some(Command::Audit {
            command: None,
            tail,
            audit_json,
            agent,
            since,
            failed,
        }) => run_audit(
            &agent,
            tail,
            &since,
            failed,
            cli.json || audit_json,
            cli.output.as_deref(),
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
            action,
            agent,
            stdio,
            allow_locked,
        }) => match action {
            Some(McpAction::Install) => {
                run_mcp_service(cli.vault.as_deref(), cli.quiet, McpService::Install)
            }
            Some(McpAction::Status) => {
                run_mcp_service(cli.vault.as_deref(), cli.quiet, McpService::Status)
            }
            Some(McpAction::Uninstall) => {
                run_mcp_service(cli.vault.as_deref(), cli.quiet, McpService::Uninstall)
            }
            Some(McpAction::Serve {
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
            None => run_mcp(
                cli.vault.as_deref(),
                cli._profile.as_deref(),
                agent.as_deref(),
                stdio,
                allow_locked,
                cli.quiet,
            ),
            Some(McpAction::Token { args }) => {
                deprecated_stub_message(deprecated_token_message(args.first().map(String::as_str)))
            }
        },
        Some(Command::McpConfig { .. }) => deprecated_stub_message(DEPRECATED_MCP_CONFIG),
        Some(Command::McpTokenRotate { .. }) => {
            deprecated_stub_message(DEPRECATED_MCP_TOKEN_ROTATE)
        }
        Some(Command::Set {
            query,
            value,
            stdin_value,
            allow_empty,
            force,
            totp_secret,
            totp_issuer,
            totp_account,
        }) => run_set(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            &query,
            value,
            stdin_value,
            allow_empty,
            force,
            totp_secret,
            totp_issuer,
            totp_account,
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
            args,
            format,
            dry_run,
            prefix,
            skip_existing,
            overwrite,
            quarantine,
            mapping,
        }) => {
            // cobra Find: only the FIRST non-flag word can name a
            // subcommand, so `import file.csv review` is a parent call
            // with two args — validated here before any vault access.
            if args
                .first()
                .is_some_and(|arg| arg.to_str() == Some("review"))
            {
                run_import_review(
                    &args[1..],
                    cli.vault.as_deref(),
                    cli._profile.as_deref(),
                    overwrite,
                    cli.quiet,
                )
            } else if args.len() != 1 {
                let error = format!("accepts 1 arg(s), received {}", args.len());
                let _ = writeln!(io::stderr(), "Error: {error}");
                let _ = writeln!(io::stderr(), "Error: {error}");
                ExitCode::from(1)
            } else {
                run_import(
                    cli.vault.as_deref(),
                    cli._profile.as_deref(),
                    Path::new(&args[0]),
                    format.as_deref(),
                    dry_run,
                    &prefix,
                    skip_existing,
                    overwrite,
                    quarantine,
                    &mapping,
                    cli.quiet,
                )
            }
        }
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
            AuthCommand::Set { method } => run_auth_set(
                cli.vault.as_deref(),
                cli._profile.as_deref(),
                &method,
                cli.quiet,
            ),
            AuthCommand::RotatePassphrase { reencrypt, yes } => run_auth_rotate_passphrase(
                cli.vault.as_deref(),
                cli._profile.as_deref(),
                reencrypt,
                yes,
                cli.quiet,
            ),
        },
        Some(Command::Migrate {
            command: MigrateCommand::Paths,
        }) => {
            let result = (|| {
                let Ok(home) = cli_home_directory() else {
                    if !cli.quiet {
                        println!("No legacy path migration is needed.");
                    }
                    return Ok(());
                };
                let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
                let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
                let cache = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
                path_migration_commands::preview(
                    &home,
                    config.as_deref(),
                    data.as_deref(),
                    cache.as_deref(),
                    cli.quiet,
                    &mut io::stdout().lock(),
                )
                .map_err(|error| format!("preview path migration: {error}"))
            })();
            if let Err(error) = &result {
                let _ = writeln!(io::stderr(), "Error: {error}");
            }
            finish_vault_result(result)
        }
        Some(Command::Migrate {
            command: MigrateCommand::Pseudonymize { yes },
        }) => run_migrate_pseudonymize(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            yes,
            cli.quiet,
        ),
        Some(Command::Migrate {
            command: MigrateCommand::Kdf { yes },
        }) => run_migrate_kdf(cli.vault.as_deref(), cli._profile.as_deref(), yes),
        Some(Command::Migrate {
            command: MigrateCommand::V4 { yes, dry_run },
        }) => run_migrate_v4(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            yes,
            dry_run,
            cli.quiet,
        ),
        Some(Command::Migrate {
            command: MigrateCommand::Session { dry_run },
        }) => run_migrate_session(
            cli.vault.as_deref(),
            cli._profile.as_deref(),
            dry_run,
            cli.quiet,
        ),
        Some(Command::Update { args }) => {
            update_commands::run(&args, cli.output.as_deref().unwrap_or("text"), cli.json)
        }
        Some(Command::Template {
            command:
                TemplateCommand::Generate {
                    kind,
                    output,
                    dry_run,
                    name,
                    prefix,
                    refs,
                },
        }) => {
            let result = (|| {
                let vault = resolve_vault(cli.vault.as_deref(), cli._profile.as_deref())?;
                require_initialized(&vault)?;
                let identity = device::unlock_vault(&vault)?;
                let rendered = template_commands::generate(
                    &vault, &identity, &kind, &name, &prefix, &refs, dry_run,
                )?;
                if let Some(path) = output {
                    symvault_sync::safeio::write_atomic(Path::new(&path), rendered.as_bytes())
                        .map_err(|error| format!("write output file: {error}"))?;
                    if cli.json || cli.output.as_deref() == Some("json") {
                        println!(
                            "{}",
                            serde_json::json!({"output_path": path, "dry_run": dry_run})
                        );
                    } else {
                        println!("Template written to: {path}");
                    }
                } else {
                    println!("{rendered}");
                }
                Ok::<(), String>(())
            })();
            finish_vault_result(result)
        }
        Some(Command::Device { command }) => {
            let vault = match resolve_vault(cli.vault.as_deref(), cli._profile.as_deref()) {
                Ok(vault) => vault,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "Error: {error}");
                    return ExitCode::from(1);
                }
            };
            let vault = vault.as_path();
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
                DeviceCommand::ApprovalList { .. } => device_approval::list(vault, cli.quiet),
                DeviceCommand::ApprovalRevoke { yes, args } => {
                    if args.len() != 1 {
                        Err(format!("accepts 1 arg(s), received {}", args.len()))
                    } else {
                        device_approval::revoke(vault, &args[0], yes, cli.quiet)
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
        Some(Command::Config {
            command: ConfigCommand::Validate { path, fix },
        }) => {
            let path = match config::resolve_path(path) {
                Ok(path) => path,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "Error: {error}");
                    return ExitCode::from(1);
                }
            };
            let output = if cli.json {
                "json"
            } else {
                cli.output.as_deref().unwrap_or("text")
            };
            match config::validate(&path, fix, output, cli.quiet) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    print_error_like_go(&error);
                    let _ = writeln!(
                        io::stderr(),
                        "Run 'symvault doctor' to diagnose and fix configuration issues."
                    );
                    ExitCode::from(6)
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
                ConfigCommand::Validate { .. } => unreachable!("handled by the arm above"),
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

fn run_add(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    mut options: add_commands::AddOptions,
    stdin_value: bool,
    stdin_totp_secret: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        if stdin_value || stdin_totp_secret {
            let stdin = io::stdin();
            let mut input = io::BufReader::new(stdin.lock());
            let (value, totp_secret) =
                add_commands::read_stdin_values(&mut input, stdin_value, stdin_totp_secret)?;
            if value.is_some() {
                options.value = value;
            }
            if let Some(totp_secret) = totp_secret {
                options.totp_secret = totp_secret;
            }
        }
        let path = options.path.clone();
        add_commands::add(&vault, &identity, &options)?;
        if !quiet {
            println!("Entry created: {path}");
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_verify(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    rebuild: bool,
    rebuild_only: bool,
    _quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        verify_commands::verify(
            &vault,
            &identity,
            rebuild,
            rebuild_only,
            &mut io::stderr().lock(),
        )
    })();
    finish_vault_result(result)
}

#[allow(clippy::too_many_arguments)]
fn run_doctor(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    no_network: bool,
    strict: bool,
    only: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    fix: bool,
    fix_dry_run: bool,
    quick: bool,
    output_format: Option<&str>,
    json: bool,
    _quiet: bool,
) -> ExitCode {
    let vault_dir =
        resolve_vault(explicit_vault, profile).unwrap_or_else(|_| PathResolver::new().data_dir);
    let opts = doctor_commands::DoctorOptions {
        no_network,
        quick,
        only: only.unwrap_or_default(),
        exclude: exclude.unwrap_or_default(),
    };

    let mut results = doctor_commands::run_checks(&vault_dir, &opts);

    if let Some(format) = output_format
        && format != "text"
    {
        let _ = writeln!(
            io::stderr(),
            "Error: output format {format:?} is not supported by 'symvault doctor' (supported commands: admin config get, delete, device list, find, generate, get, list, mcp agent install, mcp agent list, recipients, remote, share, template generate)"
        );
        return ExitCode::from(9);
    }

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    if let Err(err) = doctor_commands::apply_fixes(&mut results, fix, fix_dry_run, &mut stderr) {
        let _ = writeln!(io::stderr(), "Error: {err}");
        return ExitCode::from(1);
    }

    if json {
        if let Err(err) = doctor_commands::render_json(&vault_dir, &results, &mut stdout) {
            let _ = writeln!(io::stderr(), "Error: {err}");
            return ExitCode::from(1);
        }
    } else if let Err(err) = doctor_commands::render_text(&vault_dir, &results, &mut stderr) {
        let _ = writeln!(io::stderr(), "Error: {err}");
        return ExitCode::from(1);
    }

    if strict {
        let sc = doctor_commands::score(&results);
        if sc.fail > 0 {
            let _ = writeln!(io::stderr(), "Error: {} check(s) failed", sc.fail);
            return ExitCode::from(8);
        }
        if sc.warn > 0 {
            let _ = writeln!(io::stderr(), "Error: {} warning(s)", sc.warn);
            return ExitCode::from(7);
        }
    }

    ExitCode::SUCCESS
}

fn cli_home_directory() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| {
            cfg!(windows)
                .then(|| std::env::var_os("USERPROFILE"))
                .flatten()
                .filter(|value| !value.is_empty())
        })
        .map(PathBuf::from)
        .ok_or_else(|| "cannot determine home directory".to_owned())
}

fn run_remote_status(
    explicit: Option<&Path>,
    profile: Option<&str>,
    format: &str,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit, profile)?;
        require_initialized(&vault)?;
        let home = cli_home_directory()?;
        remote_commands::status(
            &vault,
            &home,
            format,
            quiet,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
    })();
    finish_vault_result(result)
}

fn run_profile(command: &ProfileCommand, vault: Option<&Path>, quiet: bool) -> ExitCode {
    let result = (|| {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                cfg!(windows)
                    .then(|| std::env::var_os("USERPROFILE"))
                    .flatten()
                    .filter(|value| !value.is_empty())
            })
            .map(PathBuf::from)
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        let mut output = io::stdout().lock();
        match command {
            ProfileCommand::List => profile_commands::list(&home, quiet, &mut output),
            ProfileCommand::Add { name } => profile_commands::add(
                &home,
                name,
                &vault.map(|path| path.to_string_lossy()).unwrap_or_default(),
                quiet,
                &mut output,
            ),
            ProfileCommand::Use { name } => {
                profile_commands::use_profile(&home, name, quiet, &mut output)
            }
        }
    })();
    // Go reports profile command errors through both Cobra and main.
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
    finish_vault_result(result)
}

fn run_audit_export(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    options: &audit_export_commands::Options<'_>,
    verify_hmac: bool,
    output: Option<&str>,
) -> ExitCode {
    let result = (|| {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                cfg!(windows)
                    .then(|| std::env::var_os("USERPROFILE"))
                    .flatten()
            })
            .map(PathBuf::from)
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        let mut rendered = Vec::new();
        let result = if verify_hmac {
            let vault = resolve_vault(explicit_vault, profile)?;
            let runtime = runtime_session_manager();
            let keyring = runtime
                .keyring
                .as_deref()
                .ok_or_else(|| "audit keyring unavailable".to_owned())?;
            let key = symvault_store::audit::load_or_create_key_with_keyring(&vault, keyring)
                .map_err(|error| format!("load HMAC key: {error}"))?;
            let kid = key.fingerprint();
            let keys = BTreeMap::from([(kid.clone(), key)]);
            audit_export_commands::export_with_keys(
                &home,
                options,
                true,
                &keys,
                &kid,
                &mut rendered,
            )?
        } else {
            audit_export_commands::export(&home, options, &mut rendered)?
        };
        if let Some(output) = output.filter(|value| !value.is_empty()) {
            let path = Path::new(output);
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                symvault_sync::safeio::create_dir_all(parent)
                    .map_err(|error| format!("create output directory: {error}"))?;
            }
            symvault_sync::safeio::write_atomic(path, &rendered)
                .map_err(|error| format!("create output file: {error}"))?;
        } else {
            io::stdout()
                .lock()
                .write_all(&rendered)
                .map_err(|error| error.to_string())?;
        }
        let mut summary = io::stderr().lock();
        write!(summary, "Exported {} audit entries", result.total)
            .map_err(|error| error.to_string())?;
        if result.verified > 0 || result.tampered > 0 {
            write!(
                summary,
                " (verified: {}, legacy: {}, tampered: {})",
                result.verified, result.legacy, result.tampered
            )
            .map_err(|error| error.to_string())?;
        }
        writeln!(summary).map_err(|error| error.to_string())
    })();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
    finish_vault_result(result)
}

fn run_audit(
    agent: &str,
    tail: i64,
    since: &str,
    failed: bool,
    audit_json: bool,
    output_format: Option<&str>,
) -> ExitCode {
    let result = (|| {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                cfg!(windows)
                    .then(|| std::env::var_os("USERPROFILE"))
                    .flatten()
                    .filter(|value| !value.is_empty())
            })
            .map(PathBuf::from)
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        let json = audit_json || output_format == Some("json");
        if json {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            audit_commands::view(&home, agent, tail, since, failed, true, &mut output)?;
        } else {
            let stderr = io::stderr();
            let mut output = stderr.lock();
            audit_commands::view(&home, agent, tail, since, failed, false, &mut output)?;
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_audit_rotate_key(explicit_vault: Option<&Path>, profile: Option<&str>) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        let runtime = runtime_session_manager();
        let keyring = runtime
            .keyring
            .as_deref()
            .ok_or_else(|| "audit keyring unavailable".to_owned())?;
        let (new_key, archive_path) =
            symvault_store::audit::rotate_key_with_keyring(&vault, keyring)
                .map_err(|error| format!("rotate HMAC key: {error}"))?;
        let mut stderr = io::stderr().lock();
        writeln!(stderr, "New key: {} (first 4 bytes)", new_key.preview_hex())
            .map_err(|error| error.to_string())?;
        match &archive_path {
            None => writeln!(
                stderr,
                "HMAC key bootstrapped — no previous key existed, so no archive file was written."
            ),
            Some(path) => writeln!(stderr, "HMAC key rotated successfully.")
                .and_then(|()| writeln!(stderr, "Old key archived to: {}", path.display())),
        }
        .map_err(|error| error.to_string())?;
        writeln!(
            stderr,
            "A new audit log will be started on the next audit write."
        )
        .map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
    finish_vault_result(result)
}

fn run_auth_set(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    method: &str,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        // Go validates the method argument before resolving the vault; match
        // that order so an invalid argument never depends on vault state.
        let method = AuthMethod::parse(method).map_err(|error| match error {
            symvault_core::config::ConfigError::Invalid(msg) => msg,
            other => other.to_string(),
        })?;
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let config_path = vault.join("config.yaml");
        let mut config =
            Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
        match method {
            AuthMethod::Passphrase => {
                config
                    .set_auth_method(method.as_str())
                    .map_err(|error| error.to_string())?;
                config
                    .save_to(&config_path)
                    .map_err(|error| format!("save config: {error}"))?;
                #[cfg(target_os = "macos")]
                {
                    let runtime = runtime_session_manager();
                    if let Some(keyring) = runtime.keyring.as_deref()
                        && let Err(error) =
                            session_commands::clear_touch_id_passphrase(&vault, keyring)
                    {
                        eprintln!("Warning: could not remove Touch ID unlock item: {error}");
                    }
                }
                if !quiet {
                    println!("Auth method set to passphrase");
                }
            }
            AuthMethod::Touchid => {
                if !touch_id_available() {
                    return Err(
                        "touch ID is not available in this Symaira Vault build or on this Mac"
                            .to_owned(),
                    );
                }
                #[cfg(target_os = "macos")]
                {
                    let runtime = runtime_session_manager();
                    let config_bytes =
                        fs::read(&config_path).map_err(|error| format!("read config: {error}"))?;
                    let identity_bytes = fs::read(vault.join("identity.age"))
                        .map_err(|error| format!("read identity: {error}"))?;
                    let passphrase = unlock_passphrase(&config_bytes, &config, &vault, &runtime)?;
                    decrypt_identity(&identity_bytes, &SecretBytes::new(passphrase.as_bytes()))
                        .map_err(|error| format!("open vault: {error}"))?;
                    let keyring = runtime.keyring.as_deref().ok_or_else(|| {
                        "save Touch ID unlock item: keyring unavailable".to_owned()
                    })?;
                    session_commands::save_touch_id_passphrase(
                        &vault,
                        keyring,
                        passphrase.as_bytes(),
                    )
                    .map_err(|error| format!("save Touch ID unlock item: {error}"))?;
                    config
                        .set_auth_method(method.as_str())
                        .map_err(|error| error.to_string())?;
                    config
                        .save_to(&config_path)
                        .map_err(|error| format!("save config: {error}"))?;
                    if !quiet {
                        println!("Auth method set to touchid");
                    }
                }
                #[cfg(not(target_os = "macos"))]
                unreachable!("touch_id_available() is always false on this platform");
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
    finish_vault_result(result)
}

fn run_auth_rotate_passphrase(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    reencrypt: bool,
    yes: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let config_path = vault.join("config.yaml");
        let mut config =
            Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
        let identity_path = vault.join("identity.age");
        let original = fs::read(&identity_path)
            .map_err(|error| format!("cannot read current passphrase: {error}"))?;

        let old_passphrase = session_input::read_passphrase("Current passphrase: ")
            .map_err(|error| format!("cannot read current passphrase: {error}"))?;
        let identity =
            match decrypt_identity(&original, &SecretBytes::new(old_passphrase.as_bytes())) {
                Ok(identity) => identity,
                Err(_) => {
                    let load_error = if symvault_crypto::detect_envelope(&original)
                        == symvault_crypto::EnvelopeFormat::Argon2id
                    {
                        let recipients_file = vault.join("recipients.txt");
                        if !recipients_file.is_file() {
                            "load identity: zero-key recovery requires a trusted recipients.txt"
                        } else {
                            "load identity: zero-key recovery failed"
                        }
                    } else {
                        "load identity: decryption failed"
                    };
                    return Err(format!("current passphrase is incorrect: {load_error}"));
                }
            };

        let new_passphrase =
            session_input::read_passphrase("New passphrase (minimum 12 characters): ")
                .map_err(|error| format!("cannot read new passphrase: {error}"))?;
        if new_passphrase.len() < 12 {
            return Err("passphrase must be at least 12 characters".to_owned());
        }
        let confirmation = session_input::read_passphrase("Confirm new passphrase: ")
            .map_err(|error| format!("cannot read confirmation: {error}"))?;
        if *new_passphrase != *confirmation {
            return Err("passphrases do not match".to_owned());
        }
        if *old_passphrase == *new_passphrase {
            return Err("new passphrase must be different from the current passphrase".to_owned());
        }

        if !yes {
            eprint!("Change vault passphrase? (y/N): ");
            io::stderr().flush().map_err(|error| error.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|error| format!("read confirmation: {error}"))?
                == 0
                && answer.is_empty()
            {
                return Err("read confirmation: EOF".to_owned());
            }
            if !answer.trim().eq_ignore_ascii_case("y") {
                eprintln!("Canceled");
                return Ok::<(), String>(());
            }
        }

        // Go's rotate-passphrase always re-encrypts the identity with scrypt
        // (never argon2id), even when the identity was previously migrated.
        // That is the pinned oracle contract, not a Rust simplification.
        let replacement =
            encrypt_identity_scrypt(&identity, &SecretBytes::new(new_passphrase.as_bytes()), 0)
                .map_err(|error| format!("save identity with new passphrase: {error}"))?;
        symvault_sync::safeio::write_atomic(&identity_path, &replacement)
            .map_err(|error| format!("save identity with new passphrase: {error}"))?;

        if reencrypt {
            let recipients = device::get_all_recipients_for_encryption(&vault, &identity)
                .map_err(|error| format!("get recipients for re-encryption: {error}"))?;
            device::reencrypt_all_entries(&vault, &identity, &recipients)
                .map_err(|error| format!("re-encrypt entries: {error}"))?;
        }

        let runtime = runtime_session_manager();
        let vault_string = vault
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
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
        // Session-cache refresh is best-effort here, matching Go's warn-only
        // handling in rotate-passphrase (unlike `unlock`, where it is fatal).
        if let Err(error) = runtime.manager.save_passphrase(
            vault_string,
            new_passphrase.as_bytes(),
            ttl,
            max_lifetime,
        ) {
            eprintln!("Warning: could not update session cache: {error}");
        }
        let identity_string = symvault_crypto::identity_string(&identity);
        let _ = runtime.manager.save_identity(
            vault_string,
            identity_string.as_bytes(),
            ttl,
            max_lifetime,
        );

        #[cfg(target_os = "macos")]
        if config.effective_auth_method() == AuthMethod::Touchid
            && let Some(keyring) = runtime.keyring.as_deref()
            && let Err(error) = session_commands::save_touch_id_passphrase(
                &vault,
                keyring,
                new_passphrase.as_bytes(),
            )
        {
            eprintln!("Warning: could not update Touch ID unlock: {error}");
        }

        let vault_config = config.vault.get_or_insert_with(VaultConfig::default);
        vault_config.last_rotated = Some(GoTime::now().to_rfc3339_nano());
        config
            .save_to(&config_path)
            .map_err(|error| format!("save config: {error}"))?;

        // Git auto-commit is best-effort in Go: absence of a repo is silent,
        // any other failure is a warning, never a rotation failure.
        match GitRepository::open(&vault) {
            Ok(repo) => {
                if let Err(error) = repo.commit(CommitOptions {
                    message: "Rotate vault passphrase".to_owned(),
                    ..CommitOptions::default()
                }) {
                    eprintln!("Warning: git auto-commit failed: {error}");
                }
            }
            Err(GitError::InvalidPath(_)) => {}
            Err(error) => eprintln!("Warning: git auto-commit failed: {error}"),
        }

        if let Some(keyring) = runtime.keyring.as_deref()
            && let Ok(mut logger) = symvault_store::audit::open_with_keyring(
                "symvault",
                &vault,
                keyring,
                symvault_store::audit::RotationConfig::default(),
            )
        {
            let _ = logger.append(symvault_store::audit::LogEntry {
                timestamp: export_commands::go_timestamp_seconds(),
                agent: "symvault".to_owned(),
                action: "rotate-passphrase".to_owned(),
                ok: true,
                ..symvault_store::audit::LogEntry::default()
            });
        }

        if !quiet {
            println!("Passphrase rotated successfully.");
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
    finish_vault_result(result)
}

fn run_file(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    command: FileCommand,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        match command {
            FileCommand::Add {
                path,
                field,
                source,
                secret_type,
                max_size,
                shred,
            } => {
                let result = file_commands::add(
                    &vault,
                    &identity,
                    &file_commands::AddOptions {
                        path,
                        field,
                        source,
                        secret_type,
                        max_size,
                        shred,
                    },
                )?;
                if !quiet {
                    println!(
                        "Attached {} to {}#{} ({} bytes, sha256:{})",
                        result.filename, result.path, result.field, result.size, result.sha256
                    );
                    if result.shredded {
                        println!("Shredded source file: {}", result.source.display());
                    }
                }
            }
            FileCommand::Get { query, field, out } => {
                let output = out.ok_or_else(|| "--out is required".to_owned())?;
                let result = file_commands::get(
                    &vault,
                    &identity,
                    &file_commands::GetOptions {
                        query,
                        field: field.unwrap_or_default(),
                        output,
                    },
                )?;
                if !quiet {
                    println!(
                        "Exported {}#{} to {} ({} bytes)",
                        result.path,
                        result.field,
                        result.output.display(),
                        result.size
                    );
                }
            }
            FileCommand::Use {
                query,
                field,
                as_name,
                timeout,
                command,
            } => {
                let timeout = timeout
                    .as_deref()
                    .map(session_commands::parse_ttl_override)
                    .transpose()?
                    .flatten();
                let result = file_commands::use_attachment(
                    &vault,
                    &identity,
                    &file_commands::UseOptions {
                        query,
                        field: field.unwrap_or_default(),
                        as_name: as_name.unwrap_or_default(),
                        timeout,
                        command,
                    },
                )?;
                if !result.timed_out {
                    print!("{}", result.stdout);
                    eprint!("{}", result.stderr);
                }
                if result.exit_code != 0 {
                    return Err(format!("command exited with code {}", result.exit_code));
                }
            }
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
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

#[allow(clippy::too_many_arguments)]
fn run_get(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    query: &str,
    output: &str,
    json: bool,
    print: bool,
    length: bool,
    digest: bool,
    metadata: bool,
    quiet: bool,
) -> ExitCode {
    let flags_count =
        usize::from(print) + usize::from(length) + usize::from(digest) + usize::from(metadata);
    if flags_count > 1 {
        print_error_like_go("--print, --length, --digest, and --metadata are mutually exclusive");
        return ExitCode::from(9);
    }
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let identity = device::unlock_vault(&vault)?;
        let result = vault_commands::get(&vault, &identity, query);
        if length || digest || metadata {
            let value = match result {
                Ok(vault_commands::GetResult::Field { value, .. }) => value,
                _ => {
                    // Go reports this from the command and again from
                    // ExecuteRoot; the caller below prints it once, so emit the
                    // command-level line here to keep the pair identical to Go.
                    let _ = writeln!(
                        io::stderr(),
                        "Error: field is required for --length, --digest, or --metadata"
                    );
                    return Err(
                        "field is required for --length, --digest, or --metadata".to_owned()
                    );
                }
            };
            let str_value = match &value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            if !quiet {
                if length {
                    println!("{}", str_value.len());
                } else if digest {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(str_value.as_bytes());
                    let hash = hasher.finalize();
                    let mut hex_hash = String::with_capacity(64);
                    for byte in &hash {
                        let _ =
                            std::fmt::Write::write_fmt(&mut hex_hash, format_args!("{byte:02x}"));
                    }
                    let short_hex = &hex_hash[..12];
                    println!("sha256:{short_hex}");
                } else if metadata {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(str_value.as_bytes());
                    let hash = hasher.finalize();
                    let mut hex_hash = String::with_capacity(64);
                    for byte in &hash {
                        let _ =
                            std::fmt::Write::write_fmt(&mut hex_hash, format_args!("{byte:02x}"));
                    }
                    let short_hex = &hex_hash[..12];
                    let meta = serde_json::json!({
                        "length": str_value.len(),
                        "sha256_12": short_hex,
                    });
                    println!("{meta}");
                }
            }
            return Ok(());
        }
        let result = result?;
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
            if error == "field is required for --length, --digest, or --metadata" {
                ExitCode::from(9)
            } else {
                ExitCode::from(1)
            }
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
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        match action {
            "log" => {
                let commits = history_commands::log(&vault, path, 0)
                    .map_err(|error| format!("cannot get log: {error}"))?;
                history_commands::write_log(&mut io::stdout().lock(), &commits, quiet)
            }
            "push" | "pull" => {
                let message = history_commands::transfer(&vault, action)?;
                if !quiet {
                    writeln!(io::stdout().lock(), "{message}")
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            }
            _ => Err(format!("unknown action: {action} (use push, pull, or log)")),
        }
    })();
    finish_vault_result(result)
}

fn run_recipients(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    command: RecipientsCommand,
    output: &str,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        match command {
            RecipientsCommand::List => {
                let recipients = recipients_commands::list(&vault)?;
                recipients_commands::write_list(
                    &mut io::stdout().lock(),
                    &recipients,
                    if json { "json" } else { output },
                    quiet,
                )
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
        let file = vault.join(
            file.strip_prefix(store.root())
                .map_err(|error| error.to_string())?,
        );
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

fn run_backup(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    archive: &Path,
    exclude_git: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        let archive = backup_commands::backup(&vault, archive, exclude_git)?;
        if !quiet {
            println!("Backup created: {}", archive.display());
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_restore(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    archive: &Path,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        backup_commands::restore(&vault, archive)?;
        require_initialized(&vault)?;
        if !quiet {
            println!("Vault restored to: {}", vault.display());
        }
        Ok::<(), String>(())
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

fn run_migrate_session(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    dry_run: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        let runtime = runtime_session_manager();
        let vault_string = vault
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;

        let legacy = runtime
            .manager
            .has_legacy_plaintext_session(vault_string)
            .map_err(|error| format!("inspect session: {error}"))?;
        if !legacy {
            println_quiet_aware(
                quiet,
                "No legacy plaintext session found. Nothing to migrate.",
            );
            return Ok(());
        }

        if dry_run {
            println_quiet_aware(
                quiet,
                "Dry-run: legacy plaintext session detected. Re-run without --dry-run to upgrade.",
            );
            return Ok(());
        }

        let upgraded = runtime
            .manager
            .migrate_session(vault_string)
            .map_err(|error| format!("migrate session: {error}"))?;
        if !upgraded {
            println_quiet_aware(
                quiet,
                "No legacy plaintext session found. Nothing to migrate.",
            );
            return Ok(());
        }

        println_quiet_aware(
            quiet,
            "Session upgraded. The cached passphrase is now stored encrypted in the OS keyring.",
        );
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_migrate_v4(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    yes: bool,
    dry_run: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        let config_path = vault.join("config.yaml");
        let mut config =
            Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;

        // Tier assignment mirrors the oracle: profiles that already carry a
        // non-empty tier are left alone, which makes the migration idempotent.
        let mut pending: Vec<(String, &'static str)> = Vec::new();
        for (name, agent) in &config.agents {
            if agent.tier.as_deref().is_some_and(|tier| !tier.is_empty()) {
                continue;
            }
            let tier = if agent.can_run_commands {
                "admin"
            } else if agent.can_write {
                "standard"
            } else {
                "safe"
            };
            pending.push((name.clone(), tier));
        }

        if pending.is_empty() {
            println_quiet_aware(quiet, "All profiles already have tier fields.");
            return Ok(());
        }

        println_quiet_aware(
            quiet,
            &format!(
                "Found {} agent profile(s) without tier fields:",
                pending.len()
            ),
        );
        for (name, tier) in &pending {
            println_quiet_aware(quiet, &format!("  {name} \u{2192} {tier}"));
        }

        if dry_run {
            println_quiet_aware(quiet, "Dry-run: no changes written.");
            return Ok(());
        }

        if !yes {
            eprint!("Migrate agent profiles to v4.0 format (y/N): ");
            io::stderr().flush().map_err(|error| error.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|error| format!("read confirmation: {error}"))?
                == 0
            {
                return Err("read confirmation: EOF".to_owned());
            }
            if !answer.trim().eq_ignore_ascii_case("y") {
                eprintln!("Canceled");
                return Ok(());
            }
        }

        // Back up the original bytes before touching the file. The oracle keeps
        // the pre-migration config verbatim under a timestamped name.
        let original = symvault_sync::safeio::read(&config_path)
            .map_err(|error| format!("read config for backup: {error}"))?
            .ok_or_else(|| "configuration is missing".to_owned())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("clock: {error}"))?
            .as_secs();
        let backup_path = vault.join(format!("config.yaml.v3-backup-{stamp}"));
        symvault_sync::safeio::write_atomic(&backup_path, &original)
            .map_err(|error| format!("write backup: {error}"))?;
        println_quiet_aware(quiet, &format!("Backup created: {}", backup_path.display()));

        for (name, tier) in &pending {
            if let Some(agent) = config.agents.get_mut(name) {
                agent.tier = Some((*tier).to_owned());
            }
        }

        config
            .save_to(&config_path)
            .map_err(|error| format!("save migrated config: {error}"))?;
        println_quiet_aware(
            quiet,
            &format!(
                "Migrated {} agent profile(s) to v4.0 format.",
                pending.len()
            ),
        );
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_migrate_pseudonymize(
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    yes: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, profile)?;
        require_initialized(&vault)?;
        if !yes {
            eprint!("Migrate all entries to pseudonymized paths. Make a backup first (y/N): ");
            io::stderr().flush().map_err(|error| error.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|error| format!("read confirmation: {error}"))?
                == 0
            {
                return Err("read confirmation: EOF".to_owned());
            }
            if !answer.trim().eq_ignore_ascii_case("y") {
                eprintln!("Canceled");
                return Ok(());
            }
        }

        // The flag must be on before the first rewrite. Every write resolves
        // its target through the configured storage mode, so enabling it
        // afterwards rewrites each entry onto its own plaintext path and then
        // deletes it — the Go command lost the whole vault that way (#1088).
        let config_path = vault.join("config.yaml");
        let mut config =
            Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
        let section = config.vault.get_or_insert_with(Default::default);
        if !section.pseudonymize_paths {
            section.pseudonymize_paths = true;
            config
                .save_to(&config_path)
                .map_err(|error| format!("save config: {error}"))?;
        }

        let identity = device::unlock_vault(&vault)?;
        let store = symvault_store::Store::open(&vault, &identity)
            .map_err(|error| format!("open vault: {error}"))?;
        let summary = store
            .migrate_pseudonymize(&identity)
            .map_err(|error| format!("migrate pseudonymize: {error}"))?;

        if summary.scanned == 0 {
            println_quiet_aware(
                quiet,
                "No entries to migrate. Enabling pseudonymize_paths in config.",
            );
        } else {
            println_quiet_aware(
                quiet,
                &format!(
                    "Migrating {} entries to pseudonymized paths...",
                    summary.scanned
                ),
            );
            println_quiet_aware(
                quiet,
                "Migration complete. All entries now use pseudonymized paths.",
            );
        }
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

fn run_migrate_kdf(explicit_vault: Option<&Path>, profile: Option<&str>, yes: bool) -> ExitCode {
    let result = (|| {
        use migrate_kdf_commands::MigrationResult;
        let vault = resolve_vault(explicit_vault, profile)?;
        match migrate_kdf_commands::inspect_identity(&vault)? {
            MigrationResult::AlreadyArgon2id => {
                println!(
                    "✓ Your vault identity is already protected with argon2id.\nNo migration is needed."
                );
                return Ok(());
            }
            MigrationResult::Unsupported => {
                println!(
                    "Could not determine the vault identity's key derivation function.\nRun 'symvault doctor' for a full diagnosis."
                );
                return Ok(());
            }
            _ => {}
        }
        println!("Your vault identity is currently protected with scrypt.");
        let passphrase = session_input::read_passphrase("Passphrase: ")?;
        let secret = SecretBytes::new(passphrase.as_bytes());
        let raw = symvault_sync::safeio::read(&vault.join("identity.age"))
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "identity.age is missing".to_owned())?;
        let identity =
            decrypt_identity(&raw, &secret).map_err(|error| format!("unlock vault: {error}"))?;
        let config = Config::load(vault.join("config.yaml"))
            .map_err(|error| format!("unlock vault: {error}"))?;
        let automatic = config
            .vault
            .as_ref()
            .is_some_and(|config| config.auto_migrate_kdf);
        if !automatic && !yes {
            eprint!(
                "Migrate the vault identity to argon2id now (identity.age is backed up to identity.age.bak first) (y/N): "
            );
            io::stderr().flush().map_err(|error| error.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|error| format!("read confirmation: {error}"))?
                == 0
            {
                return Err("read confirmation: EOF".to_owned());
            }
            if !answer.trim().eq_ignore_ascii_case("y") {
                eprintln!("Canceled");
                return Ok(());
            }
        }
        let state = migrate_kdf_commands::migrate_kdf(&vault, &identity, &secret)
            .map_err(|error| format!("migrate kdf: {error}"))?;
        if state != MigrationResult::Migrated && state != MigrationResult::AlreadyArgon2id {
            return Err(
                "migration did not complete; identity.age format changed during migration"
                    .to_owned(),
            );
        }
        if automatic {
            println!("✓ Migrated automatically on unlock (vault.auto_migrate_kdf is enabled).");
        } else {
            println!("✓ Migrated vault identity to argon2id.");
        }
        println!("The previous identity.age was backed up to identity.age.bak.");
        Ok::<(), String>(())
    })();
    finish_vault_result(result)
}

/// Which `mcp` service action to run.
#[derive(Clone, Copy)]
enum McpService {
    Install,
    Status,
    Uninstall,
}

/// Prints a line the way the Go CLI's quiet-aware printer does for the first
/// line of a service report.
fn println_quiet_aware(quiet: bool, line: &str) {
    if !quiet {
        println!("{line}");
    }
}

/// Loads the agent-facing global config for the service commands. A missing or
/// unreadable config is reported exactly like the oracle and the defaults apply.
fn service_config(warn: bool) -> Option<Config> {
    // The oracle reads `<home>/.symvault/config.yaml` (config.DefaultVaultSubdir),
    // not the XDG path, and only `install` reports a load failure.
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    let config_path = home.join(".symvault").join("config.yaml");
    if let Err(error) = fs::read(&config_path) {
        if warn {
            eprintln!(
                "Could not load config, using defaults: open {}: {}",
                config_path.display(),
                go_io_reason(&error)
            );
        }
        return None;
    }
    Config::load(&config_path).ok()
}

/// Renders an io error the way Go's `*os.PathError` does ("no such file or
/// directory", "permission denied", ...).
fn go_io_reason(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        std::io::ErrorKind::AlreadyExists => "file exists".to_owned(),
        _ => error.to_string(),
    }
}

fn run_mcp_service(explicit_vault: Option<&Path>, quiet: bool, action: McpService) -> ExitCode {
    let result = (|| {
        let vault = resolve_vault(explicit_vault, None)?;
        let config = service_config(matches!(action, McpService::Install));
        let (port, bind) = match config.as_ref().and_then(|cfg| cfg.mcp.as_ref()) {
            Some(mcp) => (Some(mcp.port), Some(mcp.bind.as_str())),
            None => (None, None),
        };
        let installer = daemon_commands::Installer::new(&vault, port, bind)
            .map_err(|error| error.formatted())?;
        match action {
            McpService::Install => {
                installer.install().map_err(|error| error.formatted())?;
                println_quiet_aware(quiet, "Service installed successfully.");
                if let Ok(path) = installer.service_file_path() {
                    println!("  Service file: {}", path.display());
                }
                println!("  Port:         {}", installer.port());
                println!("  Bind:         {}", installer.bind());
                println!("  Vault:        {}", installer.vault_dir().display());
            }
            McpService::Uninstall => {
                installer.uninstall().map_err(|error| error.formatted())?;
                println_quiet_aware(quiet, "Service uninstalled successfully.");
            }
            McpService::Status => {
                let status = installer.status().map_err(|error| error.formatted())?;
                println_quiet_aware(quiet, &format!("Status: {status}"));
                if let Ok(path) = installer.service_file_path() {
                    println!("  Service file: {}", path.display());
                }
                println!("  Port:         {}", installer.port());
                println!("  Bind:         {}", installer.bind());
                println!("  Vault:        {}", installer.vault_dir().display());
            }
        }
        Ok(())
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
        mcp_commands::run(&vault, agent, identity, keyring, || {
            let cache = runtime.cache_status();
            (
                touch_id_available(),
                cache.backend,
                cache.persistent,
                cache.message,
            )
        })
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
    totp_secret: Option<String>,
    totp_issuer: Option<String>,
    totp_account: Option<String>,
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
        let path = write_commands::set_entry(
            &vault,
            &identity,
            query,
            value,
            allow_empty,
            force,
            totp_secret.as_deref(),
            totp_issuer.as_deref(),
            totp_account.as_deref(),
        )?;
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

/// `symvault import review <list|promote>` — the word dispatch mirrors
/// cobra's Find on the first non-flag argument. Arg validation runs before
/// any vault access, matching cobra's Args validators (the fixture's arg
/// errors carry no passphrase warning).
fn run_import_review(
    rest: &[OsString],
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
    overwrite: bool,
    quiet: bool,
) -> ExitCode {
    let result = (|| {
        match rest.first().map(|word| word.to_string_lossy()) {
            // Bare `review`: the oracle prints the cobra group help and
            // exits 0. Help rendering is a documented non-goal (same class
            // as `symvault help`); exit status and silence are matched.
            None => Ok(()),
            Some(word) if word == "list" => {
                if rest.len() > 1 {
                    return Err(format!(
                        "unknown command {:?} for \"symvault import review list\"",
                        rest[1].to_string_lossy()
                    ));
                }
                let vault = resolve_vault(explicit_vault, profile)?;
                require_initialized(&vault)?;
                let identity = device::unlock_vault(&vault)?;
                import_review_commands::list(&vault, &identity, quiet)
            }
            Some(word) if word == "promote" => {
                let promote_args = &rest[1..];
                if promote_args.len() != 1 {
                    return Err(format!("accepts 1 arg(s), received {}", promote_args.len()));
                }
                // ponytail: import ids are generated ASCII; a non-UTF-8 id
                // is rejected instead of lossy-mangled (Go keeps raw
                // os.Args bytes). Upgrade path: carry OsStr into the prefix.
                let import_id = promote_args[0]
                    .to_str()
                    .ok_or_else(|| "import id is not valid UTF-8".to_owned())?;
                let vault = resolve_vault(explicit_vault, profile)?;
                require_initialized(&vault)?;
                let identity = device::unlock_vault(&vault)?;
                import_review_commands::promote(&vault, &identity, import_id, overwrite, quiet)
            }
            Some(word) => Err(format!(
                "unknown command {word:?} for \"symvault import review\""
            )),
        }
    })();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
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
    quarantine: bool,
    mapping: &str,
    quiet: bool,
) -> ExitCode {
    if skip_existing && overwrite {
        return finish_vault_result(Err(
            "--skip-existing and --overwrite cannot be used together".into(),
        ));
    }
    let (prefix, import_id) = match import_commands::resolve_import_prefix(prefix, quarantine) {
        Ok(value) => value,
        Err(error) => return finish_vault_result(Err(error)),
    };
    if !quiet {
        if let Some(import_id) = &import_id {
            println!("Quarantine import ID: {import_id}");
        }
    }
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
                prefix,
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
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "Error: {error}");
    }
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

/// Deprecation notices of the hidden v4.0 compatibility commands.
///
/// Copied verbatim from `cmd/mcp/mcp_token.go` and `cmd/mcp/mcp_config.go` in
/// the pinned oracle (`3232e31f`, release `unreleased`) and re-verified against
/// the built oracle binary; see `tests/cli_alias_deprecated_stubs.rs` for the
/// byte-exact capture and the reproduction command.
const DEPRECATED_MCP_TOKEN_GROUP: &str =
    "This command is deprecated in v4.0. Use: symvault agent token <new|list|revoke|rotate> <name>";
const DEPRECATED_MCP_TOKEN_CREATE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token new <name>";
const DEPRECATED_MCP_TOKEN_LIST: &str =
    "This command is deprecated in v4.0. Use: symvault agent token list <name>";
const DEPRECATED_MCP_TOKEN_REVOKE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token revoke <name> <token-id>";
const DEPRECATED_MCP_CONFIG: &str =
    "This command is deprecated in v4.0. Use: symvault agent install <agent> --config-only";
const DEPRECATED_MCP_TOKEN_ROTATE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token rotate <name>";

/// Maps the words after `mcp token` to the notice the oracle prints.
///
/// Cobra has no `Args` restriction on the group or its subcommands, so an
/// unknown word (`mcp token bogus`) falls through to the group handler and
/// prints the group notice — verified against the pinned oracle.
fn deprecated_token_message(first: Option<&str>) -> &'static str {
    match first {
        Some("create") => DEPRECATED_MCP_TOKEN_CREATE,
        Some("list") => DEPRECATED_MCP_TOKEN_LIST,
        Some("revoke") => DEPRECATED_MCP_TOKEN_REVOKE,
        _ => DEPRECATED_MCP_TOKEN_GROUP,
    }
}

/// Reproduces the oracle's output for a deprecated compatibility command.
///
/// Go's `cliout.Warnf` prints the deprecation notice first, the returned
/// `ExitNotFound` error is rendered by the command runner and again by the root
/// handler (hence the duplicated `Error: ` line, same as `print_error_like_go`),
/// and `HintForError` falls back to the generic not-found hint. All four lines
/// are printed, and `--quiet` does **not** silence them — verified against the
/// pinned oracle: empty stdout, exit status 2, identical stderr with and without
/// `--quiet`.
fn deprecated_stub_message(message: &str) -> ExitCode {
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{message}");
    let _ = writeln!(stderr, "Error: {message}");
    let _ = writeln!(stderr, "Error: {message}");
    let _ = writeln!(stderr, "Try: symvault find <search-term>");
    ExitCode::from(2)
}

/// Prints one error line the way Go's CLI does.
///
/// Cobra writes the failure from the command's own `RunE` and again from
/// `ExecuteRoot`, so the identical `Error: …` line appears twice on stderr.
/// Verified against the pinned oracle for `config validate`, `auth set`,
/// `auth rotate-passphrase` and `get`'s mutually-exclusive flags. The duplicate
/// is contract parity, not a copy-paste bug.
fn print_error_like_go(message: &str) {
    for _ in 0..2 {
        let _ = writeln!(io::stderr(), "Error: {message}");
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

fn expand_policy_path(path: &Path) -> Result<PathBuf, String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "policy path must be UTF-8".to_owned())?;
    let Some(rest) = raw.strip_prefix('~') else {
        return Ok(path.to_path_buf());
    };
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "cannot determine home directory".to_owned())?;
    Ok(agent_list_commands::clean_path(
        &PathBuf::from(home).join(rest.trim_start_matches('/')),
    ))
}

fn expand_vault_path(path: &Path) -> Result<PathBuf, String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "vault path must be UTF-8".to_owned())?;
    if raw == "~" || raw.starts_with("~/") {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "cannot determine home directory".to_owned())?;
        if raw == "~" {
            // Go returns os.UserHomeDir() untouched for a bare "~".
            return Ok(PathBuf::from(home));
        }
        // Go filepath.Join applies filepath.Clean to the joined result.
        return Ok(agent_list_commands::clean_path(
            &PathBuf::from(home).join(&raw[2..]),
        ));
    }
    // Go ExpandVaultDir ends in filepath.Clean (internal/cli/vaultpath.go);
    // without it a duplicated separator (macOS TMPDIR-style `//`) leaks into
    // rendered paths where Go normalizes it — github.com/danieljustus/symaira-vault/issues/1108.
    Ok(agent_list_commands::clean_path(&PathBuf::from(raw)))
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

#[cfg(test)]
mod expand_vault_path_tests {
    use super::*;

    #[test]
    fn expand_vault_path_cleans_like_go_filepath_clean() {
        assert_eq!(
            expand_vault_path(Path::new("/tmp//vault/./")).unwrap(),
            PathBuf::from("/tmp/vault")
        );
        assert_eq!(
            expand_vault_path(Path::new("a/../b")).unwrap(),
            PathBuf::from("b")
        );
    }
}
