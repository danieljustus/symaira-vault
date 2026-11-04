//! Agent-mode preflight, matching the tail of Go's root `PersistentPreRunE`
//! (`internal/cli/cli.go`).
//!
//! For every command that requires a vault, once the vault path has resolved,
//! a non-empty `SYMVAULT_AGENT` makes Go call `agentctx.Load(agent, vault)`.
//! A failure ends the process with exit 5 (permission denied) and the message
//! `agent mode: <error>`, printed twice (cobra, then `ExecuteRoot`) because the
//! `CLIError` carries the load error as its cause and renders `<message>:
//! <cause>`. A load that succeeds opens (and creates) the agent's audit log
//! `<vault>/audit-<agent>.log` as a side effect and then lets the command run.
//!
//! Ordering, as in cobra: the argument validator and the output-format gate run
//! first, required flags after. A vault path that does not resolve is Go's
//! `VaultPath` error, reported before the agent check: with an agent set the
//! gate ends the process the way Go does (exit 1, `resolve profile: <cause>` or
//! `expand vault path: <cause>`, printed twice). Without an agent the gate stays
//! silent and the command reports its own error, as before.
//!
//! Known wording gaps (the exit status and the refusal itself always match):
//! a `SYMVAULT_VAULT` that is not UTF-8 is refused with `vault path must be
//! UTF-8` where Go would carry on with the raw bytes, and a profile name with
//! control characters is quoted by Rust's `{:?}` rather than Go's `%q`.

use std::path::Path;

use symvault_core::config::Config;

const AGENT_ENV: &str = "SYMVAULT_AGENT";

/// Exit status of `ExitPermissionDenied`.
pub(crate) const EXIT_PERMISSION_DENIED: u8 = 5;

/// Go's `commandRequiresVault`: a command requires a vault unless it, or its
/// nearest annotated ancestor, carries `symvault/requires-vault: "false"`.
/// `path` is the command path without the program name (`agent whoami`).
pub(crate) fn requires_vault(path: &str) -> bool {
    // `audit rotate-key` is annotated "true" below an annotated "false" parent.
    if path == "audit rotate-key" {
        return true;
    }
    const EXEMPT_TREES: &[&str] = &["config", "policy", "profile", "remote", "update"];
    const EXEMPT_COMMANDS: &[&str] = &[
        "agent install",
        "agent list",
        "agent uninstall",
        "agent upgrade",
        "agent whoami",
        "audit",
        "audit export",
        "doctor",
        "setup",
        "startup-profile",
        "version",
    ];
    let in_exempt_tree = EXEMPT_TREES.iter().any(|tree| {
        path == *tree
            || path
                .strip_prefix(tree)
                .is_some_and(|rest| rest.starts_with(' '))
    });
    !(in_exempt_tree || EXEMPT_COMMANDS.contains(&path))
}

/// Why the process must end before the command runs: the text (without the
/// `Error: ` prefix, printed twice by the callers) and the exit status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) message: String,
    pub(crate) code: u8,
}

/// Whether `SYMVAULT_AGENT` is set to a non-empty value (agent mode).
pub(crate) fn agent_active() -> bool {
    std::env::var_os(AGENT_ENV).is_some_and(|value| !value.is_empty())
}

/// Runs the gate for the command `path` with the `--vault` / `--profile` flag
/// values the command line carries. Returns the refusal when the agent may not
/// run (or, with an agent set, when the vault path does not resolve).
pub(crate) fn preflight(path: &str, vault: Option<&str>, profile: Option<&str>) -> Option<Refusal> {
    if !requires_vault(path) {
        return None;
    }
    let agent = std::env::var_os(AGENT_ENV).filter(|value| !value.is_empty())?;
    let agent = agent.to_string_lossy().into_owned();
    let root = match crate::resolve_vault_with(vault.map(Path::new), profile, go_config) {
        Ok(root) => root,
        Err(error) => {
            return Some(Refusal {
                message: format!("{}: {error}", vault_error_prefix(vault, profile)),
                code: 1,
            });
        }
    };
    match load(&agent, &root) {
        Ok(()) => None,
        Err(error) => Some(Refusal {
            message: format!("agent mode: {error}: {error}"),
            code: EXIT_PERMISSION_DENIED,
        }),
    }
}

/// The gate for Go's hidden `__complete` / `__completeNoDesc` commands. They
/// disable flag parsing, so `--vault` / `--profile` on the command line never
/// reach `VaultPath`; only the environment and the default decide the vault.
pub(crate) fn complete_preflight() -> Option<Refusal> {
    preflight("__complete", None, None)
}

const VAULT_EXPAND: &str = "expand vault path";
const VAULT_PROFILE: &str = "resolve profile";

/// Go's wording for a `VaultPath` failure: `expand vault path` for an explicit
/// vault (flag or environment) or the default, `resolve profile` for a profile.
fn vault_error_prefix(vault: Option<&str>, profile: Option<&str>) -> &'static str {
    let env = |name: &str| std::env::var(name).ok();
    error_prefix(
        vault,
        profile,
        env("SYMVAULT_VAULT").as_deref(),
        env("SYMVAULT_PROFILE").as_deref(),
    )
}

/// [`vault_error_prefix`] with the environment given explicitly, in Go's
/// `VaultPath` order: vault flag, vault environment, profile flag, profile
/// environment, default.
fn error_prefix(
    vault: Option<&str>,
    profile: Option<&str>,
    env_vault: Option<&str>,
    env_profile: Option<&str>,
) -> &'static str {
    let set = |value: Option<&str>| value.is_some_and(|value| !value.trim().is_empty());
    if vault.is_some() || set(env_vault) || !(set(profile) || set(env_profile)) {
        VAULT_EXPAND
    } else {
        VAULT_PROFILE
    }
}

/// `configpkg.Load` with Go's error wording (`open <path>: <errno text>`; the
/// parser errors are already worded the way Go words them).
fn go_config(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|error| {
        match &error {
            symvault_core::config::ConfigError::Read(io_error) => {
                crate::config::go_path_error(path, io_error, true)
            }
            _ => None,
        }
        .unwrap_or_else(|| error.to_string())
    })
}

/// Go's `agentctx.Load`: the profile lookup in `<vault>/config.yaml`, then the
/// audit logger (best effort: a failure there never fails the load).
fn load(agent: &str, root: &Path) -> Result<(), String> {
    // `filepath.Join` cleans: a vault of `.` yields `config.yaml`, not `./config.yaml`.
    let config_path = crate::agent_list_commands::clean_path(&root.join("config.yaml"));
    let config = go_config(&config_path)
        .map_err(|cause| format!("load config from {}: {cause}", config_path.display()))?;
    if !config.agents.contains_key(agent) {
        return Err(format!(
            "agent {} not found in config",
            crate::cli_artifacts::quote_go_string(agent)
        ));
    }
    if let Some(keyring) = crate::runtime_session_manager().keyring.as_deref() {
        let _ = symvault_store::audit::open_with_keyring(
            agent,
            root,
            keyring,
            symvault_store::audit::RotationConfig::default(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{error_prefix, requires_vault};

    #[test]
    fn vault_path_errors_are_worded_by_the_step_that_failed() {
        const EXPAND: &str = "expand vault path";
        const PROFILE: &str = "resolve profile";
        // (vault flag, profile flag, SYMVAULT_VAULT, SYMVAULT_PROFILE, want)
        type Case<'a> = (
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a str>,
            &'a str,
        );
        let table: &[Case<'_>] = &[
            (Some("x"), Some("p"), None, None, EXPAND),
            (Some(""), None, None, Some("p"), EXPAND),
            (None, Some("p"), Some("v"), None, EXPAND),
            (None, Some("p"), Some("  "), None, PROFILE),
            (None, Some("p"), None, None, PROFILE),
            (None, Some(" "), None, Some("p"), PROFILE),
            (None, None, None, Some("p"), PROFILE),
            (None, Some(""), None, None, EXPAND),
            (None, None, None, Some("  "), EXPAND),
            (None, None, None, None, EXPAND),
        ];
        for (vault, profile, env_vault, env_profile, want) in table {
            assert_eq!(
                error_prefix(*vault, *profile, *env_vault, *env_profile),
                *want,
                "{vault:?} {profile:?} {env_vault:?} {env_profile:?}"
            );
        }
    }

    /// `path<TAB>requires` for every command of the pinned Go tree, dumped from
    /// `cmd.NewRootCmd()` with Go's own `commandRequiresVault` at ccaf3bdc.
    const GO_TREE: &str = include_str!("../tests/fixtures/agent_gate_requires_vault.tsv");

    #[test]
    fn requires_vault_matches_the_go_command_tree() {
        let mut checked = 0;
        for line in GO_TREE.lines() {
            let (path, requires) = line.split_once('\t').expect("path<TAB>requires");
            assert_eq!(
                requires_vault(path),
                requires == "true",
                "requires_vault({path:?})"
            );
            checked += 1;
        }
        assert!(checked > 100, "{checked} rows");
    }
}
