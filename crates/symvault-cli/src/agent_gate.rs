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
//! error to report before the agent check; here it is left to the command
//! itself (the gate stays silent), exactly as when no agent is set.

use std::{ffi::OsString, path::Path};

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

/// Whether `SYMVAULT_AGENT` is set to a non-empty value (agent mode).
pub(crate) fn agent_active() -> bool {
    std::env::var_os(AGENT_ENV).is_some_and(|value| !value.is_empty())
}

/// Runs the gate for the command `path` with the `--vault` / `--profile` flag
/// values the command line carries. Returns the error text (without the
/// `Error: ` prefix) when the agent may not run.
pub(crate) fn preflight(path: &str, vault: Option<&str>, profile: Option<&str>) -> Option<String> {
    if !requires_vault(path) {
        return None;
    }
    let agent = std::env::var_os(AGENT_ENV).filter(|value| !value.is_empty())?;
    let agent = agent.to_string_lossy().into_owned();
    let root = crate::resolve_vault(vault.map(Path::new), profile).ok()?;
    match load(&agent, &root) {
        Ok(()) => None,
        Err(error) => Some(format!("agent mode: {error}: {error}")),
    }
}

/// The gate for Go's hidden `__complete` / `__completeNoDesc` commands, whose
/// root flags precede the command word at `index`.
pub(crate) fn complete_preflight(args: &[OsString], index: usize) -> Option<String> {
    let mut vault = None;
    let mut profile = None;
    let mut tokens = args[1..index].iter().filter_map(|arg| arg.to_str());
    while let Some(token) = tokens.next() {
        for (name, slot) in [("--vault", &mut vault), ("--profile", &mut profile)] {
            if token == name {
                *slot = tokens.next().map(str::to_owned);
            } else if let Some(value) = token
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
            {
                *slot = Some(value.to_owned());
            }
        }
    }
    preflight("__complete", vault.as_deref(), profile.as_deref())
}

/// Go's `agentctx.Load`: the profile lookup in `<vault>/config.yaml`, then the
/// audit logger (best effort: a failure there never fails the load).
fn load(agent: &str, root: &Path) -> Result<(), String> {
    // `filepath.Join` cleans: a vault of `.` yields `config.yaml`, not `./config.yaml`.
    let config_path = crate::agent_list_commands::clean_path(&root.join("config.yaml"));
    let config = Config::load(&config_path).map_err(|error| {
        // `os.ReadFile` fails with `open <path>: <errno text>`; the parser
        // errors are already worded the way Go words them.
        let cause = match &error {
            symvault_core::config::ConfigError::Read(io_error) => {
                crate::config::go_path_error(&config_path, io_error, true)
            }
            _ => None,
        }
        .unwrap_or_else(|| error.to_string());
        format!("load config from {}: {cause}", config_path.display())
    })?;
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
    use super::requires_vault;

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
