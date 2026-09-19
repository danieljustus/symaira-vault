//! `agent uninstall` — removes an agent profile, revokes its MCP tokens,
//! deletes the token file, and removes the skill file when Symaira Vault
//! manages it.
//!
//! Order, wording, and streams mirror the Go oracle: every hint (`✓`) and
//! warning (`⚠`) goes to **stderr**, the two closing lines go to stderr
//! unconditionally.
//!
//! Measured: the oracle still prints hints under `--quiet`, because Go only
//! calls `cliout.SetQuiet` on the `internal/cli` runner path this command does
//! not use. The port therefore never suppresses here either.

use std::{
    fs,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use symvault_core::config::Config;
use symvault_store::token_registry;
use time::OffsetDateTime;

use super::agent_doctor_commands::{SENTINEL, expand_tilde, parse_manifest};

/// Flags shared with the CLI parser.
pub(crate) struct Options {
    pub(crate) keep_config: bool,
    pub(crate) keep_skill: bool,
    pub(crate) yes: bool,
}

impl Options {
    /// `✓` line on stderr — Go's `cliout.Hintf` without its unreachable quiet
    /// gate (see the module note).
    fn hint(&self, message: &str) {
        let _ = writeln!(std::io::stderr(), "{message}");
    }

    /// `⚠` line on stderr — Go's `cliout.Warnf`, same note.
    fn warn(&self, message: &str) {
        let _ = writeln!(std::io::stderr(), "{message}");
    }
}

/// Reads Go's confirmation prompt: only an interactive stdin can answer, so a
/// piped stdin (or `--yes` absent) cancels instead of blocking.
fn confirm(agent: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    let _ = write!(
        std::io::stderr(),
        "Remove agent {agent:?} and all associated data? This cannot be undone. [y/N] "
    );
    let _ = std::io::stderr().flush();
    let mut reply = String::new();
    if std::io::stdin().lock().read_line(&mut reply).is_err() {
        return false;
    }
    let reply = reply.trim().to_lowercase();
    reply == "y" || reply == "yes"
}

pub(crate) fn uninstall(vault: &Path, agent: &str, options: &Options) -> Result<(), String> {
    let config_path = vault.join("config.yaml");
    let mut config = Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
    let Some(profile) = config.agents.get(agent).cloned() else {
        return Err(format!("agent {agent:?} not found in config"));
    };

    if !options.yes && !confirm(agent) {
        options.warn("Uninstall canceled.");
        return Ok(());
    }

    if !options.keep_config {
        config.agents.remove(agent);
        config
            .save_to(&config_path)
            .map_err(|error| format!("save config: {error}"))?;
        options.hint(&format!("✓ Profile for {agent:?} removed from config"));
    } else {
        options.warn(&format!(
            "⚠ Keeping profile for {agent:?} in config (--keep-config)"
        ));
    }

    // A missing or unreadable registry stays silent, like Go's `Load` error.
    if let Ok(outcome) =
        token_registry::revoke_all_for_agent(vault, agent, OffsetDateTime::now_utc())
    {
        if let Some(error) = outcome.save_error {
            options.warn(&format!("⚠ Failed to save token registry: {error}"));
        }
        if outcome.revoked > 0 {
            options.hint(&format!(
                "✓ Revoked {} token(s) for {agent:?}",
                outcome.revoked
            ));
        }
    }

    let token_file = vault.join("mcp-tokens").join(format!("{agent}.token"));
    if token_file.exists() {
        match fs::remove_file(&token_file) {
            Ok(()) => options.hint(&format!("✓ Removed token file {}", token_file.display())),
            Err(error) => options.warn(&format!(
                "⚠ Failed to remove token file {}: {error}",
                token_file.display()
            )),
        }
    }

    if !options.keep_skill {
        remove_managed_skill(&profile.skill_path, options);
    } else {
        options.warn("⚠ Keeping skill file (--keep-skill)");
    }

    let _ = writeln!(std::io::stderr(), "\nAgent {agent:?} has been uninstalled.");
    let _ = writeln!(
        std::io::stderr(),
        "Note: MCP server entries in the agent's config file (e.g. mcp.json) must be removed manually."
    );
    Ok(())
}

/// Deletes the skill file only when its frontmatter carries the Symaira
/// sentinel. An unreadable file, missing frontmatter, or a foreign
/// `managed_by` leaves it in place and stays silent — Go's behavior.
fn remove_managed_skill(skill_path: &str, options: &Options) {
    if skill_path.is_empty() {
        return;
    }
    let path = expand_tilde(skill_path).unwrap_or_else(|| PathBuf::from(skill_path));
    let path = clean_path(&path);
    let Ok(data) = fs::read(&path) else {
        return;
    };
    let Ok((manifest, _body)) = parse_manifest(&data) else {
        return;
    };
    if manifest.managed_by != SENTINEL {
        return;
    }
    match fs::remove_file(&path) {
        Ok(()) => options.hint(&format!("✓ Removed skill file {}", path.display())),
        Err(error) => options.warn(&format!(
            "⚠ Failed to remove skill file {}: {error}",
            path.display()
        )),
    }
}

/// Lexical cleanup following Go's `filepath.Clean`: drops `.` segments and
/// redundant separators, resolves `..` without escaping the root, and keeps a
/// trailing separator rule out because Go strips it here too.
fn clean_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => {
                rooted = true;
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let popable = matches!(out.components().next_back(), Some(Component::Normal(_)));
                if popable {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    if out.as_os_str().is_empty() && rooted {
        PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANAGED: &str = "---\nmanaged_by: symaira\nmanaged_version: dev\n---\nbody\n";
    const FOREIGN: &str = "---\nmanaged_by: someone-else\n---\nbody\n";

    fn fixture(skill: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("fixture root");
        let skill_file = root.path().join("SKILL.md");
        fs::write(&skill_file, skill).unwrap();
        fs::write(
            root.path().join("config.yaml"),
            format!(
                "agents:\n  demo:\n    tier: safe\n    skillPath: {}\n",
                skill_file.display()
            ),
        )
        .unwrap();
        fs::create_dir_all(root.path().join("mcp-tokens")).unwrap();
        fs::write(root.path().join("mcp-tokens/demo.token"), "raw\n").unwrap();
        (root, skill_file.clone(), skill_file)
    }

    /// Writes the version-2 registry shape directly. Minting through
    /// `token_registry::create` made this test depend on another module's I/O
    /// and failed on the CI runners; the command under test only reads the file.
    fn mint_token(root: &Path) {
        fs::write(
            root.join("mcp-tokens.json"),
            r#"{"version":2,"tokens":{"tok-fixture":{"id":"tok-fixture","hash":"deadbeef","prefix":"dead","allowed_tools":["*"],"tool_registry_hash":"","agent_name":"demo","created_at":"2026-01-01T00:00:00Z","revoked":false}}}"#,
        )
        .unwrap();
    }

    fn options() -> Options {
        Options {
            keep_config: false,
            keep_skill: false,
            yes: true,
        }
    }

    #[test]
    fn uninstall_removes_profile_token_file_token_and_managed_skill() {
        let (root, skill_file, _) = fixture(MANAGED);
        mint_token(root.path());
        uninstall(root.path(), "demo", &options()).expect("uninstall success");

        let config = fs::read_to_string(root.path().join("config.yaml")).unwrap();
        assert!(!config.contains("demo:"), "profile kept: {config}");
        assert!(!root.path().join("mcp-tokens/demo.token").exists());
        assert!(!skill_file.exists(), "managed skill kept");

        let registry = fs::read_to_string(root.path().join("mcp-tokens.json")).unwrap();
        assert!(registry.contains("\"revoked\": true"), "{registry}");
    }

    #[test]
    fn uninstall_keeps_foreign_and_unreadable_skill_files() {
        for skill in [FOREIGN, "# no frontmatter\n"] {
            let (root, skill_file, _) = fixture(skill);
            uninstall(root.path(), "demo", &options()).expect("uninstall success");
            assert!(skill_file.exists(), "skill removed for {skill:?}");
        }
    }

    #[test]
    fn uninstall_keeps_parts_selected_by_flags() {
        let (root, skill_file, _) = fixture(MANAGED);
        uninstall(
            root.path(),
            "demo",
            &Options {
                keep_config: true,
                keep_skill: true,
                yes: true,
            },
        )
        .expect("uninstall success");
        assert!(
            fs::read_to_string(root.path().join("config.yaml"))
                .unwrap()
                .contains("demo:")
        );
        assert!(skill_file.exists());
        assert!(!root.path().join("mcp-tokens/demo.token").exists());
    }

    #[test]
    fn uninstall_without_confirmation_leaves_everything_alone() {
        let (root, skill_file, _) = fixture(MANAGED);
        uninstall(
            root.path(),
            "demo",
            &Options {
                keep_config: false,
                keep_skill: false,
                yes: false,
            },
        )
        .expect("cancel is not an error");
        assert!(
            fs::read_to_string(root.path().join("config.yaml"))
                .unwrap()
                .contains("demo:")
        );
        assert!(skill_file.exists());
        assert!(root.path().join("mcp-tokens/demo.token").exists());
    }

    #[test]
    fn uninstall_reports_an_unknown_agent() {
        let (root, _, _) = fixture(MANAGED);
        let error = uninstall(root.path(), "nope", &options()).expect_err("must fail");
        assert_eq!(error, "agent \"nope\" not found in config");
    }
}
