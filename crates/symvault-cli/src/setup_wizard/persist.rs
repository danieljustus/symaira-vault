//! Resume-state persistence (`internal/ui/wizard/state_persist.go`).
//!
//! The file lives under the user cache directory, named after the first eight
//! bytes of the SHA-256 of the vault directory string, and is rendered the
//! way `yaml.v3` renders the Go struct so the two implementations can resume
//! each other's files.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::state::{AgentSelection, WizardState};

pub(super) const RESUME_FILE_NAME: &str = ".wizard-resume.yaml";
pub(super) const RESUME_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ResumeState {
    vault_dir: String,
    existing_vault: bool,
    auth_method: String,
    sync_mode: String,
    git_remote_url: String,
    auto_push: bool,
    multi_device: bool,
    recipients: Vec<String>,
    selected_agents: Vec<AgentSelection>,
    backup_dir: String,
    profile_name: String,
    keep_on_error: bool,
    last_step: String,
}

/// Go's `os.UserCacheDir`.
fn user_cache_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LocalAppData")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(|home| PathBuf::from(home).join("Library").join("Caches"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        match std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
            Some(dir) => Path::new(&dir).is_absolute().then(|| PathBuf::from(dir)),
            None => std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".cache")),
        }
    }
}

pub(crate) fn resume_file_path(vault_dir: &str) -> PathBuf {
    if let Some(dir) = user_cache_dir() {
        let digest = Sha256::digest(vault_dir.as_bytes());
        let suffix: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        return dir
            .join("symaira")
            .join("wizard")
            .join(format!("{suffix}.yaml"));
    }
    Path::new(vault_dir).join(RESUME_FILE_NAME)
}

fn ensure_resume_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent)
    }
}

/// `yaml.v3` scalar rendering: strings that would resolve to another type are
/// double-quoted, everything else follows the YAML emitter's own quoting.
fn yaml_scalar(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_owned();
    }
    let ambiguous = matches!(
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(value),
        Ok(serde_yaml_ng::Value::Number(_)
            | serde_yaml_ng::Value::Bool(_)
            | serde_yaml_ng::Value::Null)
    ) || matches!(
        value,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
            | "~"
    ) || value.replace('_', "").parse::<f64>().is_ok();
    if ambiguous {
        return serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned());
    }
    serde_yaml_ng::to_string(&serde_yaml_ng::Value::String(value.to_owned()))
        .map(|text| text.trim_end().to_owned())
        .unwrap_or_else(|_| "\"\"".to_owned())
}

fn render(state: &WizardState, last_step: &str) -> String {
    let mut out = String::new();
    let mut line = |key: &str, value: String| {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    };
    line("vault_dir", yaml_scalar(&state.vault_dir));
    line("existing_vault", state.existing_vault.to_string());
    line("auth_method", yaml_scalar(&state.auth_method));
    line("sync_mode", yaml_scalar(&state.sync_mode));
    line("git_remote_url", yaml_scalar(&state.git_remote_url));
    line("auto_push", state.auto_push.to_string());
    line("multi_device", state.multi_device.to_string());
    if !state.recipients.is_empty() {
        out.push_str("recipients:\n");
        for recipient in &state.recipients {
            out.push_str(&format!("    - {}\n", yaml_scalar(recipient)));
        }
    }
    if !state.selected_agents.is_empty() {
        out.push_str("selected_agents:\n");
        for agent in &state.selected_agents {
            out.push_str(&format!(
                "    - agenttype: {}\n",
                yaml_scalar(&agent.agent_type)
            ));
            out.push_str(&format!(
                "      transport: {}\n",
                yaml_scalar(&agent.transport)
            ));
            out.push_str(&format!("      scope: {}\n", yaml_scalar(&agent.scope)));
            out.push_str(&format!("      readonly: {}\n", agent.read_only));
        }
    }
    let mut line = |key: &str, value: String| {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    };
    line("backup_dir", yaml_scalar(&state.backup_dir));
    line("profile_name", yaml_scalar(&state.profile_name));
    line("keep_on_error", state.keep_on_error.to_string());
    line("last_step", yaml_scalar(last_step));
    out
}

pub(crate) fn save_resume_state(
    vault_dir: &str,
    state: &WizardState,
    last_step: &str,
) -> Result<(), String> {
    let data = render(state, last_step);
    let path = resume_file_path(vault_dir);
    ensure_resume_dir(&path).map_err(|error| format!("create resume dir: {error}"))?;
    symvault_sync::safeio::write_atomic(&path, data.as_bytes()).map_err(|error| error.to_string())
}

pub(crate) fn load_resume_state(vault_dir: &str) -> Result<(WizardState, String), String> {
    let path = resume_file_path(vault_dir);
    let data = fs::read(&path).map_err(|error| format!("read resume state: {error}"))?;
    let text = String::from_utf8_lossy(&data);
    let parsed: ResumeState = if text.trim().is_empty() {
        ResumeState::default()
    } else {
        serde_yaml_ng::from_str(&text)
            .map_err(|error| format!("unmarshal resume state: {error}"))?
    };
    let state = WizardState {
        vault_dir: parsed.vault_dir,
        existing_vault: parsed.existing_vault,
        auth_method: parsed.auth_method,
        sync_mode: parsed.sync_mode,
        git_remote_url: parsed.git_remote_url,
        auto_push: parsed.auto_push,
        multi_device: parsed.multi_device,
        recipients: parsed.recipients,
        selected_agents: parsed.selected_agents,
        backup_dir: parsed.backup_dir,
        profile_name: parsed.profile_name,
        keep_on_error: parsed.keep_on_error,
        ..WizardState::default()
    };
    Ok((state, parsed.last_step))
}

pub(crate) fn resume_file_age(vault_dir: &str) -> Result<Duration, std::io::Error> {
    let modified = fs::metadata(resume_file_path(vault_dir))?.modified()?;
    Ok(SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO))
}

pub(crate) fn delete_resume_file(vault_dir: &str) -> std::io::Result<()> {
    match fs::remove_file(resume_file_path(vault_dir)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WizardState {
        WizardState {
            vault_dir: "/tmp/v".into(),
            auth_method: "passphrase".into(),
            sync_mode: "git".into(),
            git_remote_url: "https://example.invalid/v.git".into(),
            auto_push: true,
            profile_name: "default".into(),
            recipients: vec!["age1abc".into()],
            selected_agents: vec![AgentSelection {
                agent_type: "claude-code".into(),
                transport: "stdio".into(),
                scope: "*".into(),
                read_only: true,
            }],
            ..WizardState::default()
        }
    }

    #[test]
    fn rendering_matches_the_yaml_v3_layout_of_the_go_struct() {
        let text = render(&sample(), "Profile Name");
        assert_eq!(
            text,
            "vault_dir: /tmp/v\nexisting_vault: false\nauth_method: passphrase\nsync_mode: git\n\
git_remote_url: https://example.invalid/v.git\nauto_push: true\nmulti_device: false\n\
recipients:\n    - age1abc\nselected_agents:\n    - agenttype: claude-code\n      transport: stdio\n      scope: '*'\n      readonly: true\n\
backup_dir: \"\"\nprofile_name: default\nkeep_on_error: false\nlast_step: Profile Name\n"
        );
    }

    #[test]
    fn rendering_omits_empty_lists_and_quotes_empty_strings() {
        let text = render(&WizardState::default(), "Welcome");
        assert!(!text.contains("recipients"));
        assert!(!text.contains("selected_agents"));
        assert!(text.contains("vault_dir: \"\"\n"));
        assert!(text.ends_with("last_step: Welcome\n"));
    }

    #[test]
    fn ambiguous_scalars_are_quoted() {
        assert_eq!(yaml_scalar("true"), "\"true\"");
        assert_eq!(yaml_scalar("123"), "\"123\"");
        assert_eq!(yaml_scalar("yes"), "\"yes\"");
        assert_eq!(yaml_scalar("plain words"), "plain words");
    }

    #[test]
    fn rendered_state_parses_back() {
        let text = render(&sample(), "Sync Strategy");
        let parsed: ResumeState = serde_yaml_ng::from_str(&text).unwrap();
        assert_eq!(parsed.vault_dir, "/tmp/v");
        assert_eq!(parsed.selected_agents, sample().selected_agents);
        assert_eq!(parsed.last_step, "Sync Strategy");
    }

    #[test]
    fn resume_path_hashes_the_vault_dir() {
        let path = resume_file_path("/a/b");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), 16 + ".yaml".len());
        assert_ne!(path, resume_file_path("/a/c"));
    }
}
