//! The side effects behind the summary screen's "Apply"
//! (`internal/ui/wizard/apply.go`).
//!
//! Errors are collected into a list and the next step runs regardless, so the
//! user can repair things with `symvault doctor` afterwards. A few Go quirks
//! are kept on purpose because the on-disk result depends on them; each is
//! marked where it happens.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use symvault_core::config::{Config, Profile};
use symvault_crypto::{SecretBytes, encrypt_identity_scrypt, generate_identity, recipient_string};
use symvault_store::token_registry::{self, NewToken};
use symvault_sync::{GitRepository, recipients::RecipientsFile, safeio};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{
    persist,
    state::{AgentSelection, DEFAULT_PROFILE, SYNC_GIT, WizardState},
    steps::AGENT_DEFINITIONS,
};

/// Platform hooks the model cannot own: the Touch ID probe and the keychain
/// write, both of which live in the binary's session layer.
pub(crate) struct Environment {
    pub touch_id_available: bool,
    pub save_touch_id: Box<dyn Fn(&Path, &[u8]) -> Result<(), String>>,
}

impl Environment {
    /// A passphrase-only environment, used by tests and non-macOS builds.
    #[cfg(test)]
    pub(crate) fn passphrase_only() -> Self {
        Self {
            touch_id_available: false,
            save_touch_id: Box::new(|_, _| Err("Touch ID is not available".to_owned())),
        }
    }
}

/// What `applyGit` did: Go dereferences a nil `cfg.Git` there and panics.
pub(super) enum GitOutcome {
    Done,
    NilGitConfigPanic,
}

/// `preFlightCheck`.
pub(super) fn pre_flight_check(state: &WizardState) -> Result<(), String> {
    for recipient in &state.recipients {
        if !recipient.starts_with("age1") || recipient.len() < 50 {
            return Err(format!("invalid recipient key: {recipient}"));
        }
    }
    Ok(())
}

/// `rollbackInit`: never touches a vault that existed before the wizard ran.
pub(super) fn rollback_init(state: &WizardState) {
    if state.existing_vault {
        return;
    }
    let root = Path::new(&state.vault_dir);
    let _ = fs::remove_file(root.join("config.yaml"));
    let _ = fs::remove_file(root.join("identity.age"));
    let _ = fs::remove_dir_all(root.join("entries"));
    if state.sync_mode == SYNC_GIT {
        let _ = fs::remove_dir_all(root.join(".git"));
        let _ = fs::remove_file(root.join(".gitignore"));
    }
}

/// The vault `config.yaml` bytes `vault.InitWithPassphrase` writes: the
/// marshalled `config.Default()` with `vaultDir` and `authMethod` replaced.
/// An empty `authMethod` (the Auth step was skipped, so nothing set it) is
/// omitted by Go's `omitempty`.
pub(super) fn vault_config_bytes(vault_dir: &str, auth_method: &str) -> Result<Vec<u8>, String> {
    let config = Config {
        vault_dir: vault_dir.to_owned(),
        ..Config::default()
    };
    let rendered = config
        .to_yaml_bytes()
        .map_err(|error| format!("marshal config: {error}"))?;
    let text = String::from_utf8(rendered).map_err(|error| error.to_string())?;
    let replacement = if auth_method.is_empty() {
        String::new()
    } else {
        format!("authMethod: {}\n", yaml_plain_or_quoted(auth_method))
    };
    Ok(text
        .replacen("authMethod: passphrase\n", &replacement, 1)
        .into_bytes())
}

fn yaml_plain_or_quoted(value: &str) -> String {
    serde_yaml_ng::to_string(&serde_yaml_ng::Value::String(value.to_owned()))
        .map(|text| text.trim_end().to_owned())
        .unwrap_or_else(|_| format!("{value:?}"))
}

/// `vault.InitWithPassphrase` with the wizard's configuration. Returns the
/// identity's public key.
pub(super) fn init_vault(
    vault_dir: &str,
    passphrase: &[u8],
    auth_method: &str,
) -> Result<String, String> {
    if vault_dir.is_empty() {
        return Err("vault directory is empty".to_owned());
    }
    if passphrase.is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    let root = Path::new(vault_dir);
    let identity = generate_identity();
    safeio::create_dir_all(&root.join("entries"))
        .map_err(|error| format!("create vault dir: {error}"))?;
    let config = vault_config_bytes(vault_dir, auth_method)?;
    safeio::write_atomic(&root.join("config.yaml"), &config)
        .map_err(|error| format!("write config: {error}"))?;
    let encrypted = encrypt_identity_scrypt(&identity, &SecretBytes::new(passphrase), 0)
        .map_err(|error| format!("save identity: {error}"))?;
    safeio::write_atomic(&root.join("identity.age"), &encrypted)
        .map_err(|error| format!("save identity: {error}"))?;
    Ok(recipient_string(&identity))
}

/// `applyVaultInit`. The error return is discarded by the caller, as in Go.
pub(super) fn apply_vault_init(
    state: &mut WizardState,
    errors: &mut Vec<String>,
    env: &Environment,
) -> Result<(), String> {
    if state.existing_vault {
        return Ok(());
    }
    let passphrase = Zeroizing::new(state.passphrase.clone().unwrap_or_default());
    let public_key = init_vault(&state.vault_dir, &passphrase, &state.auth_method)
        .map_err(|error| format!("vault init: {error}"))?;
    state.vault_public_key = public_key;
    if state.auth_method == "touchid"
        && env.touch_id_available
        && let Err(error) = (env.save_touch_id)(Path::new(&state.vault_dir), &passphrase)
    {
        errors.push(format!("Touch ID setup: {error}"));
    }
    Ok(())
}

/// The global config path `Config.Save()` writes to.
fn default_config_path() -> PathBuf {
    symvault_core::config::PathResolver::new().config_path()
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) {}

/// `applyGit`.
pub(super) fn apply_git(state: &WizardState, errors: &mut Vec<String>) -> GitOutcome {
    if state.sync_mode != SYNC_GIT {
        return GitOutcome::Done;
    }
    let root = Path::new(&state.vault_dir);
    let repository = match GitRepository::init(root) {
        Ok(repository) => repository,
        Err(error) => {
            errors.push(format!("git init: {error}"));
            return GitOutcome::Done;
        }
    };
    match repository.create_gitignore() {
        // Go writes `.gitignore` through `AtomicWriteFile(..., 0o600)`; the
        // shared repository helper leaves the umask default.
        Ok(()) => restrict_to_owner(&root.join(".gitignore")),
        Err(error) => errors.push(format!("gitignore: {error}")),
    }
    if !state.git_remote_url.is_empty() {
        let has_remote = matches!(repository.remote_url("origin"), Ok(Some(_)));
        if !has_remote && let Err(error) = repository.add_remote("origin", &state.git_remote_url) {
            errors.push(format!("git remote: {error}"));
        }
    }
    // Go loads the *vault's* config but `Save()` writes the default (global)
    // config path, and dereferences `cfg.Git` without a nil check. A vault
    // the wizard itself just created has no `git:` section, so that panics.
    if let Ok(mut config) = Config::load(root.join("config.yaml")) {
        let Some(git) = config.git.as_mut() else {
            return GitOutcome::NilGitConfigPanic;
        };
        git.auto_push = state.auto_push;
        let _ = config.save_to(default_config_path());
    }
    GitOutcome::Done
}

/// `applyRecipients`.
pub(super) fn apply_recipients(state: &WizardState, errors: &mut Vec<String>) {
    if state.recipients.is_empty() {
        return;
    }
    let file = RecipientsFile::new(&state.vault_dir);
    for recipient in &state.recipients {
        if let Err(error) = file.add(recipient) {
            let prefix = if recipient.len() > 8 {
                recipient.get(..8).unwrap_or(recipient)
            } else {
                recipient
            };
            errors.push(format!("add recipient {prefix}: {error}"));
        }
    }
}

/// `applyProfile`: reads the legacy `~/.symvault/config.yaml`, writes the
/// resolved default config path.
pub(super) fn apply_profile(state: &WizardState, errors: &mut Vec<String>) {
    if state.profile_name.is_empty() || state.profile_name == DEFAULT_PROFILE {
        return;
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let global = home.join(".symvault").join("config.yaml");
    let mut config = Config::load(global).unwrap_or_default();
    let profiles = config.profiles.get_or_insert_with(Default::default);
    if profiles.contains_key(&state.profile_name) {
        return;
    }
    profiles.insert(
        state.profile_name.clone(),
        Profile {
            vault_path: state.vault_dir.clone(),
        },
    );
    if let Err(error) = config.save_to(default_config_path()) {
        errors.push(format!("save profile: {error}"));
    }
}

/// `applyAgents`.
pub(super) fn apply_agents(state: &WizardState, errors: &mut Vec<String>) {
    // The Rust token registry serializes writers through a `.lock` file in
    // the vault; Go's registry does not, so a lock file this step created is
    // removed again to leave the same file set behind.
    let lock = Path::new(&state.vault_dir).join(".lock");
    let had_lock = lock.exists();
    for selection in &state.selected_agents {
        if let Err(error) = install_agent(&state.vault_dir, selection) {
            errors.push(format!("install agent {}: {error}", selection.agent_type));
        }
    }
    if !had_lock {
        let _ = fs::remove_file(&lock);
    }
}

/// `installAgent`.
///
/// Go calls `install.Install` without a `Format`, and `GetReaderWriter("")`
/// rejects that, so every agent installation fails after the token registry
/// was loaded (and, for the HTTP transport, a token created). The port keeps
/// that outcome: the registry side effects happen, then the same error is
/// recorded, which makes Apply roll back unless `--keep-on-error` is set.
fn install_agent(vault_dir: &str, selection: &AgentSelection) -> Result<(), String> {
    let root = Path::new(vault_dir);
    load_token_system(root).map_err(|error| format!("load token system: {error}"))?;

    if selection.transport == "http" {
        let allowed_tools = if selection.read_only {
            vec!["get".to_owned(), "list".to_owned(), "find".to_owned()]
        } else {
            vec!["*".to_owned()]
        };
        let request = NewToken {
            label: &selection.agent_type,
            allowed_tools,
            agent_name: &selection.agent_type,
            ttl: None,
            tool_registry_hash: crate::agent_install_commands::PINNED_TOOL_REGISTRY_HASH,
        };
        token_registry::create(root, &request, OffsetDateTime::now_utc())
            .map_err(|error| format!("create token: {error}"))?;
    }

    if !AGENT_DEFINITIONS
        .iter()
        .any(|def| def.agent_type == selection.agent_type)
    {
        return Err(format!(
            "unsupported agent {:?} (valid: openclaw, claude-code, hermes, codex, opencode)",
            selection.agent_type
        ));
    }
    Err("unsupported config format \"\"".to_owned())
}

/// `auth.LoadTokenSystem`: an empty registry gets the legacy token entry,
/// migrated from `mcp-token` when that file exists.
fn load_token_system(root: &Path) -> Result<(), String> {
    let mut tokens = crate::agent_list_commands::load_tokens(root)?;
    tokens.retain(|token| !token.hash.is_empty());
    if !tokens.is_empty() {
        return Ok(());
    }
    let has_env_token =
        std::env::var_os("SYMVAULT_MCP_TOKEN").is_some_and(|token| !token.is_empty());
    let legacy_path = root.join("mcp-token");
    let legacy = match fs::read(&legacy_path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            std::str::from_utf8(&bytes)
                .ok()
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| Zeroizing::new(token.to_owned()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) if has_env_token => return Ok(()),
        Err(error) => return Err(format!("load legacy token: {error}")),
    };
    if legacy.is_none() && has_env_token {
        // Go keeps an environment token in memory only and leaves the
        // registry empty.
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    let migrated = match legacy.as_deref() {
        Some(raw) => token_registry::import_legacy(root, raw, now),
        None => token_registry::create_legacy(root, now),
    }
    .map_err(|error| format!("load legacy token: {error}"))?;
    if let Some(id) = migrated {
        eprintln!(
            "WARNING: legacy MCP token migrated to scoped registry with wildcard (*) tool access (id={id}).\n         To restrict scope, run: symvault agent token new <agent> --label <label> --tools <list>\n         Then revoke the legacy token: symvault agent token revoke legacy {id}"
        );
        if legacy.is_some() {
            match fs::symlink_metadata(&legacy_path) {
                Ok(meta) if meta.file_type().is_file() => {
                    let _ = fs::remove_file(&legacy_path);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Final cleanup shared by the success path: forget the saved progress.
pub(super) fn forget_resume(state: &WizardState) {
    let _ = persist::delete_resume_file(&state.vault_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symvault-wizard-apply-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn preflight_rejects_short_or_foreign_recipients() {
        let mut state = WizardState::default();
        state.recipients = vec!["age1short".into()];
        assert_eq!(
            pre_flight_check(&state).unwrap_err(),
            "invalid recipient key: age1short"
        );
        state.recipients =
            vec!["ssh-ed25519-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()];
        assert!(pre_flight_check(&state).is_err());
        state.recipients =
            vec!["age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y".into()];
        assert!(pre_flight_check(&state).is_ok());
    }

    #[test]
    fn vault_config_is_default_config_with_the_chosen_auth_method() {
        let with_auth = String::from_utf8(vault_config_bytes("/v", "passphrase").unwrap()).unwrap();
        assert!(with_auth.contains("vaultDir: /v\n"));
        assert!(with_auth.ends_with("authMethod: passphrase\n"));
        assert!(!with_auth.contains("useTouchID"));
        let without = String::from_utf8(vault_config_bytes("/v", "").unwrap()).unwrap();
        assert!(!without.contains("authMethod"));
        let touch = String::from_utf8(vault_config_bytes("/v", "touchid").unwrap()).unwrap();
        assert!(touch.ends_with("authMethod: touchid\n"));
    }

    #[test]
    fn init_vault_writes_the_three_artifacts_and_an_openable_identity() {
        let root = scratch("init").join("vault");
        let recipient = init_vault(
            &root.to_string_lossy(),
            b"correct horse battery staple",
            "passphrase",
        )
        .unwrap();
        assert!(recipient.starts_with("age1"));
        assert!(root.join("entries").is_dir());
        let identity = fs::read(root.join("identity.age")).unwrap();
        let opened = symvault_crypto::decrypt_identity(
            &identity,
            &SecretBytes::new(b"correct horse battery staple"),
        )
        .unwrap();
        assert_eq!(recipient_string(&opened), recipient);
        assert!(
            symvault_crypto::decrypt_identity(&identity, &SecretBytes::new(b"wrong wrong wrong"))
                .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for (name, mode) in [("config.yaml", 0o600), ("identity.age", 0o600)] {
                let actual = fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777;
                assert_eq!(actual, mode, "{name}");
            }
        }
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn init_rejects_empty_inputs_like_go() {
        assert_eq!(
            init_vault("", b"x", "").unwrap_err(),
            "vault directory is empty"
        );
        assert_eq!(
            init_vault("/x", b"", "").unwrap_err(),
            "passphrase is empty"
        );
    }

    #[test]
    fn rollback_removes_only_wizard_artifacts_and_spares_existing_vaults() {
        let root = scratch("rollback");
        for name in ["config.yaml", "identity.age", ".gitignore", "keep.txt"] {
            fs::write(root.join(name), b"x").unwrap();
        }
        fs::create_dir_all(root.join("entries/a")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        let mut state = WizardState {
            vault_dir: root.to_string_lossy().into_owned(),
            existing_vault: true,
            sync_mode: "git".into(),
            ..WizardState::default()
        };
        rollback_init(&state);
        assert!(
            root.join("config.yaml").exists(),
            "existing vault is untouched"
        );
        state.existing_vault = false;
        state.sync_mode = "local".into();
        rollback_init(&state);
        assert!(!root.join("config.yaml").exists());
        assert!(!root.join("identity.age").exists());
        assert!(!root.join("entries").exists());
        assert!(
            root.join(".git").exists(),
            "git artifacts only go in git mode"
        );
        assert!(root.join("keep.txt").exists());
        state.sync_mode = "git".into();
        rollback_init(&state);
        assert!(!root.join(".git").exists());
        assert!(!root.join(".gitignore").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn every_agent_install_fails_with_the_go_format_error() {
        let root = scratch("agents");
        let selection = AgentSelection {
            agent_type: "codex".into(),
            transport: "stdio".into(),
            scope: "*".into(),
            read_only: true,
        };
        let mut state = WizardState {
            vault_dir: root.to_string_lossy().into_owned(),
            selected_agents: vec![selection],
            ..WizardState::default()
        };
        let mut errors = Vec::new();
        apply_agents(&state, &mut errors);
        assert_eq!(
            errors,
            ["install agent codex: unsupported config format \"\""]
        );
        // The failed install still left the migrated legacy token behind.
        assert!(root.join("mcp-tokens.json").is_file());
        state.selected_agents[0].agent_type = "nope".into();
        let mut errors = Vec::new();
        apply_agents(&state, &mut errors);
        assert!(errors[0].starts_with("install agent nope: unsupported agent \"nope\""));
        let _ = fs::remove_dir_all(&root);
    }
}
