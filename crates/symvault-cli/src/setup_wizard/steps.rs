//! The wizard screens (`internal/ui/wizard/step_*.go`).
//!
//! Each step keeps the Go step's fields, key handling and validation
//! messages. Steps return a [`StepOutcome`] instead of a bubbletea command;
//! the model acts on it immediately, which is what the Go program does once
//! the `stepDone` message is delivered.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    input::{Key, TextArea, TextInput},
    persist, recipient,
    state::{
        AgentSelection, DEFAULT_PROFILE, MIN_PASSPHRASE_LEN, Passphrase, SYNC_GIT, SYNC_LOCAL,
        WizardState, measure_strength,
    },
    theme,
};
use zeroize::Zeroizing;

const EFF_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

pub(super) enum StepOutcome {
    Stay,
    Done,
    /// The welcome step asked to resume: restored state and target title.
    Resume(Box<WizardState>, String),
}

pub(super) enum Step {
    Welcome(WelcomeStep),
    VaultPath(VaultPathStep),
    Passphrase(PassphraseStep),
    Auth(AuthStep),
    Sync(SyncStep),
    MultiDevice(MultiDeviceStep),
    Recipients(RecipientsStep),
    Agents(AgentsStep),
    Backup,
    Profile(ProfileStep),
    Summary(SummaryStep),
    PairingQr(PairingQrStep),
    NextSteps(NextStepsStep),
}

impl Step {
    pub(super) fn title(&self) -> &'static str {
        match self {
            Self::Welcome(_) => "Welcome",
            Self::VaultPath(_) => "Vault Path",
            Self::Passphrase(_) => "Passphrase",
            Self::Auth(_) => "Auth Method",
            Self::Sync(_) => "Sync Strategy",
            Self::MultiDevice(_) => "Multi-Device",
            Self::Recipients(_) => "Recipients",
            Self::Agents(_) => "AI Agents",
            Self::Backup => "Backup Plan",
            Self::Profile(_) => "Profile Name",
            Self::Summary(_) => "Summary",
            Self::PairingQr(_) => "Device Pairing QR",
            Self::NextSteps(_) => "Done",
        }
    }

    pub(super) fn should_show(&self, state: &WizardState) -> bool {
        match self {
            Self::VaultPath(_) | Self::Passphrase(_) => !state.existing_vault,
            Self::Auth(step) => step.touch_id_available && !state.existing_vault,
            Self::MultiDevice(_) => state.sync_mode == SYNC_GIT,
            Self::Recipients(_) => state.sync_mode == SYNC_GIT && state.multi_device,
            Self::PairingQr(_) => {
                state.multi_device && state.sync_mode == SYNC_GIT && !state.existing_vault
            }
            _ => true,
        }
    }

    /// `Init()`: only the pairing step has side effects.
    pub(super) fn init(&mut self) {
        if let Self::PairingQr(step) = self {
            step.init();
        }
    }

    pub(super) fn update(&mut self, key: &Key) -> StepOutcome {
        match self {
            Self::Welcome(step) => step.update(key),
            Self::VaultPath(step) => step.update(key),
            Self::Passphrase(step) => step.update(key),
            Self::Auth(step) => step.update(key),
            Self::Sync(step) => step.update(key),
            Self::MultiDevice(step) => step.update(key),
            Self::Recipients(step) => step.update(key),
            Self::Agents(step) => step.update(key),
            Self::Backup => {
                if key.as_str() == "enter" {
                    StepOutcome::Done
                } else {
                    StepOutcome::Stay
                }
            }
            Self::Profile(step) => step.update(key),
            Self::Summary(step) => step.update(key),
            Self::PairingQr(step) => step.update(key),
            Self::NextSteps(step) => step.update(key),
        }
    }

    pub(super) fn view(&self) -> String {
        match self {
            Self::Welcome(step) => step.view(),
            Self::VaultPath(step) => step.view(),
            Self::Passphrase(step) => step.view(),
            Self::Auth(step) => step.view(),
            Self::Sync(step) => step.view(),
            Self::MultiDevice(step) => step.view(),
            Self::Recipients(step) => step.view(),
            Self::Agents(step) => step.view(),
            Self::Backup => backup_view(),
            Self::Profile(step) => step.view(),
            Self::Summary(step) => step.view(),
            Self::PairingQr(step) => step.view(),
            Self::NextSteps(step) => step.view(),
        }
    }
}

// ------------------------------------------------------------------ welcome

pub(super) struct WelcomeStep {
    vault_dir: String,
    existing: bool,
    resume_found: bool,
    resume_step: String,
    resume_target: String,
    resume_state: Option<WizardState>,
    resume_age: Duration,
}

impl WelcomeStep {
    pub(super) fn new(vault_dir: &str, no_resume: bool) -> Self {
        let mut step = Self {
            vault_dir: vault_dir.to_owned(),
            existing: is_initialized(vault_dir),
            resume_found: false,
            resume_step: String::new(),
            resume_target: String::new(),
            resume_state: None,
            resume_age: Duration::ZERO,
        };
        if !no_resume {
            step.check_resume();
        }
        step
    }

    fn check_resume(&mut self) {
        let Ok(age) = persist::resume_file_age(&self.vault_dir) else {
            return;
        };
        if age >= persist::RESUME_MAX_AGE {
            return;
        }
        let Ok((state, last_step)) = persist::load_resume_state(&self.vault_dir) else {
            return;
        };
        self.resume_target = if state.existing_vault {
            last_step.clone()
        } else {
            "Passphrase".to_owned()
        };
        self.resume_found = true;
        self.resume_step = last_step;
        self.resume_state = Some(state);
        self.resume_age = age;
    }

    pub(super) fn is_existing_vault(&self) -> bool {
        self.existing
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        if self.resume_found {
            match key.as_str() {
                "y" | "Y" => {
                    if let Some(state) = self.resume_state.clone() {
                        return StepOutcome::Resume(Box::new(state), self.resume_target.clone());
                    }
                }
                "n" | "N" | "enter" | " " => {
                    self.resume_found = false;
                    return StepOutcome::Done;
                }
                _ => {}
            }
        }
        if matches!(key.as_str(), "enter" | " ") {
            return StepOutcome::Done;
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        if self.resume_found {
            let age = format_age(self.resume_age);
            let found = format!(
                "A partially completed setup was found ({} ago, step: {}).",
                theme::dim(&age),
                theme::focused(&self.resume_step)
            );
            let prompt = format!(
                "Resume from {}?  {}  {}",
                theme::focused(&self.resume_step),
                theme::focused("[y]es"),
                theme::dim("[N]o — start fresh (deletes saved progress)")
            );
            let mut body = format!(
                "{}\n\n{found}\n\n{prompt}",
                theme::title("Resume Previous Setup")
            );
            if self
                .resume_state
                .as_ref()
                .is_some_and(|state| !state.existing_vault)
            {
                body.push_str("\n\n");
                body.push_str(&theme::warn("You will need to re-enter your passphrase."));
            }
            return body;
        }
        if self.existing {
            let exists = format!("A vault already exists at {}.", theme::dim(&self.vault_dir));
            let note = format!(
                "This wizard will let you update your sync, MCP agents, and other settings.\n{}",
                theme::warn("Vault passphrase and identity will not be changed.")
            );
            format!(
                "{}\n\n{exists}\n\n{note}",
                theme::title("Re-configuring Symaira Vault")
            )
        } else {
            let press = format!(
                "Press {} to start  {}",
                theme::focused("Enter"),
                theme::dim("Esc to quit")
            );
            format!(
                "{}\n\nThis wizard will guide you through setting up your password vault.\n\n{press}",
                theme::title("Welcome to Symaira Vault")
            )
        }
    }
}

/// `vault.IsInitialized`: both files exist (symlinks followed).
pub(super) fn is_initialized(vault_dir: &str) -> bool {
    let root = Path::new(vault_dir);
    root.join("config.yaml").exists() && root.join("identity.age").exists()
}

fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 60 {
        "just now".to_owned()
    } else if secs < 3600 {
        format!("{} min", secs / 60)
    } else if secs < 24 * 3600 {
        format!("{} hr", secs / 3600)
    } else {
        format!("{} days", secs / 86400)
    }
}

// --------------------------------------------------------------- vault path

pub(super) struct VaultPathStep {
    input: TextInput,
    err: String,
}

impl VaultPathStep {
    pub(super) fn new(default_dir: &str) -> Self {
        let mut input = TextInput::new(&format!("~/{}", ".symvault"), false, 512);
        input.set_value(default_dir);
        input.focus();
        Self {
            input,
            err: String::new(),
        }
    }

    pub(super) fn value(&self) -> String {
        self.input.value().trim().to_owned()
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        if key.as_str() == "enter" {
            if let Err(error) = validate_vault_path(&self.input.value()) {
                self.err = error;
                return StepOutcome::Stay;
            }
            return StepOutcome::Done;
        }
        self.input.update(key);
        self.err.clear();
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        let mut lines = vec![
            theme::title("Vault directory"),
            String::new(),
            "Where should Symaira Vault store your vault?".to_owned(),
            String::new(),
            self.input.view(theme::dim),
        ];
        if self.err.is_empty() {
            lines.extend([String::new(), theme::dim("Enter to confirm")]);
        } else {
            lines.extend([String::new(), theme::error(&format!("✗ {}", self.err))]);
        }
        lines.join("\n")
    }
}

/// `VaultPathStep.validate`.
pub(super) fn validate_vault_path(raw: &str) -> Result<(), String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("vault path must not be empty".to_owned());
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err("invalid path (traversal detected)".to_owned());
    }
    let mut path = PathBuf::from(value);
    if !path.is_absolute() {
        let cwd = std::env::current_dir()
            .map_err(|error| format!("cannot resolve path: {}", errno_text(&error)))?;
        path = crate::agent_list_commands::clean_path(&cwd.join(&path));
    }
    let mut dir = path.clone();
    if let Ok(meta) = fs::metadata(&dir)
        && !meta.is_dir()
    {
        dir = dir.parent().map(Path::to_path_buf).unwrap_or(dir);
    }
    ensure_writable(&dir).map_err(|error| format!("path not writable: {error}"))
}

/// Go `os.MkdirAll(dir, 0o700)` followed by a create/remove probe.
fn ensure_writable(dir: &Path) -> Result<(), String> {
    mkdir_all(dir)?;
    let mut random = [0u8; 4];
    let _ = getrandom::fill(&mut random);
    let name = format!(".symvault-write-test-{}", u32::from_le_bytes(random));
    let probe = dir.join(name);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(&probe);
            Ok(())
        }
        Err(error) => Err(format!("open {}: {}", probe.display(), errno_text(&error))),
    }
}

fn mkdir_all(path: &Path) -> Result<(), String> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => return Err(format!("mkdir {}: not a directory", path.display())),
        Err(_) => {}
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        mkdir_all(parent)?;
    }
    let result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(path)
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(path)
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
                return Ok(());
            }
            Err(format!("mkdir {}: {}", path.display(), errno_text(&error)))
        }
    }
}

/// Go's `syscall.Errno` wording for the errors this step can hit.
pub(super) fn errno_text(error: &std::io::Error) -> String {
    let known = match error.raw_os_error() {
        Some(1) => Some("operation not permitted"),
        Some(2) => Some("no such file or directory"),
        Some(13) => Some("permission denied"),
        Some(17) => Some("file exists"),
        Some(20) => Some("not a directory"),
        Some(21) => Some("is a directory"),
        Some(28) => Some("no space left on device"),
        Some(30) => Some("read-only file system"),
        _ => None,
    };
    match known {
        Some(text) => text.to_owned(),
        None => {
            let text = error.to_string();
            let trimmed = text
                .rsplit_once(" (os error")
                .map_or(text.as_str(), |(head, _)| head);
            let mut chars = trimmed.chars();
            chars
                .next()
                .map(|first| first.to_lowercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        }
    }
}

// ---------------------------------------------------------------- passphrase

pub(super) struct PassphraseStep {
    pass: TextInput,
    confirm: TextInput,
    focused: usize,
    err: String,
    generated_hint: bool,
}

impl PassphraseStep {
    pub(super) fn new() -> Self {
        let mut pass = TextInput::new("min 12 characters", true, 1024);
        pass.focus();
        let confirm = TextInput::new("repeat passphrase", true, 1024);
        Self {
            pass,
            confirm,
            focused: 0,
            err: String::new(),
            generated_hint: false,
        }
    }

    /// The typed passphrase, in a buffer that is wiped on drop.
    pub(super) fn passphrase(&self) -> Zeroizing<Vec<u8>> {
        let text = self.pass.secret_value();
        Zeroizing::new(text.as_bytes().to_vec())
    }

    fn focus_active(&mut self) {
        if self.focused == 0 {
            self.pass.focus();
            self.confirm.blur();
        } else {
            self.pass.blur();
            self.confirm.focus();
        }
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        match key.as_str() {
            "g" => {
                match generate_diceware(6) {
                    Ok(phrase) => {
                        self.pass.set_value(&phrase);
                        self.confirm.set_value(&phrase);
                        self.focused = 1;
                        self.focus_active();
                        self.err.clear();
                        self.generated_hint = true;
                    }
                    Err(error) => self.err = error,
                }
                return StepOutcome::Stay;
            }
            "tab" | "down" | "shift+tab" | "up" => {
                self.focused = (self.focused + 1) % 2;
                self.focus_active();
                self.generated_hint = false;
                return StepOutcome::Stay;
            }
            "enter" => {
                self.generated_hint = false;
                if self.focused == 0 {
                    self.focused = 1;
                    self.focus_active();
                    return StepOutcome::Stay;
                }
                if let Err(error) = self.validate() {
                    self.err = error;
                    return StepOutcome::Stay;
                }
                return StepOutcome::Done;
            }
            _ => {}
        }
        if self.focused == 0 {
            self.pass.update(key);
        } else {
            self.confirm.update(key);
        }
        self.err.clear();
        StepOutcome::Stay
    }

    /// `PassphraseStep.validate`: byte length, then equality.
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_passphrase_pair(&self.pass.secret_value(), &self.confirm.secret_value())
    }

    fn view(&self) -> String {
        let strength = measure_strength(&self.pass.secret_value());
        let strength_line = format!("{}{}", theme::dim("Strength: "), strength_color(strength));
        let mut lines = vec![
            theme::title("Set vault passphrase"),
            String::new(),
            "Passphrase".to_owned(),
            self.pass.view(theme::dim),
            strength_line,
            String::new(),
            "Confirm".to_owned(),
            self.confirm.view(theme::dim),
        ];
        if !self.err.is_empty() {
            lines.extend([String::new(), theme::error(&format!("✗ {}", self.err))]);
        } else if self.generated_hint {
            lines.extend([
                String::new(),
                theme::success("Generated — press Enter twice to confirm"),
            ]);
        } else {
            lines.extend([
                String::new(),
                theme::dim("Tab to switch fields · Enter to confirm · G to generate"),
            ]);
        }
        lines.join("\n")
    }
}

fn strength_color(strength: super::state::PassphraseStrength) -> String {
    use super::state::PassphraseStrength::{Fair, Good, Strong, Weak};
    let bar = strength.bar();
    match strength {
        Strong | Good => theme::success(bar),
        Fair => theme::warn(bar),
        Weak => theme::error(bar),
    }
}

/// The two checks of `PassphraseStep.validate`.
pub(super) fn validate_passphrase_pair(pass: &str, confirm: &str) -> Result<(), String> {
    if pass.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        ));
    }
    if pass != confirm {
        return Err("passphrases do not match".to_owned());
    }
    Ok(())
}

/// `crypto.GenerateDicewarePassphrase`: uniform picks from the 7776-word EFF
/// list, joined by single spaces.
pub(super) fn generate_diceware(word_count: usize) -> Result<Zeroizing<String>, String> {
    if word_count < 1 {
        return Err(format!(
            "diceware: word count must be at least 1, got {word_count}"
        ));
    }
    let words: Vec<&str> = EFF_WORDLIST
        .trim()
        .lines()
        .filter_map(|line| line.trim_end_matches('\r').split_once('\t').map(|(_, w)| w))
        .collect();
    let max = words.len() as u32;
    let limit = u32::MAX - (u32::MAX % max);
    let mut picked = Vec::with_capacity(word_count);
    while picked.len() < word_count {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes)
            .map_err(|error| format!("diceware: failed to generate random index: {error}"))?;
        let value = u32::from_le_bytes(bytes);
        if value >= limit {
            continue;
        }
        picked.push(words[(value % max) as usize]);
    }
    // The joined phrase is the passphrase: wipe it when the caller drops it.
    Ok(Zeroizing::new(picked.join(" ")))
}

// --------------------------------------------------------------------- auth

pub(super) struct AuthStep {
    pub(super) touch_id_available: bool,
    selected: usize,
}

impl AuthStep {
    pub(super) fn new(touch_id_available: bool) -> Self {
        Self {
            touch_id_available,
            selected: 0,
        }
    }

    pub(super) fn selected_method(&self) -> &'static str {
        if self.touch_id_available && self.selected == 0 {
            "touchid"
        } else {
            "passphrase"
        }
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        if !self.touch_id_available {
            return StepOutcome::Done;
        }
        match key.as_str() {
            "up" | "k" | "left" => self.selected = self.selected.saturating_sub(1),
            "down" | "j" | "right" => {
                if self.selected < 1 {
                    self.selected += 1;
                }
            }
            "enter" | " " => return StepOutcome::Done,
            _ => {}
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        if !self.touch_id_available {
            return [
                theme::title("Authentication"),
                String::new(),
                theme::dim("Touch ID not available on this system."),
                "Vault will use passphrase authentication.".to_owned(),
            ]
            .join("\n");
        }
        let mut lines = vec![
            theme::title("Authentication method"),
            String::new(),
            "Touch ID was detected. How should Symaira Vault unlock the vault?".to_owned(),
            String::new(),
        ];
        lines.extend(menu_lines(
            &["Touch ID (recommended)", "Passphrase only"],
            self.selected,
        ));
        lines.extend([String::new(), theme::dim("↑/↓ select · Enter to confirm")]);
        lines.join("\n")
    }
}

fn menu_lines(options: &[&str], selected: usize) -> Vec<String> {
    options
        .iter()
        .enumerate()
        .map(|(index, option)| {
            if index == selected {
                theme::focused(&format!("▸ {option}"))
            } else {
                format!("  {option}")
            }
        })
        .collect()
}

// --------------------------------------------------------------------- sync

pub(super) struct SyncStep {
    mode: usize,
    url_input: TextInput,
    auto_push: bool,
    phase: usize,
    err: String,
}

impl SyncStep {
    pub(super) fn new() -> Self {
        Self {
            mode: 0,
            url_input: TextInput::new("git@github.com:user/vault.git or https://…", false, 512),
            auto_push: true,
            phase: 0,
            err: String::new(),
        }
    }

    pub(super) fn mode(&self) -> &'static str {
        if self.mode == 0 { SYNC_LOCAL } else { SYNC_GIT }
    }

    pub(super) fn remote_url(&self) -> String {
        self.url_input.value().trim().to_owned()
    }

    pub(super) fn auto_push(&self) -> bool {
        self.auto_push
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        match self.phase {
            0 => match key.as_str() {
                "up" | "k" => self.mode = self.mode.saturating_sub(1),
                "down" | "j" => {
                    if self.mode < 1 {
                        self.mode += 1;
                    }
                }
                "enter" | " " => {
                    if self.mode == 0 {
                        return StepOutcome::Done;
                    }
                    self.phase = 1;
                    self.url_input.focus();
                }
                _ => {}
            },
            1 => {
                if key.as_str() == "enter" {
                    let url = self.url_input.value().trim().to_owned();
                    if url.is_empty() || !looks_like_git_url(&url) {
                        self.err = "please enter a valid git URL (https://…, ssh://…, or git@…)"
                            .to_owned();
                        return StepOutcome::Stay;
                    }
                    self.err.clear();
                    self.phase = 2;
                    return StepOutcome::Stay;
                }
                self.url_input.update(key);
                self.err.clear();
            }
            _ => match key.as_str() {
                "y" | "Y" | "enter" => {
                    self.auto_push = true;
                    return StepOutcome::Done;
                }
                "n" | "N" => {
                    self.auto_push = false;
                    return StepOutcome::Done;
                }
                _ => {}
            },
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        match self.phase {
            0 => {
                let mut lines = vec![
                    theme::title("Sync strategy"),
                    String::new(),
                    "How should this vault be synchronized?".to_owned(),
                    String::new(),
                ];
                lines.extend(menu_lines(
                    &[
                        "Local only (no sync)",
                        "Git remote (GitHub, GitLab, self-hosted, …)",
                    ],
                    self.mode,
                ));
                lines.extend([String::new(), theme::dim("↑/↓ select · Enter to confirm")]);
                lines.join("\n")
            }
            1 => {
                let mut lines = vec![
                    theme::title("Git remote URL"),
                    String::new(),
                    self.url_input.view(theme::dim),
                ];
                if self.err.is_empty() {
                    lines.extend([String::new(), theme::dim("Enter to confirm")]);
                } else {
                    lines.extend([String::new(), theme::error(&format!("✗ {}", self.err))]);
                }
                lines.join("\n")
            }
            _ => [
                theme::title("Auto-push on change?"),
                String::new(),
                format!(
                    "Automatically push to {} after each write?",
                    theme::dim(&self.url_input.value())
                ),
                String::new(),
                format!(
                    "{} / {}{}",
                    theme::focused("Y"),
                    theme::dim("N"),
                    theme::dim("  (default: Y)")
                ),
            ]
            .join("\n"),
        }
    }
}

pub(super) fn looks_like_git_url(url: &str) -> bool {
    ["https://", "http://", "ssh://", "git@", "file://"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
}

// ------------------------------------------------------------- multi-device

pub(super) struct MultiDeviceStep {
    selected: usize,
}

impl MultiDeviceStep {
    pub(super) fn new() -> Self {
        Self { selected: 1 }
    }

    pub(super) fn wants_multi_device(&self) -> bool {
        self.selected == 0
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        match key.as_str() {
            "up" | "k" => self.selected = self.selected.saturating_sub(1),
            "down" | "j" => {
                if self.selected < 1 {
                    self.selected += 1;
                }
            }
            "enter" | " " => return StepOutcome::Done,
            _ => {}
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        let mut lines = vec![
            theme::title("Multi-device setup"),
            String::new(),
            "Do you plan to access this vault from another device?".to_owned(),
            String::new(),
        ];
        lines.extend(menu_lines(
            &["Yes — I'll add another device later", "No — single device"],
            self.selected,
        ));
        if self.selected == 0 {
            lines.extend([
                String::new(),
                theme::dim("After setup, run: symvault device pair"),
                theme::dim("On the other device:  symvault device join <url> <token>"),
            ]);
        }
        lines.extend([String::new(), theme::dim("↑/↓ select · Enter to confirm")]);
        lines.join("\n")
    }
}

// --------------------------------------------------------------- recipients

pub(super) struct RecipientsStep {
    input: TextArea,
    err: String,
    line_errors: std::collections::BTreeMap<usize, String>,
}

impl RecipientsStep {
    pub(super) fn new() -> Self {
        Self {
            // Never focused, exactly like Go's `NewRecipientsStep`.
            input: TextArea::new("age1... (one per line)", 60, 5),
            err: String::new(),
            line_errors: std::collections::BTreeMap::new(),
        }
    }

    pub(super) fn recipients(&self) -> Vec<String> {
        self.lines()
    }

    fn lines(&self) -> Vec<String> {
        self.input
            .value()
            .split('\n')
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn input_blank(&self) -> bool {
        self.input.value().trim().is_empty()
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        // `Esc` never reaches this step: the wizard turns it into the cancel
        // confirmation first, so the Go "skip" branch is unreachable.
        let name = key.as_str();
        if (name == "ctrl+s" || name == "enter") && (name == "ctrl+s" || self.input_blank()) {
            if !self.line_errors.is_empty() {
                self.err = "fix invalid recipients before saving".to_owned();
                return StepOutcome::Stay;
            }
            if let Err(error) = self.validate() {
                self.err = error;
                return StepOutcome::Stay;
            }
            return StepOutcome::Done;
        }
        self.input.update(key);
        self.err.clear();
        self.validate_live();
        StepOutcome::Stay
    }

    fn validate_live(&mut self) {
        self.line_errors.clear();
        for (index, line) in self.lines().iter().enumerate() {
            if let Err(error) = recipient::validate_recipient(line) {
                self.line_errors.insert(index, error);
            }
        }
    }

    fn validate(&self) -> Result<(), String> {
        for line in self.lines() {
            recipient::validate_recipient(&line)?;
        }
        Ok(())
    }

    fn view(&self) -> String {
        let mut lines = vec![
            theme::title("Additional recipients"),
            String::new(),
            "Add age public keys of other devices or colleagues who should".to_owned(),
            format!(
                "be able to read this vault. {}",
                theme::warn("Recommended: at least one backup key.")
            ),
            String::new(),
            self.input.view(theme::dim),
        ];
        if !self.err.is_empty() {
            lines.extend([String::new(), theme::error(&format!("✗ {}", self.err))]);
        } else if !self.line_errors.is_empty() {
            lines.push(String::new());
            for (index, line) in self.input.value().split('\n').enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(message) = self.line_errors.get(&index) {
                    lines.push(theme::error(&format!("  ✗ line {}: {message}", index + 1)));
                }
            }
        }
        if self.err.is_empty() && self.line_errors.is_empty() {
            lines.extend([
                String::new(),
                theme::dim("Enter (empty line) or Ctrl+S to save · Esc to skip"),
            ]);
        }
        lines.join("\n")
    }
}

// ------------------------------------------------------------------- agents

/// One entry of `internal/mcp/install`'s agent table.
pub(super) struct AgentDefinition {
    pub(super) agent_type: &'static str,
    pub(super) display_name: &'static str,
    pub(super) config_paths: &'static [&'static str],
    pub(super) binary_names: &'static [&'static str],
}

/// Go iterates a map here, so the order the wizard lists agents in is random
/// per run; the port uses this fixed order.
pub(super) const AGENT_DEFINITIONS: [AgentDefinition; 5] = [
    AgentDefinition {
        agent_type: "openclaw",
        display_name: "OpenClaw",
        config_paths: &["~/.config/openclaw/mcp.json", "~/.openclaw/mcp.json"],
        binary_names: &["openclaw"],
    },
    AgentDefinition {
        agent_type: "claude-code",
        display_name: "Claude Code",
        config_paths: &["~/.claude/settings.json", "~/.claude/settings.local.json"],
        binary_names: &["claude", "claude-code"],
    },
    AgentDefinition {
        agent_type: "hermes",
        display_name: "Hermes",
        config_paths: &[
            "~/.config/hermes/mcp.yaml",
            "~/.hermes/mcp.yaml",
            "~/.config/hermes/mcp.yml",
            "~/.hermes/mcp.yml",
        ],
        binary_names: &["hermes"],
    },
    AgentDefinition {
        agent_type: "codex",
        display_name: "Codex",
        config_paths: &["~/.codex/config.toml"],
        binary_names: &["codex"],
    },
    AgentDefinition {
        agent_type: "opencode",
        display_name: "OpenCode",
        config_paths: &["~/.config/opencode/opencode.json", "opencode.json"],
        binary_names: &["opencode"],
    },
];

/// `install.DetectAgent`: a binary on `PATH` or an existing config file.
fn detect_agent(def: &AgentDefinition) -> bool {
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    let binary_found = std::env::split_paths(&path_env)
        .filter(|dir| !dir.as_os_str().is_empty())
        .any(|dir| {
            def.binary_names
                .iter()
                .any(|name| fs::metadata(dir.join(name)).is_ok_and(|meta| !meta.is_dir()))
        });
    if binary_found {
        return true;
    }
    let home = std::env::var_os("HOME").filter(|value| !value.is_empty());
    def.config_paths.iter().any(|candidate| {
        let expanded = if let Some(rest) = candidate.strip_prefix("~/") {
            match &home {
                Some(home) => Path::new(home).join(rest),
                None => return false,
            }
        } else {
            PathBuf::from(candidate)
        };
        fs::metadata(expanded).is_ok()
    })
}

struct AgentEntry {
    agent_type: &'static str,
    name: &'static str,
    detected: bool,
    selected: bool,
    transport: &'static str,
    scope: &'static str,
    read_only: bool,
}

pub(super) struct AgentsStep {
    entries: Vec<AgentEntry>,
    cursor: usize,
}

impl AgentsStep {
    pub(super) fn new() -> Self {
        let entries = AGENT_DEFINITIONS
            .iter()
            .map(|def| AgentEntry {
                agent_type: def.agent_type,
                name: def.display_name,
                detected: detect_agent(def),
                selected: false,
                transport: "stdio",
                scope: "*",
                read_only: true,
            })
            .collect();
        Self { entries, cursor: 0 }
    }

    pub(super) fn selections(&self) -> Vec<AgentSelection> {
        self.entries
            .iter()
            .filter(|entry| entry.selected)
            .map(|entry| AgentSelection {
                agent_type: entry.agent_type.to_owned(),
                transport: entry.transport.to_owned(),
                scope: entry.scope.to_owned(),
                read_only: entry.read_only,
            })
            .collect()
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        match key.as_str() {
            "up" | "k" => self.cursor = self.cursor.saturating_sub(1),
            "down" | "j" => {
                if self.cursor < self.entries.len() {
                    self.cursor += 1;
                }
            }
            " " => {
                if let Some(entry) = self.entries.get_mut(self.cursor) {
                    entry.selected = !entry.selected;
                }
            }
            "enter" => return StepOutcome::Done,
            _ => {}
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        let mut lines = vec![
            theme::title("AI agent configuration (MCP)"),
            String::new(),
            "Select agents to configure. Detected agents are marked with ✓.".to_owned(),
            String::new(),
        ];
        for (index, entry) in self.entries.iter().enumerate() {
            let cursor = if index == self.cursor {
                theme::focused("▸ ")
            } else {
                "  ".to_owned()
            };
            let check = if entry.selected {
                theme::success("[✓]")
            } else {
                "[ ]".to_owned()
            };
            let detected = if entry.detected {
                theme::dim(" (detected)")
            } else {
                String::new()
            };
            lines.push(format!("{cursor}{check} {}{detected}", entry.name));
        }
        let skip_cursor = if self.cursor == self.entries.len() {
            theme::focused("▸ ")
        } else {
            "  ".to_owned()
        };
        lines.push(format!(
            "{skip_cursor}{}",
            theme::dim("[ ] Skip — configure manually later")
        ));
        lines.extend([
            String::new(),
            theme::dim("↑/↓ navigate · Space to toggle · Enter to confirm"),
        ]);
        lines.join("\n")
    }
}

// ------------------------------------------------------------------- backup

fn backup_view() -> String {
    [
        theme::title("Backup plan"),
        String::new(),
        format!(
            "{} back up your identity file outside this device.",
            theme::warn("Important:")
        ),
        String::new(),
        format!("  {}", theme::dim("~/<vaultDir>/identity.age")),
        String::new(),
        "Without it, the vault is unrecoverable if Touch ID / Keychain fails.".to_owned(),
        "Suggestions: USB drive, encrypted cloud storage, printed paper backup.".to_owned(),
        String::new(),
        "Auto-backup scheduling via launchd can be configured manually later.".to_owned(),
        String::new(),
        theme::dim("Enter to continue"),
    ]
    .join("\n")
}

// ------------------------------------------------------------------ profile

pub(super) struct ProfileStep {
    input: TextInput,
    err: String,
}

impl ProfileStep {
    pub(super) fn new() -> Self {
        let mut input = TextInput::new(DEFAULT_PROFILE, false, 64);
        input.set_value(DEFAULT_PROFILE);
        input.focus();
        Self {
            input,
            err: String::new(),
        }
    }

    pub(super) fn value(&self) -> String {
        self.input.value().trim().to_owned()
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        if key.as_str() == "enter" {
            return match validate_profile_name(&self.input.value()) {
                Ok(()) => StepOutcome::Done,
                Err(error) => {
                    self.err = error;
                    StepOutcome::Stay
                }
            };
        }
        self.input.update(key);
        self.err.clear();
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        let mut lines = vec![
            theme::title("Vault profile name"),
            String::new(),
            format!(
                "Name this vault profile (used with {}).",
                theme::dim("symvault --profile <name>")
            ),
            String::new(),
            self.input.view(theme::dim),
        ];
        if self.err.is_empty() {
            lines.extend([String::new(), theme::dim("Enter to confirm")]);
        } else {
            lines.extend([String::new(), theme::error(&format!("✗ {}", self.err))]);
        }
        lines.join("\n")
    }
}

/// `ProfileStep.Update`'s validation.
pub(super) fn validate_profile_name(raw: &str) -> Result<(), String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("profile name must not be empty".to_owned());
    }
    if name.contains(['/', ' ', '\\']) {
        return Err("profile name must not contain spaces or slashes".to_owned());
    }
    Ok(())
}

// ------------------------------------------------------------------ summary

pub(super) struct SummaryStep {
    /// Go hands the step `&state`, a pointer to the constructor's local
    /// variable, while the model keeps a *copy*. The summary therefore shows
    /// the initial state (default profile, no passphrase, no sync choice)
    /// whatever the user entered. The snapshot reproduces that.
    state: WizardState,
    choice: usize,
}

impl SummaryStep {
    pub(super) fn new(state: &WizardState) -> Self {
        Self {
            state: state.clone(),
            choice: 0,
        }
    }

    /// 0 = apply, 1 = back, 2 = cancel.
    pub(super) fn decision(&self) -> usize {
        self.choice
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        match key.as_str() {
            "up" | "k" => self.choice = self.choice.saturating_sub(1),
            "down" | "j" => {
                if self.choice < 2 {
                    self.choice += 1;
                }
            }
            "enter" | " " => return StepOutcome::Done,
            _ => {}
        }
        StepOutcome::Stay
    }

    fn view(&self) -> String {
        let st = &self.state;
        let row = |label: &str, value: &str| format!("  {:<16} {value}", format!("{label}:"));
        let mut lines = vec![
            theme::title("Summary — review your choices"),
            String::new(),
            row("Vault", &st.vault_dir),
        ];
        if !st.existing_vault {
            let passphrase = Zeroizing::new(
                String::from_utf8_lossy(
                    st.passphrase.as_ref().map_or(&[][..], Passphrase::as_bytes),
                )
                .into_owned(),
            );
            let meter = measure_strength(&passphrase);
            lines.push(row(
                "Passphrase",
                &format!("{} ({})", "*".repeat(12), meter.label()),
            ));
            lines.push(row("Auth", &st.auth_method));
        }
        let sync = if st.sync_mode == SYNC_GIT {
            let push = if st.auto_push { ", auto-push" } else { "" };
            format!("{}{push}", st.git_remote_url)
        } else {
            "local only".to_owned()
        };
        lines.push(row("Sync", &sync));
        if st.recipients.is_empty() {
            lines.push(row("Recipients", &theme::dim("self only")));
        } else {
            lines.push(row(
                "Recipients",
                &format!("self + {} additional", st.recipients.len()),
            ));
        }
        if st.selected_agents.is_empty() {
            lines.push(row("AI Agents", &theme::dim("none")));
        } else {
            let names: Vec<&str> = st
                .selected_agents
                .iter()
                .map(|agent| agent.agent_type.as_str())
                .collect();
            lines.push(row("AI Agents", &names.join(", ")));
        }
        lines.push(row("Profile", &st.profile_name));
        lines.push(String::new());
        for (index, option) in ["Apply", "Go back", "Cancel"].iter().enumerate() {
            let selected = index == self.choice;
            let cursor = if selected { "▸ " } else { "  " };
            let styled = match (index, selected) {
                (2, _) => theme::error(option),
                (_, true) => theme::focused(option),
                (_, false) => (*option).to_owned(),
            };
            lines.push(format!("{cursor}{styled}"));
        }
        lines.extend([String::new(), theme::dim("↑/↓ select · Enter to confirm")]);
        lines.join("\n")
    }
}

// -------------------------------------------------------------- pairing QR

pub(super) struct PairingQrStep {
    state: WizardState,
    token: String,
    saved: bool,
    err_msg: String,
}

impl PairingQrStep {
    pub(super) fn new(state: &WizardState) -> Self {
        Self {
            state: state.clone(),
            token: String::new(),
            saved: false,
            err_msg: String::new(),
        }
    }

    fn init(&mut self) {
        if self.saved {
            return;
        }
        match symvault_sync::pairing::generate_token() {
            Ok(token) => self.token = token,
            Err(error) => {
                self.err_msg = format!("generate token: {error}");
                return;
            }
        }
        if self.state.vault_public_key.is_empty() {
            self.err_msg = "vault public key not available".to_owned();
            return;
        }
        #[derive(serde::Serialize)]
        struct PairingFile<'a> {
            token: &'a str,
            public_key: &'a str,
            created_at: String,
        }
        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let encoded = match serde_json::to_string_pretty(&PairingFile {
            token: &self.token,
            public_key: &self.state.vault_public_key,
            created_at,
        }) {
            Ok(text) => text,
            Err(error) => {
                self.err_msg = format!("marshal pairing data: {error}");
                return;
            }
        };
        let dir = Path::new(&self.state.vault_dir)
            .join(".symvault")
            .join("pairing");
        if let Err(error) = mkdir_all(&dir) {
            self.err_msg = format!("create pairing dir: {error}");
            return;
        }
        let file = dir.join(format!("{}.json", self.token));
        if let Err(error) = write_private(&file, encoded.as_bytes()) {
            self.err_msg = format!(
                "write pairing file: open {}: {}",
                file.display(),
                errno_text(&error)
            );
            return;
        }
        self.saved = true;
    }

    fn update(&mut self, key: &Key) -> StepOutcome {
        if matches!(key.as_str(), "enter" | "q") {
            StepOutcome::Done
        } else {
            StepOutcome::Stay
        }
    }

    fn view(&self) -> String {
        if !self.err_msg.is_empty() {
            return format!(
                "{}\n\n{}\n\n{}",
                theme::title("Device Pairing QR"),
                theme::error(&format!("Error: {}", self.err_msg)),
                theme::dim("Enter to continue"),
            );
        }
        let public_key = &self.state.vault_public_key;
        let qr_data = format!("{}:{public_key}", self.token);
        let art = match render_qr(&qr_data) {
            Ok(art) => art,
            Err(error) => format!("(QR rendering failed: {error} — use the token below)"),
        };
        let truncated = if public_key.len() > 16 {
            format!("{}...", &public_key[..16])
        } else {
            public_key.clone()
        };
        let ttl = theme::dim(&format!(
            "Token expires in {} — five wrong tries trigger a 30-second lockout.",
            format_ttl(Duration::from_secs(5 * 60))
        ));
        [
            theme::title("Device Pairing QR"),
            String::new(),
            "Scan this QR code on your second device, or use the token below:".to_owned(),
            String::new(),
            art,
            String::new(),
            format!("  {:<18} {}", theme::focused("Token:"), self.token),
            format!("  {:<18} {truncated}", theme::dim("Public Key:")),
            ttl,
            String::new(),
            "On the second device, run:".to_owned(),
            String::new(),
            format!(
                "  {}",
                theme::focused(&format!("symvault device add --pair \"{qr_data}\""))
            ),
            String::new(),
            theme::dim("After the second device has joined, run on this device:"),
            format!(
                "  {}",
                theme::focused(&format!("symvault device accept {}", self.token))
            ),
            String::new(),
            theme::dim("Enter or Q to continue"),
        ]
        .join("\n")
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(data)
}

/// `ui.RenderQRCode`: half-block rendering with a four-module quiet zone.
fn render_qr(data: &str) -> Result<String, String> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|error| format!("qr encode: {error}"))?;
    let size = code.width();
    let total = size + 8;
    let dark = |x: usize, y: usize| {
        x >= 4 && y >= 4 && x < size + 4 && y < size + 4 && code[(x - 4, y - 4)] == Color::Dark
    };
    let mut out = String::new();
    for y in (0..total).step_by(2) {
        for x in 0..total {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

/// `formatTTL`.
pub(super) fn format_ttl(duration: Duration) -> String {
    if duration.is_zero() {
        return "expired".to_owned();
    }
    let secs = duration.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let (m, s) = (secs / 60, secs % 60);
    if s == 0 {
        format!("{m}m")
    } else {
        format!("{m}m {s}s")
    }
}

// --------------------------------------------------------------- next steps

pub(super) struct NextStepsStep {
    state: WizardState,
}

impl NextStepsStep {
    pub(super) fn new(state: &WizardState) -> Self {
        Self {
            state: state.clone(),
        }
    }

    /// `Done` here means "quit the program".
    fn update(&mut self, key: &Key) -> StepOutcome {
        if matches!(key.as_str(), "enter" | "q") {
            StepOutcome::Done
        } else {
            StepOutcome::Stay
        }
    }

    fn view(&self) -> String {
        let st = &self.state;
        let command = |name: &str, pad: usize, text: &str| {
            format!("  {}{}{text}", theme::focused(name), " ".repeat(pad))
        };
        let mut lines = vec![
            theme::success("✓ Symaira Vault is ready!"),
            String::new(),
            "Quick-start commands:".to_owned(),
            String::new(),
            command("symvault add <name>", 11, "add your first entry"),
            command("symvault get <name>", 11, "retrieve a password"),
            command("symvault ui", 19, "browse entries in terminal UI"),
            command(
                "symvault get --autotype",
                6,
                "auto-type passwords into forms",
            ),
            command("symvault doctor", 15, "health check"),
            command(
                "symvault agent install <agent>",
                2,
                "configure MCP agent integrations",
            ),
            command("symvault auth set <method>", 4, "change auth method"),
            command("symvault --help", 15, "show all commands"),
        ];
        if st.sync_mode == SYNC_GIT && st.multi_device {
            lines.extend([
                String::new(),
                theme::dim("Pair another device:"),
                format!(
                    "  {} on the other device",
                    theme::focused("symvault device add --pair \"<data>\"")
                ),
                format!(
                    "  {}   to complete pairing",
                    theme::focused("symvault device accept <token>")
                ),
            ]);
        }
        if !st.apply_errors.is_empty() {
            lines.extend([
                String::new(),
                theme::warn("Some steps had issues — run symvault doctor to diagnose."),
            ]);
        }
        lines.extend([String::new(), theme::dim("Enter or Q to exit")]);
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(step: &mut Step, names: &[&str]) -> Vec<bool> {
        names
            .iter()
            .map(|name| matches!(step.update(&Key::new(*name)), StepOutcome::Done))
            .collect()
    }

    #[test]
    fn passphrase_validation_messages_and_order() {
        assert_eq!(
            validate_passphrase_pair("short", "short").unwrap_err(),
            "passphrase must be at least 12 characters"
        );
        assert_eq!(
            validate_passphrase_pair("short and more", "short").unwrap_err(),
            "passphrases do not match"
        );
        assert!(validate_passphrase_pair("exactly12chr", "exactly12chr").is_ok());
        // Length is counted in bytes, as Go's len().
        assert!(validate_passphrase_pair("ääääää", "ääääää").is_ok());
    }

    #[test]
    fn passphrase_step_moves_to_confirm_before_validating() {
        let mut step = Step::Passphrase(PassphraseStep::new());
        for c in "short and more".chars() {
            step.update(&Key::new(c.to_string()));
        }
        assert_eq!(press(&mut step, &["enter"]), [false]);
        for c in "short and more".chars() {
            step.update(&Key::new(c.to_string()));
        }
        assert_eq!(press(&mut step, &["enter"]), [true]);
    }

    #[test]
    fn typing_g_regenerates_the_passphrase() {
        let mut step = PassphraseStep::new();
        step.update(&Key::new("g"));
        let phrase = String::from_utf8(step.passphrase().to_vec()).unwrap();
        assert_eq!(phrase.split(' ').count(), 6);
        assert!(step.validate().is_ok());
    }

    #[test]
    fn diceware_words_come_from_the_eff_list() {
        let phrase = generate_diceware(6).unwrap();
        let words: Vec<&str> = EFF_WORDLIST
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, w)| w))
            .collect();
        assert_eq!(words.len(), 7776);
        for word in phrase.split(' ') {
            assert!(words.contains(&word), "{word}");
        }
        assert!(generate_diceware(0).is_err());
    }

    #[test]
    fn profile_name_rules() {
        assert_eq!(
            validate_profile_name("   ").unwrap_err(),
            "profile name must not be empty"
        );
        for bad in ["a b", "a/b", "a\\b"] {
            assert_eq!(
                validate_profile_name(bad).unwrap_err(),
                "profile name must not contain spaces or slashes"
            );
        }
        assert!(validate_profile_name("  work  ").is_ok());
    }

    #[test]
    fn git_url_prefixes() {
        for ok in [
            "https://x",
            "http://x",
            "ssh://x",
            "git@github.com:a/b.git",
            "file:///tmp/r",
        ] {
            assert!(looks_like_git_url(ok), "{ok}");
        }
        assert!(!looks_like_git_url("github.com/a/b"));
        assert!(!looks_like_git_url("ftp://x"));
    }

    #[test]
    fn vault_path_validation_messages() {
        assert_eq!(
            validate_vault_path("   ").unwrap_err(),
            "vault path must not be empty"
        );
        assert_eq!(
            validate_vault_path("/a/../b").unwrap_err(),
            "invalid path (traversal detected)"
        );
        let dir = std::env::temp_dir().join(format!("symvault-wizard-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(validate_vault_path(&dir.join("nested/vault").to_string_lossy()).is_ok());
        assert!(dir.join("nested/vault").is_dir());
        let leftover: Vec<_> = fs::read_dir(dir.join("nested/vault")).unwrap().collect();
        assert!(leftover.is_empty(), "write probe must be removed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_step_walks_its_three_phases() {
        let mut step = Step::Sync(SyncStep::new());
        assert_eq!(press(&mut step, &["down", "enter"]), [false, false]);
        for c in "nonsense".chars() {
            step.update(&Key::new(c.to_string()));
        }
        assert_eq!(press(&mut step, &["enter"]), [false]);
        if let Step::Sync(sync) = &step {
            assert_eq!(
                sync.err,
                "please enter a valid git URL (https://…, ssh://…, or git@…)"
            );
        }
        for _ in 0..8 {
            step.update(&Key::new("backspace"));
        }
        for c in "https://example.invalid/v.git".chars() {
            step.update(&Key::new(c.to_string()));
        }
        assert_eq!(press(&mut step, &["enter", "n"]), [false, true]);
        if let Step::Sync(sync) = &step {
            assert_eq!(sync.mode(), "git");
            assert!(!sync.auto_push());
            assert_eq!(sync.remote_url(), "https://example.invalid/v.git");
        }
    }

    /// Go's `NewRecipientsStep` never focuses its `textarea`, which then drops
    /// every key: the typed text is lost, the field stays blank and Enter saves
    /// immediately. The port reproduces that (differential scenario
    /// `existing_git_recipients_typed`).
    #[test]
    fn recipients_textarea_is_never_focused_so_typing_is_dropped() {
        let mut step = RecipientsStep::new();
        for c in "age1bad".chars() {
            assert!(matches!(
                step.update(&Key::new(c.to_string())),
                StepOutcome::Stay
            ));
        }
        assert!(step.recipients().is_empty());
        assert!(step.line_errors.is_empty());
        // Blank + Enter finishes with no recipients, and so does Ctrl+S.
        assert!(matches!(step.update(&Key::new("enter")), StepOutcome::Done));
        assert!(matches!(
            step.update(&Key::new("ctrl+s")),
            StepOutcome::Done
        ));
        assert!(step.recipients().is_empty());
    }

    /// With a focused widget (not reachable in the shipped wizard) Enter would
    /// keep editing while the text is non-blank, as in the Go `Update`.
    #[test]
    fn recipients_enter_inserts_a_newline_unless_blank_when_focused() {
        let mut step = RecipientsStep::new();
        step.input.focus();
        for c in "age1bad".chars() {
            step.update(&Key::new(c.to_string()));
        }
        assert!(matches!(step.update(&Key::new("enter")), StepOutcome::Stay));
        assert!(matches!(
            step.update(&Key::new("ctrl+s")),
            StepOutcome::Stay
        ));
        assert_eq!(step.err, "fix invalid recipients before saving");
    }

    #[test]
    fn summary_shows_the_constructor_state_only() {
        let initial = WizardState {
            vault_dir: "/v".into(),
            profile_name: "default".into(),
            ..WizardState::default()
        };
        let step = SummaryStep::new(&initial);
        let text = step.view();
        assert!(text.contains("Passphrase:      ************ (weak)"));
        assert!(text.contains("Sync:            local only"));
        assert!(text.contains("Profile:         default"));
    }

    #[test]
    fn age_formatting() {
        assert_eq!(format_age(Duration::from_secs(5)), "just now");
        assert_eq!(format_age(Duration::from_secs(120)), "2 min");
        assert_eq!(format_age(Duration::from_secs(3 * 3600)), "3 hr");
        assert_eq!(format_age(Duration::from_secs(30 * 3600)), "1 days");
        assert_eq!(format_ttl(Duration::from_secs(300)), "5m");
        assert_eq!(format_ttl(Duration::from_secs(135)), "2m 15s");
        assert_eq!(format_ttl(Duration::from_secs(30)), "30s");
    }
}
