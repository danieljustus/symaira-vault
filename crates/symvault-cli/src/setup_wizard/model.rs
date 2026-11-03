//! The wizard state machine (`internal/ui/wizard/wizard.go`).
//!
//! Terminal-free: keys go in, a view string and a result come out, so the
//! sequencing (step skipping, resume, cancel confirmation, apply) is testable
//! without a PTY. Go's behaviours that look accidental are kept and marked.

use super::{
    apply::{self, Environment, GitOutcome},
    input::Key,
    persist,
    state::{DEFAULT_PROFILE, Passphrase, SYNC_GIT, WizardState},
    steps::{
        AgentsStep, AuthStep, MultiDeviceStep, NextStepsStep, PairingQrStep, PassphraseStep,
        ProfileStep, RecipientsStep, Step, StepOutcome, SummaryStep, SyncStep, VaultPathStep,
        WelcomeStep,
    },
    theme,
};

pub(super) const APPLY_ERRORS_MESSAGE: &str =
    "apply completed with errors — run `symvault doctor` for details";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flow {
    Continue,
    Quit,
}

pub(crate) struct WizardModel {
    steps: Vec<Step>,
    current: usize,
    state: WizardState,
    width: usize,
    quitting: bool,
    pub(crate) canceled: bool,
    confirming_cancel: bool,
    pub(crate) apply_err: Option<String>,
    pub(crate) no_resume: bool,
    total_steps: usize,
    applying: bool,
    apply_step: String,
    apply_errs: Vec<String>,
    spinner_frame: usize,
    next_apply_step: Option<usize>,
    pub(crate) panicked: bool,
    env: Environment,
}

const SPINNER_FRAMES: [&str; 8] = ["⣾ ", "⣽ ", "⣻ ", "⢿ ", "⡿ ", "⣟ ", "⣯ ", "⣷ "];

const APPLY_LABELS: [&str; 6] = [
    "Initializing vault...",
    "Initializing vault...",
    "Configuring git...",
    "Adding recipients...",
    "Saving profile...",
    "Installing MCP agents...",
];

impl WizardModel {
    pub(crate) fn new(
        vault_dir: &str,
        keep_on_error: bool,
        no_resume: bool,
        env: Environment,
    ) -> Self {
        let mut state = WizardState {
            vault_dir: vault_dir.to_owned(),
            profile_name: DEFAULT_PROFILE.to_owned(),
            keep_on_error,
            no_resume,
            ..WizardState::default()
        };
        let welcome = WelcomeStep::new(vault_dir, no_resume);
        state.existing_vault = welcome.is_existing_vault();

        let steps = vec![
            Step::Welcome(welcome),
            Step::VaultPath(VaultPathStep::new(vault_dir)),
            Step::Passphrase(PassphraseStep::new()),
            Step::Auth(AuthStep::new(env.touch_id_available)),
            Step::Sync(SyncStep::new()),
            Step::MultiDevice(MultiDeviceStep::new()),
            Step::Recipients(RecipientsStep::new()),
            Step::Agents(AgentsStep::new()),
            Step::Backup,
            Step::Profile(ProfileStep::new()),
            Step::Summary(SummaryStep::new(&state)),
        ];
        let total_steps = steps.iter().filter(|step| step.should_show(&state)).count();
        Self {
            steps,
            current: 0,
            state,
            width: 0,
            quitting: false,
            canceled: false,
            confirming_cancel: false,
            apply_err: None,
            no_resume,
            total_steps,
            applying: false,
            apply_step: String::new(),
            apply_errs: Vec::new(),
            spinner_frame: 0,
            next_apply_step: None,
            panicked: false,
            env,
        }
    }

    pub(crate) fn set_width(&mut self, width: usize) {
        self.width = width;
    }

    pub(crate) fn handle_key(&mut self, key: &Key) -> Flow {
        if self.confirming_cancel {
            match key.as_str() {
                "y" | "Y" => {
                    self.canceled = true;
                    self.quitting = true;
                    return Flow::Quit;
                }
                "n" | "N" | "esc" => self.confirming_cancel = false,
                _ => {}
            }
            return Flow::Continue;
        }
        match key.as_str() {
            "ctrl+c" => {
                if self.applying {
                    return Flow::Continue;
                }
                self.canceled = true;
                self.quitting = true;
                return Flow::Quit;
            }
            "esc" => {
                if self.applying {
                    return Flow::Continue;
                }
                self.confirming_cancel = true;
                return Flow::Continue;
            }
            _ => {}
        }
        if self.applying || self.current >= self.steps.len() {
            return Flow::Continue;
        }
        match self.steps[self.current].update(key) {
            StepOutcome::Stay => Flow::Continue,
            StepOutcome::Done => self.handle_step_done(),
            StepOutcome::Resume(state, title) => self.resume(*state, &title),
        }
    }

    fn resume(&mut self, state: WizardState, title: &str) -> Flow {
        self.state = state;
        self.state.passphrase = None;
        for index in 0..self.steps.len() {
            if self.steps[index].title() == title && self.steps[index].should_show(&self.state) {
                self.current = index;
                self.steps[index].init();
                return Flow::Continue;
            }
        }
        self.handle_step_done()
    }

    fn handle_step_done(&mut self) -> Flow {
        let index = self.current;
        let title = self.steps[index].title();
        match &self.steps[index] {
            Step::Welcome(step) => self.state.existing_vault = step.is_existing_vault(),
            Step::VaultPath(step) => self.state.vault_dir = step.value(),
            Step::Passphrase(step) => {
                self.state.passphrase = Some(Passphrase::new(step.passphrase()))
            }
            Step::Auth(step) => self.state.auth_method = step.selected_method().to_owned(),
            Step::Sync(step) => {
                self.state.sync_mode = step.mode().to_owned();
                self.state.git_remote_url = step.remote_url();
                self.state.auto_push = step.auto_push();
            }
            Step::MultiDevice(step) => self.state.multi_device = step.wants_multi_device(),
            Step::Recipients(step) => self.state.recipients = step.recipients(),
            Step::Agents(step) => self.state.selected_agents = step.selections(),
            Step::Profile(step) => self.state.profile_name = step.value(),
            Step::Summary(step) => {
                let decision = step.decision();
                return self.handle_summary_step(decision);
            }
            Step::NextSteps(_) => return Flow::Quit,
            Step::Backup | Step::PairingQr(_) => {}
        }
        // Save resume state after each completed step (except the summary).
        if !self.no_resume && !self.state.vault_dir.is_empty() {
            let _ = persist::save_resume_state(&self.state.vault_dir.clone(), &self.state, title);
        }
        self.advance_to_next_visible()
    }

    fn handle_summary_step(&mut self, decision: usize) -> Flow {
        match decision {
            0 => {
                self.applying = true;
                self.apply_step = "Validating...".to_owned();
                self.next_apply_step = Some(0);
                Flow::Continue
            }
            1 => {
                // Go decrements once here and `advanceToPrevVisible` then
                // decrements again before testing visibility, so "Go back"
                // lands two steps back (the profile step is skipped).
                if self.current > 0 {
                    self.current -= 1;
                    self.advance_to_prev_visible();
                }
                Flow::Continue
            }
            2 => {
                self.canceled = true;
                Flow::Quit
            }
            _ => self.advance_to_next_visible(),
        }
    }

    fn advance_to_next_visible(&mut self) -> Flow {
        loop {
            self.current += 1;
            if self.current >= self.steps.len() {
                return Flow::Quit;
            }
            if self.steps[self.current].should_show(&self.state) {
                self.steps[self.current].init();
                return Flow::Continue;
            }
        }
    }

    fn advance_to_prev_visible(&mut self) {
        while self.current > 0 {
            self.current -= 1;
            if self.steps[self.current].should_show(&self.state) {
                return;
            }
        }
    }

    /// Whether the driver should run (and redraw between) apply steps.
    pub(crate) fn apply_pending(&self) -> bool {
        self.next_apply_step.is_some()
    }

    /// Runs one `applyProgressMsg`. The driver redraws between calls.
    pub(crate) fn apply_next(&mut self) -> Flow {
        let Some(step) = self.next_apply_step.take() else {
            return Flow::Continue;
        };
        self.spinner_frame = (self.spinner_frame + 1) % SPINNER_FRAMES.len();
        if step >= APPLY_LABELS.len() {
            return self.apply_finalize();
        }
        self.apply_step = APPLY_LABELS[step].to_owned();

        let result: Result<(), String> = match step {
            0 => apply::pre_flight_check(&self.state),
            1 => {
                if self.state.existing_vault {
                    Ok(())
                } else {
                    apply::apply_vault_init(&mut self.state, &mut self.apply_errs, &self.env)
                }
            }
            2 => match apply::apply_git(&self.state, &mut self.apply_errs) {
                GitOutcome::Done => Ok(()),
                GitOutcome::NilGitConfigPanic => {
                    self.panicked = true;
                    return Flow::Quit;
                }
            },
            3 => {
                apply::apply_recipients(&self.state, &mut self.apply_errs);
                Ok(())
            }
            4 => {
                apply::apply_profile(&self.state, &mut self.apply_errs);
                Ok(())
            }
            _ => {
                apply::apply_agents(&self.state, &mut self.apply_errs);
                Ok(())
            }
        };

        // A pre-flight failure is fatal; a vault-init failure (step 1) is
        // discarded and the remaining steps still run, as in Go.
        if step == 0
            && let Err(error) = result
        {
            self.applying = false;
            self.apply_err = Some(error);
            return Flow::Continue;
        }
        if step == 1 {
            self.state.passphrase = None;
        }
        self.next_apply_step = Some(step + 1);
        Flow::Continue
    }

    fn apply_finalize(&mut self) -> Flow {
        self.state.apply_errors = self.apply_errs.clone();
        if !self.apply_errs.is_empty() && !self.state.keep_on_error && !self.state.existing_vault {
            apply::rollback_init(&self.state);
        }
        if !self.apply_errs.is_empty() {
            self.apply_err = Some(APPLY_ERRORS_MESSAGE.to_owned());
        }
        apply::forget_resume(&self.state);
        if self.state.multi_device && self.state.sync_mode == SYNC_GIT {
            self.steps
                .push(Step::PairingQr(PairingQrStep::new(&self.state)));
        }
        self.steps
            .push(Step::NextSteps(NextStepsStep::new(&self.state)));
        self.applying = false;
        self.advance_to_next_visible()
    }

    fn visible_pos(&self) -> usize {
        self.steps[..self.current]
            .iter()
            .filter(|step| step.should_show(&self.state))
            .count()
    }

    pub(crate) fn view(&self) -> String {
        if self.quitting && self.canceled {
            return "Setup canceled.\n".to_owned();
        }
        if self.current >= self.steps.len() {
            return String::new();
        }
        let sep = "─".repeat(self.width.max(40));
        let footer = theme::dim("Esc to cancel · Ctrl+C to quit");

        if self.applying {
            let header = theme::header(&format!(
                "Symaira Vault Setup  Step {total}/{total} — {}",
                self.apply_step,
                total = self.total_steps
            ));
            let content = format!(
                "  {} {}",
                theme::spinner(SPINNER_FRAMES[self.spinner_frame]),
                self.apply_step
            );
            return [
                header,
                sep.clone(),
                String::new(),
                content,
                String::new(),
                sep,
                footer,
            ]
            .join("\n");
        }
        if self.confirming_cancel {
            let content = format!(
                "{}\n{}",
                theme::warn("Cancel setup? All progress will be lost."),
                theme::dim("y/N")
            );
            return [String::new(), content, String::new(), sep, footer].join("\n");
        }
        let step = &self.steps[self.current];
        let pos = self.visible_pos();
        let header = theme::header(&format!(
            "Symaira Vault Setup  Step {}/{}{} — {}",
            pos + 1,
            self.total_steps,
            progress_bar(pos, self.total_steps),
            step.title()
        ));
        [
            header,
            sep.clone(),
            String::new(),
            step.view(),
            String::new(),
            sep,
            footer,
        ]
        .join("\n")
    }

    /// Text printed after the terminal is restored, when the user cancelled.
    pub(crate) fn pause_notice(&self) -> Option<String> {
        if self.no_resume || self.state.vault_dir.is_empty() {
            return None;
        }
        persist::load_resume_state(&self.state.vault_dir).ok()?;
        Some(
            "\nSetup paused. Resume anytime with `symvault setup`.\nStart fresh instead: `symvault setup --no-resume`.\n"
                .to_owned(),
        )
    }
}

/// `progressBar`.
fn progress_bar(pos: usize, total: usize) -> String {
    if total <= 1 {
        return String::new();
    }
    const WIDTH: usize = 12;
    let filled = (((pos + 1) * WIDTH) / total).min(WIDTH);
    format!(" {}{}", "█".repeat(filled), "░".repeat(WIDTH - filled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use zeroize::Zeroizing;

    fn key(name: &str) -> Key {
        Key::new(name)
    }

    fn type_text(model: &mut WizardModel, text: &str) {
        for c in text.chars() {
            model.handle_key(&Key::new(c.to_string()));
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "symvault-wizard-model-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn title(model: &WizardModel) -> &'static str {
        model.steps[model.current].title()
    }

    #[test]
    fn progress_bar_matches_go() {
        assert_eq!(progress_bar(0, 1), "");
        assert_eq!(progress_bar(0, 9), " █░░░░░░░░░░░");
        assert_eq!(progress_bar(8, 9), " ████████████");
    }

    #[test]
    fn new_vault_flow_skips_auth_without_touch_id_and_hides_git_only_steps() {
        let dir = scratch("flow");
        let vault = dir.join("vault");
        let vault_dir = vault.to_string_lossy().into_owned();
        // `HOME` for the resume file stays untouched by --no-resume.
        let mut model = WizardModel::new(&vault_dir, false, true, Environment::passphrase_only());
        assert_eq!(model.total_steps, 8);
        assert_eq!(title(&model), "Welcome");
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Vault Path");
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Passphrase");
        type_text(&mut model, "correct horse battery staple");
        model.handle_key(&key("enter"));
        type_text(&mut model, "correct horse battery staple");
        model.handle_key(&key("enter"));
        assert_eq!(
            title(&model),
            "Sync Strategy",
            "auth, multi-device, recipients skipped"
        );
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "AI Agents");
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Backup Plan");
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Profile Name");
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Summary");
        assert_eq!(model.state.sync_mode, "local");
        assert_eq!(
            model.state.auth_method, "",
            "skipped auth step never sets a method"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn go_back_from_the_summary_skips_the_profile_step() {
        let dir = scratch("back");
        let vault = dir.join("vault").to_string_lossy().into_owned();
        let mut model = WizardModel::new(&vault, false, true, Environment::passphrase_only());
        model.current = model.steps.len() - 1;
        model.handle_key(&key("down"));
        model.handle_key(&key("enter"));
        assert_eq!(title(&model), "Backup Plan");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn escape_asks_before_cancelling_and_ctrl_c_does_not_while_confirming() {
        let dir = scratch("cancel");
        let vault = dir.join("vault").to_string_lossy().into_owned();
        let mut model = WizardModel::new(&vault, false, true, Environment::passphrase_only());
        model.handle_key(&key("esc"));
        assert!(model.confirming_cancel);
        assert_eq!(model.handle_key(&key("ctrl+c")), Flow::Continue);
        assert_eq!(model.handle_key(&key("x")), Flow::Continue);
        assert!(model.confirming_cancel);
        model.handle_key(&key("n"));
        assert!(!model.confirming_cancel);
        model.handle_key(&key("esc"));
        assert_eq!(model.handle_key(&key("Y")), Flow::Quit);
        assert!(model.canceled);
        assert_eq!(model.view(), "Setup canceled.\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_creates_the_vault_and_a_failed_agent_install_rolls_it_back() {
        let dir = scratch("apply");
        let vault = dir.join("vault");
        let vault_dir = vault.to_string_lossy().into_owned();
        for keep in [false, true] {
            let _ = fs::remove_dir_all(&vault);
            let mut model =
                WizardModel::new(&vault_dir, keep, true, Environment::passphrase_only());
            model.state.passphrase = Some(Passphrase::new(Zeroizing::new(
                b"correct horse battery staple".to_vec(),
            )));
            model.state.selected_agents = vec![crate::setup_wizard::state::AgentSelection {
                agent_type: "codex".into(),
                transport: "stdio".into(),
                scope: "*".into(),
                read_only: true,
            }];
            model.current = model.steps.len() - 1;
            model.applying = true;
            model.next_apply_step = Some(0);
            let mut guard = 0;
            while model.apply_pending() {
                assert_eq!(model.apply_next(), Flow::Continue);
                guard += 1;
                assert!(guard < 20);
            }
            assert_eq!(model.apply_err.as_deref(), Some(APPLY_ERRORS_MESSAGE));
            assert_eq!(model.state.passphrase, None, "wiped after init");
            assert_eq!(vault.join("config.yaml").exists(), keep);
            assert_eq!(vault.join("identity.age").exists(), keep);
            assert_eq!(vault.join("entries").exists(), keep);
            assert!(
                vault.join("mcp-tokens.json").exists(),
                "registry file survives rollback; apply errors: {:?}",
                model.state.apply_errors
            );
            assert_eq!(title(&model), "Done");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fresh_vault_in_git_mode_hits_the_go_nil_config_panic() {
        let dir = scratch("gitpanic");
        let vault = dir.join("vault");
        let vault_dir = vault.to_string_lossy().into_owned();
        let mut model = WizardModel::new(&vault_dir, false, true, Environment::passphrase_only());
        model.state.passphrase = Some(Passphrase::new(Zeroizing::new(
            b"correct horse battery staple".to_vec(),
        )));
        model.state.sync_mode = "git".into();
        model.state.git_remote_url = "https://example.invalid/v.git".into();
        model.current = model.steps.len() - 1;
        model.applying = true;
        model.next_apply_step = Some(0);
        let mut last = Flow::Continue;
        while model.apply_pending() {
            last = model.apply_next();
        }
        assert_eq!(last, Flow::Quit);
        assert!(model.panicked);
        assert!(
            vault.join("config.yaml").exists(),
            "no rollback after the panic"
        );
        assert!(vault.join(".git").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn preflight_failure_stays_on_the_summary_and_the_stale_error_survives() {
        let dir = scratch("preflight");
        let vault = dir.join("vault").to_string_lossy().into_owned();
        let mut model = WizardModel::new(&vault, false, true, Environment::passphrase_only());
        model.current = model.steps.len() - 1;
        model.state.recipients = vec!["age1short".into()];
        model.handle_key(&key("enter"));
        assert!(model.applying);
        model.apply_next();
        assert!(!model.applying);
        assert_eq!(
            model.apply_err.as_deref(),
            Some("invalid recipient key: age1short")
        );
        assert_eq!(title(&model), "Summary");
        let _ = fs::remove_dir_all(&dir);
    }
}
