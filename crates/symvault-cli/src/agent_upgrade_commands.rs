//! Go `cmd/mcp/agent_upgrade.go`: `agent upgrade <name> --tier <tier>`.
//!
//! Byte-parity scope: all output goes to stderr (Go uses `cliout.Hintf/Warnf`
//! plus direct `Fprintf(os.Stderr, …)`); stdout stays empty; errors surface
//! doubled as `Error: …` via the dispatch + `finish_vault_result` path
//! (CLI-005, deliberately not fixed here).

use std::io::{BufRead, Write};
use std::path::Path;

use symvault_core::config::{AgentProfile, Config};
use symvault_mcp::authguard::{Challenger, OperationType};
use symvault_store::token_registry::{self, NewToken};
use time::OffsetDateTime;

use super::agent_install_commands::{map_scoped_token_error, write_agent_token_file};

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

/// Mirrors the `agent upgrade` flag set.
pub(crate) struct UpgradeFlags {
    pub(crate) tier: String,
    pub(crate) dry_run: bool,
    pub(crate) yes: bool,
    pub(crate) reason: String,
    pub(crate) rotate_token: bool,
    pub(crate) no_biometric: bool,
}

// ---------------------------------------------------------------------------
// Tier diff.
// ---------------------------------------------------------------------------

/// Go `tierDiff`.
struct TierDiff {
    field: &'static str,
    old_value: String,
    new_value: String,
    changed: bool,
}

fn bool_str(value: bool) -> String {
    value.to_string()
}

/// Go `computeTierDiff`. The Rust profile carries plain `bool`/`i64` where Go
/// holds `*bool`/`*int`; absent there means `false`/`0`, exactly what the
/// defaults here already are, so the observable diffs agree.
fn compute_tier_diff(old: &AgentProfile, new: &AgentProfile) -> Vec<TierDiff> {
    let mut diffs = vec![
        ("canWrite", old.can_write, new.can_write),
        ("canRunCommands", old.can_run_commands, new.can_run_commands),
        (
            "canManageConfig",
            old.can_manage_config,
            new.can_manage_config,
        ),
        (
            "canUseClipboard",
            old.can_use_clipboard,
            new.can_use_clipboard,
        ),
        ("canUseAutotype", old.can_use_autotype, new.can_use_autotype),
        ("canReadValues", old.can_read_values, new.can_read_values),
        (
            "exposeValueTools",
            old.expose_value_tools,
            new.expose_value_tools,
        ),
        ("autoUnseal", old.auto_unseal, new.auto_unseal),
        (
            "requireApproval",
            old.require_approval,
            new.require_approval,
        ),
    ]
    .into_iter()
    .map(|(field, old_value, new_value)| TierDiff {
        field,
        old_value: bool_str(old_value),
        new_value: bool_str(new_value),
        changed: old_value != new_value,
    })
    .collect::<Vec<_>>();
    diffs.push(TierDiff {
        field: "approvalMode",
        old_value: old.approval_mode.clone().unwrap_or_default(),
        new_value: new.approval_mode.clone().unwrap_or_default(),
        changed: old.approval_mode != new.approval_mode,
    });

    let join_or = |values: &[String], empty: &str| {
        if values.is_empty() {
            empty.to_owned()
        } else {
            values.join(", ")
        }
    };
    let old_exec = join_or(&old.allowed_executables, "(none)");
    let new_exec = join_or(&new.allowed_executables, "(none)");
    diffs.push(TierDiff {
        field: "allowedExecutables",
        old_value: old_exec.clone(),
        new_value: new_exec.clone(),
        changed: old_exec != new_exec,
    });
    let old_tools = join_or(&old.allowed_tools, "(all)");
    let new_tools = join_or(&new.allowed_tools, "(all)");
    diffs.push(TierDiff {
        field: "allowedTools",
        old_value: old_tools.clone(),
        new_value: new_tools.clone(),
        changed: old_tools != new_tools,
    });
    for (field, old_value, new_value) in [
        (
            "maxReadsPerHour",
            old.max_reads_per_hour,
            new.max_reads_per_hour,
        ),
        (
            "maxReadsPerDay",
            old.max_reads_per_day,
            new.max_reads_per_day,
        ),
        (
            "maxSecretsInSession",
            old.max_secrets_in_session,
            new.max_secrets_in_session,
        ),
    ] {
        if old_value != new_value {
            diffs.push(TierDiff {
                field,
                old_value: old_value.to_string(),
                new_value: new_value.to_string(),
                changed: true,
            });
        }
    }
    diffs
}

/// Go `printTierDiff` (stderr). Field names are ASCII, so Rust's char-width
/// padding matches Go's.
fn print_tier_diff(stderr: &mut dyn Write, diffs: &[TierDiff]) {
    let _ = writeln!(
        stderr,
        "  FIELD                    CURRENT                  NEW"
    );
    let _ = writeln!(stderr, "  {}", "-".repeat(72));
    for diff in diffs {
        if diff.changed {
            let _ = writeln!(
                stderr,
                "  ✓ {:<22} {:<24} {}",
                diff.field, diff.old_value, diff.new_value
            );
        } else {
            let _ = writeln!(
                stderr,
                "  {:<23} {:<24} {} (unchanged)",
                diff.field, diff.old_value, diff.new_value
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Biometric gate and confirmation.
// ---------------------------------------------------------------------------

/// Go `requireBiometricForUpgrade`.
///
/// Without an available authenticator (every CI runner and headless machine,
/// and the gated production default) `--yes` fails and the interactive path
/// warns and continues. With one, the user is challenged and any failure maps
/// to Go's `biometric verification required for tier upgrade: <challenge
/// error>` (`authguard.Challenge` + the darwin `errTouchID*` texts).
fn require_biometric_for_upgrade(
    challenger: &Challenger,
    agent_name: &str,
    target_tier: &str,
    yes: bool,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    if !challenger.available() {
        if yes {
            return Err("biometric verification is required for non-interactive tier upgrades on this platform.\nRe-run with --no-biometric to bypass (not recommended)".to_owned());
        }
        let _ = writeln!(
            stderr,
            "⚠ Biometric verification is not available on this platform."
        );
        let _ = writeln!(
            stderr,
            "   The upgrade will proceed after interactive confirmation."
        );
        return Ok(());
    }
    let reason = format!(
        "Upgrade Symaira Vault agent {} to {} tier",
        symvault_core::go_quote(agent_name),
        symvault_core::go_quote(target_tier)
    );
    challenger
        .challenge(&OperationType::TIER_UPGRADE, &reason)
        .map_err(|error| format!("biometric verification required for tier upgrade: {error}"))
}

/// Go `confirmUpgrade`: piped stdin is never a terminal, so tests and scripts
/// always land on "Upgrade canceled.".
fn confirm_upgrade(
    agent_name: &str,
    target_tier: &str,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> bool {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return false;
    }
    let _ = write!(
        stderr,
        "Upgrade agent {agent_name:?} from current tier to {target_tier:?}? [y/N] "
    );
    let _ = stderr.flush();
    let mut reply = String::new();
    let _ = stdin.read_line(&mut reply);
    let reply = reply.trim().to_lowercase();
    reply == "y" || reply == "yes"
}

// ---------------------------------------------------------------------------
// Command.
// ---------------------------------------------------------------------------

/// Go `newAgentUpgradeCmd().RunE` with the production (gated) challenger.
pub(crate) fn run(
    vault: &Path,
    args: &[String],
    flags: &UpgradeFlags,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    run_with_challenger(
        vault,
        args,
        flags,
        &crate::authguard::default_challenger(),
        stdin,
        stderr,
    )
}

/// `run` over an injected challenger; tests use a fake so no Touch ID prompt
/// can ever appear.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_challenger(
    vault: &Path,
    args: &[String],
    flags: &UpgradeFlags,
    challenger: &Challenger,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    if args.len() != 1 {
        return Err(format!("accepts 1 arg(s), received {}", args.len()));
    }
    let agent_name = &args[0];
    if flags.tier.is_empty() {
        return Err("--tier is required (valid: safe, standard, admin)".to_owned());
    }
    if flags.yes && flags.reason.is_empty() {
        return Err("--reason is required when using --yes".to_owned());
    }
    if !matches!(
        flags.tier.as_str(),
        "safe" | "read-only" | "standard" | "admin"
    ) {
        return Err(format!(
            "invalid tier {:?}: valid values are safe, standard, admin",
            flags.tier
        ));
    }
    // Go's `agentUpgradeTierAlias`: "safe" is a synonym for "read-only".
    let target_tier = if flags.tier == "safe" {
        "read-only"
    } else {
        flags.tier.as_str()
    };

    let config_path = vault.join("config.yaml");
    let mut cfg = Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
    let Some(mut profile) = cfg.agents.get(agent_name).cloned() else {
        return Err(format!("agent {agent_name:?} not found in config"));
    };
    let mut current_tier = profile.tier.clone().unwrap_or_default();
    if current_tier.is_empty() {
        current_tier = "custom".to_owned();
    }
    if current_tier == target_tier {
        return Err(format!(
            "agent {agent_name:?} is already at tier {target_tier:?}"
        ));
    }

    let old_profile = profile.clone();
    symvault_core::config::apply_tier_preset_to_profile(&mut profile, target_tier);
    profile.tier = Some(target_tier.to_owned());
    let diffs = compute_tier_diff(&old_profile, &profile);

    let _ = writeln!(stderr, "Agent:   {agent_name}");
    let _ = writeln!(stderr, "Current: {current_tier}");
    let _ = writeln!(stderr, "Target:  {target_tier}");
    if !flags.reason.is_empty() {
        let _ = writeln!(stderr, "Reason:  {}", flags.reason);
    }
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "Tier changes:");
    print_tier_diff(stderr, &diffs);
    let _ = writeln!(stderr);

    if flags.dry_run {
        let _ = writeln!(stderr, "[DRY-RUN] No changes written.");
        return Ok(());
    }

    if !flags.no_biometric {
        require_biometric_for_upgrade(challenger, agent_name, target_tier, flags.yes, stderr)?;
    }

    if !flags.yes && !confirm_upgrade(agent_name, target_tier, stdin, stderr) {
        let _ = writeln!(stderr, "Upgrade canceled.");
        return Ok(());
    }

    cfg.agents.insert(agent_name.clone(), profile.clone());
    cfg.save_to(&config_path)
        .map_err(|error| format!("save config: {error}"))?;
    let _ = writeln!(
        stderr,
        "✓ Profile for {agent_name:?} upgraded to {target_tier:?}"
    );

    if flags.rotate_token {
        let outcome =
            token_registry::revoke_all_for_agent(vault, agent_name, OffsetDateTime::now_utc())
                .map_err(|error| map_scoped_token_error(&error, "create token: "))?;
        if let Some(error) = outcome.save_error {
            return Err(format!("save token registry: {error}"));
        }
        let request = NewToken {
            label: &format!("upgrade-{agent_name}-{target_tier}"),
            allowed_tools: vec!["*".to_owned()],
            agent_name,
            ttl: None,
            tool_registry_hash: super::agent_install_commands::PINNED_TOOL_REGISTRY_HASH,
        };
        let (record, raw_token) =
            token_registry::create(vault, &request, OffsetDateTime::now_utc()).map_err(
                |error| {
                    // Go's `Create` is in-memory (only randomness can fail it), so
                    // a write failure here surfaces where Go's `Save` would: as
                    // `save token registry: …`; anything else keeps the
                    // `create token for …` stage.
                    match &error {
                        symvault_store::StoreError::Write { .. } => {
                            format!("save token registry: {error}")
                        }
                        _ => format!("create token for {agent_name:?}: {error}"),
                    }
                },
            )?;
        let token_path = write_agent_token_file(vault, agent_name, &raw_token)
            .map_err(|error| format!("write token file: {error}"))?;
        let _ = writeln!(stderr, "✓ Token rotated: {token_path} (id={})", record.id);
    }

    let skill_path = profile.skill_path.clone();
    if !skill_path.is_empty() {
        let expanded = super::agent_skill_commands::require_tilde_expansion(&skill_path);
        match super::agent_skill_commands::refresh_target_with_tier(
            vault,
            agent_name,
            &expanded,
            target_tier,
        ) {
            Ok(_) => {
                let _ = writeln!(stderr, "✓ Skill refreshed at {expanded}");
            }
            Err(error) => {
                let _ = writeln!(stderr, "⚠ Skill refresh: {error}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use symvault_core::platform::{PlatformError, PlatformErrorKind, TouchId};

    /// Never a real prompt: the decision, availability and the reason text the
    /// system dialog would have shown are all scripted.
    struct FakeTouchId {
        available: bool,
        outcome: Result<(), PlatformErrorKind>,
        prompts: AtomicUsize,
        reasons: Mutex<Vec<String>>,
    }

    impl FakeTouchId {
        fn new(available: bool, outcome: Result<(), PlatformErrorKind>) -> Arc<Self> {
            Arc::new(Self {
                available,
                outcome,
                prompts: AtomicUsize::new(0),
                reasons: Mutex::new(Vec::new()),
            })
        }
    }

    impl TouchId for FakeTouchId {
        fn is_available(&self) -> bool {
            self.available
        }
        fn authenticate(&self, reason: &str, _: Duration) -> Result<(), PlatformError> {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            self.reasons.lock().unwrap().push(reason.to_owned());
            self.outcome.map_err(|kind| PlatformError {
                kind,
                message: "adapter detail must not reach the user".into(),
            })
        }
    }

    use std::sync::Arc;
    use std::time::Duration;

    fn seeded_vault() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp vault");
        std::fs::write(
            dir.path().join("config.yaml"),
            "defaultAgent: hermes\nagents:\n  hermes:\n    tier: standard\n",
        )
        .expect("seed config");
        dir
    }

    fn flags(yes: bool, no_biometric: bool) -> UpgradeFlags {
        UpgradeFlags {
            tier: "admin".into(),
            dry_run: false,
            yes,
            reason: if yes {
                "unit test".into()
            } else {
                String::new()
            },
            rotate_token: false,
            no_biometric,
        }
    }

    fn upgrade(
        dir: &tempfile::TempDir,
        fake: &Arc<FakeTouchId>,
        flags: &UpgradeFlags,
    ) -> (Result<(), String>, String) {
        let mut stderr = Vec::new();
        let result = run_with_challenger(
            dir.path(),
            &["hermes".to_owned()],
            flags,
            &Challenger::new(fake.clone()),
            &mut std::io::empty(),
            &mut stderr,
        );
        (result, String::from_utf8(stderr).expect("utf-8 stderr"))
    }

    fn tier_on_disk(dir: &tempfile::TempDir) -> String {
        Config::load(dir.path().join("config.yaml"))
            .expect("config loads")
            .agents["hermes"]
            .tier
            .clone()
            .unwrap_or_default()
    }

    #[test]
    fn approved_challenge_upgrades_with_go_reason_text() {
        let dir = seeded_vault();
        let fake = FakeTouchId::new(true, Ok(()));
        let (result, stderr) = upgrade(&dir, &fake, &flags(true, false));
        assert_eq!(result, Ok(()));
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *fake.reasons.lock().unwrap(),
            ["Upgrade Symaira Vault agent \"hermes\" to \"admin\" tier"]
        );
        assert_eq!(tier_on_disk(&dir), "admin");
        assert!(stderr.contains("✓ Profile for \"hermes\" upgraded to \"admin\""));
        assert!(!stderr.contains("Biometric verification is not available"));
    }

    #[test]
    fn rejected_challenge_fails_with_go_chain_and_leaves_config_untouched() {
        for kind in [
            PlatformErrorKind::Canceled,
            PlatformErrorKind::Failed,
            PlatformErrorKind::TimedOut,
        ] {
            let dir = seeded_vault();
            let fake = FakeTouchId::new(true, Err(kind));
            let (result, _) = upgrade(&dir, &fake, &flags(true, false));
            assert_eq!(
                result.unwrap_err(),
                "biometric verification required for tier upgrade: biometric verification for agent tier upgrade failed: touch id authentication failed"
            );
            assert_eq!(fake.prompts.load(Ordering::SeqCst), 1);
            assert_eq!(tier_on_disk(&dir), "standard");
        }
    }

    #[test]
    fn authenticator_lost_between_probe_and_prompt_maps_to_not_available() {
        let dir = seeded_vault();
        let fake = FakeTouchId::new(true, Err(PlatformErrorKind::Unavailable));
        let (result, _) = upgrade(&dir, &fake, &flags(true, false));
        assert_eq!(
            result.unwrap_err(),
            "biometric verification required for tier upgrade: biometric verification for agent tier upgrade failed: touch id not available"
        );
        assert_eq!(tier_on_disk(&dir), "standard");
    }

    #[test]
    fn unavailable_with_yes_keeps_go_non_interactive_error_without_prompting() {
        let dir = seeded_vault();
        let fake = FakeTouchId::new(false, Ok(()));
        let (result, _) = upgrade(&dir, &fake, &flags(true, false));
        assert_eq!(
            result.unwrap_err(),
            "biometric verification is required for non-interactive tier upgrades on this platform.\nRe-run with --no-biometric to bypass (not recommended)"
        );
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 0);
        assert_eq!(tier_on_disk(&dir), "standard");
    }

    #[test]
    fn unavailable_interactive_warns_then_proceeds_to_confirmation() {
        let mut stderr = Vec::new();
        let fake = FakeTouchId::new(false, Ok(()));
        let result = require_biometric_for_upgrade(
            &Challenger::new(fake.clone()),
            "hermes",
            "admin",
            false,
            &mut stderr,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "⚠ Biometric verification is not available on this platform.\n   The upgrade will proceed after interactive confirmation.\n"
        );
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_biometric_flag_skips_the_challenge_entirely() {
        let dir = seeded_vault();
        let fake = FakeTouchId::new(true, Err(PlatformErrorKind::Failed));
        let (result, _) = upgrade(&dir, &fake, &flags(true, true));
        assert_eq!(result, Ok(()));
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 0);
        assert_eq!(tier_on_disk(&dir), "admin");
    }
}
