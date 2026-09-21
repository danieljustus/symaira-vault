//! Go `cmd/mcp/agent_upgrade.go`: `agent upgrade <name> --tier <tier>`.
//!
//! Byte-parity scope: all output goes to stderr (Go uses `cliout.Hintf/Warnf`
//! plus direct `Fprintf(os.Stderr, …)`); stdout stays empty; errors surface
//! doubled as `Error: …` via the dispatch + `finish_vault_result` path
//! (CLI-005, deliberately not fixed here).

use std::io::{BufRead, Write};
use std::path::Path;

use symvault_core::config::{AgentProfile, Config};
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

/// Go `requireBiometricForUpgrade` on a platform without a challenger.
///
/// ponytail: the Rust port has no `authguard` challenger (TouchID prompt),
/// so this is permanently the unavailable-platform branch — byte-identical to
/// Go wherever no biometric hardware answers (all CI runners, headless
/// machines). On a TouchID Mac Go would prompt while the port warns and
/// proceeds; documented divergence, upgrade path: port the challenger.
fn require_biometric_for_upgrade(yes: bool) -> Result<(), String> {
    if yes {
        return Err("biometric verification is required for non-interactive tier upgrades on this platform.\nRe-run with --no-biometric to bypass (not recommended)".to_owned());
    }
    Ok(())
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

/// Go `newAgentUpgradeCmd().RunE`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    vault: &Path,
    args: &[String],
    flags: &UpgradeFlags,
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
        require_biometric_for_upgrade(flags.yes)?;
        // Go's unavailable-platform branch warns and proceeds after
        // interactive confirmation.
        let _ = writeln!(
            stderr,
            "⚠ Biometric verification is not available on this platform."
        );
        let _ = writeln!(
            stderr,
            "   The upgrade will proceed after interactive confirmation."
        );
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
