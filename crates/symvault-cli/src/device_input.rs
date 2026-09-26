//! Credential input boundary for the bounded pairing CLI.
use serde::Deserialize;
use std::{
    env,
    io::{self, BufRead, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

static PIPE_WARNING_EMITTED: AtomicBool = AtomicBool::new(false);
static QUIET: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub(crate) enum PassphraseInputError {
    Missing,
    Other(String),
}

impl std::fmt::Display for PassphraseInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("read passphrase: EOF"),
            Self::Other(message) => formatter.write_str(message),
        }
    }
}

/// Mirrors Go's `cli.QuietMode`: `--quiet` also suppresses the environment
/// passphrase warning (`WarnEnvPassphrase` returns early under QuietMode).
pub(crate) fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub(crate) fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>, String> {
    read_passphrase_typed(prompt).map_err(|error| error.to_string())
}

fn read_passphrase_typed(prompt: &str) -> Result<Zeroizing<String>, PassphraseInputError> {
    eprint!("{prompt}");
    io::stderr()
        .flush()
        .map_err(|e| PassphraseInputError::Other(format!("prompt: {e}")))?;
    if io::stdin().is_terminal() {
        // Secure input failure must never fall back to an echoing read.
        let line = Zeroizing::new(
            rpassword::read_password()
                .map_err(|e| PassphraseInputError::Other(format!("read passphrase: {e}")))?,
        );
        return Ok(Zeroizing::new(line.trim().to_owned()));
    }
    let label = prompt.trim_end().trim_end_matches(':').trim();
    if !PIPE_WARNING_EMITTED.swap(true, Ordering::Relaxed)
        && env::var("SYMVAULT_NO_PIPE_WARNING")
            .map(|v| v.is_empty() || v == "0")
            .unwrap_or(true)
    {
        eprintln!(
            "Reading {label} from a non-TTY source — the producing process may expose it in 'ps' or audit logs. Prefer 'symvault unlock' or 'symvault auth set touchid'."
        );
    }
    let mut line = Zeroizing::new(String::new());
    if io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| PassphraseInputError::Other(format!("read passphrase: {e}")))?
        == 0
    {
        return Err(PassphraseInputError::Missing);
    }
    Ok(Zeroizing::new(line.trim().to_owned()))
}

#[derive(Default, Deserialize)]
struct UnlockPolicy {
    #[serde(default)]
    security: Option<EnvironmentPolicy>,
}

#[derive(Default, Deserialize)]
struct EnvironmentPolicy {
    #[serde(default)]
    allow_env_passphrase: bool,
    #[serde(default)]
    disable_env_passphrase: bool,
}

pub(crate) fn env_passphrase_selected(bytes: &[u8]) -> bool {
    let Ok(passphrase) = env::var("SYMVAULT_PASSPHRASE").map(Zeroizing::new) else {
        return false;
    };
    if passphrase.is_empty() {
        return false;
    }
    let Ok(policy) = serde_yaml_ng::from_slice::<UnlockPolicy>(bytes) else {
        return false;
    };
    let policy = policy.security.unwrap_or_default();
    if policy.disable_env_passphrase {
        return false;
    }
    policy.allow_env_passphrase
        || matches!(
            env::var("SYMVAULT_ALLOW_ENV_PASSPHRASE").as_deref(),
            Ok("1" | "true" | "yes")
        )
}

pub(crate) fn unlock_passphrase_for_session_typed(
    bytes: &[u8],
) -> Result<Zeroizing<String>, PassphraseInputError> {
    let policy: UnlockPolicy = serde_yaml_ng::from_slice(bytes)
        .map_err(|e| PassphraseInputError::Other(format!("parse unlock policy: {e}")))?;
    let policy = policy.security.unwrap_or_default();
    if let Ok(pass) = std::env::var("SYMVAULT_PASSPHRASE") {
        let pass = Zeroizing::new(pass);
        if !pass.is_empty() {
            let opt_in = std::env::var("SYMVAULT_ALLOW_ENV_PASSPHRASE").unwrap_or_default();
            if policy.disable_env_passphrase
                || !(policy.allow_env_passphrase || matches!(opt_in.as_str(), "1" | "true" | "yes"))
            {
                return Err(PassphraseInputError::Other("environment passphrase is disabled; opt in with security.allow_env_passphrase or SYMVAULT_ALLOW_ENV_PASSPHRASE=1".to_owned()));
            }
            if !QUIET.load(Ordering::Relaxed)
                && !std::env::var("SYMVAULT_NO_ENV_WARNING")
                    .is_ok_and(|value| !value.is_empty() && value != "0")
            {
                eprintln!(
                    "SYMVAULT_PASSPHRASE is active \u{2014} environment passphrases are visible in process listings and crash dumps."
                );
            }
            return Ok(pass);
        }
    }
    read_passphrase_typed("Enter passphrase: ")
}
