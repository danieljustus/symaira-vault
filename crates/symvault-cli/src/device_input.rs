//! Credential input boundary for the bounded pairing CLI.
use serde::Deserialize;
use std::{
    env,
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

use crate::stdin_input;

static PIPE_WARNING_EMITTED: AtomicBool = AtomicBool::new(false);
static QUIET: AtomicBool = AtomicBool::new(false);
static NO_PIPE_WARNING: AtomicBool = AtomicBool::new(false);

/// Mirrors Go's `cli.QuietMode`: `--quiet` also suppresses the environment
/// passphrase warning (`WarnEnvPassphrase` returns early under QuietMode).
pub(crate) fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Whether `--quiet` is in effect (`cliout.Warnf` prints nothing then).
pub(crate) fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// `--no-pipe-warning`: Go's `cli.NoPipeWarning`, set from the root flag.
pub(crate) fn set_no_pipe_warning(suppress: bool) {
    NO_PIPE_WARNING.store(suppress, Ordering::Relaxed);
}

/// Go's `ReadHiddenInput(prompt, nil)`: a hidden terminal read, or the
/// unbuffered `ReadLineFromStdin` when stdin is piped.
pub(crate) fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>, String> {
    read_hidden(prompt, false)
}

/// Go's `ReadHiddenInput(prompt, reader)` with the `bufio.Reader` over stdin
/// that `set` creates: a piped read goes through the shared buffer.
pub(crate) fn read_passphrase_buffered(prompt: &str) -> Result<Zeroizing<String>, String> {
    read_hidden(prompt, true)
}

fn read_hidden(prompt: &str, buffered: bool) -> Result<Zeroizing<String>, String> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|e| format!("prompt: {e}"))?;
    // Go's `ReadHiddenInput` words its failures `read <label>: <cause>` with the
    // prompt minus its trailing `: `.
    let label = prompt.trim_end().trim_end_matches(':').trim();
    if io::stdin().is_terminal() {
        let read = stdin_input::read_hidden_tty();
        // Go ends the hidden prompt's line on stderr, before it looks at the
        // outcome; the terminal itself never echoes it.
        let _ = writeln!(io::stderr());
        let line = read.map_err(|error| format!("read {label}: {error}"))?;
        return Ok(stdin_input::trim_space(&line));
    }
    // Go's `WarnPipeRead` returns early under `QuietMode` and `--no-pipe-warning`.
    if !QUIET.load(Ordering::Relaxed)
        && !NO_PIPE_WARNING.load(Ordering::Relaxed)
        && !PIPE_WARNING_EMITTED.swap(true, Ordering::Relaxed)
        && env::var("SYMVAULT_NO_PIPE_WARNING")
            .map(|v| v.is_empty() || v == "0")
            .unwrap_or(true)
    {
        eprintln!(
            "Reading {label} from a non-TTY source — the producing process may expose it in 'ps' or audit logs. Prefer 'symvault unlock' or 'symvault auth set touchid'."
        );
    }
    let line = if buffered {
        match stdin_input::read_buffered_line() {
            Ok((line, _)) if line.is_empty() => Err(None),
            Ok((line, _)) => Ok(line),
            Err(error) => Err(Some(error)),
        }
    } else {
        match stdin_input::read_unbuffered_line() {
            Ok(Some(line)) => Ok(line),
            Ok(None) => Err(None),
            Err(error) => Err(Some(error)),
        }
    };
    match line {
        Ok(line) => Ok(stdin_input::trim_space(&line)),
        Err(None) => Err(format!("read {label}: EOF")),
        Err(Some(error)) => Err(format!("read {label}: {error}")),
    }
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

pub(crate) fn unlock_passphrase_for_session(bytes: &[u8]) -> Result<Zeroizing<String>, String> {
    unlock_passphrase_with_mode(bytes, true, false)
}

pub(crate) fn unlock_passphrase_noninteractive(
    bytes: &[u8],
    persistent: bool,
) -> Result<Zeroizing<String>, String> {
    unlock_passphrase_with_mode(bytes, false, persistent)
}

fn unlock_passphrase_with_mode(
    bytes: &[u8],
    interactive: bool,
    persistent: bool,
) -> Result<Zeroizing<String>, String> {
    let policy: UnlockPolicy =
        serde_yaml_ng::from_slice(bytes).map_err(|e| format!("parse unlock policy: {e}"))?;
    let policy = policy.security.unwrap_or_default();
    if let Ok(pass) = std::env::var("SYMVAULT_PASSPHRASE") {
        let pass = Zeroizing::new(pass);
        if !pass.is_empty() {
            let opt_in = std::env::var("SYMVAULT_ALLOW_ENV_PASSPHRASE").unwrap_or_default();
            if policy.disable_env_passphrase
                || !(policy.allow_env_passphrase || matches!(opt_in.as_str(), "1" | "true" | "yes"))
            {
                if !interactive {
                    return Err(
                        "vault locked: SYMVAULT_PASSPHRASE is set but env passphrase unlock is disabled"
                            .to_owned(),
                    );
                }
                // Go warns and falls through to the prompt (`resolveUnlockPassphrase`).
                if !QUIET.load(Ordering::Relaxed) {
                    eprintln!(
                        "SYMVAULT_PASSPHRASE is set but ignored: env passphrase unlock is disabled. Set SYMVAULT_ALLOW_ENV_PASSPHRASE=1 or security.allow_env_passphrase: true in config.yaml to allow it."
                    );
                }
                return read_passphrase("Passphrase: ")
                    .map_err(|error| format!("read passphrase: {error}"));
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
    if !interactive {
        if persistent {
            return Err("vault locked: run 'symvault unlock' first or enable Touch ID with 'symvault auth set touchid' (for headless/CI see security.allow_env_passphrase)".to_owned());
        }
        return Err("vault locked: this build cannot share 'symvault unlock' sessions across processes; use 'symvault unlock', enable Touch ID, or for headless/CI set security.allow_env_passphrase: true / SYMVAULT_ALLOW_ENV_PASSPHRASE=1".to_owned());
    }
    // `resolveUnlockPassphrase` prompts `Passphrase: ` and wraps a failed read.
    read_passphrase("Passphrase: ").map_err(|error| format!("read passphrase: {error}"))
}
