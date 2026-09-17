//! Credential input boundary for the bounded pairing CLI.
use serde::Deserialize;
use std::{
    env,
    io::{self, BufRead, IsTerminal, Write},
};
use zeroize::Zeroizing;

pub(crate) fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>, String> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|e| format!("prompt: {e}"))?;
    if io::stdin().is_terminal() {
        // Secure input failure must never fall back to an echoing read.
        let line = Zeroizing::new(
            rpassword::read_password().map_err(|e| format!("read passphrase: {e}"))?,
        );
        return Ok(Zeroizing::new(line.trim().to_owned()));
    }
    eprintln!(
        "Warning: reading passphrase from a non-TTY source; the producing process may expose it."
    );
    let mut line = Zeroizing::new(String::new());
    if io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("read passphrase: {e}"))?
        == 0
    {
        return Err("read passphrase: EOF".to_owned());
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

pub(crate) fn unlock_passphrase_for_session(bytes: &[u8]) -> Result<Zeroizing<String>, String> {
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
                return Err("environment passphrase is disabled; opt in with security.allow_env_passphrase or SYMVAULT_ALLOW_ENV_PASSPHRASE=1".to_owned());
            }
            eprintln!(
                "Warning: SYMVAULT_PASSPHRASE is active; environment passphrases may be exposed by process inspection."
            );
            return Ok(pass);
        }
    }
    read_passphrase("Enter passphrase: ")
}
