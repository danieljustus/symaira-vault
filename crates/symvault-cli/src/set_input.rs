//! Interactive input of `symvault set`: Go's `readConfirmedFieldValue`
//! (cmd/crud/set.go) and `cli.CollectEntryData` (internal/cli/input).
use std::{
    collections::BTreeMap,
    io::{self, BufRead, IsTerminal, Write},
};

use serde_json::Value;
use symvault_core::password;

use crate::{session_input, write_commands::sensitive_field};

/// A failed interactive read, classified by Go's exit code.
pub(crate) enum InputError {
    /// `ExitInvalidInput` (9) CLIError.
    Invalid(String),
    /// Any other error (exit 1).
    General(String),
}

/// Go's `set` splits `path.field` at the last dot when that dot is not the
/// first byte; the field may be empty (`a.`), which selects the entry-wide
/// prompts.
pub(crate) fn split_query(query: &str) -> (&str, &str) {
    query
        .rsplit_once('.')
        .filter(|(path, _)| !path.is_empty())
        .unwrap_or((query, ""))
}

/// Go's `readConfirmedFieldValue`: a hidden prompt, then, for a non-empty
/// sensitive value, a matching confirmation.
pub(crate) fn read_confirmed_field_value(
    field: &str,
    allow_empty: bool,
) -> Result<String, InputError> {
    let value = session_input::read_passphrase(&format!("Enter value for {field}: "))
        .map_err(|error| InputError::General(format!("read value: {error}")))?;
    if sensitive_field(field) {
        if value.is_empty() && !allow_empty {
            return Err(InputError::Invalid(format!(
                "cannot set empty value for sensitive field {field:?} (use --allow-empty to override)"
            )));
        }
        if !value.is_empty() {
            let confirmation =
                session_input::read_passphrase(&format!("Confirm value for {field}: "))
                    .map_err(|error| InputError::General(format!("read confirmation: {error}")))?;
            if confirmation.is_empty() {
                return Err(InputError::Invalid(
                    "confirmation cannot be empty".to_owned(),
                ));
            }
            if confirmation.as_str() != value.as_str() {
                return Err(InputError::Invalid("values do not match".to_owned()));
            }
        }
    }
    Ok(value.as_str().to_owned())
}

/// One line from stdin, delimiter included; `None` at end of input.
fn read_raw_line() -> Option<String> {
    let mut bytes = Vec::new();
    match io::stdin().lock().read_until(b'\n', &mut bytes) {
        Ok(_) if bytes.is_empty() => None,
        Ok(_) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => None,
    }
}

fn prompt(text: &str) {
    eprint!("{text}");
    let _ = io::stderr().flush();
}

/// Go's `CollectEntryData` as `set` calls it (no flags besides the TOTP secret
/// and `--force`; notes and TOTP details are skipped).
pub(crate) fn collect_entry_data(
    totp_secret: &str,
    force: bool,
) -> Result<BTreeMap<String, Value>, String> {
    let mut data = BTreeMap::new();

    prompt("Username (optional): ");
    let username = read_raw_line().ok_or("read username: EOF")?;
    let username = username.trim();
    if !username.is_empty() {
        data.insert("username".to_owned(), Value::String(username.to_owned()));
    }

    let password = session_input::read_passphrase("Password: ")
        .map_err(|error| format!("read password: {error}"))?;
    if !password.is_empty() {
        data.insert(
            "password".to_owned(),
            Value::String(password.as_str().to_owned()),
        );
        if !force {
            confirm_weak_password(&password)?;
        }
    }

    prompt("URL (optional): ");
    let url = read_raw_line().ok_or("read url: EOF")?;
    let url = url.trim();
    if !url.is_empty() {
        data.insert("url".to_owned(), Value::String(url.to_owned()));
    }

    // The TOTP flags are applied by the caller; with one set Go asks nothing.
    if totp_secret.is_empty() {
        prompt("TOTP Secret (optional): ");
        // `ReadBytes` reports EOF for a final line without a newline too.
        let line = read_raw_line()
            .filter(|line| line.ends_with('\n'))
            .ok_or("read TOTP secret: EOF")?;
        let secret = line.trim();
        if !secret.is_empty() {
            let mut totp = serde_json::Map::new();
            totp.insert("secret".to_owned(), Value::String(secret.to_owned()));
            data.insert("totp".to_owned(), Value::Object(totp));
        }
    }
    Ok(data)
}

/// Go's `confirmWeakPassword`.
fn confirm_weak_password(candidate: &str) -> Result<(), String> {
    let strength = password::assess_password_strength(candidate);
    if !strength.weak {
        return Ok(());
    }
    // Go prints this even under `--quiet`: the command-scoped flag reaches
    // `cliout` only after this warning consults it.
    eprintln!("Warning: {}", strength.message);
    if !io::stdin().is_terminal() {
        return Err(format!(
            "{} — use --force to bypass this check (the entry will be tagged as weak)",
            strength.message
        ));
    }
    prompt("Use this password anyway? (y/N): ");
    let answer = read_raw_line().ok_or("read confirmation: EOF")?;
    if answer.trim().to_lowercase() != "y" {
        return Err("password rejected by user".to_owned());
    }
    Ok(())
}
