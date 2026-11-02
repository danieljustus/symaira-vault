//! Noninteractive `add` entry creation over the shared encrypted store.

use std::{
    collections::BTreeMap,
    io::{BufRead, IsTerminal},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use serde_json::Value;
use symvault_core::{password, totp};
use symvault_crypto::Identity;
use symvault_store::{Entry, SecretMetadata, SecretType, infer_secret_type};
use symvault_sync::GoTime;

#[path = "add_form.rs"]
mod add_form;
#[path = "add_form_terminal.rs"]
mod add_form_terminal;

/// Set once `--stdin-totp-secret` has been consumed, so the argv-exposure
/// warning (Go's `warnArgvExposure(.., stdinTOTP)`) can tell the TOTP secret did
/// not come from the command line.
static STDIN_TOTP_READ: AtomicBool = AtomicBool::new(false);

/// The explicit portion of Go's `add` command; the interactive form runs when
/// neither a value source nor `--generate` is given and stdin is a terminal.
#[derive(Debug, Default)]
pub struct AddOptions {
    pub path: String,
    pub value: Option<String>,
    pub generate: bool,
    pub length: i64,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: String,
    pub totp_issuer: String,
    pub totp_account: String,
    pub force: bool,
    pub allow_empty: bool,
    pub secret_type: String,
    pub usage_hint: String,
    pub auto_rotate: bool,
    pub expires_at: String,
}

/// Reads the stdin flags in Go's fixed order and accepts a final line without
/// a trailing newline. The caller supplies `None` for flags that were absent.
pub fn read_stdin_values<R: BufRead>(
    input: &mut R,
    read_value: bool,
    read_totp: bool,
) -> Result<(Option<String>, Option<String>), String> {
    if !read_value && !read_totp {
        return Ok((None, None));
    }
    STDIN_TOTP_READ.store(read_totp, Ordering::Relaxed);
    let value = read_value.then(|| read_line(input, "--stdin-value"));
    let value = match value {
        Some(result) => Some(result?),
        None => None,
    };
    let totp = read_totp.then(|| read_line(input, "--stdin-totp-secret"));
    let totp = match totp {
        Some(result) => Some(result?),
        None => None,
    };
    Ok((value, totp))
}

fn read_line<R: BufRead>(input: &mut R, flag: &str) -> Result<String, String> {
    // Go reads the raw bytes; its JSON encoder later turns each invalid byte
    // into U+FFFD, which `go_string` does here.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    input
        .read_until(b'\n', &mut bytes)
        .map_err(|error| format!("read {flag}: {error}"))?;
    if bytes.is_empty() {
        return Err(format!("read {flag}: EOF"));
    }
    let line = crate::stdin_input::go_string(&bytes);
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Creates one new entry. Existing entries are rejected by path presence,
/// including entries whose ciphertext is damaged and cannot be decrypted.
pub fn add(root: &Path, identity: &Identity, options: &AddOptions) -> Result<(), String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    if store
        .entry_exists(&options.path, identity)
        .map_err(|error| error.to_string())?
    {
        return Err(format!(
            "entry {:?} already exists (use 'set' to update or 'edit' to modify)",
            options.path
        ));
    }

    warn_argv_exposure(options);

    let mut data = BTreeMap::new();
    if !options.username.is_empty() {
        data.insert(
            "username".to_owned(),
            Value::String(options.username.clone()),
        );
    }

    let mut form: Option<add_form::FormResult> = None;
    let (value, field, inferred_type) = if let Some(value) = &options.value {
        let inferred = infer_secret_type(&options.path, "", value, nonempty(&options.secret_type));
        let field = primary_field(inferred);
        if value.is_empty()
            && crate::write_commands::sensitive_field(&field)
            && !options.allow_empty
        {
            return Err(format!(
                "cannot set empty value for sensitive field {field:?} (use --allow-empty to override)"
            ));
        }
        if !options.force && !value.is_empty() {
            password::validate_password_strength(value)?;
        }
        (value.clone(), field, inferred)
    } else if options.generate {
        if options.length <= 0 {
            return Err("length must be greater than zero".to_owned());
        }
        if options.length > password::MAX_PASSWORD_LENGTH as i64 {
            return Err(format!(
                "length must be at most {}",
                password::MAX_PASSWORD_LENGTH
            ));
        }
        let generated = password::generate_password(options.length as isize, true)
            .map_err(|error| error.to_string())?;
        let inferred = infer_secret_type(
            &options.path,
            "",
            "",
            nonempty(&options.secret_type).or(Some("password")),
        );
        (
            generated.as_str().to_owned(),
            primary_field(inferred),
            inferred,
        )
    } else if std::io::stdin().is_terminal() {
        // Go: `forms.RunAddEntryForm(AddForce, buildFormDefaults())`.
        let result = add_form_terminal::run_add_form(options.force, &form_defaults(options))?;
        for (key, value) in &result.data {
            data.insert(key.clone(), value.clone());
        }
        form = Some(result);
        (String::new(), String::new(), SecretType::Custom)
    } else {
        return Err(
            "interactive add form is not implemented; use --value, --stdin-value, or --generate"
                .to_owned(),
        );
    };
    if form.is_none() {
        data.insert(field.clone(), Value::String(value));
    }

    // Go's `addNonReaderFields`: flags win over form answers.
    if !options.url.is_empty() {
        data.insert("url".to_owned(), Value::String(options.url.clone()));
    }
    if !options.notes.is_empty() {
        data.insert("notes".to_owned(), Value::String(options.notes.clone()));
    }
    if !options.totp_secret.is_empty() {
        let mut totp_data = serde_json::Map::new();
        totp_data.insert(
            "secret".to_owned(),
            Value::String(options.totp_secret.clone()),
        );
        if !options.totp_issuer.is_empty() {
            totp_data.insert(
                "issuer".to_owned(),
                Value::String(options.totp_issuer.clone()),
            );
        }
        if !options.totp_account.is_empty() {
            totp_data.insert(
                "account_name".to_owned(),
                Value::String(options.totp_account.clone()),
            );
        }
        data.insert("totp".to_owned(), Value::Object(totp_data));
    }
    // Go's `ValidateTOTPData`.
    if let Some(Value::Object(totp_data)) = data.get("totp")
        && let Some(Value::String(secret)) = totp_data.get("secret")
        && !secret.is_empty()
    {
        totp::validate_totp_secret(secret).map_err(|error| error.to_string())?;
    }

    let mut secret_metadata = if let Some(form) = &form {
        form_secret_metadata(options, form)
    } else {
        let metadata_type = if options.secret_type.is_empty() {
            inferred_type
        } else {
            infer_secret_type(
                &options.path,
                &field,
                &value_for_type(&data, &field),
                nonempty(&options.secret_type),
            )
        };
        SecretMetadata {
            secret_type: metadata_type.as_str().to_owned(),
            usage_hint: if options.usage_hint.is_empty() {
                metadata_type.usage_hint().to_owned()
            } else {
                options.usage_hint.clone()
            },
            auto_rotate: options.auto_rotate,
            ..SecretMetadata::default()
        }
    };
    if !options.expires_at.is_empty()
        && let Ok(parsed) = GoTime::parse_rfc3339(&options.expires_at)
    {
        secret_metadata.expires_at = Some(parsed.to_rfc3339_nano());
    }

    // Go's `add` writes a fresh `Entry{Created, Updated, Version: 1}` without a
    // pending write record: the store bumps the version to 2 and keeps no
    // write history.
    let now = GoTime::now().to_rfc3339_nano();
    let mut entry = Entry {
        data,
        secret_metadata,
        ..Entry::default()
    };
    entry.metadata.created = now.clone();
    entry.metadata.updated = now.clone();
    entry.metadata.version = 1;
    store
        .write_entry_with_recipients_at(&options.path, &entry, identity, &now, None)
        .map_err(|error| format!("cannot create entry: {error}"))?;

    // Go treats auto-commit failure as a warning after the entry is durable.
    crate::write_commands::auto_commit(&store, identity, &options.path, "Add");
    Ok(())
}

/// Go's `buildFormDefaults`.
fn form_defaults(options: &AddOptions) -> add_form::FormDefaults {
    let with_totp = !options.totp_secret.is_empty();
    add_form::FormDefaults {
        username: options.username.clone(),
        url: options.url.clone(),
        notes: options.notes.clone(),
        secret_type: options.secret_type.clone(),
        usage_hint: options.usage_hint.clone(),
        auto_rotate: options.auto_rotate,
        totp_secret: options.totp_secret.clone(),
        totp_issuer: if with_totp {
            options.totp_issuer.clone()
        } else {
            String::new()
        },
        totp_account: if with_totp {
            options.totp_account.clone()
        } else {
            String::new()
        },
    }
}

/// Go's `applySecretMetaFlags` applied to the form's metadata (expiry is added
/// by the caller).
fn form_secret_metadata(options: &AddOptions, form: &add_form::FormResult) -> SecretMetadata {
    let mut secret_type = form.secret_type.clone();
    if secret_type.is_empty() && !options.secret_type.is_empty() {
        secret_type = add_form::secret_type_from_string(&options.secret_type)
            .as_str()
            .to_owned();
    }
    let mut hint = form.usage_hint.clone();
    if hint.is_empty() {
        if !options.usage_hint.is_empty() {
            hint = options.usage_hint.clone();
        } else if let Some(kind) = SecretType::from_name(&secret_type) {
            hint = kind.usage_hint().to_owned();
        }
    }
    SecretMetadata {
        secret_type,
        usage_hint: hint,
        auto_rotate: form.auto_rotate || options.auto_rotate,
        ..SecretMetadata::default()
    }
}

/// Go's `warnArgvExposure` for `add`.
fn warn_argv_exposure(options: &AddOptions) {
    warn_argv_exposure_values(
        options.value.as_deref().unwrap_or_default(),
        &options.totp_secret,
        STDIN_TOTP_READ.load(Ordering::Relaxed),
    );
}

/// Go's `warnArgvExposure(value, totpSecret, stdinTOTP)`: secrets on the
/// command line are visible in process listings, which matters when a person is
/// sitting at the terminal. Shared by `add` and `set`.
pub(crate) fn warn_argv_exposure_values(value: &str, totp_secret: &str, stdin_totp: bool) {
    // Go prints these even under `--quiet` (observed with the oracle: the
    // command-scoped quiet flag is applied after `cliout.Warnf` consults it).
    if !std::io::stdin().is_terminal() {
        return;
    }
    if !value.is_empty() {
        eprintln!(
            "Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input."
        );
    }
    if !totp_secret.is_empty() && !stdin_totp {
        eprintln!(
            "Warning: --totp-secret is visible in process listings (ps aux). Use --stdin-totp-secret for secure input."
        );
    }
}

fn value_for_type(data: &BTreeMap<String, Value>, field: &str) -> String {
    data.get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn primary_field(secret_type: SecretType) -> String {
    match secret_type {
        SecretType::ApiKey => "api_key",
        SecretType::BearerToken => "token",
        SecretType::BasicAuth => "basic_auth",
        SecretType::SshKey => "private_key",
        SecretType::Certificate => "cert_pem",
        SecretType::DatabaseUrl => "connection_string",
        SecretType::TotpSeed => "seed",
        SecretType::Payment => "card_number",
        SecretType::Password | SecretType::Custom => "password",
    }
    .to_owned()
}
