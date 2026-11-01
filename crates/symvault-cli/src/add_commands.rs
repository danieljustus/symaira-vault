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
use symvault_store::{Entry, SecretMetadata, SecretType, WriteRecord, infer_secret_type};
use symvault_sync::GoTime;

#[path = "add_form.rs"]
mod add_form;

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
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|error| format!("read {flag}: {error}"))?;
    if line.is_empty() {
        return Err(format!("read {flag}: EOF"));
    }
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
        let result = add_form::run_add_form(options.force, &form_defaults(options))?;
        for (key, value) in &result.data {
            data.insert(key.clone(), value.clone());
        }
        let field = if result.data.contains_key("password") {
            "password"
        } else {
            ""
        }
        .to_owned();
        form = Some(result);
        (String::new(), field, SecretType::Custom)
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
                usage_hint(metadata_type).to_owned()
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

    let record = WriteRecord {
        field,
        action: "add".to_owned(),
        ..WriteRecord::default()
    };
    let entry = Entry {
        data,
        secret_metadata,
        ..Entry::default()
    };
    store
        .write_entry_with_recipients_at(
            &options.path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            Some(&record),
        )
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
            hint = usage_hint(kind).to_owned();
        }
    }
    SecretMetadata {
        secret_type,
        usage_hint: hint,
        auto_rotate: form.auto_rotate || options.auto_rotate,
        ..SecretMetadata::default()
    }
}

/// Go's `warnArgvExposure`: secrets on the command line are visible in process
/// listings, which matters when a person is sitting at the terminal.
fn warn_argv_exposure(options: &AddOptions) {
    if quiet_requested() || !std::io::stdin().is_terminal() {
        return;
    }
    if options
        .value
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        eprintln!(
            "Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input."
        );
    }
    if !options.totp_secret.is_empty() && !STDIN_TOTP_READ.load(Ordering::Relaxed) {
        eprintln!(
            "Warning: --totp-secret is visible in process listings (ps aux). Use --stdin-totp-secret for secure input."
        );
    }
}

/// Reads `--quiet` from the command line: `cliout.Warnf` is silent under
/// `QuietMode`, and the flag is not otherwise visible to this module.
fn quiet_requested() -> bool {
    let mut quiet = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--" => break,
            "--quiet" => quiet = true,
            other => {
                if let Some(value) = other.strip_prefix("--quiet=") {
                    quiet = matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True");
                }
            }
        }
    }
    quiet
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

fn usage_hint(secret_type: SecretType) -> &'static str {
    add_form::usage_hint_for(secret_type)
}
