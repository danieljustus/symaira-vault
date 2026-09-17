//! Noninteractive `add` entry creation over the shared encrypted store.

use std::{collections::BTreeMap, io::BufRead, path::Path};

use serde_json::Value;
use symvault_core::{password, totp};
use symvault_crypto::Identity;
use symvault_store::{Entry, SecretMetadata, SecretType, Store, WriteRecord, infer_secret_type};
use symvault_sync::GoTime;

/// The explicit, noninteractive portion of Go's `add` command.
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
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    if store
        .entry_exists(&options.path, identity)
        .map_err(|error| error.to_string())?
    {
        return Err(format!(
            "entry {:?} already exists (use 'set' to update or 'edit' to modify)",
            options.path
        ));
    }

    let mut data = BTreeMap::new();
    if !options.username.is_empty() {
        data.insert(
            "username".to_owned(),
            Value::String(options.username.clone()),
        );
    }
    if !options.url.is_empty() {
        data.insert("url".to_owned(), Value::String(options.url.clone()));
    }
    if !options.notes.is_empty() {
        data.insert("notes".to_owned(), Value::String(options.notes.clone()));
    }

    let (value, field, inferred_type) = if let Some(value) = &options.value {
        let inferred = infer_secret_type(&options.path, "", value, nonempty(&options.secret_type));
        let field = primary_field(inferred);
        if value.is_empty() && sensitive_field(&field) && !options.allow_empty {
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
    } else {
        return Err(
            "interactive add form is not implemented; use --value, --stdin-value, or --generate"
                .to_owned(),
        );
    };
    data.insert(field.clone(), Value::String(value));

    if !options.totp_secret.is_empty() {
        totp::validate_totp_secret(&options.totp_secret).map_err(|error| error.to_string())?;
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
    let mut secret_metadata = SecretMetadata {
        secret_type: metadata_type.as_str().to_owned(),
        usage_hint: if options.usage_hint.is_empty() {
            usage_hint(metadata_type).to_owned()
        } else {
            options.usage_hint.clone()
        },
        auto_rotate: options.auto_rotate,
        ..SecretMetadata::default()
    };
    if !options.expires_at.is_empty() {
        if let Ok(parsed) = GoTime::parse_rfc3339(&options.expires_at) {
            secret_metadata.expires_at = Some(parsed.to_rfc3339_nano());
        }
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

fn value_for_type(data: &BTreeMap<String, Value>, field: &str) -> String {
    data.get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn sensitive_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    ["password", "token", "secret", "key", "passwd", "pwd"]
        .iter()
        .any(|part| lower.contains(part))
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
    match secret_type {
        SecretType::ApiKey => {
            "Set as header or query parameter depending on API documentation. Common: X-API-Key: <key> or ?api_key=<key>"
        }
        SecretType::BearerToken => "Set Header Authorization: Bearer <token>",
        SecretType::BasicAuth => {
            "Encode as base64(user:pass) and set Header Authorization: Basic <encoded>"
        }
        SecretType::SshKey => {
            "Write to temporary file with chmod 600 before use. Use with ssh -i <keyfile>"
        }
        SecretType::Password => {
            "Use for authentication. Consider using a password manager or secret injection."
        }
        SecretType::Certificate => {
            "Use with TLS/SSL configuration. May require private key pairing."
        }
        SecretType::DatabaseUrl => "Use as connection string. Ensure credentials are not logged.",
        SecretType::TotpSeed => {
            "Use with TOTP generator. Never share the seed - only share generated codes."
        }
        SecretType::Payment => {
            "Payment card or bank account details. Sensitive fields (card_number, cvc, iban) are redacted by default."
        }
        SecretType::Custom => "Follow the specific integration instructions for this secret.",
    }
}
