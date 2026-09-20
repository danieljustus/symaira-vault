//! Recipient mutations reuse the device-pairing encryption boundary.
use std::{io::Write, path::Path};
use symvault_crypto::Identity;
use symvault_sync::{RecipientsFile, recipients::RecipientsError};

/// One line reported by `recipients list`.
///
/// Invalid lines are retained with an empty normalized value, matching the
/// Go command's `RecipientInfo` JSON projection. The raw line is deliberately
/// not exposed because the command does not print it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedRecipient {
    pub normalized: String,
    pub valid: bool,
    pub error: String,
}

/// Loads and validates every non-comment recipient line in file order.
pub fn list(root: &Path) -> Result<Vec<ListedRecipient>, String> {
    let lines = RecipientsFile::new(root)
        .load_strings()
        .map_err(|error| format!("cannot list recipients: {error}"))?
        .unwrap_or_default();

    Ok(lines
        .into_iter()
        .map(|raw| match validate_for_list(&raw) {
            Ok(normalized) => ListedRecipient {
                normalized,
                valid: true,
                error: String::new(),
            },
            Err(error) => ListedRecipient {
                normalized: String::new(),
                valid: false,
                error,
            },
        })
        .collect())
}

/// Renders the `recipients list` result in the global CLI output format.
pub fn write_list<W: Write>(
    output: &mut W,
    recipients: &[ListedRecipient],
    format: &str,
    quiet: bool,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }

    match format {
        "text" | "" => {
            if recipients.is_empty() {
                writeln!(output, "No recipients configured.")
                    .and_then(|()| {
                        writeln!(
                            output,
                            "Use 'symvault recipients add <public-key>' to add a recipient."
                        )
                    })
                    .map_err(|error| error.to_string())
            } else {
                writeln!(output, "Recipients ({}):", recipients.len())
                    .and_then(|()| writeln!(output))
                    .map_err(|error| error.to_string())?;
                for recipient in recipients {
                    let status = if recipient.valid { '✓' } else { '✗' };
                    writeln!(output, "  {status} {}", recipient.normalized)
                        .map_err(|error| error.to_string())?;
                    if !recipient.valid {
                        writeln!(output, "    Error: {}", recipient.error)
                            .map_err(|error| error.to_string())?;
                    }
                }
                Ok(())
            }
        }
        "json" => {
            let values: Vec<&str> = recipients
                .iter()
                .map(|recipient| recipient.normalized.as_str())
                .collect();
            serde_json::to_writer(&mut *output, &serde_json::json!({ "recipients": values }))
                .map_err(|error| error.to_string())?;
            writeln!(output).map_err(|error| error.to_string())
        }
        "yaml" => {
            let values: Vec<&str> = recipients
                .iter()
                .map(|recipient| recipient.normalized.as_str())
                .collect();
            let rendered = serde_yaml_ng::to_string(&serde_json::json!({ "recipients": values }))
                .map_err(|error| error.to_string())?;
            output
                .write_all(rendered.as_bytes())
                .map_err(|error| error.to_string())
        }
        other => Err(format!(
            "unknown output format: {other:?} (valid: text, json, yaml)"
        )),
    }
}

fn validate_for_list(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("recipient string is empty".to_owned());
    }
    if !raw.starts_with("age1") {
        return Err("invalid key format: recipient must start with 'age1'".to_owned());
    }
    symvault_crypto::parse_recipient(raw)
        .map(|recipient| recipient.to_string())
        .map_err(|_| {
            // The Go validator wraps age parser failures in this stable public
            // category. The Rust crypto boundary intentionally redacts parser
            // internals, so retain the category without inventing secret-bearing
            // detail.
            "invalid key format: invalid recipient".to_owned()
        })
}

pub fn add(
    root: &Path,
    identity: &Identity,
    recipient: &str,
    reencrypt: bool,
    quiet: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    RecipientsFile::new(root)
        .add(recipient)
        .map_err(|error| mutation_error(error, recipient, "add"))?;
    if reencrypt {
        let recipients = crate::device::get_all_recipients_for_encryption(root, identity)
            .map_err(|error| format!("get recipients: {error}"))?;
        if !quiet {
            writeln!(
                output,
                "Recipient added. Re-encrypting all entries for {} recipient(s)...",
                recipients.len()
            )
            .map_err(|e| e.to_string())?;
        }
        crate::device::reencrypt_all_entries(root, identity, &recipients)
            .map_err(|error| format!("re-encrypt entries: {error}"))?;
        if !quiet {
            writeln!(
                output,
                "Recipient added and all entries re-encrypted successfully."
            )
            .map_err(|e| e.to_string())?;
        }
    } else if !quiet {
        writeln!(output, "Recipient added successfully.\nNote: existing entries are not yet shared with this recipient. Run 'symvault recipients add <key> --reencrypt' or 'symvault auth rotate' to re-encrypt existing entries.").map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn remove(
    root: &Path,
    identity: &Identity,
    recipient: &str,
    no_reencrypt: bool,
    quiet: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    // The dispatcher confirms before calling this mutation.
    RecipientsFile::new(root)
        .remove(recipient)
        .map_err(|error| mutation_error(error, recipient, "remove"))?;
    if no_reencrypt {
        if !quiet {
            writeln!(output, "Recipient removed successfully.\nWarning: existing entries are still encrypted to the removed recipient. Run 'symvault auth rotate' to re-encrypt all entries and fully revoke access.").map_err(|e| e.to_string())?;
        }
    } else {
        let recipients = crate::device::get_all_recipients_for_encryption(root, identity)
            .map_err(|error| format!("get remaining recipients: {error}"))?;
        if !quiet {
            writeln!(
                output,
                "Recipient removed. Re-encrypting 0 entries for {} recipient(s)...",
                recipients.len()
            )
            .map_err(|e| e.to_string())?;
        }
        crate::device::reencrypt_all_entries(root, identity, &recipients)
            .map_err(|error| format!("re-encrypt entries: {error}"))?;
        if !quiet {
            writeln!(
                output,
                "Recipient removed and all entries re-encrypted successfully."
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn mutation_error(error: RecipientsError, recipient: &str, action: &str) -> String {
    match error {
        RecipientsError::AlreadyExists => "recipient already exists".to_owned(),
        RecipientsError::Invalid => {
            "invalid recipient: must be a valid age public key starting with 'age1'".to_owned()
        }
        RecipientsError::NotFound => format!("recipient {recipient:?} not found"),
        other => format!("cannot {action} recipient: {other}"),
    }
}
