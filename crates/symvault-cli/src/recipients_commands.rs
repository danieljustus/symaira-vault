//! Recipient mutations reuse the device-pairing encryption boundary.
use std::{io::Write, path::Path};
use symvault_crypto::Identity;
use symvault_sync::{RecipientsFile, recipients::RecipientsError};

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
