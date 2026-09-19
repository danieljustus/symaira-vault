#![deny(unsafe_code)]

// The production module also contains mutation functions whose device
// boundary is private to the CLI binary. These test-only stubs let the list
// and renderer contract run independently until main.rs wires the module.
#[allow(dead_code)]
mod device {
    use std::path::Path;
    use symvault_crypto::{Identity, Recipient};

    pub(crate) fn get_all_recipients_for_encryption(
        _root: &Path,
        _identity: &Identity,
    ) -> Result<Vec<Recipient>, String> {
        unreachable!("recipient list tests do not mutate a vault")
    }

    pub(crate) fn reencrypt_all_entries(
        _root: &Path,
        _identity: &Identity,
        _recipients: &[Recipient],
    ) -> Result<(), String> {
        unreachable!("recipient list tests do not mutate a vault")
    }
}

#[path = "../src/recipients_commands.rs"]
#[allow(dead_code)]
mod recipients_commands;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const RECIPIENT: &str = "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y";

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "symvault-cli-recipients-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn list_preserves_go_order_normalization_and_invalid_details() {
    let root = scratch("list");
    fs::write(
        root.join("recipients.txt"),
        format!("# comment\n  {RECIPIENT}  \ninvalid-key\n"),
    )
    .unwrap();

    let listed = recipients_commands::list(&root).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].normalized, RECIPIENT);
    assert!(listed[0].valid);
    assert!(listed[0].error.is_empty());
    assert_eq!(listed[1].normalized, "");
    assert!(!listed[1].valid);
    assert_eq!(
        listed[1].error,
        "invalid key format: recipient must start with 'age1'"
    );
}

#[test]
fn render_list_matches_go_text_json_yaml_and_empty_contracts() {
    let root = scratch("render");
    fs::write(
        root.join("recipients.txt"),
        format!("{RECIPIENT}\ninvalid-key\n"),
    )
    .unwrap();
    let listed = recipients_commands::list(&root).unwrap();

    let mut text = Vec::new();
    recipients_commands::write_list(&mut text, &listed, "text", false).unwrap();
    assert_eq!(
        String::from_utf8(text).unwrap(),
        format!(
            "Recipients (2):\n\n  ✓ {RECIPIENT}\n  ✗ \n    Error: invalid key format: recipient must start with 'age1'\n"
        )
    );

    let mut json = Vec::new();
    recipients_commands::write_list(&mut json, &listed, "json", false).unwrap();
    assert_eq!(
        String::from_utf8(json).unwrap(),
        format!("{{\"recipients\":[\"{RECIPIENT}\",\"\"]}}\n")
    );

    let mut yaml = Vec::new();
    recipients_commands::write_list(&mut yaml, &listed, "yaml", false).unwrap();
    let yaml = String::from_utf8(yaml).unwrap();
    assert!(yaml.starts_with("recipients:\n"));
    assert!(yaml.contains(RECIPIENT));

    let mut empty = Vec::new();
    recipients_commands::write_list(&mut empty, &[], "text", false).unwrap();
    assert_eq!(
        String::from_utf8(empty).unwrap(),
        "No recipients configured.\nUse 'symvault recipients add <public-key>' to add a recipient.\n"
    );
}

#[test]
fn quiet_list_has_no_output_and_missing_file_is_empty() {
    let root = scratch("quiet");
    let listed = recipients_commands::list(&root).unwrap();
    assert!(listed.is_empty());
    let mut output = Vec::new();
    recipients_commands::write_list(&mut output, &listed, "text", true).unwrap();
    assert!(output.is_empty());
}
