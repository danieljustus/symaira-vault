#![deny(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sv-list-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join(".symvault")).unwrap();
        Self(path)
    }
    fn run(&self, flags: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_symvault"))
            .env("HOME", &self.0)
            .env("USERPROFILE", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_DATA_HOME", self.0.join("data"))
            .args(["--vault"])
            .arg(&self.0)
            .args(["device", "list"])
            .args(flags)
            .output()
            .unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn missing_registry_is_read_only_and_json_devices_is_an_array() {
    let dir = Scratch::new();
    let output = dir.run(&["--json"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"{\"count\":0,\"devices\":[]}\n");
    assert!(output.stderr.is_empty());
    assert!(!dir.0.join(".symvault/devices.json").exists());
}

#[test]
fn malformed_registry_is_not_hidden_by_quiet() {
    let dir = Scratch::new();
    fs::write(dir.0.join(".symvault/devices.json"), "not json").unwrap();
    let output = dir.run(&["--quiet"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert_eq!(
        fs::read(dir.0.join(".symvault/devices.json")).unwrap(),
        b"not json"
    );
}

#[test]
fn help_is_successful_and_uses_stdout() {
    let dir = Scratch::new();
    let output = dir.run(&["--help"]);
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn populated_listing_preserves_order_last_seen_and_unmanaged_keys() {
    // These rendering rules are also checked against the live pinned Go CLI
    // by device_list_differential.py's registered/text and registered/json.
    let dir = Scratch::new();
    let entries = br#"[{"name":"first","public_key":"managed","added_at":"2026-09-14T12:34:56.123+02:00"},{"name":"second","public_key":"other","added_at":"2026-01-01T00:00:00Z","last_seen":"2026-09-14T10:11:12.9Z"}]"#;
    fs::write(dir.0.join(".symvault/devices.json"), entries).unwrap();
    fs::write(dir.0.join("recipients.txt"), "managed\nother\nunmanaged\n").unwrap();
    let output = dir.run(&["--json"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["count"], 2);
    assert_eq!(value["devices"][0]["name"], "first");
    assert_eq!(value["devices"][0]["added_at"], "2026-09-14T12:34:56+02:00");
    assert!(value["devices"][0].get("last_seen").is_none());
    assert_eq!(value["devices"][1]["last_seen"], "2026-09-14T10:11:12Z");
    assert_eq!(
        value["unmanaged_recipients"],
        serde_json::json!(["unmanaged"])
    );
    let output = dir.run(&[]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("Devices (2):\n\n  first\n"));
    assert!(text.contains("    Last Seen:  never\n\n  second\n"));
    assert!(text.ends_with("Unmanaged recipients in recipients.txt:\n  unmanaged\n\n"));
    assert_eq!(
        fs::read(dir.0.join(".symvault/devices.json")).unwrap(),
        entries
    );
}

#[test]
fn list_preserves_go_byte_truncation_without_unicode_replacement() {
    let dir = Scratch::new();
    fs::write(dir.0.join("recipients.txt"), "123456789012345é-after\n").unwrap();
    let output = dir.run(&[]);
    assert!(output.status.success());
    assert!(output.stdout.ends_with(b"  123456789012345\xc3...\n"));
}

#[test]
fn unimplemented_mutations_cannot_change_registry() {
    let dir = Scratch::new();
    for command in ["pair", "join", "accept", "add", "revoke"] {
        let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
            .arg("--vault")
            .arg(&dir.0)
            .args(["device", command])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "unsafe placeholder exposed: {command}"
        );
        assert!(!dir.0.join("recipients.txt").exists());
        assert!(!dir.0.join(".symvault/devices.json").exists());
    }
}
