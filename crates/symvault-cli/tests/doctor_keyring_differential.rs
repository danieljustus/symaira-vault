#![deny(unsafe_code)]

//! DOCTOR-KEYRING-001: `session.cache`, `session.keyring` and
//! `audit.keyring.orphans` must report the real session/keychain state exactly
//! like the Go oracle.
//!
//! The always-on tests run both binaries in the forced in-memory states
//! (`CI`, `HEADLESS`, `SYMVAULT_TEST_KEYRING=memory`) with a cleared
//! environment, so they never reach a keychain. The real-keychain test is
//! opt-in (`SYMVAULT_DOCTOR_REAL_KEYCHAIN=1`, macOS only): it creates and
//! deletes its own disposable items and only *counts* matching entries; it
//! never runs `--fix` against the login keychain.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const IDS: &str = "session.cache,session.keyring,audit.keyring.orphans";

fn oracle_binaries() -> Option<(PathBuf, PathBuf)> {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return None;
    };
    let go = PathBuf::from(go_binary);
    assert!(go.is_file(), "Go binary does not exist at {go:?}");
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    assert!(rust.is_file(), "Rust binary does not exist at {rust:?}");
    Some((go, rust))
}

/// Runs `doctor` with a cleared environment so no ambient `CI`/`SYMVAULT_*`
/// variable decides which branch is exercised.
fn doctor(
    binary: &Path,
    vault: &Path,
    home: &Path,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> Output {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .arg("--vault")
        .arg(vault)
        .arg("doctor")
        .args(args)
        .current_dir(vault);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.output().expect("run CLI")
}

fn results(output: &Output) -> Vec<serde_json::Value> {
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "doctor --json is not JSON ({error}): stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    json["results"].as_array().cloned().unwrap_or_default()
}

/// Text and JSON must be byte-identical for the three ids.
fn compare_text_and_json(
    go: &Path,
    rust: &Path,
    vault: &Path,
    home: &Path,
    env: &[(&str, &str)],
) -> Vec<serde_json::Value> {
    let json_args = ["--json", "--no-network", "--only", IDS];
    let text_args = ["--no-network", "--only", IDS];

    let (go_json, rust_json) = (
        doctor(go, vault, home, env, &json_args),
        doctor(rust, vault, home, env, &json_args),
    );
    assert_eq!(
        go_json.status.code(),
        rust_json.status.code(),
        "json exit code"
    );
    assert_eq!(
        String::from_utf8_lossy(&go_json.stdout),
        String::from_utf8_lossy(&rust_json.stdout),
        "json stdout (env {env:?})"
    );
    let selected = results(&go_json);
    assert_eq!(selected.len(), 3, "all three checks must run: {selected:?}");

    let (go_text, rust_text) = (
        doctor(go, vault, home, env, &text_args),
        doctor(rust, vault, home, env, &text_args),
    );
    assert_eq!(
        go_text.status.code(),
        rust_text.status.code(),
        "text exit code"
    );
    assert_eq!(
        String::from_utf8_lossy(&go_text.stdout),
        String::from_utf8_lossy(&rust_text.stdout),
        "text stdout (env {env:?})"
    );
    assert_eq!(
        String::from_utf8_lossy(&go_text.stderr),
        String::from_utf8_lossy(&rust_text.stderr),
        "text stderr (env {env:?})"
    );
    selected
}

fn find<'a>(items: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    items
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("missing {id} in {items:?}"))
}

#[test]
fn differential_doctor_keyring_checks_in_forced_memory_states() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = test_temp_root::TempRoot::existing("symvault-doctor-keyring-home-");
    let vault = test_temp_root::TempRoot::existing("symvault-doctor-keyring-vault-");

    for forced in [
        ("CI", "1"),
        ("GITHUB_ACTIONS", "true"),
        ("HEADLESS", "1"),
        ("SYMVAULT_TEST_KEYRING", "memory"),
    ] {
        let items = compare_text_and_json(&go, &rust, &vault, &home, &[forced]);
        let cache = find(&items, "session.cache");
        assert_eq!(cache["status"], "warn", "{forced:?}");
        assert_eq!(
            cache["message"],
            "session cache uses in-memory backend (not persistent)"
        );
        let keyring = find(&items, "session.keyring");
        assert_eq!(keyring["status"], "warn", "{forced:?}");
        assert_eq!(
            keyring["message"],
            "OS keyring persistence not verified in test/CI environment (in-memory backend active)"
        );
        let orphans = find(&items, "audit.keyring.orphans");
        assert_eq!(orphans["status"], "ok", "{forced:?}");
    }
}

#[cfg(target_os = "macos")]
mod real_keychain {
    use super::*;
    use std::os::unix::fs::symlink;

    const SECURITY: &str = "/usr/bin/security";

    /// Deletes the disposable items even when an assertion panics.
    struct Items(Vec<(String, String)>);

    impl Drop for Items {
        fn drop(&mut self) {
            for (service, account) in &self.0 {
                let _ = Command::new(SECURITY)
                    .args(["delete-generic-password", "-s", service, "-a", account])
                    .output();
            }
        }
    }

    fn add(items: &mut Items, service: &str, account: &str) {
        let status = Command::new(SECURITY)
            .args([
                "add-generic-password",
                "-s",
                service,
                "-a",
                account,
                "-w",
                "disposable-test-value",
            ])
            .output()
            .expect("run security")
            .status;
        assert!(status.success(), "add disposable keychain item");
        items.0.push((service.to_owned(), account.to_owned()));
    }

    fn orphan_count(item: &serde_json::Value) -> usize {
        let message = item["message"].as_str().unwrap();
        if message.starts_with("no orphaned") {
            return 0;
        }
        message
            .split_whitespace()
            .next()
            .and_then(|count| count.parse().ok())
            .unwrap_or_else(|| panic!("unexpected orphan message {message:?}"))
    }

    /// Non-CI Go and Rust against the real login keychain. HOME is a disposable
    /// directory whose only entry is a `Library` symlink, so `security` finds
    /// the login keychain without any other real home state being visible.
    #[test]
    fn differential_doctor_keyring_checks_real_macos_keychain() {
        if env::var_os("SYMVAULT_DOCTOR_REAL_KEYCHAIN").is_none() {
            eprintln!(
                "skipping real-keychain differential: SYMVAULT_DOCTOR_REAL_KEYCHAIN is not set"
            );
            return;
        }
        let Some((go, rust)) = oracle_binaries() else {
            return;
        };
        let real_home = PathBuf::from(
            env::var_os("SYMVAULT_DOCTOR_REAL_HOME").expect("SYMVAULT_DOCTOR_REAL_HOME"),
        );
        let home = test_temp_root::TempRoot::existing("symvault-doctor-keyring-real-home-");
        symlink(real_home.join("Library"), home.join("Library")).expect("link Library");
        let vault = test_temp_root::TempRoot::existing("symvault-doctor-keyring-real-vault-");

        let before = compare_text_and_json(&go, &rust, &vault, &home, &[]);
        assert_eq!(find(&before, "session.cache")["status"], "ok");
        assert_eq!(
            find(&before, "session.cache")["message"],
            "backend: os-keyring, persistent: true (verified)"
        );
        assert_eq!(find(&before, "session.keyring")["status"], "ok");
        let baseline = orphan_count(find(&before, "audit.keyring.orphans"));

        let tag = format!("doctor-keyring-test-{}", std::process::id());
        let gone = vault.join(format!("{tag}-gone"));
        let mut items = Items(Vec::new());
        add(
            &mut items,
            "symaira",
            &format!("audit-hmac-key:{}", gone.display()),
        );
        add(
            &mut items,
            "openpass",
            &format!("audit-hmac-key:{}-legacy", gone.display()),
        );
        // A live vault directory and an unrelated service must not count.
        add(
            &mut items,
            "symaira",
            &format!("audit-hmac-key:{}", vault.display()),
        );
        add(
            &mut items,
            &tag,
            &format!("audit-hmac-key:{}", gone.display()),
        );

        let during = compare_text_and_json(&go, &rust, &vault, &home, &[]);
        assert_eq!(
            orphan_count(find(&during, "audit.keyring.orphans")),
            baseline + 2
        );
        assert_eq!(find(&during, "audit.keyring.orphans")["fixable"], true);

        // Dry run reports the same plan in both and deletes nothing.
        let dry = [
            "--no-network",
            "--only",
            "audit.keyring.orphans",
            "--fix",
            "--fix-dry-run",
        ];
        let (go_dry, rust_dry) = (
            doctor(&go, &vault, &home, &[], &dry),
            doctor(&rust, &vault, &home, &[], &dry),
        );
        assert_eq!(
            String::from_utf8_lossy(&go_dry.stderr),
            String::from_utf8_lossy(&rust_dry.stderr)
        );
        assert!(
            String::from_utf8_lossy(&rust_dry.stderr).contains("Would fix audit.keyring.orphans")
        );
        let after_dry = compare_text_and_json(&go, &rust, &vault, &home, &[]);
        assert_eq!(
            orphan_count(find(&after_dry, "audit.keyring.orphans")),
            baseline + 2
        );

        drop(items);
        let after = compare_text_and_json(&go, &rust, &vault, &home, &[]);
        assert_eq!(
            orphan_count(find(&after, "audit.keyring.orphans")),
            baseline
        );
        let _ = fs::remove_dir_all(&gone);
    }
}
