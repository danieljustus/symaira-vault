#![deny(unsafe_code)]

//! DOCTOR-KEYRING-001: `session.cache`, `session.keyring` and
//! `audit.keyring.orphans` must report the real session/keychain state exactly
//! like the Go oracle.
//!
//! The always-on tests run both binaries in the forced in-memory states
//! (`CI`, `HEADLESS`, `SYMVAULT_TEST_KEYRING=memory`) with a cleared
//! environment, so they never reach a keychain. The Go answers are replayed
//! from `testdata/port/cli-transcripts/doctor_keyring_differential.json`.
//!
//! The former opt-in real-login-keychain comparison was retired: it needed the
//! operator's keychain and counted host-specific items, so it cannot be
//! recorded (docs/rust-port/go-oracle-archive.md).

#[path = "common/go_oracle.rs"]
mod go_oracle;

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const IDS: &str = "session.cache,session.keyring,audit.keyring.orphans";

fn oracle_binaries(test: &str) -> (go_oracle::GoOracle, PathBuf, PathBuf) {
    let oracle = go_oracle::GoOracle::begin(
        "doctor_keyring_differential",
        test,
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go = oracle.binary();
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    assert!(rust.is_file(), "Rust binary does not exist at {rust:?}");
    (oracle, go, rust)
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
    go_oracle::output(&mut command).expect("run CLI")
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
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn differential_doctor_keyring_checks_in_forced_memory_states() {
    let (oracle, go, rust) =
        oracle_binaries("differential_doctor_keyring_checks_in_forced_memory_states");
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
    // 4 forced states x (json + text) x 1 Go call.
    assert_eq!(oracle.calls(), 8);
}
