#![deny(unsafe_code)]

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use symvault_crypto::{SecretBytes, encrypt_identity_scrypt, generate_identity};

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    exit_code: u8,
    #[serde(default)]
    stdout_bytes: Vec<u8>,
    #[serde(default)]
    stderr_bytes: Vec<u8>,
    #[serde(default)]
    stderr_contains: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    config_bytes: Vec<u8>,
    #[serde(default)]
    initialized: bool,
    #[serde(default)]
    root_config_bytes: Vec<u8>,
    #[serde(default)]
    vault_dir: String,
    #[serde(default)]
    disable_vault_env: bool,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
    args: Vec<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    serde_json::from_slice(include_bytes!("../../../testdata/port/cli/session.json"))
        .expect("session fixture parses")
}

fn run_case(case: &Case) -> (std::process::Output, PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("symvault-session-cli-case-{unique}"));
    fs::create_dir_all(&root).expect("create isolated case root");
    let vault = root.join(if case.vault_dir.is_empty() {
        "missing-vault"
    } else {
        &case.vault_dir
    });
    if case.initialized {
        fs::create_dir_all(&vault).expect("create initialized fixture vault");
        fs::write(vault.join("identity.age"), b"fixture identity").expect("write fixture identity");
        fs::write(vault.join("config.yaml"), &case.config_bytes).expect("write fixture config");
    }
    if !case.root_config_bytes.is_empty() {
        let root_config_path = root.join("home/.config/symaira-vault/config.yaml");
        fs::create_dir_all(root_config_path.parent().expect("root config parent"))
            .expect("create resolver config directory");
        let profile_vault = root.join("profile-vault");
        let root_config = replace_bytes(
            &case.root_config_bytes,
            b"__PROFILE_VAULT__",
            profile_vault
                .to_str()
                .expect("UTF-8 profile vault")
                .as_bytes(),
        );
        fs::write(root_config_path, root_config).expect("write resolver config");
    }
    let args: Vec<_> = case
        .args
        .iter()
        .map(|arg| arg.replace("__VAULT__", vault.to_str().expect("UTF-8 temp path")))
        .collect();
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    command
        .args(args)
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env("CI", "1")
        .env_remove("SYMVAULT_PROFILE")
        .env_remove("SYMVAULT_PASSPHRASE");
    if case.disable_vault_env {
        command.env_remove("SYMVAULT_VAULT");
    } else {
        command.env("SYMVAULT_VAULT", &vault);
    }
    for (key, value) in &case.env {
        let value = value.replace(
            "__VAULT__",
            vault.to_str().expect("UTF-8 fixture vault path"),
        );
        command.env(
            key,
            value.replace(
                "__PROFILE_VAULT__",
                root.join("profile-vault")
                    .to_str()
                    .expect("UTF-8 profile vault"),
            ),
        );
    }
    let output = command.output().expect("run Rust session CLI case");
    (output, root)
}

fn expand_markers(bytes: &[u8], root: &Path, vault: &Path) -> Vec<u8> {
    let root = root.to_str().expect("UTF-8 fixture root path").as_bytes();
    let vault = vault.to_str().expect("UTF-8 fixture vault path").as_bytes();
    let mut expanded = Vec::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let root_offset = remaining
            .windows(b"__ROOT__".len())
            .position(|candidate| candidate == b"__ROOT__");
        let vault_offset = remaining
            .windows(b"__VAULT__".len())
            .position(|candidate| candidate == b"__VAULT__");
        let Some((offset, marker, replacement)) = (match (root_offset, vault_offset) {
            (None, None) => None,
            (Some(offset), None) => Some((offset, b"__ROOT__".as_slice(), root)),
            (None, Some(offset)) => Some((offset, b"__VAULT__".as_slice(), vault)),
            (Some(root_offset), Some(vault_offset)) if root_offset < vault_offset => {
                Some((root_offset, b"__ROOT__".as_slice(), root))
            }
            (Some(_), Some(vault_offset)) => Some((vault_offset, b"__VAULT__".as_slice(), vault)),
        }) else {
            expanded.extend_from_slice(remaining);
            break;
        };
        expanded.extend_from_slice(&remaining[..offset]);
        expanded.extend_from_slice(replacement);
        remaining = &remaining[offset + marker.len()..];
    }
    expanded
}

fn replace_bytes(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let Some(offset) = bytes
        .windows(from.len())
        .position(|candidate| candidate == from)
    else {
        return bytes.to_vec();
    };
    let mut replaced = Vec::with_capacity(bytes.len() + to.len() - from.len());
    replaced.extend_from_slice(&bytes[..offset]);
    replaced.extend_from_slice(to);
    replaced.extend_from_slice(&bytes[offset + from.len()..]);
    replaced
}

#[test]
fn initialized_status_uses_memory_fallback_in_ci_without_keychain_access() {
    let root = std::env::temp_dir().join(format!(
        "symvault-session-cli-initialized-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    let vault = root.join("vault");
    fs::create_dir_all(&vault).expect("create isolated vault");
    fs::write(
        vault.join("config.yaml"),
        b"vaultDir: /fixture/vault\nauthMethod: passphrase\n",
    )
    .expect("write fixture config");
    fs::write(vault.join("identity.age"), b"fixture identity").expect("write fixture identity");

    let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args([
            "--vault",
            vault.to_str().expect("UTF-8 temp path"),
            "auth",
            "status",
            "--json",
        ])
        .env("CI", "1")
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env_remove("SYMVAULT_PASSPHRASE")
        .output()
        .expect("run initialized Rust session status");
    let _ = fs::remove_dir_all(&root);

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert_eq!(value["cache"]["backend"], "memory");
    assert_eq!(value["cache"]["persistent"], false);
    assert_eq!(value["keyringHealth"], "unavailable");
}

#[test]
fn unlock_validates_identity_and_uses_memory_fallback_without_keychain_access() {
    let root = std::env::temp_dir().join(format!(
        "symvault-session-cli-unlock-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    let vault = root.join("vault");
    fs::create_dir_all(&vault).expect("create isolated vault");
    let passphrase = b"fixture-passphrase";
    let identity = generate_identity();
    let secret = SecretBytes::new(passphrase);
    let encrypted = encrypt_identity_scrypt(&identity, &secret, 12).expect("encrypt identity");
    fs::write(vault.join("identity.age"), encrypted).expect("write encrypted identity");
    fs::write(
        vault.join("config.yaml"),
        b"authMethod: passphrase\nsessionTimeout: 15m\n",
    )
    .expect("write unlock config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(["--vault", vault.to_str().expect("UTF-8 vault"), "unlock"])
        .env("CI", "1")
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env_remove("SYMVAULT_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn unlock");
    child
        .stdin
        .take()
        .expect("unlock stdin")
        .write_all(b"fixture-passphrase\n")
        .expect("write fixture passphrase");
    let output = child.wait_with_output().expect("wait for unlock");
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("session cache is memory-only"));

    let mut wrong = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(["--vault", vault.to_str().expect("UTF-8 vault"), "unlock"])
        .env("CI", "1")
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrong unlock");
    wrong
        .stdin
        .take()
        .expect("wrong unlock stdin")
        .write_all(b"wrong-passphrase\n")
        .expect("write wrong fixture passphrase");
    let wrong_output = wrong.wait_with_output().expect("wait for wrong unlock");
    assert_eq!(wrong_output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong_output.stderr).contains("unlock vault"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fixture_pins_go_sources_and_runs_empty_vault_cases() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "cmd/auth/auth.go",
            "cmd/auth/lock.go",
            "cmd/auth/unlock.go",
            "internal/cli/cli.go",
            "internal/cli/passphrase_env.go",
            "internal/cli/terminal.go",
            "internal/cli/unlock.go",
            "internal/cli/vault.go",
            "internal/cli/vaultpath.go",
            "internal/config/config.go",
            "internal/config/config_load.go",
            "internal/config/config_merge.go",
            "internal/config/config_validate.go",
            "internal/config/paths.go",
            "internal/config/schema.go",
            "internal/session/biometric.go",
            "internal/session/guisession_darwin.go",
            "internal/session/guisession_nondarwin.go",
            "internal/session/keyring.go",
            "internal/session/memory_init.go",
            "internal/session/memory_keyring.go",
            "internal/session/oskeyring.go",
            "internal/session/oskeyring_unavailable.go",
            "internal/session/secure_bytes.go",
            "internal/session/session.go",
            "internal/session/touchid_darwin.go",
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 18);

    let mut failures = Vec::new();
    for case in &fixture.cases {
        let (output, root) = run_case(case);
        let status = output.status.code().unwrap_or(255);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let vault = root.join(if case.vault_dir.is_empty() {
            "missing-vault"
        } else {
            &case.vault_dir
        });
        let expected_stdout = expand_markers(&case.expected.stdout_bytes, &root, &vault);
        let expected_stderr = expand_markers(&case.expected.stderr_bytes, &root, &vault);
        let stdout_matches = if case.name.starts_with("auth_status_")
            && !case.expected.stdout_bytes.is_empty()
        {
            // The Go and Rust commands ask the host biometric provider for
            // this capability. Keep every emitted byte exact while allowing
            // the native boolean to differ on a host without Touch ID.
            let actual: serde_json::Value = match serde_json::from_slice(&output.stdout) {
                Ok(value) => value,
                Err(error) => {
                    failures.push(format!(
                            "{}: invalid status JSON: {error}; status={status}, stdout={:?}, stderr={:?}",
                            case.name, output.stdout, output.stderr
                        ));
                    serde_json::Value::Null
                }
            };
            let actual_touch = if actual["touchIDAvailable"].as_bool().unwrap_or(false) {
                b"true".as_slice()
            } else {
                b"false".as_slice()
            };
            let normalized = replace_bytes(
                &expected_stdout,
                b"\"touchIDAvailable\":true",
                format!(
                    "\"touchIDAvailable\":{}",
                    String::from_utf8_lossy(actual_touch)
                )
                .as_bytes(),
            );
            if normalized != output.stdout {
                eprintln!("{} expected: {:?}", case.name, normalized);
                eprintln!("{} actual: {:?}", case.name, output.stdout);
            }
            normalized == output.stdout
        } else {
            output.stdout == expected_stdout
        };
        let stderr_matches = if !case.expected.stderr_bytes.is_empty() {
            output.stderr == expected_stderr
        } else {
            true
        };
        if status != i32::from(case.expected.exit_code)
            || !stdout_matches
            || !stderr_matches
            || (!case.expected.stderr_contains.is_empty()
                && !stderr.contains(&case.expected.stderr_contains))
        {
            failures.push(format!(
                "{}: status={status}, expected_status={}, stdout={:?}, expected_stdout={:?}, stderr={stderr:?}, expected_stderr={expected_stderr:?}, stderr_contains={:?}",
                case.name,
                case.expected.exit_code,
                output.stdout,
                expected_stdout,
                case.expected.stderr_contains,
            ));
        }
        let _ = fs::remove_dir_all(&root);
    }
    assert!(failures.is_empty(), "session CLI mismatches: {failures:#?}");
}
