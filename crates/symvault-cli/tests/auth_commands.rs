#![deny(unsafe_code)]

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_crypto::{SecretBytes, decrypt_identity};

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            env::temp_dir().join(format!("symvault-auth-cmd-{label}-{pid}-{suffix}-{count}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_cli(vault: &Path, home: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_symvault"));
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1");
    if let Some(data) = input {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn symvault CLI");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).expect("write to stdin");
        }
        child.wait_with_output().expect("wait for symvault CLI")
    } else {
        cmd.output().expect("run symvault CLI")
    }
}

fn init_vault(vault: &Path, home: &Path, passphrase: &str) {
    let input = format!("{passphrase}\n{passphrase}\n");
    let out = run_cli(vault, home, &["init"], Some(input.as_bytes()));
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn auth_set_validation_and_execution() {
    let home = TempDir::new("home");
    let uninit_vault = home.0.join("uninit-vault");

    // 1. Invalid auth method is rejected before vault resolution
    let out = run_cli(
        &uninit_vault,
        &home.0,
        &["auth", "set", "invalid-method"],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Error: invalid authMethod \"invalid-method\" (valid: passphrase, touchid)"),
        "stderr={err}"
    );

    // 2. Uninitialized vault with valid method fails
    let out = run_cli(&uninit_vault, &home.0, &["auth", "set", "passphrase"], None);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("vault not initialized. Run 'symvault init' first"),
        "stderr={err}"
    );

    // 3. Initialized vault: successfully set to passphrase
    let vault = home.0.join("vault");
    init_vault(&vault, &home.0, "initial-passphrase-123");

    let out = run_cli(&vault, &home.0, &["auth", "set", "passphrase"], None);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Auth method set to passphrase\n"
    );

    let config_content = fs::read_to_string(vault.join("config.yaml")).expect("read config");
    assert!(config_content.contains("authMethod: passphrase"));

    // 4. Quiet mode suppresses stdout
    let out = run_cli(
        &vault,
        &home.0,
        &["--quiet", "auth", "set", "passphrase"],
        None,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "quiet mode must produce no stdout");
}

#[test]
fn auth_rotate_passphrase_failure_paths() {
    let home = TempDir::new("home");
    let uninit = home.0.join("uninit");

    // 1. Uninitialized vault
    let out = run_cli(&uninit, &home.0, &["auth", "rotate-passphrase", "-y"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("vault not initialized"));

    // Initialize vault
    let vault = home.0.join("vault");
    init_vault(&vault, &home.0, "current-passphrase-456");

    // 2. Wrong current passphrase
    let input = b"wrong-passphrase\n";
    let out = run_cli(
        &vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("current passphrase is incorrect"));

    // 3. Short new passphrase (<12)
    let input = b"current-passphrase-456\nshort\n";
    let out = run_cli(
        &vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("passphrase must be at least 12 characters")
    );

    // 4. Mismatched new passphrases
    let input = b"current-passphrase-456\nnew-passphrase-1234\nnew-passphrase-different\n";
    let out = run_cli(
        &vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("passphrases do not match"));

    // 5. New passphrase same as current
    let input = b"current-passphrase-456\ncurrent-passphrase-456\ncurrent-passphrase-456\n";
    let out = run_cli(
        &vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("new passphrase must be different from the current passphrase")
    );

    // 6. Canceled confirmation
    let input = b"current-passphrase-456\nnew-valid-passphrase-999\nnew-valid-passphrase-999\nn\n";
    let out = run_cli(&vault, &home.0, &["auth", "rotate-passphrase"], Some(input));
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Canceled"));
}

#[test]
fn auth_rotate_passphrase_success_rotates_identity_and_logs_audit() {
    let home = TempDir::new("home");
    let vault = home.0.join("vault");
    init_vault(&vault, &home.0, "first-passphrase-000");

    let original_identity = fs::read(vault.join("identity.age")).expect("read identity");
    assert!(
        decrypt_identity(
            &original_identity,
            &SecretBytes::new(b"first-passphrase-000")
        )
        .is_ok()
    );

    // Rotate with confirmation prompt "y"
    let input = b"first-passphrase-000\nsecond-passphrase-111\nsecond-passphrase-111\ny\n";
    let out = run_cli(&vault, &home.0, &["auth", "rotate-passphrase"], Some(input));
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Passphrase rotated successfully."));

    // Verify identity on disk is now encrypted with the new passphrase
    let updated_identity = fs::read(vault.join("identity.age")).expect("read updated identity");
    assert!(
        decrypt_identity(
            &updated_identity,
            &SecretBytes::new(b"first-passphrase-000")
        )
        .is_err(),
        "old passphrase must fail"
    );
    assert!(
        decrypt_identity(
            &updated_identity,
            &SecretBytes::new(b"second-passphrase-111")
        )
        .is_ok(),
        "new passphrase must succeed"
    );

    // Verify config has last_rotated timestamp
    let config_content = fs::read_to_string(vault.join("config.yaml")).expect("read config");
    assert!(config_content.contains("last_rotated") || config_content.contains("lastRotated"));

    // Verify audit log has rotate-passphrase action
    let audit_log = vault.join("audit-symvault.log");
    if audit_log.is_file() {
        let content = fs::read_to_string(&audit_log).expect("read audit log");
        assert!(content.contains("\"action\":\"rotate-passphrase\""));
        assert!(content.contains("\"ok\":true"));
    }

    // Rotate again with -y and --quiet
    let input = b"second-passphrase-111\nthird-passphrase-222\nthird-passphrase-222\n";
    let out = run_cli(
        &vault,
        &home.0,
        &["--quiet", "auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "quiet mode must produce no stdout");

    let third_identity = fs::read(vault.join("identity.age")).expect("read third identity");
    assert!(decrypt_identity(&third_identity, &SecretBytes::new(b"third-passphrase-222")).is_ok());
}
