#![deny(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_core::session::{Keyring, MemoryKeyring};
use symvault_store::audit::{load_or_create_key_with_keyring, rotate_key_with_keyring};

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
            env::temp_dir().join(format!("symvault-audit-cmd-{label}-{pid}-{suffix}-{count}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_cli(vault: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1")
        .output()
        .expect("run symvault CLI")
}

fn init_vault(vault: &Path, home: &Path) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_symvault"));
    cmd.args(["init"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn init");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(b"test-passphrase-123\ntest-passphrase-123\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "init failed");
}

#[test]
fn audit_rotate_key_cli_flow() {
    let home = TempDir::new("home");
    let uninit_vault = home.0.join("uninit");

    // 1. Uninitialized vault bootstraps like Go (exit code 0, printed to stderr)
    let out0 = run_cli(&uninit_vault, &home.0, &["audit", "rotate-key"]);
    assert_eq!(out0.status.code(), Some(0));
    let stderr0 = String::from_utf8_lossy(&out0.stderr);
    assert!(stderr0.contains("New key: "));
    assert!(stderr0.contains("HMAC key bootstrapped"));

    // Initialize vault
    let vault = home.0.join("vault");
    init_vault(&vault, &home.0);

    // 2. First rotation bootstraps because no key exists yet
    let out1 = run_cli(&vault, &home.0, &["audit", "rotate-key"]);
    assert_eq!(out1.status.code(), Some(0));
    let stderr1 = String::from_utf8_lossy(&out1.stderr);
    assert!(stderr1.contains("New key: "));
    assert!(stderr1.contains("(first 4 bytes)"));
    assert!(stderr1.contains(
        "HMAC key bootstrapped — no previous key existed, so no archive file was written."
    ));
    assert!(stderr1.contains("A new audit log will be started on the next audit write."));

    // Check no rotated files exist yet
    let rotated_files: Vec<_> = fs::read_dir(&vault)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".rotated."))
        .collect();
    assert!(
        rotated_files.is_empty(),
        "bootstrap must not create archive file"
    );

    // 3. Write a key on disk to test CLI rotation without touching real OS keychain
    let key_bytes = [0x55u8; 32];
    fs::write(vault.join("audit-hmac-key"), key_bytes).unwrap();

    let out2 = run_cli(&vault, &home.0, &["audit", "rotate-key"]);
    assert_eq!(out2.status.code(), Some(0));
    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr2.contains("HMAC key rotated successfully."));
    assert!(stderr2.contains("Old key archived to: "));
    assert!(stderr2.contains("audit-hmac-key.rotated."));
    assert!(
        !vault.join("audit-hmac-key").exists(),
        "legacy key must be removed after rotation"
    );

    let rotated_files: Vec<_> = fs::read_dir(&vault)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".rotated."))
        .collect();
    assert_eq!(
        rotated_files.len(),
        1,
        "exactly one archived key must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(rotated_files[0].path()).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "archive file mode must be 0600"
        );
    }

    // 4. Write another legacy key to test second rotation without collision
    let key2_bytes = [0x77u8; 32];
    fs::write(vault.join("audit-hmac-key"), key2_bytes).unwrap();

    let out3 = run_cli(&vault, &home.0, &["audit", "rotate-key"]);
    assert_eq!(out3.status.code(), Some(0));

    let rotated_files: Vec<_> = fs::read_dir(&vault)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".rotated."))
        .collect();
    assert_eq!(rotated_files.len(), 2, "two distinct archives must exist");
}

#[test]
fn rotate_key_with_keyring_edge_cases() {
    let temp = TempDir::new("store");
    let keyring = MemoryKeyring::new();

    // 1. Initial rotation bootstraps
    let (key1, archive1) = rotate_key_with_keyring(&temp.0, &keyring).expect("bootstrap");
    assert!(archive1.is_none());
    assert!(!key1.fingerprint().is_empty());

    // 2. Second rotation archives key1
    let (key2, archive2) = rotate_key_with_keyring(&temp.0, &keyring).expect("rotate 1");
    let arch2 = archive2.expect("archive path exists");
    assert!(arch2.is_file());
    assert!(arch2.to_string_lossy().contains(&key1.fingerprint()));

    // 3. Third rotation archives key2
    let (_key3, archive3) = rotate_key_with_keyring(&temp.0, &keyring).expect("rotate 2");
    let arch3 = archive3.expect("archive path exists");
    assert!(arch3.is_file());
    assert!(arch3.to_string_lossy().contains(&key2.fingerprint()));
    assert_ne!(
        arch2, arch3,
        "different fingerprints produce different archive paths"
    );
    assert!(arch2.is_file(), "previous archive must remain intact");

    // 4. Corrupt entry in keyring fails rather than bootstrapping
    let bad_dir = TempDir::new("corrupt");
    let address = format!("symaira|audit-hmac-key:{}", bad_dir.0.display());
    keyring.set(&address, b"not-valid-hex!").unwrap();

    let err = rotate_key_with_keyring(&bad_dir.0, &keyring).expect_err("corrupt key must fail");
    assert!(err.to_string().contains("invalid audit key encoding"));

    // 5. Legacy unencrypted key file on disk is migrated and archived
    let legacy_dir = TempDir::new("legacy");
    let legacy_key = [0x42u8; 32];
    fs::write(legacy_dir.0.join("audit-hmac-key"), legacy_key).unwrap();

    let (new_key, archive) =
        rotate_key_with_keyring(&legacy_dir.0, &keyring).expect("legacy migration");
    let arch_path = archive.expect("archived legacy key");
    assert!(arch_path.is_file());
    assert!(
        !legacy_dir.0.join("audit-hmac-key").exists(),
        "legacy file must be removed"
    );

    // Keyring now has the new key
    let loaded = load_or_create_key_with_keyring(&legacy_dir.0, &keyring).expect("load key");
    assert_eq!(loaded.fingerprint(), new_key.fingerprint());
}
