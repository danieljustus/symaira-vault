use serde_json::Value;
use std::{path::Path, process::Command};
use symvault_sync::importer::import_pass;

#[test]
#[ignore = "requires scripts/rust-port/check_pass_gpg_compat.sh and real gpg"]
fn real_gpg_import_matches_go_and_rejects_wrong_recipient() {
    let store = std::env::var_os("SYMVAULT_PASS_GPG_STORE").expect("compat script sets store");
    let bad_store =
        std::env::var_os("SYMVAULT_PASS_GPG_BAD_STORE").expect("compat script sets bad store");
    let entries = import_pass(Path::new(&store)).expect("Rust decrypts real GPG ciphertext");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "Personal/Example-Entry");
    assert_eq!(entries[0].data["password"], "synthetic-password");
    assert_eq!(entries[0].data["url"], "https://example.test/login");
    assert_eq!(entries[0].data["username"], "alice");
    assert_eq!(
        entries[0].data["totp"]["secret"],
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    );
    assert_eq!(entries[0].data["notes"], "first note\nsecond note");
    assert_eq!(entries[0].warnings.as_ref().map(Vec::len), Some(1));

    let go = Command::new("go")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "test",
            "./internal/importer",
            "-run",
            "^TestPassGPGCompatibilityOracle$",
            "-count=1",
            "-v",
        ])
        .output()
        .expect("run the Go production importer oracle");
    assert!(
        go.status.success(),
        "Go importer failed: {}",
        String::from_utf8_lossy(&go.stderr)
    );
    let stdout = String::from_utf8(go.stdout).expect("Go output is UTF-8");
    let oracle: Value = stdout
        .lines()
        .find_map(|line| line.strip_prefix("PASS_GPG_COMPAT_ORACLE="))
        .map(|json| serde_json::from_str(json).expect("Go oracle JSON"))
        .expect("Go oracle emitted importer entries");
    assert_eq!(
        serde_json::to_value(&entries).unwrap(),
        oracle,
        "real GPG import fields, warnings, and paths must match Go"
    );
    assert!(
        import_pass(Path::new(&bad_store)).is_err(),
        "Rust importer must reject ciphertext encrypted to another key"
    );
}
