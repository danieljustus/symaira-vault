#![deny(unsafe_code)]

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_crypto::{
    EnvelopeFormat, SecretBytes, detect_envelope, encrypt_identity_argon2id,
    encrypt_identity_scrypt, generate_identity,
};

const PASSPHRASE: &[u8] = b"fixture migrate passphrase";
const CUSTOM_CONFIG: &[u8] = b"vault:\n  format_version: 1\n  scrypt_work_factor: 10\n  auto_migrate_kdf: false\n  argon2id_time: 2\n  argon2id_memory: 19456\n  argon2id_threads: 1\ncustom:\n  retained: true\n";

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-migrate-kdf-{label}-{nanos}"))
}

fn make_scrypt_vaults(label: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let identity = generate_identity();
    let old = encrypt_identity_scrypt(&identity, &SecretBytes::new(PASSPHRASE), 10)
        .expect("scrypt fixture");
    let go = unique_root(&format!("{label}-go"));
    let rust = unique_root(&format!("{label}-rust"));
    write_vault(&go, &old, CUSTOM_CONFIG);
    write_vault(&rust, &old, CUSTOM_CONFIG);
    (go, rust, old)
}

fn write_vault(root: &Path, identity: &[u8], config: &[u8]) {
    fs::create_dir_all(root.join("entries")).expect("entries");
    fs::write(root.join("identity.age"), identity).expect("identity");
    fs::write(root.join("config.yaml"), config).expect("config");
}

fn run_with_input(binary: &Path, args: &[&str], root: &Path, input: &[u8]) -> Output {
    let home = root.join("home");
    fs::create_dir_all(&home).expect("home");
    let mut child = Command::new(binary)
        .args(args)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env_remove("SYMVAULT_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait CLI")
}

fn migrate_args(root: &Path, yes: bool) -> Vec<String> {
    let mut args = vec![
        "--vault".to_owned(),
        root.to_str().expect("UTF-8 fixture path").to_owned(),
        "migrate".to_owned(),
        "kdf".to_owned(),
    ];
    if yes {
        args.push("--yes".to_owned());
    }
    args
}

fn as_refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_migrated(root: &Path, original: &[u8]) {
    let migrated = fs::read(root.join("identity.age")).expect("migrated identity");
    assert_eq!(detect_envelope(&migrated), EnvelopeFormat::Argon2id);
    assert_eq!(
        fs::read(root.join("identity.age.bak")).expect("backup"),
        original
    );
    let config = fs::read(root.join("config.yaml")).expect("config");
    let config = String::from_utf8_lossy(&config);
    assert!(config.contains("format_version: 2"), "config={config}");
    assert!(!config.contains("scrypt_work_factor"), "config={config}");
    assert!(config.contains("argon2id_time: 2"), "config={config}");
}

fn assert_unchanged(root: &Path, original: &[u8]) {
    assert_eq!(
        fs::read(root.join("identity.age")).expect("identity"),
        original
    );
    assert!(!root.join("identity.age.bak").exists());
}

#[test]
#[ignore = "requires the pinned Go CLI binary and the wired Rust migrate command"]
fn migrate_kdf_go_rust_integration() {
    let go_binary = PathBuf::from(
        env::var_os("SYMVAULT_GO_BINARY")
            .expect("SYMVAULT_GO_BINARY is required for this explicit integration gate"),
    );
    assert!(go_binary.is_file(), "SYMVAULT_GO_BINARY is not a file");
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let (go_root, rust_root, original) = make_scrypt_vaults("migrate");
    let go_args = migrate_args(&go_root, true);
    let rust_args = migrate_args(&rust_root, true);
    let go = run_with_input(
        &go_binary,
        &as_refs(&go_args),
        &go_root,
        b"fixture migrate passphrase\n",
    );
    let rust = run_with_input(
        &rust_binary,
        &as_refs(&rust_args),
        &rust_root,
        b"fixture migrate passphrase\n",
    );
    assert_success(&go, "Go migrate kdf");
    assert_success(&rust, "Rust migrate kdf");
    assert_eq!(go.stdout, rust.stdout, "migration stdout differs");
    assert_migrated(&go_root, &original);
    assert_migrated(&rust_root, &original);

    // Each implementation must open the other implementation's migrated
    // envelope through its normal vault path, rather than only matching bytes.
    let rust_list = run_with_input(
        &rust_binary,
        &["--vault", go_root.to_str().unwrap(), "list"],
        &go_root,
        b"fixture migrate passphrase\n",
    );
    let go_list = run_with_input(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        b"fixture migrate passphrase\n",
    );
    assert_success(&rust_list, "Rust list after Go migration");
    assert_success(&go_list, "Go list after Rust migration");

    let (go_root, rust_root, original) = make_scrypt_vaults("cancel");
    let go_args = migrate_args(&go_root, false);
    let rust_args = migrate_args(&rust_root, false);
    let input = b"fixture migrate passphrase\nn\n";
    let go = run_with_input(&go_binary, &as_refs(&go_args), &go_root, input);
    let rust = run_with_input(&rust_binary, &as_refs(&rust_args), &rust_root, input);
    assert_success(&go, "Go canceled migrate kdf");
    assert_success(&rust, "Rust canceled migrate kdf");
    assert_eq!(go.stdout, rust.stdout, "canceled stdout differs");
    assert_unchanged(&go_root, &original);
    assert_unchanged(&rust_root, &original);

    let identity = generate_identity();
    let modern = encrypt_identity_argon2id(
        &identity,
        &SecretBytes::new(PASSPHRASE),
        symvault_crypto::Argon2idParams {
            time: 2,
            memory_kib: 19_456,
            threads: 1,
        },
    )
    .expect("argon2id fixture");
    let go_root = unique_root("already-go");
    let rust_root = unique_root("already-rust");
    write_vault(&go_root, &modern, CUSTOM_CONFIG);
    write_vault(&rust_root, &modern, CUSTOM_CONFIG);
    let go_args = migrate_args(&go_root, true);
    let rust_args = migrate_args(&rust_root, true);
    let go = run_with_input(&go_binary, &as_refs(&go_args), &go_root, b"");
    let rust = run_with_input(&rust_binary, &as_refs(&rust_args), &rust_root, b"");
    assert_success(&go, "Go already-modern migrate kdf");
    assert_success(&rust, "Rust already-modern migrate kdf");
    assert_eq!(go.stdout, rust.stdout, "already-modern stdout differs");
    assert_eq!(fs::read(go_root.join("identity.age")).unwrap(), modern);
    assert_eq!(fs::read(rust_root.join("identity.age")).unwrap(), modern);
    assert!(!go_root.join("identity.age.bak").exists());
    assert!(!rust_root.join("identity.age.bak").exists());

    for root in [go_root, rust_root] {
        if root.exists() {
            let _ = fs::remove_dir_all(root);
        }
    }
}
