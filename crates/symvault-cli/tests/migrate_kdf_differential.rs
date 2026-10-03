#![deny(unsafe_code)]

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use symvault_crypto::{
    EnvelopeFormat, SecretBytes, detect_envelope, encrypt_identity_argon2id,
    encrypt_identity_scrypt, generate_identity,
};

const PASSPHRASE: &[u8] = b"fixture migrate passphrase";
const CUSTOM_CONFIG: &[u8] = b"vault:\n  format_version: 1\n  scrypt_work_factor: 10\n  auto_migrate_kdf: false\n  argon2id_time: 2\n  argon2id_memory: 19456\n  argon2id_threads: 1\ncustom:\n  retained: true\n";

fn unique_root(label: &str) -> test_temp_root::TempRoot {
    test_temp_root::TempRoot::missing(&format!("symvault-migrate-kdf-{label}-"))
}

fn make_scrypt_vaults(
    label: &str,
) -> (test_temp_root::TempRoot, test_temp_root::TempRoot, Vec<u8>) {
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
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
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

#[test]
#[ignore = "requires the current Go CLI binary for the new resource policy"]
fn kdf_resource_policy_go_rust_integration() {
    use base64::Engine as _;
    let go_binary = PathBuf::from(env::var_os("SYMVAULT_GO_BINARY").expect("current Go binary"));
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../testdata/port/crypto/kdf-policy-v1.json"
    ))
    .expect("genuine historical Go fixture");
    let old = base64::engine::general_purpose::STANDARD
        .decode(fixture["cases"][0]["ciphertext"].as_str().unwrap())
        .unwrap();
    let passphrase = fixture["passphrase"].as_str().unwrap();
    let config = b"vault:\n  format_version: 2\n  argon2id_time: 5\n  argon2id_memory: 65536\n  argon2id_threads: 4\n  auto_heal_zero_key: true\nunknown_root: retained\n";
    for (label, binary) in [("go", go_binary), ("rust", rust_binary)] {
        for scenario in ["no-flag", "decline", "wrong", "migrate", "scrypt-config"] {
            let root = unique_root(&format!("policy-{label}-{scenario}"));
            let original = if scenario == "scrypt-config" {
                encrypt_identity_scrypt(
                    &generate_identity(),
                    &SecretBytes::new(passphrase.as_bytes()),
                    10,
                )
                .unwrap()
            } else {
                old.clone()
            };
            write_vault(&root, &original, config);
            let mut args = migrate_args(&root, scenario != "decline");
            if scenario != "no-flag" {
                args.push("--allow-legacy-kdf".to_owned());
            }
            let input = match scenario {
                "no-flag" => String::new(),
                "decline" => format!("{passphrase}\nn\n"),
                "wrong" => "wrong public fixture\n".to_owned(),
                _ => format!("{passphrase}\n"),
            };
            let output = run_with_input(&binary, &as_refs(&args), &root, input.as_bytes());
            if matches!(scenario, "no-flag" | "wrong") {
                assert!(
                    !output.status.success(),
                    "{label} {scenario} unexpectedly succeeded"
                );
                if scenario == "no-flag" {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-legacy-kdf"));
                    assert!(!String::from_utf8_lossy(&output.stderr).contains("Passphrase:"));
                }
            } else {
                assert_success(&output, &format!("{label} {scenario}"));
            }
            if matches!(scenario, "migrate" | "scrypt-config") {
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("current Argon2 resource policy")
                );
                let replacement = fs::read(root.join("identity.age")).unwrap();
                let secret = SecretBytes::new(passphrase.as_bytes());
                let before = if scenario == "scrypt-config" {
                    symvault_crypto::decrypt_identity(&original, &secret).unwrap()
                } else {
                    symvault_crypto::decrypt_identity_for_legacy_kdf_migration(&original, &secret)
                        .unwrap()
                };
                let after = symvault_crypto::decrypt_identity(&replacement, &secret).unwrap();
                assert_eq!(
                    symvault_crypto::recipient_string(&before),
                    symvault_crypto::recipient_string(&after)
                );
                assert!(!symvault_crypto::inspect_argon2id_policy(&replacement).unwrap());
                assert_eq!(fs::read(root.join("identity.age.bak")).unwrap(), original);
                assert_eq!(fs::read(root.join("config.yaml.bak")).unwrap(), config);
                let rendered = fs::read_to_string(root.join("config.yaml")).unwrap();
                assert!(
                    rendered.contains("argon2id_time: 3")
                        && rendered.contains("unknown_root: retained")
                );
                assert!(!root.join("index.age").exists());
            } else {
                assert_unchanged(&root, &original);
                assert_eq!(fs::read(root.join("config.yaml")).unwrap(), config);
                assert!(!root.join("config.yaml.bak").exists());
            }
        }
    }
}
