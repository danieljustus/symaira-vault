use std::{env, fs, path::Path, process::Command};

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("copy vault directory");
    for entry in fs::read_dir(source).expect("read vault directory") {
        let entry = entry.expect("vault entry");
        let target = destination.join(entry.file_name());
        let kind = entry.file_type().expect("vault entry type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            fs::copy(entry.path(), target).expect("copy vault file");
        } else {
            panic!("rollback fixture contains a non-regular file");
        }
    }
}

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .args(["--vault", vault.to_str().expect("UTF-8 vault path")])
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", "rollback-fixture-passphrase")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .output()
        .expect("run vault CLI")
}

#[test]
fn go_mutates_copied_rust_vault_without_touching_source() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go rollback differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let go = Path::new(&go);
    let temp = tempfile::tempdir().expect("temporary rollback root");
    let home = temp.path().join("home");
    fs::create_dir(&home).expect("home");
    let source = temp.path().join("source");
    let copy = temp.path().join("copy");
    let initialized = run(rust, &source, &home, &["init", "--auth", "passphrase"]);
    assert!(initialized.status.success(), "Rust init: {initialized:?}");
    let original_config = fs::read(source.join("config.yaml")).unwrap();
    let original_identity = fs::read(source.join("identity.age")).unwrap();
    let original_recipients = fs::read(source.join("recipients.txt")).ok();
    copy_tree(&source, &copy);

    let written = run(
        go,
        &copy,
        &home,
        &[
            "set",
            "rollback/check.password",
            "--value",
            "copied-secret",
            "--force",
        ],
    );
    assert!(written.status.success(), "Go set copied vault: {written:?}");
    for binary in [go, rust] {
        let read = run(
            binary,
            &copy,
            &home,
            &["get", "rollback/check.password", "--print"],
        );
        assert_eq!(read.status.code(), Some(0), "read copied vault: {read:?}");
        assert_eq!(read.stdout, b"copied-secret\n");
    }
    assert_eq!(
        fs::read(source.join("config.yaml")).unwrap(),
        original_config
    );
    assert_eq!(
        fs::read(source.join("identity.age")).unwrap(),
        original_identity
    );
    assert_eq!(
        fs::read(source.join("recipients.txt")).ok(),
        original_recipients
    );
    assert!(!source.join("entries/rollback/check.age").exists());
}
