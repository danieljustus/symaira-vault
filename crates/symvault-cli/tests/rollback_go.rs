use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

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

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, relative: &Path, files: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(root.join(relative)).expect("read vault tree") {
            let entry = entry.expect("vault tree entry");
            let path = relative.join(entry.file_name());
            let kind = entry.file_type().expect("vault tree entry type");
            if kind.is_dir() {
                files.insert(path.clone(), None);
                visit(root, &path, files);
            } else if kind.is_file() {
                files.insert(
                    path.clone(),
                    Some(fs::read(root.join(path)).expect("vault file")),
                );
            } else {
                panic!("rollback fixture contains a non-regular file");
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, Path::new(""), &mut files);
    files
}

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    run_with_passphrase(binary, vault, home, args, "rollback-fixture-passphrase")
}

fn run_with_passphrase(
    binary: &Path,
    vault: &Path,
    home: &Path,
    args: &[&str],
    passphrase: &str,
) -> std::process::Output {
    Command::new(binary)
        .args(["--vault", vault.to_str().expect("UTF-8 vault path")])
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", passphrase)
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
    let original_tree = snapshot(&source);
    copy_tree(&source, &copy);
    assert_eq!(
        snapshot(&copy),
        original_tree,
        "copied vault differs from source"
    );

    let wrong_passphrase = run_with_passphrase(
        go,
        &copy,
        &home,
        &["get", "rollback/check.password", "--print"],
        "wrong-rollback-fixture-passphrase",
    );
    assert!(
        !wrong_passphrase.status.success(),
        "Go should reject the wrong passphrase"
    );
    assert_eq!(
        snapshot(&copy),
        original_tree,
        "failed Go unlock changed copied Rust vault"
    );
    assert_eq!(
        snapshot(&source),
        original_tree,
        "failed Go unlock changed source Rust vault"
    );

    let corrupt_archive = temp.path().join("corrupt-backup.tar.gz");
    fs::write(&corrupt_archive, b"not a valid gzip or tar archive").expect("corrupt archive");
    let rejected = run(
        go,
        &copy,
        &home,
        &[
            "restore",
            corrupt_archive.to_str().expect("UTF-8 archive path"),
        ],
    );
    assert!(
        !rejected.status.success(),
        "Go restore should reject corrupt archive: {rejected:?}"
    );
    assert_eq!(
        snapshot(&copy),
        original_tree,
        "failed Go restore changed copied Rust vault"
    );
    assert_eq!(
        snapshot(&source),
        original_tree,
        "failed Go restore changed source Rust vault"
    );

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
    assert_eq!(snapshot(&source), original_tree, "source vault changed");
}
