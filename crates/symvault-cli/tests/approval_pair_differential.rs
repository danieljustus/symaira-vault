use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, root: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--vault")
        .arg(root)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

#[test]
fn approval_pair_rejects_loopback_server_like_go_oracle() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_binary = PathBuf::from(go_binary);
    let guard = tempfile::tempdir().expect("temporary directory");
    let go_root = guard.path().join("go-vault");
    let rust_root = guard.path().join("rust-vault");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&go_root).expect("Go vault root");
    fs::create_dir_all(&rust_root).expect("Rust vault root");

    let go_init = run(
        &go_binary,
        &go_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(go_init.status.success(), "Go init: {go_init:?}");
    let rust_init = run(
        &rust_binary,
        &rust_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(rust_init.status.success(), "Rust init: {rust_init:?}");

    for root in [&go_root, &rust_root] {
        fs::write(
            root.join(".runtime-port"),
            br#"{"port":18443,"bind":"127.0.0.1"}"#,
        )
        .expect("write runtime server metadata");
    }

    let go_pair = run(
        &go_binary,
        &go_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    let rust_pair = run(
        &rust_binary,
        &rust_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !go_pair.status.success(),
        "Go unexpectedly paired: {go_pair:?}"
    );
    assert!(
        !rust_pair.status.success(),
        "Rust unexpectedly paired: {rust_pair:?}"
    );
    for (name, output) in [("Go", go_pair), ("Rust", rust_pair)] {
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("127.0.0.1 (loopback-only)"),
            "{name} error did not explain loopback binding: {message}"
        );
    }
}
