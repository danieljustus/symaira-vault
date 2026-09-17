use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_root(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-profile-differential-{name}-{suffix}"))
}

fn run(binary: &Path, args: &[&str], home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: status={:?}\nstdout={:?}\nstderr={:?}",
        output.status,
        output.stdout,
        output.stderr
    );
}

fn assert_same(go: &Output, rust: &Output, command: &str) {
    assert_success(go, &format!("Go {command}"));
    assert_success(rust, &format!("Rust {command}"));
    assert_eq!(rust.stdout, go.stdout, "{command} stdout");
    assert_eq!(rust.stderr, go.stderr, "{command} stderr");
}

#[test]
fn profile_list_matches_go_for_empty_and_go_generated_profile_config() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));

    let empty_home = temporary_root("empty");
    fs::create_dir_all(&empty_home).expect("empty home");
    let go_empty = run(&go_binary, &["profile", "list"], &empty_home);
    let rust_empty = run(&rust_binary, &["profile", "list"], &empty_home);
    assert_same(&go_empty, &rust_empty, "profile list empty");

    let quiet_go_empty = run(&go_binary, &["--quiet", "profile", "list"], &empty_home);
    let quiet_rust_empty = run(&rust_binary, &["--quiet", "profile", "list"], &empty_home);
    assert_same(
        &quiet_go_empty,
        &quiet_rust_empty,
        "quiet profile list empty",
    );

    let profile_home = temporary_root("profile");
    fs::create_dir_all(&profile_home).expect("profile home");
    let add = run(
        &go_binary,
        &[
            "profile",
            "add",
            "über.work[dev]",
            "--vault",
            "/fixture-vault/東京",
        ],
        &profile_home,
    );
    assert_success(&add, "Go profile add");

    // Go profile add saves through the XDG default config path, while profile
    // list intentionally loads the legacy HOME/.symvault path. Copy the
    // bytes produced by Go so this fixture exercises the actual loader input
    // without inventing YAML or relying on profile-list's path mismatch.
    let generated = profile_home.join("config/symaira-vault/config.yaml");
    let legacy = profile_home.join(".symvault/config.yaml");
    fs::create_dir_all(legacy.parent().expect("legacy parent")).expect("legacy directory");
    fs::copy(generated, &legacy).expect("copy Go generated config");

    let use_profile = run(
        &go_binary,
        &["profile", "use", "über.work[dev]"],
        &profile_home,
    );
    assert_success(&use_profile, "Go profile use");

    let go_profile = run(&go_binary, &["profile", "list"], &profile_home);
    let rust_profile = run(&rust_binary, &["profile", "list"], &profile_home);
    assert_same(&go_profile, &rust_profile, "profile list profile");

    let go_add_home = temporary_root("go-add");
    let rust_add_home = temporary_root("rust-add");
    fs::create_dir_all(&go_add_home).expect("Go add home");
    fs::create_dir_all(&rust_add_home).expect("Rust add home");
    let go_add = run(
        &go_binary,
        &[
            "profile",
            "add",
            "über.work[dev]",
            "--vault",
            "/fixture-vault/東京",
        ],
        &go_add_home,
    );
    let rust_add = run(
        &rust_binary,
        &[
            "profile",
            "add",
            "über.work[dev]",
            "--vault",
            "/fixture-vault/東京",
        ],
        &rust_add_home,
    );
    assert_same(&go_add, &rust_add, "profile add");
    let quiet_go_add = run(
        &go_binary,
        &[
            "--quiet",
            "profile",
            "add",
            "über.work[dev]",
            "--vault",
            "/fixture-vault/東京",
        ],
        &go_add_home,
    );
    let quiet_rust_add = run(
        &rust_binary,
        &[
            "--quiet",
            "profile",
            "add",
            "über.work[dev]",
            "--vault",
            "/fixture-vault/東京",
        ],
        &rust_add_home,
    );
    assert_same(&quiet_go_add, &quiet_rust_add, "quiet profile add");
    let go_generated = go_add_home.join("config/symaira-vault/config.yaml");
    let rust_generated = rust_add_home.join("config/symaira-vault/config.yaml");
    assert!(go_generated.is_file(), "Go profile destination");
    assert!(rust_generated.is_file(), "Rust profile destination");

    let go_legacy = go_add_home.join(".symvault/config.yaml");
    let rust_legacy = rust_add_home.join(".symvault/config.yaml");
    fs::create_dir_all(go_legacy.parent().expect("Go legacy parent")).expect("Go legacy");
    fs::create_dir_all(rust_legacy.parent().expect("Rust legacy parent")).expect("Rust legacy");
    fs::copy(go_generated, &go_legacy).expect("seed Go legacy config");
    fs::copy(rust_generated, &rust_legacy).expect("seed Rust legacy config");
    let mut rust_bytes = fs::read(&rust_legacy).expect("read Rust legacy config");
    rust_bytes.extend_from_slice(b"customUnknown: keep\n");
    fs::write(&rust_legacy, rust_bytes).expect("add unknown Rust config field");

    let go_use = run(
        &go_binary,
        &["profile", "use", "über.work[dev]"],
        &go_add_home,
    );
    let rust_use = run(
        &rust_binary,
        &["profile", "use", "über.work[dev]"],
        &rust_add_home,
    );
    assert_same(&go_use, &rust_use, "profile use");
    let preserved = String::from_utf8(fs::read(&rust_legacy).expect("read updated Rust config"))
        .expect("Rust config UTF-8");
    assert!(preserved.contains("customUnknown: keep"));

    let go_missing = run(&go_binary, &["profile", "use", "missing"], &go_add_home);
    let rust_missing = run(&rust_binary, &["profile", "use", "missing"], &rust_add_home);
    assert_eq!(go_missing.status.code(), rust_missing.status.code());
    assert_eq!(
        go_missing.stdout, rust_missing.stdout,
        "missing profile stdout"
    );
    assert_eq!(
        go_missing.stderr, rust_missing.stderr,
        "missing profile stderr"
    );

    let _ = fs::remove_dir_all(empty_home);
    let _ = fs::remove_dir_all(profile_home);
    let _ = fs::remove_dir_all(go_add_home);
    let _ = fs::remove_dir_all(rust_add_home);
}

#[cfg(unix)]
#[test]
fn profile_add_keeps_symlink_destination_and_target_unchanged() {
    let Some(rust_binary) = env::var_os("CARGO_BIN_EXE_symvault") else {
        eprintln!("skipping Rust profile safety test: Rust binary is not set");
        return;
    };
    use std::os::unix::fs::symlink;

    let home = temporary_root("symlink");
    fs::create_dir_all(home.join("config/symaira-vault")).expect("config directory");
    let target = home.join("sentinel");
    fs::write(&target, b"keep me").expect("sentinel");
    let destination = home.join("config/symaira-vault/config.yaml");
    symlink(&target, &destination).expect("destination symlink");

    let result = run(
        &PathBuf::from(rust_binary),
        &["profile", "add", "work", "--vault", "/fixture-vault"],
        &home,
    );
    assert!(!result.status.success(), "symlink destination was accepted");
    assert_eq!(
        fs::read(&target).expect("sentinel after failure"),
        b"keep me"
    );
    assert!(
        fs::symlink_metadata(destination)
            .expect("destination metadata")
            .file_type()
            .is_symlink()
    );
    let _ = fs::remove_dir_all(home);
}

#[cfg(unix)]
#[test]
fn profile_add_keeps_invalid_existing_config_unchanged() {
    let Some(rust_binary) = env::var_os("CARGO_BIN_EXE_symvault") else {
        eprintln!("skipping Rust profile safety test: Rust binary is not set");
        return;
    };
    let home = temporary_root("invalid");
    let config = home.join(".symvault/config.yaml");
    fs::create_dir_all(config.parent().expect("legacy parent")).expect("legacy directory");
    fs::write(&config, b"profiles: [\n").expect("invalid config");

    let result = run(
        &PathBuf::from(rust_binary),
        &["profile", "add", "work", "--vault", "/fixture-vault"],
        &home,
    );
    assert!(!result.status.success(), "invalid config was overwritten");
    assert_eq!(
        fs::read(&config).expect("config after failure"),
        b"profiles: [\n"
    );
    let _ = fs::remove_dir_all(home);
}
