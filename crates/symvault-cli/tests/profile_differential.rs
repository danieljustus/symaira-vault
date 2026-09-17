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
        &["profile", "add", "work", "--vault", "/fixture-vault"],
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

    let use_profile = run(&go_binary, &["profile", "use", "work"], &profile_home);
    assert_success(&use_profile, "Go profile use");
    fs::copy(
        profile_home.join("config/symaira-vault/config.yaml"),
        &legacy,
    )
    .expect("copy Go generated default profile config");

    let go_profile = run(&go_binary, &["profile", "list"], &profile_home);
    let rust_profile = run(&rust_binary, &["profile", "list"], &profile_home);
    assert_same(&go_profile, &rust_profile, "profile list profile");

    let _ = fs::remove_dir_all(empty_home);
    let _ = fs::remove_dir_all(profile_home);
}
