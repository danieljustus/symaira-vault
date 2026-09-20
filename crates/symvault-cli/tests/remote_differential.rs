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
    env::temp_dir().join(format!("symvault-remote-differential-{name}-{suffix}"))
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status, go.status,
        "{case}: status differs\ngo={:?}\nrust={:?}",
        go.status, rust.status
    );
    assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
    assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
}

fn assert_success(output: &Output, case: &str) {
    assert!(
        output.status.success(),
        "{case} failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn remote_status_matches_go_for_local_repository_states() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let bare = temporary_root("bare");
    fs::create_dir_all(&home).expect("home");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            vault.to_str().expect("vault path"),
            "init",
            "--auth",
            "passphrase",
        ],
        &vault,
        &home,
    );
    assert_success(&init, "Rust init");

    let no_remote_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "remote",
        "status",
    ];
    let go_no_remote = run(&go_binary, &no_remote_args, &vault, &home);
    let rust_no_remote = run(&rust_binary, &no_remote_args, &vault, &home);
    assert_success(&go_no_remote, "Go remote status without remote");
    assert_success(&rust_no_remote, "Rust remote status without remote");
    assert_same(&go_no_remote, &rust_no_remote, "no remote text");

    let no_remote_json_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "--output",
        "json",
        "remote",
        "status",
    ];
    let go_no_remote_json = run(&go_binary, &no_remote_json_args, &vault, &home);
    let rust_no_remote_json = run(&rust_binary, &no_remote_json_args, &vault, &home);
    assert_success(&go_no_remote_json, "Go remote status JSON without remote");
    assert_success(
        &rust_no_remote_json,
        "Rust remote status JSON without remote",
    );
    assert_same(&go_no_remote_json, &rust_no_remote_json, "no remote JSON");

    let quiet_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "--quiet",
        "remote",
        "status",
    ];
    let go_quiet = run(&go_binary, &quiet_args, &vault, &home);
    let rust_quiet = run(&rust_binary, &quiet_args, &vault, &home);
    assert_success(&go_quiet, "Go quiet remote status");
    assert_success(&rust_quiet, "Rust quiet remote status");
    assert_same(&go_quiet, &rust_quiet, "no remote quiet");

    Command::new("git")
        .args(["init", "--bare", bare.to_str().expect("bare path")])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("init bare remote");
    let remote_url = bare.to_str().expect("bare path");
    let add_remote = Command::new("git")
        .args([
            "-C",
            vault.to_str().expect("vault path"),
            "remote",
            "add",
            "origin",
            remote_url,
        ])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("add local remote");
    assert_success(&add_remote, "git remote add");

    fs::create_dir_all(home.join(".symvault")).expect("legacy config directory");
    fs::write(
        home.join(".symvault/config.yaml"),
        b"git:\n  auto_push: false\n",
    )
    .expect("auto push config");

    let configured_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "remote",
        "status",
    ];
    let go_configured = run(&go_binary, &configured_args, &vault, &home);
    let rust_configured = run(&rust_binary, &configured_args, &vault, &home);
    assert_success(&go_configured, "Go configured remote status");
    assert_success(&rust_configured, "Rust configured remote status");
    assert_same(&go_configured, &rust_configured, "configured remote text");

    let json_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "--output",
        "json",
        "remote",
        "status",
    ];
    let go_json = run(&go_binary, &json_args, &vault, &home);
    let rust_json = run(&rust_binary, &json_args, &vault, &home);
    assert_success(&go_json, "Go configured remote JSON");
    assert_success(&rust_json, "Rust configured remote JSON");
    assert_same(&go_json, &rust_json, "configured remote JSON");

    let yaml_args = [
        "--vault",
        vault.to_str().expect("vault path"),
        "--output",
        "yaml",
        "remote",
        "status",
    ];
    let go_yaml = run(&go_binary, &yaml_args, &vault, &home);
    let rust_yaml = run(&rust_binary, &yaml_args, &vault, &home);
    assert_success(&go_yaml, "Go configured remote YAML");
    assert_success(&rust_yaml, "Rust configured remote YAML");
    assert_same(&go_yaml, &rust_yaml, "configured remote YAML");

    // Git accepts arbitrary configured URLs; reporting must retain their bytes.
    for url in ["ssh://host/über<&>\u{2028}repo", "ssh://host/line\n  next"] {
        let output = Command::new("git")
            .args([
                "-C",
                vault.to_str().unwrap(),
                "remote",
                "set-url",
                "origin",
                url,
            ])
            .output()
            .expect("set unusual remote URL");
        assert_success(&output, "set unusual URL");
        for args in [&json_args, &yaml_args] {
            let go = run(&go_binary, args, &vault, &home);
            let rust = run(&rust_binary, args, &vault, &home);
            assert_success(&go, "Go unusual URL");
            assert_same(&go, &rust, "unusual remote URL");
        }
    }

    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&vault);
    let _ = fs::remove_dir_all(&bare);
}

fn initialized_remote_fixture(name: &str) -> (PathBuf, PathBuf) {
    let home = temporary_root(&format!("{name}-home"));
    let vault = temporary_root(&format!("{name}-vault"));
    fs::create_dir_all(home.join(".symvault")).expect("legacy config directory");
    fs::create_dir_all(&vault).expect("vault directory");
    fs::write(vault.join("identity.age"), b"synthetic identity marker").expect("identity");
    fs::write(vault.join("config.yaml"), b"authMethod: passphrase\n").expect("vault config");
    fs::write(
        home.join(".symvault/config.yaml"),
        b"git:\n  auto_push: false\n",
    )
    .expect("user config");
    let git = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&vault)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("initialize git repository");
    assert_success(&git, "initialize remote fixture repository");
    (home, vault)
}

#[test]
fn remote_init_matches_go_for_target_forms_and_rejects_empty_target() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let (go_home, go_vault) = initialized_remote_fixture("default-go");
    let (rust_home, rust_vault) = initialized_remote_fixture("default-rust");
    let go_args = [
        "--vault",
        go_vault.to_str().expect("Go vault path"),
        "remote",
        "init",
        "alice@example.test",
    ];
    let rust_args = [
        "--vault",
        rust_vault.to_str().expect("Rust vault path"),
        "remote",
        "init",
        "alice@example.test",
    ];
    let go = run(&go_binary, &go_args, &go_vault, &go_home);
    let rust = run(&rust_binary, &rust_args, &rust_vault, &rust_home);
    assert_success(&go, "Go remote init default target");
    assert_success(&rust, "Rust remote init default target");
    assert_same(&go, &rust, "remote init default target");

    let go_url = Command::new("git")
        .args([
            "-C",
            go_vault.to_str().unwrap(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .expect("read Go remote URL");
    let rust_url = Command::new("git")
        .args([
            "-C",
            rust_vault.to_str().unwrap(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .expect("read Rust remote URL");
    assert_eq!(go_url.stdout, rust_url.stdout, "remote init URL");
    assert_eq!(
        go_url.stdout,
        b"ssh://alice@example.test/~symvault-remote.git\n"
    );

    let (go_home, go_vault) = initialized_remote_fixture("custom-go");
    let (rust_home, rust_vault) = initialized_remote_fixture("custom-rust");
    let go_args = [
        "--vault",
        go_vault.to_str().expect("Go custom vault path"),
        "remote",
        "init",
        "alice@example.test:/srv/ignored.git",
        "--name",
        "upstream",
        "--path",
        "/srv/custom.git",
    ];
    let rust_args = [
        "--vault",
        rust_vault.to_str().expect("Rust custom vault path"),
        "remote",
        "init",
        "alice@example.test:/srv/ignored.git",
        "--name",
        "upstream",
        "--path",
        "/srv/custom.git",
    ];
    let go = run(&go_binary, &go_args, &go_vault, &go_home);
    let rust = run(&rust_binary, &rust_args, &rust_vault, &rust_home);
    assert_success(&go, "Go remote init custom target");
    assert_success(&rust, "Rust remote init custom target");
    assert_same(&go, &rust, "remote init custom target");

    let (go_home, go_vault) = initialized_remote_fixture("empty-go");
    let (rust_home, rust_vault) = initialized_remote_fixture("empty-rust");
    let go_args = [
        "--vault",
        go_vault.to_str().expect("Go empty vault path"),
        "remote",
        "init",
        "   ",
    ];
    let rust_args = [
        "--vault",
        rust_vault.to_str().expect("Rust empty vault path"),
        "remote",
        "init",
        "   ",
    ];
    let go = run(&go_binary, &go_args, &go_vault, &go_home);
    let rust = run(&rust_binary, &rust_args, &rust_vault, &rust_home);
    assert_same(&go, &rust, "remote init empty target");

    for path in [go_home, go_vault, rust_home, rust_vault] {
        let _ = fs::remove_dir_all(path);
    }
}
