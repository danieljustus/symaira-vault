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
    env::temp_dir().join(format!("symvault-sync-differential-{name}-{suffix}"))
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

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(rust.status, go.status, "{case}: status differs");
    assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
    assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
}

fn sync_args(vault: &Path, push: bool, force: bool) -> Vec<String> {
    let mut args = vec![
        "--vault".to_owned(),
        vault.to_str().expect("vault path").to_owned(),
        "sync".to_owned(),
    ];
    if push {
        args.push("--push".to_owned());
    }
    if force {
        args.push("--force".to_owned());
    }
    args
}

fn arg_refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn sync_matches_go_for_no_remote_pull_push_and_offline_local_remote() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let bare = temporary_root("bare");
    let remote_work = temporary_root("remote-work");
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

    let no_remote = sync_args(&vault, false, false);
    let no_remote = arg_refs(&no_remote);
    let go_no_remote = run(&go_binary, &no_remote, &vault, &home);
    let rust_no_remote = run(&rust_binary, &no_remote, &vault, &home);
    assert_success(&go_no_remote, "Go sync without remote");
    assert_success(&rust_no_remote, "Rust sync without remote");
    assert_same(&go_no_remote, &rust_no_remote, "sync without remote");

    git(&vault, &["config", "user.name", "Symaira Vault Test"]);
    git(
        &vault,
        &["config", "user.email", "symvault-test@example.invalid"],
    );
    fs::write(vault.join("sync.txt"), b"base\n").expect("base file");
    git(&vault, &["add", ".gitignore", "sync.txt"]);
    git(&vault, &["commit", "--quiet", "-m", "base"]);
    fs::create_dir_all(&bare).expect("bare parent");
    git(&bare, &["init", "--bare", "--quiet"]);
    git(
        &vault,
        &["remote", "add", "origin", bare.to_str().expect("bare path")],
    );
    git(
        &vault,
        &["push", "--quiet", "--set-upstream", "origin", "HEAD"],
    );
    git(&bare, &["config", "receive.denyCurrentBranch", "ignore"]);
    let clone = Command::new("git")
        .args(["clone", "--quiet", bare.to_str().expect("bare path")])
        .arg(&remote_work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("clone remote");
    assert_success(&clone, "clone remote");
    git(
        &remote_work,
        &["config", "user.name", "Symaira Remote Test"],
    );
    git(
        &remote_work,
        &["config", "user.email", "symvault-remote@example.invalid"],
    );

    fs::write(remote_work.join("sync.txt"), b"remote-one\n").expect("remote file");
    git(&remote_work, &["commit", "--quiet", "-am", "remote-one"]);
    git(&remote_work, &["push", "--quiet", "origin", "HEAD"]);
    let pull = sync_args(&vault, false, false);
    let pull = arg_refs(&pull);
    let go_pull = run(&go_binary, &pull, &vault, &home);
    assert_success(&go_pull, "Go pull sync");
    assert_eq!(
        fs::read(vault.join("sync.txt")).expect("Go pull file"),
        b"remote-one\n"
    );

    fs::write(remote_work.join("sync.txt"), b"remote-two\n").expect("remote file two");
    git(&remote_work, &["commit", "--quiet", "-am", "remote-two"]);
    git(&remote_work, &["push", "--quiet", "origin", "HEAD"]);
    let rust_pull = run(&rust_binary, &pull, &vault, &home);
    assert_success(&rust_pull, "Rust pull sync");
    assert_eq!(
        fs::read(vault.join("sync.txt")).expect("Rust pull file"),
        b"remote-two\n"
    );
    assert_eq!(go_pull.stdout, rust_pull.stdout, "pull stdout");
    assert_eq!(go_pull.stderr, rust_pull.stderr, "pull stderr");
    assert!(vault.join(".git/symvault-last-sync").is_file());

    fs::write(remote_work.join("sync.txt"), b"remote-force\n").expect("force remote file");
    git(&remote_work, &["commit", "--quiet", "-am", "remote-force"]);
    git(&remote_work, &["push", "--quiet", "origin", "HEAD"]);
    let force = sync_args(&vault, false, true);
    let force = arg_refs(&force);
    let rust_force = run(&rust_binary, &force, &vault, &home);
    assert_success(&rust_force, "Rust force sync");
    assert_eq!(
        fs::read(vault.join("sync.txt")).expect("Rust force file"),
        b"remote-force\n"
    );

    fs::write(vault.join("local-go.txt"), b"go\n").expect("Go local file");
    git(&vault, &["add", "local-go.txt"]);
    git(&vault, &["commit", "--quiet", "-m", "local-go"]);
    let push = sync_args(&vault, true, false);
    let push = arg_refs(&push);
    let go_push = run(&go_binary, &push, &vault, &home);
    assert_success(&go_push, "Go push sync");

    fs::write(vault.join("local-rust.txt"), b"rust\n").expect("Rust local file");
    git(&vault, &["add", "local-rust.txt"]);
    git(&vault, &["commit", "--quiet", "-m", "local-rust"]);
    let rust_push = run(&rust_binary, &push, &vault, &home);
    assert_success(&rust_push, "Rust push sync");
    assert_eq!(go_push.stdout, rust_push.stdout, "push stdout");
    assert_eq!(go_push.stderr, rust_push.stderr, "push stderr");

    git(
        &vault,
        &[
            "remote",
            "set-url",
            "origin",
            "http://127.0.0.1:1/vault.git",
        ],
    );
    let offline = sync_args(&vault, false, false);
    let offline = arg_refs(&offline);
    let go_offline = run(&go_binary, &offline, &vault, &home);
    let rust_offline = run(&rust_binary, &offline, &vault, &home);
    assert_success(&go_offline, "Go offline sync");
    assert_success(&rust_offline, "Rust offline sync");
    assert_same(&go_offline, &rust_offline, "offline sync");

    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&vault);
    let _ = fs::remove_dir_all(&bare);
    let _ = fs::remove_dir_all(&remote_work);
}

#[test]
fn force_sync_preserves_dirty_config_like_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("force-home");
    let vault = temporary_root("force-vault");
    let bare = temporary_root("force-bare");
    let go_vault = temporary_root("force-go-vault");
    let rust_vault = temporary_root("force-rust-vault");
    let remote_work = temporary_root("force-remote-work");
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
    assert_success(&init, "Rust force init");
    git(&vault, &["config", "user.name", "Symaira Vault Test"]);
    git(
        &vault,
        &["config", "user.email", "symvault-test@example.invalid"],
    );
    git(&vault, &["add", ".gitignore", "config.yaml"]);
    git(&vault, &["commit", "--quiet", "-m", "base"]);
    fs::create_dir_all(&bare).expect("force bare parent");
    git(&bare, &["init", "--bare", "--quiet"]);
    git(
        &vault,
        &["remote", "add", "origin", bare.to_str().expect("bare path")],
    );
    git(
        &vault,
        &["push", "--quiet", "--set-upstream", "origin", "HEAD"],
    );

    for clone_path in [&go_vault, &rust_vault, &remote_work] {
        let clone = Command::new("git")
            .args(["clone", "--quiet", bare.to_str().expect("bare path")])
            .arg(clone_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("clone force fixture");
        assert_success(&clone, "clone force fixture");
    }
    git(
        &remote_work,
        &["config", "user.name", "Symaira Remote Test"],
    );
    git(
        &remote_work,
        &["config", "user.email", "symvault-remote@example.invalid"],
    );
    let base_config = fs::read(remote_work.join("config.yaml")).expect("base config");
    let mut remote_config = base_config.clone();
    remote_config.extend_from_slice(b"remote_marker: remote\n");
    fs::write(remote_work.join("config.yaml"), remote_config).expect("remote config");
    git(&remote_work, &["add", "config.yaml"]);
    git(&remote_work, &["commit", "--quiet", "-m", "remote-config"]);
    git(&remote_work, &["push", "--quiet", "origin", "HEAD"]);

    for local_path in [&go_vault, &rust_vault] {
        let mut local_config = base_config.clone();
        local_config.extend_from_slice(b"local_marker: local\n");
        fs::write(local_path.join("config.yaml"), local_config).expect("local config");
        fs::write(local_path.join(".device-id"), b"test-device\n").expect("device identity");
    }
    let go_force_args = sync_args(&go_vault, false, true);
    let rust_force_args = sync_args(&rust_vault, false, true);
    let go_force_refs = arg_refs(&go_force_args);
    let rust_force_refs = arg_refs(&rust_force_args);
    let go_force = run(&go_binary, &go_force_refs, &go_vault, &home);
    let rust_force = run(&rust_binary, &rust_force_refs, &rust_vault, &home);
    assert_success(&go_force, "Go dirty force sync");
    assert_success(&rust_force, "Rust dirty force sync");
    assert_same(&go_force, &rust_force, "dirty force sync");
    assert_eq!(
        fs::read(go_vault.join("config.yaml")).expect("Go remote config"),
        fs::read(rust_vault.join("config.yaml")).expect("Rust remote config")
    );
    assert_eq!(
        fs::read(go_vault.join("config.conflict-test-device.yaml")).expect("Go conflict config"),
        fs::read(rust_vault.join("config.conflict-test-device.yaml"))
            .expect("Rust conflict config")
    );
    assert_eq!(
        fs::read(rust_vault.join("config.conflict-test-device.yaml")).expect("Rust local config"),
        {
            let mut expected = base_config.clone();
            expected.extend_from_slice(b"local_marker: local\n");
            expected
        }
    );
    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&vault);
    let _ = fs::remove_dir_all(&bare);
    let _ = fs::remove_dir_all(&go_vault);
    let _ = fs::remove_dir_all(&rust_vault);
    let _ = fs::remove_dir_all(&remote_work);
}
