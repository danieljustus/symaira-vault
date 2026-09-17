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
    env::temp_dir().join(format!("symvault-cli-differential-{name}-{suffix}"))
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
        .output()
        .expect("run CLI")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_initialized(root: &Path) {
    assert!(root.join("config.yaml").is_file());
    let identity = fs::read(root.join("identity.age")).expect("identity");
    assert!(identity.starts_with(b"age-encryption.org/v1\n"));
    assert!(root.join(".git").is_dir());
    assert!(root.join(".gitignore").is_file());
}

#[test]
fn init_list_get_match_go_cli_on_a_disposable_vault() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("home");
    let rust_root = temporary_root("rust");
    let go_root = temporary_root("go");
    fs::create_dir_all(&home).expect("home");

    let rust_init = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_init, "Rust init");
    assert_initialized(&rust_root);

    let go_set = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.password",
            "--value",
            "secret",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_set, "Go set");

    let go_list = run(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    let rust_list = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    assert_success(&go_list, "Go list");
    assert_success(&rust_list, "Rust list");
    assert_eq!(go_list.stdout, b"work/github\n");
    assert_eq!(rust_list.stdout, go_list.stdout);

    let go_get = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    let rust_get = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_get, "Go get");
    assert_success(&rust_get, "Rust get");
    assert_eq!(go_get.stdout, b"secret\n");
    assert_eq!(rust_get.stdout, go_get.stdout);

    let go_json = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_json = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_json, "Go get JSON");
    assert_success(&rust_json, "Rust get JSON");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rust_json.stdout).expect("Rust JSON"),
        serde_json::from_slice::<serde_json::Value>(&go_json.stdout).expect("Go JSON")
    );

    let go_init = run(
        &go_binary,
        &[
            "--vault",
            go_root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &go_root,
        &home,
    );
    assert_success(&go_init, "Go init");
    assert_initialized(&go_root);

    fs::remove_dir_all(home).expect("cleanup home");
    fs::remove_dir_all(rust_root).expect("cleanup Rust vault");
    fs::remove_dir_all(go_root).expect("cleanup Go vault");
}
