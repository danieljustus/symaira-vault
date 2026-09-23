use std::{
    env,
    path::Path,
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

#[test]
fn intake_missing_args_and_watch_precedence_match_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");

    for args in [&["intake"][..], &["intake", "watch"]] {
        let go = run(&go_binary, args, home.path());
        let rust = run(rust_binary, args, home.path());
        assert_eq!(
            rust.status.code(),
            go.status.code(),
            "status differs for {args:?}\nGo stderr: {:?}\nRust stderr: {:?}",
            go.stderr,
            rust.stderr
        );
        assert_eq!(rust.stdout, go.stdout, "stdout differs for {args:?}");
        assert_eq!(rust.stderr, go.stderr, "stderr differs for {args:?}");
    }

    assert!(
        !home.path().join(".symvault").exists(),
        "invalid parent arguments must not initialize or access the vault"
    );
}
