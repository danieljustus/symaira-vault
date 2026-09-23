use std::{
    env,
    path::Path,
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

fn assert_same(go: &Output, rust: &Output, args: &[&str]) {
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

#[test]
fn print_keybindings_and_argument_errors_match_go_without_a_vault() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");

    for args in [
        &["ui", "--print-keybindings"][..],
        &["ui", "--experimental", "--print-keybindings"][..],
        &["ui", "--print-keybindings", "--experimental"][..],
        &["ui", "extra"][..],
        &["ui", "--print-keybindings", "extra"][..],
        &["ui", "--experimental", "extra"][..],
        &["ui", "--bad-flag"][..],
    ] {
        let go = run(&go_binary, args, home.path());
        let rust = run(&rust_binary, args, home.path());
        assert_same(&go, &rust, args);
    }

    let rust = run(&rust_binary, &["ui"], home.path());
    assert_eq!(rust.status.code(), Some(1));
    assert!(rust.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rust.stderr).contains("interactive UI is not implemented"));
}
