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
fn get_and_list_help_and_extra_argument_errors_match_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");

    for args in [
        &["get", "--help"][..],
        &["list", "--help"][..],
        &["help", "get"][..],
        &["help", "list"][..],
        &["get", "entry", "extra"][..],
        &["list", "prefix", "extra"][..],
    ] {
        let go = run(&go_binary, args, home.path());
        let rust = run(&rust_binary, args, home.path());
        assert_same(&go, &rust, args);
    }
}
