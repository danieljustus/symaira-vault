use std::{env, path::Path, process::Command};

#[test]
fn hidden_agent_setup_matches_go_without_touching_a_vault() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let home = tempfile::tempdir().expect("temporary home");
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    for args in [
        &["agent", "setup"][..],
        &["agent", "setup", "example"][..],
        &["agent", "setup", "example", "extra"][..],
        &["agent", "setup", "--bad"][..],
    ] {
        let run = |binary: &Path| {
            Command::new(binary)
                .args(args)
                .env("HOME", home.path())
                .env("USERPROFILE", home.path())
                .env("XDG_CONFIG_HOME", home.path().join("config"))
                .env("XDG_DATA_HOME", home.path().join("data"))
                .env("XDG_CACHE_HOME", home.path().join("cache"))
                .env("CI", "1")
                .env("NO_COLOR", "1")
                .output()
                .expect("run agent setup")
        };
        let go = run(Path::new(&go_binary));
        let rust = run(rust_binary);
        assert_eq!(rust.status.code(), go.status.code(), "{args:?}");
        assert_eq!(rust.stdout, go.stdout, "{args:?}");
        assert_eq!(rust.stderr, go.stderr, "{args:?}");
    }
}
