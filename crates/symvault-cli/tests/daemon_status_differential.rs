use std::{
    env,
    path::Path,
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], home: &Path, vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

#[test]
fn mcp_and_serve_status_match_go_for_disposable_uninstalled_service() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        eprintln!(
            "skipping daemon status differential: Go service status supports macOS and Linux only"
        );
        return;
    }

    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");
    let vault = home.path().join("vault");
    std::fs::create_dir(&vault).expect("create disposable vault");

    for command in ["mcp", "serve"] {
        let args = ["--vault", vault.to_str().unwrap(), command, "status"];
        let go = run(&go_binary, &args, home.path(), &vault);
        let rust = run(&rust_binary, &args, home.path(), &vault);

        assert_eq!(go.status.code(), Some(0), "Go stderr: {:?}", go.stderr);
        assert_eq!(
            rust.status.code(),
            Some(0),
            "Rust stderr: {:?}",
            rust.stderr
        );
        assert_eq!(rust.stdout, go.stdout, "{command} status stdout differs");
        assert_eq!(rust.stderr, go.stderr, "{command} status stderr differs");
        assert!(
            String::from_utf8_lossy(&rust.stdout).contains("Status: not installed\n"),
            "{command} status did not report the disposable service as not installed: {:?}",
            rust.stdout
        );
    }
}
