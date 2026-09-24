use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PASSPHRASE: &str = "csv import differential fixture";

fn run(binary: &Path, args: &[&str], home: &Path, vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

#[test]
fn csv_import_auto_detects_and_matches_go_cli_output_and_entries() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let temp = tempfile::tempdir().expect("temporary import root");
    let go_home = temp.path().join("go-home");
    let rust_home = temp.path().join("rust-home");
    let go_vault = temp.path().join("go-vault");
    let rust_vault = temp.path().join("rust-vault");
    for dir in [&go_home, &rust_home] {
        std::fs::create_dir_all(dir).expect("create temporary HOME");
    }

    for (binary, home, vault) in [
        (&go_binary, &go_home, &go_vault),
        (&rust_binary, &rust_home, &rust_vault),
    ] {
        let initialized = run(binary, &["init", "--auth", "passphrase"], home, vault);
        assert!(
            initialized.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&initialized.stderr)
        );
    }

    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/importer/csv/sample.csv");
    let fixture = fixture.to_str().expect("UTF-8 fixture path");
    let args = ["import", fixture];
    let go = run(&go_binary, &args, &go_home, &go_vault);
    let rust = run(&rust_binary, &args, &rust_home, &rust_vault);
    assert_eq!(go.status.code(), Some(0), "Go import: {:?}", go.stderr);
    assert_eq!(
        rust.status.code(),
        Some(0),
        "Rust import: {:?}",
        rust.stderr
    );
    assert_eq!(rust.stdout, go.stdout, "CSV import output differs");
    assert_eq!(rust.stderr, go.stderr, "CSV import stderr differs");
    assert!(
        String::from_utf8_lossy(&rust.stdout).contains("Import summary: 3 imported, 0 skipped")
    );

    for (path, expected) in [
        (
            "GitHub,-Personal",
            [
                ("username", "user@example.com"),
                ("password", "mysecretpassword"),
                ("url", "https://github.com/login"),
            ],
        ),
        (
            "Bank-Checking",
            [
                ("username", "bank.user@example.com"),
                ("password", "p@ss,with,commas"),
                ("url", "https://bank.example.com/login"),
            ],
        ),
        (
            "Work-AWS",
            [
                ("username", "admin@company.com"),
                ("password", "work-aws-secret"),
                ("url", "https://aws.amazon.com"),
            ],
        ),
    ] {
        let args = ["get", path, "--output", "json"];
        let go = run(&go_binary, &args, &go_home, &go_vault);
        let rust = run(&rust_binary, &args, &rust_home, &rust_vault);
        assert_eq!(go.status.code(), Some(0), "Go get {path}: {:?}", go.stderr);
        assert_eq!(
            rust.status.code(),
            Some(0),
            "Rust get {path}: {:?}",
            rust.stderr
        );
        let go: serde_json::Value = serde_json::from_slice(&go.stdout).expect("Go entry JSON");
        let rust: serde_json::Value =
            serde_json::from_slice(&rust.stdout).expect("Rust entry JSON");
        assert_eq!(
            rust["Fields"], go["Fields"],
            "entry data differs for {path}"
        );
        for (field, value) in expected {
            assert_eq!(rust["Fields"][field], value, "{path}.{field}");
        }
    }
}
