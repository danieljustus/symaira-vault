use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

fn run(binary: &Path, home: &Path, temp: &Path, vault: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(binary);
    if let Some(vault) = vault {
        command.arg("--vault").arg(vault);
    }
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", temp)
        .env("TMP", temp)
        .env("TEMP", temp)
        .env("SYMVAULT_PASSPHRASE", "fixture-passphrase-123")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env_remove("SYMVAULT_VAULT")
        .output()
        .expect("run dynamic generate")
}

fn initialize(binary: &Path, home: &Path, temp: &Path, vault: &Path) {
    let output = run(
        binary,
        home,
        temp,
        Some(vault),
        &["init", "--auth", "passphrase"],
    );
    assert!(
        output.status.success(),
        "initialize disposable vault: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .expect("read vault directory")
        .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn generate_matches_go_for_required_flags_and_missing_engine() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let root = TempDir::new().expect("create disposable root");
    let go_home = root.path().join("go-home");
    let rust_home = root.path().join("rust-home");
    let temp = root.path().join("tmp");
    let go_vault = root.path().join("go-vault");
    let rust_vault = root.path().join("rust-vault");
    for path in [&go_home, &rust_home, &temp] {
        fs::create_dir_all(path).expect("create disposable directory");
    }
    initialize(&rust, &go_home, &temp, &go_vault);
    initialize(&rust, &rust_home, &temp, &rust_vault);
    // Go's first open of a newly initialized vault writes its migration marker,
    // manifest, and lock. Do that before measuring generate's side effects.
    let opened = run(&go, &go_home, &temp, Some(&go_vault), &["list"]);
    assert!(opened.status.success(), "Go first open: {opened:?}");

    // Both current Go engines fail before an external DB/AWS request because
    // the CLI manager does not register a backend.
    let args = [
        "dynamic", "generate", "--engine", "postgres", "--role", "analyst",
    ];
    let go_before = directory_names(&go_vault);
    let rust_before = directory_names(&rust_vault);
    let go_output = run(&go, &go_home, &temp, Some(&go_vault), &args);
    let rust_output = run(&rust, &rust_home, &temp, Some(&rust_vault), &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);
    assert_eq!(go_output.status.code(), Some(1));
    assert_eq!(directory_names(&go_vault), go_before);
    assert_eq!(directory_names(&rust_vault), rust_before);

    // Cobra validates both required flags before looking up the vault.
    let missing_vault = root.path().join("not-initialized");
    let args = ["dynamic", "generate"];
    let go_output = run(&go, &go_home, &temp, Some(&missing_vault), &args);
    let rust_output = run(&rust, &rust_home, &temp, Some(&missing_vault), &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);
}
