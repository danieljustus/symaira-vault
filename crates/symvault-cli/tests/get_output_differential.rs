use std::{
    env,
    path::Path,
    process::{Command, Output},
};

const PASSPHRASE: &str = "differential sample passphrase";

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
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

#[test]
fn get_field_text_json_and_yaml_match_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");
    let vault = home.path().join("vault");

    let initialized = run(
        &go_binary,
        &["init", "--auth", "passphrase"],
        home.path(),
        &vault,
    );
    assert!(
        initialized.status.success(),
        "Go init failed: {:?}",
        initialized.stderr
    );
    let added = run(
        &go_binary,
        &["add", "example", "--value", "sample", "--force"],
        home.path(),
        &vault,
    );
    assert!(added.status.success(), "Go add failed: {:?}", added.stderr);

    for (format, expected) in [
        ("text", b"sample\n".as_slice()),
        ("json", b"\"sample\"\n".as_slice()),
        ("yaml", b"sample\n".as_slice()),
    ] {
        let args = ["get", "example.password", "--output", format];
        let go = run(&go_binary, &args, home.path(), &vault);
        let rust = run(&rust_binary, &args, home.path(), &vault);
        assert_eq!(go.status.code(), Some(0), "Go {format}: {:?}", go.stderr);
        assert_eq!(
            rust.status.code(),
            Some(0),
            "Rust {format}: {:?}",
            rust.stderr
        );
        assert_eq!(go.stdout, expected, "Go {format} output changed");
        assert_eq!(rust.stdout, go.stdout, "Rust {format} stdout differs");
        assert_eq!(rust.stderr, go.stderr, "Rust {format} stderr differs");
    }
}
