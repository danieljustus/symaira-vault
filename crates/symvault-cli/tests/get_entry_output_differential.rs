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

fn normalize_yaml_totp_clock(output: &[u8]) -> String {
    let output = String::from_utf8(output.to_vec()).expect("YAML output is UTF-8");
    let mut normalized = output
        .lines()
        .map(|line| {
            let indent = &line[..line.len() - line.trim_start().len()];
            match line.trim_start() {
                value if value.starts_with("code:") => format!("{indent}code: <CODE>"),
                value if value.starts_with("remaining:") => {
                    format!("{indent}remaining: <REMAINING>")
                }
                _ => line.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    normalized.push('\n');
    normalized
}

#[test]
fn get_entry_json_and_yaml_match_go() {
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
        &[
            "add",
            "example",
            "--value",
            "sample",
            "--username",
            "alice",
            "--url",
            "https://example.test",
            "--notes",
            "fixture",
            "--force",
        ],
        home.path(),
        &vault,
    );
    assert!(added.status.success(), "Go add failed: {:?}", added.stderr);

    for format in ["json", "yaml"] {
        let args = ["get", "example", "--output", format];
        let go = run(&go_binary, &args, home.path(), &vault);
        let rust = run(&rust_binary, &args, home.path(), &vault);
        assert_eq!(go.status.code(), Some(0), "Go {format}: {:?}", go.stderr);
        assert_eq!(
            rust.status.code(),
            Some(0),
            "Rust {format}: {:?}",
            rust.stderr
        );
        assert_eq!(rust.stdout, go.stdout, "Rust {format} stdout differs");
        assert_eq!(rust.stderr, go.stderr, "Rust {format} stderr differs");
    }

    let added_totp = run(
        &go_binary,
        &[
            "add",
            "totp",
            "--value",
            "fallback",
            "--type",
            "totp_seed",
            "--totp-secret",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "--totp-account",
            "alice",
            "--totp-issuer",
            "Example",
            "--force",
        ],
        home.path(),
        &vault,
    );
    assert!(
        added_totp.status.success(),
        "Go TOTP add failed: {:?}",
        added_totp.stderr
    );

    for format in ["json", "yaml"] {
        let args = ["get", "totp", "--output", format];
        let go = run(&go_binary, &args, home.path(), &vault);
        let rust = run(&rust_binary, &args, home.path(), &vault);
        assert_eq!(go.status.code(), Some(0), "Go {format}: {:?}", go.stderr);
        assert_eq!(
            rust.status.code(),
            Some(0),
            "Rust {format}: {:?}",
            rust.stderr
        );
        assert_eq!(rust.stderr, go.stderr, "Rust {format} stderr differs");
        if format == "json" {
            let mut go_value: serde_json::Value =
                serde_json::from_slice(&go.stdout).expect("Go JSON");
            let mut rust_value: serde_json::Value =
                serde_json::from_slice(&rust.stdout).expect("Rust JSON");
            for value in [&mut go_value, &mut rust_value] {
                let totp = value["TOTP"].as_object_mut().expect("TOTP object");
                totp.insert(
                    "code".to_owned(),
                    serde_json::Value::String("CODE".to_owned()),
                );
                totp.insert("remaining".to_owned(), serde_json::Value::from(0));
            }
            assert_eq!(rust_value, go_value, "Rust {format} structure differs");
        } else {
            assert_eq!(
                normalize_yaml_totp_clock(&rust.stdout),
                normalize_yaml_totp_clock(&go.stdout),
                "Rust {format} bytes differ outside the time-dependent TOTP values"
            );
            let mut go_value: serde_yaml_ng::Value =
                serde_yaml_ng::from_slice(&go.stdout).expect("Go YAML");
            let mut rust_value: serde_yaml_ng::Value =
                serde_yaml_ng::from_slice(&rust.stdout).expect("Rust YAML");
            for value in [&mut go_value, &mut rust_value] {
                let totp_key = serde_yaml_ng::Value::String("totp".to_owned());
                let totp = value
                    .as_mapping_mut()
                    .and_then(|mapping| mapping.get_mut(&totp_key))
                    .and_then(serde_yaml_ng::Value::as_mapping_mut)
                    .expect("TOTP object");
                totp.insert(
                    serde_yaml_ng::Value::String("code".to_owned()),
                    serde_yaml_ng::Value::String("CODE".to_owned()),
                );
                totp.insert(
                    serde_yaml_ng::Value::String("remaining".to_owned()),
                    serde_yaml_ng::Value::Number(0.into()),
                );
            }
            assert_eq!(rust_value, go_value, "Rust {format} structure differs");
        }
    }
}
