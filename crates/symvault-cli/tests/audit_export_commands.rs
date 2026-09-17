#![deny(unsafe_code)]

#[path = "../src/audit_export_commands.rs"]
mod audit_export_commands;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("symvault-audit-export-{name}-{suffix}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn first_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .next()
        .expect("JSON output")
        .expect("valid JSON output")
}

fn go_export(go: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(go)
        .args(["audit", "export"])
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .output()
        .expect("run Go audit export")
}

#[test]
fn audit_export_json_matches_go_for_filters_and_redaction() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let home = TempDir::new("fixture");
    fs::create_dir_all(home.0.join(".symvault")).expect("audit directory");
    fs::write(
        home.0.join(".symvault/audit-fixture.log"),
        concat!(
            "{\"ts\":\"2020-01-01T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"set\",\"path\":\"safe/password\",\"transport\":\"cli\",\"ok\":true}\n",
            "{\"ts\":\"2020-01-02T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"get\",\"path\":\"private/password\",\"ok\":false}\n",
            "not json\n"
        ),
    )
    .expect("audit fixture");

    let go = PathBuf::from(go);
    let cases: &[&[&str]] = &[
        &["--agent", "fixture", "--format", "json"],
        &[
            "--agent",
            "fixture",
            "--action",
            "get",
            "--failed",
            "--redact-paths",
            "--format",
            "json",
        ],
    ];
    for &args in cases {
        let expected = go_export(&go, &home.0, &args);
        assert!(
            expected.status.success(),
            "Go export failed: {}",
            String::from_utf8_lossy(&expected.stderr)
        );
        let mut actual = Vec::new();
        audit_export_commands::export(
            &home.0,
            &audit_export_commands::Options {
                agent: args[1],
                action: args
                    .iter()
                    .position(|arg| *arg == "--action")
                    .map_or("", |i| args[i + 1]),
                since: "",
                failed_only: args.contains(&"--failed"),
                redact_paths: args.contains(&"--redact-paths"),
                format: "json",
            },
            &mut actual,
        )
        .expect("Rust export");
        assert_eq!(first_json(&actual), first_json(&expected.stdout));
    }
}
