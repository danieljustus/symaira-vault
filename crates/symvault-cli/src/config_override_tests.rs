//! Fresh-process replay through the production clap parser and resolve_vault.
use super::*;
use serde::Deserialize;
use std::process::{Command as ProcessCommand, Output, Stdio};

// These children only read ordinary fixture files and never spawn descendants.
fn bounded_output(command: &mut ProcessCommand) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if started.elapsed() > std::time::Duration::from_secs(15) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("config override child timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    config: Option<String>,
    result: serde_json::Value,
}

#[test]
fn child() {
    let Some(path) = std::env::var_os("CFG_OVERRIDES_CASE") else {
        return; // Only the parent invokes the child with a case.
    };
    let case: Case = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let result = match Cli::try_parse_from(std::iter::once("symvault".to_owned()).chain(case.args))
    {
        Err(_) => serde_json::json!({"path":"", "error_class":"flags"}),
        Ok(cli) => match resolve_vault(cli.vault.as_deref(), cli._profile.as_deref()) {
            Ok(path) => {
                let home =
                    std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap();
                let path = path.to_string_lossy().replace(&home, "HOME");
                let path = if cfg!(windows) {
                    path.replace('\\', "/")
                } else {
                    path
                };
                serde_json::json!({"path":path, "error_class":""})
            }
            Err(message) => serde_json::json!({"path":"", "error_class":
                if message.contains("cannot load config") { "config" } else { "profile" }}),
        },
    };
    assert_eq!(result, case.result, "{}", case.name);
}

#[test]
fn overrides_match_go_oracle() {
    let source = std::env::var_os("CFG_OVERRIDES_FIXTURE")
        .map(|path| fs::read_to_string(path).expect("read explicit override corpus"))
        .unwrap_or_else(|| include_str!("../../../testdata/port/config/overrides.json").to_owned());
    let fixture: serde_json::Value = serde_json::from_str(&source).unwrap();
    assert_eq!(
        fixture["oracle"]["commit"],
        "314a25a5cdd2e90517bb55a90495d7b97f68c6df"
    );
    let expected_flags: Vec<String> =
        serde_json::from_value(fixture["root_flags"].clone()).unwrap();
    let command = Cli::command();
    let mut flags: Vec<_> = command
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .filter_map(|arg| arg.get_long().map(str::to_owned))
        .collect();
    flags.sort();
    assert_eq!(
        flags, expected_flags,
        "all Go root flag bindings must be accounted for"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 59);
    for raw in cases {
        let case: Case = serde_json::from_value(raw.clone()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        if let Some(config) = case.config {
            let parent = home.join(".config").join("symaira-vault");
            fs::create_dir_all(&parent).unwrap();
            fs::write(parent.join("config.yaml"), config).unwrap();
        }
        let input = root.join("case.json");
        fs::write(&input, serde_json::to_vec(raw).unwrap()).unwrap();
        let mut child = ProcessCommand::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "config_override_tests::child", "--nocapture"])
            .env_clear()
            .current_dir(&home)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local").join("share"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("TMPDIR", &root)
            .env("TMP", &root)
            .env("TEMP", &root)
            .env("LANG", "C")
            .env("TZ", "UTC")
            .env("CFG_OVERRIDES_CASE", input);
        if let Some(system) = std::env::var_os("SystemRoot") {
            child.env("SystemRoot", system);
        }
        for (key, value) in case.env {
            assert!(key.starts_with("SYMVAULT_"));
            child.env(key, value);
        }
        let output = bounded_output(&mut child);
        assert!(
            output.status.success(),
            "{}: {}{}",
            case.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
    eprintln!(
        "PASS CFG-002 production Rust parser/resolver: {} cases",
        cases.len()
    );
}

#[test]
fn altered_oracle_answer_is_rejected() {
    let mut fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/port/config/overrides.json")).unwrap();
    fixture["cases"][0]["result"]["path"] = "wrong-oracle-answer".into();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mutant.json");
    let bytes = serde_json::to_vec(&fixture).unwrap();
    fs::write(&path, &bytes).unwrap();
    let mut child = ProcessCommand::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "config_override_tests::overrides_match_go_oracle",
            "--nocapture",
        ])
        .env("CFG_OVERRIDES_FIXTURE", &path);
    let output = bounded_output(&mut child);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("defaults_no_file"));
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "checking must never rewrite evidence"
    );
}
