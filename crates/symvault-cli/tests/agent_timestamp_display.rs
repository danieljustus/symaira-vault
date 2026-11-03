//! `agent token list` (EXPIRES AT) and `agent list` (LAST SEEN) print
//! `time.Time.Format("2006-01-02 15:04")` of the *parsed* registry timestamp.
//! Every accepted timestamp of the Go-recorded sweep
//! (`go_timestamp_display_cases.json`, re-recorded by
//! `the Go oracle archive recipe (docs/rust-port/go-oracle-archive.md)`) is run through the real binary, so a
//! non-canonical form Go's parser accepts (one-digit hour, `,` fraction,
//! `+24:00`, ...) must display exactly what Go displays.

use std::{fs, path::Path, process::Command};

struct Case {
    text: String,
    display: String,
    after_zero: bool,
}

fn cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../symvault-store/tests/fixtures/go_timestamp_display_cases.json");
    let rows: Vec<(String, String, bool)> =
        serde_json::from_str(&fs::read_to_string(path).expect("fixture")).expect("fixture json");
    assert!(rows.len() > 200, "{} display cases", rows.len());
    rows.into_iter()
        .map(|(raw, display, after_zero)| Case {
            text: serde_json::from_str(&raw).expect("quoted string"),
            display,
            after_zero,
        })
        .collect()
}

fn run(args: &[&str], root: &Path, home: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run symvault");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The command tables go to stderr or stdout depending on the command.
    let mut text = String::from_utf8(output.stdout).expect("utf-8 stdout");
    text.push_str(&String::from_utf8(output.stderr).expect("utf-8 stderr"));
    text
}

fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    for name in ["config", "data", "cache"] {
        fs::create_dir_all(home.path().join(name)).expect("home dir");
    }
    (root, home)
}

#[test]
fn token_list_expiry_matches_recorded_go_format() {
    let (root, home) = setup();
    let cases = cases();
    fs::write(
        root.path().join("config.yaml"),
        "agents:\n  alpha:\n    tier: standard\n",
    )
    .expect("config");
    let tokens: String = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            format!(
                r#""h{index}":{{"id":"tok-{index}","hash":"h{index}","agent_name":"alpha","expires_at":"{}","revoked":false}}"#,
                case.text
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        root.path().join("mcp-tokens.json"),
        format!(r#"{{"version":2,"tokens":{{{tokens}}}}}"#),
    )
    .expect("registry");

    let stdout = run(
        &[
            "--vault",
            root.path().to_str().expect("utf-8 path"),
            "agent",
            "token",
            "list",
            "alpha",
        ],
        root.path(),
        home.path(),
    );
    // "{:<22} {:<16} {:<14} {:<28} {:<20} STATUS": EXPIRES AT starts at 84.
    let rows: std::collections::HashMap<&str, &str> = stdout
        .lines()
        .skip(1)
        .map(|line| (line[..22].trim_end(), line[84..104].trim_end()))
        .collect();
    // Go drops expired tokens when it loads the registry, so only instants in
    // the future are listed; the year-2999 cases keep the coverage clock-free.
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut wrong = Vec::new();
    let mut listed = 0;
    for (index, case) in cases.iter().enumerate() {
        let expires = symvault_store::go_registry::parse_go_rfc3339(&case.text)
            .expect("Go-accepted timestamp")
            .unix_timestamp();
        let shown = rows.get(format!("tok-{index}").as_str());
        if expires > now + 86_400 {
            listed += 1;
            if shown != Some(&case.display.as_str()) {
                wrong.push((&case.text, &case.display, shown));
            }
        } else if expires < now - 86_400 && shown.is_some() {
            wrong.push((&case.text, &case.display, shown));
        }
    }
    assert!(listed >= 70, "only {listed} future cases\n{stdout}");
    assert!(wrong.is_empty(), "(timestamp, go, rust): {wrong:?}");
}

#[test]
fn agent_list_last_seen_matches_recorded_go_format() {
    let (root, home) = setup();
    let cases = cases();
    let config: String = cases
        .iter()
        .enumerate()
        .map(|(index, _)| format!("  a{index:03}:\n    tier: standard\n"))
        .collect();
    fs::write(
        root.path().join("config.yaml"),
        format!("agents:\n{config}"),
    )
    .expect("config");
    let tokens: String = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            format!(
                r#""h{index}":{{"id":"tok-{index}","hash":"h{index}","agent_name":"a{index:03}","last_used_at":"{}","revoked":false}}"#,
                case.text
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        root.path().join("mcp-tokens.json"),
        format!(r#"{{"version":2,"tokens":{{{tokens}}}}}"#),
    )
    .expect("registry");

    let stdout = run(&["agent", "list"], root.path(), home.path());
    // "{:<14} {:<10} {:<10} {:<12} LAST SEEN": the last column starts at 50.
    let rows: std::collections::HashMap<&str, &str> = stdout
        .lines()
        .skip(2)
        .map(|line| (line[..14].trim_end(), line[50..].trim_end()))
        .collect();
    assert!(rows.len() >= cases.len(), "{stdout}");
    let mut wrong = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        // Go shows a last-used time only when it is After(time.Time{}).
        let expected = if case.after_zero {
            case.display.as_str()
        } else {
            "-"
        };
        let shown = rows[format!("a{index:03}").as_str()];
        if shown != expected {
            wrong.push((&case.text, expected, shown));
        }
    }
    assert!(wrong.is_empty(), "(timestamp, go, rust): {wrong:?}");
}
