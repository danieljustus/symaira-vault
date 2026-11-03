//! PLATFORM-002 / ADR 0034 item 29 on a real `symvault mcp --stdio` process:
//! the anomaly detector writes Go's `anomaly_<type>` audit rows and warning
//! lines while stdout stays pure protocol. The rate rule is used because it is
//! wall-clock independent (31 calls inside 60 s), so this needs no injected
//! clock; the detector itself is replayed against the real Go recording in
//! `crates/symvault-mcp/tests/anomaly_replay.rs` and the call-path wiring is
//! pinned with an injected clock in `anomaly_dispatch.rs`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const PASSPHRASE: &str = "anomaly-process-fixture-passphrase";
const AGENT: &str = "anomaly-agent";

fn base_command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    command
        .env_clear()
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env("SYMVAULT_SECUREUI", "none")
        .env("CI", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    command
}

struct Vault {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Vault {
    fn init() -> Self {
        let temp = tempfile::tempdir().expect("vault tempdir");
        let root = temp.path().join("vault");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let vault = Self {
            _temp: temp,
            root,
            home,
        };
        let output = base_command(&vault.home)
            .arg("--vault")
            .arg(&vault.root)
            .args(["init", "--auth", "passphrase"])
            .output()
            .expect("run init");
        assert!(
            output.status.success(),
            "init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = vault.root.join("config.yaml");
        let mut config: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).expect("config")).expect("yaml");
        let extra: serde_yaml_ng::Value = serde_yaml_ng::from_str(&format!(
            "agents:\n  {AGENT}:\n    tier: admin\n    allowedPaths: ['*']\n    canWrite: false\n    approvalMode: none\n"
        ))
        .expect("agent fragment");
        let target = config.as_mapping_mut().expect("mapping");
        for (key, value) in extra.as_mapping().expect("fragment mapping") {
            target.insert(key.clone(), value.clone());
        }
        fs::write(&path, serde_yaml_ng::to_string(&config).expect("encode")).expect("write");
        vault
    }

    /// Runs one stdio session with `calls` `list_entries` requests.
    fn session(&self, calls: usize) -> Output {
        let mut frames = vec![
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        ];
        for index in 0..calls {
            frames.push(json!({"jsonrpc":"2.0","id":index + 2,"method":"tools/call",
                "params":{"name":"list_entries","arguments":{}}}));
        }
        let input: String = frames.iter().map(|frame| format!("{frame}\n")).collect();
        let mut child = base_command(&self.home)
            .arg("--vault")
            .arg(&self.root)
            .args(["mcp", "--stdio", "--agent", AGENT])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn symvault mcp");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write frames");
        child.wait_with_output().expect("wait")
    }

    fn audit_rows(&self) -> Vec<Value> {
        let log = self.root.join(format!("audit-{AGENT}.log"));
        fs::read_to_string(&log)
            .unwrap_or_else(|error| panic!("audit log {}: {error}", log.display()))
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit row"))
            .collect()
    }
}

fn is_hex(value: &Value, len: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn anomaly_rows(rows: &[Value]) -> Vec<&Value> {
    rows.iter()
        .filter(|row| {
            row["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("anomaly_"))
        })
        .collect()
}

#[test]
fn thirty_one_calls_in_a_minute_write_rate_anomaly_rows_and_warning_lines() {
    let vault = Vault::init();
    let output = vault.session(32);
    assert!(output.status.success(), "{output:?}");

    // stdout carries exactly the 33 protocol frames and nothing else.
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let frames: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("protocol frame"))
        .collect();
    assert_eq!(frames.len(), 33, "{stdout}");
    assert!(frames.iter().all(|frame| frame["jsonrpc"] == "2.0"));

    // Calls 31 and 32 exceed Go's limit of 30 per 60 s: one row each, written
    // with the session id only (Go logs with context.Background()).
    let rows = vault.audit_rows();
    let anomalies = anomaly_rows(&rows);
    assert_eq!(anomalies.len(), 2, "{rows:?}");
    let session = rows[0]["sess_id"].clone();
    assert!(is_hex(&session, 32));
    for row in &anomalies {
        assert_eq!(row["action"], "anomaly_rate_anomaly");
        assert_eq!(row["agent"], AGENT);
        assert_eq!(row["transport"], "stdio");
        assert_eq!(row["ok"], false);
        assert_eq!(row["reason"], "anomaly_rate_anomaly");
        assert_eq!(row["sess_id"], session);
        for absent in ["path", "req_id", "token_id"] {
            assert!(row.get(absent).is_none(), "{absent} present: {row}");
        }
    }
    // The 32 calls themselves keep their identified rows.
    let lists: Vec<_> = rows.iter().filter(|row| row["action"] == "list").collect();
    assert_eq!(lists.len(), 32);
    assert!(lists.iter().all(|row| is_hex(&row["req_id"], 16)));
    // Each anomaly row follows the list row of the call that raised it.
    let positions: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row["action"] == "anomaly_rate_anomaly")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(rows[positions[0] - 1]["action"], "list");
    assert_eq!(rows[positions[1] - 1]["action"], "list");

    // Go's two warning lines per alert (detector hook, then dispatch), both on
    // stderr with the standard-logger prefix `YYYY/MM/DD HH:MM:SS `.
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 4, "{stderr}");
    for (pair, count) in lines.chunks(2).zip([31, 32]) {
        let description = format!(r#"description="Rate anomaly: {AGENT} made {count} requests""#);
        let head = format!("WARN anomaly detected type=rate_anomaly severity=medium agent={AGENT}");
        assert_eq!(without_timestamp(pair[0]), format!("{head} {description}"));
        let dispatched = without_timestamp(pair[1]);
        let prefix = format!(r#"{head} path="" request_id="#);
        let rest = dispatched
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{dispatched}"));
        let (request_id, tail) = rest.split_at(16);
        assert!(is_hex(&json!(request_id), 16), "{dispatched}");
        assert_eq!(tail, format!(" {description}"));
    }
}

/// Strips and validates the standard logger's `YYYY/MM/DD HH:MM:SS ` prefix.
fn without_timestamp(line: &str) -> &str {
    let (stamp, rest) = line.split_at(20);
    let shape: Vec<u8> = stamp
        .bytes()
        .map(|b| if b.is_ascii_digit() { b'd' } else { b })
        .collect();
    assert_eq!(shape, b"dddd/dd/dd dd:dd:dd ", "{line}");
    rest
}

#[test]
fn thirty_calls_stay_silent_negative_control() {
    let vault = Vault::init();
    let output = vault.session(30);
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = vault.audit_rows();
    assert!(anomaly_rows(&rows).is_empty(), "{rows:?}");
}
