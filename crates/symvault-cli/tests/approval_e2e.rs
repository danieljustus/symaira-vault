//! APPROVAL-001 end-to-end: the real Rust `approval list|decide` CLI against the
//! real Rust local approval listener, with no recorded server in between.
//!
//! `approval_queue_replay.rs` freezes the CLI half of the contract (a recorded
//! Go server answers the Rust CLI). This file closes the other half: the same
//! Go-recorded scenarios in `testdata/port/approval/queue.json` are replayed
//! against the production Rust listener (`symvault_mcp::http::
//! serve_with_oauth_and_approval_options_until`, wired exactly as
//! `symvault mcp` wires it: `load_tls_server_config`, `LocalApprovalApi`, the
//! `.runtime-port`/`.runtime-tls-cert` discovery files) with a seeded
//! `ApprovalQueue`. The CLI's stdout/stderr/exit must equal the Go CLI's
//! recorded outcome once the random queue ids and clock values are mapped onto
//! the fixture's canonical ones, and the queue state afterwards must be what
//! the recorded outcome implies (approved/denied by `local-cli`, or untouched
//! when the request was refused).
//!
//! Not reproducible end to end (declared, not hidden): `decide_expired` needs a
//! queue entry whose expiry the Rust queue API does not let a caller choose
//! (the TTL is fixed at five minutes); expiry is covered by the queue unit
//! tests in `crates/symvault-mcp/src/approval.rs`.

use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    thread,
    time::Duration,
};

use serde::Deserialize;
use symvault_mcp::{
    approval::ApprovalQueue,
    http::{
        HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
        load_tls_server_config, serve_with_oauth_and_approval_options_until,
    },
};

const FIXTURE: &str = "../../testdata/port/approval/queue.json";
const CERTS: &str = "../../testdata/port/approval/certs";
/// Cases the Rust queue API cannot reproduce (see the module comment).
const NOT_REPRODUCIBLE: &[&str] = &["decide_expired"];

// ---------------------------------------------------------------- fixture

#[derive(Debug, Clone, Deserialize)]
struct Fixture {
    secret_hex: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize)]
struct Case {
    id: String,
    args: Vec<String>,
    secret: String,
    runtime: Runtime,
    server_tls: String,
    outcome: Outcome,
}

#[derive(Debug, Clone, Deserialize)]
struct Runtime {
    port: String,
    tls: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Outcome {
    exit_code: i32,
    stdout: String,
    stderr: String,
    stderr_compare: String,
    #[serde(default)]
    stderr_prefix: String,
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn certs_dir() -> PathBuf {
    manifest_dir().join(CERTS)
}

fn load_fixture() -> Fixture {
    let path = manifest_dir().join(FIXTURE);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("decode approval fixture")
}

fn secret_bytes(fixture: &Fixture, class: &str) -> Vec<u8> {
    hex::decode(&fixture.secret_hex[class]).expect("fixture secret hex")
}

// ---------------------------------------------------------------- listener

/// The production listener on a fresh loopback port, serving `queue`.
struct Listener {
    port: u16,
    shutdown: HttpShutdown,
    handle: Option<thread::JoinHandle<()>>,
}

impl Listener {
    /// `client_ca`: `Some` makes mTLS mandatory (as `MCP.mtls_enabled` does).
    fn start(
        vault: &Path,
        queue: &Arc<ApprovalQueue>,
        secret: &[u8],
        server_certificate: &str,
        server_key: &str,
        client_ca: Option<&str>,
    ) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = certs_dir();
        let tls = load_tls_server_config(
            certs.join(server_certificate),
            certs.join(server_key),
            client_ca.map(|name| certs.join(name)).as_deref(),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let shutdown = HttpShutdown::default();
        let api = LocalApprovalApi::new(Arc::clone(queue), secret.to_vec());
        // The server refuses to start without a token registry; the CLI's own
        // startup creates one (`load_token_system`). No tokens: only the local
        // approval route, which needs no bearer, is exercised here.
        let registry = vault.join("mcp-tokens.json");
        fs::write(&registry, br#"{"version":2,"tokens":{}}"#).map_err(|e| e.to_string())?;
        let until = shutdown.clone();
        let handle = thread::spawn(move || {
            let result = serve_with_oauth_and_approval_options_until(
                listener,
                registry,
                |_agent: &str| Err("no MCP agent in the approval e2e".to_owned()),
                "oauth",
                |_client: &str, _redirect: &str| OAuthConsentDecision::Denied,
                |_passphrase: &str| false,
                Some(tls),
                api,
                HttpServerOptions::default(),
                Some(until),
            );
            assert!(result.is_ok(), "approval listener failed: {result:?}");
        });
        Ok(Self {
            port,
            shutdown,
            handle: Some(handle),
        })
    }

    fn stop(mut self) {
        self.shutdown
            .drain(Duration::from_secs(5))
            .expect("drain approval listener");
        self.handle
            .take()
            .expect("listener thread")
            .join()
            .expect("join approval listener");
    }
}

// ---------------------------------------------------------------- vault + CLI

fn runtime_tls_record(kind: &str) -> serde_json::Value {
    let certs = certs_dir();
    let path = |name: &str| certs.join(name).to_string_lossy().into_owned();
    match kind {
        "mtls_full" => serde_json::json!({
            "certificate": path("server.pem"), "client_auth_required": true,
            "client_ca_file": path("client-ca.pem"),
            "client_certificate": path("client.pem"), "client_key": path("client.key"),
        }),
        "mtls_missing_identity" => serde_json::json!({
            "certificate": path("server.pem"), "client_auth_required": true,
        }),
        "mtls_reused_server_identity" => serde_json::json!({
            "certificate": path("server.pem"), "client_auth_required": true,
            "client_ca_file": path("client-ca.pem"),
            "client_certificate": path("server.pem"), "client_key": path("server.key"),
        }),
        "mtls_wrong_ca" => serde_json::json!({
            "certificate": path("server.pem"), "client_auth_required": true,
            "client_ca_file": path("server.pem"),
            "client_certificate": path("client.pem"), "client_key": path("client.key"),
        }),
        "mtls_wrong_key" => serde_json::json!({
            "certificate": path("server.pem"), "client_auth_required": true,
            "client_ca_file": path("client-ca.pem"),
            "client_certificate": path("client.pem"), "client_key": path("server.key"),
        }),
        "tls_only" => serde_json::json!({ "certificate": path("server.pem") }),
        "tls_unrelated_server" => serde_json::json!({ "certificate": path("other-server.pem") }),
        other => panic!("unknown runtime TLS kind {other:?}"),
    }
}

/// A disposable vault directory holding what the CLI reads to find the server.
struct Vault {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Vault {
    fn new(secret: &[u8]) -> Self {
        let temp = tempfile::tempdir().expect("case tempdir");
        let root = temp.path().join("vault");
        let home = temp.path().join("home");
        fs::create_dir_all(&root).expect("vault dir");
        fs::create_dir_all(&home).expect("home dir");
        fs::write(
            root.join("identity.age"),
            b"test-only initialization marker",
        )
        .expect("identity");
        fs::write(root.join("config.yaml"), b"{}\n").expect("config");
        fs::write(root.join("mcp-server.enroll-secret"), secret).expect("secret");
        Self {
            _temp: temp,
            root,
            home,
        }
    }

    fn publish(&self, port: Option<u16>, bind: &str, tls_kind: &str) {
        if let Some(port) = port {
            fs::write(
                self.root.join(".runtime-port"),
                serde_json::to_vec(&serde_json::json!({ "port": port, "bind": bind }))
                    .expect("runtime port"),
            )
            .expect("write runtime port");
        }
        fs::write(
            self.root.join(".runtime-tls-cert"),
            serde_json::to_vec(&runtime_tls_record(tls_kind)).expect("runtime tls"),
        )
        .expect("write runtime tls");
    }

    fn cli(&self, args: &[String]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_symvault"))
            .arg("--vault")
            .arg(&self.root)
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("CI", "1")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("run Rust CLI")
    }
}

// ---------------------------------------------------------------- canonicalisation

const CANONICAL_CREATED: &str = "2026-01-02T03:04:05.123456789Z";
const CANONICAL_EXPIRES: &str = "2026-01-02T03:09:05.123456789Z";
const CANONICAL_EXPIRES_SECONDS: &str = "2026-01-02T03:09:05Z";
const CANONICAL_DECIDED: &str = "2026-01-02T03:04:07.25Z";
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Length of an RFC 3339 UTC timestamp starting at `text` (`...Z`), if any.
fn timestamp_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|b| b.iter().all(u8::is_ascii_digit))
    };
    let shape = digits(0..4)
        && bytes.get(4) == Some(&b'-')
        && digits(5..7)
        && bytes.get(7) == Some(&b'-')
        && digits(8..10)
        && bytes.get(10) == Some(&b'T')
        && digits(11..13)
        && bytes.get(13) == Some(&b':')
        && digits(14..16)
        && bytes.get(16) == Some(&b':')
        && digits(17..19);
    if !shape {
        return None;
    }
    let mut end = 19;
    if bytes.get(end) == Some(&b'.') {
        let start = end + 1;
        end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if !(1..=9).contains(&(end - start)) {
            return None;
        }
    }
    (bytes.get(end) == Some(&b'Z')).then_some(end + 1)
}

/// Maps the clock values the live server produced onto the fixture's canonical
/// ones by the field that carries them, and reports the raw values seen.
fn canonical_timestamps(text: &str, seen: &mut Vec<(String, String)>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let Some(len) = timestamp_len(rest) else {
            let ch = rest.chars().next().expect("non-empty");
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        };
        let (value, tail) = rest.split_at(len);
        let context = out.rsplit('\n').next().unwrap_or_default();
        let (field, canonical) =
            if context.ends_with("\"created_at\":\"") || context.ends_with("createdat: ") {
                ("created", CANONICAL_CREATED)
            } else if context.ends_with("\"expires_at\":\"") || context.ends_with("expiresat: ") {
                ("expires", CANONICAL_EXPIRES)
            } else if context.ends_with("\"decided_at\":\"") || context.ends_with("decidedat: ") {
                if value == ZERO_TIME {
                    ("undecided", ZERO_TIME)
                } else {
                    ("decided", CANONICAL_DECIDED)
                }
            } else if context.contains("  pending") {
                ("expires-table", CANONICAL_EXPIRES_SECONDS)
            } else {
                panic!("timestamp {value:?} in an unrecognised position: {context:?}");
            };
        seen.push((field.to_owned(), value.to_owned()));
        out.push_str(canonical);
        rest = tail;
    }
    out
}

struct Canon {
    /// (real id, canonical id)
    ids: Vec<(String, String)>,
    port: u16,
}

impl Canon {
    fn text(&self, text: &str, seen: &mut Vec<(String, String)>) -> String {
        let mut text = text.to_owned();
        for (real, canonical) in &self.ids {
            text = text.replace(real, canonical);
        }
        text = text.replace(&format!(":{}", self.port), ":{port}");
        canonical_timestamps(&text, seen)
    }
}

// ---------------------------------------------------------------- queue

fn status_of(queue: &ApprovalQueue, id: &str) -> String {
    if queue
        .pending()
        .expect("pending")
        .iter()
        .any(|entry| entry.id == id)
    {
        return "pending".to_owned();
    }
    // Not pending: `wait` returns the recorded outcome without blocking.
    let outcome = queue.wait(id).expect("decided request");
    format!(
        "{}:{}",
        outcome.status,
        outcome.decided_by.unwrap_or_default()
    )
}

fn snapshot(queue: &ApprovalQueue, ids: &[(String, String)]) -> BTreeMap<String, String> {
    ids.iter()
        .map(|(real, canonical)| (canonical.clone(), status_of(queue, real)))
        .collect()
}

fn seed(
    queue: &ApprovalQueue,
    ids: &mut Vec<(String, String)>,
    path: &str,
    write: bool,
    reason: &str,
) {
    let id = queue
        .enqueue("agent-e2e", path, write, reason)
        .expect("enqueue");
    let canonical = format!("apr-a{:011}", ids.len() + 1);
    ids.push((id, canonical));
    // Distinct created_at values pin the newest-first listing order.
    thread::sleep(Duration::from_millis(5));
}

/// Replays every reproducible recorded case against the live listener.
fn run_all(
    fixture: &Fixture,
    queue_secret_class: &str,
    server_for: impl Fn(&Case, &Path, &Arc<ApprovalQueue>, &[u8]) -> Result<Listener, String>,
) -> Vec<String> {
    let queue = Arc::new(ApprovalQueue::default());
    let mut ids: Vec<(String, String)> = Vec::new();
    seed(
        &queue,
        &mut ids,
        "notes/approve.md",
        true,
        "approve fixture",
    );
    seed(&queue, &mut ids, "notes/deny.md", false, "deny fixture");
    seed(&queue, &mut ids, "notes/quiet.md", false, "quiet fixture");

    let mut failures = Vec::new();
    for case in &fixture.cases {
        if NOT_REPRODUCIBLE.contains(&case.id.as_str()) {
            continue;
        }
        if case.id == "tls_only_list" {
            // Mirrors the generator's `enqueue_tls` pre-action (canonical id 4;
            // the skipped `decide_expired` entry would have been 5).
            seed(&queue, &mut ids, "notes/tls.md", true, "tls fixture");
        }
        let problems = run_case(fixture, queue_secret_class, &server_for, &queue, &ids, case);
        if !problems.is_empty() {
            failures.push(format!("{}:\n    {}", case.id, problems.join("\n    ")));
        }
    }
    failures
}

fn run_case(
    fixture: &Fixture,
    queue_secret_class: &str,
    server_for: &impl Fn(&Case, &Path, &Arc<ApprovalQueue>, &[u8]) -> Result<Listener, String>,
    queue: &Arc<ApprovalQueue>,
    ids: &[(String, String)],
    case: &Case,
) -> Vec<String> {
    let mut problems = Vec::new();
    // The server always holds the vault's real secret; a "wrong" case gives the
    // CLI a different one (a local process that does not own the vault).
    let server_secret = secret_bytes(fixture, queue_secret_class);
    let vault = Vault::new(&secret_bytes(fixture, &case.secret));
    let listener = server_for(case, &vault.root, queue, &server_secret).expect("start listener");
    let bind = if case.runtime.port == "non_loopback_bind" {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let port = (case.runtime.port != "absent").then_some(listener.port);
    vault.publish(port, bind, &case.runtime.tls);

    let real = |arg: &String| {
        ids.iter()
            .find(|(_, canonical)| canonical == arg)
            .map_or_else(|| arg.clone(), |(real, _)| real.clone())
    };
    let args: Vec<String> = case.args.iter().map(real).collect();
    let before = snapshot(queue, ids);
    let output = vault.cli(&args);
    let after = snapshot(queue, ids);
    let live_port = listener.port;
    listener.stop();

    let canon = Canon {
        ids: ids.to_vec(),
        port: live_port,
    };
    let mut seen = Vec::new();
    let stdout = canon.text(&String::from_utf8_lossy(&output.stdout), &mut seen);
    let stderr = canon.text(&String::from_utf8_lossy(&output.stderr), &mut seen);
    let recorded = &case.outcome;
    if output.status.code() != Some(recorded.exit_code) {
        problems.push(format!(
            "exit {:?} != recorded {}",
            output.status.code(),
            recorded.exit_code
        ));
    }
    if stdout != recorded.stdout {
        problems.push(format!(
            "stdout {stdout:?} != recorded {:?}",
            recorded.stdout
        ));
    }
    match recorded.stderr_compare.as_str() {
        "exact" if stderr != recorded.stderr => {
            problems.push(format!(
                "stderr {stderr:?} != recorded {:?}",
                recorded.stderr
            ));
        }
        "prefix" if !stderr.starts_with(&recorded.stderr_prefix) => {
            problems.push(format!(
                "stderr {stderr:?} lacks recorded prefix {:?}",
                recorded.stderr_prefix
            ));
        }
        "exact" | "prefix" => {}
        other => problems.push(format!("unknown stderr_compare {other:?}")),
    }

    // Clock values: right shape and right order of magnitude for a live queue.
    for (field, value) in &seen {
        let parsed =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339);
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                problems.push(format!(
                    "{field} timestamp {value:?} does not parse: {error}"
                ));
                continue;
            }
        };
        if field == "undecided" {
            continue;
        }
        let skew = (time::OffsetDateTime::now_utc() - parsed).whole_seconds();
        let window = if field.starts_with("expires") {
            301
        } else {
            60
        };
        if skew.abs() > window {
            problems.push(format!("{field} timestamp {value:?} is {skew}s from now"));
        }
    }

    // Queue effect: a successful decision is recorded by `local-cli`; every
    // refused or failed request leaves the queue untouched.
    let decision_target = case
        .args
        .windows(2)
        .find(|pair| pair[0] == "decide")
        .map(|pair| pair[1].clone());
    let mut expected = before.clone();
    if recorded.exit_code == 0
        && let Some(target) = &decision_target
    {
        let verdict = if case.args.iter().any(|arg| arg == "--approve") {
            "approved:local-cli"
        } else {
            "denied:local-cli"
        };
        expected.insert(target.clone(), verdict.to_owned());
    }
    if after != expected {
        problems.push(format!("queue after {after:?}, expected {expected:?}"));
    }
    problems
}

fn mtls_listener(
    case: &Case,
    vault: &Path,
    queue: &Arc<ApprovalQueue>,
    secret: &[u8],
) -> Result<Listener, String> {
    let client_ca = (case.server_tls == "mtls").then_some("client-ca.pem");
    Listener::start(vault, queue, secret, "server.pem", "server.key", client_ca)
}

// ---------------------------------------------------------------- tests

#[test]
fn rust_cli_matches_go_recorded_outcomes_against_the_real_rust_listener() {
    let fixture = load_fixture();
    let failures = run_all(&fixture, "valid", mtls_listener);
    assert!(
        failures.is_empty(),
        "{} recorded case(s) diverge against the live Rust listener:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let replayed = fixture.cases.len() - NOT_REPRODUCIBLE.len();
    eprintln!(
        "replayed {replayed} of {} recorded Go cases end to end",
        fixture.cases.len()
    );
}

#[test]
fn the_reproducible_set_is_exactly_the_recorded_set_minus_the_declared_gap() {
    let fixture = load_fixture();
    for declared in NOT_REPRODUCIBLE {
        assert!(
            fixture.cases.iter().any(|case| case.id == *declared),
            "declared gap {declared} is not in the fixture any more"
        );
    }
    let mtls = fixture
        .cases
        .iter()
        .filter(|case| case.server_tls == "mtls")
        .count();
    let tls_only = fixture
        .cases
        .iter()
        .filter(|case| case.server_tls == "tls")
        .count();
    assert!(
        mtls >= 20 && tls_only >= 3,
        "fixture lost TLS/mTLS coverage"
    );
}

/// Negative controls: a listener that holds a different ownership secret must
/// be refused 401 by the real HMAC check, and an mTLS listener trusting the
/// wrong CA must refuse the dedicated approval client. Both must surface as
/// failing cases, otherwise a green run proves nothing.
#[test]
fn a_listener_with_a_broken_proof_secret_or_the_wrong_client_ca_fails_the_replay() {
    let fixture = load_fixture();
    // Server holds the "wrong" secret while the CLI proves with "valid".
    let failures = run_all(&fixture, "wrong", mtls_listener);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("list_json:")),
        "a server with a different secret must fail list_json: {failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("approve_json:")),
        "a server with a different secret must fail approve_json: {failures:?}"
    );

    // mTLS listener whose client CA is the server certificate, not the CA that
    // signed the approval client identity.
    let failures = run_all(&fixture, "valid", |case, vault, queue, secret| {
        let client_ca = (case.server_tls == "mtls").then_some("server.pem");
        Listener::start(vault, queue, secret, "server.pem", "server.key", client_ca)
    });
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("list_json:")),
        "a listener trusting the wrong client CA must fail list_json: {failures:?}"
    );
}

// ================================================================ real process
//
// Everything above drives the production listener in-process with a seeded
// queue. Below, the real `symvault mcp` server process is started from an
// initialised vault: its own startup validates the mTLS settings, publishes
// `.runtime-port`/`.runtime-tls-cert`, creates the ownership secret and wires
// the queue to the MCP tool path, so a write by an agent in `approvalMode:
// prompt` produces a genuinely pending approval that the CLI then decides.

use std::{
    io::{BufRead, BufReader},
    process::{Child, Stdio},
    sync::mpsc,
    time::Instant,
};

const PASSPHRASE: &str = "approval-e2e-fixture-passphrase";
const MCP_BEARER: &str = "approval-e2e-legacy-bearer";
const MCP_AGENT: &str = "e2e-writer";
const SETTINGS_FIXTURE: &str = "../../testdata/port/approval/mtls_settings.json";

fn base_command(home: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    command
        .env_clear()
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env("CI", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    command
}

/// A real, initialised vault for the real server process.
struct RealVault {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl RealVault {
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
        let output = vault.run(&["init", "--auth", "passphrase"]);
        assert!(
            output.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        vault
    }

    fn run(&self, args: &[&str]) -> Output {
        base_command(&self.home, self.home.as_path())
            .arg("--vault")
            .arg(&self.root)
            .args(args)
            .output()
            .expect("run symvault")
    }

    /// Merges `fragment` (top-level YAML keys) into the vault's config.yaml.
    fn merge_config(&self, fragment: &str) {
        let path = self.root.join("config.yaml");
        let mut config: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).expect("read config"))
                .expect("parse config");
        let extra: serde_yaml_ng::Value = serde_yaml_ng::from_str(fragment).expect("fragment");
        let target = config.as_mapping_mut().expect("config mapping");
        for (key, value) in extra.as_mapping().expect("fragment mapping") {
            target.insert(key.clone(), value.clone());
        }
        fs::write(
            &path,
            serde_yaml_ng::to_string(&config).expect("encode config"),
        )
        .expect("write config");
    }
}

fn cert_path(name: &str) -> String {
    certs_dir().join(name).to_string_lossy().into_owned()
}

/// A running `symvault mcp` HTTP server.
struct McpServer {
    child: Child,
    port: u16,
}

impl McpServer {
    fn start(vault: &RealVault) -> Self {
        let child = base_command(&vault.home, vault.home.as_path())
            .arg("--vault")
            .arg(&vault.root)
            .args(["mcp", "--port", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn symvault mcp");
        // Owned before anything can panic: `Drop` kills and reaps the process.
        let mut server = Self { child, port: 0 };
        let stderr = server.child.stderr.take().expect("server stderr");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = sender.send(line);
            }
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut seen = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = receiver
                .recv_timeout(remaining)
                .unwrap_or_else(|_| panic!("server did not report its port; stderr: {seen:?}"));
            if let Some(port) = line
                .strip_prefix("MCP server listening on 127.0.0.1:")
                .and_then(|port| port.parse::<u16>().ok())
            {
                server.port = port;
                // Like Go, the vault-ownership secret exists before the port is
                // announced, so a client started on "listening" can prove ownership.
                assert!(
                    vault.root.join("mcp-server.enroll-secret").is_file(),
                    "server announced its port before creating the enroll secret"
                );
                assert!(
                    vault.root.join(".runtime-port").is_file(),
                    "server announced its port before saving the runtime port"
                );
                return server;
            }
            seen.push(line);
        }
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// MCP-over-HTTPS client authenticated like a device: bearer + mTLS identity.
struct McpClient {
    http: reqwest::blocking::Client,
    url: String,
}

impl McpClient {
    fn new(port: u16) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = fs::read(certs_dir().join("server.pem")).expect("server certificate");
        let mut identity = fs::read(certs_dir().join("client.pem")).expect("client certificate");
        identity.extend(fs::read(certs_dir().join("client.key")).expect("client key"));
        let http = reqwest::blocking::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only([reqwest::Certificate::from_pem(&server).expect("pin server")])
            .identity(reqwest::Identity::from_pem(&identity).expect("client identity"))
            .no_proxy()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("MCP client");
        Self {
            http,
            url: format!("https://127.0.0.1:{port}/mcp"),
        }
    }

    fn post(&self, session: Option<&str>, body: &serde_json::Value) -> reqwest::blocking::Response {
        let mut request = self
            .http
            .post(&self.url)
            .bearer_auth(MCP_BEARER)
            .header("X-Symaira-Agent", MCP_AGENT)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .body(body.to_string());
        if let Some(session) = session {
            request = request.header("Mcp-Session-Id", session);
        }
        request.send().expect("MCP request")
    }

    fn initialize(&self) -> Option<String> {
        let response = self.post(
            None,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "approval-e2e", "version": "1"}}
            }),
        );
        assert_eq!(response.status().as_u16(), 200, "initialize");
        let session = response
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let _ = response.text();
        session
    }
}

/// Starts a tools/call that needs approval on its own thread and returns the
/// handle that yields the MCP result once the CLI decided it.
fn spawn_write_call(port: u16, value: &'static str) -> thread::JoinHandle<serde_json::Value> {
    thread::spawn(move || {
        let client = McpClient::new(port);
        let session = client.initialize();
        let response = client.post(
            session.as_deref(),
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "set_entry_field",
                           "arguments": {"path": "notes/file", "field": "title", "value": value}}
            }),
        );
        let text = response.text().expect("MCP call body");
        // The reply is JSON or a single SSE `data:` frame.
        let payload = text
            .lines()
            .find_map(|line| line.strip_prefix("data:"))
            .unwrap_or(&text);
        serde_json::from_str(payload.trim()).unwrap_or_else(|e| panic!("MCP reply {text:?}: {e}"))
    })
}

fn approval_cli(vault: &RealVault, args: &[&str]) -> Output {
    let mut all = vec!["approval"];
    all.extend_from_slice(args);
    // Same environment shape as the replay: nothing but a private HOME.
    Command::new(env!("CARGO_BIN_EXE_symvault"))
        .arg("--vault")
        .arg(&vault.root)
        .args(all)
        .env_clear()
        .env("HOME", &vault.home)
        .env("XDG_CONFIG_HOME", vault.home.join("config"))
        .env("XDG_DATA_HOME", vault.home.join("data"))
        .env("XDG_CACHE_HOME", vault.home.join("cache"))
        .env("CI", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run approval CLI")
}

/// Waits until `count` requests are pending and returns their ids
/// (newest first, as listed).
fn wait_for_pending(vault: &RealVault, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let output = approval_cli(vault, &["list", "--json"]);
        if output.status.success() {
            let listed: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("list JSON");
            let ids: Vec<String> = listed["requests"]
                .as_array()
                .expect("requests array")
                .iter()
                .map(|request| request["id"].as_str().expect("id").to_owned())
                .collect();
            if ids.len() >= count {
                return ids;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no pending approval appeared: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn mtls_vault_for_real_server() -> RealVault {
    let vault = RealVault::init();
    let set = vault.run(&["set", "notes/file.title", "--value", "original", "--force"]);
    assert!(
        set.status.success(),
        "seed entry: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    vault.merge_config(&format!(
        "agents:\n  cli:\n    allowedPaths: ['*']\n    canWrite: true\n    exposeValueTools: false\n  {MCP_AGENT}:\n    tier: admin\n    allowedPaths: ['*']\n    canWrite: true\n    canRunCommands: false\n    canUseAutotype: false\n    exposeValueTools: false\n    approvalMode: prompt\n    approvalTimeout: 120s\nmcp:\n  tls_cert_file: {}\n  tls_key_file: {}\n  mtls_enabled: true\n  tls_client_ca_file: {}\n  approval_tls_cert_file: {}\n  approval_tls_key_file: {}\n",
        cert_path("server.pem"),
        cert_path("server.key"),
        cert_path("client-ca.pem"),
        cert_path("client.pem"),
        cert_path("client.key"),
    ));
    fs::write(vault.root.join("mcp-token"), MCP_BEARER).expect("legacy bearer");
    vault
}

/// The whole path on real processes: an agent write over mTLS becomes a
/// pending approval; the Rust CLI lists it, then approves one request and
/// denies another; the waiting MCP callers observe both decisions; a repeat
/// decision and an unknown id are refused with the recorded Go texts.
#[test]
fn real_server_process_and_cli_decide_an_agent_write_over_mtls() {
    let vault = mtls_vault_for_real_server();
    let server = McpServer::start(&vault);

    // First request: approve.
    let first = spawn_write_call(server.port, "approved-value");
    let ids = wait_for_pending(&vault, 1);
    assert_eq!(ids.len(), 1);
    let listed = approval_cli(&vault, &["list", "--json"]);
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("list JSON");
    let request = &listed["requests"][0];
    assert_eq!(request["agent_name"], MCP_AGENT);
    assert_eq!(request["path"], "notes/file");
    assert_eq!(request["write"], true);
    assert_eq!(request["status"], "pending");
    assert_eq!(request["decided_at"], ZERO_TIME);
    assert!(request.get("decided_by").is_none());

    let text = approval_cli(&vault, &["list"]);
    let table = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(table.starts_with("REQUEST ID         AGENT"), "{table}");
    assert!(
        table.contains(&ids[0]) && table.contains(MCP_AGENT),
        "{table}"
    );

    let approve = approval_cli(&vault, &["decide", &ids[0], "--approve", "--json"]);
    assert!(approve.status.success(), "{approve:?}");
    let outcome: serde_json::Value = serde_json::from_slice(&approve.stdout).expect("outcome");
    assert_eq!(outcome["outcome"]["id"], ids[0].as_str());
    assert_eq!(outcome["outcome"]["status"], "approved");
    assert_eq!(outcome["outcome"]["decided_by"], "local-cli");
    let reply = first.join().expect("first MCP call");
    assert!(
        reply["result"]["isError"] != true,
        "approved write must succeed: {reply}"
    );

    // Repeat decision: recorded 409 text; the other path: 404 text.
    let repeat = approval_cli(&vault, &["decide", &ids[0], "--deny"]);
    assert_eq!(repeat.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&repeat.stderr),
        format!(
            "Error: approval server: approval request {0} already approved\nError: approval server: approval request {0} already approved\n",
            ids[0]
        )
    );
    let unknown = approval_cli(&vault, &["decide", "apr-ffffffffffff", "--deny"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&unknown.stderr),
        "Error: approval server: approval request not found\nError: approval server: approval request not found\n"
    );

    // Second request: deny. The decided one is gone from the list.
    let second = spawn_write_call(server.port, "denied-value");
    let pending = wait_for_pending(&vault, 1);
    assert_eq!(pending.len(), 1);
    assert_ne!(
        pending[0], ids[0],
        "the approved request must not be listed"
    );
    let deny = approval_cli(&vault, &["decide", &pending[0], "--deny"]);
    assert!(deny.status.success(), "{deny:?}");
    assert_eq!(
        String::from_utf8_lossy(&deny.stdout),
        format!("Approval request \"{}\" denied.\n", pending[0])
    );
    let reply = second.join().expect("second MCP call");
    assert!(
        reply["result"]["isError"] == true
            && reply.to_string().contains("denied by approval device"),
        "denied write must fail with the approval text: {reply}"
    );
    let empty = approval_cli(&vault, &["list"]);
    assert_eq!(
        String::from_utf8_lossy(&empty.stdout),
        "No pending approval requests.\n"
    );

    // The server wrote the discovery records the CLI relied on.
    assert!(vault.root.join(".runtime-port").is_file());
    assert!(vault.root.join(".runtime-tls-cert").is_file());
    assert!(vault.root.join("mcp-server.enroll-secret").is_file());
}

/// A CLI that does not own the vault (different ownership secret) is refused by
/// the real server's HMAC check with the Go-recorded text.
#[test]
fn real_server_refuses_a_cli_without_the_vault_ownership_secret() {
    let vault = mtls_vault_for_real_server();
    let _server = McpServer::start(&vault);
    let before = approval_cli(&vault, &["list", "--json"]);
    assert!(before.status.success(), "{before:?}");

    let secret_path = vault.root.join("mcp-server.enroll-secret");
    let genuine = fs::read(&secret_path).expect("server secret");
    let mut forged = genuine.clone();
    forged[0] ^= 0xff;
    fs::write(&secret_path, &forged).expect("forge secret");
    let refused = approval_cli(&vault, &["list", "--json"]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "Error: approval server: missing or invalid proof of vault-directory ownership\nError: approval server: missing or invalid proof of vault-directory ownership\n"
    );
    assert!(refused.stdout.is_empty());
    fs::write(&secret_path, &genuine).expect("restore secret");
    assert!(approval_cli(&vault, &["list", "--json"]).status.success());
}

// ---------------------------------------------------------------- device enrollment

/// PAIRING-001 / APPROVAL-001 server-side device enrollment on the real
/// `symvault mcp` process (default TLS with the vault's own certificate):
/// the pairing code is minted with the vault-ownership proof, the fingerprint
/// it carries is the SHA-256 of the certificate the server really presents,
/// the code redeems exactly once, the new device shows up in
/// `device approval-list`, its bearer authorises the device approval API, and
/// `device approval-revoke` takes effect on the running server.
#[test]
fn real_server_enrolls_a_device_with_a_pinned_fingerprint_and_honours_revocation() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use time::format_description::well_known::Rfc3339;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let vault = RealVault::init();
    let server = McpServer::start(&vault);
    let base = format!("https://127.0.0.1:{}", server.port);

    let certificate = fs::read(vault.root.join("mcp-server.crt")).expect("vault certificate");
    let (_, pem) = x509_parser::pem::parse_x509_pem(&certificate).expect("certificate PEM");
    let presented = Sha256::digest(&pem.contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let http = reqwest::blocking::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only([reqwest::Certificate::from_pem(&certificate).expect("pin certificate")])
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("HTTPS client");

    // The server announces its port before it writes the ownership secret.
    let secret_path = vault.root.join("mcp-server.enroll-secret");
    let secret_deadline = Instant::now() + Duration::from_secs(30);
    let secret = loop {
        match fs::read(&secret_path) {
            Ok(secret) if secret.len() == 32 => break secret,
            _ if Instant::now() < secret_deadline => thread::sleep(Duration::from_millis(50)),
            other => panic!("enroll secret did not appear: {other:?}"),
        }
    };
    let proof_headers = |secret: &[u8]| {
        let timestamp = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("whole second")
            .format(&Rfc3339)
            .expect("timestamp");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
        mac.update(timestamp.as_bytes());
        let proof = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        (timestamp, proof)
    };
    let mint = |secret: &[u8]| {
        let (timestamp, proof) = proof_headers(secret);
        http.post(format!("{base}/api/v1/devices/enroll-code"))
            .header("X-Enroll-Timestamp", timestamp)
            .header("X-Enroll-Proof", proof)
            .send()
            .expect("mint request")
    };

    // A forged proof and a wrong method are refused before anything is minted.
    let mut forged = secret.clone();
    forged[0] ^= 0xff;
    let refused = mint(&forged);
    assert_eq!(refused.status().as_u16(), 401);
    assert_eq!(
        refused.text().expect("body"),
        "{\"error\":\"missing or invalid proof of vault-directory ownership\"}\n"
    );
    let wrong_method = http
        .get(format!("{base}/api/v1/devices/enroll-code"))
        .send()
        .expect("GET mint route");
    assert_eq!(wrong_method.status().as_u16(), 404);

    let minted = mint(&secret);
    assert_eq!(minted.status().as_u16(), 200);
    let minted: serde_json::Value =
        serde_json::from_str(&minted.text().expect("mint body")).expect("mint JSON");
    let code = minted["code"].as_str().expect("code").to_owned();
    assert_eq!(code.len(), 32);
    assert_eq!(
        minted["fingerprint"].as_str(),
        Some(presented.as_str()),
        "the pinned fingerprint is the presented certificate"
    );

    let enroll = |code: &str| {
        http.post(format!("{base}/api/v1/devices/enroll"))
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"code": code, "device_name": "e2e phone"}).to_string())
            .send()
            .expect("enroll request")
    };
    let enrolled = enroll(&code);
    assert_eq!(enrolled.status().as_u16(), 200);
    let enrolled: serde_json::Value =
        serde_json::from_str(&enrolled.text().expect("enroll body")).expect("enroll JSON");
    let device_id = enrolled["device_id"]
        .as_str()
        .expect("device id")
        .to_owned();
    let token = enrolled["token"].as_str().expect("token").to_owned();
    assert!(device_id.starts_with("dev-"));

    let reused = enroll(&code);
    assert_eq!(reused.status().as_u16(), 401);
    assert_eq!(
        reused.text().expect("body"),
        "{\"error\":\"invalid or expired pairing code\"}\n"
    );

    // The raw bearer never reaches the disk; the CLI lists the device.
    let store = fs::read_to_string(vault.root.join(".symvault/device-sessions.json"))
        .expect("device sessions");
    assert!(!store.contains(&token));
    let listed = vault.run(&["device", "approval-list"]);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(
        listed.contains(&device_id) && listed.contains("e2e phone"),
        "{listed}"
    );
    assert!(listed.contains("active"), "{listed}");

    // The bearer authorises the device approval API of the same server.
    let approvals = |bearer: &str| {
        http.get(format!("{base}/api/v1/approvals"))
            .bearer_auth(bearer)
            .send()
            .expect("approvals request")
    };
    let allowed = approvals(&token);
    assert_eq!(allowed.status().as_u16(), 200);
    assert_eq!(allowed.text().expect("body"), "{\"requests\":[]}\n");

    // Revocation by the CLI (a second process) is seen by the running server.
    let revoked = vault.run(&["device", "approval-revoke", "--yes", &device_id]);
    assert!(revoked.status.success(), "{revoked:?}");
    assert_eq!(approvals(&token).status().as_u16(), 401);
    let listed = vault.run(&["device", "approval-list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("revoked"));
}

// ---------------------------------------------------------------- mTLS settings

#[derive(Debug, Deserialize)]
struct SettingsFixture {
    cases: Vec<SettingsCase>,
}

#[derive(Debug, Deserialize)]
struct SettingsCase {
    id: String,
    mcp: Vec<Setting>,
    stdin: String,
    exit_code: i32,
    stdout: String,
    error_lines: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Setting {
    key: String,
    value: String,
}

fn run_settings_case(case: &SettingsCase) -> (Option<i32>, String, Vec<String>) {
    let vault = RealVault::init();
    let garbage = vault.root.join("garbage.pem");
    fs::write(&garbage, "not a pem\n").expect("garbage");
    let certs = certs_dir().to_string_lossy().into_owned();
    let vault_dir = vault.root.to_string_lossy().into_owned();
    let mut section = serde_yaml_ng::Mapping::new();
    for setting in &case.mcp {
        let value = setting
            .value
            .replace("{certs}", &certs)
            .replace("{vault}", &vault_dir);
        let value = match value.as_str() {
            "true" => serde_yaml_ng::Value::Bool(true),
            _ => serde_yaml_ng::Value::String(value),
        };
        section.insert(setting.key.clone().into(), value);
    }
    let mut fragment = serde_yaml_ng::Mapping::new();
    fragment.insert("mcp".into(), serde_yaml_ng::Value::Mapping(section));
    vault.merge_config(&serde_yaml_ng::to_string(&fragment).expect("fragment"));

    let mut child = base_command(&vault.home, vault.home.as_path())
        .arg("--vault")
        .arg(&vault.root)
        .args(["mcp", "--port", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn symvault mcp");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        let _ = stdin.write_all(case.stdin.as_bytes());
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll server") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{}: server kept running instead of failing closed on its settings",
                case.id
            );
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().expect("stdout"), &mut stdout)
        .expect("stdout");
    std::io::Read::read_to_string(&mut child.stderr.take().expect("stderr"), &mut stderr)
        .expect("stderr");
    let normalise = |text: &str| {
        text.replace(&vault_dir, "{vault}")
            .replace(&certs, "{certs}")
    };
    let error_lines = normalise(&stderr)
        .split_inclusive('\n')
        .filter_map(|line| line.find("Error: ").map(|at| line[at..].to_owned()))
        .collect();
    (status.code(), normalise(&stdout), error_lines)
}

/// Rust server startup validation of the mTLS settings against the Go-recorded
/// refusals (`testdata/port/approval/mtls_settings.json`, generated by
/// `approvaltlsgen` from the real Go `symvault mcp`). The Go-only diagnostics
/// printed before the failing check are out of scope (declared in the fixture).
#[cfg(unix)]
#[test]
fn rust_server_refuses_broken_mtls_settings_with_the_go_recorded_errors() {
    let path = manifest_dir().join(SETTINGS_FIXTURE);
    let raw = fs::read_to_string(&path).expect("read mtls settings fixture");
    let fixture: SettingsFixture = serde_json::from_str(&raw).expect("decode settings fixture");
    assert!(fixture.cases.len() >= 10, "fixture lost settings cases");
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let (code, stdout, error_lines) = run_settings_case(case);
        let mut problems = Vec::new();
        if code != Some(case.exit_code) {
            problems.push(format!("exit {code:?} != recorded {}", case.exit_code));
        }
        if stdout != case.stdout {
            problems.push(format!("stdout {stdout:?} != recorded {:?}", case.stdout));
        }
        if error_lines != case.error_lines {
            problems.push(format!(
                "error lines {error_lines:?} != recorded {:?}",
                case.error_lines
            ));
        }
        if !problems.is_empty() {
            failures.push(format!("{}:\n    {}", case.id, problems.join("\n    ")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} settings case(s) diverge from the Go oracle:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
