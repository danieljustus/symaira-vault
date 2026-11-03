//! APPROVAL-001 frozen replay: the Rust `approval list|decide` CLI against the
//! Go-recorded wire contract in `testdata/port/approval/queue.json`.
//!
//! The fixture is produced by `scripts/rust-port/cmd/approvalgen` from the real
//! Go `approval.LocalHTTPHandler` and the real Go CLI. This test needs no Go
//! toolchain: a recorded-response mTLS server (rustls, the committed fixture
//! certificates) serves the recorded Go responses, and every case asserts
//!
//! * the request the Rust CLI sent (method, path, contract headers, HMAC proof
//!   recomputed with the recorded secret class, mTLS client identity, no body,
//!   no forbidden headers),
//! * how many connections/requests the CLI made (client-side failures must
//!   happen before any network traffic), and
//! * the CLI's stdout/stderr/exit code against the Go CLI's recorded outcome.
//!
//! The live Go differential (`approval_queue_differential.rs`) remains as a
//! pre-removal cross-check; this replay is the evidence that survives Go.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE: &str = "../../testdata/port/approval/queue.json";
const CERTS: &str = "../../testdata/port/approval/certs";
const PROOF_WINDOW_SECS: i64 = 30;
/// Headers an HTTP library adds on its own; Rust is not held to Go's choice.
const TRANSPORT_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "connection",
    "content-length",
    "user-agent",
];

// ---------------------------------------------------------------- fixture

#[derive(Debug, Clone, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    secret_hex: std::collections::BTreeMap<String, String>,
    certs: Vec<FileDigest>,
    cases: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize)]
struct Oracle {
    commit: String,
    source_files: Vec<FileDigest>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Case {
    id: String,
    args: Vec<String>,
    secret: String,
    runtime: Runtime,
    server_tls: String,
    exchanges: Vec<Exchange>,
    outcome: Outcome,
}

#[derive(Debug, Clone, Deserialize)]
struct Runtime {
    port: String,
    tls: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Exchange {
    request: RecordedRequest,
    response: RecordedResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    proof_secret: String,
    client_certificate_cn: String,
    body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedResponse {
    status: u16,
    content_type: String,
    body: String,
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

fn load_fixture() -> Fixture {
    let path = manifest_dir().join(FIXTURE);
    let raw = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    // A CRLF checkout must not change recorded bytes: the fixture is JSON, but
    // its string values embed LF-terminated Go output.
    let text = String::from_utf8(raw).expect("fixture is UTF-8");
    serde_json::from_str(&text.replace("\r\n", "\n")).expect("decode approval fixture")
}

fn certs_dir() -> PathBuf {
    manifest_dir().join(CERTS)
}

// ---------------------------------------------------------------- recorded server

#[derive(Debug, Clone, Default)]
struct Observed {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    client_cn: String,
}

#[derive(Default)]
struct ServerState {
    observed: Vec<Observed>,
    connections: usize,
    handshake_failures: usize,
}

struct ReplayServer {
    port: u16,
    state: Arc<Mutex<ServerState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ReplayServer {
    fn start(server_tls: &str, exchanges: Vec<Exchange>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = certs_dir();
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(certs.join("server.pem"))
                .expect("open server certificate")
                .collect::<Result<_, _>>()
                .expect("parse server certificate");
        let key = PrivateKeyDer::from_pem_file(certs.join("server.key")).expect("server key");
        let builder = ServerConfig::builder();
        let config = if server_tls == "mtls" {
            let mut roots = RootCertStore::empty();
            for cert in
                CertificateDer::pem_file_iter(certs.join("client-ca.pem")).expect("open client CA")
            {
                roots.add(cert.expect("parse client CA")).expect("add CA");
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .expect("client verifier");
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
        } else {
            builder.with_no_client_auth().with_single_cert(chain, key)
        }
        .expect("server TLS config");
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay listener");
        let port = listener.local_addr().expect("listener address").port();
        let state = Arc::new(Mutex::new(ServerState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicUsize::new(0));
        let handle = {
            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    state.lock().unwrap().connections += 1;
                    serve_connection(stream, &config, &state, &exchanges, &served);
                }
            })
        };
        Self {
            port,
            state,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> ServerState {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept loop; the stop flag then ends it.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join replay server");
        }
        let mut state = self.state.lock().unwrap();
        ServerState {
            observed: std::mem::take(&mut state.observed),
            connections: state.connections,
            handshake_failures: state.handshake_failures,
        }
    }
}

fn serve_connection(
    stream: TcpStream,
    config: &Arc<ServerConfig>,
    state: &Arc<Mutex<ServerState>>,
    exchanges: &[Exchange],
    served: &AtomicUsize,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout");
    let connection = ServerConnection::new(Arc::clone(config)).expect("server connection");
    let mut tls = StreamOwned::new(connection, stream);
    // Drive the handshake explicitly so a refused client is counted.
    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(&mut tls.sock).is_err() {
            state.lock().unwrap().handshake_failures += 1;
            return;
        }
    }
    let client_cn = tls
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|der| common_name(der.as_ref()))
        .unwrap_or_default();

    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return, // wake-up connection or client gave up
        }
        if head.len() > 64 * 1024 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let observed = Observed {
        method: parts.next().unwrap_or_default().to_owned(),
        path: parts.next().unwrap_or_default().to_owned(),
        headers: lines
            .filter(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect(),
        client_cn,
    };
    state.lock().unwrap().observed.push(observed);

    let index = served.fetch_add(1, Ordering::SeqCst);
    let (status, content_type, body) = match exchanges.get(index) {
        Some(exchange) => (
            exchange.response.status,
            exchange.response.content_type.as_str(),
            exchange.response.body.as_str(),
        ),
        None => (599, "text/plain", "unexpected extra request"),
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn common_name(der: &[u8]) -> String {
    x509_parser::parse_x509_certificate(der)
        .ok()
        .and_then(|(_, cert)| {
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|attribute| attribute.as_str().ok().map(str::to_owned))
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------- assertions

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("clock fits i64")
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` into Unix seconds.
fn parse_rfc3339_utc_seconds(value: &str) -> Option<i64> {
    let parsed =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?;
    let bytes = value.as_bytes();
    // The Go CLI formats time.RFC3339 in UTC: exactly 20 bytes ending in Z.
    (bytes.len() == 20 && value.ends_with('Z')).then(|| parsed.unix_timestamp())
}

fn header<'a>(observed: &'a Observed, name: &str) -> Option<&'a str> {
    let matches: Vec<&str> = observed
        .headers
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .collect();
    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

/// Checks one observed request against its Go recording.
fn check_request(
    observed: &Observed,
    recorded: &RecordedRequest,
    port: u16,
    secrets: &std::collections::BTreeMap<String, Vec<u8>>,
    now: i64,
) -> Result<(), String> {
    if observed.method != recorded.method {
        return Err(format!(
            "method {} != recorded {}",
            observed.method, recorded.method
        ));
    }
    if observed.path != recorded.path {
        return Err(format!(
            "path {} != recorded {}",
            observed.path, recorded.path
        ));
    }
    if recorded.body_bytes != 0 {
        return Err("fixture records a request body; none is expected".to_owned());
    }
    if let Some(length) = header(observed, "content-length")
        && length != "0"
    {
        return Err(format!("unexpected request body (content-length {length})"));
    }
    if header(observed, "transfer-encoding").is_some() {
        return Err("unexpected chunked request body".to_owned());
    }
    // Contract headers: those Go sent that are not HTTP-library artefacts.
    let contract: Vec<String> = recorded
        .headers
        .keys()
        .map(|name| name.to_ascii_lowercase())
        .filter(|name| !TRANSPORT_HEADERS.contains(&name.as_str()))
        .collect();
    for (name, _) in &observed.headers {
        if !contract.contains(name) && !TRANSPORT_HEADERS.contains(&name.as_str()) {
            return Err(format!("forbidden extra request header {name:?}"));
        }
    }
    for name in &contract {
        if header(observed, name).is_none() {
            return Err(format!("missing contract header {name:?}"));
        }
    }
    let expected_host = recorded.headers["Host"].replace("{port}", &port.to_string());
    if header(observed, "host") != Some(expected_host.as_str()) {
        return Err(format!(
            "Host {:?} != {expected_host:?}",
            header(observed, "host")
        ));
    }
    let timestamp = header(observed, "x-enroll-timestamp").ok_or("missing timestamp")?;
    let signed_at = parse_rfc3339_utc_seconds(timestamp)
        .ok_or_else(|| format!("timestamp {timestamp:?} is not RFC3339 UTC seconds"))?;
    if (now - signed_at).abs() > PROOF_WINDOW_SECS {
        return Err(format!("timestamp {timestamp:?} outside the proof window"));
    }
    let secret = secrets
        .get(&recorded.proof_secret)
        .ok_or_else(|| format!("unknown secret class {:?}", recorded.proof_secret))?;
    let proof = header(observed, "x-enroll-proof").ok_or("missing proof")?;
    if proof != hmac_hex(secret, timestamp.as_bytes()) {
        return Err(format!(
            "X-Enroll-Proof is not HMAC-SHA256({} secret, timestamp)",
            recorded.proof_secret
        ));
    }
    if observed.client_cn != recorded.client_certificate_cn {
        return Err(format!(
            "mTLS client identity {:?} != recorded {:?}",
            observed.client_cn, recorded.client_certificate_cn
        ));
    }
    Ok(())
}

/// Compares a CLI result with the recorded Go outcome; returns every mismatch.
fn compare_outcome(
    recorded: &Outcome,
    exit: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    if exit != Some(recorded.exit_code) {
        problems.push(format!("exit {exit:?} != recorded {}", recorded.exit_code));
    }
    if stdout != recorded.stdout {
        problems.push(format!(
            "stdout {stdout:?} != recorded {:?}",
            recorded.stdout
        ));
    }
    match recorded.stderr_compare.as_str() {
        "exact" => {
            if stderr != recorded.stderr {
                problems.push(format!(
                    "stderr {stderr:?} != recorded {:?}",
                    recorded.stderr
                ));
            }
        }
        "prefix" => {
            if !stderr.starts_with(&recorded.stderr_prefix) {
                problems.push(format!(
                    "stderr {stderr:?} lacks recorded prefix {:?}",
                    recorded.stderr_prefix
                ));
            }
        }
        other => problems.push(format!("unknown stderr_compare {other:?}")),
    }
    problems
}

// ---------------------------------------------------------------- case runner

fn secrets(fixture: &Fixture) -> std::collections::BTreeMap<String, Vec<u8>> {
    fixture
        .secret_hex
        .iter()
        .map(|(name, value)| (name.clone(), hex::decode(value).expect("secret hex")))
        .collect()
}

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

struct CaseRun {
    output: Output,
    state: ServerState,
    port: u16,
}

fn run_case(binary: &Path, fixture: &Fixture, case: &Case) -> CaseRun {
    let temp = tempfile::tempdir().expect("case tempdir");
    let vault = temp.path().join("vault");
    let home = temp.path().join("home");
    fs::create_dir_all(&vault).expect("vault dir");
    fs::create_dir_all(&home).expect("home dir");
    fs::write(
        vault.join("identity.age"),
        b"test-only initialization marker",
    )
    .expect("identity");
    fs::write(vault.join("config.yaml"), b"{}\n").expect("config");
    let secret = secrets(fixture)
        .remove(&case.secret)
        .unwrap_or_else(|| panic!("secret class {:?}", case.secret));
    fs::write(vault.join("mcp-server.enroll-secret"), secret).expect("secret");

    let server = ReplayServer::start(&case.server_tls, case.exchanges.clone());
    let bind = if case.runtime.port == "non_loopback_bind" {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    if case.runtime.port != "absent" {
        fs::write(
            vault.join(".runtime-port"),
            serde_json::to_vec(&serde_json::json!({ "port": server.port, "bind": bind }))
                .expect("runtime port"),
        )
        .expect("write runtime port");
    }
    fs::write(
        vault.join(".runtime-tls-cert"),
        serde_json::to_vec(&runtime_tls_record(&case.runtime.tls)).expect("runtime tls"),
    )
    .expect("write runtime tls");

    let port = server.port;
    let output = Command::new(binary)
        .arg("--vault")
        .arg(&vault)
        .args(&case.args)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run Rust CLI");
    CaseRun {
        output,
        state: server.finish(),
        port,
    }
}

/// Returns every divergence of one case from its Go recording.
fn judge(fixture: &Fixture, case: &Case, run: &CaseRun) -> Vec<String> {
    let mut problems = Vec::new();
    let stdout = String::from_utf8_lossy(&run.output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&run.output.stderr).into_owned();
    problems.extend(compare_outcome(
        &case.outcome,
        run.output.status.code(),
        &stdout,
        &stderr,
    ));
    // The server's own wake-up connection is never counted.
    let cli_connections = run.state.connections;
    let observed = &run.state.observed;
    if observed.len() != case.exchanges.len() {
        problems.push(format!(
            "CLI made {} HTTP request(s), recorded {}",
            observed.len(),
            case.exchanges.len()
        ));
    }
    let secret_map = secrets(fixture);
    for (seen, exchange) in observed.iter().zip(&case.exchanges) {
        if let Err(error) =
            check_request(seen, &exchange.request, run.port, &secret_map, now_secs())
        {
            problems.push(format!("request: {error}"));
        }
    }
    let expects_connect_failure =
        case.exchanges.is_empty() && case.outcome.stderr_compare == "prefix";
    if case.exchanges.is_empty() {
        if expects_connect_failure {
            if cli_connections == 0 {
                problems.push("expected a TLS connection attempt, saw none".to_owned());
            }
        } else if cli_connections != 0 {
            problems.push(format!(
                "client-side failure must not touch the network, saw {cli_connections} connection(s)"
            ));
        }
    }
    problems
}

// ---------------------------------------------------------------- tests

#[test]
fn fixture_is_self_consistent_and_covers_the_contract() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit.len(), 40);
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(!fixture.oracle.source_files.is_empty());
    // Committed certificates are the ones the Go oracle recorded against.
    for cert in &fixture.certs {
        let name = cert.path.rsplit('/').next().expect("cert file name");
        let bytes = fs::read(certs_dir().join(name)).expect("fixture certificate");
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            digest, cert.sha256,
            "certificate {name} drifted from the recording"
        );
    }
    let ids: Vec<&str> = fixture.cases.iter().map(|case| case.id.as_str()).collect();
    for required in [
        "list_json",
        "list_text",
        "list_yaml",
        "list_quiet",
        "list_empty",
        "approve_json",
        "deny_text",
        "deny_quiet",
        "decide_repeat_conflict",
        "decide_unknown_id",
        "decide_expired",
        "bad_hmac_list",
        "bad_hmac_decide",
        "non_loopback_bind",
        "mtls_missing_identity",
        "mtls_reused_server_identity",
        "mtls_wrong_ca",
        "mtls_wrong_key",
        "mtls_handshake_rejected",
        "tls_only_list",
    ] {
        assert!(ids.contains(&required), "fixture lost case {required}");
    }
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "duplicate case ids");
}

#[test]
fn rust_cli_replays_the_go_recorded_approval_contract() {
    let fixture = load_fixture();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let run = run_case(&binary, &fixture, case);
        let problems = judge(&fixture, case, &run);
        if !problems.is_empty() {
            failures.push(format!("{}:\n    {}", case.id, problems.join("\n    ")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} recorded cases diverge:\n{}",
        failures.len(),
        fixture.cases.len(),
        failures.join("\n")
    );
    eprintln!("replayed {} recorded Go cases", fixture.cases.len());
}

/// Negative controls: the judge must reject a tampered recording or request,
/// otherwise a green replay proves nothing.
#[test]
fn replay_judge_rejects_tampered_recordings_and_requests() {
    let fixture = load_fixture();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let case = fixture
        .cases
        .iter()
        .find(|case| case.id == "approve_json")
        .expect("approve_json case");
    let run = run_case(&binary, &fixture, case);
    assert!(
        judge(&fixture, case, &run).is_empty(),
        "approve_json must replay clean before it is mutated"
    );

    // One recorded stdout byte flipped.
    let mut mutated = case.clone();
    mutated.outcome.stdout = mutated.outcome.stdout.replacen("approved", "approveD", 1);
    assert!(
        !judge(&fixture, &mutated, &run).is_empty(),
        "a flipped recorded stdout byte must fail"
    );
    // Exit code and stderr.
    let mut mutated = case.clone();
    mutated.outcome.exit_code = 1;
    assert!(!judge(&fixture, &mutated, &run).is_empty());
    let mut mutated = case.clone();
    mutated.outcome.stderr = "Error: x\n".to_owned();
    assert!(!judge(&fixture, &mutated, &run).is_empty());

    // The recorded request path changed.
    let mut mutated = case.clone();
    mutated.exchanges[0].request.path.push('x');
    assert!(!judge(&fixture, &mutated, &run).is_empty());

    // Mutations of the request the Rust CLI actually sent.
    let seen = run.state.observed[0].clone();
    let recorded = &case.exchanges[0].request;
    let secret_map = secrets(&fixture);
    let ok =
        |observed: &Observed| check_request(observed, recorded, run.port, &secret_map, now_secs());
    ok(&seen).expect("the real request satisfies the recording");

    let mut tampered = seen.clone();
    for (name, value) in &mut tampered.headers {
        if name == "x-enroll-proof" {
            value.replace_range(0..1, if value.starts_with('0') { "1" } else { "0" });
        }
    }
    assert!(ok(&tampered).unwrap_err().contains("X-Enroll-Proof"));

    let mut tampered = seen.clone();
    tampered
        .headers
        .retain(|(name, _)| name != "x-enroll-timestamp");
    assert!(
        ok(&tampered)
            .unwrap_err()
            .contains("missing contract header")
    );

    let mut tampered = seen.clone();
    tampered
        .headers
        .push(("authorization".to_owned(), "Bearer x".to_owned()));
    assert!(
        ok(&tampered)
            .unwrap_err()
            .contains("forbidden extra request header")
    );

    let mut tampered = seen.clone();
    tampered.method = "GET".to_owned();
    assert!(ok(&tampered).unwrap_err().contains("method"));

    let mut tampered = seen.clone();
    tampered.client_cn.clear();
    assert!(ok(&tampered).unwrap_err().contains("mTLS client identity"));

    // A stale timestamp (properly re-signed) is outside the proof window.
    let mut tampered = seen.clone();
    let stale = "2020-01-01T00:00:00Z";
    for (name, value) in &mut tampered.headers {
        match name.as_str() {
            "x-enroll-timestamp" => *value = stale.to_owned(),
            "x-enroll-proof" => *value = hmac_hex(&secret_map["valid"], stale.as_bytes()),
            _ => {}
        }
    }
    assert!(ok(&tampered).unwrap_err().contains("proof window"));

    // A proof made with the wrong secret fails against a "valid" recording.
    let mut tampered = seen;
    for (name, value) in &mut tampered.headers {
        if name == "x-enroll-proof" {
            let timestamp = header_value(&seen_headers(&run), "x-enroll-timestamp");
            *value = hmac_hex(&secret_map["wrong"], timestamp.as_bytes());
        }
    }
    assert!(ok(&tampered).unwrap_err().contains("X-Enroll-Proof"));
}

fn seen_headers(run: &CaseRun) -> Vec<(String, String)> {
    run.state.observed[0].headers.clone()
}

fn header_value(headers: &[(String, String)], name: &str) -> String {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .expect("header present")
}
