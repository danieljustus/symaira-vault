//! `symvault device approval-pair`.
//!
//! * `approval_pair_rejects_loopback_server_like_go_oracle`: the Go answer comes
//!   from `testdata/port/cli-transcripts/approval_pair_differential.json`
//!   (replay-or-fail).
//! * `approval_pair_proves_vault_ownership_against_recorded_go_handler`: the
//!   Rust client talks to a loopback TLS server that answers with the responses
//!   the real Go enroll-code handler (`approval.NewEnrollCodeHTTPHandler`) was
//!   recorded giving in `testdata/port/approval/device-enroll.json`
//!   (`mint_proof_required`, `mint_ok`). The server applies the recorded Go
//!   rule (a 401 unless `X-Enroll-Proof` is the lower-case hex HMAC-SHA256 of
//!   `X-Enroll-Timestamp` under the vault's enroll secret, timestamp within the
//!   30 s proof window); this replaces the former Go test server.

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    env, fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use sha2::{Digest, Sha256};

const ENROLL_SECRET: &str = "mcp-server.enroll-secret";
const FIXTURE: &str = include_str!("../../../testdata/port/approval/device-enroll.json");
const CERTS: &str = "../../testdata/port/approval/certs";
const ORACLE_COMMIT: &str = go_oracle::CONFIG_CLI_ORACLE;

fn run(binary: &Path, root: &Path, home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(root)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1");
    go_oracle::output(&mut command).expect("run CLI")
}

/// One Go-recorded response of step 0 of fixture case `case`.
struct Recorded {
    status: u16,
    content_type: String,
    body: String,
}

fn recorded_response(case: &str) -> Recorded {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("device-enroll fixture");
    let case = fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"] == case)
        .unwrap_or_else(|| panic!("fixture case {case}"));
    let response = &case["steps"][0]["response"];
    Recorded {
        status: u16::try_from(response["status"].as_u64().expect("status")).expect("status"),
        content_type: response["headers"]["Content-Type"]
            .as_str()
            .expect("content type")
            .to_owned(),
        body: response["body"].as_str().expect("body").to_owned(),
    }
}

/// The fingerprint every recorded 200 response carries (a fixture constant);
/// the replay serves the SHA-256 of the certificate it really presents instead.
fn canned_fingerprint() -> String {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("device-enroll fixture");
    fixture["constants"]["fingerprint"]
        .as_str()
        .expect("fixture fingerprint")
        .to_owned()
}

/// What the real `approval.EnrollCodeHTTPHandler` (oracle bfa4e244,
/// `internal/approval/enroll.go`) is constructed with.
#[derive(Clone)]
struct HandlerConfig {
    secret: Vec<u8>,
    /// Empty = "TLS is not configured" (503 after the proof check).
    fingerprint: String,
}

/// The part of an HTTP request the Go handler looks at.
struct Request {
    method: String,
    /// Request target including any query.
    target: String,
    timestamp: Option<String>,
    proof: Option<String>,
    peer: IpAddr,
}

struct Reply {
    status: u16,
    content_type: String,
    body: String,
}

impl From<Recorded> for Reply {
    fn from(recorded: Recorded) -> Self {
        Self {
            status: recorded.status,
            content_type: recorded.content_type,
            body: recorded.body,
        }
    }
}

/// `enrollProofWindow`.
const PROOF_WINDOW: time::Duration = time::Duration::seconds(30);

/// Go's `EnrollProof`: HMAC-SHA256 over `ts.UTC().Format(time.RFC3339)` (UTC,
/// whole seconds, `Z`), hex in lower case.
fn go_enroll_proof(secret: &[u8], ts: time::OffsetDateTime) -> String {
    let formatted = ts
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("zero nanoseconds")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format RFC3339");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("key");
    mac.update(formatted.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Go's `verifyEnrollProof`.
fn go_verify_enroll_proof(
    secret: &[u8],
    timestamp: Option<&str>,
    proof: Option<&str>,
    now: time::OffsetDateTime,
) -> bool {
    let (Some(timestamp), Some(proof)) = (timestamp, proof) else {
        return false;
    };
    if secret.is_empty() || timestamp.is_empty() || proof.is_empty() {
        return false;
    }
    let Ok(at) =
        time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    let diff = now - at;
    if diff > PROOF_WINDOW || diff < -PROOF_WINDOW {
        return false;
    }
    go_enroll_proof(secret, at) == proof
}

/// `EnrollCodeHTTPHandler.ServeHTTP` behind the `ServeMux` pattern
/// `/api/v1/devices/enroll-code`, answering with the recorded Go responses.
fn serve_enroll_code(
    config: &HandlerConfig,
    request: &Request,
    now: time::OffsetDateTime,
) -> Reply {
    let path = request.target.split('?').next().unwrap_or_default();
    // Mux: any other path; handler: any other method.
    if path != "/api/v1/devices/enroll-code" || request.method != "POST" {
        return recorded_response("mint_wrong_method_is_mux_404_before_everything").into();
    }
    if !request.peer.is_loopback() {
        return recorded_response("mint_non_loopback_peer_forbidden").into();
    }
    if !go_verify_enroll_proof(
        &config.secret,
        request.timestamp.as_deref(),
        request.proof.as_deref(),
        now,
    ) {
        return recorded_response("mint_proof_required").into();
    }
    if config.fingerprint.is_empty() {
        return recorded_response("mint_tls_unavailable").into();
    }
    let mut ok: Reply = recorded_response("mint_ok").into();
    let canned = canned_fingerprint();
    assert!(
        ok.body.contains(&canned),
        "recorded mint_ok carries the fixture fingerprint"
    );
    ok.body = ok.body.replace(&canned, &config.fingerprint);
    ok
}

/// SHA-256 (hex) of the leaf certificate a server presents: Go's
/// `serverbootstrap.CertFingerprint`.
fn certificate_fingerprint(certificate_pem: &Path) -> String {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(certificate_pem)
        .expect("open certificate")
        .collect::<Result<_, _>>()
        .expect("parse certificate");
    hex::encode(Sha256::digest(chain[0].as_ref()))
}

/// One-shot-per-connection TLS server applying [`serve_enroll_code`].
struct RecordedHandler {
    port: u16,
    /// Requests that reached the handler (TLS handshake succeeded).
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RecordedHandler {
    /// Serves `certificate`/`key` (file names below the test certificates).
    fn start(config: HandlerConfig, certificate: &str, key: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join(CERTS);
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(certs.join(certificate))
                .expect("open server certificate")
                .collect::<Result<_, _>>()
                .expect("parse server certificate");
        let key = PrivateKeyDer::from_pem_file(certs.join(key)).expect("server key");
        let tls = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server TLS config"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let handle = {
            let (stop, requests) = (Arc::clone(&stop), Arc::clone(&requests));
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let Ok(peer) = stream.peer_addr() else {
                        continue;
                    };
                    let connection = ServerConnection::new(Arc::clone(&tls)).expect("conn");
                    let mut tls_stream = StreamOwned::new(connection, stream);
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls_stream.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => break,
                        }
                    }
                    if head.is_empty() {
                        continue; // the handshake or the request never completed
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let header = |name: &str| {
                        text.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.trim()
                                .eq_ignore_ascii_case(name)
                                .then(|| value.trim().to_owned())
                        })
                    };
                    let mut request_line = text.lines().next().unwrap_or_default().split(' ');
                    let request = Request {
                        method: request_line.next().unwrap_or_default().to_owned(),
                        target: request_line.next().unwrap_or_default().to_owned(),
                        timestamp: header("X-Enroll-Timestamp"),
                        proof: header("X-Enroll-Proof"),
                        peer: peer.ip(),
                    };
                    let reply =
                        serve_enroll_code(&config, &request, time::OffsetDateTime::now_utc());
                    let response = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.status,
                        reply.content_type,
                        reply.body.len(),
                        reply.body
                    );
                    let _ = tls_stream.write_all(response.as_bytes());
                    let _ = tls_stream.flush();
                    tls_stream.conn.send_close_notify();
                    let _ = tls_stream.flush();
                }
            })
        };
        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for RecordedHandler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn request(method: &str, target: &str, timestamp: Option<&str>, proof: Option<&str>) -> Request {
    Request {
        method: method.to_owned(),
        target: target.to_owned(),
        timestamp: timestamp.map(str::to_owned),
        proof: proof.map(str::to_owned),
        peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

/// The recorded Go rule, case by case: each branch of `ServeHTTP` answers with
/// exactly the response the Go handler was recorded giving, and the proof is
/// checked the way Go checks it (HMAC over the re-formatted UTC time, window,
/// lower-case hex, empty secret).
#[test]
fn replay_handler_follows_the_go_enroll_code_rules() {
    use time::{Duration as Span, OffsetDateTime};
    let secret = vec![0x5A_u8; 32];
    let config = HandlerConfig {
        secret: secret.clone(),
        fingerprint: "ab".repeat(32),
    };
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("now");
    let stamp = |at: OffsetDateTime| {
        at.replace_nanosecond(0)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let (ts, proof) = (stamp(now), go_enroll_proof(&secret, now));
    let post = |ts: Option<&str>, proof: Option<&str>| {
        serve_enroll_code(
            &config,
            &request("POST", "/api/v1/devices/enroll-code", ts, proof),
            now,
        )
    };
    let same = |reply: &Reply, case: &str| {
        let recorded = recorded_response(case);
        assert_eq!(
            (
                reply.status,
                reply.content_type.as_str(),
                reply.body.as_str()
            ),
            (
                recorded.status,
                recorded.content_type.as_str(),
                recorded.body.as_str()
            ),
            "{case}"
        );
    };

    // 200 with the served certificate's fingerprint in place of the fixture's.
    let ok = post(Some(&ts), Some(&proof));
    assert_eq!(ok.status, 200);
    assert!(ok.body.contains(&config.fingerprint) && !ok.body.contains(&canned_fingerprint()));

    // 404 for any other method or path (query ignored, trailing slash is another route).
    for (method, target) in [
        ("GET", "/api/v1/devices/enroll-code"),
        ("HEAD", "/api/v1/devices/enroll-code"),
        ("POST", "/api/v1/devices/enroll-code/"),
        ("POST", "/api/v1/devices/enroll-codes"),
        ("POST", "/"),
    ] {
        let reply = serve_enroll_code(
            &config,
            &request(method, target, Some(&ts), Some(&proof)),
            now,
        );
        same(&reply, "mint_wrong_method_is_mux_404_before_everything");
    }
    let with_query = serve_enroll_code(
        &config,
        &request(
            "POST",
            "/api/v1/devices/enroll-code?x=1&y=2",
            Some(&ts),
            Some(&proof),
        ),
        now,
    );
    assert_eq!(with_query.status, 200);

    // 403 for a non-loopback peer, before the proof is looked at.
    let mut remote = request("POST", "/api/v1/devices/enroll-code", None, None);
    remote.peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    same(
        &serve_enroll_code(&config, &remote, now),
        "mint_non_loopback_peer_forbidden",
    );
    remote.peer = IpAddr::V6(Ipv6Addr::LOCALHOST);
    remote.timestamp = Some(ts.clone());
    remote.proof = Some(proof.clone());
    assert_eq!(
        serve_enroll_code(&config, &remote, now).status,
        200,
        "::1 is loopback"
    );

    // 401: missing/empty headers, upper-case hex, wrong secret, unparsable time.
    same(&post(None, None), "mint_proof_required");
    same(&post(Some(&ts), None), "mint_proof_required");
    same(&post(None, Some(&proof)), "mint_proof_required");
    same(&post(Some(""), Some(&proof)), "mint_proof_required");
    same(&post(Some(&ts), Some("")), "mint_proof_required");
    same(
        &post(Some(&ts), Some(&proof.to_uppercase())),
        "mint_proof_required",
    );
    same(
        &post(Some("yesterday"), Some(&proof)),
        "mint_proof_required",
    );
    let wrong = go_enroll_proof(&[0xA5; 32], now);
    same(&post(Some(&ts), Some(&wrong)), "mint_proof_required");

    // The proof is over Go's re-formatted time: a sub-second or offset spelling
    // of the same instant verifies with the proof of the whole-second UTC form,
    // and the proof of the raw header text does not.
    let fractional = format!("{}.250Z", ts.trim_end_matches('Z'));
    assert_eq!(post(Some(&fractional), Some(&proof)).status, 200);
    let offset = now
        .to_offset(time::UtcOffset::from_hms(2, 0, 0).unwrap())
        .replace_nanosecond(0)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert!(offset.ends_with("+02:00"), "{offset}");
    assert_eq!(post(Some(&offset), Some(&proof)).status, 200);
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("key");
    mac.update(offset.as_bytes());
    let raw_text_proof = hex::encode(mac.finalize().into_bytes());
    same(
        &post(Some(&offset), Some(&raw_text_proof)),
        "mint_proof_required",
    );

    // Window: +-30 s accepted, beyond rejected (both directions).
    for (skew, accepted) in [(-29, true), (29, true), (-31, false), (31, false)] {
        let at = now + Span::seconds(skew);
        let reply = post(Some(&stamp(at)), Some(&go_enroll_proof(&secret, at)));
        assert_eq!(reply.status == 200, accepted, "skew {skew}s");
    }

    // An empty enroll secret never verifies (even for the HMAC of the empty key).
    let empty = HandlerConfig {
        secret: Vec::new(),
        fingerprint: config.fingerprint.clone(),
    };
    let reply = serve_enroll_code(
        &empty,
        &request(
            "POST",
            "/api/v1/devices/enroll-code",
            Some(&ts),
            Some(&go_enroll_proof(&[], now)),
        ),
        now,
    );
    same(&reply, "mint_proof_required");

    // 503 once the proof is good but no fingerprint (no TLS) is configured; a bad
    // proof still wins over the 503.
    let no_tls = HandlerConfig {
        secret: secret.clone(),
        fingerprint: String::new(),
    };
    let good = request(
        "POST",
        "/api/v1/devices/enroll-code",
        Some(&ts),
        Some(&proof),
    );
    same(
        &serve_enroll_code(&no_tls, &good, now),
        "mint_tls_unavailable",
    );
    let bad = request("POST", "/api/v1/devices/enroll-code", None, None);
    same(
        &serve_enroll_code(&no_tls, &bad, now),
        "mint_proof_required",
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn approval_pair_rejects_loopback_server_like_go_oracle() {
    let oracle = go_oracle::GoOracle::begin(
        "approval_pair_differential",
        "approval_pair_rejects_loopback_server_like_go_oracle",
        Some(ORACLE_COMMIT),
    );
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_binary = oracle.binary();
    let guard = tempfile::tempdir().expect("temporary directory");
    let go_root = guard.path().join("go-vault");
    let rust_root = guard.path().join("rust-vault");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&go_root).expect("Go vault root");
    fs::create_dir_all(&rust_root).expect("Rust vault root");

    let go_init = run(
        &go_binary,
        &go_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(go_init.status.success(), "Go init: {go_init:?}");
    let rust_init = run(
        &rust_binary,
        &rust_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(rust_init.status.success(), "Rust init: {rust_init:?}");

    for root in [&go_root, &rust_root] {
        fs::write(
            root.join(".runtime-port"),
            br#"{"port":18443,"bind":"127.0.0.1"}"#,
        )
        .expect("write runtime server metadata");
    }

    let go_pair = run(
        &go_binary,
        &go_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    let rust_pair = run(
        &rust_binary,
        &rust_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !go_pair.status.success(),
        "Go unexpectedly paired: {go_pair:?}"
    );
    assert!(
        !rust_pair.status.success(),
        "Rust unexpectedly paired: {rust_pair:?}"
    );
    for (name, output) in [("Go", go_pair), ("Rust", rust_pair)] {
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("127.0.0.1 (loopback-only)"),
            "{name} error did not explain loopback binding: {message}"
        );
    }
    assert_eq!(oracle.calls(), 2);
}

#[test]
fn approval_pair_proves_vault_ownership_against_recorded_go_handler() {
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let guard = tempfile::tempdir().expect("temporary directory");
    let vault = guard.path().join("vault");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&vault).expect("vault root");

    let init = run(
        &rust_binary,
        &vault,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(init.status.success(), "Rust init: {init:?}");
    let secret = vec![0x5A_u8; 32];
    let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join(CERTS);
    // The recorded Go response carries the fingerprint of the certificate the
    // handler was constructed with; the replay serves the SHA-256 of the
    // certificate it really presents, so the client's output ties to it.
    let fingerprint = certificate_fingerprint(&certs.join("server.pem"));
    let server = RecordedHandler::start(
        HandlerConfig {
            secret: secret.clone(),
            fingerprint: fingerprint.clone(),
        },
        "server.pem",
        "server.key",
    );
    fs::write(
        vault.join(".runtime-port"),
        format!(r#"{{"port":{},"bind":"0.0.0.0"}}"#, server.port),
    )
    .expect("runtime port");
    fs::write(
        vault.join(".runtime-tls-cert"),
        serde_json::to_vec(&serde_json::json!({
            "certificate": certs.join("server.pem"),
        }))
        .expect("runtime tls"),
    )
    .expect("runtime tls record");
    let secret_path = vault.join(ENROLL_SECRET);

    fs::write(&secret_path, [0xA5; 32]).expect("install invalid proof secret");
    let invalid = run(
        &rust_binary,
        &vault,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !invalid.status.success(),
        "invalid proof was accepted: {invalid:?}"
    );
    assert!(
        String::from_utf8_lossy(&invalid.stderr)
            .contains("missing or invalid proof of vault-directory ownership"),
        "the recorded Go handler rejects the invalid HMAC proof: {invalid:?}"
    );

    fs::write(&secret_path, &secret).expect("install the handler's enroll secret");
    let paired = run(
        &rust_binary,
        &vault,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        paired.status.success(),
        "valid proof was rejected: {paired:?}"
    );
    let output = String::from_utf8_lossy(&paired.stdout);
    for expected in [
        fingerprint.as_str(),
        "=== Approval Device Pairing ===",
        "Scan this with the Symaira Vault iOS app",
        "Host:        192.168.1.42",
        "Port:",
        "Code:",
        "Fingerprint:",
        "Expires:",
        "C0DE0000000000000000000000000001",
    ] {
        assert!(
            output.contains(expected),
            "pair output missing {expected:?}: {output}"
        );
    }
    assert!(
        output.chars().any(|glyph| matches!(glyph, '█' | '▀' | '▄')),
        "expected QR output at the deterministic 80-column non-terminal width"
    );

    let quiet = run(
        &rust_binary,
        &vault,
        &home,
        &[
            "device",
            "approval-pair",
            "--host",
            "192.168.1.42",
            "--quiet",
        ],
    );
    assert!(quiet.status.success(), "quiet pairing failed: {quiet:?}");
    assert!(quiet.stdout.is_empty(), "--quiet wrote stdout: {quiet:?}");
    assert!(quiet.stderr.is_empty(), "--quiet wrote stderr: {quiet:?}");
}

/// Mutation control for client-side certificate pinning: the same recorded
/// handler, correct enroll secret, but it presents a certificate other than the
/// one `.runtime-tls-cert` pins. The client must refuse before sending anything
/// the handler could answer (no request reaches it, no code is printed); with a
/// client that stops pinning, the 200 response would be accepted and this test
/// fails.
#[test]
fn approval_pair_refuses_a_server_certificate_that_is_not_the_pinned_one() {
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let guard = tempfile::tempdir().expect("temporary directory");
    let vault = guard.path().join("vault");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&vault).expect("vault root");
    let init = run(
        &rust_binary,
        &vault,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(init.status.success(), "Rust init: {init:?}");

    let secret = vec![0x5A_u8; 32];
    let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join(CERTS);
    let server = RecordedHandler::start(
        HandlerConfig {
            secret: secret.clone(),
            fingerprint: certificate_fingerprint(&certs.join("other-server.pem")),
        },
        "other-server.pem",
        "other-server.key",
    );
    fs::write(
        vault.join(".runtime-port"),
        format!(r#"{{"port":{},"bind":"0.0.0.0"}}"#, server.port),
    )
    .expect("runtime port");
    fs::write(
        vault.join(".runtime-tls-cert"),
        serde_json::to_vec(&serde_json::json!({ "certificate": certs.join("server.pem") }))
            .expect("runtime tls"),
    )
    .expect("runtime tls record");
    fs::write(vault.join(ENROLL_SECRET), &secret).expect("enroll secret");

    let paired = run(
        &rust_binary,
        &vault,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !paired.status.success(),
        "a certificate other than the pinned one was accepted: {paired:?}"
    );
    let stderr = String::from_utf8_lossy(&paired.stderr);
    assert!(
        stderr.contains("/api/v1/devices/enroll-code"),
        "expected a connection failure, got: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&paired.stdout).contains("Code:"),
        "a pairing code was printed: {paired:?}"
    );
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        0,
        "the request reached a server whose certificate is not pinned"
    );
}
