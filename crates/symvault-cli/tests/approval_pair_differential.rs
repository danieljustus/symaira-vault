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
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use sha2::Sha256;

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

/// The Go-recorded response of step 0 of fixture case `case`: `(status, body)`.
fn recorded_response(case: &str) -> (u16, String) {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("device-enroll fixture");
    let case = fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"] == case)
        .unwrap_or_else(|| panic!("fixture case {case}"));
    let response = &case["steps"][0]["response"];
    (
        u16::try_from(response["status"].as_u64().expect("status")).expect("status"),
        response["body"].as_str().expect("body").to_owned(),
    )
}

/// One-shot-per-connection TLS server applying the recorded Go proof rule.
struct RecordedHandler {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RecordedHandler {
    fn start(secret: Vec<u8>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join(CERTS);
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(certs.join("server.pem"))
                .expect("open server certificate")
                .collect::<Result<_, _>>()
                .expect("parse server certificate");
        let key = PrivateKeyDer::from_pem_file(certs.join("server.key")).expect("server key");
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server TLS config"),
        );
        let (invalid_status, invalid_body) = recorded_response("mint_proof_required");
        let (ok_status, ok_body) = recorded_response("mint_ok");
        assert_eq!((invalid_status, ok_status), (401, 200));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let connection = ServerConnection::new(Arc::clone(&config)).expect("conn");
                    let mut tls = StreamOwned::new(connection, stream);
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => break,
                        }
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let header = |name: &str| {
                        text.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
                        })
                    };
                    let request_line = text.lines().next().unwrap_or_default();
                    let proven = request_line.starts_with("POST /api/v1/devices/enroll-code ")
                        && header("X-Enroll-Timestamp").is_some_and(|timestamp| {
                            let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("key");
                            mac.update(timestamp.as_bytes());
                            let expected = hex::encode(mac.finalize().into_bytes());
                            let fresh = time::OffsetDateTime::parse(
                                &timestamp,
                                &time::format_description::well_known::Rfc3339,
                            )
                            .is_ok_and(|at| {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("clock")
                                    .as_secs();
                                u64::try_from(at.unix_timestamp())
                                    .is_ok_and(|at| at.abs_diff(now) <= 30)
                            });
                            fresh && header("X-Enroll-Proof").as_deref() == Some(expected.as_str())
                        });
                    let (status, body) = if proven {
                        (ok_status, &ok_body)
                    } else {
                        (invalid_status, &invalid_body)
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(response.as_bytes());
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            })
        };
        Self {
            port,
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

#[test]
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

    let init = run(&rust_binary, &vault, &home, &["init", "--auth", "passphrase"]);
    assert!(init.status.success(), "Rust init: {init:?}");
    let secret = vec![0x5A_u8; 32];
    let server = RecordedHandler::start(secret.clone());
    let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join(CERTS);
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
        "=== Approval Device Pairing ===",
        "Scan this with the Symaira Vault iOS app",
        "Host:        192.168.1.42",
        "Port:",
        "Code:",
        "Fingerprint:",
        "Expires:",
        "C0DE0000000000000000000000000001",
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63206cbd67d3b8a0e",
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
