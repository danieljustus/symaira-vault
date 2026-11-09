//! ADR 0037 R18 (HTTP-004): replays `testdata/port/mcp/http-tls-lifecycle.json`,
//! recorded from the production Go server (`RunHTTPServerOnListener`) with real
//! certificate files: server identity rotation (files replaced while running,
//! then restart), client certificate "revocation" (client CA file replaced; Go
//! has no CRL/OCSP) and client certificate expiration (expired, not yet valid,
//! expiring while a connection is up). Generator:
//! `scripts/rust-port/http_tls_lifecycle_record.go.txt`.
//!
//! The Rust CLI loads the identity and the client CA once at startup
//! (`load_tls_server_config`, then one `serve_with_oauth_and_approval_options_until`
//! call), which is what this replay mirrors: files are written, the server is
//! started from them, files are replaced while it runs, and it is restarted.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Deserialize;
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::http::{
    HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
    load_tls_server_config, serve_with_oauth_and_approval_options_until,
};
use symvault_mcp::{ProtocolHandler, ToolCallResult, ToolCallRuntime};
use time::{Duration as TimeDuration, OffsetDateTime};

const RECORDING: &str = include_str!("../../../testdata/port/mcp/http-tls-lifecycle.json");

#[derive(Deserialize, Debug, Clone, PartialEq)]
struct Case {
    id: String,
    stage: String,
    outcome: String,
    #[serde(default)]
    detail: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Recording {
    oracle_commit: String,
    cases: Vec<Case>,
}

struct Runtime;

impl ToolCallRuntime for Runtime {
    fn authorize(&self, _name: &str, _arguments: &serde_json::Value) -> Result<(), ToolCallResult> {
        Ok(())
    }

    fn call(&self, name: &str, _arguments: &serde_json::Value) -> Result<ToolCallResult, String> {
        Err(format!("unexpected tool {name}"))
    }
}

struct Ident {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    issuer: Option<CertifiedIssuer<'static, KeyPair>>,
}

fn ca(name: &str, now: OffsetDateTime) -> Ident {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now - TimeDuration::hours(1);
    params.not_after = now + TimeDuration::hours(48);
    let key = KeyPair::generate().unwrap();
    let key_pem = key.serialize_pem();
    let key_der = key.serialize_der();
    let issuer = CertifiedIssuer::self_signed(params, key).unwrap();
    Ident {
        cert_pem: issuer.pem(),
        key_pem,
        cert_der: issuer.der().to_vec(),
        key_der,
        issuer: Some(issuer),
    }
}

fn leaf(
    name: &str,
    ca: &Ident,
    server: bool,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Ident {
    let sans = if server {
        vec!["localhost".to_owned(), "127.0.0.1".to_owned()]
    } else {
        Vec::new()
    };
    let mut params = CertificateParams::new(sans).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    params.use_authority_key_identifier_extension = true;
    params.not_before = not_before;
    params.not_after = not_after;
    let key = KeyPair::generate().unwrap();
    let cert = params
        .signed_by(&key, ca.issuer.as_ref().expect("issuer"))
        .unwrap();
    Ident {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
        issuer: None,
    }
}

struct Server {
    address: SocketAddr,
    shutdown: HttpShutdown,
    thread: Option<thread::JoinHandle<()>>,
    _registry: tempfile::TempDir,
}

impl Server {
    fn stop(mut self) {
        self.stop_in_place();
    }

    fn stop_in_place(&mut self) {
        let _ = self.shutdown.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop_in_place();
    }
}

fn start(address: &str, directory: &Path, mtls: bool) -> Result<Server, String> {
    let ca_file = directory.join("client-ca.pem");
    let tls = load_tls_server_config(
        directory.join("server.pem"),
        directory.join("server.key"),
        mtls.then_some(ca_file.as_path()),
    )?;
    let registry = tempfile::tempdir().unwrap();
    let registry_path: PathBuf = registry.path().join("mcp-tokens.json");
    std::fs::write(&registry_path, r#"{"version":2,"tokens":{}}"#).unwrap();
    let mut listener = None;
    for _ in 0..50 {
        match TcpListener::bind(address) {
            Ok(bound) => {
                listener = Some(bound);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    let listener = listener.expect("bind");
    let address = listener.local_addr().unwrap();
    let shutdown = HttpShutdown::default();
    let server_shutdown = shutdown.clone();
    let api = LocalApprovalApi::new(Arc::new(ApprovalQueue::default()), b"tls-secret".to_vec());
    let thread = thread::spawn(move || {
        let template = ProtocolHandler::with_tool_call_runtime("tls", "0", Arc::new(Runtime));
        serve_with_oauth_and_approval_options_until(
            listener,
            registry_path,
            move |_agent| Ok(template.new_session()),
            "default",
            |_client, _redirect| OAuthConsentDecision::Denied,
            |_passphrase| false,
            Some(tls),
            api,
            HttpServerOptions::default(),
            Some(server_shutdown),
        )
        .expect("serve TLS lifecycle probe");
    });
    Ok(Server {
        address,
        shutdown,
        thread: Some(thread),
        _registry: registry,
    })
}

fn go_alert_text(error: &std::io::Error) -> String {
    let rustls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match rustls_error {
        Some(rustls::Error::AlertReceived(description)) => {
            use rustls::AlertDescription as A;
            match description {
                A::BadCertificate => "bad certificate".into(),
                A::CertificateExpired => "expired certificate".into(),
                A::UnknownCA => "unknown certificate authority".into(),
                A::CertificateRequired => "certificate required".into(),
                A::HandshakeFailure => "handshake failure".into(),
                other => format!("{other:?}"),
            }
        }
        _ => match error.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => "connection-closed".into(),
            _ => format!("other: {error}"),
        },
    }
}

struct Connection {
    tls: ClientConnection,
    socket: TcpStream,
}

#[derive(Clone, Copy, PartialEq)]
enum Version {
    Tls12,
    Tls13,
}

struct Client {
    root: Vec<u8>,
    names: Vec<(Vec<u8>, &'static str)>,
}

impl Client {
    fn config(&self, identity: Option<&Ident>, version: Version) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.root.clone())).unwrap();
        let versions: &[&'static rustls::SupportedProtocolVersion] = match version {
            Version::Tls12 => &[&rustls::version::TLS12],
            Version::Tls13 => &[&rustls::version::TLS13],
        };
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .unwrap()
                .with_root_certificates(roots);
        Arc::new(match identity {
            Some(identity) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(identity.cert_der.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone())),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        })
    }

    /// One handshake plus one discovery GET, or the same GET on `reuse`.
    fn request(
        &self,
        address: SocketAddr,
        config: &Arc<ClientConfig>,
        reuse: Option<Connection>,
        id: &str,
    ) -> (Case, Option<Connection>) {
        let mut case = Case {
            id: id.to_owned(),
            stage: String::new(),
            outcome: String::new(),
            detail: BTreeMap::new(),
        };
        let mut connection = match reuse {
            Some(connection) => connection,
            None => {
                let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut tls = ClientConnection::new(
                    Arc::clone(config),
                    ServerName::try_from("localhost").unwrap(),
                )
                .unwrap();
                let mut socket = socket;
                while tls.is_handshaking() {
                    if let Err(error) = tls.complete_io(&mut socket) {
                        case.stage = "handshake".into();
                        case.outcome = format!("alert:{}", go_alert_text(&error));
                        return (case, None);
                    }
                }
                let leaf = tls.peer_certificates().unwrap()[0].as_ref().to_vec();
                let name = self
                    .names
                    .iter()
                    .find(|(der, _)| *der == leaf)
                    .map_or("unknown", |(_, name)| *name);
                case.detail.insert("server_identity".into(), name.into());
                case.detail.insert(
                    "tls_version".into(),
                    match tls.protocol_version().unwrap() {
                        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3",
                        _ => "TLS 1.2",
                    }
                    .into(),
                );
                Connection { tls, socket }
            }
        };
        let request = format!(
            "GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: {address}\r\n\r\n"
        );
        let mut stream = rustls::Stream::new(&mut connection.tls, &mut connection.socket);
        if let Err(error) = stream.write_all(request.as_bytes()) {
            case.stage = "first-write".into();
            case.outcome = format!("alert:{}", go_alert_text(&error));
            return (case, None);
        }
        let mut raw = Vec::new();
        let mut byte = [0_u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => raw.push(byte[0]),
                Ok(_) => {
                    case.stage = "first-read".into();
                    case.outcome = "alert:connection-closed".into();
                    return (case, None);
                }
                Err(error) => {
                    case.stage = "first-read".into();
                    case.outcome = format!("alert:{}", go_alert_text(&error));
                    return (case, None);
                }
            }
        }
        let head = String::from_utf8_lossy(&raw).into_owned();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body).unwrap();
        case.stage = "response".into();
        case.outcome = format!("status:{status}");
        (case, Some(connection))
    }
}

fn write(path: impl AsRef<Path>, data: &str) {
    std::fs::write(path, data).unwrap();
}

/// Differences that are opaque library choices, as exact
/// `(case, Go outcome, Rust outcome)` triples. Every other field of every case
/// must match. TLS 1.2 without a client certificate is refused by both; Go's
/// crypto/tls sends `handshake_failure` (RFC 5246), rustls sends
/// `certificate_required`. The alert byte is chosen inside the TLS library and
/// the peer sees a failed handshake either way (ADR 0037 R18).
const OPAQUE_ALERT_DIFFERENCES: &[(&str, &str, &str)] = &[(
    "mtls/client-none-tls12",
    "alert:handshake failure",
    "alert:certificate required",
)];

/// The startup refusal for a mismatched key pair has the same stage and
/// outcome on both sides; only the error wording differs (Go: crypto/tls
/// "private key does not match public key" or "load server TLS key pair
/// failed", Rust: "configure TLS server identity: ...").
const MISMATCHED_PAIR_IDS: &[&str] = &[
    "tls/server-identity-mismatched-pair-on-restart",
    "mtls/server-identity-mismatched-pair-on-restart",
];

fn run_all() -> Vec<Case> {
    let now = OffsetDateTime::now_utc();
    let hour = TimeDuration::hours(1);
    let server_ca = ca("r18-server-ca", now);
    let srv_a = leaf(
        "r18-server-a",
        &server_ca,
        true,
        now - hour,
        now + hour * 48,
    );
    let srv_b = leaf(
        "r18-server-b",
        &server_ca,
        true,
        now - hour,
        now + hour * 48,
    );
    let client_ca1 = ca("r18-client-ca-1", now);
    let client_ca2 = ca("r18-client-ca-2", now);
    let other_ca = ca("r18-other-ca", now);
    let good1 = leaf(
        "r18-client-good-1",
        &client_ca1,
        false,
        now - hour,
        now + hour * 24,
    );
    let good2 = leaf(
        "r18-client-good-2",
        &client_ca2,
        false,
        now - hour,
        now + hour * 24,
    );
    let expired = leaf(
        "r18-client-expired",
        &client_ca1,
        false,
        now - hour * 2,
        now - hour,
    );
    let future = leaf(
        "r18-client-not-yet-valid",
        &client_ca1,
        false,
        now + hour,
        now + hour * 2,
    );
    let foreign = leaf(
        "r18-client-foreign",
        &other_ca,
        false,
        now - hour,
        now + hour * 24,
    );
    let short = leaf(
        "r18-client-short",
        &client_ca1,
        false,
        now - hour,
        now + TimeDuration::seconds(3),
    );
    let client = Client {
        root: server_ca.cert_der.clone(),
        names: vec![
            (srv_a.cert_der.clone(), "server-a"),
            (srv_b.cert_der.clone(), "server-b"),
        ],
    };
    let mut cases = Vec::new();

    for mtls in [false, true] {
        let mode = if mtls { "mtls" } else { "tls" };
        let directory = tempfile::tempdir().unwrap();
        let dir = directory.path();
        write(dir.join("server.pem"), &srv_a.cert_pem);
        write(dir.join("server.key"), &srv_a.key_pem);
        write(dir.join("client-ca.pem"), &client_ca1.cert_pem);
        let identity = mtls.then_some(&good1);
        let config = client.config(identity, Version::Tls13);
        let server = start("127.0.0.1:0", dir, mtls).expect("start");
        let address = server.address;
        let (case, kept) = client.request(
            address,
            &config,
            None,
            &format!("{mode}/server-identity-initial"),
        );
        cases.push(case);
        write(dir.join("server.pem"), &srv_b.cert_pem);
        write(dir.join("server.key"), &srv_b.key_pem);
        let (case, _) = client.request(
            address,
            &config,
            None,
            &format!("{mode}/server-identity-new-handshake-after-files-replaced"),
        );
        cases.push(case);
        let (case, _) = client.request(
            address,
            &config,
            kept,
            &format!("{mode}/server-identity-established-connection-after-files-replaced"),
        );
        cases.push(case);
        server.stop();
        let server = start(&address.to_string(), dir, mtls).expect("restart");
        let (case, _) = client.request(
            server.address,
            &config,
            None,
            &format!("{mode}/server-identity-after-restart"),
        );
        cases.push(case);
        server.stop();
        write(dir.join("server.pem"), &srv_a.cert_pem); // key is B's: mismatch
        let id = format!("{mode}/server-identity-mismatched-pair-on-restart");
        cases.push(match start("127.0.0.1:0", dir, mtls) {
            Err(_) => Case {
                id,
                stage: "startup".into(),
                outcome: "error".into(),
                detail: BTreeMap::new(),
            },
            Ok(_) => Case {
                id,
                stage: "startup".into(),
                outcome: "serving".into(),
                detail: BTreeMap::new(),
            },
        });
    }

    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    write(dir.join("server.pem"), &srv_a.cert_pem);
    write(dir.join("server.key"), &srv_a.key_pem);
    write(dir.join("client-ca.pem"), &client_ca1.cert_pem);
    let server = start("127.0.0.1:0", dir, true).expect("start mTLS");
    let address = server.address;
    let cfg = |identity: Option<&Ident>, version| client.config(identity, version);
    let (case, c1) = client.request(
        address,
        &cfg(Some(&good1), Version::Tls13),
        None,
        "mtls/client-valid",
    );
    cases.push(case);
    for (id, identity, version) in [
        ("mtls/client-none", None, Version::Tls13),
        ("mtls/client-none-tls12", None, Version::Tls12),
        ("mtls/client-expired", Some(&expired), Version::Tls13),
        ("mtls/client-expired-tls12", Some(&expired), Version::Tls12),
        ("mtls/client-not-yet-valid", Some(&future), Version::Tls13),
        ("mtls/client-unknown-ca", Some(&foreign), Version::Tls13),
        (
            "mtls/client-unknown-ca-tls12",
            Some(&foreign),
            Version::Tls12,
        ),
    ] {
        let (case, _) = client.request(address, &cfg(identity, version), None, id);
        cases.push(case);
    }
    let (case, short_connection) = client.request(
        address,
        &cfg(Some(&short), Version::Tls13),
        None,
        "mtls/client-expiring-in-3s-before-expiry",
    );
    cases.push(case);
    write(dir.join("client-ca.pem"), &client_ca2.cert_pem);
    let (case, _) = client.request(
        address,
        &cfg(Some(&good1), Version::Tls13),
        None,
        "mtls/client-ca-file-replaced-old-client-new-handshake",
    );
    cases.push(case);
    let (case, _) = client.request(
        address,
        &cfg(Some(&good2), Version::Tls13),
        None,
        "mtls/client-ca-file-replaced-new-client-new-handshake",
    );
    cases.push(case);
    let (case, _) = client.request(
        address,
        &cfg(Some(&good1), Version::Tls13),
        c1,
        "mtls/client-ca-file-replaced-old-client-established-connection",
    );
    cases.push(case);
    thread::sleep(Duration::from_millis(3500));
    let (case, _) = client.request(
        address,
        &cfg(Some(&short), Version::Tls13),
        short_connection,
        "mtls/client-expiring-in-3s-established-connection-after-expiry",
    );
    cases.push(case);
    let (case, _) = client.request(
        address,
        &cfg(Some(&short), Version::Tls13),
        None,
        "mtls/client-expiring-in-3s-new-handshake-after-expiry",
    );
    cases.push(case);
    server.stop();
    let server = start(&address.to_string(), dir, true).expect("restart mTLS");
    let (case, _) = client.request(
        server.address,
        &cfg(Some(&good1), Version::Tls13),
        None,
        "mtls/after-restart-old-client",
    );
    cases.push(case);
    let (case, _) = client.request(
        server.address,
        &cfg(Some(&good2), Version::Tls13),
        None,
        "mtls/after-restart-new-client",
    );
    cases.push(case);
    server.stop();
    cases
}

#[test]
fn tls_lifecycle_matches_the_go_recording() {
    let recording: Recording = serde_json::from_str(RECORDING).expect("parse recording");
    assert_eq!(
        recording.oracle_commit,
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    let observed = run_all();
    assert_eq!(
        observed.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        recording
            .cases
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        "case order and set"
    );
    let mut differences = Vec::new();
    let mut opaque = Vec::new();
    for (got, want) in observed.iter().zip(&recording.cases) {
        let mut want_detail = want.detail.clone();
        let go_error = want_detail.remove("go_error");
        assert_eq!(
            go_error.is_some(),
            MISMATCHED_PAIR_IDS.contains(&want.id.as_str()),
            "{}",
            want.id
        );
        if got.stage == want.stage && got.outcome == want.outcome && got.detail == want_detail {
            continue;
        }
        let known = OPAQUE_ALERT_DIFFERENCES.iter().any(|(id, go, rust)| {
            *id == got.id
                && want.outcome == *go
                && got.outcome == *rust
                && got.stage == want.stage
                && got.detail == want_detail
        });
        if known {
            opaque.push(got.id.clone());
        } else {
            differences.push(format!("{}: go {want:?} rust {got:?}", got.id));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    assert_eq!(opaque.len(), OPAQUE_ALERT_DIFFERENCES.len(), "{opaque:?}");
}

#[test]
fn recording_pins_what_the_go_server_never_reloads() {
    let recording: Recording = serde_json::from_str(RECORDING).expect("parse recording");
    let find = |id: &str| recording.cases.iter().find(|c| c.id == id).unwrap();
    for mode in ["tls", "mtls"] {
        let identity = |id: &str| {
            find(&format!("{mode}/{id}")).detail["server_identity"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(identity("server-identity-initial"), "server-a");
        assert_eq!(
            identity("server-identity-new-handshake-after-files-replaced"),
            "server-a"
        );
        assert_eq!(identity("server-identity-after-restart"), "server-b");
    }
    assert_eq!(
        find("mtls/client-ca-file-replaced-old-client-new-handshake").outcome,
        "status:200"
    );
    assert_eq!(
        find("mtls/after-restart-old-client").outcome,
        "alert:unknown certificate authority"
    );
}
