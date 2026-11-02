//! MCP-TOOLS-PP-001: replays the Go `perplexity_search` / `perplexity_ask`
//! fixture (`testdata/port/mcp/perplexity.json`) through the native runtime
//! against a loopback TLS mock. The production endpoint constant is never
//! contacted: the base URL, `allow_private` and the fixture trust root are
//! injected exactly where Go's tests assign `srv.vault.Config` and swap the
//! HTTP client.

use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use symvault_core::session::MemoryKeyring;
use symvault_mcp::broker::ApiTransportOptions;
use symvault_mcp::perplexity::{PerplexityRuntimeConfig, reset_rate_limiter_for_tests};
use symvault_mcp::store_adapter::StoreReadOnlyRuntime;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Entry, Store, audit::RotationConfig};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit_sha: String,
    go_version: String,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    path: String,
    data: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Reply {
    status: u16,
    body: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    tier: String,
    entries: Option<Vec<FixtureEntry>>,
    #[serde(default)]
    config_key: String,
    base_url: String,
    allow_private: bool,
    #[serde(default)]
    rate_limit_per_min: i64,
    reply: Option<Reply>,
    observed: Observed,
}

#[derive(Debug, Deserialize)]
struct Observed {
    input: Vec<String>,
    output: Vec<Box<serde_json::value::RawValue>>,
    audit: Vec<AuditEvent>,
    #[serde(default)]
    upstream_requests: Vec<Upstream>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct AuditEvent {
    action: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    ok: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Upstream {
    method: String,
    path: String,
    authorization: String,
    content_type: String,
    accept: String,
    raw_body: String,
    body: Value,
}

struct Pki {
    ca_pem: String,
    config: Arc<rustls::ServerConfig>,
}

fn pki() -> Pki {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    let now = time::OffsetDateTime::now_utc();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(5);
    ca_params.not_after = now + time::Duration::days(1);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(1);
    let leaf = params.signed_by(&key, &ca).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap(),
    );
    Pki {
        ca_pem: ca.pem(),
        config,
    }
}

/// One-request-per-connection HTTPS responder recording every request.
struct Mock {
    port: u16,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Upstream>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Mock {
    fn start(pki: &Pki, reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop_flag, seen, tls) = (stop.clone(), requests.clone(), pki.config.clone());
        let worker = thread::spawn(move || {
            while !stop_flag.load(Ordering::Acquire) {
                let Ok((socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(tls.clone()).unwrap(),
                    socket,
                );
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let mut lines = text.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_owned();
                let mut headers = BTreeMap::new();
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
                    }
                }
                let length: usize = headers
                    .get("content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                if stream.read_exact(&mut body).is_err() {
                    continue;
                }
                let raw_body = String::from_utf8_lossy(&body).into_owned();
                let mut parts = request_line.split(' ');
                let (method, path) = (
                    parts.next().unwrap_or_default().to_owned(),
                    parts.next().unwrap_or_default().to_owned(),
                );
                seen.lock().unwrap().push(Upstream {
                    method,
                    path,
                    authorization: headers.get("authorization").cloned().unwrap_or_default(),
                    content_type: headers.get("content-type").cloned().unwrap_or_default(),
                    accept: headers.get("accept").cloned().unwrap_or_default(),
                    body: serde_json::from_str(&raw_body).unwrap_or(Value::Null),
                    raw_body,
                });
                let reason = if reply.status == 200 { "OK" } else { "Status" };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status,
                    reply.body.len(),
                    reply.body
                );
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Self {
            port,
            stop,
            requests,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<Upstream> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

#[test]
fn perplexity_replays_go_fixture_against_loopback_tls_mock() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/mcp/perplexity.json"))
            .expect("decode actual Go perplexity fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "1f965f6e56f2507b9183cf30b822f58f7badb951"
    );
    assert_eq!(fixture.oracle.go_version, "go1.26.6");
    assert!(fixture.cases.len() >= 78, "fixture shrank unexpectedly");
    let pki = pki();
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();

    let mut executed_calls = 0_usize;
    for case in fixture.cases {
        reset_rate_limiter_for_tests();
        let root = tempdir().expect("synthetic disposable vault");
        fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 1\n",
        )
        .unwrap();
        fs::write(
            root.path().join("identity.age"),
            b"synthetic identity marker",
        )
        .unwrap();
        fs::create_dir(root.path().join("entries")).unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(
            symvault_store::data_safety::test_support_pre_marked(root.path()),
            &identity,
        )
        .expect("open synthetic store");
        for entry in case.entries.iter().flatten() {
            store
                .write_new_entry(
                    &entry.path,
                    &Entry {
                        path: entry.path.clone(),
                        data: entry.data.clone(),
                        ..Entry::default()
                    },
                    &identity,
                )
                .unwrap();
        }

        let mock = (case.base_url == "<mock>").then(|| {
            Mock::start(
                &pki,
                Reply {
                    status: case.reply.as_ref().expect("mock reply").status,
                    body: case.reply.as_ref().unwrap().body.clone(),
                },
            )
        });
        let base_url = mock.as_ref().map_or_else(
            || case.base_url.clone(),
            |mock| format!("https://127.0.0.1:{}", mock.port),
        );

        let audit = symvault_store::audit::open_with_keyring(
            "pp-fixture",
            root.path(),
            &MemoryKeyring::new(),
            RotationConfig::default(),
        )
        .expect("open synthetic audit logger");
        let audit_path = audit.path().to_owned();
        let mut tools = read_only_tool_names();
        tools.extend(["perplexity_search".to_owned(), "perplexity_ask".to_owned()]);
        let runtime = StoreReadOnlyRuntime::from_store_with_audit(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: fixture.server_name.clone(),
                server_version: fixture.server_version.clone(),
                transport: "stdio".into(),
                agent_name: "pp-fixture".into(),
                tier: case.tier.clone(),
                allowed_paths: vec!["*".into()],
                approval_mode: "none".into(),
                available_tools: tools,
                vault_dir: "<fixture-vault>".into(),
                vault_unlocked: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            Some(Arc::new(Mutex::new(audit))),
        )
        .expect("construct synthetic runtime")
        .with_perplexity_config(Some(PerplexityRuntimeConfig {
            api_key: case.config_key.clone(),
            base_url,
            rate_limit_per_min: case.rate_limit_per_min,
            allow_private: case.allow_private,
        }))
        .with_api_transport_options(ApiTransportOptions {
            upstream_root_certificates: vec![ca.clone()],
            dns_server: None,
        });
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            Arc::new(runtime),
        );
        let input = case
            .observed
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let lines = run_stream(&input, &mut handler).expect("Rust perplexity protocol dispatch");
        let actual: Vec<Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust response is JSON"))
            .collect();
        assert_eq!(
            lines.len(),
            case.observed.output.len(),
            "frame count for {}",
            case.name
        );
        // Byte-exact. The fixture is pretty-printed, so Go's frames are
        // re-compacted; Go's `<`/`>`/`&` escaping is preserved by compact.
        for (index, (got, want)) in lines.iter().zip(&case.observed.output).enumerate() {
            assert_eq!(
                got,
                &symvault_gojson::compact(want.get()),
                "response frame {index} for {}",
                case.name
            );
        }
        executed_calls += case.observed.input.len() - 2;
        assert!(
            !serde_json::to_string(&actual)
                .unwrap()
                .contains("test-perplexity-key"),
            "{} leaked the API key",
            case.name
        );

        let upstream = mock.map(Mock::finish).unwrap_or_default();
        assert_eq!(
            upstream, case.observed.upstream_requests,
            "upstream requests for {}",
            case.name
        );

        let audit_text = fs::read_to_string(&audit_path).unwrap_or_default();
        let actual_audit: Vec<AuditEvent> = audit_text
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
            .collect();
        assert_eq!(
            actual_audit, case.observed.audit,
            "audit trail for {}",
            case.name
        );
    }
    assert!(
        executed_calls >= 80,
        "too few tools/call frames executed: {executed_calls}"
    );
}

#[test]
fn production_endpoint_is_the_go_constant_and_config_cannot_enable_private_targets() {
    assert_eq!(
        symvault_mcp::perplexity::DEFAULT_BASE_URL,
        "https://api.perplexity.ai"
    );
    let directory = tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    fs::write(
        &config,
        "mcp:\n  perplexity:\n    api_key: k\n    base_url: https://example.test\n    rate_limit_per_min: 3\n    allow_private: true\n",
    )
    .unwrap();
    let loaded = symvault_mcp::perplexity::load_perplexity_config(&config).unwrap();
    assert_eq!(
        loaded,
        PerplexityRuntimeConfig {
            api_key: "k".into(),
            base_url: "https://example.test".into(),
            rate_limit_per_min: 3,
            // Go's mergeMCPConfig never reads allow_private from config.yaml.
            allow_private: false,
        }
    );
    fs::write(&config, "mcp:\n  perplexity:\n    rate_limit_per_min: -4\n").unwrap();
    let loaded = symvault_mcp::perplexity::load_perplexity_config(&config).unwrap();
    assert_eq!(
        loaded.rate_limit_per_min, 0,
        "non-positive limits keep the default"
    );
}
