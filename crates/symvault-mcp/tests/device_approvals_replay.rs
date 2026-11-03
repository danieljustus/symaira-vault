//! Replays `testdata/port/approval/device-approvals.json`, recorded by
//! `scripts/rust-port/cmd/deviceapprovalgen` from the production Go
//! `approval.HTTPHandler` + `pairing.DeviceSessionStore` behind Go's
//! `http.ServeMux`, against the Rust MCP HTTP server. No Go is involved at
//! replay time.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::http::{
    HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
    serve_with_oauth_and_approval_options_until,
};
use symvault_sync::DeviceSessionStore;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const ORACLE_COMMIT: &str = "8d2e5e156cd95f04e608182ab8179fdd49f1884a";
const SOURCE_DIGEST: &str = "79d0307ea78ee1268163236ef54f8eb821c81ff91150357f486793b759186ea1";
const GENERATOR_DIGEST: &str = "6aa4360a939ce208a05b1ed1707b84bca07431afef47f969f0e97a6cf099e379";
const EXPECTED_CASES: usize = 22;
const EXPECTED_REQUESTS: usize = 88;
const CONTRACT_HEADERS: [&str; 3] = ["Content-Type", "X-Content-Type-Options", "Location"];

const CANONICAL_CREATED: &str = "2026-01-02T03:04:05.123456789Z";
const CANONICAL_EXPIRES: &str = "2026-01-02T03:09:05.123456789Z";
const CANONICAL_DECIDED: &str = "2026-01-02T03:04:07.25Z";
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    mounting: Vec<String>,
    counts: BTreeMap<String, usize>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    source_files: Vec<SourceFile>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Deserialize)]
struct SourceFile {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    devices: Vec<Device>,
    queue: Option<Vec<QueueItem>>,
    #[serde(default)]
    settle_ms: u64,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Device {
    name: String,
    device_id: String,
    state: String,
}

#[derive(Deserialize)]
struct QueueItem {
    key: String,
    agent_name: String,
    path: String,
    write: bool,
    reason: String,
    #[serde(default)]
    ttl_ms: u64,
}

#[derive(Deserialize)]
struct Step {
    action: String,
    #[serde(default)]
    device: String,
    request: Option<Request>,
    response: Option<Response>,
}

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    #[serde(default)]
    auth_header_name: String,
    authorization: String,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/approval/device-approvals.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read device approvals fixture"))
        .expect("parse device approvals fixture")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn fixture_is_the_pinned_go_recording() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.source_digest, SOURCE_DIGEST);
    assert_eq!(fixture.oracle.generator_digest, GENERATOR_DIGEST);
    assert_eq!(
        fixture.oracle.generator_files,
        ["scripts/rust-port/cmd/deviceapprovalgen/main.go"]
    );
    let paths = fixture
        .oracle
        .source_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "cmd/mcp/serve_deps.go",
            "internal/approval/http.go",
            "internal/approval/queue.go",
            "internal/mcp/auth/token.go",
            "internal/mcp/serverbootstrap/http.go",
            "internal/pairing/devicesession.go",
        ]
    );
    // The source digest is derived exactly as the generator derives it.
    let mut digest = Sha256::new();
    for file in &fixture.oracle.source_files {
        digest.update(file.path.as_bytes());
        let raw = (0..file.sha256.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&file.sha256[index..index + 2], 16).expect("hex"))
            .collect::<Vec<_>>();
        assert_eq!(raw.len(), 32, "{}", file.path);
        digest.update(&raw);
    }
    assert_eq!(
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        fixture.oracle.source_digest
    );
    assert_eq!(fixture.mounting.len(), 4);
    assert!(
        fixture
            .mounting
            .iter()
            .any(|line| line.contains("mux.Handle(approval.PathApprovals, approvalChain)"))
    );
    assert!(
        fixture
            .mounting
            .iter()
            .any(|line| line.contains("mux.Handle(approval.PathApprovalAction, approvalChain)"))
    );
    let requests = fixture
        .cases
        .iter()
        .flat_map(|case| &case.steps)
        .filter(|step| step.action == "request")
        .count();
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);
    assert_eq!(requests, EXPECTED_REQUESTS);
    assert_eq!(fixture.counts["cases"], EXPECTED_CASES);
    assert_eq!(fixture.counts["requests"], EXPECTED_REQUESTS);
}

struct Server {
    address: SocketAddr,
    shutdown: HttpShutdown,
    thread: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(api: LocalApprovalApi, registry: &std::path::Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let shutdown = HttpShutdown::default();
        let server_shutdown = shutdown.clone();
        let registry = registry.to_path_buf();
        let thread = thread::spawn(move || {
            serve_with_oauth_and_approval_options_until(
                listener,
                registry,
                |_| Err("no agent in the approval replay".to_owned()),
                "default",
                |_, _| OAuthConsentDecision::Denied,
                |_| false,
                None,
                api,
                HttpServerOptions::default(),
                Some(server_shutdown),
            )
            .expect("serve Rust MCP HTTP");
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
        }
    }

    fn send(&self, head: &str, header_lines: &[(String, String)], body: &str) -> Reply {
        let mut stream = TcpStream::connect(self.address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        let mut raw = format!("{head} HTTP/1.1\r\nHost: {}\r\n", self.address);
        for (name, value) in header_lines {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            raw.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        raw.push_str("Connection: close\r\n\r\n");
        raw.push_str(body);
        stream.write_all(raw.as_bytes()).expect("send request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        Reply::parse(&response)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shutdown.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn parse(raw: &[u8]) -> Self {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or_else(|| {
                panic!("no header terminator in {:?}", String::from_utf8_lossy(raw))
            });
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status code");
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
            .collect::<Vec<_>>();
        assert!(
            !headers.iter().any(
                |(name, value)| name.eq_ignore_ascii_case("transfer-encoding")
                    && value.contains("chunked")
            ),
            "responses carry a Content-Length"
        );
        Self {
            status,
            headers,
            body: String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct World {
    tokens: BTreeMap<String, String>,
    ids: BTreeMap<String, String>,
    canonical_ids: Vec<(String, String)>,
}

impl World {
    fn expand(&self, template: &str) -> String {
        let mut out = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let tail = &rest[start..];
            let placeholder = ["{id:", "{idtail:", "{token:"]
                .iter()
                .find(|prefix| tail.starts_with(**prefix))
                .and_then(|prefix| {
                    tail.find('}')
                        .map(|end| (&prefix[1..prefix.len() - 1], &tail[prefix.len()..end], end))
                });
            let Some((kind, name, end)) = placeholder else {
                out.push('{');
                rest = &tail[1..];
                continue;
            };
            match kind {
                "id" => out.push_str(&self.ids[name]),
                "idtail" => out.push_str(self.ids[name].strip_prefix('a').expect("id tail")),
                _ => out.push_str(&self.tokens[name]),
            }
            rest = &tail[end + 1..];
        }
        out.push_str(rest);
        out
    }

    fn canonical(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for (real, canonical) in &self.canonical_ids {
            text = text.replace(real, canonical);
        }
        text = replace_field(&text, "created_at", |value| {
            assert_instant(value);
            CANONICAL_CREATED.to_owned()
        });
        text = replace_field(&text, "expires_at", |value| {
            assert_instant(value);
            CANONICAL_EXPIRES.to_owned()
        });
        replace_field(&text, "decided_at", |value| {
            if value == ZERO_TIME {
                return value.to_owned();
            }
            assert_instant(value);
            CANONICAL_DECIDED.to_owned()
        })
    }
}

fn assert_instant(value: &str) {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|error| panic!("timestamp {value:?} is not RFC 3339: {error}"));
    assert!(value.ends_with('Z'), "timestamps are UTC: {value}");
}

/// Replaces the value of every `"key":"<value>"` string field.
fn replace_field(text: &str, key: &str, mut replace: impl FnMut(&str) -> String) -> String {
    let needle = format!("\"{key}\":\"");
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find(&needle) {
        let value_start = start + needle.len();
        out.push_str(&rest[..value_start]);
        let end = rest[value_start..].find('"').expect("closing quote") + value_start;
        out.push_str(&replace(&rest[value_start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

const MCP_REGISTRY_TOKEN: &str = "mcp-registry-token-not-a-device";

fn write_registry(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("mcp-tokens.json");
    let hash = sha256_hex(MCP_REGISTRY_TOKEN.as_bytes());
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 2,
        "tokens": {
            "tok-test": {
                "id": "tok-test",
                "hash": hash,
                "prefix": "mcp-",
                "allowed_tools": ["*"],
                "agent_name": "default",
                "created_at": "2026-01-01T00:00:00Z"
            }
        }
    }))
    .expect("registry JSON");
    std::fs::write(&path, bytes).expect("write token registry");
    path
}

fn expire_device(dir: &std::path::Path, device: &str) {
    let path = dir.join(".symvault/device-sessions.json");
    let mut sessions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read store")).expect("store JSON");
    for session in sessions.as_object_mut().expect("store map").values_mut() {
        if session["device_id"] == device {
            session["expires_at"] = serde_json::json!("2000-01-01T00:00:00Z");
        }
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&sessions).expect("store JSON"),
    )
    .expect("write store");
}

fn run_case(case: &Case) -> usize {
    let dir = tempfile::tempdir().expect("vault directory");
    let seed = DeviceSessionStore::new(Some(dir.path())).expect("seed store");
    let mut world = World {
        tokens: BTreeMap::new(),
        ids: BTreeMap::new(),
        canonical_ids: Vec::new(),
    };
    for device in &case.devices {
        let token = seed
            .enroll(
                &device.device_id,
                &device.name,
                &format!("pk-{}", device.name),
            )
            .expect("enroll device");
        world.tokens.insert(device.name.clone(), token);
    }
    for device in &case.devices {
        match device.state.as_str() {
            "active" => {}
            "revoked" => seed.revoke(&device.device_id).expect("revoke device"),
            "expired" => expire_device(dir.path(), &device.device_id),
            other => panic!("unknown device state {other}"),
        }
    }
    // Like a server restart: the store is loaded from disk.
    let store = Arc::new(DeviceSessionStore::new(Some(dir.path())).expect("load store"));

    let queue = Arc::new(ApprovalQueue::default());
    for (index, item) in case.queue.iter().flatten().enumerate() {
        let id = queue
            .enqueue_with_ttl(
                &item.agent_name,
                &item.path,
                item.write,
                &item.reason,
                Duration::from_millis(item.ttl_ms),
            )
            .expect("enqueue");
        world
            .canonical_ids
            .push((id.clone(), format!("apr-a{:011}", index + 1)));
        world.ids.insert(item.key.clone(), id);
        thread::sleep(Duration::from_millis(6));
    }
    thread::sleep(Duration::from_millis(case.settle_ms));

    let registry = write_registry(dir.path());
    let api = LocalApprovalApi::new(Arc::clone(&queue), b"replay-vault-secret".to_vec())
        .with_device_sessions(store);
    let server = Server::start(api, &registry);

    let mut requests = 0;
    for (index, step) in case.steps.iter().enumerate() {
        let label = format!("{} step {index}", case.id);
        match step.action.as_str() {
            "revoke_external" => {
                let device_id = case
                    .devices
                    .iter()
                    .find(|device| device.name == step.device)
                    .map_or(step.device.as_str(), |device| device.device_id.as_str());
                DeviceSessionStore::new(Some(dir.path()))
                    .expect("second store")
                    .revoke(device_id)
                    .expect("external revoke");
            }
            "request" => {
                let request = step.request.as_ref().expect("request");
                let expected = step.response.as_ref().expect("response");
                let mut headers = Vec::new();
                if !request.authorization.is_empty() {
                    let name = if request.auth_header_name.is_empty() {
                        "Authorization"
                    } else {
                        request.auth_header_name.as_str()
                    };
                    headers.push((name.to_owned(), world.expand(&request.authorization)));
                }
                let head = format!("{} {}", request.method, world.expand(&request.path));
                let reply = server.send(&head, &headers, &world.expand(&request.body));
                assert_eq!(
                    reply.status, expected.status,
                    "{label}: status, body {:?}",
                    reply.body
                );
                for name in CONTRACT_HEADERS {
                    assert_eq!(
                        reply.header(name).map(|value| world.canonical(value)),
                        expected.headers.get(name).cloned(),
                        "{label}: header {name}"
                    );
                }
                assert_eq!(world.canonical(&reply.body), expected.body, "{label}: body");
                requests += 1;
            }
            other => panic!("unknown action {other}"),
        }
    }
    requests
}

#[test]
fn rust_server_replays_every_recorded_go_exchange() {
    let fixture = fixture();
    let mut cases = 0;
    let mut requests = 0;
    for case in &fixture.cases {
        requests += run_case(case);
        cases += 1;
    }
    assert_eq!(cases, EXPECTED_CASES);
    assert_eq!(requests, EXPECTED_REQUESTS);
}

#[test]
fn mcp_bearers_do_not_authenticate_device_routes_and_device_tokens_do_not_authenticate_mcp() {
    const LEGACY: &str = "legacy-mcp-bearer-not-a-device";
    symvault_mcp::http::set_legacy_bearer(LEGACY);
    let dir = tempfile::tempdir().expect("vault directory");
    let store = DeviceSessionStore::new(Some(dir.path())).expect("store");
    let device_token = store.enroll("dev-phone", "phone", "pk").expect("enroll");
    let queue = Arc::new(ApprovalQueue::default());
    let id = queue
        .enqueue("agent", "notes/a.md", false, "r")
        .expect("enqueue");
    let registry = write_registry(dir.path());
    let api = LocalApprovalApi::new(Arc::clone(&queue), b"secret".to_vec())
        .with_device_sessions(Arc::new(store));
    let server = Server::start(api, &registry);

    for (label, token) in [("legacy", LEGACY), ("registry", MCP_REGISTRY_TOKEN)] {
        let auth = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
        let listed = server.send("GET /api/v1/approvals", &auth, "");
        assert_eq!(listed.status, 401, "{label} list");
        assert_eq!(
            listed.body,
            "{\"error\":\"unauthorized: valid device token required\"}\n"
        );
        let decided = server.send(&format!("POST /api/v1/approvals/{id}/approve"), &auth, "");
        assert_eq!(decided.status, 401, "{label} decide");
    }
    assert_eq!(
        queue.pending().expect("pending").len(),
        1,
        "nothing was decided"
    );

    let mcp = server.send(
        "POST /mcp",
        &[
            ("Authorization".to_owned(), format!("Bearer {device_token}")),
            ("X-Symaira-Agent".to_owned(), "default".to_owned()),
            (
                "Accept".to_owned(),
                "application/json, text/event-stream".to_owned(),
            ),
        ],
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
    );
    assert_eq!(
        mcp.status, 401,
        "a device token is not an MCP token: {}",
        mcp.body
    );

    let ok = server.send(
        "GET /api/v1/approvals",
        &[("Authorization".to_owned(), format!("Bearer {device_token}"))],
        "",
    );
    assert_eq!(ok.status, 200);
}

#[test]
fn device_routes_are_unmounted_without_a_session_store() {
    let dir = tempfile::tempdir().expect("vault directory");
    let registry = write_registry(dir.path());
    let api = LocalApprovalApi::new(Arc::new(ApprovalQueue::default()), b"secret".to_vec());
    let server = Server::start(api, &registry);
    let reply = server.send(
        "GET /api/v1/approvals",
        &[("Authorization".to_owned(), "Bearer anything".to_owned())],
        "",
    );
    assert_eq!(reply.status, 404);
    assert_eq!(reply.body, "404 page not found\n");
}
