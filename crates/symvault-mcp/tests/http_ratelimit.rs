//! Replays `testdata/port/mcp/http-ratelimit.json`, recorded from the Go MCP
//! HTTP server's per-client rate limiter (HTTP-002 / HTTP-001 residual).
//!
//! * `limiter_scenarios` / `eviction_scenarios` run the Rust limiter on an
//!   injected clock; Go's real-clock sleeps become exact clock advances.
//! * `stack_scenarios` run the real Rust accept loop over loopback with the
//!   scenario's `config.yaml` parsed by the Rust config loader.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use symvault_core::config::Config;
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::http::{
    HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
    serve_with_oauth_and_approval_options_until,
};
use symvault_mcp::ratelimit::{
    CLEANUP_INTERVAL, MAX_RATE_LIMITER_ENTRIES, REFUSED_BODY, RateLimiter, WINDOW,
};
use symvault_mcp::{ProtocolHandler, ToolCallResult, ToolCallRuntime};
use symvault_sync::DeviceSessionStore;

const BEARER: &str = "http002-ratelimit-fixture-token";

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    defaults: Defaults,
    stack_scenarios: Vec<StackScenario>,
    limiter_scenarios: Vec<LimiterScenario>,
    eviction_scenarios: Vec<EvictionScenario>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Deserialize)]
struct Defaults {
    config_rate_limit: i64,
    window_seconds: u64,
    max_entries: usize,
    cleanup_interval_ms: u64,
    status: u16,
    body: String,
}

#[derive(Deserialize)]
struct StackScenario {
    name: String,
    config_yaml: String,
    effective_config_rate_limit: i64,
    steps: Vec<StackStep>,
}

#[derive(Deserialize)]
struct StackStep {
    note: String,
    request: StackRequest,
    repeat: usize,
    compare: String,
    response: Response,
}

#[derive(Deserialize)]
struct StackRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct Response {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct LimiterScenario {
    name: String,
    limit: u64,
    window_ms: u64,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    steps: Vec<LimiterStep>,
}

#[derive(Deserialize)]
struct LimiterStep {
    op: String,
    #[serde(default)]
    sleep_ms: u64,
    #[serde(default)]
    remote_addr: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    allowed: Option<bool>,
}

#[derive(Deserialize)]
struct EvictionScenario {
    name: String,
    limit: u64,
    window_ms: u64,
    max_entries: usize,
    steps: Vec<EvictionStep>,
    eviction_count: u64,
}

#[derive(Deserialize)]
struct EvictionStep {
    op: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    sleep_ms: u64,
    allowed: Option<bool>,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/mcp/http-ratelimit.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read Go rate-limit fixture"))
        .expect("parse Go rate-limit fixture")
}

#[test]
fn fixture_is_bound_to_the_pinned_oracle() {
    let fixture = fixture();
    assert_eq!(
        fixture.oracle.commit,
        "b1da45d1332fdb118b702dedf4addfb28b890cdf"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/approval/http.go",
            "internal/approval/local.go",
            "internal/config/config_merge.go",
            "internal/config/schema.go",
            "internal/mcp/auth/auth.go",
            "internal/mcp/serverbootstrap/http.go",
            "internal/mcp/serverbootstrap/http_setup.go",
            "internal/mcp/util.go",
        ]
    );
    assert_eq!(
        fixture.oracle.source_digest,
        "8e2e0b56eeba4d4be1600e2f241a04d20b30e5a38ef9388ff7a6d89003c54e6d"
    );
    assert_eq!(
        fixture.oracle.generator_files,
        ["scripts/rust-port/cmd/http002ratelimitgen/main.go"]
    );
    assert_eq!(
        fixture.oracle.generator_digest,
        "f67be139aa99aba09d26f220b10adfcf6c5548d0d9d7216defcea28eacb6f40d"
    );
    assert_eq!(fixture.server_name, "symaira");
    assert_eq!(fixture.server_version, "1.0.0");
    assert_eq!(fixture.stack_scenarios.len(), 9);
    assert_eq!(fixture.limiter_scenarios.len(), 33);
    assert_eq!(fixture.eviction_scenarios.len(), 3);
}

#[test]
fn go_constants_match_the_rust_constants() {
    let defaults = fixture().defaults;
    assert_eq!(defaults.config_rate_limit, 60);
    assert_eq!(defaults.window_seconds, WINDOW.as_secs());
    assert_eq!(defaults.max_entries, MAX_RATE_LIMITER_ENTRIES);
    assert_eq!(
        defaults.cleanup_interval_ms,
        u64::try_from(CLEANUP_INTERVAL.as_millis()).expect("interval")
    );
    assert_eq!(defaults.status, 429);
    assert_eq!(defaults.body, REFUSED_BODY);
    // The Rust config loader resolves the same default for an `mcp` section
    // that does not mention the limit.
    let config = Config::load_from_bytes(b"mcp:\n  allow_insecure_bind: true\n").expect("config");
    assert_eq!(
        config.mcp.expect("mcp section").rate_limit,
        defaults.config_rate_limit
    );
}

fn header_map(step: &LimiterStep, name: &str) -> String {
    step.headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

#[test]
fn limiter_scenarios_match_go() {
    let fixture = fixture();
    let mut requests = 0;
    for scenario in &fixture.limiter_scenarios {
        let base = Instant::now();
        let limiter = RateLimiter::new_at(
            scenario.limit,
            Duration::from_millis(scenario.window_ms),
            &scenario.trusted_proxies,
            base,
        );
        let mut elapsed = Duration::ZERO;
        for (index, step) in scenario.steps.iter().enumerate() {
            match step.op.as_str() {
                "sleep" => elapsed += Duration::from_millis(step.sleep_ms),
                "request" => {
                    let key = limiter.client_key(
                        &step.remote_addr,
                        &header_map(step, "X-Forwarded-For"),
                        &header_map(step, "X-Real-IP"),
                    );
                    assert_eq!(
                        Some(limiter.allow_at(&key, base + elapsed)),
                        step.allowed,
                        "{} step {index} (key {key:?})",
                        scenario.name
                    );
                    requests += 1;
                }
                other => panic!("{}: unknown op {other}", scenario.name),
            }
        }
    }
    assert_eq!(requests, 77, "limiter requests replayed");
}

#[test]
fn eviction_scenarios_match_go() {
    let fixture = fixture();
    for scenario in &fixture.eviction_scenarios {
        let base = Instant::now();
        let limiter = RateLimiter::new_at(
            scenario.limit,
            Duration::from_millis(scenario.window_ms),
            &[],
            base,
        )
        .with_max_entries(scenario.max_entries);
        let mut elapsed = Duration::ZERO;
        for (index, step) in scenario.steps.iter().enumerate() {
            match step.op.as_str() {
                "sleep" => elapsed += Duration::from_millis(step.sleep_ms),
                "allow" => {
                    assert_eq!(
                        Some(limiter.allow_at(&step.ip, base + elapsed)),
                        step.allowed,
                        "{} step {index}",
                        scenario.name
                    );
                    assert!(limiter.len() <= scenario.max_entries);
                }
                other => panic!("{}: unknown op {other}", scenario.name),
            }
        }
        assert_eq!(
            limiter.eviction_count(),
            scenario.eviction_count,
            "{} eviction count",
            scenario.name
        );
    }
}

struct FixtureRuntime;

impl ToolCallRuntime for FixtureRuntime {
    fn authorize(&self, _name: &str, _arguments: &serde_json::Value) -> Result<(), ToolCallResult> {
        Ok(())
    }

    fn call(&self, name: &str, _arguments: &serde_json::Value) -> Result<ToolCallResult, String> {
        Err(format!("unexpected fixture tool {name}"))
    }
}

struct RunningServer {
    address: std::net::SocketAddr,
    shutdown: HttpShutdown,
    thread: Option<thread::JoinHandle<()>>,
    _registry: tempfile::TempDir,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.shutdown.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start(scenario: &StackScenario, server_name: &str, server_version: &str) -> RunningServer {
    let config = Config::load_from_bytes(scenario.config_yaml.as_bytes()).expect("scenario config");
    let mcp = config.mcp.expect("scenario has an mcp section");
    assert_eq!(
        mcp.rate_limit, scenario.effective_config_rate_limit,
        "{}: the Rust config loader resolves the same rate_limit as Go",
        scenario.name
    );
    let options = HttpServerOptions {
        rate_limit: mcp.rate_limit,
        trusted_proxy_ips: mcp.trusted_proxy_ips,
        ..HttpServerOptions::default()
    };

    let registry = tempfile::tempdir().expect("registry dir");
    let hash = symvault_store::sha256_hex(BEARER.as_bytes());
    let registry_path: PathBuf = registry.path().join("mcp-tokens.json");
    std::fs::write(
        &registry_path,
        format!(
            r#"{{"version":2,"tokens":{{"tok-default":{{"id":"tok-default","hash":"{hash}","prefix":"http","allowed_tools":["*"],"agent_name":"default","created_at":"2026-01-01T00:00:00Z"}}}}}}"#
        ),
    )
    .expect("write registry");

    let sessions =
        Arc::new(DeviceSessionStore::new(Some(registry.path())).expect("device session store"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let address = listener.local_addr().expect("address");
    let shutdown = HttpShutdown::default();
    let server_shutdown = shutdown.clone();
    let (name, version) = (server_name.to_owned(), server_version.to_owned());
    let thread = thread::spawn(move || {
        let template =
            ProtocolHandler::with_tool_call_runtime(name, version, Arc::new(FixtureRuntime));
        serve_with_oauth_and_approval_options_until(
            listener,
            registry_path,
            move |_agent| Ok(template.new_session()),
            "default",
            |_client, _redirect| OAuthConsentDecision::Denied,
            |_passphrase| false,
            None,
            LocalApprovalApi::new(
                Arc::new(ApprovalQueue::default()),
                b"fixture-secret".to_vec(),
            )
            .with_device_sessions(sessions),
            options,
            Some(server_shutdown),
        )
        .expect("serve rate-limit fixture");
    });
    RunningServer {
        address,
        shutdown,
        thread: Some(thread),
        _registry: registry,
    }
}

struct Observed {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

fn round_trip(address: std::net::SocketAddr, request: &StackRequest) -> Observed {
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: {address}\r\n",
        request.method, request.path
    );
    for (name, value) in &request.headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    if request.authenticated {
        wire.push_str(&format!("Authorization: Bearer {BEARER}\r\n"));
    }
    if !request.body.is_empty() || request.method == "POST" {
        wire.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    wire.push_str("Connection: close\r\n\r\n");
    wire.push_str(&request.body);

    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream.write_all(wire.as_bytes()).expect("send request");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("status line");
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status code");
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("header line");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_owned(), value.trim().to_owned());
        }
    }
    let mut body = String::new();
    reader.read_to_string(&mut body).expect("body");
    Observed {
        status,
        headers,
        body,
    }
}

fn comparable(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("date") && !name.eq_ignore_ascii_case("connection")
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

#[test]
fn stack_scenarios_match_go_over_the_real_accept_loop() {
    let fixture = fixture();
    let mut served = 0;
    let mut refused = 0;
    for scenario in &fixture.stack_scenarios {
        let server = start(scenario, &fixture.server_name, &fixture.server_version);
        for (index, step) in scenario.steps.iter().enumerate() {
            for repeat in 0..step.repeat {
                let label = format!(
                    "{} step {index} ({}) repeat {repeat}",
                    scenario.name, step.note
                );
                let observed = round_trip(server.address, &step.request);
                assert_eq!(observed.status, step.response.status, "{label} status");
                assert!(
                    !observed
                        .headers
                        .keys()
                        .any(|name| name.eq_ignore_ascii_case("retry-after")),
                    "{label}: Go sends no Retry-After"
                );
                if step.compare == "full" {
                    let expected: BTreeMap<String, String> = step
                        .response
                        .headers
                        .iter()
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                        .collect();
                    assert_eq!(comparable(&observed.headers), expected, "{label} headers");
                    assert_eq!(observed.body, step.response.body, "{label} body");
                }
                if step.response.status == 429 {
                    refused += 1;
                } else {
                    served += 1;
                }
            }
        }
    }
    assert_eq!((served, refused), (364, 30), "stack requests replayed");
}
