//! Replays `testdata/port/approval/device-enroll.json`, recorded by
//! `scripts/rust-port/cmd/deviceenrollgen` from the production Go
//! `approval.EnrollCodeHTTPHandler` / `EnrollHTTPHandler` over the real
//! `pairing.TokenStore` and `pairing.DeviceSessionStore` behind Go's
//! `http.ServeMux`, against the Rust MCP HTTP server. No Go is involved at
//! replay time.
//!
//! Values Go draws at random (codes, tokens, device ids, queue ids) or reads
//! from the clock (expiry instants, request timestamps and proofs) are
//! resolved the way the generator resolved them: placeholders in the recorded
//! requests, canonical values in the recorded responses after the shape and
//! the distance from "now" of the real value have been asserted.

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::enroll::{PairingCodes, handle_enroll_code_request, handle_enroll_request};
use symvault_mcp::http::{
    HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
    serve_with_oauth_and_approval_options_until,
};
use symvault_sync::DeviceSessionStore;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const ORACLE_COMMIT: &str = "bfa4e2440bd8338f177bb739f469794948efa519";
const SOURCE_DIGEST: &str = "95217929c171eb36b7886bd8e5891061ee6c92da64b88398a4cbf79b4131c89c";
const GENERATOR_DIGEST: &str = "b9f26a928a7fa8c7afee0fc3bb7599e23fa14c22be5ec03cd425b627e41b7bfe";
const EXPECTED_CASES: usize = 27;
const EXPECTED_REQUESTS: usize = 265;
const CONTRACT_HEADERS: [&str; 3] = ["Content-Type", "X-Content-Type-Options", "Location"];

const CANONICAL_EXPIRES: &str = "2026-01-02T03:09:05.123456789Z";
const CANONICAL_CREATED: &str = "2026-01-02T03:04:05.123456789Z";
const CANONICAL_DECIDED: &str = "2026-01-02T03:04:07.25Z";
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
const OTHER_SECRET: &[u8] = b"a-different-enroll-secret-value!";

/// Cases whose Rust answer is a declared, stricter difference from the Go
/// recording (see the module documentation of `symvault_mcp::enroll`).
const REFUSED_BEFORE_ROUTING: [&str; 1] = ["redeem_body_over_one_mib"];

/// Steps that repeat one of the two proof headers. Go's `Header.Get` reads the
/// first value; the Rust listener refuses any repeated authentication header
/// as a request-smuggling ambiguity (`DUPLICATE_SENSITIVE_HEADERS`), a
/// stricter and already declared policy, before any route runs.
const DUPLICATE_PROOF_HEADER_STEPS: [(&str, usize); 3] = [
    ("mint_proof_required", 8),
    ("mint_proof_required", 9),
    ("mint_proof_required", 10),
];

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    mounting: Vec<String>,
    constants: Constants,
    counts: BTreeMap<String, usize>,
    cases: Vec<Case>,
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
struct Constants {
    secret: String,
    fingerprint: String,
    code_ttl_seconds: u64,
    session_ttl_seconds: u64,
    proof_window_seconds: u64,
    max_failed_attempts: u32,
    failed_cooldown_seconds: u64,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(default)]
    non_loopback_peer: bool,
    #[serde(default)]
    no_fingerprint: bool,
    #[serde(default)]
    code_ttl_ms: u64,
    #[serde(default)]
    queue: Vec<QueueItem>,
    steps: Vec<Step>,
    store_after: Vec<StoredSession>,
}

#[derive(Deserialize)]
struct QueueItem {
    key: String,
    agent_name: String,
    path: String,
    write: bool,
    reason: String,
}

#[derive(Deserialize)]
struct Step {
    action: String,
    #[serde(default)]
    sleep_ms: u64,
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
    headers: BTreeMap<String, String>,
    #[serde(default)]
    extra_header_lines: Vec<String>,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct StoredSession {
    device_id: String,
    name: String,
    public_key: String,
    revoked: bool,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/approval/device-enroll.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read device enroll fixture"))
        .expect("parse device enroll fixture")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn requests_in(fixture: &Fixture) -> usize {
    fixture
        .cases
        .iter()
        .flat_map(|case| &case.steps)
        .filter(|step| step.action == "request")
        .count()
}

#[test]
fn fixture_is_the_pinned_go_recording() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.commit_sha, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.source_digest, SOURCE_DIGEST);
    assert_eq!(fixture.oracle.generator_digest, GENERATOR_DIGEST);
    assert_eq!(
        fixture.oracle.generator_files,
        ["scripts/rust-port/cmd/deviceenrollgen/main.go"]
    );
    assert_eq!(
        fixture.oracle.source_files,
        [
            "cmd/mcp/serve_deps.go",
            "internal/approval/enroll.go",
            "internal/approval/http.go",
            "internal/approval/queue.go",
            "internal/mcp/auth/token.go",
            "internal/mcp/serverbootstrap/http.go",
            "internal/mcp/util.go",
            "internal/pairing/devicesession.go",
            "internal/pairing/token.go",
        ]
    );
    for expected in [
        "mux.Handle(approval.PathDeviceEnroll, enrollChain)",
        "mux.Handle(approval.PathDeviceEnrollCode, enrollCodeChain)",
        "serverbootstrap.WithDeviceEnrollAPI(enrollHandler)",
        "serverbootstrap.WithDeviceEnrollCodeAPI(enrollCodeHandler)",
    ] {
        assert!(
            fixture.mounting.iter().any(|line| line.contains(expected)),
            "mounting evidence for {expected}"
        );
    }
    assert_eq!(fixture.mounting.len(), 9);
    // The recorded Go constants are the ones the Rust side implements.
    let constants = &fixture.constants;
    assert_eq!(
        constants.code_ttl_seconds,
        symvault_mcp::enroll::PAIRING_CODE_TTL.as_secs()
    );
    assert_eq!(
        constants.session_ttl_seconds,
        u64::try_from(symvault_sync::device_sessions::DEFAULT_SESSION_TTL_SECONDS).unwrap()
    );
    assert_eq!(constants.proof_window_seconds, 30);
    assert_eq!(
        constants.max_failed_attempts,
        symvault_sync::pairing::MAX_FAILED_ATTEMPTS
    );
    assert_eq!(
        constants.failed_cooldown_seconds * 1000,
        u64::try_from(symvault_sync::pairing::FAILED_ATTEMPT_COOLDOWN_MS).unwrap()
    );
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);
    assert_eq!(requests_in(&fixture), EXPECTED_REQUESTS);
    assert_eq!(fixture.counts["cases"], EXPECTED_CASES);
    assert_eq!(fixture.counts["requests"], EXPECTED_REQUESTS);
}

// ---------------------------------------------------------------- server

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
                |_| Err("no agent in the enrollment replay".to_owned()),
                "default",
                |_, _| OAuthConsentDecision::Denied,
                |_| false,
                None,
                api,
                // The Go recording drove the handlers on a bare mux, without
                // the per-client limiter; throttling of these routes is
                // recorded by http002ratelimitgen and replayed in
                // http_ratelimit.rs.
                HttpServerOptions {
                    rate_limit: 0,
                    ..HttpServerOptions::default()
                },
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

    /// `None` when the peer reset the connection (an early refusal).
    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Option<Reply> {
        let mut stream = TcpStream::connect(self.address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("read timeout");
        let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.address);
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            // The default content type is not repeated when the case sets one.
            if !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
            {
                raw.push_str("Content-Type: application/json\r\n");
            }
            raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        raw.push_str("Connection: close\r\n\r\n");
        raw.push_str(body);
        // An early refusal may close the socket while the body is still being
        // written; the response (or the reset) is judged by the caller.
        let _ = stream.write_all(raw.as_bytes());
        let mut response = Vec::new();
        match stream.read_to_end(&mut response) {
            Ok(_) if !response.is_empty() => Some(Reply::parse(&response)),
            _ => None,
        }
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

// ---------------------------------------------------------------- world

struct World {
    secret: Vec<u8>,
    codes: Vec<String>,
    tokens: Vec<String>,
    devices: Vec<String>,
    code_canonical: BTreeMap<String, String>,
    device_canonical: BTreeMap<String, String>,
    queue_ids: BTreeMap<String, String>,
    queue_canonical: Vec<(String, String)>,
    code_ttl: Duration,
}

fn canon_code(n: usize) -> String {
    format!("C0DE{n:028}")
}
fn canon_token(n: usize) -> String {
    format!("T0KE{n:028}")
}
fn canon_device(n: usize) -> String {
    format!("dev-{n:016x}")
}

/// `YYYY-MM-DDTHH:MM:SS` of `t`.
fn naive(t: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Spells the whole-second UTC instant `t` in the named way (the generator's
/// `tsForm`).
fn ts_form(form: &str, t: OffsetDateTime) -> String {
    let at = |seconds: i64| t + time::Duration::seconds(seconds);
    match form {
        "utc" => format!("{}Z", naive(t)),
        "plus2" => format!("{}+02:00", naive(at(7200))),
        "minus0530" => format!("{}-05:30", naive(at(-(5 * 3600 + 30 * 60)))),
        "plus00" => format!("{}+00:00", naive(t)),
        "frac" => format!("{}.5Z", naive(t)),
        "frac9" => format!("{}.123456789Z", naive(t)),
        "comma" => format!("{},5Z", naive(t)),
        "lower_t" => format!("{}Z", naive(t)).replacen('T', "t", 1),
        "lower_z" => format!("{}z", naive(t)),
        "space_sep" => format!("{}Z", naive(t)).replacen('T', " ", 1),
        "no_colon" => format!("{}+0200", naive(at(7200))),
        "lead_space" => format!(" {}Z", naive(t)),
        "trail_space" => format!("{}Z ", naive(t)),
        "frac12" => format!("{}.123456789012Z", naive(t)),
        "frac_dot" => format!("{}.Z", naive(t)),
        "no_zone" => naive(t),
        "feb30" => "2026-02-30T00:00:00Z".to_owned(),
        "hour24" => "2026-01-02T24:00:00Z".to_owned(),
        "leap60" => "2026-06-30T23:59:60Z".to_owned(),
        "plus2400" => format!("{}+24:00", naive(at(24 * 3600))),
        "minus2400" => format!("{}-24:00", naive(at(-24 * 3600))),
        "plus2500" => format!("{}+25:00", naive(at(25 * 3600))),
        "plus0060" => format!("{}+00:60", naive(at(3600))),
        "plus0061" => format!("{}+00:61", naive(at(3660))),
        "plus0160" => format!("{}+01:60", naive(at(7200))),
        "single_digit" => format!(
            "{}-{}-{}T{}:{}:{}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        "epoch" => "0001-01-01T00:00:00Z".to_owned(),
        "far" => "9999-12-31T23:59:59Z".to_owned(),
        other => panic!("unknown timestamp form {other}"),
    }
}

fn proof_for(secret: &[u8], t: OffsetDateTime) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
    mac.update(format!("{}Z", naive(t)).as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl World {
    fn expand(&self, template: &str, now: OffsetDateTime) -> String {
        let mut out = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let tail = &rest[start..];
            let parsed = [
                "code", "token", "device", "ts", "proof", "badproof", "pad", "id",
            ]
            .iter()
            .find_map(|kind| {
                let prefix = format!("{{{kind}:");
                let end = tail.find('}')?;
                tail.starts_with(&prefix)
                    .then(|| (*kind, &tail[prefix.len()..end], end))
            });
            let Some((kind, arg, end)) = parsed else {
                out.push('{');
                rest = &tail[1..];
                continue;
            };
            out.push_str(&match kind {
                "code" => self.expand_code(arg),
                "token" => self.tokens[arg.parse::<usize>().unwrap() - 1].clone(),
                "device" => self.devices[arg.parse::<usize>().unwrap() - 1].clone(),
                "id" => self.queue_ids[arg].clone(),
                "pad" => "a".repeat(arg.parse().unwrap()),
                "ts" => {
                    let (form, offset) = arg.split_once(':').expect("ts form:offset");
                    let t = (now + time::Duration::seconds(offset.parse().unwrap()))
                        .replace_nanosecond(0)
                        .unwrap();
                    ts_form(form, t)
                }
                _ => {
                    let (offset, transform) = arg.split_once(':').unwrap_or((arg, ""));
                    let t = (now + time::Duration::seconds(offset.parse().unwrap()))
                        .replace_nanosecond(0)
                        .unwrap();
                    let secret: &[u8] = if kind == "badproof" {
                        OTHER_SECRET
                    } else {
                        &self.secret
                    };
                    let proof = proof_for(secret, t);
                    match transform {
                        "upper" => proof.to_ascii_uppercase(),
                        "short" => proof[..63].to_owned(),
                        "long" => format!("{proof}0"),
                        "nonhex" => format!("g{}", &proof[1..]),
                        "padded" => format!(" {proof} "),
                        _ => proof,
                    }
                }
            });
            rest = &tail[end + 1..];
        }
        out.push_str(rest);
        out
    }

    fn expand_code(&self, arg: &str) -> String {
        let (index, transform) = arg.split_once(':').unwrap_or((arg, ""));
        let code = &self.codes[index.parse::<usize>().unwrap() - 1];
        match transform {
            "lower" => code.to_ascii_lowercase(),
            "cut" => code[..31].to_owned(),
            "plus" => format!("{code}A"),
            "dashed" => format!("{}-{}", &code[..8], &code[8..]),
            _ => code.clone(),
        }
    }

    /// Replaces what is random or clock-derived, after asserting its shape.
    fn canonical(&mut self, text: &str, sent: OffsetDateTime) -> String {
        let mut text = replace_field(text, "code", |real| {
            assert_code_shape(real);
            if let Some(canonical) = self.code_canonical.get(real) {
                return canonical.clone();
            }
            self.codes.push(real.to_owned());
            let canonical = canon_code(self.codes.len());
            self.code_canonical
                .insert(real.to_owned(), canonical.clone());
            canonical
        });
        text = replace_field(&text, "token", |real| {
            assert_code_shape(real);
            self.tokens.push(real.to_owned());
            canon_token(self.tokens.len())
        });
        text = replace_field(&text, "device_id", |real| {
            let hex = real.strip_prefix("dev-").expect("device id prefix");
            assert!(
                hex.len() == 16
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "device id {real:?}"
            );
            self.devices.push(real.to_owned());
            let canonical = canon_device(self.devices.len());
            self.device_canonical
                .insert(real.to_owned(), canonical.clone());
            canonical
        });
        let enrolment = text.contains("\"token\"");
        let minted = text.contains("\"fingerprint\"");
        let code_ttl = self.code_ttl;
        text = replace_field(&text, "expires_at", |real| {
            if minted {
                assert_expiry(real, sent, code_ttl);
            } else if enrolment {
                assert_expiry(real, sent, Duration::from_secs(90 * 24 * 60 * 60));
            } else {
                assert_instant(real);
            }
            CANONICAL_EXPIRES.to_owned()
        });
        for (real, canonical) in &self.queue_canonical {
            text = text.replace(real, canonical);
        }
        for (real, canonical) in &self.device_canonical {
            text = text.replace(real, canonical);
        }
        text = replace_field(&text, "created_at", |value| {
            assert_instant(value);
            CANONICAL_CREATED.to_owned()
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

fn assert_code_shape(value: &str) {
    assert!(
        value.len() == 32
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'V')),
        "random credential {value:?} must be 32 characters of [0-9A-V]"
    );
}

/// RFC 3339 in UTC, the fraction (when present) without trailing zeros.
fn assert_instant(value: &str) {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|error| panic!("timestamp {value:?} is not RFC 3339: {error}"));
    assert!(value.ends_with('Z'), "timestamps are UTC: {value}");
    if let Some((_, fraction)) = value.trim_end_matches('Z').split_once('.') {
        assert!(
            !fraction.is_empty() && !fraction.ends_with('0'),
            "fraction is trimmed like Go's RFC3339Nano: {value}"
        );
    }
}

fn assert_expiry(value: &str, sent: OffsetDateTime, ttl: Duration) {
    assert_instant(value);
    let at = OffsetDateTime::parse(value, &Rfc3339).unwrap();
    let expected = sent + ttl;
    assert!(
        (at - expected).abs() < time::Duration::seconds(3),
        "expires_at {value} is not within 3 s of now + {ttl:?}"
    );
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

fn compact_name(name: &str) -> String {
    if name.len() > 64 && name.bytes().all(|b| b == b'a') {
        format!("{{pad:{}}}", name.len())
    } else {
        name.to_owned()
    }
}

/// Everything a case needs: the in-process pieces both transports share.
struct Rig {
    dir: tempfile::TempDir,
    sessions: Arc<DeviceSessionStore>,
    codes: Arc<PairingCodes>,
    fingerprint: String,
    secret: Vec<u8>,
    queue: Arc<ApprovalQueue>,
}

fn run_case(fixture: &Fixture, case: &Case) -> usize {
    let dir = tempfile::tempdir().expect("vault directory");
    let sessions = Arc::new(DeviceSessionStore::new(Some(dir.path())).expect("session store"));
    let code_ttl = if case.code_ttl_ms > 0 {
        Duration::from_millis(case.code_ttl_ms)
    } else {
        Duration::from_secs(fixture.constants.code_ttl_seconds)
    };
    let rig = Rig {
        sessions,
        codes: Arc::new(PairingCodes::with_ttl(code_ttl)),
        fingerprint: if case.no_fingerprint {
            String::new()
        } else {
            fixture.constants.fingerprint.clone()
        },
        secret: fixture.constants.secret.as_bytes().to_vec(),
        queue: Arc::new(ApprovalQueue::default()),
        dir,
    };
    let mut world = World {
        secret: rig.secret.clone(),
        codes: Vec::new(),
        tokens: Vec::new(),
        devices: Vec::new(),
        code_canonical: BTreeMap::new(),
        device_canonical: BTreeMap::new(),
        queue_ids: BTreeMap::new(),
        queue_canonical: Vec::new(),
        code_ttl,
    };
    for (index, item) in case.queue.iter().enumerate() {
        let id = rig
            .queue
            .enqueue(&item.agent_name, &item.path, item.write, &item.reason)
            .expect("enqueue");
        world
            .queue_canonical
            .push((id.clone(), format!("apr-a{:011}", index + 1)));
        world.queue_ids.insert(item.key.clone(), id);
        thread::sleep(Duration::from_millis(6));
    }

    let registry = write_registry(rig.dir.path());
    let api = LocalApprovalApi::new(Arc::clone(&rig.queue), rig.secret.clone())
        .with_device_sessions(Arc::clone(&rig.sessions))
        .with_device_enrollment(Arc::clone(&rig.codes), rig.fingerprint.clone());
    let server = Server::start(api, &registry);
    let declared_difference = REFUSED_BEFORE_ROUTING.contains(&case.id.as_str());

    let mut requests = 0;
    for (index, step) in case.steps.iter().enumerate() {
        let label = format!("{} step {index}", case.id);
        match step.action.as_str() {
            "sleep" => thread::sleep(Duration::from_millis(step.sleep_ms)),
            "revoke_external" => {
                let device = world.expand(&step.device, OffsetDateTime::now_utc());
                DeviceSessionStore::new(Some(rig.dir.path()))
                    .expect("second store")
                    .revoke(&device)
                    .expect("external revoke");
            }
            "request" => {
                requests += 1;
                let request = step.request.as_ref().expect("request");
                let expected = step.response.as_ref().expect("response");
                let now = OffsetDateTime::now_utc();
                let path = world.expand(&request.path, now);
                let body = world.expand(&request.body, now);
                let mut headers = request
                    .headers
                    .iter()
                    .map(|(name, value)| (name.clone(), world.expand(value, now)))
                    .collect::<Vec<_>>();
                headers.extend(request.extra_header_lines.iter().map(|line| {
                    let line = world.expand(line, now);
                    let (name, value) = line.split_once(": ").expect("header line");
                    (name.to_owned(), value.to_owned())
                }));
                let reply = if case.non_loopback_peer {
                    Some(answer_directly(
                        &rig,
                        &request.method,
                        &path,
                        &body,
                        &headers,
                    ))
                } else {
                    server.send(&request.method, &path, &headers, &body)
                };
                if declared_difference && request.body.contains("{pad:1200000}") {
                    // Go serves a body above 1 MiB (it reads only the first
                    // JSON value); Rust bounds the request before routing:
                    // a 400 or a closed connection, never a 200.
                    assert!(
                        reply.as_ref().is_none_or(|reply| reply.status == 400),
                        "{label}: a body above 1 MiB must be refused"
                    );
                    continue;
                }
                let reply = reply.unwrap_or_else(|| panic!("{label}: no reply"));
                if DUPLICATE_PROOF_HEADER_STEPS.contains(&(case.id.as_str(), index)) {
                    assert_eq!(
                        (reply.status, reply.body.as_str()),
                        (400, "bad request\n"),
                        "{label}: a repeated proof header is refused"
                    );
                    continue;
                }
                assert_eq!(
                    reply.status, expected.status,
                    "{label}: status, body {:?}",
                    reply.body
                );
                for name in CONTRACT_HEADERS {
                    assert_eq!(
                        reply.header(name).map(str::to_owned),
                        expected.headers.get(name).cloned(),
                        "{label}: header {name}"
                    );
                }
                let canonical = world.canonical(&reply.body, now);
                assert_eq!(canonical, expected.body, "{label}: body");
            }
            other => panic!("unknown action {other}"),
        }
    }

    if declared_difference {
        assert!(
            DeviceSessionStore::new(Some(rig.dir.path()))
                .expect("reload store")
                .list()
                .expect("list")
                .is_empty(),
            "{}: a refused body must not enrol",
            case.id
        );
        return requests;
    }

    // The persisted sessions: names, empty public key, revocation; the raw
    // bearer tokens must be absent from the file.
    let path = rig.dir.path().join(".symvault/device-sessions.json");
    let persisted = std::fs::read_to_string(&path).unwrap_or_default();
    for token in &world.tokens {
        assert!(
            !persisted.contains(token.as_str()),
            "{}: raw bearer persisted",
            case.id
        );
    }
    let mut stored = DeviceSessionStore::new(Some(rig.dir.path()))
        .expect("reload store")
        .list()
        .expect("list sessions")
        .into_iter()
        .map(|session| StoredSession {
            device_id: world
                .device_canonical
                .get(&session.device_id)
                .unwrap_or_else(|| panic!("{}: unknown device {}", case.id, session.device_id))
                .clone(),
            name: compact_name(&session.name),
            public_key: session.public_key,
            revoked: session.revoked,
        })
        .collect::<Vec<_>>();
    stored.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    assert_eq!(stored, case.store_after, "{}: persisted sessions", case.id);
    requests
}

/// Cases with a non-loopback peer cannot be produced over a real socket (the
/// plaintext listener refuses such peers before routing), so the handler is
/// asked directly with a documentation-range peer address.
fn answer_directly(
    rig: &Rig,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(String, String)],
) -> Reply {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map_or("", |(_, value)| value.as_str())
    };
    let peer: IpAddr = "192.0.2.9".parse().unwrap();
    let response = handle_enroll_code_request(
        &rig.codes,
        &rig.fingerprint,
        &rig.secret,
        peer,
        method,
        path,
        header("X-Enroll-Timestamp"),
        header("X-Enroll-Proof"),
    )
    .or_else(|| handle_enroll_request(&rig.codes, &rig.sessions, method, path, body));
    match response {
        Some(response) => Reply {
            status: response.status,
            headers: vec![("Content-Type".to_owned(), response.content_type.to_owned())],
            body: String::from_utf8(response.body).expect("UTF-8 body"),
        },
        // The generic mux 404 the server writes for everything else.
        None => Reply {
            status: 404,
            headers: vec![
                (
                    "Content-Type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("X-Content-Type-Options".to_owned(), "nosniff".to_owned()),
            ],
            body: "404 page not found\n".to_owned(),
        },
    }
}

#[test]
fn rust_server_replays_every_recorded_go_exchange() {
    let fixture = fixture();
    let mut requests = 0;
    for case in &fixture.cases {
        requests += run_case(&fixture, case);
    }
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);
    assert_eq!(requests, EXPECTED_REQUESTS);
}

// ------------------------------------------------- properties beyond Go's bytes

#[test]
fn enrollment_routes_are_unmounted_without_both_halves_of_their_state() {
    let dir = tempfile::tempdir().expect("vault directory");
    let registry = write_registry(dir.path());
    let sessions = Arc::new(DeviceSessionStore::new(Some(dir.path())).expect("store"));
    // Sessions but no enrollment state, and enrollment state but no sessions,
    // are the same 404 as no approval API at all.
    let only_sessions = LocalApprovalApi::new(Arc::new(ApprovalQueue::default()), b"s".to_vec())
        .with_device_sessions(Arc::clone(&sessions));
    let only_codes = LocalApprovalApi::new(Arc::new(ApprovalQueue::default()), b"s".to_vec())
        .with_device_enrollment(Arc::new(PairingCodes::new()), "fp");
    for api in [only_sessions, only_codes] {
        let server = Server::start(api, &registry);
        for path in ["/api/v1/devices/enroll", "/api/v1/devices/enroll-code"] {
            let reply = server
                .send("POST", path, &[], r#"{"code":"x"}"#)
                .expect("reply");
            assert_eq!(reply.status, 404, "{path}");
            assert_eq!(reply.body, "404 page not found\n");
        }
    }
}

#[test]
fn a_minted_code_enrols_once_over_the_wire() {
    let dir = tempfile::tempdir().expect("vault directory");
    let registry = write_registry(dir.path());
    let sessions = Arc::new(DeviceSessionStore::new(Some(dir.path())).expect("store"));
    let codes = Arc::new(PairingCodes::new());
    let api = LocalApprovalApi::new(Arc::new(ApprovalQueue::default()), b"wire-secret".to_vec())
        .with_device_sessions(Arc::clone(&sessions))
        .with_device_enrollment(Arc::clone(&codes), "fp");
    let server = Server::start(api, &registry);
    let code = codes.mint().expect("mint");
    let body = format!(r#"{{"code":"{code}","device_name":"p"}}"#);
    let attempts = (0..2)
        .map(|_| {
            server
                .send("POST", "/api/v1/devices/enroll", &[], &body)
                .expect("reply")
                .status
        })
        .collect::<Vec<_>>();
    assert_eq!(attempts, [200, 401]);
    assert_eq!(sessions.list().expect("list").len(), 1);
}
