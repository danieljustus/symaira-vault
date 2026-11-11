//! ADR 0037 R17 (HTTP-004): replays `testdata/port/mcp/http-budget-combinations.json`,
//! recorded from the production Go server (`RunHTTPServerOnListener`) for seven
//! combinations of `read_header_timeout`, `read_timeout` and `write_timeout`.
//! The recording carries its own probe specs, so Go and Rust receive the same
//! byte schedule; the client below is the Rust twin of the Go recorder
//! (`scripts/rust-port/http_budget_record.go.txt`).
//!
//! Compared per probe: whether and when the server closed the connection
//! (elapsed rounded to 500 ms, tolerance one bucket) and the exact status line
//! plus body of every response.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::http::{
    HttpServerOptions, HttpShutdown, LocalApprovalApi, OAuthConsentDecision,
    serve_with_oauth_and_approval_options_until,
};
use symvault_mcp::{ProtocolHandler, ToolCallResult, ToolCallRuntime};

const RECORDING: &str = include_str!("../../../testdata/port/mcp/http-budget-combinations.json");

#[derive(Deserialize, Clone)]
struct Step {
    at_ms: u64,
    data: String,
}

#[derive(Deserialize, Clone)]
struct Dribble {
    from_ms: u64,
    byte: String,
    interval_ms: u64,
    #[serde(default)]
    until_ms: u64,
}

#[derive(Deserialize, Clone)]
struct Probe {
    id: String,
    steps: Vec<Step>,
    dribble: Option<Dribble>,
    max_ms: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
struct Outcome {
    terminal: String,
    elapsed_bucket_ms: u64,
    responses: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Profile {
    id: String,
    read_header_timeout_ms: u64,
    read_timeout_ms: u64,
    write_timeout_ms: u64,
    probes: Vec<Probe>,
    results: std::collections::BTreeMap<String, Outcome>,
}

#[derive(Deserialize)]
struct Recording {
    oracle_commit: String,
    profiles: Vec<Profile>,
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

struct Server {
    address: std::net::SocketAddr,
    shutdown: HttpShutdown,
    thread: Option<thread::JoinHandle<()>>,
    _directory: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shutdown.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start(profile: &Profile) -> Server {
    let directory = tempfile::tempdir().expect("server directory");
    let registry_path = directory.path().join("mcp-tokens.json");
    std::fs::write(&registry_path, r#"{"version":2,"tokens":{}}"#).expect("write registry");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let address = listener.local_addr().expect("address");
    let shutdown = HttpShutdown::default();
    let server_shutdown = shutdown.clone();
    let options = HttpServerOptions {
        read_header_timeout: Duration::from_millis(profile.read_header_timeout_ms),
        read_timeout: Duration::from_millis(profile.read_timeout_ms),
        write_timeout: Duration::from_millis(profile.write_timeout_ms),
        ..HttpServerOptions::default()
    };
    let api = LocalApprovalApi::new(
        Arc::new(ApprovalQueue::default()),
        b"budget-secret".to_vec(),
    );
    let thread = thread::spawn(move || {
        let template = ProtocolHandler::with_tool_call_runtime("budget", "0", Arc::new(Runtime));
        serve_with_oauth_and_approval_options_until(
            listener,
            registry_path,
            move |_agent| Ok(template.new_session()),
            "default",
            |_client, _redirect| OAuthConsentDecision::Denied,
            |_passphrase| false,
            None,
            api,
            options,
            Some(server_shutdown),
        )
        .expect("serve budget probe");
    });
    Server {
        address,
        shutdown,
        thread: Some(thread),
        _directory: directory,
    }
}

fn bucket(elapsed: Duration) -> u64 {
    let ms = u64::try_from((elapsed + Duration::from_millis(250)).as_millis()).unwrap();
    ms / 500 * 500
}

/// Same reduction as the Go recorder: `status line | body`, a 201 body is
/// shortened because it carries a random client id.
fn responses(raw: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let Some(head_end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
            out.push(format!("partial:{}", rest.len()));
            break;
        };
        let head = String::from_utf8_lossy(&rest[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or_default().to_owned();
        let length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let body_start = head_end + 4;
        let end = (body_start + length).min(rest.len());
        let mut body = String::from_utf8_lossy(&rest[body_start..end])
            .trim()
            .to_owned();
        if status.starts_with("HTTP/1.1 201") {
            body = "<client registration>".into();
        }
        out.push(format!("{status} | {body}"));
        rest = &rest[end..];
    }
    out
}

/// Every byte write of a probe as `(at_ms, data)`, in the order the recorded
/// schedule intends: steps and dribble slots sorted by time, a step first when
/// both fall on the same millisecond.
fn timeline(probe: &Probe, host: &str) -> Vec<(u64, Vec<u8>)> {
    let mut events: Vec<(u64, u8, Vec<u8>)> = probe
        .steps
        .iter()
        .map(|step| {
            (
                step.at_ms,
                0,
                step.data.replace("{host}", host).into_bytes(),
            )
        })
        .collect();
    if let Some(dribble) = &probe.dribble {
        let mut slot = 0_u64;
        loop {
            let at = dribble.from_ms + slot * dribble.interval_ms;
            if (dribble.until_ms > 0 && at > dribble.until_ms) || at >= probe.max_ms {
                break;
            }
            events.push((at, 1, dribble.byte.clone().into_bytes()));
            slot += 1;
        }
    }
    events.sort_by_key(|(at, order, _)| (*at, *order));
    events.into_iter().map(|(at, _, data)| (at, data)).collect()
}

fn run(address: std::net::SocketAddr, probe: &Probe) -> Outcome {
    let host = address.to_string();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).expect("connect");
    let writer = stream.try_clone().expect("clone stream");
    let start = Instant::now();
    let stop = Arc::new(Mutex::new(false));
    let sleep_until = {
        let stop = Arc::clone(&stop);
        move |ms: u64| -> bool {
            let target = start + Duration::from_millis(ms);
            loop {
                if *stop.lock().unwrap() {
                    return false;
                }
                let now = Instant::now();
                if now >= target {
                    return true;
                }
                thread::sleep((target - now).min(Duration::from_millis(10)));
            }
        }
    };
    let send = |stream: &TcpStream, data: &[u8]| -> bool {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
        (&*stream).write_all(data).is_ok()
    };
    // One sender thread walks the merged step/dribble timeline in recorded
    // order. Go's recorder uses a goroutine per stream, which is harmless on a
    // fast host, but a descheduled dribble thread here can deliver its last
    // filler bytes after the next step: they then arrive behind a complete
    // request and open a second, header-timeout-bound request, so the server
    // closes at step + read_header_timeout instead of idling like Go. A single
    // sender may fall behind its clock, never reorder bytes (a step wins a tie).
    let sender_writer = writer.try_clone().unwrap();
    let sender_sleep = sleep_until.clone();
    let schedule = timeline(probe, &host);
    let sender_thread = thread::spawn(move || {
        for (at_ms, data) in schedule {
            if !sender_sleep(at_ms) || !send(&sender_writer, &data) {
                return;
            }
        }
    });

    let mut raw = Vec::new();
    let mut terminal = "cap";
    let mut buffer = [0_u8; 4096];
    while start.elapsed() < Duration::from_millis(probe.max_ms) {
        if stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .is_err()
        {
            // macOS rejects the call once the peer has torn the socket down.
            terminal = "closed";
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => {
                terminal = "closed";
                break;
            }
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                terminal = "closed";
                break;
            }
        }
    }
    let elapsed = start.elapsed();
    *stop.lock().unwrap() = true;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    sender_thread.join().unwrap();
    let responses = responses(&raw);
    Outcome {
        terminal: terminal.into(),
        elapsed_bucket_ms: bucket(elapsed),
        responses: (!responses.is_empty()).then_some(responses),
    }
}

/// Go's body-read timeout surfaces as the handler's `400 invalid_client_metadata`
/// JSON envelope; Rust closes without a late application response. This is the
/// ADR 0024 decision ("Go's optional body-timeout error ... Rust consistently
/// stops with empty EOF/reset"); close time and terminal kind still match.
const GO_BODY_TIMEOUT_ENVELOPE: &str =
    "HTTP/1.1 400 Bad Request | {\"error\":\"invalid_client_metadata\"}";

/// Number of recorded probes that end in that envelope on the Go side. Pinned
/// so a new Go-only response cannot hide behind the documented exception.
const DOCUMENTED_ADR_0024_PROBES: usize = 13;

struct Replayed {
    differences: Vec<String>,
    adr_0024: Vec<String>,
}

fn replay(profile: &Profile) -> Replayed {
    let server = start(profile);
    let observed: Vec<(String, Outcome)> = thread::scope(|scope| {
        let handles: Vec<_> = profile
            .probes
            .iter()
            .map(|probe| scope.spawn(|| (probe.id.clone(), run(server.address, probe))))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut replayed = Replayed {
        differences: Vec::new(),
        adr_0024: Vec::new(),
    };
    for (id, got) in observed {
        let want = &profile.results[&id];
        let same_time = got.elapsed_bucket_ms.abs_diff(want.elapsed_bucket_ms) <= 500;
        let label = format!("{} / {id}", profile.id);
        if got.terminal == want.terminal && same_time && got.responses == want.responses {
            continue;
        }
        let envelope_only = got.terminal == want.terminal
            && same_time
            && got.responses.is_none()
            && want.responses.as_deref() == Some(&[GO_BODY_TIMEOUT_ENVELOPE.to_owned()]);
        if envelope_only {
            replayed.adr_0024.push(label);
        } else {
            replayed
                .differences
                .push(format!("{label}: go {want:?} rust {got:?}"));
        }
    }
    replayed
}

#[test]
fn budget_combinations_match_go_except_the_adr_0024_body_timeout_envelope() {
    let recording: Recording = serde_json::from_str(RECORDING).expect("parse recording");
    assert_eq!(
        recording.oracle_commit,
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    assert_eq!(recording.profiles.len(), 7);
    let mut replayed: Vec<Replayed> = thread::scope(|scope| {
        let handles: Vec<_> = recording
            .profiles
            .iter()
            .map(|profile| scope.spawn(|| replay(profile)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    // ponytail: the replay compares wall-clock close times in 500 ms buckets,
    // and all seven profiles run at once. On a loaded CI runner a single probe
    // can miss its bucket (each failure hit a different probe). A profile with
    // a difference is replayed alone, at most twice more; a real regression is
    // deterministic and stays red. Upgrade path: drive the server with a
    // virtual clock instead of wall time.
    for (profile, result) in recording.profiles.iter().zip(replayed.iter_mut()) {
        for _ in 0..2 {
            if result.differences.is_empty() {
                break;
            }
            *result = replay(profile);
        }
    }
    let differences: Vec<&str> = replayed
        .iter()
        .flat_map(|r| r.differences.iter().map(String::as_str))
        .collect();
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    let documented: usize = replayed.iter().map(|r| r.adr_0024.len()).sum();
    assert_eq!(documented, DOCUMENTED_ADR_0024_PROBES);
}

/// Static facts of the recording that the replay relies on: every probe has a
/// recorded result, header-slow-forever closes at exactly the header budget
/// whatever the read budget, and the header-longer-than-read case (the R17 fix)
/// is part of it.
#[test]
fn recording_pins_the_header_longer_than_read_cases() {
    let recording: Recording = serde_json::from_str(RECORDING).expect("parse recording");
    for profile in &recording.profiles {
        assert_eq!(profile.probes.len(), 8, "{}", profile.id);
        for probe in &profile.probes {
            assert!(profile.results.contains_key(&probe.id), "{}", probe.id);
        }
        let by = |id: &str| &profile.results[id];
        assert_eq!(
            by("header-slow-forever").elapsed_bucket_ms,
            profile.read_header_timeout_ms,
            "{}",
            profile.id
        );
        if profile.read_header_timeout_ms > profile.read_timeout_ms {
            // Headers finished after the read budget but with the body in the
            // same segment: Go still serves the request.
            assert_eq!(
                by("header-ends-after-read-budget-body-together").responses,
                Some(vec![
                    "HTTP/1.1 201 Created | <client registration>".to_owned()
                ]),
                "{}",
                profile.id
            );
        }
    }
}
