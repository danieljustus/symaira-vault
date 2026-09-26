use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use symvault_mcp::http::{HttpRequest, HttpResponse, handle_request};
use symvault_mcp::{ProtocolHandler, ToolCallResult, ToolCallRuntime};

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_digest: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    go_authenticated: bool,
    request: Request,
    response: ExpectedResponse,
}

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    origin: String,
    content_type: String,
    accept: String,
    protocol_version: String,
    agent: String,
    #[serde(default)]
    token_name: String,
    #[serde(default)]
    token_agent: String,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    body_repeat: usize,
    #[serde(default)]
    header_repeat: usize,
    #[serde(default)]
    http_version: String,
    #[serde(default)]
    request_line_repeat: usize,
    #[serde(default)]
    duplicate_authorization: bool,
    #[serde(default)]
    duplicate_content_length: bool,
    body: String,
}

impl Request {
    fn is_wire_case(&self) -> bool {
        !self.http_version.is_empty()
            || self.request_line_repeat > 0
            || self.duplicate_authorization
            || self.duplicate_content_length
    }
}

#[derive(Deserialize)]
struct ExpectedResponse {
    status: u16,
    headers: HashMap<String, String>,
    absent_headers: Vec<String>,
    body: String,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/mcp/http-initialize.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read Go HTTP fixture"))
        .expect("parse Go HTTP fixture")
}

#[test]
fn go_authenticated_http_session_matches_rust_adapter() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.commit, "08c162e5");
    assert_eq!(
        fixture.oracle.commit_sha,
        "08c162e5090b6450889e2840b4caaf1b4c963cef"
    );
    assert_eq!(
        fixture.oracle.source_digest,
        "dee03f837dc962d746609a6e20686c9f4a399f524ee1da2b0ec29b570a1447ef"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("loopback address");
    let token_cases = fixture
        .cases
        .iter()
        .filter(|case| case.go_authenticated && !case.request.is_wire_case())
        .map(|case| {
            (
                case.request.token_name.clone(),
                case.request.allowed_tools.clone(),
            )
        })
        .collect::<Vec<_>>();
    let server_name = fixture.server_name.clone();
    let server_version = fixture.server_version.clone();
    let server = thread::spawn(move || {
        let runtime = FixtureRuntime;
        let template =
            ProtocolHandler::with_tool_call_runtime(server_name, server_version, Arc::new(runtime));
        let mut sessions = HashMap::new();
        for (token_name, allowed_tools) in token_cases {
            let (stream, _) = listener.accept().expect("accept loopback request");
            let handler = sessions
                .entry(token_name)
                .or_insert_with(|| template.new_session());
            serve_one(stream, handler, &allowed_tools);
        }
    });

    for case in &fixture.cases {
        if !case.go_authenticated || case.request.is_wire_case() {
            continue;
        }
        let body = if case.request.body_repeat > 0 {
            "x".repeat(case.request.body_repeat)
        } else {
            case.request.body.clone()
        };
        let host = if case.request.host.is_empty() {
            addr.to_string()
        } else {
            case.request.host.clone()
        };
        let mut stream = TcpStream::connect(addr).expect("connect to Rust loopback adapter");
        write!(
            stream,
            "{} {} HTTP/1.1\r\nHost: {host}\r\nOrigin: {}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nX-Symaira-Agent: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            case.request.method,
            case.request.path,
            case.request.origin,
            case.request.content_type,
            case.request.accept,
            case.request.protocol_version,
            case.request.agent,
            if case.request.header_repeat > 0 {
                format!("X-Rust-Port-Fixture: {}\r\n", "x".repeat(case.request.header_repeat))
            } else {
                String::new()
            },
            body.len(),
            body,
        )
        .expect("send initialize HTTP request");
        let (status, headers, body) = read_response(stream);
        if case.name == "oversized_body_rejected" {
            assert_eq!(case.response.status, 400, "Go body limit response");
            assert_eq!(status, 413, "Rust rejects the body at its parser limit");
            assert_eq!(
                body,
                "{\"error\":{\"message\":\"request body too large\",\"code\":-32700},\"jsonrpc\":\"2.0\"}\n"
            );
            continue;
        }
        assert_eq!(status, case.response.status, "{} status", case.name);
        for (name, value) in &case.response.headers {
            assert_eq!(
                headers.get(&name.to_ascii_lowercase()),
                Some(value),
                "{} header {name}",
                case.name
            );
        }
        for name in &case.response.absent_headers {
            assert!(
                !headers.contains_key(&name.to_ascii_lowercase()),
                "{} unexpectedly returned {name}",
                case.name
            );
        }
        assert_eq!(body, case.response.body, "{} body", case.name);
    }
    server.join().expect("Rust loopback adapter thread");
}

#[test]
fn go_fixture_captures_token_agent_mismatch_rejection() {
    let fixture = fixture();
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "token_agent_mismatch_rejected")
        .expect("Go token-agent mismatch case");
    assert!(!case.go_authenticated);
    assert_eq!(case.request.agent, "other");
    assert_eq!(case.request.token_agent, "default");
    assert_eq!(case.request.token_name, "health");
    assert_eq!(case.response.status, 403);
    assert_eq!(
        case.response.body,
        "forbidden: token agent does not match X-Symaira-Agent header\n"
    );
    assert_eq!(
        case.response
            .headers
            .get("Content-Type")
            .map(String::as_str),
        Some("text/plain; charset=utf-8")
    );
}

#[test]
fn rust_loopback_rejects_go_fixture_token_agent_mismatch() {
    const BEARER: &str = "http001-agent-bound-token";
    let temp = tempfile::tempdir().expect("temporary token registry");
    let hash = symvault_store::sha256_hex(BEARER.as_bytes());
    let registry = temp.path().join("mcp-tokens.json");
    let registry_json = format!(
        r#"{{"version":2,"tokens":{{"tok-agent":{{"id":"tok-agent","hash":"{hash}","prefix":"http","allowed_tools":["health"],"agent_name":"default","created_at":"2026-01-01T00:00:00Z"}}}}}}"#
    );
    std::fs::write(&registry, registry_json).expect("write registry");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let address = listener.local_addr().expect("listener address");
    let registry_path: PathBuf = registry;
    thread::spawn(move || {
        symvault_mcp::http::serve_loopback(listener, registry_path, |_| {
            Err("handler must not be selected for an agent-mismatched token".into())
        })
        .expect("serve loopback request");
    });

    let mut stream = TcpStream::connect(address).expect("connect loopback server");
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nOrigin: http://127.0.0.1\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .expect("write mismatched-agent request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    assert!(
        response
            .ends_with("\r\n\r\nforbidden: token agent does not match X-Symaira-Agent header\n")
    );
}

struct FixtureRuntime;

impl ToolCallRuntime for FixtureRuntime {
    fn authorize(&self, _name: &str, _arguments: &Value) -> Result<(), ToolCallResult> {
        Ok(())
    }

    fn call(&self, name: &str, _arguments: &Value) -> Result<ToolCallResult, String> {
        match name {
            "health" => Ok(ToolCallResult::text(
                r#"{"server":"Symaira Vault MCP","status":"healthy","transport":"","version":"1.0.0"}"#,
            )),
            _ => Err(format!("unexpected fixture tool {name}")),
        }
    }
}

fn serve_one(stream: TcpStream, handler: &mut ProtocolHandler, allowed_tools: &[String]) {
    handler.set_token_scope(allowed_tools);
    let mut reader = BufReader::new(stream.try_clone().expect("clone request stream"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read request line");
    let mut first = line.split_whitespace();
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("read request header");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("request content length");
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("read request body");
    let body = String::from_utf8(body).expect("UTF-8 JSON request");
    let response = handle_request(
        HttpRequest {
            method: &method,
            path: &path,
            content_type: header(&headers, "content-type"),
            accept: header(&headers, "accept"),
            protocol_version: header(&headers, "mcp-protocol-version"),
            body: &body,
        },
        handler,
    )
    .expect("handle HTTP request");
    write_response(stream, response);
}

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> &'a str {
    headers.get(name).map(String::as_str).unwrap_or_default()
}

fn write_response(mut stream: TcpStream, response: HttpResponse) {
    let reason = match response.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {} {reason}\r\n", response.status).expect("write status");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    )
    .expect("write framing headers");
    stream
        .write_all(&response.body)
        .expect("write response body");
}

fn read_response(stream: TcpStream) -> (u16, HashMap<String, String>, String) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response status");
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP status code");
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("read response header");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .expect("read HTTP response body");
    (status, headers, body)
}
