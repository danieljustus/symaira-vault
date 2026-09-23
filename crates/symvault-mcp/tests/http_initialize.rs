use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use symvault_mcp::ProtocolHandler;
use symvault_mcp::http::{HttpRequest, handle_request};

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    request: Request,
    response: ExpectedResponse,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_digest: String,
}

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    content_type: String,
    accept: String,
    protocol_version: String,
    body: String,
}

#[derive(Deserialize)]
struct ExpectedResponse {
    status: u16,
    headers: std::collections::BTreeMap<String, String>,
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
fn initialize_http_matches_pinned_go_loopback() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.commit, "08c162e5");
    assert_eq!(
        fixture.oracle.commit_sha,
        "08c162e5090b6450889e2840b4caaf1b4c963cef"
    );
    assert_eq!(
        fixture.oracle.source_digest,
        "7b93a350a514e992c3538a2a24524a17b7f525b643bf1f6ddf2251bb3b55617e"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("loopback address");
    let server_fixture = fixture.request;
    let server_name = fixture.server_name;
    let server_version = fixture.server_version;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept loopback request");
        let mut reader = BufReader::new(stream.try_clone().expect("clone request stream"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read request line");
        let mut first = line.split_whitespace();
        let method = first.next().unwrap_or_default().to_string();
        let path = first.next().unwrap_or_default().to_string();
        let mut headers = std::collections::HashMap::new();
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

        let mut handler = ProtocolHandler::new(server_name, server_version);
        let response = handle_request(
            HttpRequest {
                method: &method,
                path: &path,
                content_type: headers
                    .get("content-type")
                    .map(String::as_str)
                    .unwrap_or_default(),
                accept: headers
                    .get("accept")
                    .map(String::as_str)
                    .unwrap_or_default(),
                protocol_version: headers
                    .get("mcp-protocol-version")
                    .map(String::as_str)
                    .unwrap_or_default(),
                body: &body,
            },
            &mut handler,
        )
        .expect("handle HTTP request");

        let reason = if response.status == 200 {
            "OK"
        } else {
            "Accepted"
        };
        write!(stream, "HTTP/1.1 {} {}\r\n", response.status, reason).expect("write status");
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
    });

    let mut stream = TcpStream::connect(addr).expect("connect to Rust loopback adapter");
    write!(
        stream,
        "{} {} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        server_fixture.method,
        server_fixture.path,
        server_fixture.content_type,
        server_fixture.accept,
        server_fixture.protocol_version,
        server_fixture.body.len(),
        server_fixture.body,
    )
    .expect("send initialize HTTP request");
    let mut wire = Vec::new();
    stream.read_to_end(&mut wire).expect("read HTTP response");
    server.join().expect("Rust loopback adapter thread");

    let mut reader = BufReader::new(wire.as_slice());
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response status");
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP status code");
    let mut headers = std::collections::HashMap::new();
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

    assert_eq!(status, fixture.response.status);
    for (name, value) in fixture.response.headers {
        assert_eq!(headers.get(&name.to_ascii_lowercase()), Some(&value));
    }
    for name in fixture.response.absent_headers {
        assert!(!headers.contains_key(&name.to_ascii_lowercase()));
    }
    assert_eq!(body, fixture.response.body);
}
