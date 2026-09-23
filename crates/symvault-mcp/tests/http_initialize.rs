use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use symvault_mcp::ProtocolHandler;
use symvault_mcp::http::{HttpRequest, HttpResponse, handle_request};

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
    content_type: String,
    accept: String,
    protocol_version: String,
    agent: String,
    body: String,
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
    let count = fixture.cases.len();
    let server_name = fixture.server_name.clone();
    let server_version = fixture.server_version.clone();
    let server = thread::spawn(move || {
        let mut handler = ProtocolHandler::new(server_name, server_version);
        for _ in 0..count {
            let (stream, _) = listener.accept().expect("accept loopback request");
            serve_one(stream, &mut handler);
        }
    });

    for case in &fixture.cases {
        assert!(
            case.go_authenticated,
            "{} oracle request was not authenticated",
            case.name
        );
        let mut stream = TcpStream::connect(addr).expect("connect to Rust loopback adapter");
        write!(
            stream,
            "{} {} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nX-Symaira-Agent: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            case.request.method,
            case.request.path,
            case.request.content_type,
            case.request.accept,
            case.request.protocol_version,
            case.request.agent,
            case.request.body.len(),
            case.request.body,
        )
        .expect("send initialize HTTP request");
        let (status, headers, body) = read_response(stream);
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

fn serve_one(stream: TcpStream, handler: &mut ProtocolHandler) {
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
