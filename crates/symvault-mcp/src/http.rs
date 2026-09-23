//! Minimal Streamable HTTP request adapter for the existing MCP protocol handler.
//! The socket listener stays with the caller; this module owns `/mcp` request
//! checks and response framing for one request.

use crate::{
    Error, Message, ProtocolHandler, error_code, handle_line, is_supported_protocol_version,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    path::Path,
    time::Duration,
};

pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub accept: &'a str,
    pub protocol_version: &'a str,
    pub body: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
}

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const MAX_HTTP_BODY: usize = 1_048_576;
const MAX_HTTP_SESSIONS: usize = 256;

#[derive(Deserialize)]
struct TokenRegistry {
    #[serde(default)]
    tokens: BTreeMap<String, symvault_store::token_registry::TokenRecord>,
}

/// Serves authenticated HTTP requests on a loopback-only listener. The caller
/// owns the protocol handler and must supply an already configured runtime.
/// Encrypted Go registries are rejected until the caller can supply their age
/// identity; a missing or unreadable token registry never opens the endpoint.
pub fn serve_loopback(
    listener: TcpListener,
    registry_path: impl AsRef<Path>,
    handler: &mut ProtocolHandler,
) -> Result<(), std::io::Error> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "MCP HTTP listener must bind to loopback",
        ));
    }
    load_token_registry(registry_path.as_ref())?;
    let mut sessions = HashMap::new();
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let result =
            serve_one_authenticated(&mut stream, registry_path.as_ref(), handler, &mut sessions);
        if let Err(error) = result
            && error.kind() == std::io::ErrorKind::InvalidData
        {
            let (status, message) = if error.to_string().contains("too large") {
                (413, "request body too large")
            } else {
                (400, "bad request")
            };
            write_http_error(&mut stream, status, message)?;
        }
    }
    Ok(())
}

fn serve_one_authenticated(
    stream: &mut TcpStream,
    registry_path: &Path,
    handler_template: &ProtocolHandler,
    sessions: &mut HashMap<String, ProtocolHandler>,
) -> Result<(), std::io::Error> {
    let peer = stream.peer_addr()?;
    let local = stream.local_addr()?;
    if !peer.ip().is_loopback() || !local.ip().is_loopback() {
        return write_plain_error(stream, 403, "forbidden");
    }
    let request = read_wire_request(stream)?;
    let Some(request) = request else {
        return Ok(());
    };
    if !allowed_origin(&request.origin, &request.host) {
        return write_json_error(stream, 403, "invalid Origin header");
    }
    let Some(bearer) = request.authorization.strip_prefix("Bearer ") else {
        return write_plain_error(stream, 401, "unauthorized");
    };
    let token = match lookup_token(registry_path, bearer) {
        Ok(Some(token)) => token,
        Ok(None) | Err(_) => return write_plain_error(stream, 401, "unauthorized"),
    };
    if !token.agent_name.is_empty() && token.agent_name != request.agent {
        return write_plain_error(
            stream,
            403,
            "forbidden: token agent does not match X-Symaira-Agent header",
        );
    }
    if request.agent.is_empty() {
        return write_plain_error(stream, 403, "forbidden: missing X-Symaira-Agent header");
    }
    let session_key = format!("{}:{}", token.id, request.agent);
    if !sessions.contains_key(&session_key) && sessions.len() >= MAX_HTTP_SESSIONS {
        return write_http_error(stream, 503, "too many MCP sessions");
    }
    let handler = sessions
        .entry(session_key)
        .or_insert_with(|| handler_template.new_session());
    handler.set_token_scope(token.allowed_tools.as_deref().unwrap_or_default());
    let response = handle_request(
        HttpRequest {
            method: &request.method,
            path: &request.path,
            content_type: &request.content_type,
            accept: &request.accept,
            protocol_version: &request.protocol_version,
            body: &request.body,
        },
        handler,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    write_http_response(stream, response)
}

struct WireRequest {
    method: String,
    path: String,
    host: String,
    origin: String,
    authorization: String,
    agent: String,
    content_type: String,
    accept: String,
    protocol_version: String,
    body: String,
}

fn read_wire_request(stream: &mut TcpStream) -> Result<Option<WireRequest>, std::io::Error> {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    let mut header_bytes = first.len();
    loop {
        let mut line = String::new();
        let count = reader.read_line(&mut line)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP headers",
            ));
        }
        header_bytes += count;
        if header_bytes > MAX_HTTP_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if headers.contains_key("transfer-encoding") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer encoding is unsupported",
        ));
    }
    if length > MAX_HTTP_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8(body).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "request body is not UTF-8")
    })?;
    let get = |name: &str| headers.get(name).cloned().unwrap_or_default();
    Ok(Some(WireRequest {
        method,
        path,
        host: get("host"),
        origin: get("origin"),
        authorization: get("authorization"),
        agent: get("x-symaira-agent"),
        content_type: get("content-type"),
        accept: get("accept"),
        protocol_version: get("mcp-protocol-version"),
        body,
    }))
}

fn lookup_token(
    registry_path: &Path,
    bearer: &str,
) -> Result<Option<symvault_store::token_registry::TokenRecord>, std::io::Error> {
    let registry = load_token_registry(registry_path)?;
    let now = time::OffsetDateTime::now_utc();
    let Some(token) =
        symvault_store::token_registry::lookup_raw_bearer(&registry.tokens, bearer, now)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
    else {
        return Ok(None);
    };
    Ok(Some(token.clone()))
}

fn load_token_registry(registry_path: &Path) -> Result<TokenRegistry, std::io::Error> {
    let encrypted = registry_path.with_file_name("registry.age");
    if encrypted.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "encrypted token registry is unsupported",
        ));
    }
    let metadata = fs::symlink_metadata(registry_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "token registry must be a regular file",
        ));
    }
    let bytes = fs::read(registry_path)?;
    if bytes.len() > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "token registry too large",
        ));
    }
    let registry: TokenRegistry = serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(registry)
}

fn allowed_origin(origin: &str, request_host: &str) -> bool {
    let Some((scheme, authority)) = origin.trim().split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
    {
        return false;
    }
    let origin_host = host_without_port(authority);
    let request_host = host_without_port(request_host);
    loopback_host(origin_host) && loopback_host(request_host)
}

fn host_without_port(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host).unwrap_or("");
    }
    authority
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(authority, |(host, _)| host)
}

fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn write_http_response(
    stream: &mut TcpStream,
    response: HttpResponse,
) -> Result<(), std::io::Error> {
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
    write!(stream, "HTTP/1.1 {} {reason}\r\n", response.status)?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    )?;
    stream.write_all(&response.body)
}

fn write_plain_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), std::io::Error> {
    write_http_error(stream, status, message)
}

fn write_http_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), std::io::Error> {
    let body = format!("{message}\n");
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn write_json_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), std::io::Error> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32600,\"message\":{}}}}}\n",
        serde_json::to_string(message).unwrap_or_else(|_| "\"invalid request\"".into())
    );
    write!(
        stream,
        "HTTP/1.1 {status} Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Handles the initialize-sized `/mcp` HTTP slice using the shared JSON-RPC
/// handler. The caller owns TCP, authentication, and connection lifecycle.
pub fn handle_request(
    request: HttpRequest<'_>,
    handler: &mut ProtocolHandler,
) -> Result<HttpResponse, Error> {
    if request.method != "POST" {
        return error(405, None, error_code::INVALID_REQUEST, "method not allowed");
    }
    if request.path != "/mcp" {
        return Ok(HttpResponse {
            status: 404,
            headers: vec![
                ("Content-Type", "text/plain; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            body: b"404 page not found\n".to_vec(),
        });
    }
    if !is_json_content_type(request.content_type) {
        return error(
            415,
            None,
            error_code::INVALID_REQUEST,
            "Content-Type must be application/json",
        );
    }
    if !accepts_response(request.accept) {
        return error(
            406,
            None,
            error_code::INVALID_REQUEST,
            "Accept must include application/json and text/event-stream",
        );
    }
    if request.body.len() > 1_048_576 {
        return error(413, None, error_code::PARSE_ERROR, "request body too large");
    }

    let version = request.protocol_version.trim();
    if !version.is_empty() && !is_supported_protocol_version(version) {
        let id = serde_json::from_str::<Message>(request.body)
            .ok()
            .and_then(|message| message.id);
        return error(
            400,
            id,
            error_code::INVALID_REQUEST,
            "unsupported MCP-Protocol-Version",
        );
    }

    match handle_line(request.body, handler)? {
        Some(mut body) => {
            body.push('\n');
            Ok(HttpResponse {
                status: 200,
                headers: vec![("Content-Type", "application/json")],
                body: body.into_bytes(),
            })
        }
        None => Ok(HttpResponse {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        }),
    }
}

fn error(
    status: u16,
    id: Option<Box<serde_json::value::RawValue>>,
    code: i32,
    message: &str,
) -> Result<HttpResponse, Error> {
    let mut body = crate::encode(&Message::error_response(id, code, message, None))?;
    body.push('\n');
    let mut headers = vec![("Content-Type", "application/json")];
    if status == 405 {
        headers.push(("Allow", "POST"));
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.into_bytes(),
    })
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn accepts_response(value: &str) -> bool {
    let mut json = false;
    let mut event_stream = false;
    for part in value.split(',') {
        let media_type = part.split(';').next().unwrap_or_default().trim();
        match media_type.to_ascii_lowercase().as_str() {
            "*/*" | "application/*" | "application/json" => json = true,
            "text/event-stream" => event_stream = true,
            _ => {}
        }
    }
    json && event_stream
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{io::Read, thread};

    const BEARER: &str = "http001-rust-loopback-token";
    const BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"http-test","version":"1"}}}"#;

    fn registry(dir: &Path) -> std::path::PathBuf {
        let hash = symvault_store::sha256_hex(BEARER.as_bytes());
        let bytes = format!(
            r#"{{"version":2,"tokens":{{"tok-test":{{"id":"tok-test","hash":"{hash}","prefix":"http","allowed_tools":["*"],"agent_name":"default","created_at":"2026-01-01T00:00:00Z"}}}}}}"#
        );
        let path = dir.join("mcp-tokens.json");
        fs::write(&path, bytes).expect("write token registry");
        path
    }

    fn round_trip(auth: bool, origin: &str) -> String {
        let dir = tempfile::tempdir().expect("temp dir");
        let registry_path = registry(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let handler = ProtocolHandler::new("symaira", "1.0.0");
            serve_one_authenticated(&mut stream, &registry_path, &handler, &mut HashMap::new())
                .expect("serve request");
        });
        let mut stream = TcpStream::connect(address).expect("connect");
        let auth = if auth {
            format!("Authorization: Bearer {BEARER}\r\n")
        } else {
            String::new()
        };
        write!(
            stream,
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\n{auth}X-Symaira-Agent: default\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        )
        .expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        server.join().expect("server thread");
        response
    }

    #[test]
    fn authenticated_loopback_listener_dispatches_initialize() {
        let response = round_trip(true, "http://127.0.0.1");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("\"protocolVersion\":\"2025-11-25\""));
    }

    #[test]
    fn loopback_listener_rejects_missing_bearer() {
        let response = round_trip(false, "http://127.0.0.1");
        #[derive(Deserialize)]
        struct Fixture {
            cases: Vec<FixtureCase>,
        }
        #[derive(Deserialize)]
        struct FixtureCase {
            name: String,
            response: FixtureResponse,
        }
        #[derive(Deserialize)]
        struct FixtureResponse {
            status: u16,
            headers: BTreeMap<String, String>,
            body: String,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../testdata/port/mcp/http-initialize.json"
        ))
        .expect("parse Go HTTP fixture");
        let expected = fixture
            .cases
            .into_iter()
            .find(|case| case.name == "missing_bearer_rejected")
            .expect("Go missing bearer case")
            .response;
        let mut lines = response.split("\r\n");
        assert_eq!(
            lines.next().unwrap_or_default(),
            format!("HTTP/1.1 {} Unauthorized", expected.status)
        );
        let headers = lines
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect::<BTreeMap<_, _>>();
        for (name, value) in expected.headers {
            assert_eq!(
                headers.get(&name.to_ascii_lowercase()),
                Some(&value),
                "Go header {name}"
            );
        }
        assert!(response.ends_with(&format!("\r\n\r\n{}", expected.body)));
    }

    #[test]
    fn loopback_listener_rejects_foreign_origin_before_authentication() {
        let response = round_trip(false, "https://attacker.example");
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{response}"
        );
        assert!(response.contains("invalid Origin header"), "{response}");
    }
}
