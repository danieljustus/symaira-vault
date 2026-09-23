//! Minimal Streamable HTTP request adapter for the existing MCP protocol handler.
//! The socket listener stays with the caller; this module owns `/mcp` request
//! checks and response framing for bounded HTTP/1.x connections.

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
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
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
const MAX_HTTP_REQUEST_LINE: usize = 8 * 1024;
// ponytail: eight workers bound thread/socket use; revisit if real concurrent demand exceeds this.
const MAX_HTTP_CONNECTIONS: usize = 8;

#[derive(Clone, Copy)]
struct HttpTimeouts {
    initial_read: Duration,
    request_read: Duration,
    keep_alive_idle: Duration,
    write: Duration,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            // Keep the existing 10-second bounded request-read behavior;
            // only an idle keep-alive wait adopts Go's longer idle timeout.
            initial_read: Duration::from_secs(10),
            request_read: Duration::from_secs(10),
            keep_alive_idle: Duration::from_secs(120),
            write: Duration::from_secs(10),
        }
    }
}

#[derive(Deserialize)]
struct TokenRegistry {
    #[serde(default)]
    tokens: BTreeMap<String, symvault_store::token_registry::TokenRecord>,
}

/// Serves authenticated HTTP requests on a loopback-only listener. The caller
/// supplies a runtime factory so each authenticated agent gets its own handler.
/// Encrypted Go registries are rejected until the caller can supply their age
/// identity; a missing or unreadable token registry never opens the endpoint.
pub fn serve_loopback<F>(
    listener: TcpListener,
    registry_path: impl AsRef<Path>,
    handler_for_agent: F,
) -> Result<(), std::io::Error>
where
    F: FnMut(&str) -> Result<ProtocolHandler, String> + Send,
{
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "MCP HTTP listener must bind to loopback",
        ));
    }
    load_token_registry(registry_path.as_ref())?;
    let registry_path = registry_path.as_ref().to_path_buf();
    let state = Arc::new(Mutex::new(HttpServerState {
        handler_for_agent,
        handlers: HashMap::new(),
        sessions: HashMap::new(),
    }));
    let active = Arc::new(AtomicUsize::new(0));
    thread::scope(|scope| {
        for incoming in listener.incoming() {
            let mut stream = incoming?;
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_HTTP_CONNECTIONS).then_some(count + 1)
                })
                .is_err()
            {
                write_plain_error(&mut stream, 503, "server busy")?;
                continue;
            }
            let state = Arc::clone(&state);
            let active_for_thread = Arc::clone(&active);
            let registry_path = registry_path.clone();
            if let Err(error) = thread::Builder::new().spawn_scoped(scope, move || {
                let _active = ActiveHttpConnection(active_for_thread);
                let _ = serve_connection_shared(
                    stream,
                    &registry_path,
                    &state,
                    HttpTimeouts::default(),
                );
            }) {
                active.fetch_sub(1, Ordering::AcqRel);
                return Err(error);
            }
        }
        Ok(())
    })
}

struct HttpServerState<F> {
    handler_for_agent: F,
    handlers: HashMap<String, ProtocolHandler>,
    sessions: HashMap<String, ProtocolHandler>,
}

fn serve_connection_shared<F>(
    stream: TcpStream,
    registry_path: &Path,
    state: &Mutex<HttpServerState<F>>,
    timeouts: HttpTimeouts,
) -> Result<(), std::io::Error>
where
    F: FnMut(&str) -> Result<ProtocolHandler, String>,
{
    serve_connection_with_timeouts(stream, timeouts, |reader, request, keep_alive| {
        let mut state = state
            .lock()
            .map_err(|_| std::io::Error::other("MCP HTTP state poisoned"))?;
        let HttpServerState {
            handler_for_agent,
            handlers,
            sessions,
        } = &mut *state;
        serve_one_authenticated(
            reader,
            request,
            keep_alive,
            registry_path,
            handler_for_agent,
            handlers,
            sessions,
        )
    })
}

struct ActiveHttpConnection(Arc<AtomicUsize>);

impl Drop for ActiveHttpConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_connection_authenticated<F>(
    stream: TcpStream,
    registry_path: &Path,
    handler_for_agent: &mut F,
    handlers: &mut HashMap<String, ProtocolHandler>,
    sessions: &mut HashMap<String, ProtocolHandler>,
) -> Result<(), std::io::Error>
where
    F: FnMut(&str) -> Result<ProtocolHandler, String>,
{
    serve_connection_with_timeouts(
        stream,
        HttpTimeouts::default(),
        |reader, request, keep_alive| {
            serve_one_authenticated(
                reader,
                request,
                keep_alive,
                registry_path,
                handler_for_agent,
                handlers,
                sessions,
            )
        },
    )
}

fn serve_connection_with_timeouts<F>(
    mut stream: TcpStream,
    timeouts: HttpTimeouts,
    mut serve_request: F,
) -> Result<(), std::io::Error>
where
    F: FnMut(&mut BufReader<TcpStream>, WireRequest, bool) -> Result<bool, std::io::Error>,
{
    let peer = stream.peer_addr()?;
    let local = stream.local_addr()?;
    if !peer.ip().is_loopback() || !local.ip().is_loopback() {
        return write_plain_error(&mut stream, 403, "forbidden");
    }
    stream.set_write_timeout(Some(timeouts.write))?;
    let mut reader = BufReader::new(stream);
    let mut first_request = true;
    loop {
        let first_byte_timeout = if first_request {
            timeouts.initial_read
        } else {
            timeouts.keep_alive_idle
        };
        let request =
            match read_wire_request(&mut reader, first_byte_timeout, timeouts.request_read) {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    let (status, message) = if error.to_string().contains("too large") {
                        let message = if error.to_string().contains("request body") {
                            "request body too large"
                        } else {
                            "request too large"
                        };
                        (413, message)
                    } else {
                        (400, "bad request")
                    };
                    write_http_error(reader.get_mut(), status, message)?;
                    return Ok(());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
        first_request = false;
        let connection_tokens = request
            .connection
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        let closes = connection_tokens
            .iter()
            .any(|value| value.eq_ignore_ascii_case("close"));
        let requested_keep_alive = request.http_version == "HTTP/1.1"
            || connection_tokens
                .iter()
                .any(|value| value.eq_ignore_ascii_case("keep-alive"));
        let keep_alive = requested_keep_alive && !closes;
        if let Some(response) = well_known_response(&request, local) {
            write_http_response(
                reader.get_mut(),
                response,
                &request.http_version,
                keep_alive,
            )?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }
        if !serve_request(&mut reader, request, keep_alive)? {
            return Ok(());
        }
    }
}

fn serve_one_authenticated<F>(
    reader: &mut BufReader<TcpStream>,
    request: WireRequest,
    keep_alive: bool,
    registry_path: &Path,
    handler_for_agent: &mut F,
    handlers: &mut HashMap<String, ProtocolHandler>,
    sessions: &mut HashMap<String, ProtocolHandler>,
) -> Result<bool, std::io::Error>
where
    F: FnMut(&str) -> Result<ProtocolHandler, String>,
{
    let stream = reader.get_mut();
    let response_version = request.http_version.as_str();
    if !allowed_origin(&request.origin, &request.host) {
        write_json_error_for_request(
            stream,
            403,
            "invalid Origin header",
            response_version,
            keep_alive,
        )?;
        return Ok(keep_alive);
    }
    let Some(bearer) = request.authorization.strip_prefix("Bearer ") else {
        write_request_error(stream, 401, "unauthorized", response_version, keep_alive)?;
        return Ok(keep_alive);
    };
    let token = match lookup_token(registry_path, bearer) {
        Ok(Some(token)) => token,
        Ok(None) | Err(_) => {
            write_request_error(stream, 401, "unauthorized", response_version, keep_alive)?;
            return Ok(keep_alive);
        }
    };
    if !token.agent_name.is_empty() && token.agent_name != request.agent {
        write_request_error(
            stream,
            403,
            "forbidden: token agent does not match X-Symaira-Agent header",
            response_version,
            keep_alive,
        )?;
        return Ok(keep_alive);
    }
    if request.agent.is_empty() {
        write_request_error(
            stream,
            403,
            "forbidden: missing X-Symaira-Agent header",
            response_version,
            keep_alive,
        )?;
        return Ok(keep_alive);
    }
    if !handlers.contains_key(&request.agent) {
        match handler_for_agent(&request.agent) {
            Ok(handler) if handlers.len() < MAX_HTTP_SESSIONS => {
                handlers.insert(request.agent.clone(), handler);
            }
            Ok(_) => {
                write_request_error(
                    stream,
                    503,
                    "too many MCP agent handlers",
                    response_version,
                    keep_alive,
                )?;
                return Ok(keep_alive);
            }
            Err(error) => {
                write_json_error_for_request(stream, 403, &error, response_version, keep_alive)?;
                return Ok(keep_alive);
            }
        }
    }
    let session_key = format!("{}:{}", token.id, request.agent);
    if !sessions.contains_key(&session_key) && sessions.len() >= MAX_HTTP_SESSIONS {
        write_request_error(
            stream,
            503,
            "too many MCP sessions",
            response_version,
            keep_alive,
        )?;
        return Ok(keep_alive);
    }
    let handler = sessions.entry(session_key).or_insert_with(|| {
        handlers
            .get(&request.agent)
            .expect("agent handler inserted")
            .new_session()
    });
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
    write_http_response(stream, response, response_version, keep_alive)?;
    Ok(keep_alive)
}

struct WireRequest {
    method: String,
    path: String,
    http_version: String,
    host: String,
    origin: String,
    authorization: String,
    agent: String,
    content_type: String,
    accept: String,
    protocol_version: String,
    connection: String,
    body: String,
}

fn read_wire_request(
    reader: &mut BufReader<TcpStream>,
    first_byte_timeout: Duration,
    request_read_timeout: Duration,
) -> Result<Option<WireRequest>, std::io::Error> {
    reader
        .get_mut()
        .set_read_timeout(Some(first_byte_timeout))?;
    let has_first_byte = !reader.fill_buf()?.is_empty();
    if has_first_byte {
        reader
            .get_mut()
            .set_read_timeout(Some(request_read_timeout))?;
    }
    let Some(first) = read_bounded_line(reader, MAX_HTTP_REQUEST_LINE)? else {
        return Ok(None);
    };
    let request_line = parse_crlf_line(&first)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
        || !method.bytes().all(is_http_token)
        || !path.starts_with('/')
        || path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(invalid_http("invalid HTTP request line"));
    }
    let method = method.to_owned();
    let path = path.to_owned();
    let mut headers = BTreeMap::new();
    let mut header_bytes = first.len();
    loop {
        let Some(line) = read_bounded_line(reader, MAX_HTTP_HEADERS)? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP headers",
            ));
        };
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HTTP_HEADERS {
            return Err(invalid_http("HTTP headers too large"));
        }
        if line == b"\r\n" {
            break;
        }
        let line = parse_crlf_line(&line)?;
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_http("malformed HTTP header"));
        };
        if name.is_empty() || !name.bytes().all(is_http_token) {
            return Err(invalid_http("invalid HTTP header name"));
        }
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(invalid_http("invalid HTTP header value"));
        }
        let name = name.to_ascii_lowercase();
        if headers
            .insert(name, value.trim_matches([' ', '\t']).to_owned())
            .is_some()
        {
            return Err(invalid_http("duplicate HTTP header"));
        }
    }
    if headers.get("host").is_none_or(String::is_empty) {
        return Err(invalid_http("missing Host header"));
    }
    if headers.contains_key("transfer-encoding") {
        return Err(invalid_http("transfer encoding is unsupported"));
    }
    let length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| invalid_http("invalid Content-Length"))?,
        None => 0,
    };
    if length > MAX_HTTP_BODY {
        return Err(invalid_http("request body too large"));
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
        http_version: version.to_owned(),
        host: get("host"),
        origin: get("origin"),
        authorization: get("authorization"),
        agent: get("x-symaira-agent"),
        content_type: get("content-type"),
        accept: get("accept"),
        protocol_version: get("mcp-protocol-version"),
        connection: get("connection"),
        body,
    }))
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete HTTP line",
                ))
            };
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(count) > max_bytes {
            return Err(invalid_http("HTTP line too large"));
        }
        let complete = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if complete {
            return Ok(Some(line));
        }
    }
}

fn parse_crlf_line(bytes: &[u8]) -> Result<&str, std::io::Error> {
    let Some(line) = bytes.strip_suffix(b"\r\n") else {
        return Err(invalid_http("HTTP lines must end in CRLF"));
    };
    std::str::from_utf8(line).map_err(|_| invalid_http("HTTP headers must be UTF-8"))
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn invalid_http(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
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
    version: &str,
    keep_alive: bool,
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
    write!(stream, "{version} {} {reason}\r\n", response.status)?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n", response.body.len())?;
    write_connection_header(stream, version, keep_alive)?;
    stream.write_all(b"\r\n")?;
    stream.write_all(&response.body)
}

fn write_connection_header(
    stream: &mut TcpStream,
    version: &str,
    keep_alive: bool,
) -> Result<(), std::io::Error> {
    match (version, keep_alive) {
        ("HTTP/1.0", true) => stream.write_all(b"Connection: keep-alive\r\n"),
        ("HTTP/1.1", false) => stream.write_all(b"Connection: close\r\n"),
        _ => Ok(()),
    }
}

fn well_known_response(request: &WireRequest, local: std::net::SocketAddr) -> Option<HttpResponse> {
    if request.method != "GET" || request.path != "/.well-known/oauth-protected-resource" {
        return None;
    }
    let resource = format!("http://{}:{}/mcp", local.ip(), local.port());
    let mut body = serde_json::to_vec(&serde_json::json!({
        "resource": resource,
        "bearer_methods_supported": ["header"],
        "resource_name": "Symaira Vault MCP Server",
    }))
    .ok()?;
    body.push(b'\n');
    Some(HttpResponse {
        status: 200,
        headers: vec![("Content-Type", "application/json")],
        body,
    })
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

fn write_request_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
    version: &str,
    keep_alive: bool,
) -> Result<(), std::io::Error> {
    let body = format!("{message}\n");
    let reason = match status {
        401 => "Unauthorized",
        403 => "Forbidden",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "{version} {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    write_connection_header(stream, version, keep_alive)?;
    write!(stream, "\r\n{body}")
}

fn write_json_error_for_request(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
    version: &str,
    keep_alive: bool,
) -> Result<(), std::io::Error> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32600,\"message\":{}}}}}\n",
        serde_json::to_string(message).unwrap_or_else(|_| "\"invalid request\"".into())
    );
    write!(
        stream,
        "{version} {status} Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    write_connection_header(stream, version, keep_alive)?;
    write!(stream, "\r\n{body}")
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
    parse_mime_media_type(value).is_some_and(|media_type| media_type == "application/json")
}

fn accepts_response(value: &str) -> bool {
    let mut json = false;
    let mut event_stream = false;
    for part in value.split(',') {
        match parse_mime_media_type(part).as_deref() {
            Some("*/*" | "application/*" | "application/json") => json = true,
            Some("text/event-stream") => event_stream = true,
            _ => {}
        }
    }
    json && event_stream
}

fn parse_mime_media_type(value: &str) -> Option<String> {
    let parts = split_mime_parts(value, ';')?;
    let media = parts.first()?.trim();
    let (top, sub) = media.split_once('/')?;
    if media.matches('/').count() != 1 || !is_mime_token(top) || !is_mime_token(sub) {
        return None;
    }
    let mut parameters = std::collections::HashSet::new();
    for parameter in parts.iter().skip(1) {
        let (name, value) = parameter.split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if !is_mime_token(name) || !parameters.insert(name.to_ascii_lowercase()) {
            return None;
        }
        if value.starts_with('"') {
            let bytes = value.as_bytes();
            if bytes.len() < 2 || bytes.last() != Some(&b'"') {
                return None;
            }
            let mut escaped = false;
            for byte in &bytes[1..bytes.len() - 1] {
                if escaped {
                    if *byte < 0x20 || *byte == 0x7f {
                        return None;
                    }
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' || *byte < 0x20 || *byte == 0x7f {
                    return None;
                }
            }
            if escaped {
                return None;
            }
        } else if !is_mime_token(value) {
            return None;
        }
    }
    Some(media.to_ascii_lowercase())
}

fn split_mime_parts(value: &str, separator: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == separator && !quoted {
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

fn is_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{io::BufRead, thread};

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

    fn round_trip_wire(request: &str) -> String {
        let dir = tempfile::tempdir().expect("temp dir");
        let registry_path = registry(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut handlers = HashMap::new();
            let mut sessions = HashMap::new();
            serve_connection_authenticated(
                stream,
                &registry_path,
                &mut |_| Ok(ProtocolHandler::new("symaira", "1.0.0")),
                &mut handlers,
                &mut sessions,
            )
            .expect("serve connection");
        });
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(request.as_bytes()).expect("write request");
        let response = read_http_response(&mut BufReader::new(
            stream.try_clone().expect("clone stream"),
        ));
        drop(stream);
        server.join().expect("server thread");
        response
    }

    #[test]
    fn protected_resource_discovery_matches_go_response_without_authentication() {
        let response = round_trip_wire(
            "GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("Content-Type: application/json\r\n"),
            "{response}"
        );
        let body: serde_json::Value = serde_json::from_str(raw_body(&response)).unwrap();
        let resource = body["resource"].as_str().expect("resource URL");
        assert!(resource.starts_with("http://127.0.0.1:"), "{resource}");
        assert!(resource.ends_with("/mcp"), "{resource}");
        assert_eq!(
            body["bearer_methods_supported"],
            serde_json::json!(["header"])
        );
        assert_eq!(body["resource_name"], "Symaira Vault MCP Server");
        assert!(body.get("authorization_servers").is_none());
    }

    fn round_trip_wire_sequence(request: &str, count: usize) -> Vec<String> {
        let dir = tempfile::tempdir().expect("temp dir");
        let registry_path = registry(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut handlers = HashMap::new();
            let mut sessions = HashMap::new();
            serve_connection_authenticated(
                stream,
                &registry_path,
                &mut |_| Ok(ProtocolHandler::new("symaira", "1.0.0")),
                &mut handlers,
                &mut sessions,
            )
            .expect("serve connection sequence");
        });
        let stream = TcpStream::connect(address).expect("connect");
        let mut reader = BufReader::new(stream);
        let mut responses = Vec::with_capacity(count);
        for _ in 0..count {
            reader
                .get_mut()
                .write_all(request.as_bytes())
                .expect("write request");
            responses.push(read_http_response(&mut reader));
        }
        drop(reader);
        server.join().expect("server thread");
        responses
    }

    #[test]
    fn keep_alive_idle_timeout_matches_go_source_and_closes_socket() {
        let go_http = include_str!("../../../internal/mcp/serverbootstrap/http.go");
        let compact_go = go_http
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(compact_go.contains("IdleTimeout:120*time.Second"));
        assert_eq!(
            HttpTimeouts::default().keep_alive_idle,
            Duration::from_secs(120)
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let registry_path = registry(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut handlers = HashMap::new();
            let mut sessions = HashMap::new();
            serve_connection_with_timeouts(
                stream,
                HttpTimeouts {
                    initial_read: Duration::from_secs(1),
                    request_read: Duration::from_secs(1),
                    keep_alive_idle: Duration::from_millis(100),
                    write: Duration::from_secs(1),
                },
                |reader, request, keep_alive| {
                    serve_one_authenticated(
                        reader,
                        request,
                        keep_alive,
                        &registry_path,
                        &mut |_| Ok(ProtocolHandler::new("symaira", "1.0.0")),
                        &mut handlers,
                        &mut sessions,
                    )
                },
            )
            .expect("serve connection with short test idle timeout");
        });

        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .write_all(b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
            .expect("write discovery request");
        let mut reader = BufReader::new(stream);
        let response = read_http_response(&mut reader);
        assert_eq!(raw_status(&response), 200);
        reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test read timeout");
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte).expect("read connection close"), 0);
        drop(reader);
        server.join().expect("server thread");
    }

    #[test]
    fn idle_connection_does_not_block_twenty_keep_alive_requests() {
        let source = include_str!("../../../internal/mcp/serverbootstrap/http.go");
        assert!(source.contains("IdleTimeout:       120 * time.Second"));
        assert!(source.contains("serveErr = server.Serve(listener)"));
        let state = Arc::new(Mutex::new(HttpServerState {
            handler_for_agent: |_| Ok(ProtocolHandler::new("symaira", "1.0.0")),
            handlers: HashMap::new(),
            sessions: HashMap::new(),
        }));
        let registry_dir = tempfile::tempdir().expect("temporary token registry");
        let registry_path = registry(registry_dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let timeouts = HttpTimeouts {
            initial_read: Duration::from_secs(2),
            request_read: Duration::from_secs(1),
            keep_alive_idle: Duration::from_secs(1),
            write: Duration::from_secs(1),
        };

        let idle_client = TcpStream::connect(address).expect("connect idle client");
        let (idle_server, _) = listener.accept().expect("accept idle client");
        let idle_registry = registry_path.clone();
        let idle_state = Arc::clone(&state);
        let idle = thread::spawn(move || {
            serve_connection_shared(idle_server, &idle_registry, &idle_state, timeouts)
                .expect("serve idle client")
        });

        let mut client = TcpStream::connect(address).expect("connect active client");
        client
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("set bounded client read");
        let (active_server, _) = listener.accept().expect("accept active client");
        let active_registry = registry_path;
        let active_state = Arc::clone(&state);
        let active = thread::spawn(move || {
            serve_connection_shared(active_server, &active_registry, &active_state, timeouts)
                .expect("serve active client")
        });

        for index in 0..20 {
            let connection = if index == 19 {
                "Connection: close\r\n"
            } else {
                ""
            };
            write!(
                client,
                "GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\n{connection}\r\n"
            )
            .expect("write sequential keep-alive request");
            let response = read_http_response(&mut BufReader::new(
                client.try_clone().expect("clone active client"),
            ));
            assert_eq!(raw_status(&response), 200, "request {index}");
        }
        drop(client);
        active.join().expect("active connection worker");
        drop(idle_client);
        idle.join().expect("idle connection worker");
    }

    fn read_http_response(reader: &mut BufReader<TcpStream>) -> String {
        let mut response = Vec::new();
        let mut line = Vec::new();
        reader
            .read_until(b'\n', &mut line)
            .expect("read response line");
        assert!(line.ends_with(b"\r\n"), "invalid response status line");
        response.extend_from_slice(&line);
        let mut content_length = None;
        loop {
            line.clear();
            reader
                .read_until(b'\n', &mut line)
                .expect("read response header");
            assert!(line.ends_with(b"\r\n"), "invalid response header line");
            if line == b"\r\n" {
                break;
            }
            if let Some((name, value)) = std::str::from_utf8(&line)
                .expect("response header UTF-8")
                .trim_end_matches("\r\n")
                .split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = Some(value.trim().parse::<usize>().expect("content length"));
            }
            response.extend_from_slice(&line);
        }
        response.extend_from_slice(b"\r\n");
        let mut body = vec![0; content_length.expect("response Content-Length")];
        reader.read_exact(&mut body).expect("read response body");
        response.extend_from_slice(&body);
        String::from_utf8(response).expect("HTTP response UTF-8")
    }

    fn round_trip(auth: bool, origin: &str) -> String {
        let address = "127.0.0.1";
        let auth = if auth {
            format!("Authorization: Bearer {BEARER}\r\n")
        } else {
            String::new()
        };
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\n{auth}X-Symaira-Agent: default\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        );
        round_trip_wire(&request)
    }

    fn go_http_case(name: &str) -> serde_json::Value {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/port/mcp/http-initialize.json"
        ))
        .expect("parse Go HTTP oracle fixture");
        fixture["cases"]
            .as_array()
            .expect("fixture cases")
            .iter()
            .find(|case| case["name"] == name)
            .unwrap_or_else(|| panic!("missing Go HTTP case {name}"))
            .clone()
    }

    #[test]
    fn source_bound_notification_returns_202_and_keeps_session_initialized() {
        let mut handler = ProtocolHandler::new("symaira", "1.0.0");
        for name in [
            "initialize",
            "authenticated_initialized_notification_accepted",
            "authenticated_prompts_list_after_initialized_notification",
        ] {
            let case = go_http_case(name);
            let request = &case["request"];
            let response = handle_request(
                HttpRequest {
                    method: request["method"].as_str().expect("fixture method"),
                    path: request["path"].as_str().expect("fixture path"),
                    content_type: request["content_type"]
                        .as_str()
                        .expect("fixture content type"),
                    accept: request["accept"].as_str().expect("fixture Accept"),
                    protocol_version: request["protocol_version"]
                        .as_str()
                        .expect("fixture protocol version"),
                    body: request["body"].as_str().expect("fixture body"),
                },
                &mut handler,
            )
            .expect("handle fixture request");
            assert_eq!(
                response.status,
                case["response"]["status"].as_u64().expect("fixture status") as u16,
                "{name} status"
            );
            assert_eq!(
                String::from_utf8(response.body).expect("UTF-8 response"),
                case["response"]["body"]
                    .as_str()
                    .expect("fixture response body"),
                "{name} body"
            );
        }
    }

    #[test]
    fn source_bound_authenticated_sse_get_matches_go_method_rejection() {
        let go = go_http_case("authenticated_sse_get_rejected_with_allow_post");
        assert_eq!(go["response"]["status"], 405);
        assert_eq!(go["response"]["headers"]["Allow"], "POST");
        let response = round_trip_wire(&format!(
            "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: default\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\nContent-Length: 0\r\n\r\n"
        ));
        assert_eq!(
            raw_status(&response),
            go["response"]["status"].as_u64().expect("Go status") as u16
        );
        assert!(response.contains("Allow: POST\r\n"), "{response}");
        assert!(
            response.contains("Content-Type: application/json\r\n"),
            "{response}"
        );
        assert_eq!(
            raw_body(&response),
            go["response"]["body"].as_str().expect("Go response body")
        );
    }

    #[test]
    fn source_bound_post_sse_negotiation_matches_go_json_or_406_paths() {
        let wire_request = |case: &serde_json::Value| {
            let request = &case["request"];
            let body = request["body"].as_str().expect("fixture request body");
            format!(
                "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {}\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: {}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                request["method"].as_str().expect("fixture method"),
                request["path"].as_str().expect("fixture path"),
                request["origin"].as_str().expect("fixture origin"),
                request["agent"].as_str().expect("fixture agent"),
                request["content_type"]
                    .as_str()
                    .expect("fixture content type"),
                request["accept"].as_str().expect("fixture Accept"),
                request["protocol_version"]
                    .as_str()
                    .expect("fixture protocol version"),
                body.len(),
                body,
            )
        };

        let initialized = go_http_case("initialize");
        assert_eq!(
            initialized["request"]["accept"],
            "text/event-stream, application/json"
        );
        assert_eq!(initialized["response"]["status"], 200);
        assert_eq!(
            initialized["response"]["headers"]["Content-Type"],
            "application/json"
        );
        let rust_initialized = round_trip_wire(&wire_request(&initialized));
        assert_eq!(raw_status(&rust_initialized), 200);
        assert!(rust_initialized.contains("Content-Type: application/json\r\n"));
        assert_eq!(
            raw_body(&rust_initialized),
            initialized["response"]["body"]
                .as_str()
                .expect("Go initialize body")
        );

        for name in [
            "authenticated_sse_only_prompts_list_rejected",
            "authenticated_sse_only_health_tool_rejected",
        ] {
            let go = go_http_case(name);
            assert_eq!(go["request"]["accept"], "text/event-stream");
            assert_eq!(go["response"]["status"], 406);
            assert_eq!(
                go["response"]["headers"]["Content-Type"],
                "application/json"
            );
            let rust = round_trip_wire(&wire_request(&go));
            assert_eq!(raw_status(&rust), 406, "{name} status");
            assert!(
                rust.contains("Content-Type: application/json\r\n"),
                "{rust}"
            );
            assert_eq!(
                raw_body(&rust),
                go["response"]["body"]
                    .as_str()
                    .expect("Go negotiation body"),
                "{name} body"
            );
            assert!(!rust.contains("Content-Type: text/event-stream\r\n"));
        }
    }

    #[test]
    fn source_bound_go_keep_alive_reuses_authenticated_session_on_rust_connection() {
        let go_initial = go_http_case("initialize");
        let go_continuation = go_http_case("authenticated_prompts_list_after_initialize");
        assert!(
            !go_initial["response"]["connection_reused"]
                .as_bool()
                .unwrap_or(false)
        );
        assert!(
            go_continuation["response"]["connection_reused"]
                .as_bool()
                .unwrap()
        );

        let wire_request = |case: &serde_json::Value| {
            let request = &case["request"];
            let body = request["body"].as_str().expect("fixture body");
            format!(
                "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {}\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: {}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nContent-Length: {}\r\n\r\n{}",
                request["method"].as_str().expect("fixture method"),
                request["path"].as_str().expect("fixture path"),
                request["origin"].as_str().expect("fixture origin"),
                request["agent"].as_str().expect("fixture agent"),
                request["content_type"]
                    .as_str()
                    .expect("fixture content type"),
                request["accept"].as_str().expect("fixture Accept"),
                request["protocol_version"]
                    .as_str()
                    .expect("fixture protocol version"),
                body.len(),
                body,
            )
        };

        let dir = tempfile::tempdir().expect("temp dir");
        let registry_path = registry(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut handlers = HashMap::new();
            let mut sessions = HashMap::new();
            serve_connection_authenticated(
                stream,
                &registry_path,
                &mut |_| Ok(ProtocolHandler::new("symaira", "1.0.0")),
                &mut handlers,
                &mut sessions,
            )
            .expect("serve keep-alive connection");
        });
        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .write_all(wire_request(&go_initial).as_bytes())
            .expect("send initialize");
        let mut reader = BufReader::new(stream);
        let rust_initial = read_http_response(&mut reader);
        assert_eq!(raw_status(&rust_initial), 200);
        assert!(!rust_initial.contains("Connection: close\r\n"));
        assert_eq!(
            raw_body(&rust_initial),
            go_initial["response"]["body"]
                .as_str()
                .expect("Go initialize body")
        );

        reader
            .get_mut()
            .write_all(wire_request(&go_continuation).as_bytes())
            .expect("send session continuation");
        let rust_continuation = read_http_response(&mut reader);
        assert_eq!(raw_status(&rust_continuation), 200);
        assert!(!rust_continuation.contains("Connection: close\r\n"));
        assert_eq!(
            raw_body(&rust_continuation),
            go_continuation["response"]["body"]
                .as_str()
                .expect("Go continuation body")
        );
        drop(reader);
        server.join().expect("server thread");
    }

    fn raw_status(response: &str) -> u16 {
        response
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .expect("HTTP response status")
    }

    fn raw_body(response: &str) -> &str {
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("HTTP response body")
    }

    #[test]
    fn source_bound_duplicate_authorization_is_rejected_before_authentication() {
        let go = go_http_case("duplicate_authorization_first_value_reaches_handler");
        assert_eq!(go["response"]["status"], 200);
        // Go's Header.Get uses the first duplicate value. Rust rejects duplicate
        // headers before auth so request-smuggling ambiguities fail closed.
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {BEARER}\r\nAuthorization: Bearer invalid-second-value\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        );
        let response = round_trip_wire(&request);
        assert_eq!(raw_status(&response), 400);
        assert_eq!(raw_body(&response), "bad request\n");
    }

    #[test]
    fn source_bound_duplicate_content_length_matches_go_rejection_status() {
        let go = go_http_case("duplicate_content_length_rejected_by_go_parser");
        assert_eq!(go["response"]["status"], 400);
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len(),
            BODY.len() + 1
        );
        let response = round_trip_wire(&request);
        assert_eq!(raw_status(&response), 400);
        // Go's net/http parser owns its generated error page; the Rust listener
        // deliberately keeps a small stable parser-error body.
        assert_eq!(raw_body(&response), "bad request\n");
    }

    #[test]
    fn source_bound_http_10_initialize_matches_go_and_closes_connection() {
        let go = go_http_case("http_10_initialize_accepted");
        assert!(
            !go["response"]["connection_reused"]
                .as_bool()
                .unwrap_or(false)
        );
        let request = &go["request"];
        let body = request["body"].as_str().expect("Go request body");
        let request = format!(
            "{} {} HTTP/1.0\r\nHost: 127.0.0.1\r\nOrigin: {}\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: {}\r\nContent-Type: {}\r\nAccept: {}\r\nMCP-Protocol-Version: {}\r\nContent-Length: {}\r\n\r\n{}",
            request["method"].as_str().expect("Go method"),
            request["path"].as_str().expect("Go path"),
            request["origin"].as_str().expect("Go origin"),
            request["agent"].as_str().expect("Go agent"),
            request["content_type"].as_str().expect("Go content type"),
            request["accept"].as_str().expect("Go Accept"),
            request["protocol_version"]
                .as_str()
                .expect("Go protocol version"),
            body.len(),
            body,
        );
        let response = round_trip_wire(&request);
        assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
        assert!(!response.contains("Connection:"), "{response}");
        assert_eq!(
            raw_status(&response),
            go["response"]["status"].as_u64().expect("Go status") as u16
        );
        assert_eq!(
            raw_body(&response),
            go["response"]["body"].as_str().expect("Go response body")
        );
        assert!(
            response.contains(&format!(
                "Content-Length: {}\r\n",
                go["response"]["headers"]["Content-Length"]
                    .as_str()
                    .expect("Go Content-Length")
            )),
            "{response}"
        );
        assert!(response.contains("Content-Type: application/json\r\n"));
    }

    #[test]
    fn source_bound_http_10_error_framing_and_explicit_keep_alive_match_go() {
        let default_close = "POST /mcp HTTP/1.0\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nX-Symaira-Agent: default\r\nContent-Length: 0\r\n\r\n";
        let response = round_trip_wire(default_close);
        assert!(
            response.starts_with("HTTP/1.0 401 Unauthorized\r\n"),
            "{response}"
        );
        assert!(response.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(response.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(!response.contains("Connection:"), "{response}");
        assert_eq!(raw_body(&response), "unauthorized\n");

        let keep_alive = "POST /mcp HTTP/1.0\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nX-Symaira-Agent: default\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
        let responses = round_trip_wire_sequence(keep_alive, 2);
        assert_eq!(responses.len(), 2);
        for response in responses {
            assert!(
                response.starts_with("HTTP/1.0 401 Unauthorized\r\n"),
                "{response}"
            );
            assert!(
                response.contains("Connection: keep-alive\r\n"),
                "{response}"
            );
            assert!(response.contains("Content-Length: 13\r\n"));
            assert_eq!(raw_body(&response), "unauthorized\n");
        }
    }

    #[test]
    fn source_bound_request_line_limit_is_stricter_than_go_server_limit() {
        let go = go_http_case("oversized_request_line_reaches_handler");
        assert_eq!(go["response"]["status"], 200);
        let line = format!("POST /mcp?x={} HTTP/1.1\r\n", "x".repeat(16 * 1024));
        let error = read_bounded_line(&mut std::io::Cursor::new(line), MAX_HTTP_REQUEST_LINE)
            .expect_err("Rust rejects the Go request line before allocation");
        assert_eq!(error.to_string(), "HTTP line too large");
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

    #[test]
    fn raw_loopback_origin_rejections_match_source_bound_go_cases() {
        for (case_name, origin) in [
            ("foreign_origin_rejected", "https://attacker.example"),
            ("malformed_origin_rejected", "http://%"),
        ] {
            let case = go_http_case(case_name);
            let response = round_trip_wire(&format!(
                "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {origin}\r\nContent-Length: 0\r\n\r\n"
            ));
            assert_eq!(
                raw_status(&response),
                case["response"]["status"].as_u64().unwrap() as u16
            );
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(raw_body(&response)).unwrap(),
                serde_json::from_str::<serde_json::Value>(
                    case["response"]["body"].as_str().unwrap()
                )
                .unwrap(),
                "{case_name} body"
            );
        }
    }

    #[test]
    fn raw_loopback_rejects_spoofed_host_even_when_go_same_host_origin_reaches_auth() {
        let case = go_http_case("matching_host_and_origin_reaches_authentication");
        assert_eq!(case["response"]["status"], 401);
        let response = round_trip_wire(
            "POST /mcp HTTP/1.1\r\nHost: attacker.example\r\nOrigin: https://attacker.example\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            raw_status(&response),
            403,
            "Rust should reject non-loopback host"
        );
        assert!(raw_body(&response).contains("invalid Origin header"));
    }

    #[test]
    fn raw_loopback_caps_headers_at_the_documented_rust_limit() {
        let case = go_http_case("oversized_header_reaches_mcp_handler");
        assert_eq!(case["response"]["status"], 200);
        assert_eq!(case["request"]["header_repeat"], 17 * 1024);
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nAuthorization: Bearer {BEARER}\r\nX-Symaira-Agent: default\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nX-Rust-Port-Fixture: {}\r\nContent-Length: 0\r\n\r\n",
            "x".repeat(17 * 1024)
        );
        let response = round_trip_wire(&request);
        assert_eq!(raw_status(&response), 413);
        assert_eq!(raw_body(&response), "request too large\n");
    }

    #[test]
    fn loopback_parser_rejects_duplicate_authorization_with_http_error() {
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {BEARER}\r\nAuthorization: Bearer {BEARER}\r\n\r\n"
        );
        let response = round_trip_wire(&request);
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(
            response.contains("X-Content-Type-Options: nosniff\r\n"),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\nbad request\n"), "{response}");
    }

    #[test]
    fn loopback_parser_rejects_duplicate_content_length_with_http_error() {
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len(),
            BODY.len()
        );
        let response = round_trip_wire(&request);
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\nbad request\n"), "{response}");
    }

    #[test]
    fn loopback_parser_rejects_unsupported_version_before_authentication() {
        let response = round_trip_wire("POST /mcp HTTP/2.0\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\nbad request\n"), "{response}");
    }

    #[test]
    fn loopback_parser_bounds_request_line_before_allocation() {
        let request = format!("POST /{} HTTP/1.1\r\n", "x".repeat(MAX_HTTP_REQUEST_LINE));
        let response = round_trip_wire(&request);
        assert!(
            response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "{response}"
        );
        assert!(
            response.ends_with("\r\n\r\nrequest too large\n"),
            "{response}"
        );
    }
}
