//! Source-bound HTTP subset of Go's API-template and egress broker contract.
//! Oracle sources: proxy/auth at `ba4dc0680878870bfb30ccd39a0b973b960d3e09`,
//! and `internal/ssrf/ssrf.go` at `c7c6d04b6dc6349800d12d87d605ae55081bf694`.
//!
//! Plain HTTP is allowed only to loopback targets. The full Go broker's TLS MITM,
//! template catalog loading, vault lookup, substitutions, audit, and response
//! pattern sanitizer remain separate migration work.
//! The CLI currently exposes only an explicitly allowlisted CONNECT tunnel for
//! certificate-pinning hosts; it does not intercept TLS or attach credentials.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_HEADER_LIMIT: usize = 64 * 1024;

/// Serve the explicitly allowlisted CONNECT passthrough subset of the CLI broker.
/// Targets are resolved once, checked, and dialed by pinned IP address.
pub fn serve_connect_passthrough(
    listener: TcpListener,
    passthrough: Vec<String>,
    strict: bool,
    stopping: &AtomicBool,
    allow_private: bool,
) -> Result<(), String> {
    if passthrough.iter().all(|host| host.trim().is_empty()) {
        return Err("--passthrough requires at least one host".into());
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configure broker listener: {error}"))?;
    while !stopping.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                let passthrough = passthrough.clone();
                // ponytail: one thread per tunnel, bounded workers if local connection volume grows.
                thread::spawn(move || {
                    let _ = handle_connect_client(client, &passthrough, strict, allow_private);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("accept broker connection: {error}")),
        }
    }
    Ok(())
}

fn handle_connect_client(
    mut client: TcpStream,
    passthrough: &[String],
    strict: bool,
    allow_private: bool,
) -> Result<(), String> {
    let request = read_connect_headers(&mut client)?;
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some() || version != "HTTP/1.1" {
        write_proxy_error(&mut client, 400, "invalid proxy request")?;
        return Ok(());
    }
    if method != "CONNECT" {
        if strict {
            write_proxy_error(
                &mut client,
                403,
                "host is outside the passthrough allowlist",
            )?;
        } else {
            write_proxy_error(
                &mut client,
                501,
                "HTTP forwarding is not supported by the Rust broker",
            )?;
        }
        return Ok(());
    }
    if authority.is_empty() {
        write_proxy_error(&mut client, 400, "missing CONNECT target")?;
        return Ok(());
    }
    let Some((host, addresses)) = resolve_connect_target(authority, allow_private) else {
        write_proxy_error(&mut client, 403, "CONNECT target is blocked")?;
        return Ok(());
    };
    if !passthrough.iter().any(|entry| host_matches(entry, &host)) {
        let (status, body) = if strict {
            (403, "host is outside the passthrough allowlist")
        } else {
            (501, "TLS interception is not supported by the Rust broker")
        };
        write_proxy_error(&mut client, status, body)?;
        return Ok(());
    }
    let mut upstream = addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok());
    let Some(mut upstream) = upstream.take() else {
        write_proxy_error(&mut client, 502, "cannot connect to passthrough host")?;
        return Ok(());
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|error| format!("write CONNECT response: {error}"))?;
    let mut client_reader = client
        .try_clone()
        .map_err(|error| format!("clone broker client: {error}"))?;
    let mut upstream_writer = upstream
        .try_clone()
        .map_err(|error| format!("clone broker upstream: {error}"))?;
    let outbound = thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = outbound.join();
    Ok(())
}

fn read_connect_headers(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut byte = [0; 1];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while bytes.len() < CONNECT_HEADER_LIMIT {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure broker client")?;
        stream
            .read_exact(&mut byte)
            .map_err(|_| "cannot read proxy request".to_owned())?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| "invalid proxy request".to_owned());
        }
    }
    Err("proxy request headers too large".into())
}

fn resolve_connect_target(
    authority: &str,
    allow_private: bool,
) -> Option<(String, Vec<SocketAddr>)> {
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b'/' | b'@' | b'\\')
        })
    {
        return None;
    }
    let (raw_host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, port)
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    if raw_host.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    let host = canonical_host(raw_host);
    if host.is_empty() || host.contains('%') {
        return None;
    }
    let addresses = authority.to_socket_addrs().ok()?.collect::<Vec<_>>();
    if addresses.is_empty()
        || (!allow_private
            && (matches!(host.as_str(), "localhost" | "localhost.localdomain")
                || addresses
                    .iter()
                    .any(|address| private_or_local(address.ip()))))
    {
        return None;
    }
    Some((host, addresses))
}

fn canonical_host(value: &str) -> String {
    let value = value.trim_start_matches('[').trim_end_matches(']');
    value
        .parse::<IpAddr>()
        .map_or_else(|_| value.to_ascii_lowercase(), |ip| ip.to_string())
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':'))
        .map_or(pattern, |(host, _)| host);
    let pattern = canonical_host(pattern);
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn write_proxy_error(stream: &mut TcpStream, status: u16, message: &str) -> Result<(), String> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        501 => "Not Implemented",
        _ => "Bad Gateway",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}\n",
        message.len() + 1
    )
    .map_err(|error| format!("write proxy error response: {error}"))
}

#[derive(Clone, Debug)]
pub struct ApiTemplate {
    pub base_url: String,
    pub allowed_endpoints: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub default_headers: BTreeMap<String, String>,
    pub allow_private: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Send one template-bound HTTP request. Redirects are returned as responses,
/// never followed, so credentials cannot be redirected to a different host.
pub fn execute_http(
    template: &ApiTemplate,
    method: &str,
    endpoint: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    bearer: Option<&str>,
) -> Result<ApiResponse, String> {
    execute_http_with_timeout(
        template,
        method,
        endpoint,
        headers,
        body,
        bearer,
        REQUEST_TIMEOUT,
    )
}

fn execute_http_with_timeout(
    template: &ApiTemplate,
    method: &str,
    endpoint: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    bearer: Option<&str>,
    timeout: Duration,
) -> Result<ApiResponse, String> {
    let deadline = std::time::Instant::now() + timeout;
    let target = Target::parse(&template.base_url, endpoint)?;
    if !template.allowed_endpoints.is_empty()
        && !template
            .allowed_endpoints
            .iter()
            .any(|pattern| endpoint_matches(pattern, target.endpoint_path))
    {
        return Err("endpoint not allowed by template".into());
    }
    if !template.allowed_methods.is_empty()
        && !template
            .allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    {
        return Err("method not allowed by template".into());
    }
    if !is_http_token(method) {
        return Err("invalid request method".into());
    }
    if method.eq_ignore_ascii_case("HEAD") {
        return Err("HEAD is unsupported by this broker slice".into());
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("request body too large".into());
    }
    let addresses = resolve_and_check(&target.connect_authority, template.allow_private)?;
    let mut stream = connect(&addresses, deadline)?;

    let mut outgoing = BTreeMap::new();
    for (name, value) in headers.iter().chain(template.default_headers.iter()) {
        validate_header(name, value)?;
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "proxy-connection"
        ) {
            return Err("request header is controlled by the broker".into());
        }
        outgoing.insert(name.to_ascii_lowercase(), (name.as_str(), value.as_str()));
    }
    if let Some(token) = bearer.filter(|token| !token.is_empty()) {
        if validate_header("Authorization", &format!("Bearer {token}")).is_err() {
            return Err("invalid credential value".into());
        }
        outgoing.insert("authorization".into(), ("Authorization", ""));
    } else if bearer.is_some() {
        return Err("credential value is empty".into());
    }

    let mut request_head = Vec::new();
    write!(
        request_head,
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        target.path, target.host_header
    )
    .map_err(|_| "cannot write upstream request")?;
    for (key, (name, value)) in outgoing {
        if key == "authorization" && bearer.is_some() {
            write!(
                request_head,
                "{name}: Bearer {}\r\n",
                bearer.unwrap_or_default()
            )
            .map_err(|_| "cannot write upstream request")?;
        } else {
            write!(request_head, "{name}: {value}\r\n")
                .map_err(|_| "cannot write upstream request")?;
        }
    }
    write!(request_head, "Content-Length: {}\r\n\r\n", body.len())
        .map_err(|_| "cannot write upstream request")?;
    write_all_deadline(&mut stream, &request_head, deadline)?;
    write_all_deadline(&mut stream, body, deadline)?;

    let (status, mut response_body) = read_response(stream, deadline)?;
    if let Some(token) = bearer.filter(|token| !token.is_empty()) {
        response_body = replace_bytes(&response_body, token.as_bytes(), b"***");
    }
    Ok(ApiResponse {
        status,
        body: response_body,
    })
}

struct Target<'a> {
    connect_authority: String,
    host_header: String,
    path: String,
    endpoint_path: &'a str,
}

impl<'a> Target<'a> {
    fn parse(base_url: &str, endpoint: &'a str) -> Result<Self, String> {
        let base = base_url.strip_prefix("http://").ok_or_else(|| {
            "only http template URLs are supported by this broker slice".to_owned()
        })?;
        let (authority, base_path) = base.split_once('/').unwrap_or((base, ""));
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains('?')
            || authority.contains('#')
            || authority
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
        {
            return Err("invalid template URL".into());
        }
        if base_path.contains('?') || base_path.contains('#') {
            return Err("invalid template URL".into());
        }
        if !safe_path(base_path) {
            return Err("invalid template URL path".into());
        }
        if !endpoint.starts_with('/')
            || endpoint.bytes().any(|b| b.is_ascii_control() || b == b' ')
            || endpoint.contains('#')
        {
            return Err("invalid endpoint".into());
        }
        let endpoint_path = endpoint.split('?').next().unwrap_or(endpoint);
        if !safe_path(endpoint_path) {
            return Err("invalid endpoint path".into());
        }
        let base_path = base_path.trim_end_matches('/');
        let (path, query) = endpoint.split_once('?').unwrap_or((endpoint, ""));
        let path = format!("{base_path}{path}");
        let path = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        if !path.starts_with('/') || path.contains('\r') || path.contains('\n') {
            return Err("invalid endpoint".into());
        }
        let has_port = authority.rsplit_once(':').is_some_and(|(_, port)| {
            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        });
        let connect_authority = if has_port {
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        Ok(Self {
            connect_authority,
            host_header: authority.to_owned(),
            path,
            endpoint_path,
        })
    }
}

fn endpoint_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with("/*") {
        let prefix = pattern.trim_end_matches("/*");
        return (prefix.is_empty() || prefix == "/") && path.starts_with('/')
            || path.starts_with(&format!("{prefix}/"));
    }
    let mut pattern_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    loop {
        match (pattern_parts.next(), path_parts.next()) {
            (None, None) => return true,
            (Some(p), Some(v)) if p == "*" || p == v => {}
            _ => return false,
        }
    }
}

fn safe_path(path: &str) -> bool {
    !path.contains('%')
        && !path.contains('\\')
        && !path.contains('\r')
        && !path.contains('\n')
        && !path.contains("//")
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

fn resolve_and_check(authority: &str, allow_private: bool) -> Result<Vec<SocketAddr>, String> {
    // ponytail: std DNS resolution is uninterruptible; add a cancellable resolver if latency matters.
    let addresses = authority
        .to_socket_addrs()
        .map_err(|_| "cannot resolve upstream host")?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("cannot resolve upstream host".into());
    }
    if addresses.iter().any(|addr| !is_loopback(addr.ip())) {
        return Err("plain HTTP is restricted to loopback targets".into());
    }
    if !allow_private && addresses.iter().any(|addr| private_or_local(addr.ip())) {
        return Err("blocked private or local upstream host".into());
    }
    Ok(addresses)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|mapped| mapped.is_loopback())
                || ip.is_loopback()
        }
    }
}

fn private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|mapped| private_or_local(IpAddr::V4(mapped)))
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    }
}

fn remaining(deadline: std::time::Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "upstream request timed out".into())
}

fn connect(addresses: &[SocketAddr], deadline: std::time::Instant) -> Result<TcpStream, String> {
    for address in addresses {
        let timeout = remaining(deadline)?;
        if let Ok(stream) = TcpStream::connect_timeout(address, timeout) {
            return Ok(stream);
        }
    }
    Err("cannot connect to upstream host".into())
}

fn write_all_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<(), String> {
    let mut written = 0;
    while written < bytes.len() {
        let timeout = remaining(deadline)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| "cannot configure upstream connection")?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err("cannot write upstream request".into()),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err("upstream request timed out".into());
            }
            Err(_) => return Err("cannot write upstream request".into()),
        }
    }
    Ok(())
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn validate_header(name: &str, value: &str) -> Result<(), String> {
    if !is_http_token(name)
        || value
            .bytes()
            .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
    {
        return Err("invalid request header".into());
    }
    Ok(())
}

fn read_response(
    stream: TcpStream,
    deadline: std::time::Instant,
) -> Result<(u16, Vec<u8>), String> {
    let mut reader = BufReader::new(stream);
    let mut total_header_bytes = 0;
    let mut informational_count = 0;
    loop {
        let status_line = read_line_limited(&mut reader, 8 * 1024, deadline)?
            .ok_or("invalid upstream response")?;
        total_header_bytes += status_line.len();
        if total_header_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err("upstream response headers too large".into());
        }
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|status| status.parse::<u16>().ok())
            .filter(|status| (100..=599).contains(status))
            .ok_or("invalid upstream response")?;
        let mut content_length = None;
        let mut chunked = false;
        let mut header_bytes = status_line.len();
        loop {
            let line = read_line_limited(&mut reader, 8 * 1024, deadline)?
                .ok_or("invalid upstream response")?;
            header_bytes += line.len();
            total_header_bytes += line.len();
            if header_bytes > MAX_RESPONSE_HEADER_BYTES
                || total_header_bytes > MAX_RESPONSE_HEADER_BYTES
            {
                return Err("upstream response headers too large".into());
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line
                .trim_end_matches(&['\r', '\n'][..])
                .split_once(':')
                .ok_or("invalid upstream response")?;
            if name.eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid upstream response")?;
                if content_length.replace(parsed).is_some() {
                    return Err("invalid upstream response".into());
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
            }
        }
        if chunked && content_length.is_some() {
            return Err("invalid upstream response".into());
        }
        if (100..200).contains(&status) {
            if status == 101 {
                return Err("upstream protocol switch is unsupported".into());
            }
            informational_count += 1;
            if informational_count > MAX_INFORMATIONAL_RESPONSES {
                return Err("too many informational upstream responses".into());
            }
            continue;
        }
        if matches!(status, 204 | 205 | 304) {
            return Ok((status, Vec::new()));
        }
        let body = if chunked {
            read_chunked(
                &mut reader,
                deadline,
                MAX_RESPONSE_HEADER_BYTES - total_header_bytes,
            )?
        } else if let Some(length) = content_length {
            if length > MAX_RESPONSE_BYTES {
                return Err("upstream response too large".into());
            }
            let mut body = vec![0; length];
            read_exact_deadline(&mut reader, &mut body, deadline)?;
            body
        } else {
            read_until_close_deadline(&mut reader, deadline)?
        };
        return Ok((status, body));
    }
}

fn read_chunked(
    reader: &mut BufReader<TcpStream>,
    deadline: std::time::Instant,
    max_trailer_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line =
            read_line_limited(reader, 8 * 1024, deadline)?.ok_or("invalid upstream response")?;
        let size = usize::from_str_radix(
            line.trim_end_matches(&['\r', '\n'][..])
                .split(';')
                .next()
                .ok_or("invalid upstream response")?,
            16,
        )
        .map_err(|_| "invalid upstream response")?;
        if size == 0 {
            let mut trailer_bytes = 0;
            loop {
                let line = read_line_limited(reader, 8 * 1024, deadline)?
                    .ok_or("invalid upstream response")?;
                trailer_bytes += line.len();
                if trailer_bytes > max_trailer_bytes {
                    return Err("upstream response headers too large".into());
                }
                if line == "\r\n" || line.is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len().saturating_add(size) > MAX_RESPONSE_BYTES {
            return Err("upstream response too large".into());
        }
        let old_len = body.len();
        body.resize(old_len + size, 0);
        read_exact_deadline(reader, &mut body[old_len..], deadline)?;
        let mut crlf = [0; 2];
        read_exact_deadline(reader, &mut crlf, deadline)?;
        if crlf != *b"\r\n" {
            return Err("invalid upstream response".into());
        }
    }
}

fn read_line_limited(
    reader: &mut BufReader<TcpStream>,
    max_bytes: usize,
    deadline: std::time::Instant,
) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    loop {
        reader
            .get_ref()
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure upstream connection")?;
        let available = reader.fill_buf().map_err(read_error)?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("invalid upstream response".into())
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if bytes.len() + take > max_bytes {
            return Err("upstream response line too large".into());
        }
        let done = available[take - 1] == b'\n';
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            return String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| "invalid upstream response".into());
        }
    }
}

fn read_exact_deadline(
    reader: &mut BufReader<TcpStream>,
    bytes: &mut [u8],
    deadline: std::time::Instant,
) -> Result<(), String> {
    let mut read = 0;
    while read < bytes.len() {
        reader
            .get_ref()
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure upstream connection")?;
        match reader.read(&mut bytes[read..]) {
            Ok(0) => return Err("invalid upstream response".into()),
            Ok(count) => read += count,
            Err(error) => return Err(read_error(error)),
        }
    }
    Ok(())
}

fn read_until_close_deadline(
    reader: &mut BufReader<TcpStream>,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut chunk = [0; 8 * 1024];
    loop {
        reader
            .get_ref()
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure upstream connection")?;
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(body),
            Ok(count) => {
                if body.len() + count > MAX_RESPONSE_BYTES {
                    return Err("upstream response too large".into());
                }
                body.extend_from_slice(&chunk[..count]);
            }
            Err(error) => return Err(read_error(error)),
        }
    }
}

fn read_error(error: std::io::Error) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        "upstream request timed out".into()
    } else {
        "upstream request failed".into()
    }
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut result = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(index) = rest
        .windows(needle.len())
        .position(|window| window == needle)
    {
        result.extend_from_slice(&rest[..index]);
        result.extend_from_slice(replacement);
        rest = &rest[index + needle.len()..];
    }
    result.extend_from_slice(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        sync::{Arc, atomic::AtomicBool},
        thread,
    };

    #[test]
    fn connect_passthrough_tunnels_only_allowlisted_loopback_hosts() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let proxy_stopping = Arc::clone(&stopping);
        let proxy_thread = thread::spawn(move || {
            serve_connect_passthrough(
                proxy,
                vec!["127.0.0.1".into()],
                false,
                &proxy_stopping,
                true,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        write!(
            client,
            "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"
        )
        .unwrap();
        let mut response = BufReader::new(client.try_clone().unwrap());
        let mut status = String::new();
        response.read_line(&mut status).unwrap();
        assert_eq!(status, "HTTP/1.1 200 Connection Established\r\n");
        loop {
            let mut header = String::new();
            response.read_line(&mut header).unwrap();
            if header == "\r\n" {
                break;
            }
        }
        client.write_all(b"ping").unwrap();
        let mut body = [0; 4];
        response.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"pong");
        drop(response);
        drop(client);
        upstream_thread.join().unwrap();
        stopping.store(true, Ordering::Relaxed);
        proxy_thread.join().unwrap();
    }

    #[test]
    fn connect_passthrough_fails_closed_for_unlisted_or_private_targets() {
        let private = resolve_connect_target("127.0.0.1:443", false);
        assert!(private.is_none());
        let (ipv6_host, _) = resolve_connect_target("[::1]:443", true).unwrap();
        assert_eq!(ipv6_host, "::1");
        assert!(host_matches("example.com", "api.example.com"));
        assert!(host_matches("example.com:443", "api.example.com"));
        assert!(host_matches("[::1]", "::1"));
        assert!(!host_matches("example.com", "notexample.com"));
        assert!(!host_matches("example.com", "example.com.evil"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_connect_client(stream.try_clone().unwrap(), &[], true, true).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        write!(client, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut response = String::new();
        BufReader::new(client).read_line(&mut response).unwrap();
        assert_eq!(response, "HTTP/1.1 403 Forbidden\r\n");
        client_thread.join().unwrap();
    }

    #[test]
    fn loopback_transcript_injects_then_redacts_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    content_length = line
                        .split_once(':')
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .unwrap_or_default();
                }
                request.extend_from_slice(line.as_bytes());
                if line == "\r\n" {
                    break;
                }
            }
            assert!(
                String::from_utf8_lossy(&request).contains("Authorization: Bearer fixture-secret")
            );
            assert!(String::from_utf8_lossy(&request).contains("X-Mode: default"));
            assert!(!String::from_utf8_lossy(&request).contains("X-Mode: caller"));
            let mut request_body = vec![0; content_length];
            reader.read_exact(&mut request_body).unwrap();
            assert_eq!(request_body, b"{}");
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\nfixture-secret:ok!!";
            stream.write_all(response).unwrap();
        });
        let template = ApiTemplate {
            base_url: format!("http://{address}"),
            allowed_endpoints: vec!["/v1/*".into()],
            allowed_methods: vec!["POST".into()],
            default_headers: BTreeMap::from([("X-Mode".into(), "default".into())]),
            allow_private: true,
        };
        let response = execute_http(
            &template,
            "POST",
            "/v1/items?x=1",
            &BTreeMap::from([("X-Mode".into(), "caller".into())]),
            b"{}",
            Some("fixture-secret"),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"***:ok!!");
    }

    #[test]
    fn denied_target_and_endpoint_do_not_echo_credential() {
        let template = ApiTemplate {
            base_url: "http://127.0.0.1:9".into(),
            allowed_endpoints: vec!["/safe/*".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private: false,
        };
        let denied = execute_http(
            &template,
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            Some("must-not-leak"),
        )
        .unwrap_err();
        assert!(!denied.contains("must-not-leak"));

        let denied = execute_http(
            &template,
            "GET",
            "/unsafe",
            &BTreeMap::new(),
            b"",
            Some("must-not-leak"),
        )
        .unwrap_err();
        assert_eq!(denied, "endpoint not allowed by template");
        assert!(!denied.contains("must-not-leak"));
    }

    #[test]
    fn cleartext_bearer_is_restricted_to_loopback_even_when_private_is_allowed() {
        let template = ApiTemplate {
            base_url: "http://192.0.2.1".into(),
            allowed_endpoints: vec!["/safe/*".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private: true,
        };
        let error = execute_http(
            &template,
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            Some("must-not-leak"),
        )
        .unwrap_err();
        assert_eq!(error, "plain HTTP is restricted to loopback targets");
        assert!(!error.contains("must-not-leak"));
    }

    #[test]
    fn ambiguous_paths_and_head_are_rejected_before_transport() {
        let template = ApiTemplate {
            base_url: "http://127.0.0.1:9".into(),
            allowed_endpoints: vec!["/v1/*".into()],
            allowed_methods: vec!["GET".into(), "HEAD".into()],
            default_headers: BTreeMap::new(),
            allow_private: true,
        };
        for endpoint in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1%2fadmin",
            "/v1//admin",
            "/v1\\admin",
        ] {
            let error = execute_http(
                &template,
                "GET",
                endpoint,
                &BTreeMap::new(),
                b"",
                Some("must-not-leak"),
            )
            .unwrap_err();
            assert!(!error.contains("must-not-leak"));
            assert!(!error.contains(endpoint));
        }
        assert_eq!(
            execute_http(&template, "HEAD", "/v1/item", &BTreeMap::new(), b"", None,).unwrap_err(),
            "HEAD is unsupported by this broker slice"
        );
    }

    #[test]
    fn informational_and_bodyless_responses_keep_the_final_framing() {
        let (status, body) = response_from_loopback(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec(),
        )
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"OK");

        let (status, body) = response_from_loopback(
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .unwrap();
        assert_eq!(status, 304);
        assert!(body.is_empty());

        let mut interim = Vec::new();
        for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
            interim.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n\r\n");
        }
        assert_eq!(
            response_from_loopback(interim).unwrap_err(),
            "too many informational upstream responses"
        );

        let mut headers = Vec::new();
        for _ in 0..MAX_INFORMATIONAL_RESPONSES {
            headers.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nX-Pad: ");
            headers.extend(std::iter::repeat_n(b'a', 8_180));
            headers.extend_from_slice(b"\r\n\r\n");
        }
        assert_eq!(
            response_from_loopback(headers).unwrap_err(),
            "upstream response headers too large"
        );
    }

    #[test]
    fn slow_drip_cannot_extend_the_absolute_request_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let template = ApiTemplate {
            base_url: format!("http://{address}"),
            allowed_endpoints: vec!["/safe/*".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private: true,
        };
        let started = std::time::Instant::now();
        let error = execute_http_with_timeout(
            &template,
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            None,
            Duration::from_millis(150),
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        server.join().unwrap();
        assert_eq!(error, "upstream request timed out");
        assert!(elapsed < Duration::from_millis(500));
    }

    fn response_from_loopback(wire: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&wire).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        let response = read_response(stream, std::time::Instant::now() + Duration::from_secs(2));
        server.join().unwrap();
        response
    }
}
