//! Bounded HTTP slice for Go's API-template and egress broker contract.
//! Oracle sources: broker proxy/auth at `ba4dc0680878870bfb30ccd39a0b973b960d3e09`,
//! and `internal/ssrf/ssrf.go` at `c7c6d04b6dc6349800d12d87d605ae55081bf694`.
//!
//! This helper sends plain HTTP only to numeric loopback addresses or `localhost`,
//! and verified HTTPS only to those same local targets in this slice. Public
//! DNS validation, vault lookup, substitutions, audit, and response pattern
//! sanitization remain separate migration work.

use reqwest::{
    Method, Url,
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const API_RESPONSE_LIMIT: usize = 100 * 1024;
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const REQWEST_IMPLICIT_HEADER_BUDGET: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct ApiTemplate {
    pub base_url: String,
    pub allowed_endpoints: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub default_headers: BTreeMap<String, String>,
    pub allow_private: bool,
}

/// YAML-facing template definition used by the CLI's existing template loader.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTemplateDefinition {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub entry_ref: String,
    #[serde(default)]
    pub allowed_endpoints: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub default_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub substitutions: Vec<ApiSubstitution>,
    #[serde(default)]
    pub allow_private: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSubstitution {
    pub placeholder: String,
    pub field: String,
    #[serde(default, rename = "in")]
    pub surfaces: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: BTreeMap<String, String>,
    pub body_truncated: bool,
    pub sanitized: bool,
}

/// Send one template-bound request. Redirects are returned, never followed.
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
    execute_http_inner(
        template,
        method,
        endpoint,
        headers,
        body,
        bearer,
        timeout,
        MAX_BODY_BYTES,
        false,
        true,
        None,
        &[],
    )
}

/// Bounded API response transport; the caller immediately applies exact
/// redaction for every credential-entry string followed by Go-compatible
/// pattern masking before it can become an MCP result.
pub(crate) fn execute_http_for_api(
    template: &ApiTemplate,
    method: &str,
    endpoint: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    bounds: ApiResponseBounds,
) -> Result<ApiResponse, String> {
    let request_url = Url::parse(request_url).map_err(|_| "invalid template URL")?;
    execute_http_inner(
        template,
        method,
        endpoint,
        headers,
        body,
        None,
        bounds.timeout,
        bounds.response_limit,
        true,
        false,
        Some(request_url),
        &[],
    )
}

pub(crate) struct ApiResponseBounds {
    pub timeout: Duration,
    pub response_limit: usize,
}

#[allow(clippy::too_many_arguments)]
fn execute_http_inner(
    template: &ApiTemplate,
    method: &str,
    endpoint: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    bearer: Option<&str>,
    timeout: Duration,
    response_limit: usize,
    truncate_response: bool,
    redact_bearer: bool,
    request_url_override: Option<Url>,
    extra_root_certificates: &[reqwest::Certificate],
) -> Result<ApiResponse, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err("request body too large".into());
    }
    if response_limit == 0 || response_limit > MAX_BODY_BYTES {
        return Err("invalid response body limit".into());
    }
    let mut target = Target::parse(&template.base_url, endpoint, template.allow_private)?;
    if let Some(request_url) = request_url_override {
        if request_url.scheme() != target.url.scheme()
            || request_url.host() != target.url.host()
            || request_url.port_or_known_default() != target.url.port_or_known_default()
            || !request_url.username().is_empty()
            || request_url.password().is_some()
        {
            return Err("API request URL changed the validated upstream authority".into());
        }
        target.url = request_url;
    }
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

    let mut outgoing = BTreeMap::new();
    let mut supplied_header_bytes = 0;
    for (name, value) in headers.iter().chain(template.default_headers.iter()) {
        validate_header(name, value)?;
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "proxy-connection"
        ) {
            return Err("request header is controlled by the broker".into());
        }
        add_header_bytes(&mut supplied_header_bytes, name.len())?;
        add_header_bytes(&mut supplied_header_bytes, value.len())?;
        add_header_bytes(&mut supplied_header_bytes, 4)?;
        outgoing.insert(name.to_ascii_lowercase(), (name.clone(), value.clone()));
    }
    if let Some(token) = bearer {
        if token.is_empty() {
            return Err("credential value is empty".into());
        }
        validate_header("Authorization", token)?;
        add_header_bytes(&mut supplied_header_bytes, "Authorization".len())?;
        add_header_bytes(&mut supplied_header_bytes, "Bearer ".len())?;
        add_header_bytes(&mut supplied_header_bytes, token.len())?;
        add_header_bytes(&mut supplied_header_bytes, 4)?;
        outgoing.insert(
            "authorization".into(),
            ("Authorization".into(), format!("Bearer {token}")),
        );
    }

    let mut request_headers = HeaderMap::new();
    for (name, value) in outgoing.values() {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid request header")?;
        let value = HeaderValue::from_str(value).map_err(|_| "invalid request header")?;
        request_headers.insert(name, value);
    }
    let request_target_bytes =
        target.url.path().len() + target.url.query().map_or(0, |query| query.len() + 1);
    // Reserve space for standard fields inserted by reqwest/hyper (for
    // example User-Agent and Accept) as well as the fields counted below.
    let mut total_header_bytes = REQWEST_IMPLICIT_HEADER_BUDGET;
    add_header_bytes(&mut total_header_bytes, supplied_header_bytes)?;
    for size in [
        method.len(),
        1,
        request_target_bytes,
        " HTTP/1.1\r\nHost: \r\nConnection: close\r\nContent-Length: \r\n\r\n".len(),
        target.host.len(),
        body.len().to_string().len(),
    ] {
        add_header_bytes(&mut total_header_bytes, size)?;
    }

    let addresses = target.addresses;
    let client = build_http_client(timeout, &target.host, &addresses, extra_root_certificates)?;
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| "invalid request method")?;
    let response = client
        .request(method, target.url)
        .headers(request_headers)
        .body(body.to_vec())
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                "upstream request timed out"
            } else {
                "upstream request failed"
            }
        })?;

    let status = response.status().as_u16();
    let raw_response_headers = response.headers().clone();
    let mut response_body = Vec::new();
    response
        .take((response_limit + 1) as u64)
        .read_to_end(&mut response_body)
        .map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                "upstream request timed out"
            } else {
                "upstream request failed"
            }
        })?;
    let body_truncated = response_body.len() > response_limit;
    if body_truncated && !truncate_response {
        return Err("upstream response too large".into());
    }
    response_body.truncate(response_limit);
    let mut sanitized = false;
    let mut response_headers = BTreeMap::new();
    for name in raw_response_headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "set-cookie"
                | "authorization"
                | "www-authenticate"
                | "proxy-authenticate"
                | "proxy-authorization"
        ) {
            continue;
        }
        let raw_value = raw_response_headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let token = if redact_bearer { bearer } else { None };
        let sanitized_value = token.map_or_else(
            || raw_value.to_owned(),
            |token| {
                String::from_utf8_lossy(&replace_bytes(
                    raw_value.as_bytes(),
                    token.as_bytes(),
                    b"***",
                ))
                .into_owned()
            },
        );
        sanitized |= sanitized_value != raw_value;
        response_headers.insert(canonical_header_name(name.as_str()), sanitized_value);
    }
    if redact_bearer && let Some(token) = bearer {
        let redacted = replace_bytes(&response_body, token.as_bytes(), b"***");
        sanitized |= redacted != response_body;
        response_body = redacted;
    }
    Ok(ApiResponse {
        status,
        body: response_body,
        headers: response_headers,
        body_truncated,
        sanitized,
    })
}

fn build_http_client(
    timeout: Duration,
    host: &str,
    addresses: &[SocketAddr],
    extra_root_certificates: &[reqwest::Certificate],
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(Policy::none())
        .no_proxy();
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(host, addresses);
    }
    if !extra_root_certificates.is_empty() {
        // Tests may provide a private fixture CA. Keep that root scoped to the
        // constructed client; production requests never enter this branch.
        builder = builder.tls_certs_only(extra_root_certificates.iter().cloned());
    }
    builder
        .build()
        .map_err(|_| "cannot configure upstream connection".into())
}

fn canonical_header_name(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Validate endpoint and method policy before approval or credential access.
pub fn validate_api_request(
    template: &ApiTemplate,
    method: &str,
    endpoint: &str,
) -> Result<(), String> {
    let target = Target::parse(&template.base_url, endpoint, template.allow_private)?;
    if template.allowed_endpoints.is_empty()
        || !template
            .allowed_endpoints
            .iter()
            .any(|pattern| endpoint_matches(pattern, target.endpoint_path))
    {
        return Err("endpoint not allowed by template".into());
    }
    if template.allowed_methods.is_empty()
        || !template
            .allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    {
        return Err("method not allowed by template".into());
    }
    if !is_http_token(method) || method.eq_ignore_ascii_case("HEAD") {
        return Err("invalid request method".into());
    }
    let mut header_bytes = 0;
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in &template.default_headers {
        validate_header(name, value)?;
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "proxy-connection"
        ) {
            return Err("request header is controlled by the broker".into());
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err("duplicate request header".into());
        }
        add_header_bytes(&mut header_bytes, name.len())?;
        add_header_bytes(&mut header_bytes, value.len())?;
        add_header_bytes(&mut header_bytes, 4)?;
    }
    Ok(())
}

#[derive(Debug)]
struct Target<'a> {
    url: Url,
    host: String,
    addresses: Vec<SocketAddr>,
    endpoint_path: &'a str,
}

impl<'a> Target<'a> {
    fn parse(base_url: &str, endpoint: &'a str, allow_private: bool) -> Result<Self, String> {
        if base_url.len().saturating_add(endpoint.len()) > MAX_REQUEST_HEADER_BYTES {
            return Err("request headers too large".into());
        }
        if base_url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
        {
            return Err(
                "only plain HTTP loopback template URLs are supported by this broker slice".into(),
            );
        }
        let (scheme, raw_base) = if let Some(raw) = base_url.strip_prefix("http://") {
            ("http", raw)
        } else if let Some(raw) = base_url.strip_prefix("https://") {
            ("https", raw)
        } else {
            return Err("only HTTP and HTTPS template URLs are supported".into());
        };
        let (authority, base_path) = raw_base.split_once('/').unwrap_or((raw_base, ""));
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains('?')
            || authority.contains('#')
            || base_path.contains('?')
            || base_path.contains('#')
            || !safe_path(base_path)
        {
            return Err("invalid template URL".into());
        }
        if !endpoint.starts_with('/')
            || endpoint
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || endpoint.contains('#')
        {
            return Err("invalid endpoint".into());
        }
        let endpoint_path = endpoint.split('?').next().unwrap_or(endpoint);
        if !safe_path(endpoint_path) {
            return Err("invalid endpoint path".into());
        }

        let url = Url::parse(&format!("{}{}", base_url.trim_end_matches('/'), endpoint))
            .map_err(|_| "invalid template URL")?;
        // `host_str()` includes brackets around IPv6 literals; remove them so
        // the address parser and loopback checks see the canonical IP text.
        let host = url
            .host_str()
            .ok_or("invalid template URL")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port_or_known_default().ok_or("invalid template URL")?;
        let addresses = match loopback_addresses(&host, port) {
            Ok(addresses) => addresses,
            Err(_) if scheme == "https" => {
                return Err(
                    "HTTPS public DNS targets are not supported by this broker slice".into(),
                );
            }
            Err(error) => return Err(error),
        };
        if !allow_private {
            return Err("blocked private or local upstream host".into());
        }
        if url.scheme() != scheme {
            return Err("invalid template URL".into());
        }
        Ok(Self {
            url,
            host,
            addresses,
            endpoint_path,
        })
    }
}

fn loopback_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_loopback(ip) {
            return Err("plain HTTP is restricted to loopback targets".into());
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]);
    }
    Err("plain HTTP is restricted to loopback targets".into())
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
            (Some(pattern_part), Some(path_part))
                if pattern_part == "*" || pattern_part == path_part => {}
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

fn add_header_bytes(total: &mut usize, bytes: usize) -> Result<(), String> {
    *total = total
        .checked_add(bytes)
        .filter(|size| *size <= MAX_REQUEST_HEADER_BYTES)
        .ok_or_else(|| "request headers too large".to_owned())?;
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

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }

    // KMP keeps redaction linear even for long, adversarial bearer values.
    let mut prefix = vec![0; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && needle[index] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
            prefix[index] = matched;
        }
    }

    let mut result = Vec::with_capacity(haystack.len());
    let mut segment_start = 0;
    let mut index = 0;
    matched = 0;
    while index < haystack.len() {
        while matched > 0 && haystack[index] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if haystack[index] == needle[matched] {
            matched += 1;
            if matched == needle.len() {
                let end = index + 1;
                result.extend_from_slice(&haystack[segment_start..end - needle.len()]);
                result.extend_from_slice(replacement);
                segment_start = end;
                matched = 0;
            }
        }
        index += 1;
    }
    result.extend_from_slice(&haystack[segment_start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::Arc,
        thread,
    };

    #[test]
    fn loopback_transcript_injects_then_redacts_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
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
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let request = request.to_ascii_lowercase();
            assert!(request.contains("authorization: bearer fixture-secret"));
            assert!(request.contains("x-mode: default"));
            assert!(!request.contains("x-mode: caller"));
            let mut request_body = vec![0; content_length];
            reader.read_exact(&mut request_body).unwrap();
            assert_eq!(request_body, b"{}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\nfixture-secret:ok!!")
                .unwrap();
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
    fn execute_http_keeps_the_sixteen_mib_response_error_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let body = vec![b'x'; MAX_BODY_BYTES + 1];
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let template = ApiTemplate {
            base_url: format!("http://{address}"),
            allowed_endpoints: vec!["/oversized".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private: true,
        };
        assert_eq!(
            execute_http(&template, "GET", "/oversized", &BTreeMap::new(), b"", None).unwrap_err(),
            "upstream response too large"
        );
        server.join().unwrap();
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
        let error = execute_http(
            &template,
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            Some("must-not-leak"),
        )
        .unwrap_err();
        assert_eq!(error, "blocked private or local upstream host");
        assert!(!error.contains("must-not-leak"));
        let mut allowed_private = template.clone();
        allowed_private.allow_private = true;
        assert_eq!(
            execute_http(
                &allowed_private,
                "GET",
                "/unsafe",
                &BTreeMap::new(),
                b"",
                Some("must-not-leak")
            )
            .unwrap_err(),
            "endpoint not allowed by template"
        );
    }

    #[test]
    fn cleartext_remote_and_non_literal_hosts_are_rejected() {
        let mut template = ApiTemplate {
            base_url: "http://192.0.2.1".into(),
            allowed_endpoints: vec!["/safe/*".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private: true,
        };
        assert_eq!(
            execute_http(&template, "GET", "/safe/item", &BTreeMap::new(), b"", None).unwrap_err(),
            "plain HTTP is restricted to loopback targets"
        );
        template.base_url = "http://api.example.test".into();
        assert_eq!(
            execute_http(&template, "GET", "/safe/item", &BTreeMap::new(), b"", None).unwrap_err(),
            "plain HTTP is restricted to loopback targets"
        );
    }

    #[test]
    fn https_is_verified_for_local_targets_and_public_dns_remains_blocked() {
        let template = |base_url: &str, allow_private| ApiTemplate {
            base_url: base_url.into(),
            allowed_endpoints: vec!["/v1/*".into()],
            allowed_methods: vec!["GET".into()],
            default_headers: BTreeMap::new(),
            allow_private,
        };
        assert!(Target::parse("https://localhost:443", "/v1/status", true).is_ok());
        assert_eq!(
            Target::parse("https://localhost:443", "/v1/status", false).unwrap_err(),
            "blocked private or local upstream host"
        );
        assert_eq!(
            Target::parse("https://api.example.test", "/v1/status", true).unwrap_err(),
            "HTTPS public DNS targets are not supported by this broker slice"
        );
        assert_eq!(
            execute_http(
                &template("https://api.example.test", true),
                "GET",
                "/v1/status",
                &BTreeMap::new(),
                b"",
                None,
            )
            .unwrap_err(),
            "HTTPS public DNS targets are not supported by this broker slice"
        );
    }

    #[test]
    fn local_https_contract_matches_the_source_bound_go_handler_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/port/mcp/execute-api-https.json"
        ))
        .unwrap();
        for (case_name, host, bind, trust_root) in [
            ("valid_local_tls", "127.0.0.1", "127.0.0.1:0", true),
            (
                "wrong_hostname_tls",
                "wrong.example.test",
                "127.0.0.1:0",
                true,
            ),
            ("untrusted_root_tls", "127.0.0.1", "127.0.0.1:0", false),
        ] {
            let expected = fixture["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == case_name)
                .unwrap_or_else(|| panic!("missing Go HTTPS fixture case {case_name}"));
            assert_eq!(expected["host"], host);
            let listener = TcpListener::bind(bind).unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || serve_test_tls_once(listener));
            let template = ApiTemplate {
                base_url: format!("https://{host}:{}", address.port()),
                allowed_endpoints: vec!["/v1/*".into()],
                allowed_methods: vec!["GET".into()],
                default_headers: BTreeMap::new(),
                allow_private: true,
            };
            let roots = if trust_root {
                vec![
                    reqwest::Certificate::from_pem(include_bytes!("../tests/fixtures/tls-ca.pem"))
                        .unwrap(),
                ]
            } else {
                Vec::new()
            };
            let response = if case_name == "wrong_hostname_tls" {
                let client = build_http_client(
                    Duration::from_secs(3),
                    host,
                    &[SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        address.port(),
                    )],
                    &roots,
                )
                .unwrap();
                client
                    .get(format!("https://{host}:{}/v1/status", address.port()))
                    .send()
                    .map(|response| ApiResponse {
                        status: response.status().as_u16(),
                        body: Vec::new(),
                        headers: BTreeMap::new(),
                        body_truncated: false,
                        sanitized: false,
                    })
                    .map_err(|_| "upstream request failed".to_owned())
            } else {
                execute_http_inner(
                    &template,
                    "GET",
                    "/v1/status",
                    &BTreeMap::new(),
                    b"",
                    None,
                    Duration::from_secs(3),
                    MAX_BODY_BYTES,
                    false,
                    false,
                    None,
                    &roots,
                )
            };
            let actual_requests = server.join().unwrap();
            assert_eq!(
                actual_requests,
                expected["requests"].as_u64().unwrap() as usize
            );
            if expected["is_error"] == true {
                assert!(response.is_err(), "{case_name} unexpectedly succeeded");
            } else {
                let response = response.unwrap_or_else(|error| panic!("{case_name}: {error}"));
                assert_eq!(response.status, expected["status"].as_u64().unwrap() as u16);
                assert_eq!(response.body, expected["body"].as_str().unwrap().as_bytes());
            }
        }
    }

    fn serve_test_tls_once(listener: TcpListener) -> usize {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return 0;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return 0,
            }
        };
        stream.set_nonblocking(false).unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let cert = decode_pem_fixture(
            include_str!("../tests/fixtures/tls-server.pem"),
            "CERTIFICATE",
        );
        let key = decode_pem_fixture(
            include_str!("../tests/fixtures/tls-server.key"),
            "PRIVATE KEY",
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, stream);
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) => return 0,
                Err(_) => return 0,
                Ok(_) => request.push(byte[0]),
            }
            if request.len() > 16 * 1024 {
                return 0;
            }
        }
        assert!(request.starts_with(b"GET /v1/status HTTP/1.1\r\n"));
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\nfixture tls ok";
        let _ = stream.write_all(response);
        1
    }

    fn decode_pem_fixture(pem: &str, label: &str) -> Vec<u8> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = pem
            .split_once(&begin)
            .and_then(|(_, rest)| rest.split_once(&end).map(|(body, _)| body))
            .expect("fixture PEM block");
        STANDARD
            .decode(body.split_whitespace().collect::<String>())
            .unwrap()
    }

    #[test]
    fn ipv6_loopback_host_is_normalized_without_brackets() {
        let target = Target::parse("http://[::1]", "/v1/item", true).unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(
            target.addresses,
            vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80)]
        );
    }

    #[test]
    fn bearer_redaction_replaces_non_overlapping_matches() {
        assert_eq!(replace_bytes(b"ababa", b"aba", b"***"), b"***ba");
        assert_eq!(
            replace_bytes(b"secret secret", b"secret", b"***"),
            b"*** ***"
        );
    }

    #[test]
    fn unsafe_paths_headers_and_header_size_are_rejected_before_network() {
        let template = ApiTemplate {
            base_url: "http://127.0.0.1:9".into(),
            allowed_endpoints: vec!["/v1/*".into()],
            allowed_methods: vec!["GET".into()],
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
            assert!(execute_http(&template, "GET", endpoint, &BTreeMap::new(), b"", None).is_err());
        }
        let mut bad_base = template.clone();
        bad_base.base_url = "http://127.0.0.1/a b".into();
        assert_eq!(
            execute_http(&bad_base, "GET", "/v1/item", &BTreeMap::new(), b"", None).unwrap_err(),
            "only plain HTTP loopback template URLs are supported by this broker slice"
        );
        let mut oversized = template;
        oversized
            .default_headers
            .insert("X-Large".into(), "x".repeat(MAX_REQUEST_HEADER_BYTES));
        assert_eq!(
            execute_http(&oversized, "GET", "/v1/item", &BTreeMap::new(), b"", None).unwrap_err(),
            "request headers too large"
        );
        assert_eq!(
            execute_http(
                &ApiTemplate {
                    base_url: "http://127.0.0.1".into(),
                    allowed_endpoints: vec![],
                    allowed_methods: vec![],
                    default_headers: BTreeMap::new(),
                    allow_private: true,
                },
                "GET",
                &format!("/{}", "x".repeat(MAX_REQUEST_HEADER_BYTES)),
                &BTreeMap::new(),
                b"",
                None,
            )
            .unwrap_err(),
            "request headers too large"
        );
    }

    #[test]
    fn slow_response_cannot_extend_the_request_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nx")
                .unwrap();
            thread::sleep(Duration::from_millis(400));
            let _ = stream.write_all(b"xxxxxxx");
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
        assert!(matches!(
            error.as_str(),
            "upstream request timed out" | "upstream request failed"
        ));
        assert!(
            elapsed >= Duration::from_millis(100),
            "{error}: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_millis(500), "{error}: {elapsed:?}");
        server.join().unwrap();
    }
}
