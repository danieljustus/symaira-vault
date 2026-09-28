//! Bounded HTTP slice for Go's API-template and egress broker contract.
//! Oracle sources: broker proxy/auth at `ba4dc0680878870bfb30ccd39a0b973b960d3e09`,
//! and `internal/ssrf/ssrf.go` at `c7c6d04b6dc6349800d12d87d605ae55081bf694`.
//!
//! This helper only sends plain HTTP to numeric loopback addresses or `localhost`.
//! TLS interception, template loading, vault lookup, substitutions, audit, and
//! response pattern sanitization remain separate migration work.

use reqwest::{
    Method, Url,
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use std::{
    collections::BTreeMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
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

#[derive(Debug, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
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
    if body.len() > MAX_BODY_BYTES {
        return Err("request body too large".into());
    }
    let target = Target::parse(&template.base_url, endpoint, template.allow_private)?;
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
    let mut builder = Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(Policy::none())
        .no_proxy();
    if target.host.eq_ignore_ascii_case("localhost") {
        builder = builder.resolve_to_addrs("localhost", &addresses);
    }
    let client = builder
        .build()
        .map_err(|_| "cannot configure upstream connection")?;
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
    let mut response_body = Vec::new();
    response
        .take((MAX_BODY_BYTES + 1) as u64)
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
    if response_body.len() > MAX_BODY_BYTES {
        return Err("upstream response too large".into());
    }
    if let Some(token) = bearer {
        response_body = replace_bytes(&response_body, token.as_bytes(), b"***");
    }
    Ok(ApiResponse {
        status,
        body: response_body,
    })
}

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
        if !base_url.starts_with("http://")
            || base_url
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
        {
            return Err(
                "only plain HTTP loopback template URLs are supported by this broker slice".into(),
            );
        }
        let raw_base = &base_url["http://".len()..];
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
        let addresses = loopback_addresses(&host, port)?;
        if !allow_private {
            return Err("blocked private or local upstream host".into());
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
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
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
        assert_eq!(error, "upstream request timed out");
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }
}
