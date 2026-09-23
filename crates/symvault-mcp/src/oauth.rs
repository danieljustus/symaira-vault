use crate::http::HttpResponse;
use serde::Deserialize;

#[derive(Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
}

/// RFC 7591 public-client registration. Authorization, consent, and token
/// routes remain unavailable, so this endpoint is not advertised in metadata.
pub(super) fn registration_response(
    method: &str,
    path: &str,
    content_type: &str,
    origin: &str,
    host: &str,
    body: &str,
) -> Option<HttpResponse> {
    if path.split_once('?').map_or(path, |(path, _)| path) != "/oauth/register" {
        return None;
    }
    if method != "POST" {
        return Some(HttpResponse {
            status: 405,
            headers: vec![
                ("Allow", "POST"),
                ("Content-Type", "text/plain; charset=utf-8"),
            ],
            body: b"Method Not Allowed\n".to_vec(),
        });
    }
    if !origin.is_empty() && !super::http::allowed_origin(origin, host) {
        return Some(HttpResponse {
            status: 403,
            headers: vec![("Content-Type", "application/json")],
            body: b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"invalid Origin header\"}}\n".to_vec(),
        });
    }
    if !super::http::is_json_content_type(content_type) {
        return Some(json_error(400, "invalid_client_metadata"));
    }
    let Ok(request) = serde_json::from_str::<RegistrationRequest>(body) else {
        return Some(json_error(400, "invalid_client_metadata"));
    };
    if request.redirect_uris.is_empty()
        || !request
            .redirect_uris
            .iter()
            .all(|uri| allowed_redirect_uri(uri))
    {
        return Some(json_error(400, "invalid_redirect_uri"));
    }

    let mut id = [0_u8; 16];
    if getrandom::fill(&mut id).is_err() {
        return Some(json_error(500, "server_error"));
    }
    let client_id = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut body = serde_json::to_vec(&serde_json::json!({
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
        "redirect_uris": request.redirect_uris,
    }))
    .expect("registration response is serializable");
    body.push(b'\n');
    Some(HttpResponse {
        status: 201,
        headers: vec![("Content-Type", "application/json")],
        body,
    })
}

fn json_error(status: u16, error: &str) -> HttpResponse {
    let mut body = serde_json::to_vec(&serde_json::json!({ "error": error }))
        .expect("error response is serializable");
    body.push(b'\n');
    HttpResponse {
        status,
        headers: vec![("Content-Type", "application/json")],
        body,
    }
}

fn allowed_redirect_uri(value: &str) -> bool {
    if value.is_empty()
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || invalid_percent_escape(value)
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        || value
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return false;
    }
    if scheme == "http" || scheme == "https" {
        let Some(authority) = remainder.strip_prefix("//") else {
            return false;
        };
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return false;
        }
        let hostname = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some((host, tail)) = bracketed.split_once(']') else {
                return false;
            };
            if !tail.is_empty()
                && !tail.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
            {
                return false;
            }
            host
        } else {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)));
            if port.is_some_and(|port| {
                port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                return false;
            }
            host
        };
        matches!(hostname, "localhost" | "127.0.0.1" | "::1")
    } else {
        scheme.starts_with("symvault") || scheme.starts_with("symaira")
    }
}

fn invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}
