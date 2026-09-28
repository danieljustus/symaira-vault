use std::{collections::HashMap, path::PathBuf};

use serde::Deserialize;
use symvault_store::token_registry::{self, NewToken};
use time::{Duration, OffsetDateTime};

use crate::http::HttpResponse;

const AUTH_CODE_TTL: Duration = Duration::minutes(5);
const ACCESS_TOKEN_TTL: Duration = Duration::hours(24);
const REFRESH_TOKEN_TTL: Duration = Duration::hours(720);

#[derive(Deserialize)]
struct RegistrationRequest {
    #[serde(default)]
    redirect_uris: Option<Vec<String>>,
}

#[derive(Clone)]
struct PendingCode {
    client_id: String,
    code_challenge: String,
    expires_at: OffsetDateTime,
}

pub(super) struct OAuthState {
    root: PathBuf,
    agent_name: String,
    codes: HashMap<String, PendingCode>,
    consent: Box<dyn FnMut(&str, &str) -> bool + Send>,
}

pub(super) enum OAuthResponse {
    Http(HttpResponse),
    Redirect(String),
}

impl OAuthState {
    pub(super) fn new(
        root: PathBuf,
        agent_name: String,
        consent: Box<dyn FnMut(&str, &str) -> bool + Send>,
    ) -> Self {
        Self {
            root,
            agent_name,
            codes: HashMap::new(),
            consent,
        }
    }
}

/// Handles the Go-backed DCR, authorization-code, PKCE, token, refresh, and
/// authorization-server discovery routes. The caller supplies human consent.
pub(super) fn handle(
    state: &mut OAuthState,
    method: &str,
    path_and_query: &str,
    content_type: &str,
    origin: &str,
    host: &str,
    body: &str,
    local: std::net::SocketAddr,
) -> Option<OAuthResponse> {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let now = OffsetDateTime::now_utc();
    if path == "/.well-known/oauth-authorization-server" {
        return Some(if method == "GET" {
            OAuthResponse::Http(discovery_response(local))
        } else {
            OAuthResponse::Http(error(405, "invalid_request"))
        });
    }
    if !matches!(
        path,
        "/oauth/register" | "/mcp/oauth/authorize" | "/mcp/oauth/token"
    ) {
        return None;
    }
    if !origin.is_empty() && !super::http::allowed_origin(origin, host) {
        return Some(OAuthResponse::Http(origin_error()));
    }
    match (path, method) {
        ("/oauth/register", "POST") => Some(register(state, content_type, body, now)),
        ("/mcp/oauth/authorize", "GET") => Some(authorize(state, query, now)),
        ("/mcp/oauth/token", "POST") => Some(token(state, body, now)),
        _ => Some(OAuthResponse::Http(error(405, "invalid_request"))),
    }
}

fn register(
    state: &OAuthState,
    content_type: &str,
    body: &str,
    now: OffsetDateTime,
) -> OAuthResponse {
    let redirects = match validate_registration(content_type, body) {
        Ok(redirects) => redirects,
        Err(error_name) => return OAuthResponse::Http(error(400, error_name)),
    };
    let client = match token_registry::register_oauth_client(&state.root, redirects, now) {
        Ok(client) => client,
        Err(_) => return OAuthResponse::Http(error(500, "server_error")),
    };
    let body = serde_json::json!({
        "client_id": client.client_id,
        "client_id_issued_at": now.unix_timestamp(),
        "client_secret_expires_at": 0,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": client.redirect_uris,
    });
    OAuthResponse::Http(json_response(201, body))
}

fn authorize(state: &mut OAuthState, query: &str, now: OffsetDateTime) -> OAuthResponse {
    let Some(parameters) = parse_form(query) else {
        return OAuthResponse::Http(error(400, "invalid_request"));
    };
    let client_id = parameters.get("client_id").map_or("", String::as_str);
    let redirect_uri = parameters.get("redirect_uri").map_or("", String::as_str);
    let challenge = parameters.get("code_challenge").map_or("", String::as_str);
    let state_value = parameters.get("state").map_or("", String::as_str);
    if parameters.get("response_type").map(String::as_str) != Some("code")
        || client_id.is_empty()
        || redirect_uri.is_empty()
        || challenge.is_empty()
    {
        return OAuthResponse::Http(error(400, "invalid_request"));
    }
    if parameters.get("code_challenge_method").map(String::as_str) != Some("S256") {
        return OAuthResponse::Http(error(400, "invalid_request"));
    }
    if parameters
        .get("scope")
        .is_some_and(|requested| !requested.is_empty())
    {
        return OAuthResponse::Http(error(400, "invalid_scope"));
    }
    let client = match token_registry::get_oauth_client(&state.root, client_id, now) {
        Ok(Some(client)) => client,
        Ok(None) | Err(_) => return OAuthResponse::Http(error(400, "invalid_client")),
    };
    if client.client_id != client_id || !valid_client_id(client_id) {
        return OAuthResponse::Http(error(400, "invalid_client"));
    }
    if !is_allowed_redirect_uri(redirect_uri, &client.redirect_uris) {
        return OAuthResponse::Http(error(400, "invalid_redirect_uri"));
    }
    if !(state.consent)(client_id, redirect_uri) {
        return OAuthResponse::Http(error(403, "access_denied"));
    }
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_err() {
        return OAuthResponse::Http(error(500, "server_error"));
    }
    let code = encode_hex(&random);
    state.codes.insert(
        code.clone(),
        PendingCode {
            client_id: client_id.to_owned(),
            code_challenge: challenge.to_owned(),
            expires_at: now + AUTH_CODE_TTL,
        },
    );
    OAuthResponse::Redirect(redirect_uri_with_code(redirect_uri, &code, state_value))
}

fn token(state: &mut OAuthState, body: &str, now: OffsetDateTime) -> OAuthResponse {
    let Some(parameters) = parse_form(body) else {
        return OAuthResponse::Http(error(400, "invalid_request"));
    };
    match parameters.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some(code) = parameters.get("code") else {
                return OAuthResponse::Http(error(400, "invalid_grant"));
            };
            // Like Go's code store, take before verifier checks: every attempt is single-use.
            let Some(pending) = state.codes.remove(code) else {
                return OAuthResponse::Http(error(400, "invalid_grant"));
            };
            if now > pending.expires_at
                || !parameters.get("code_verifier").is_some_and(|verifier| {
                    token_registry::verify_s256_code_verifier(verifier, &pending.code_challenge)
                })
            {
                return OAuthResponse::Http(error(400, "invalid_grant"));
            }
            let label = format!("oauth-{}", &pending.client_id[..8]);
            let new = NewToken {
                label: &label,
                allowed_tools: vec!["*".into()],
                agent_name: &state.agent_name,
                ttl: Some(ACCESS_TOKEN_TTL),
                tool_registry_hash: "",
            };
            match token_registry::create_with_refresh(
                &state.root,
                &new,
                Some(REFRESH_TOKEN_TTL),
                now,
            ) {
                Ok((record, access, refresh)) => {
                    OAuthResponse::Http(token_response(&record, access, refresh, now))
                }
                Err(_) => OAuthResponse::Http(error(500, "server_error")),
            }
        }
        Some("refresh_token") => {
            let Some(refresh) = parameters.get("refresh_token") else {
                return OAuthResponse::Http(error(400, "invalid_request"));
            };
            match token_registry::rotate_via_refresh_token_with_access_ttl(
                &state.root,
                refresh,
                ACCESS_TOKEN_TTL,
                now,
            ) {
                Ok((record, access, refresh)) => {
                    OAuthResponse::Http(token_response(&record, access, refresh, now))
                }
                Err(_) => OAuthResponse::Http(json_error(
                    400,
                    serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "invalid or expired refresh token",
                    }),
                )),
            }
        }
        _ => OAuthResponse::Http(error(400, "unsupported_grant_type")),
    }
}

fn token_response(
    token: &token_registry::TokenRecord,
    access: String,
    refresh: String,
    now: OffsetDateTime,
) -> HttpResponse {
    let expires_in = token
        .expires_at
        .as_deref()
        .and_then(|value| {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        })
        .map_or(0, |expires_at| (expires_at - now).whole_seconds().max(0));
    json_response(
        200,
        serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh,
        }),
    )
}

fn validate_registration(content_type: &str, body: &str) -> Result<Vec<String>, &'static str> {
    if !super::http::is_json_content_type(content_type) {
        return Err("invalid_client_metadata");
    }
    let mut decoder = serde_json::Deserializer::from_str(body);
    let request =
        RegistrationRequest::deserialize(&mut decoder).map_err(|_| "invalid_client_metadata")?;
    let redirect_uris = request.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() || !redirect_uris.iter().all(|uri| allowed_redirect_uri(uri)) {
        return Err("invalid_redirect_uri");
    }
    Ok(redirect_uris)
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
    if let Some(authority) = remainder.strip_prefix("//") {
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') {
            return false;
        }
    }
    if scheme == "http" || scheme == "https" {
        let Some(authority) = remainder.strip_prefix("//") else {
            return false;
        };
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some((host, suffix)) = bracketed.split_once(']') else {
                return false;
            };
            if !valid_port_suffix(suffix) {
                return false;
            }
            host
        } else {
            let (host, suffix) = authority
                .split_once(':')
                .map_or((authority, ""), |(host, suffix)| (host, suffix));
            if suffix.contains(':') || (!suffix.is_empty() && !valid_port_number(suffix)) {
                return false;
            }
            host
        };
        matches!(host, "localhost" | "127.0.0.1" | "::1")
    } else {
        scheme.starts_with("symvault") || scheme.starts_with("symaira")
    }
}

fn valid_port_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let Some(port) = suffix.strip_prefix(':') else {
        return false;
    };
    valid_port_number(port)
}

fn valid_port_number(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn is_allowed_redirect_uri(uri: &str, allowed: &[String]) -> bool {
    let normalized = uri.strip_suffix('/').unwrap_or(uri);
    allowed
        .iter()
        .any(|candidate| candidate.strip_suffix('/').unwrap_or(candidate) == normalized)
}

fn valid_client_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn discovery_response(local: std::net::SocketAddr) -> HttpResponse {
    let issuer = format!("http://{local}");
    json_response(
        200,
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/mcp/oauth/authorize"),
            "token_endpoint": format!("{issuer}/mcp/oauth/token"),
            "registration_endpoint": format!("{issuer}/oauth/register"),
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        }),
    )
}

fn origin_error() -> HttpResponse {
    json_response(
        403,
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "invalid Origin header"},
        }),
    )
}

fn error(status: u16, message: &str) -> HttpResponse {
    json_response(status, serde_json::json!({ "error": message }))
}

fn json_response(status: u16, body: serde_json::Value) -> HttpResponse {
    let mut body = serde_json::to_vec(&body).expect("JSON values serialize");
    body.push(b'\n');
    HttpResponse {
        status,
        headers: vec![("Content-Type", "application/json")],
        body,
    }
}

fn parse_form(value: &str) -> Option<HashMap<String, String>> {
    let mut fields = HashMap::new();
    for pair in value.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = form_decode(key)?;
        let value = form_decode(value)?;
        fields.entry(key).or_insert(value);
    }
    Some(fields)
}

fn form_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                decoded.push((hex_value(high)? << 4) | hex_value(low)?);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn form_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*') {
            encoded.push(char::from(byte));
        } else if byte == b' ' {
            encoded.push('+');
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn redirect_uri_with_code(uri: &str, code: &str, state: &str) -> String {
    let (without_fragment, fragment) = uri
        .split_once('#')
        .map_or((uri, None), |(uri, fragment)| (uri, Some(fragment)));
    let separator = if without_fragment.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut redirected = format!("{without_fragment}{separator}code={}", form_encode(code));
    if !state.is_empty() {
        redirected.push_str("&state=");
        redirected.push_str(&form_encode(state));
    }
    if let Some(fragment) = fragment {
        redirected.push('#');
        redirected.push_str(fragment);
    }
    redirected
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const REDIRECT: &str = "http://localhost/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn register(state: &OAuthState) -> String {
        let response = super::register(
            state,
            "application/json",
            r#"{"redirect_uris":["http://localhost/callback"]}"#,
            OffsetDateTime::now_utc(),
        );
        let OAuthResponse::Http(response) = response else {
            panic!("registration must return JSON");
        };
        assert_eq!(response.status, 201);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        body["client_id"].as_str().unwrap().to_owned()
    }

    fn response_body(response: OAuthResponse) -> (u16, serde_json::Value) {
        let OAuthResponse::Http(response) = response else {
            panic!("expected JSON response");
        };
        (
            response.status,
            serde_json::from_slice(&response.body).unwrap(),
        )
    }

    #[test]
    fn consent_pkce_access_and_refresh_are_connected_and_single_use() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| true),
        );
        let client_id = register(&state);
        let authorization = format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}&state=st-1&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let OAuthResponse::Redirect(location) =
            authorize(&mut state, &authorization, OffsetDateTime::now_utc())
        else {
            panic!("approved request must redirect");
        };
        let code = parse_form(location.split_once('?').unwrap().1)
            .unwrap()
            .remove("code")
            .unwrap();

        let token_request =
            format!("grant_type=authorization_code&code={code}&code_verifier={VERIFIER}");
        let (status, token_body) =
            response_body(token(&mut state, &token_request, OffsetDateTime::now_utc()));
        assert_eq!(status, 200);
        let access = token_body["access_token"].as_str().unwrap();
        let refresh = token_body["refresh_token"].as_str().unwrap();
        let registry =
            fs::read_to_string(directory.path().join(token_registry::TOKEN_REGISTRY_FILE)).unwrap();
        assert!(!registry.contains(access));
        assert!(!registry.contains(refresh));
        let registry: serde_json::Value = serde_json::from_str(&registry).unwrap();
        let access_hash = symvault_store::sha256_hex(access.as_bytes());
        assert_eq!(
            registry["tokens"][access_hash.as_str()]["agent_name"],
            "default"
        );
        assert_eq!(
            registry["tokens"][access_hash.as_str()]["allowed_tools"],
            serde_json::json!(["*"])
        );

        assert_eq!(
            response_body(token(&mut state, &token_request, OffsetDateTime::now_utc(),)).0,
            400,
            "authorization codes are single use"
        );

        let refresh_request = format!("grant_type=refresh_token&refresh_token={refresh}");
        let (status, rotated) = response_body(token(
            &mut state,
            &refresh_request,
            OffsetDateTime::now_utc(),
        ));
        assert_eq!(status, 200);
        assert_ne!(rotated["access_token"].as_str(), Some(access));
        assert_ne!(rotated["refresh_token"].as_str(), Some(refresh));
        assert_eq!(
            response_body(token(
                &mut state,
                &refresh_request,
                OffsetDateTime::now_utc(),
            ))
            .0,
            400,
            "refresh tokens are single use"
        );
    }

    #[test]
    fn consent_denial_and_failed_pkce_never_mint_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let mut denied = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| false),
        );
        let client_id = register(&denied);
        let authorization = format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        assert_eq!(
            response_body(authorize(
                &mut denied,
                &authorization,
                OffsetDateTime::now_utc(),
            ))
            .0,
            403
        );
        assert!(denied.codes.is_empty());

        let mut approved = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| true),
        );
        let OAuthResponse::Redirect(location) =
            authorize(&mut approved, &authorization, OffsetDateTime::now_utc())
        else {
            panic!("approved request must redirect");
        };
        let code = parse_form(location.split_once('?').unwrap().1)
            .unwrap()
            .remove("code")
            .unwrap();
        assert_eq!(
            response_body(token(
                &mut approved,
                &format!("grant_type=authorization_code&code={code}&code_verifier=wrong"),
                OffsetDateTime::now_utc(),
            ))
            .0,
            400
        );
        assert!(
            fs::read_to_string(directory.path().join(token_registry::TOKEN_REGISTRY_FILE)).is_err()
        );
    }

    #[test]
    fn registration_rejects_custom_scheme_userinfo_like_go() {
        let directory = tempfile::tempdir().unwrap();
        let state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| true),
        );
        let response = super::register(
            &state,
            "application/json",
            r#"{"redirect_uris":["symvault://user@vault/callback"]}"#,
            OffsetDateTime::now_utc(),
        );
        assert_eq!(response_body(response).0, 400);
    }

    #[test]
    fn authorization_rejects_unimplemented_scope_requests() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| true),
        );
        let client_id = register(&state);
        let authorization = format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}&code_challenge={CHALLENGE}&code_challenge_method=S256&scope=read"
        );
        assert_eq!(
            response_body(authorize(
                &mut state,
                &authorization,
                OffsetDateTime::now_utc(),
            ))
            .0,
            400
        );
        assert!(state.codes.is_empty());
    }

    #[test]
    fn redirect_validation_matches_go_loopback_and_userinfo_boundaries() {
        for uri in [
            "http://user@localhost/callback",
            "symvault://user@vault/callback",
            "https://example.com/callback",
            "http://localhost:abc/callback",
            "http://localhost:65536/callback",
        ] {
            let body = format!("{{\"redirect_uris\":[\"{uri}\"]}}");
            assert!(
                validate_registration("application/json", &body).is_err(),
                "{uri}"
            );
        }
        for uri in [
            "http://localhost:8080/callback",
            "https://127.0.0.1/callback",
            "http://[::1]:9000/callback",
            "symvault:callback",
        ] {
            let body = format!("{{\"redirect_uris\":[\"{uri}\"]}}");
            assert!(
                validate_registration("application/json", &body).is_ok(),
                "{uri}"
            );
        }
    }

    #[test]
    fn registration_metadata_errors_match_go_handler_cases() {
        assert_eq!(
            validate_registration("application/json", "not json"),
            Err("invalid_client_metadata")
        );
        assert_eq!(
            validate_registration("application/json", "{}"),
            Err("invalid_redirect_uri")
        );
        assert_eq!(
            validate_registration("application/json", r#"{"redirect_uris":null}"#),
            Err("invalid_redirect_uri")
        );
        assert_eq!(
            validate_registration("application/json", r#"{"redirect_uris":[]}"#),
            Err("invalid_redirect_uri")
        );
        assert_eq!(
            validate_registration("text/plain", r#"{"redirect_uris":["http://localhost/cb"]}"#),
            Err("invalid_client_metadata")
        );
    }
}
