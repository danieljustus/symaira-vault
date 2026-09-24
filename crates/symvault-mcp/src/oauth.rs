use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration as StdDuration, Instant},
};

use serde::Deserialize;
use symvault_store::token_registry::{self, NewToken};
use time::{Duration, OffsetDateTime};

use crate::http::HttpResponse;

const AUTH_CODE_TTL: Duration = Duration::minutes(5);
const ACCESS_TOKEN_TTL: Duration = Duration::hours(24);
const REFRESH_TOKEN_TTL: Duration = Duration::hours(720);
const MAX_BROWSER_CONSENTS: usize = 256;
const MAX_BROWSER_ATTEMPTS_PER_FLOW: u8 = 5;
const MAX_BROWSER_ATTEMPTS_PER_WINDOW: usize = 10;
const BROWSER_ATTEMPT_WINDOW: StdDuration = StdDuration::from_secs(60);

type ConsentCallback = dyn Fn(&str, &str) -> crate::http::OAuthConsentDecision + Send + Sync;

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
    codes: Mutex<HashMap<String, PendingCode>>,
    browser_consents: Mutex<BrowserConsentState>,
    consent: Box<ConsentCallback>,
    verify_passphrase: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

#[derive(Clone)]
struct BrowserRequest {
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    expires_at: OffsetDateTime,
    attempts: u8,
}

struct BrowserConsentState {
    requests: HashMap<String, BrowserRequest>,
    window_started: Instant,
    attempts_in_window: usize,
}

pub(super) enum OAuthResponse {
    Http(HttpResponse),
    Redirect(String),
}

impl OAuthState {
    pub(super) fn new(
        root: PathBuf,
        agent_name: String,
        consent: Box<ConsentCallback>,
        verify_passphrase: Box<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            root,
            agent_name,
            codes: Mutex::new(HashMap::new()),
            browser_consents: Mutex::new(BrowserConsentState {
                requests: HashMap::new(),
                window_started: Instant::now(),
                attempts_in_window: 0,
            }),
            consent,
            verify_passphrase,
        }
    }
}

/// Handles the Go-backed DCR, authorization-code, PKCE, token, refresh, and
/// authorization-server discovery routes. The caller supplies human consent.
#[allow(clippy::too_many_arguments)] // Mirrors the transport request without allocating a wrapper.
pub(super) fn handle(
    state: &OAuthState,
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
        "/oauth/register"
            | "/mcp/oauth/authorize"
            | "/mcp/oauth/authorize/confirm"
            | "/mcp/oauth/token"
    ) {
        return None;
    }
    if !origin.is_empty() && !super::http::allowed_origin(origin, host) {
        return Some(OAuthResponse::Http(origin_error()));
    }
    match (path, method) {
        ("/oauth/register", "POST") => Some(register(state, content_type, body, now)),
        ("/mcp/oauth/authorize", "GET") => Some(authorize(state, query, now)),
        ("/mcp/oauth/authorize/confirm", "POST") => Some(confirm(state, content_type, body, now)),
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

fn authorize(state: &OAuthState, query: &str, now: OffsetDateTime) -> OAuthResponse {
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
    let decision = (state.consent)(client_id, redirect_uri);
    match decision {
        crate::http::OAuthConsentDecision::Denied => {
            return OAuthResponse::Http(error(403, "access_denied"));
        }
        crate::http::OAuthConsentDecision::Browser => {
            return start_browser_consent(
                state,
                client_id,
                redirect_uri,
                state_value,
                challenge,
                now,
            );
        }
        crate::http::OAuthConsentDecision::Approved => {}
    }
    issue_code(state, client_id, redirect_uri, state_value, challenge, now)
}

fn issue_code(
    state: &OAuthState,
    client_id: &str,
    redirect_uri: &str,
    state_value: &str,
    challenge: &str,
    now: OffsetDateTime,
) -> OAuthResponse {
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_err() {
        return OAuthResponse::Http(error(500, "server_error"));
    }
    let code = encode_hex(&random);
    let Ok(mut codes) = state.codes.lock() else {
        return OAuthResponse::Http(error(500, "server_error"));
    };
    codes.insert(
        code.clone(),
        PendingCode {
            client_id: client_id.to_owned(),
            code_challenge: challenge.to_owned(),
            expires_at: now + AUTH_CODE_TTL,
        },
    );
    OAuthResponse::Redirect(redirect_uri_with_code(redirect_uri, &code, state_value))
}

fn start_browser_consent(
    state: &OAuthState,
    client_id: &str,
    redirect_uri: &str,
    state_value: &str,
    challenge: &str,
    now: OffsetDateTime,
) -> OAuthResponse {
    let mut random = [0_u8; 32];
    if getrandom::fill(&mut random).is_err() {
        return OAuthResponse::Http(error(500, "server_error"));
    }
    let flow_id = encode_hex(&random);
    let request = BrowserRequest {
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        state: state_value.to_owned(),
        code_challenge: challenge.to_owned(),
        expires_at: now + AUTH_CODE_TTL,
        attempts: 0,
    };
    let Ok(mut browser) = state.browser_consents.lock() else {
        return OAuthResponse::Http(error(500, "server_error"));
    };
    browser
        .requests
        .retain(|_, request| request.expires_at >= now);
    if browser.requests.len() >= MAX_BROWSER_CONSENTS {
        return OAuthResponse::Http(error(503, "server_error"));
    }
    browser.requests.insert(flow_id.clone(), request);
    OAuthResponse::Http(html_response(
        200,
        &consent_page(&flow_id, client_id, redirect_uri, &state.agent_name, ""),
    ))
}

fn confirm(
    state: &OAuthState,
    content_type: &str,
    body: &str,
    now: OffsetDateTime,
) -> OAuthResponse {
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return OAuthResponse::Http(error(400, "invalid_request"));
    }
    let Some(parameters) = parse_form(body) else {
        return OAuthResponse::Http(error(400, "invalid_request"));
    };
    let flow_id = parameters.get("flow_id").map_or("", String::as_str);
    let passphrase = parameters.get("passphrase").map_or("", String::as_str);
    let decision = parameters.get("decision").map(String::as_str);
    if decision.is_some_and(|decision| !matches!(decision, "approve" | "deny")) {
        return OAuthResponse::Http(error(400, "invalid_request"));
    }
    let denied = decision == Some("deny");
    let Some(request) = state
        .browser_consents
        .lock()
        .ok()
        .and_then(|browser| browser.requests.get(flow_id).cloned())
        .filter(|request| request.expires_at >= now)
    else {
        return OAuthResponse::Http(error(400, "invalid_request"));
    };
    let client = match token_registry::get_oauth_client(&state.root, &request.client_id, now) {
        Ok(Some(client)) if client.client_id == request.client_id => client,
        _ => return OAuthResponse::Http(error(400, "invalid_client")),
    };
    if !is_allowed_redirect_uri(&request.redirect_uri, &client.redirect_uris) {
        return OAuthResponse::Http(error(400, "invalid_redirect_uri"));
    }
    if denied {
        let Ok(mut browser) = state.browser_consents.lock() else {
            return OAuthResponse::Http(error(500, "server_error"));
        };
        if browser.requests.remove(flow_id).is_none() {
            return OAuthResponse::Http(error(400, "invalid_request"));
        }
        return OAuthResponse::Redirect(redirect_uri_with_error(
            &request.redirect_uri,
            "access_denied",
            &request.state,
        ));
    }
    let Some((request, last_flow_attempt)) = reserve_browser_attempt(state, flow_id, now) else {
        return OAuthResponse::Http(error(429, "slow_down"));
    };
    if !(state.verify_passphrase)(passphrase) {
        if last_flow_attempt {
            if let Ok(mut browser) = state.browser_consents.lock() {
                browser.requests.remove(flow_id);
            }
            return OAuthResponse::Http(error(429, "slow_down"));
        }
        return OAuthResponse::Http(html_response(
            200,
            &consent_page(
                flow_id,
                &request.client_id,
                &request.redirect_uri,
                &state.agent_name,
                "Incorrect passphrase.",
            ),
        ));
    }
    let Ok(mut browser) = state.browser_consents.lock() else {
        return OAuthResponse::Http(error(500, "server_error"));
    };
    if browser.requests.remove(flow_id).is_none() {
        return OAuthResponse::Http(error(400, "invalid_request"));
    }
    issue_code(
        state,
        &request.client_id,
        &request.redirect_uri,
        &request.state,
        &request.code_challenge,
        now,
    )
}

/// Reserve a passphrase verification before running the potentially expensive
/// verifier. The service-wide window is deliberately independent of flow
/// creation, so creating another DCR/authorize flow cannot reset the budget.
fn reserve_browser_attempt(
    state: &OAuthState,
    flow_id: &str,
    now: OffsetDateTime,
) -> Option<(BrowserRequest, bool)> {
    let mut browser = state.browser_consents.lock().ok()?;
    browser
        .requests
        .retain(|_, request| request.expires_at >= now);
    if browser.window_started.elapsed() >= BROWSER_ATTEMPT_WINDOW {
        browser.window_started = Instant::now();
        browser.attempts_in_window = 0;
    }
    if browser.attempts_in_window >= MAX_BROWSER_ATTEMPTS_PER_WINDOW {
        return None;
    }
    let request = browser.requests.get_mut(flow_id)?;
    if request.attempts >= MAX_BROWSER_ATTEMPTS_PER_FLOW {
        browser.requests.remove(flow_id);
        return None;
    }
    request.attempts += 1;
    let last_flow_attempt = request.attempts == MAX_BROWSER_ATTEMPTS_PER_FLOW;
    let request = request.clone();
    browser.attempts_in_window += 1;
    Some((request, last_flow_attempt))
}

fn consent_page(
    flow_id: &str,
    client_id: &str,
    redirect_uri: &str,
    agent_name: &str,
    error_text: &str,
) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Symaira Vault consent</title></head><body><main><h1>Authorize MCP client</h1><p>Client: {}</p><p>Redirect URI: {}</p><p>Agent: {}</p><p>This client requests full access to this agent's tools.</p><p>{}</p><form method=\"POST\" action=\"/mcp/oauth/authorize/confirm\"><input type=\"hidden\" name=\"flow_id\" value=\"{}\"><label>Vault passphrase <input type=\"password\" name=\"passphrase\" autocomplete=\"current-password\" required></label><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\" formnovalidate>Deny</button></form></main></body></html>",
        html_escape(client_id),
        html_escape(redirect_uri),
        html_escape(agent_name),
        html_escape(error_text),
        html_escape(flow_id)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ],
        body: body.as_bytes().to_vec(),
    }
}

fn token(state: &OAuthState, body: &str, now: OffsetDateTime) -> OAuthResponse {
    let Some(parameters) = parse_form(body) else {
        return OAuthResponse::Http(error(400, "invalid_request"));
    };
    match parameters.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some(code) = parameters.get("code") else {
                return OAuthResponse::Http(error(400, "invalid_grant"));
            };
            // Like Go's code store, take before verifier checks: every attempt is single-use.
            let Ok(mut codes) = state.codes.lock() else {
                return OAuthResponse::Http(error(500, "server_error"));
            };
            let Some(pending) = codes.remove(code) else {
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
                Err(_) => OAuthResponse::Http(json_response(
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
    let mut parameters = vec![("code", code)];
    if !state.is_empty() {
        parameters.push(("state", state));
    }
    redirect_uri_with_parameters(uri, &parameters)
}

fn redirect_uri_with_error(uri: &str, error_name: &str, state: &str) -> String {
    let mut parameters = vec![("error", error_name)];
    if !state.is_empty() {
        parameters.push(("state", state));
    }
    redirect_uri_with_parameters(uri, &parameters)
}

fn redirect_uri_with_parameters(uri: &str, parameters: &[(&str, &str)]) -> String {
    let (without_fragment, fragment) = uri
        .split_once('#')
        .map_or((uri, None), |(uri, fragment)| (uri, Some(fragment)));
    let separator = if without_fragment.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut redirected = without_fragment.to_owned();
    for (index, (name, value)) in parameters.iter().enumerate() {
        redirected.push(if index == 0 { separator } else { '&' });
        redirected.push_str(name);
        redirected.push('=');
        redirected.push_str(&form_encode(value));
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
            Box::new(|_, _| crate::http::OAuthConsentDecision::Approved),
            Box::new(|_| false),
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
            Box::new(|_, _| crate::http::OAuthConsentDecision::Denied),
            Box::new(|_| false),
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
        assert!(denied.codes.lock().unwrap().is_empty());

        let mut approved = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| crate::http::OAuthConsentDecision::Approved),
            Box::new(|_| false),
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
    fn browser_consent_requires_the_vault_passphrase_before_issuing_a_code() {
        let directory = tempfile::tempdir().unwrap();
        let state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| crate::http::OAuthConsentDecision::Browser),
            Box::new(|passphrase| passphrase == "approved-passphrase"),
        );
        let client_id = register(&state);
        let authorization = format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}&state=browser-state&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let OAuthResponse::Http(page) =
            authorize(&state, &authorization, OffsetDateTime::now_utc())
        else {
            panic!("daemon authorization should render a consent page");
        };
        assert_eq!(page.status, 200);
        let html = String::from_utf8(page.body).unwrap();
        let flow_id = html
            .split("name=\"flow_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let wrong = confirm(
            &state,
            "application/x-www-form-urlencoded",
            &format!("flow_id={flow_id}&passphrase=wrong"),
            OffsetDateTime::now_utc(),
        );
        assert!(matches!(wrong, OAuthResponse::Http(response) if response.status == 200));
        let approved = confirm(
            &state,
            "application/x-www-form-urlencoded",
            &format!("flow_id={flow_id}&passphrase=approved-passphrase"),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(approved, OAuthResponse::Redirect(location) if location.contains("state=browser-state") && location.contains("code="))
        );
        assert!(!html.contains("approved-passphrase"));
    }

    #[test]
    fn browser_passphrase_budget_survives_new_consent_flows() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let verification_count = std::sync::Arc::new(AtomicUsize::new(0));
        let verifier_count = verification_count.clone();
        let state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| crate::http::OAuthConsentDecision::Browser),
            Box::new(move |_| {
                verifier_count.fetch_add(1, Ordering::SeqCst);
                false
            }),
        );
        let client_id = register(&state);
        let make_flow = || {
            let response = start_browser_consent(
                &state,
                &client_id,
                REDIRECT,
                "state",
                CHALLENGE,
                OffsetDateTime::now_utc(),
            );
            let OAuthResponse::Http(response) = response else {
                panic!("browser flow must render a page");
            };
            let page = String::from_utf8(response.body).unwrap();
            page.split("name=\"flow_id\" value=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_owned()
        };

        for _ in 0..2 {
            let flow_id = make_flow();
            for attempt in 0..MAX_BROWSER_ATTEMPTS_PER_FLOW {
                let response = confirm(
                    &state,
                    "application/x-www-form-urlencoded",
                    &format!("flow_id={flow_id}&passphrase=wrong"),
                    OffsetDateTime::now_utc(),
                );
                let OAuthResponse::Http(response) = response else {
                    panic!("bad passphrase must not redirect");
                };
                assert_eq!(
                    response.status,
                    if attempt + 1 == MAX_BROWSER_ATTEMPTS_PER_FLOW {
                        429
                    } else {
                        200
                    },
                    "each flow permits at most five verifier calls"
                );
            }
        }
        assert_eq!(
            verification_count.load(Ordering::SeqCst),
            MAX_BROWSER_ATTEMPTS_PER_WINDOW
        );

        let new_flow = make_flow();
        let blocked = confirm(
            &state,
            "application/x-www-form-urlencoded",
            &format!("flow_id={new_flow}&passphrase=wrong"),
            OffsetDateTime::now_utc(),
        );
        assert!(matches!(blocked, OAuthResponse::Http(response) if response.status == 429));
        assert_eq!(
            verification_count.load(Ordering::SeqCst),
            MAX_BROWSER_ATTEMPTS_PER_WINDOW,
            "creating a fresh authorization flow cannot reset the global verification budget"
        );
    }

    #[test]
    fn registration_rejects_custom_scheme_userinfo_like_go() {
        let directory = tempfile::tempdir().unwrap();
        let state = OAuthState::new(
            directory.path().to_path_buf(),
            "default".into(),
            Box::new(|_, _| crate::http::OAuthConsentDecision::Approved),
            Box::new(|_| false),
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
            Box::new(|_, _| crate::http::OAuthConsentDecision::Approved),
            Box::new(|_| false),
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
        assert!(state.codes.lock().unwrap().is_empty());
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
