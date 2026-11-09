//! ADR 0037 R16 (HTTP-003): replay of the Go OAuth expiry-boundary recording
//! `testdata/port/mcp/http-oauth-expiry.json` (captured from
//! `legacy/go-oracle`, generator `scripts/rust-port/http_oauth_expiry_record.go.txt`).
//!
//! Go has no clock injection here (`time.Now().After(expiry)`), so the
//! recording holds "before"/"after" observations taken with a 400 ms TTL
//! (immediately and after 900 ms) or one-hour offsets. Rust takes an injected
//! `now`, so each recorded position is replayed at `expiry - 1 ms` and
//! `expiry + 1 ms`, and the response is compared with the recorded one. The
//! access-token leg crosses the HTTP middleware and lives in `http.rs`.
//!
//! Rust-only, deliberately not Go's: see the two `*_at_the_deadline` tests.

use std::fs;

use symvault_store::token_registry::{self, NewToken};
use time::{Duration, OffsetDateTime};

use super::*;

const RECORDING: &str = include_str!("../../../../testdata/port/mcp/http-oauth-expiry.json");
const REDIRECT_URI: &str = "http://localhost/callback";

fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn recorded(id: &str) -> serde_json::Value {
    let doc: serde_json::Value = serde_json::from_str(RECORDING).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("recording has no case {id}"))
        .clone()
}

/// Same normalisation as the Go generator: token strings become shape records.
fn normalise(mut body: serde_json::Value) -> serde_json::Value {
    for key in ["access_token", "refresh_token"] {
        if let Some(value) = body.get(key).and_then(|v| v.as_str()) {
            assert!(
                value.bytes().all(|b| b.is_ascii_hexdigit()),
                "{key} is not hex"
            );
            body[key] = serde_json::json!({"shape": "hex", "len": value.len()});
        }
    }
    body
}

fn http_body(
    response: OAuthResponse,
) -> (u16, serde_json::Value, Vec<(&'static str, &'static str)>) {
    let OAuthResponse::Http(response) = response else {
        panic!("expected an HTTP response");
    };
    let body = serde_json::from_slice(&response.body).unwrap_or_default();
    (response.status, normalise(body), response.headers)
}

/// Compares status, content type and body with the recorded Go case. `expires_in`
/// is compared as "within one second below the TTL" because Go floors a
/// wall-clock remainder (3599) where the injected clock gives the exact TTL.
fn assert_matches_go(id: &str, got: (u16, serde_json::Value, Vec<(&'static str, &'static str)>)) {
    let go = recorded(id);
    assert_eq!(u64::from(got.0), go["status"].as_u64().unwrap(), "{id}");
    let content_type = got
        .2
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| *value);
    assert_eq!(content_type, go["headers"]["content_type"].as_str(), "{id}");
    let mut body = got.1;
    let mut want = go["body"].clone();
    if want.get("expires_in").is_some() {
        let go_expires = want["expires_in"].as_i64().unwrap();
        let rust_expires = body["expires_in"].as_i64().unwrap();
        assert!(
            (go_expires..=go_expires + 1).contains(&rust_expires),
            "{id}: expires_in go={go_expires} rust={rust_expires}"
        );
        body["expires_in"] = serde_json::Value::Null;
        want["expires_in"] = serde_json::Value::Null;
    }
    assert_eq!(body, want, "{id}");
}

fn make_state(
    directory: &std::path::Path,
    consent: crate::http::OAuthConsentDecision,
) -> OAuthState {
    OAuthState::new(
        directory.to_path_buf(),
        "oauth".into(),
        Box::new(move |_, _| match consent {
            crate::http::OAuthConsentDecision::Approved => {
                crate::http::OAuthConsentDecision::Approved
            }
            _ => crate::http::OAuthConsentDecision::Browser,
        }),
        Box::new(|_| false),
    )
    .with_token_ttls(crate::http::OAuthTokenTtls {
        access_token_ttl: std::time::Duration::from_secs(3600),
        refresh_token_ttl: std::time::Duration::from_secs(24 * 3600),
    })
    .unwrap()
}

fn register_at(state: &OAuthState, at: OffsetDateTime) -> String {
    let (status, body, _) = http_body(super::register(
        state,
        "application/json",
        r#"{"redirect_uris":["http://localhost/callback"]}"#,
        at,
    ));
    assert_eq!(status, 201);
    body["client_id"].as_str().unwrap().to_owned()
}

fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=s"
    )
}

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn issue_code(state: &OAuthState, at: OffsetDateTime) -> String {
    let client_id = register_at(state, at);
    let OAuthResponse::Redirect(location) = authorize(state, &authorize_query(&client_id), at)
    else {
        panic!("approved request must redirect");
    };
    parse_form(location.split_once('?').unwrap().1)
        .unwrap()
        .remove("code")
        .unwrap()
}

fn exchange(state: &OAuthState, code: &str, at: OffsetDateTime) -> OAuthResponse {
    token(
        state,
        &format!("grant_type=authorization_code&code={code}&code_verifier={VERIFIER}"),
        at,
    )
}

fn registry_json(root: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(root.join(token_registry::TOKEN_REGISTRY_FILE)).unwrap())
        .unwrap()
}

#[test]
fn authorization_code_expiry_matches_the_go_recording() {
    let ttl = recorded("code-issuer-ttl");
    assert_eq!(
        ttl["notes"]["ttl_seconds_rounded"].as_i64().unwrap(),
        AUTH_CODE_TTL.whole_seconds()
    );
    let before = AUTH_CODE_TTL - Duration::milliseconds(1);
    let after = AUTH_CODE_TTL + Duration::milliseconds(1);
    for (id, offset) in [
        ("code-valid-long", before),
        ("code-short-immediate", before),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let state = make_state(
            directory.path(),
            crate::http::OAuthConsentDecision::Approved,
        );
        let code = issue_code(&state, t0());
        assert_matches_go(id, http_body(exchange(&state, &code, t0() + offset)));
    }
    for (id, offset) in [
        ("code-short-after-wait", after),
        (
            "code-expired-by-1ns",
            AUTH_CODE_TTL + Duration::nanoseconds(1),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let state = make_state(
            directory.path(),
            crate::http::OAuthConsentDecision::Approved,
        );
        let code = issue_code(&state, t0());
        assert_matches_go(id, http_body(exchange(&state, &code, t0() + offset)));
        let go = recorded(id);
        if id == "code-short-after-wait" {
            // The failed attempt consumed the code and minted nothing.
            assert_eq!(go["notes"]["tokens_minted"], 0);
            assert!(
                !directory
                    .path()
                    .join(token_registry::TOKEN_REGISTRY_FILE)
                    .exists()
            );
            let replay = http_body(exchange(&state, &code, t0()));
            assert_eq!(u64::from(replay.0), go["notes"]["replay_status"]);
            assert_eq!(replay.1, go["notes"]["replay_body"]);
        }
    }
}

fn create_pair(
    root: &std::path::Path,
    access: Option<Duration>,
    refresh: Option<Duration>,
) -> (token_registry::TokenRecord, String) {
    let new = NewToken {
        label: "oauth-0123456789abcdef",
        allowed_tools: vec!["*".into()],
        agent_name: "oauth",
        ttl: access,
        tool_registry_hash: "r16",
    };
    let (record, _, raw_refresh) =
        token_registry::create_with_refresh(root, &new, refresh, t0()).unwrap();
    (record, raw_refresh)
}

fn refresh_at(state: &OAuthState, raw: &str, at: OffsetDateTime) -> OAuthResponse {
    token(
        state,
        &format!("grant_type=refresh_token&refresh_token={raw}"),
        at,
    )
}

fn parse(value: &serde_json::Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        value.as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

#[test]
fn refresh_token_expiry_matches_the_go_recording() {
    // before: 400 ms refresh deadline observed 1 ms ahead of it.
    let directory = tempfile::tempdir().unwrap();
    let state = make_state(
        directory.path(),
        crate::http::OAuthConsentDecision::Approved,
    );
    let (old, raw) = create_pair(
        directory.path(),
        Some(Duration::hours(1)),
        Some(Duration::milliseconds(400)),
    );
    let go = recorded("refresh-short-immediate");
    assert_matches_go(
        "refresh-short-immediate",
        http_body(refresh_at(&state, &raw, t0() + Duration::milliseconds(399))),
    );
    let registry = registry_json(directory.path());
    let tokens = registry["tokens"].as_object().unwrap();
    let live: Vec<_> = tokens.values().filter(|t| t["revoked"] != true).collect();
    assert_eq!(live.len(), 1);
    assert_eq!(go["notes"]["old_pair_revoked"], true);
    assert_eq!(tokens[&old.id]["revoked"], true);
    // Deadlines survive rotation (Go notes: preserved within 50 ms).
    for key in ["refresh_expires_at", "expires_at"] {
        let drift = parse(&live[0][key]) - parse(&tokens[&old.id][key]);
        assert!(drift.abs() < Duration::milliseconds(50), "{key}: {drift}");
    }
    assert_eq!(go["notes"]["refresh_deadline_preserved_within_50ms"], true);
    assert_eq!(go["notes"]["access_deadline_preserved_within_50ms"], true);

    // after
    let directory = tempfile::tempdir().unwrap();
    let state = state_for(directory.path());
    let (_, raw) = create_pair(
        directory.path(),
        Some(Duration::hours(1)),
        Some(Duration::milliseconds(400)),
    );
    assert_matches_go(
        "refresh-short-after-wait",
        http_body(refresh_at(&state, &raw, t0() + Duration::milliseconds(401))),
    );
    let _ = raw;

    // refresh without a deadline never expires; the rotated pair has none either
    let directory = tempfile::tempdir().unwrap();
    let state = state_for(directory.path());
    let (_, raw) = create_pair(directory.path(), Some(Duration::hours(1)), None);
    assert_matches_go(
        "refresh-no-ttl-never-expires",
        http_body(refresh_at(&state, &raw, t0() + Duration::days(3650))),
    );
    let tokens = registry_json(directory.path());
    let rotated = tokens["tokens"]
        .as_object()
        .unwrap()
        .values()
        .find(|t| t["revoked"] != true)
        .unwrap();
    assert_eq!(
        recorded("refresh-no-ttl-never-expires")["notes"]["rotated_refresh_expires_at_is_null"],
        true
    );
    assert!(
        rotated
            .get("refresh_expires_at")
            .is_none_or(|v| v.is_null())
    );
}

fn state_for(directory: &std::path::Path) -> OAuthState {
    make_state(directory, crate::http::OAuthConsentDecision::Approved)
}

/// ADR 0019: Go rejects a refresh once the access token has expired
/// (`getByRefreshTokenHash` demands `!IsExpired()`), even though the refresh
/// token is still valid; Rust renews with the configured finite access TTL and
/// keeps the original refresh deadline. The Go answer is pinned in the
/// recording, the Rust answer here.
#[test]
fn refresh_after_access_expiry_is_the_adr_0019_divergence() {
    let go = recorded("refresh-valid-but-access-expired");
    assert_eq!(go["status"], 400);
    assert_eq!(
        go["body"],
        serde_json::json!({"error": "invalid_grant", "error_description": "invalid or expired refresh token"})
    );
    let directory = tempfile::tempdir().unwrap();
    let state = state_for(directory.path());
    let (old, raw) = create_pair(
        directory.path(),
        Some(Duration::milliseconds(400)),
        Some(Duration::hours(1)),
    );
    let at = t0() + Duration::milliseconds(900);
    let (status, body, _) = http_body(refresh_at(&state, &raw, at));
    assert_eq!(status, 200, "{body}");
    let tokens = registry_json(directory.path());
    let tokens = tokens["tokens"].as_object().unwrap();
    let rotated = tokens.values().find(|t| t["revoked"] != true).unwrap();
    assert_eq!(parse(&rotated["expires_at"]), at + Duration::hours(1));
    assert_eq!(
        parse(&rotated["refresh_expires_at"]),
        parse(&tokens[&old.id]["refresh_expires_at"])
    );
}

/// Go accepts a refresh at exactly its deadline (`After` is strict) and then
/// computes `refreshTTL = Until(deadline) = 0`, i.e. a replacement pair whose
/// refresh token never expires. Rust refuses at the deadline instead
/// (`now >= expiry`): security-motivated, the instant is unreachable on Go's
/// wall clock and is not part of the recording.
#[test]
fn refresh_at_exactly_the_deadline_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let state = state_for(directory.path());
    let (_, raw) = create_pair(
        directory.path(),
        Some(Duration::hours(1)),
        Some(Duration::milliseconds(400)),
    );
    let (status, body, _) = http_body(refresh_at(&state, &raw, t0() + Duration::milliseconds(400)));
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

fn set_expiry(
    root: &std::path::Path,
    client_id: &str,
    expires_at: OffsetDateTime,
    ttl: Option<i64>,
) {
    let path = root.join(token_registry::OAUTH_CLIENTS_FILE);
    let mut file: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let client = file["clients"][client_id].as_object_mut().unwrap();
    client.insert(
        "expires_at".into(),
        expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
            .into(),
    );
    if let Some(ttl) = ttl {
        client.insert("ttl_seconds".into(), ttl.into());
    }
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
}

fn consent_or_error(response: OAuthResponse) -> serde_json::Value {
    let OAuthResponse::Http(response) = response else {
        return serde_json::json!({"consent_page": false, "redirect": true});
    };
    if response
        .headers
        .contains(&("Content-Type", "text/html; charset=utf-8"))
    {
        return serde_json::json!({"consent_page": String::from_utf8_lossy(&response.body)
            .contains("Authorize MCP client"), "status": response.status});
    }
    let www = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
        .map(|(_, value)| (*value).to_owned());
    serde_json::json!({
        "status": response.status,
        "body": serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
        "www_authenticate": www,
    })
}

fn assert_dcr(id: &str, got: serde_json::Value) {
    let go = recorded(id);
    if go["status"] == 200 {
        // Go renders its consent page without a TTY; Rust's browser flow renders
        // its own (ADR 0019): the class is "request passed the client check".
        assert_eq!(got["consent_page"], true, "{id}: {got}");
        assert_eq!(go["body"]["consent_page"], true, "{id}");
    } else {
        assert_eq!(got["status"], go["status"], "{id}");
        assert_eq!(got["body"], go["body"], "{id}");
        assert_eq!(
            got["www_authenticate"].as_str(),
            go["headers"]["www_authenticate"].as_str(),
            "{id}"
        );
    }
}

#[test]
fn dcr_client_expiry_matches_the_go_recording() {
    let browser = crate::http::OAuthConsentDecision::Browser;
    for (id, expires_at, ttl, at) in [
        (
            "dcr-persisted-expires-in-future",
            t0() + Duration::hours(1),
            None,
            t0(),
        ),
        (
            "dcr-persisted-expires-in-past",
            t0() - Duration::hours(1),
            None,
            t0(),
        ),
        (
            "dcr-short-immediate",
            t0() + Duration::milliseconds(400),
            None,
            t0() + Duration::milliseconds(399),
        ),
        (
            "dcr-short-after-wait",
            t0() + Duration::milliseconds(400),
            None,
            t0() + Duration::milliseconds(401),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let state = make_state(directory.path(), browser);
        let client_id = register_at(&state, t0() - Duration::days(1));
        set_expiry(directory.path(), &client_id, expires_at, ttl);
        assert_dcr(
            id,
            consent_or_error(authorize(&state, &authorize_query(&client_id), at)),
        );
    }

    // `ttl_seconds` is metadata: without `expires_at` the client never expires.
    let directory = tempfile::tempdir().unwrap();
    let state = make_state(directory.path(), browser);
    let client_id = register_at(&state, t0());
    let path = directory.path().join(token_registry::OAUTH_CLIENTS_FILE);
    let mut file: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    file["clients"][&client_id]["ttl_seconds"] = 1.into();
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert_dcr(
        "dcr-ttl-seconds-without-expires-at",
        consent_or_error(authorize(
            &state,
            &authorize_query(&client_id),
            t0() + Duration::days(3650),
        )),
    );
}

#[test]
fn dcr_registration_stores_no_expiry_like_go() {
    let go = recorded("dcr-register-stores-no-expiry");
    let directory = tempfile::tempdir().unwrap();
    let state = state_for(directory.path());
    let (status, body, _) = http_body(super::register(
        &state,
        "application/json",
        r#"{"redirect_uris":["http://localhost/callback"]}"#,
        t0(),
    ));
    assert_eq!(u64::from(status), go["status"].as_u64().unwrap());
    assert_eq!(
        body["client_secret_expires_at"],
        go["notes"]["client_secret_expires_at"]
    );
    let file: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.path().join(token_registry::OAUTH_CLIENTS_FILE)).unwrap(),
    )
    .unwrap();
    let client = file["clients"][body["client_id"].as_str().unwrap()]
        .as_object()
        .unwrap();
    let mut keys: Vec<&str> = client.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let want: Vec<&str> = go["notes"]["stored_client_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(keys, want);
}

/// Negative control: the recording really carries every boundary, so a
/// truncated or re-labelled file cannot make the replay vacuous.
#[test]
fn recording_covers_all_four_boundaries() {
    let doc: serde_json::Value = serde_json::from_str(RECORDING).unwrap();
    assert_eq!(
        doc["oracle_commit"],
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for boundary in [
        "authorization_code",
        "access_token",
        "refresh_token",
        "dcr_client",
    ] {
        for position in ["before", "after"] {
            assert!(
                cases
                    .iter()
                    .any(|c| c["boundary"] == boundary && c["position"] == position),
                "{boundary}/{position} missing"
            );
        }
    }
}
