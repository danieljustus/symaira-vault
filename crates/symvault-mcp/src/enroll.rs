//! Go's server-side device enrollment routes (`internal/approval/enroll.go`),
//! mounted by `serverbootstrap` beside the approval transports:
//!
//! * `POST /api/v1/devices/enroll-code` mints a short-lived, single-use
//!   pairing code. Loopback peers only, and only with a proof of vault
//!   directory ownership (HMAC over the request timestamp, keyed by the
//!   vault's enroll secret); `symvault device approval-pair` is the client.
//! * `POST /api/v1/devices/enroll` exchanges such a code for a long-lived
//!   device-session bearer token (the approval devices' credential). It is
//!   reachable from the LAN like the approval API.
//!
//! Both are exact-path mux entries behind the shared per-client rate limiter.
//! Any other method answers the mux's generic 404 *before* authentication, so
//! the handlers return `None` for it and the caller's 404 applies.
//!
//! Security properties held here, each pinned by a test:
//!
//! * a code is single use and expires after [`PAIRING_CODE_TTL`]; five failed
//!   redemptions anywhere put every redemption, valid or not, into a 30 s
//!   cooldown ([`symvault_sync::TokenStore`], Go's `pairing.TokenStore`);
//! * the vault-ownership proof is an HMAC verified with the MAC's constant
//!   time comparison, and an unparsable header, stale clock or wrong key is
//!   the same 401;
//! * only the SHA-256 of the issued bearer token is persisted; codes, tokens
//!   and the enroll secret are never logged or echoed in an error.
//!
//! Declared differences (all stricter than Go, none more permissive):
//! request bodies above 1 MiB, non-UTF-8 bodies and JSON nested deeper than
//! the parser's recursion limit are refused before or by the parser, where Go
//! would read the first value of an unbounded body.

use crate::approval::{ApprovalResponse, error_json, hex, json_line, verify_proof};
use serde::Serialize;
use serde::de::{Deserializer as _, IgnoredAny, MapAccess, Visitor};
use std::{
    fmt,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use symvault_sync::{DeviceSessionStore, GoTime, TokenStore, generate_token};
use time::OffsetDateTime;

/// Go's `approval.PathDeviceEnrollCode`.
pub const PATH_ENROLL_CODE: &str = "/api/v1/devices/enroll-code";
/// Go's `approval.PathDeviceEnroll`.
pub const PATH_ENROLL: &str = "/api/v1/devices/enroll";

/// Go's `pairing.TokenTTL`.
pub const PAIRING_CODE_TTL: Duration = Duration::from_secs(5 * 60);

/// Go's `pairing.DefaultSessionTTL`, the lifetime reported by an enrolment.
const SESSION_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Whether `path` (query stripped) is one of the two enrollment routes: Go
/// registers both as exact mux patterns, so neither has a subtree.
pub(crate) fn is_enroll_route(path: &str) -> bool {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    path == PATH_ENROLL_CODE || path == PATH_ENROLL
}

/// The shared pairing-code store of one serve process (Go's
/// `cmd/mcp.EnrollCodes`, a `pairing.TokenStore`). Time is monotonic.
pub struct PairingCodes {
    epoch: Instant,
    ttl: Duration,
    store: Mutex<TokenStore>,
}

impl Default for PairingCodes {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingCodes {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(PAIRING_CODE_TTL)
    }

    /// A store whose codes live for `ttl` (Go assigns `pairing.TokenTTL` for
    /// the same purpose in its tests).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            epoch: Instant::now(),
            ttl,
            store: Mutex::new(TokenStore::new(
                i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX),
            )),
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn now_ms(&self) -> i64 {
        i64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// Mints and stores a fresh code (32 characters of `0-9A-V`, 160 bits).
    ///
    /// # Errors
    /// When the system random source fails or the store lock is poisoned.
    pub fn mint(&self) -> Result<String, MintError> {
        let code = generate_token().map_err(|_| MintError::Generate)?;
        let now = self.now_ms();
        let mut store = self.store.lock().map_err(|_| MintError::Store)?;
        // Dropping expired codes is unobservable: an expired code and an
        // unknown one are the same failed attempt.
        store.cleanup_expired(now);
        store.store(&code, "", now);
        Ok(code)
    }

    /// Consumes `code` when it is live. A miss, an expired code and any
    /// attempt during the cooldown are all `false`; a poisoned lock fails
    /// closed.
    #[must_use]
    pub fn redeem(&self, code: &str) -> bool {
        let now = self.now_ms();
        self.store
            .lock()
            .is_ok_and(|mut store| store.validate(code, now).is_some())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MintError {
    Generate,
    Store,
}

#[derive(Serialize)]
struct MintResponse<'a> {
    code: &'a str,
    expires_at: String,
    fingerprint: &'a str,
}

#[derive(Serialize)]
struct EnrollResponse<'a> {
    device_id: &'a str,
    expires_at: String,
    token: &'a str,
}

fn instant_after(after: Duration) -> String {
    GoTime::from_offset_datetime(OffsetDateTime::now_utc() + after).to_rfc3339_nano()
}

/// Go's `EnrollCodeHTTPHandler`. `None` for any path or method it does not
/// answer itself (the mux's 404).
///
/// `fingerprint` is the SHA-256 of the certificate the pairing QR code pins;
/// empty means TLS is unavailable and every proven request is refused.
#[allow(clippy::too_many_arguments)] // The request fields Go's handler reads, plus the server state.
#[must_use]
pub fn handle_enroll_code_request(
    codes: &PairingCodes,
    fingerprint: &str,
    secret: &[u8],
    remote_ip: IpAddr,
    method: &str,
    path: &str,
    timestamp_header: &str,
    proof_header: &str,
) -> Option<ApprovalResponse> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if path != PATH_ENROLL_CODE || method != "POST" {
        return None;
    }
    // Go's `IsLoopbackHost(net.SplitHostPort(RemoteAddr))` parses an
    // IPv4-mapped IPv6 peer as its IPv4 address.
    if !remote_ip.to_canonical().is_loopback() {
        return Some(ApprovalResponse::json(
            403,
            error_json("device pairing codes can only be minted from localhost"),
        ));
    }
    if !verify_proof(secret, timestamp_header, proof_header) {
        return Some(ApprovalResponse::json(
            401,
            error_json("missing or invalid proof of vault-directory ownership"),
        ));
    }
    if fingerprint.is_empty() {
        return Some(ApprovalResponse::json(
            503,
            error_json("TLS is not configured; device pairing requires TLS"),
        ));
    }
    let code = match codes.mint() {
        Ok(code) => code,
        Err(MintError::Generate) => {
            return Some(ApprovalResponse::json(
                500,
                error_json("generate pairing code"),
            ));
        }
        Err(MintError::Store) => {
            return Some(ApprovalResponse::json(
                500,
                error_json("store pairing code"),
            ));
        }
    };
    Some(ApprovalResponse::json(
        200,
        json_line(&MintResponse {
            code: &code,
            expires_at: instant_after(codes.ttl()),
            fingerprint,
        }),
    ))
}

/// Go's `EnrollHTTPHandler`. `None` for any path or method it does not answer
/// itself (the mux's 404).
#[must_use]
pub fn handle_enroll_request(
    codes: &PairingCodes,
    sessions: &DeviceSessionStore,
    method: &str,
    path: &str,
    body: &str,
) -> Option<ApprovalResponse> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if path != PATH_ENROLL || method != "POST" {
        return None;
    }
    let Ok(request) = parse_enroll_body(body) else {
        return Some(ApprovalResponse::json(
            400,
            error_json("malformed request body"),
        ));
    };
    // Go: strings.TrimSpace, i.e. the Unicode White_Space set.
    let code = request.code.trim();
    if code.is_empty() {
        return Some(ApprovalResponse::json(
            400,
            error_json("missing pairing code"),
        ));
    }
    if !codes.redeem(code) {
        return Some(ApprovalResponse::json(
            401,
            error_json("invalid or expired pairing code"),
        ));
    }
    let mut random = [0_u8; 8];
    if getrandom::fill(&mut random).is_err() {
        return Some(ApprovalResponse::json(
            500,
            error_json("generate device id"),
        ));
    }
    let device_id = format!("dev-{}", hex(&random));
    let Ok(token) = sessions.enroll(&device_id, &request.device_name, "") else {
        return Some(ApprovalResponse::json(500, error_json("enroll device")));
    };
    Some(ApprovalResponse::json(
        200,
        json_line(&EnrollResponse {
            device_id: &device_id,
            expires_at: instant_after(SESSION_TTL),
            token: &token,
        }),
    ))
}

#[derive(Default)]
struct EnrollBody {
    code: String,
    device_name: String,
}

/// `json.NewDecoder(body).Decode(&enrollRequest{})`: the first JSON value
/// only (anything after it is never read), `null` is a no-op, unknown keys are
/// skipped, keys match exactly or ASCII-case-insensitively with the last
/// duplicate winning, a `null` field leaves the earlier value, and a field of
/// the wrong type fails the whole decode.
fn parse_enroll_body(body: &str) -> Result<EnrollBody, serde_json::Error> {
    struct BodyVisitor;

    impl<'de> Visitor<'de> for BodyVisitor {
        type Value = EnrollBody;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_unit<E>(self) -> Result<EnrollBody, E> {
            Ok(EnrollBody::default())
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<EnrollBody, A::Error> {
            let mut out = EnrollBody::default();
            let mut wrong_type = false;
            while let Some(key) = map.next_key::<String>()? {
                let target = if key.eq_ignore_ascii_case("code") {
                    Some(&mut out.code)
                } else if key.eq_ignore_ascii_case("device_name") {
                    Some(&mut out.device_name)
                } else {
                    None
                };
                let Some(target) = target else {
                    map.next_value::<IgnoredAny>()?;
                    continue;
                };
                match map.next_value::<serde_json::Value>()? {
                    serde_json::Value::Null => {}
                    serde_json::Value::String(text) => *target = text,
                    _ => wrong_type = true,
                }
            }
            if wrong_type {
                return Err(serde::de::Error::custom("field has the wrong type"));
            }
            Ok(out)
        }
    }

    // `Decode` reads one value and stops, so the deserializer is dropped
    // without checking for trailing characters.
    serde_json::Deserializer::from_str(body).deserialize_any(BodyVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::sync::Arc;

    const SECRET: &[u8] = b"enroll-unit-test-secret";
    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn proof_headers(at: OffsetDateTime) -> (String, String) {
        let at = at.replace_nanosecond(0).expect("whole second");
        let text = at
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format");
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).expect("key");
        mac.update(text.as_bytes());
        (text, hex(&mac.finalize().into_bytes()))
    }

    fn mint(codes: &PairingCodes) -> ApprovalResponse {
        let (timestamp, proof) = proof_headers(OffsetDateTime::now_utc());
        handle_enroll_code_request(
            codes,
            &"ab".repeat(32),
            SECRET,
            LOOPBACK,
            "POST",
            PATH_ENROLL_CODE,
            &timestamp,
            &proof,
        )
        .expect("mint route")
    }

    fn code_of(response: &ApprovalResponse) -> String {
        serde_json::from_slice::<serde_json::Value>(&response.body).expect("JSON")["code"]
            .as_str()
            .expect("code")
            .to_owned()
    }

    #[test]
    fn minted_codes_are_32_base32hex_characters_and_distinct() {
        let codes = PairingCodes::new();
        let first = code_of(&mint(&codes));
        let second = code_of(&mint(&codes));
        assert_ne!(first, second);
        for code in [&first, &second] {
            assert_eq!(code.len(), 32);
            assert!(
                code.bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'V'))
            );
        }
    }

    #[test]
    fn a_code_redeems_exactly_once_even_under_contention() {
        let codes = Arc::new(PairingCodes::new());
        let code = code_of(&mint(&codes));
        let handles = (0..16)
            .map(|_| {
                let (codes, code) = (Arc::clone(&codes), code.clone());
                std::thread::spawn(move || codes.redeem(&code))
            })
            .collect::<Vec<_>>();
        let wins = handles
            .into_iter()
            .map(|handle| handle.join().expect("redeemer"))
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
    }

    #[test]
    fn an_expired_code_is_refused() {
        let codes = PairingCodes::with_ttl(Duration::from_millis(30));
        let code = code_of(&mint(&codes));
        std::thread::sleep(Duration::from_millis(80));
        assert!(!codes.redeem(&code));
    }

    #[test]
    fn the_wire_constants_are_gos() {
        assert_eq!(PAIRING_CODE_TTL, Duration::from_secs(300));
        assert_eq!(symvault_sync::pairing::MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(symvault_sync::pairing::FAILED_ATTEMPT_COOLDOWN_MS, 30_000);
        assert_eq!(
            symvault_sync::pairing::DEFAULT_TOKEN_TTL_MS,
            i64::try_from(PAIRING_CODE_TTL.as_millis()).unwrap()
        );
        assert_eq!(
            i64::try_from(SESSION_TTL.as_secs()).unwrap(),
            symvault_sync::device_sessions::DEFAULT_SESSION_TTL_SECONDS
        );
    }

    #[test]
    fn five_failures_start_a_cooldown_that_refuses_valid_codes() {
        let codes = PairingCodes::new();
        let valid = code_of(&mint(&codes));
        for _ in 0..5 {
            assert!(!codes.redeem("nope"));
        }
        assert!(!codes.redeem(&valid), "cooling down: the valid code waits");
    }

    #[test]
    fn four_failures_then_a_valid_code_succeeds_and_resets_the_count() {
        let codes = PairingCodes::new();
        let first = code_of(&mint(&codes));
        let second = code_of(&mint(&codes));
        for _ in 0..4 {
            assert!(!codes.redeem("nope"));
        }
        assert!(codes.redeem(&first));
        for _ in 0..4 {
            assert!(!codes.redeem("nope"));
        }
        assert!(codes.redeem(&second));
    }

    #[test]
    fn mint_refuses_non_loopback_missing_proof_and_missing_tls_in_gos_order() {
        let codes = PairingCodes::new();
        let (timestamp, proof) = proof_headers(OffsetDateTime::now_utc());
        let call = |ip: IpAddr, fingerprint: &str, timestamp: &str, proof: &str| {
            handle_enroll_code_request(
                &codes,
                fingerprint,
                SECRET,
                ip,
                "POST",
                PATH_ENROLL_CODE,
                timestamp,
                proof,
            )
            .expect("mint route")
            .status
        };
        let remote: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(call(remote, "fp", &timestamp, &proof), 403);
        assert_eq!(call(remote, "fp", "", ""), 403, "loopback before proof");
        assert_eq!(call(LOOPBACK, "fp", "", ""), 401);
        assert_eq!(call(LOOPBACK, "", "", ""), 401, "proof before TLS");
        assert_eq!(call(LOOPBACK, "", &timestamp, &proof), 503);
        assert_eq!(call(LOOPBACK, "fp", &timestamp, &proof), 200);
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(call(mapped, "fp", &timestamp, &proof), 200);
        let mapped_remote: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        assert_eq!(call(mapped_remote, "fp", &timestamp, &proof), 403);
    }

    #[test]
    fn other_methods_and_paths_are_left_to_the_generic_404() {
        let codes = PairingCodes::new();
        let sessions = DeviceSessionStore::new(None).expect("store");
        for method in ["GET", "PUT", "DELETE", "HEAD", "PATCH"] {
            assert!(
                handle_enroll_code_request(
                    &codes,
                    "fp",
                    SECRET,
                    LOOPBACK,
                    method,
                    PATH_ENROLL_CODE,
                    "",
                    ""
                )
                .is_none()
            );
            assert!(handle_enroll_request(&codes, &sessions, method, PATH_ENROLL, "{}").is_none());
        }
        assert!(
            handle_enroll_request(&codes, &sessions, "POST", "/api/v1/devices/enroll/", "{}")
                .is_none()
        );
        assert!(
            handle_enroll_code_request(
                &codes,
                "fp",
                SECRET,
                LOOPBACK,
                "POST",
                "/api/v1/devices/enroll-codes",
                "",
                ""
            )
            .is_none()
        );
        assert!(is_enroll_route("/api/v1/devices/enroll?x=1"));
        assert!(is_enroll_route(PATH_ENROLL_CODE));
        assert!(!is_enroll_route("/api/v1/devices/enroll/"));
    }

    #[test]
    fn redeeming_persists_only_a_hash_and_the_token_authenticates() {
        let vault = tempfile::tempdir().expect("vault");
        let sessions = DeviceSessionStore::new(Some(vault.path())).expect("store");
        let codes = PairingCodes::new();
        let code = code_of(&mint(&codes));
        let response = handle_enroll_request(
            &codes,
            &sessions,
            "POST",
            PATH_ENROLL,
            &format!(r#"{{"code":" {code}\n","device_name":"phone"}}"#),
        )
        .expect("enroll route");
        assert_eq!(
            response.status,
            200,
            "{:?}",
            String::from_utf8_lossy(&response.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("JSON");
        let token = body["token"].as_str().expect("token");
        let device = body["device_id"].as_str().expect("device id");
        assert_eq!(
            sessions.validate(token).expect("validate").as_deref(),
            Some(device)
        );
        let persisted =
            std::fs::read_to_string(vault.path().join(".symvault/device-sessions.json")).unwrap();
        assert!(
            !persisted.contains(token),
            "the raw bearer must not be persisted"
        );
        // Single use.
        let again = handle_enroll_request(
            &codes,
            &sessions,
            "POST",
            PATH_ENROLL,
            &format!(r#"{{"code":"{code}"}}"#),
        )
        .expect("enroll route");
        assert_eq!(again.status, 401);
    }

    #[test]
    fn body_decoding_follows_encoding_json() {
        let ok = |body: &str| parse_enroll_body(body).expect(body);
        let both = ok(r#"{"CODE":"a","Device_Name":"b","x":[1,{"y":1e999}]}"#);
        assert_eq!((both.code.as_str(), both.device_name.as_str()), ("a", "b"));
        assert_eq!(ok(r#"{"code":"a","code":"b"}"#).code, "b");
        assert_eq!(ok(r#"{"code":"a","code":null}"#).code, "a");
        assert_eq!(ok(r#"{"\u0063ode":"a"}"#).code, "a");
        assert_eq!(ok(r#"{"code":"a"} trailing {"#).code, "a");
        assert_eq!(ok("null").code, "");
        for bad in [
            "",
            "{",
            "[]",
            r#""s""#,
            "5",
            "true",
            r#"{"code":5}"#,
            r#"{"code":"a","device_name":{}}"#,
            r#"{"code":"a",}"#,
            "\u{feff}{}",
        ] {
            assert!(parse_enroll_body(bad).is_err(), "{bad:?}");
        }
        // A wrongly typed field fails even when a later duplicate is fine.
        assert!(parse_enroll_body(r#"{"code":5,"code":"a"}"#).is_err());
    }
}
