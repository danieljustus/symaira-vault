//! In-process request queue and the loopback-only approval CLI API.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Condvar, Mutex},
    time::Duration,
};
use symvault_sync::device_sessions::DeviceSessionStore;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
const PROOF_WINDOW: Duration = Duration::from_secs(30);
const LOCAL_APPROVALS: &str = "/api/v1/local/approvals";
const LOCAL_APPROVAL_ACTION: &str = "/api/v1/local/approvals/";
const DEVICE_APPROVALS: &str = "/api/v1/approvals";
const DEVICE_APPROVAL_ACTION: &str = "/api/v1/approvals/";
const DEVICE_UNAUTHORIZED: &str = "unauthorized: valid device token required";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub agent_name: String,
    pub path: String,
    pub write: bool,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalEntry {
    #[serde(flatten)]
    pub request: ApprovalRequest,
    pub id: String,
    pub status: String,
    pub decided_at: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub decided_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub id: String,
    pub status: String,
    pub decided_at: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub decided_by: Option<String>,
}

#[derive(Default)]
pub struct ApprovalQueue {
    entries: Mutex<BTreeMap<String, ApprovalEntry>>,
    changed: Condvar,
}

impl ApprovalQueue {
    pub fn enqueue(
        &self,
        agent_name: impl Into<String>,
        path: impl Into<String>,
        write: bool,
        reason: impl Into<String>,
    ) -> Result<String, String> {
        self.enqueue_with_ttl(agent_name, path, write, reason, DEFAULT_TTL)
    }

    /// Like [`Self::enqueue`] with an explicit lifetime, the way Go's
    /// `Request.ExpiresAt` overrides the queue default. A zero lifetime keeps
    /// the default, as Go does for an expiry that is not in the future.
    pub fn enqueue_with_ttl(
        &self,
        agent_name: impl Into<String>,
        path: impl Into<String>,
        write: bool,
        reason: impl Into<String>,
        ttl: Duration,
    ) -> Result<String, String> {
        let ttl = if ttl.is_zero() { DEFAULT_TTL } else { ttl };
        let mut random = [0_u8; 6];
        getrandom::fill(&mut random).map_err(|error| format!("generate approval id: {error}"))?;
        let id = format!("apr-{}", hex(&random));
        let now = OffsetDateTime::now_utc();
        let expires = now + ttl;
        let request = ApprovalRequest {
            agent_name: agent_name.into(),
            path: path.into(),
            write,
            reason: reason.into(),
            created_at: timestamp(now)?,
            expires_at: timestamp(expires)?,
        };
        let entry = ApprovalEntry {
            request,
            id: id.clone(),
            status: "pending".into(),
            decided_at: "0001-01-01T00:00:00Z".into(),
            decided_by: None,
        };
        self.entries
            .lock()
            .map_err(|_| "approval queue lock poisoned".to_owned())?
            .insert(id.clone(), entry);
        Ok(id)
    }

    pub fn pending(&self) -> Result<Vec<ApprovalEntry>, String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "approval queue lock poisoned".to_owned())?;
        expire(&mut entries);
        let mut pending = entries
            .values()
            .filter(|entry| entry.status == "pending")
            .cloned()
            .collect::<Vec<_>>();
        // Go orders by `time.Time`; RFC 3339 strings with trimmed fractional
        // zeros do not compare like instants, so compare parsed instants.
        pending.sort_by(|a, b| {
            let created = |entry: &ApprovalEntry| {
                OffsetDateTime::parse(&entry.request.created_at, &Rfc3339).ok()
            };
            created(b).cmp(&created(a)).then_with(|| a.id.cmp(&b.id))
        });
        Ok(pending)
    }

    fn decide(
        &self,
        id: &str,
        status: &str,
        decided_by: &str,
    ) -> Result<ApprovalOutcome, (u16, String)> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| (500, "approval queue lock poisoned".into()))?;
        expire(&mut entries);
        let Some(entry) = entries.get_mut(id) else {
            return Err((404, "approval request not found".into()));
        };
        if entry.status != "pending" {
            return Err((
                409,
                format!("approval request {id} already {}", entry.status),
            ));
        }
        let decided_at = timestamp(OffsetDateTime::now_utc())
            .map_err(|_| (500, "format approval decision time".into()))?;
        entry.status = status.to_owned();
        entry.decided_at = decided_at.clone();
        entry.decided_by = Some(decided_by.to_owned());
        self.changed.notify_all();
        Ok(ApprovalOutcome {
            id: id.to_owned(),
            status: status.to_owned(),
            decided_at,
            decided_by: Some(decided_by.to_owned()),
        })
    }

    pub fn approve(&self, id: &str, decided_by: &str) -> Result<ApprovalOutcome, String> {
        self.decide(id, "approved", decided_by)
            .map_err(|(_, message)| message)
    }

    pub fn deny(&self, id: &str, decided_by: &str) -> Result<ApprovalOutcome, String> {
        self.decide(id, "denied", decided_by)
            .map_err(|(_, message)| message)
    }

    pub fn wait(&self, id: &str) -> Result<ApprovalOutcome, String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "approval queue lock poisoned".to_owned())?;
        loop {
            expire(&mut entries);
            let Some(entry) = entries.get(id) else {
                return Err("approval request not found".to_owned());
            };
            if entry.status != "pending" {
                return Ok(ApprovalOutcome {
                    id: entry.id.clone(),
                    status: entry.status.clone(),
                    decided_at: entry.decided_at.clone(),
                    decided_by: entry.decided_by.clone(),
                });
            }
            let expires = OffsetDateTime::parse(&entry.request.expires_at, &Rfc3339)
                .map_err(|_| "parse approval request expiry".to_owned())?;
            let remaining = (expires - OffsetDateTime::now_utc())
                .try_into()
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                continue;
            }
            let (next, _) = self
                .changed
                .wait_timeout(entries, remaining)
                .map_err(|_| "approval queue lock poisoned".to_owned())?;
            entries = next;
        }
    }

    pub fn request_and_wait(
        &self,
        agent_name: impl Into<String>,
        path: impl Into<String>,
        write: bool,
        reason: impl Into<String>,
    ) -> Result<ApprovalOutcome, String> {
        let id = self.enqueue(agent_name, path, write, reason)?;
        self.wait(&id)
    }
}

pub(crate) fn handle_local_request(
    queue: &ApprovalQueue,
    secret: &[u8],
    remote_ip: IpAddr,
    method: &str,
    path: &str,
    timestamp_header: &str,
    proof_header: &str,
) -> Option<ApprovalResponse> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if path != LOCAL_APPROVALS && !path.starts_with(LOCAL_APPROVAL_ACTION) {
        return None;
    }
    let route = match (method, path == LOCAL_APPROVALS) {
        ("GET", true) => "list",
        ("POST", false) => "decide",
        _ => return Some(ApprovalResponse::not_found()),
    };
    let (status, body) = if !remote_ip.is_loopback() {
        (
            403,
            error_json("local approval API requires a loopback connection"),
        )
    } else if !verify_proof(secret, timestamp_header, proof_header) {
        (
            401,
            error_json("missing or invalid proof of vault-directory ownership"),
        )
    } else if route == "list" {
        match queue.pending() {
            Ok(requests) => (200, json_line(&RequestsResponse { requests })),
            Err(_) => (500, error_json("approval queue unavailable")),
        }
    } else {
        let action = path.strip_prefix(LOCAL_APPROVAL_ACTION).unwrap_or_default();
        let (id, decision) = if let Some(id) = action.strip_suffix("/approve") {
            (id.strip_suffix('/').unwrap_or(id), "approved")
        } else if let Some(id) = action.strip_suffix("/deny") {
            (id.strip_suffix('/').unwrap_or(id), "denied")
        } else {
            return Some(ApprovalResponse::json(
                404,
                error_json("unknown approval action"),
            ));
        };
        if id.is_empty() {
            (404, error_json("approval request not found"))
        } else {
            match queue.decide(id, decision, "local-cli") {
                Ok(outcome) => (200, json_line(&OutcomeResponse { outcome })),
                Err((status, message)) => (status, error_json(&message)),
            }
        }
    };
    Some(ApprovalResponse::json(status, body))
}

/// Go's `approval.HTTPHandler`, mounted by `serverbootstrap` at
/// `/api/v1/approvals` and `/api/v1/approvals/`: an enrolled approval device
/// lists pending requests and approves or denies them with its long-lived
/// device-session bearer token. It does not accept the MCP legacy or scoped
/// bearer tokens, and the MCP routes do not accept a device token.
///
/// Returns `None` for any method/path pair Go's handler answers with
/// `http.NotFound`, so the caller's generic 404 (identical bytes) applies
/// before any authentication is attempted, exactly as in Go.
pub(crate) fn handle_device_request(
    queue: &ApprovalQueue,
    sessions: &DeviceSessionStore,
    method: &str,
    path: &str,
    authorization: &str,
) -> Option<ApprovalResponse> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let list = method == "GET" && path == DEVICE_APPROVALS;
    let decide = method == "POST" && path.starts_with(DEVICE_APPROVAL_ACTION);
    if !list && !decide {
        return None;
    }
    let Some(device_id) = device_from_authorization(sessions, authorization) else {
        return Some(ApprovalResponse::json(401, error_json(DEVICE_UNAUTHORIZED)));
    };
    if list {
        return Some(match queue.pending() {
            Ok(requests) => ApprovalResponse::json(200, json_line(&RequestsResponse { requests })),
            Err(_) => ApprovalResponse::json(500, error_json("approval queue unavailable")),
        });
    }
    let id = path
        .strip_prefix(DEVICE_APPROVAL_ACTION)
        .unwrap_or_default();
    let id = id.strip_suffix('/').unwrap_or(id);
    if id.is_empty() {
        return Some(ApprovalResponse::json(
            400,
            error_json("missing approval request id"),
        ));
    }
    let (base, decision) = if let Some(base) = id.strip_suffix("/approve") {
        (base, "approved")
    } else if let Some(base) = id.strip_suffix("/deny") {
        (base, "denied")
    } else {
        return Some(ApprovalResponse::json(
            404,
            error_json("unknown approval action"),
        ));
    };
    Some(match queue.decide(base, decision, &device_id) {
        Ok(outcome) => ApprovalResponse::json(200, json_line(&OutcomeResponse { outcome })),
        Err((status, message)) => ApprovalResponse::json(status, error_json(&message)),
    })
}

/// Go's `deviceFromRequest`: `TrimPrefix(Authorization, "Bearer ")`, an empty
/// or unchanged result is unauthorized, and so is a session without a device
/// id. An unreadable store fails closed.
fn device_from_authorization(sessions: &DeviceSessionStore, authorization: &str) -> Option<String> {
    let token = authorization.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    sessions
        .validate(token)
        .ok()
        .flatten()
        .filter(|device_id| !device_id.is_empty())
}

fn omit_empty(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(str::is_empty)
}

pub(crate) struct ApprovalResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl ApprovalResponse {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body,
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain; charset=utf-8",
            body: b"404 page not found\n".to_vec(),
        }
    }
}

#[derive(Serialize)]
struct RequestsResponse {
    requests: Vec<ApprovalEntry>,
}

#[derive(Serialize)]
struct OutcomeResponse {
    outcome: ApprovalOutcome,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn error_json(message: &str) -> Vec<u8> {
    json_line(&ErrorResponse { error: message })
}

/// `json.NewEncoder(w).Encode(v)`: compact, HTML-escaped, newline-terminated.
fn json_line(value: &impl Serialize) -> Vec<u8> {
    let mut body = symvault_gojson::to_string(value)
        .expect("approval responses are serializable")
        .into_bytes();
    body.push(b'\n');
    body
}

fn timestamp(value: OffsetDateTime) -> Result<String, String> {
    value
        .format(&Rfc3339)
        .map_err(|error| format!("format approval timestamp: {error}"))
}

fn expire(entries: &mut BTreeMap<String, ApprovalEntry>) {
    let now = OffsetDateTime::now_utc();
    for entry in entries
        .values_mut()
        .filter(|entry| entry.status == "pending")
    {
        if OffsetDateTime::parse(&entry.request.expires_at, &Rfc3339)
            .is_ok_and(|expires| now > expires)
        {
            entry.status = "expired".into();
            entry.decided_at = entry.request.expires_at.clone();
        }
    }
}

fn verify_proof(secret: &[u8], timestamp_header: &str, proof_header: &str) -> bool {
    if secret.is_empty() || proof_header.len() != 64 {
        return false;
    }
    let Ok(parsed) = OffsetDateTime::parse(timestamp_header, &Rfc3339) else {
        return false;
    };
    if (OffsetDateTime::now_utc() - parsed).unsigned_abs() > PROOF_WINDOW {
        return false;
    }
    let Ok(timestamp) = timestamp(parsed.to_offset(time::UtcOffset::UTC)) else {
        return false;
    };
    let Some(proof) = unhex(proof_header) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(timestamp.as_bytes());
    mac.verify_slice(&proof).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: &str = "0001-01-01T00:00:00Z";

    fn proof(secret: &[u8], at: OffsetDateTime) -> (String, String) {
        let timestamp = timestamp(at).expect("timestamp");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
        mac.update(timestamp.as_bytes());
        (timestamp, hex(&mac.finalize().into_bytes()))
    }

    #[test]
    fn local_api_matches_go_list_decide_and_fail_closed_contract() {
        let queue = ApprovalQueue::default();
        let id = queue
            .enqueue("agent-a", "notes/file", true, "write request")
            .expect("enqueue");
        let secret = b"test vault secret";
        let (timestamp, proof) = proof(secret, OffsetDateTime::now_utc());
        let list = handle_local_request(
            &queue,
            secret,
            "127.0.0.1".parse().unwrap(),
            "GET",
            LOCAL_APPROVALS,
            &timestamp,
            &proof,
        )
        .expect("local API route");
        assert_eq!(list.status, 200);
        let listed: serde_json::Value = serde_json::from_slice(&list.body).expect("list JSON");
        assert_eq!(listed["requests"][0]["id"], id);
        assert_eq!(listed["requests"][0]["status"], "pending");
        assert_eq!(listed["requests"][0]["decided_at"], "0001-01-01T00:00:00Z");
        assert!(listed["requests"][0].get("decided_by").is_none());

        let decided = handle_local_request(
            &queue,
            secret,
            "127.0.0.1".parse().unwrap(),
            "POST",
            &format!("{LOCAL_APPROVAL_ACTION}{id}/approve"),
            &timestamp,
            &proof,
        )
        .expect("local API route");
        assert_eq!(decided.status, 200);
        let outcome: serde_json::Value =
            serde_json::from_slice(&decided.body).expect("outcome JSON");
        assert_eq!(outcome["outcome"]["status"], "approved");
        assert_eq!(outcome["outcome"]["decided_by"], "local-cli");
        let duplicate = handle_local_request(
            &queue,
            secret,
            "127.0.0.1".parse().unwrap(),
            "POST",
            &format!("{LOCAL_APPROVAL_ACTION}{id}/deny"),
            &timestamp,
            &proof,
        )
        .expect("local API route");
        assert_eq!(duplicate.status, 409);

        let remote = handle_local_request(
            &queue,
            secret,
            "192.0.2.1".parse().unwrap(),
            "GET",
            LOCAL_APPROVALS,
            &timestamp,
            &proof,
        )
        .expect("local API route");
        assert_eq!(remote.status, 403);
        let bad_proof = handle_local_request(
            &queue,
            secret,
            "127.0.0.1".parse().unwrap(),
            "GET",
            LOCAL_APPROVALS,
            &timestamp,
            &"0".repeat(64),
        )
        .expect("local API route");
        assert_eq!(bad_proof.status, 401);
    }

    #[test]
    fn local_api_rejects_a_correctly_signed_proof_outside_the_window() {
        let queue = ApprovalQueue::default();
        let secret = b"test vault secret";
        let now = OffsetDateTime::now_utc();
        let window = time::Duration::try_from(PROOF_WINDOW).expect("window");
        for (at, expected) in [
            (now - window - time::Duration::seconds(5), 401),
            (now + window + time::Duration::seconds(5), 401),
            (now - time::Duration::seconds(5), 200),
        ] {
            let (timestamp, proof) = proof(secret, at);
            let response = handle_local_request(
                &queue,
                secret,
                "127.0.0.1".parse().unwrap(),
                "GET",
                LOCAL_APPROVALS,
                &timestamp,
                &proof,
            )
            .expect("local API route");
            assert_eq!(response.status, expected, "timestamp {timestamp}");
        }
    }

    #[test]
    fn pending_orders_by_instant_not_by_rfc3339_text() {
        // "...05.12Z" is earlier than "...05.123Z" although it compares greater
        // as text ('Z' > '3'); Go orders by time.Time.
        let queue = ApprovalQueue::default();
        let earlier = queue.enqueue("a", "p", false, "r").expect("enqueue");
        let later = queue.enqueue("a", "p", false, "r").expect("enqueue");
        {
            let mut entries = queue.entries.lock().expect("lock");
            entries.get_mut(&earlier).unwrap().request.created_at =
                "2026-01-02T03:04:05.12Z".into();
            entries.get_mut(&later).unwrap().request.created_at = "2026-01-02T03:04:05.123Z".into();
        }
        let ids = queue
            .pending()
            .expect("pending")
            .into_iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>();
        assert_eq!(ids, [later, earlier]);
    }

    #[test]
    fn explicit_lifetime_expires_and_zero_keeps_the_default() {
        let queue = ApprovalQueue::default();
        let short = queue
            .enqueue_with_ttl("a", "p", false, "r", Duration::from_millis(20))
            .expect("enqueue");
        let default = queue
            .enqueue_with_ttl("a", "p", false, "r", Duration::ZERO)
            .expect("enqueue");
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            queue.decide(&short, "approved", "dev").unwrap_err(),
            (409, format!("approval request {short} already expired"))
        );
        assert!(queue.decide(&default, "approved", "dev").is_ok());
    }

    #[test]
    fn empty_decided_by_is_omitted_like_go_omitempty() {
        let mut entry = ApprovalEntry {
            request: ApprovalRequest {
                agent_name: "a".into(),
                path: "p".into(),
                write: false,
                reason: "r".into(),
                created_at: "c".into(),
                expires_at: "e".into(),
            },
            id: "apr-1".into(),
            status: "pending".into(),
            decided_at: ZERO.into(),
            decided_by: Some(String::new()),
        };
        assert!(
            !String::from_utf8(json_line(&entry))
                .unwrap()
                .contains("decided_by")
        );
        entry.decided_by = Some("dev".into());
        assert!(
            String::from_utf8(json_line(&entry))
                .unwrap()
                .contains("\"decided_by\":\"dev\"")
        );
    }

    #[test]
    fn device_route_rejects_wrong_methods_and_bad_bearers_without_deciding() {
        let sessions = DeviceSessionStore::new(None).expect("in-memory store");
        let token = sessions.enroll("dev-1", "one", "pk").expect("enroll");
        let queue = ApprovalQueue::default();
        let id = queue.enqueue("agent", "p", true, "r").expect("enqueue");
        let approve = format!("{DEVICE_APPROVAL_ACTION}{id}/approve");
        // Not Go's routes: left to the caller's 404, no auth attempted.
        assert!(handle_device_request(&queue, &sessions, "PUT", DEVICE_APPROVALS, "").is_none());
        assert!(handle_device_request(&queue, &sessions, "POST", DEVICE_APPROVALS, "").is_none());
        assert!(handle_device_request(&queue, &sessions, "GET", &approve, "").is_none());
        // Unauthenticated variants.
        for bad in ["", "Bearer", "Bearer ", "bearer x", &token, "Bearer nope"] {
            let response = handle_device_request(&queue, &sessions, "POST", &approve, bad)
                .expect("device route");
            assert_eq!(response.status, 401, "{bad:?}");
        }
        assert_eq!(queue.pending().unwrap().len(), 1);
        let ok = handle_device_request(
            &queue,
            &sessions,
            "POST",
            &approve,
            &format!("Bearer {token}"),
        )
        .expect("device route");
        assert_eq!(ok.status, 200);
        assert!(
            String::from_utf8(ok.body)
                .unwrap()
                .contains("\"decided_by\":\"dev-1\"")
        );
        sessions.revoke("dev-1").expect("revoke");
        let revoked = handle_device_request(
            &queue,
            &sessions,
            "GET",
            DEVICE_APPROVALS,
            &format!("Bearer {token}"),
        )
        .expect("device route");
        assert_eq!(revoked.status, 401);
    }
}
