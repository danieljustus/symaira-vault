//! In-process request queue and the loopback-only approval CLI API.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Condvar, Mutex},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
const PROOF_WINDOW: Duration = Duration::from_secs(30);
const LOCAL_APPROVALS: &str = "/api/v1/local/approvals";
const LOCAL_APPROVAL_ACTION: &str = "/api/v1/local/approvals/";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub id: String,
    pub status: String,
    pub decided_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
        let mut random = [0_u8; 6];
        getrandom::fill(&mut random).map_err(|error| format!("generate approval id: {error}"))?;
        let id = format!("apr-{}", hex(&random));
        let now = OffsetDateTime::now_utc();
        let expires = now + DEFAULT_TTL;
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
        pending.sort_by(|a, b| {
            b.request
                .created_at
                .cmp(&a.request.created_at)
                .then_with(|| a.id.cmp(&b.id))
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

fn json_line(value: &impl Serialize) -> Vec<u8> {
    let mut body = serde_json::to_vec(value).expect("approval responses are serializable");
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
}
