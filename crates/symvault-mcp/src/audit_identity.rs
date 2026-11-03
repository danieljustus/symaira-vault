//! Per-call audit identity (Go `RequestIDFromContext` and `auth.TokenFromContext`).
//!
//! Go's `logAudit` stamps every audit row with the server's session id, the
//! request id minted at the top of `executeTool` and, for HTTP callers that
//! authenticated with a scoped token, the token id. The Rust handlers append
//! audit rows from roughly a hundred call sites that carry no context, and the
//! whole `tools/call` path (authorization, then the handler) is synchronous on
//! the thread that serves the request. The protocol layer therefore installs
//! the identity for exactly that span and `append_audit` reads it back.
//!
//! The scope is a guard: it restores the previous value on drop, so it cannot
//! leak onto the next request served by the same thread. Code that runs on
//! another thread (for example the clipboard auto-clear timer) sees no
//! identity, like Go's `context.Background()` audit calls.

use std::cell::RefCell;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CallAuditIdentity {
    /// The scoped token's id; empty for stdio and for the legacy bearer.
    pub(crate) token_id: String,
    /// Go's `generateRequestID`: 8 random bytes, lower-case hex.
    pub(crate) request_id: String,
}

thread_local! {
    static CURRENT: RefCell<CallAuditIdentity> = RefCell::new(CallAuditIdentity::default());
}

pub(crate) struct CallAuditScope {
    previous: CallAuditIdentity,
}

impl CallAuditScope {
    pub(crate) fn enter(identity: CallAuditIdentity) -> Self {
        let previous = CURRENT.with(|current| current.replace(identity));
        Self { previous }
    }
}

impl Drop for CallAuditScope {
    fn drop(&mut self) {
        let previous = std::mem::take(&mut self.previous);
        CURRENT.with(|current| {
            *current.borrow_mut() = previous;
        });
    }
}

pub(crate) fn current() -> CallAuditIdentity {
    CURRENT.with(|current| current.borrow().clone())
}

/// Go `generateRequestID`. Go logs a warning and continues with an empty id
/// when the random source fails; so does this.
pub(crate) fn generate_request_id() -> String {
    random_hex::<8>()
}

/// Go `generateSessionID`: 16 random bytes, lower-case hex.
pub(crate) fn generate_session_id() -> String {
    random_hex::<16>()
}

fn random_hex<const N: usize>() -> String {
    let mut bytes = [0_u8; N];
    if getrandom::fill(&mut bytes).is_err() {
        return String::new();
    }
    let mut text = String::with_capacity(N * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_go_lengths_and_are_hex() {
        let request = generate_request_id();
        let session = generate_session_id();
        assert_eq!(request.len(), 16);
        assert_eq!(session.len(), 32);
        assert!(
            request
                .bytes()
                .chain(session.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(request, generate_request_id());
    }

    #[test]
    fn scope_restores_previous_identity_and_does_not_cross_threads() {
        assert_eq!(current(), CallAuditIdentity::default());
        let outer = CallAuditScope::enter(CallAuditIdentity {
            token_id: "tok".into(),
            request_id: "r1".into(),
        });
        {
            let _inner = CallAuditScope::enter(CallAuditIdentity {
                token_id: String::new(),
                request_id: "r2".into(),
            });
            assert_eq!(current().request_id, "r2");
            assert_eq!(current().token_id, "");
        }
        assert_eq!(current().request_id, "r1");
        std::thread::spawn(|| assert_eq!(current(), CallAuditIdentity::default()))
            .join()
            .unwrap();
        drop(outer);
        assert_eq!(current(), CallAuditIdentity::default());
    }
}
