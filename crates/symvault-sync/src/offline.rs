//! GIT-002: deciding whether a remote failure is a connectivity problem.
//!
//! Ported from `internal/git/git_offline.go` and the `PushError` formatting in
//! `internal/git/git.go`. Both push and pull route their failures through this
//! one classifier, and the answer changes what the user is told and whether the
//! failure reads as transient — so the marker list is a contract, not a
//! heuristic that may drift.
//!
//! The list is deliberately broad at the tail: `connection`, `refused`,
//! `network`, `tls` and `eof` match anywhere in the message. That is wide
//! enough that an authentication failure which merely mentions a connection is
//! classified as offline. This port reproduces that rather than quietly
//! tightening it, because narrowing the classifier would silently reclassify
//! failures the oracle currently calls transient. The corpus pins both of those
//! cases so the behavior is visible instead of surprising.

/// Substrings that mark a remote as unreachable. Matching is case-insensitive
/// and substring-based, in the oracle's order.
pub const OFFLINE_ERROR_MARKERS: &[&str] = &[
    // Real-world ssh / net / git error strings.
    "no route to host",
    "connection refused",
    "connection timed out",
    "operation timed out",
    "i/o timeout",
    "no such host",
    "could not resolve hostname",
    "name or service not known",
    "network is unreachable",
    "host is unreachable",
    "connection reset by peer",
    "timed out",
    "timeout",
    // Generic markers kept for parity with the previous per-package
    // classifiers.
    "connection",
    "refused",
    "network",
    "tls",
    "eof",
];

/// The user-facing text every offline classification resolves to.
pub const NETWORK_MESSAGE: &str = "network error - please check your connection";

/// Reports whether a message indicates the remote is unreachable, as opposed to
/// a configuration or authentication problem.
pub fn is_offline_error(message: &str) -> bool {
    let lowered = go_to_lower(message);
    OFFLINE_ERROR_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// Lowercases the way Go's `strings.ToLower` does: one replacement rune per
/// input rune.
///
/// Rust's `str::to_lowercase` applies *full* Unicode case mapping, which can
/// expand one char into several — U+0130 (LATIN CAPITAL LETTER I WITH DOT
/// ABOVE) becomes `i` plus a combining dot, where Go yields a bare `i`. That
/// expansion inserts a character into the middle of the haystack and can break
/// a marker match that the oracle would have made, so the classifier would
/// disagree with the oracle on an error message containing such a character.
fn go_to_lower(value: &str) -> String {
    value
        .chars()
        .map(|ch| ch.to_lowercase().next().unwrap_or(ch))
        .collect()
}

/// A push or pull failure as the user sees it.
///
/// The oracle uses one type for both directions, so this does too.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushError {
    pub message: String,
    pub cause: Option<String>,
}

impl PushError {
    pub fn new(message: impl Into<String>) -> Self {
        PushError {
            message: message.into(),
            cause: None,
        }
    }

    pub fn with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        PushError {
            message: message.into(),
            cause: Some(cause.into()),
        }
    }
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Some(cause) => write!(f, "push failed: {}: {}", self.message, cause),
            None => write!(f, "push failed: {}", self.message),
        }
    }
}

impl std::error::Error for PushError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tail markers are broad enough to outvote the word "authentication".
    /// Pinned as a test so the breadth is a decision on the record.
    #[test]
    fn broad_markers_outvote_the_word_authentication() {
        assert!(is_offline_error(
            "authentication failed on connection to host"
        ));
        assert!(is_offline_error("authentication failed: network path"));
        assert!(!is_offline_error("authentication failed"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_offline_error("CONNECTION REFUSED"));
        assert!(is_offline_error("No Route To Host"));
    }

    /// Go maps one rune to one rune; Rust's default mapping can expand, which
    /// would insert a combining mark into the middle of a marker.
    #[test]
    fn lowercasing_matches_gos_one_rune_mapping() {
        let message = "\u{0130}/O timeout";
        assert_eq!(go_to_lower(message), "i/o timeout");
        assert_ne!(
            message.to_lowercase(),
            "i/o timeout",
            "precondition: Rust's default mapping expands here, which is the bug"
        );
        assert!(is_offline_error(message));
    }

    #[test]
    fn an_empty_message_matches_nothing() {
        assert!(!is_offline_error(""));
    }
}
