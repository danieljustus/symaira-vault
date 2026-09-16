//! GIT-003: choosing between two versions of the same entry.
//!
//! Ported from `internal/vault/sync.WinnerByVersion`. The rule has three tiers,
//! applied in order: a higher `version` wins; failing that a later `updated`
//! wins; failing that the canonical JSON of the two metadata values is compared
//! lexicographically.
//!
//! The third tier is the reason this is more delicate than it looks. It decides
//! the outcome by comparing *serialized bytes*, so the port only agrees with the
//! oracle while its JSON encoding agrees byte-for-byte — field order, the
//! `omitempty` fields, and the timestamp format all feed into the answer. The
//! differential fixture therefore carries the oracle's own marshaled bytes for
//! every operand and asserts the round-trip, rather than only checking which
//! side won.

use serde::Serialize;
use symvault_store::EntryMetadata;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Picks the winning and losing metadata for `path`.
///
/// `path` is not compared; it only carries the oracle's short-circuit. An empty
/// `path` returns the first argument without consulting the tiebreak, which
/// makes that one case deliberately order-dependent. Every other pair gives the
/// same answer whichever way round the arguments are passed.
pub fn winner_by_version<'a>(
    path: &str,
    a: &'a EntryMetadata,
    b: &'a EntryMetadata,
) -> (&'a EntryMetadata, &'a EntryMetadata) {
    if a.version != b.version {
        return if a.version > b.version {
            (a, b)
        } else {
            (b, a)
        };
    }

    match (parse_instant(&a.updated), parse_instant(&b.updated)) {
        (Some(ta), Some(tb)) if ta != tb => {
            return if ta > tb { (a, b) } else { (b, a) };
        }
        // Unparseable timestamps cannot come from the oracle, which holds a
        // real time value. Rather than guessing an ordering from malformed
        // input, fall through to the canonical-JSON tiebreak, which is total
        // and deterministic for any pair.
        _ => {}
    }

    if path.is_empty() || canonical_is_smaller_or_equal(a, b) {
        (a, b)
    } else {
        (b, a)
    }
}

/// Parses an RFC 3339 timestamp.
///
/// The timestamps are carried as strings to keep the wire format identical to
/// the oracle's, but they must be compared as instants: Go trims trailing zeros
/// from the fractional second, so `...:07Z` and `...:07.5Z` differ in length and
/// a lexicographic compare would order them backwards — `.` sorts before `Z`.
fn parse_instant(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// The oracle's final tiebreak: compare the canonical JSON of the two values so
/// the winner depends on the metadata contents alone and never on argument
/// order or map iteration.
fn canonical_is_smaller_or_equal(a: &EntryMetadata, b: &EntryMetadata) -> bool {
    match (canonical_json(a), canonical_json(b)) {
        (Ok(ja), Ok(jb)) => ja <= jb,
        // The oracle returns true when either value fails to marshal.
        _ => true,
    }
}

/// The tiebreak orders entries by these bytes, so they must be the bytes Go
/// produces. `serde_json::to_string` leaves `<`, `>` and `&` literal where
/// `json.Marshal` escapes them, and the escape moves `<` (0x3C) to `\` (0x5C) —
/// from below `=` to above it. With a user-controlled tag containing `<`, the
/// two implementations pick *opposite winners* for the same pair.
fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    symvault_gojson::to_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(updated: &str, version: i64) -> EntryMetadata {
        EntryMetadata {
            created: "2026-01-01T00:00:00Z".into(),
            updated: updated.into(),
            version,
            tags: Vec::new(),
            write_history: Vec::new(),
        }
    }

    /// A sub-second timestamp is later than a whole-second one, even though it
    /// sorts earlier as a string. This is the case a string compare gets wrong.
    #[test]
    fn fractional_seconds_compare_as_instants_not_strings() {
        let whole = meta("2026-01-01T00:00:00Z", 1);
        let fractional = meta("2026-01-01T00:00:00.5Z", 1);
        assert!(
            "2026-01-01T00:00:00.5Z" < "2026-01-01T00:00:00Z",
            "precondition: the fractional form sorts earlier as a string"
        );
        let (winner, _) = winner_by_version("entries/item.age", &whole, &fractional);
        assert_eq!(
            winner.updated, "2026-01-01T00:00:00.5Z",
            "the later instant must win despite sorting earlier as a string"
        );
    }

    /// Malformed timestamps fall through to the tiebreak rather than producing
    /// an arbitrary order, and the result stays consistent both ways round.
    #[test]
    fn unparseable_timestamps_fall_through_to_the_tiebreak() {
        let a = meta("not-a-timestamp", 1);
        let b = meta("also-not-a-timestamp", 1);
        let (forward, _) = winner_by_version("entries/item.age", &a, &b);
        let (swapped, _) = winner_by_version("entries/item.age", &b, &a);
        assert_eq!(
            canonical_json(forward).unwrap(),
            canonical_json(swapped).unwrap(),
            "the fallback must still be order-independent"
        );
    }

    /// An empty path is the one order-dependent case, and it is deliberate.
    #[test]
    fn empty_path_returns_the_first_argument() {
        let a = meta("2026-01-01T00:00:00Z", 1);
        let b = meta("2026-01-01T00:00:00Z", 1);
        let mut b = b;
        b.tags = vec!["alpha".into()];
        let (forward, _) = winner_by_version("", &a, &b);
        assert_eq!(forward.tags, Vec::<String>::new(), "first argument wins");
        let (swapped, _) = winner_by_version("", &b, &a);
        assert_eq!(swapped.tags, vec!["alpha".to_string()], "still the first");
    }
}
