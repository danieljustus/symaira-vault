//! Deterministic entry metadata preparation for the Go→Rust write slice.
//!
//! The helper takes the clock as data. Filesystem writers can adopt it once
//! their write API has an explicit clock seam; keeping it pure prevents tests
//! and ports from acquiring a global mutable clock.

use crate::Entry;

/// Applies Go-compatible write metadata mutations without I/O.
///
/// `now` must be the canonical UTC RFC3339Nano representation supplied by the
/// caller. The helper intentionally does not parse or reformat it: preserving
/// the explicit bytes is part of the fixture contract. PendingWrite is not yet
/// represented by the Rust `Entry` type, so pending-record integration remains
/// a follow-up to the Rust writer integration slice.
pub fn prepare_entry(entry: &Entry, now: &str, path: &str, pseudonymize: bool) -> Entry {
    let mut prepared = entry.clone();
    if prepared.metadata.created == "0001-01-01T00:00:00Z" {
        prepared.metadata.created = now.to_owned();
    }
    prepared.metadata.updated = now.to_owned();
    prepared.metadata.version = prepared.metadata.version.wrapping_add(1);
    if pseudonymize {
        prepared.path = path.to_owned();
    }
    prepared
}

#[cfg(test)]
mod tests {
    use super::prepare_entry;
    use crate::Entry;
    use std::collections::BTreeMap;

    #[test]
    fn fixed_clock_mutates_only_metadata_and_path() {
        let entry = Entry {
            path: "old".into(),
            data: BTreeMap::new(),
            ..Entry::default()
        };
        let got = prepare_entry(&entry, "2026-09-08T10:11:12.123456789Z", "logical", true);
        assert_eq!(got.metadata.created, "2026-09-08T10:11:12.123456789Z");
        assert_eq!(got.metadata.updated, "2026-09-08T10:11:12.123456789Z");
        assert_eq!(got.metadata.version, 1);
        assert_eq!(got.path, "logical");
        assert_eq!(entry.metadata.version, 0);
    }

    #[test]
    fn existing_created_and_path_are_preserved_without_pseudonymization() {
        let entry = Entry {
            path: "old".into(),
            metadata: crate::EntryMetadata {
                created: "2026-01-01T00:00:00Z".into(),
                ..crate::EntryMetadata::default()
            },
            ..Entry::default()
        };
        let got = prepare_entry(&entry, "2026-09-08T10:11:12Z", "logical", false);
        assert_eq!(got.metadata.created, "2026-01-01T00:00:00Z");
        assert_eq!(got.path, "old");
        assert_eq!(got.metadata.version, 1);
    }
}
