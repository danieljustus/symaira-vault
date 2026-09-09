//! Deterministic entry metadata preparation for the Go→Rust write slice.

use crate::{Entry, WriteRecord};

/// Applies Go-compatible write metadata mutations without I/O.
///
/// `now` is RFC3339 and is normalized to UTC exactly as Go's `Time.UTC()`.
/// Pending writes are supplied separately because they are runtime-only on the
/// Go wire model (`json:"-"`).
pub fn prepare_entry(
    entry: &Entry,
    now: &str,
    path: &str,
    pseudonymize: bool,
    pending: Option<&WriteRecord>,
) -> Result<Entry, String> {
    let now = time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("invalid RFC3339 clock: {error}"))?
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("format RFC3339 clock: {error}"))?;
    let mut prepared = entry.clone();
    let zero = time::OffsetDateTime::parse(
        "0001-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixed Go zero time");
    let created_is_zero = time::OffsetDateTime::parse(
        &prepared.metadata.created,
        &time::format_description::well_known::Rfc3339,
    )
    .map(|created| created.unix_timestamp_nanos() == zero.unix_timestamp_nanos())
    .unwrap_or(false);
    if created_is_zero {
        prepared.metadata.created = now.clone();
    }
    prepared.metadata.updated = now.clone();
    prepared.metadata.version = prepared.metadata.version.wrapping_add(1);
    if let Some(record) = pending {
        let mut record = record.clone();
        record.timestamp = now;
        prepared.metadata.write_history.push(record);
    }
    if pseudonymize {
        prepared.path = path.to_owned();
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::prepare_entry;
    use crate::{Entry, WriteRecord};
    use serde::Deserialize;
    use serde_json::Value;
    use std::{collections::BTreeMap, fs};

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/store/metadata.json"
    );

    #[derive(Debug, Deserialize)]
    struct Fixture {
        schema_version: u8,
        oracle: Oracle,
        vectors: Vec<Vector>,
    }
    #[derive(Debug, Deserialize)]
    struct Oracle {
        commit: String,
        source_files: Vec<String>,
        source_digest: String,
        generator_files: Vec<String>,
        generator_digest: String,
    }
    #[derive(Debug, Deserialize)]
    struct Vector {
        name: String,
        input: Entry,
        pending_write: Option<WriteRecord>,
        path: String,
        pseudonymize: bool,
        now: String,
        expected: Value,
        expected_json: String,
    }

    #[test]
    fn consumes_every_go_generated_metadata_vector_with_exact_bytes() {
        let raw = fs::read_to_string(FIXTURE).expect("metadata fixture");
        let fixture: Fixture = serde_json::from_str(&raw).expect("valid metadata fixture");
        assert_eq!(fixture.schema_version, 1);
        assert_eq!(
            fixture.oracle.commit,
            "fe098b917a72125207bc711915f8daa791d1658f"
        );
        assert_eq!(fixture.oracle.source_files.len(), 4);
        assert_eq!(fixture.oracle.source_digest.len(), 64);
        assert_eq!(fixture.oracle.generator_files.len(), 1);
        assert_eq!(fixture.oracle.generator_digest.len(), 64);
        assert_eq!(fixture.vectors.len(), 8);
        let names: Vec<_> = fixture
            .vectors
            .iter()
            .map(|vector| vector.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "created_zero_pending",
                "nil_data_existing_version",
                "created_nonzero",
                "offset_clock",
                "created_zero_offset",
                "created_zero_walltime_offset",
                "created_near_zero_nonzero",
                "version_overflow"
            ]
        );

        for vector in &fixture.vectors {
            let before = vector.input.clone();
            let got = prepare_entry(
                &vector.input,
                &vector.now,
                &vector.path,
                vector.pseudonymize,
                vector.pending_write.as_ref(),
            )
            .expect("fixture clock");
            assert_eq!(
                got,
                serde_json::from_value(vector.expected.clone()).expect("expected Entry"),
                "semantic mismatch for {}",
                vector.name
            );
            assert_eq!(
                serde_json::to_string(&got).unwrap(),
                vector.expected_json,
                "wire bytes mismatch for {}",
                vector.name
            );
            assert_eq!(vector.input, before, "input mutated for {}", vector.name);
        }
    }

    #[test]
    fn pending_record_is_explicit_and_timestamped_without_entry_wire_field() {
        let entry = Entry {
            data: BTreeMap::new(),
            ..Entry::default()
        };
        let pending = WriteRecord {
            field: "token".into(),
            action: "set".into(),
            ..WriteRecord::default()
        };
        let got = prepare_entry(
            &entry,
            "2026-09-08T10:11:12+01:30",
            "logical",
            true,
            Some(&pending),
        )
        .unwrap();
        assert_eq!(
            got.metadata.write_history[0].timestamp,
            "2026-09-08T08:41:12Z"
        );
        assert_eq!(got.metadata.write_history[0].field, "token");
        assert!(
            serde_json::to_string(&got)
                .unwrap()
                .find("pending_write")
                .is_none()
        );
    }

    #[test]
    fn invalid_clock_and_missing_pending_are_rejected_or_preserved() {
        let entry = Entry::default();
        assert!(prepare_entry(&entry, "not-a-clock", "", false, None).is_err());
        let got = prepare_entry(&entry, "2026-09-08T10:11:12Z", "", false, None).unwrap();
        assert!(got.metadata.write_history.is_empty());
    }
}
