#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{fs, io, process};
use symvault_crypto::{encrypt, parse_identity, parse_recipient, recipient_string};
use symvault_store::{Entry, Store};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

#[derive(Deserialize)]
struct Request {
    case_id: String,
    root: String,
    identity: String,
    #[serde(default)]
    now: String,
    #[serde(default)]
    pseudonymize: bool,
}

#[derive(Default, Serialize)]
struct Outcome {
    case_id: String,
    direct: String,
    highlevel: String,
    manifest_exists: bool,
    entry_exists: bool,
    alpha_record_present: bool,
    generation: i64,
    created_nonzero: bool,
    created_preserved: bool,
    updated_nonzero: bool,
    entry_mtime_nonzero: bool,
    direct_generation: i64,
    remove_generation: i64,
    direct_record_present: bool,
    remove_record_present: bool,
    direct_entry_mtime_utc: bool,
    direct_malformed_preserved: bool,
    highlevel_malformed_preserved: bool,
}

fn classify<T>(result: Result<T, impl std::fmt::Display>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(error) => {
            let text = error.to_string();
            if text.contains("not found") || text.contains("No such file") {
                "missing".into()
            } else if text.contains("invalid")
                || text.contains("malformed")
                || text.contains("decrypt")
            {
                "malformed".into()
            } else {
                "error".into()
            }
        }
    }
}

fn run() -> Result<Outcome, String> {
    let request: Request = serde_json::from_reader(io::stdin()).map_err(|e| e.to_string())?;
    let identity = parse_identity(&request.identity).map_err(|e| e.to_string())?;
    let store = Store::open(&request.root, &identity).map_err(|e| e.to_string())?;
    let actual_root = store.root().to_path_buf();
    let mut outcome = Outcome {
        case_id: request.case_id.clone(),
        direct: "ok".into(),
        highlevel: "ok".into(),
        ..Default::default()
    };
    let entry = Entry {
        data: [("value".into(), serde_json::json!("one"))]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let now = if request.now.is_empty() {
        "2026-09-08T10:11:12Z"
    } else {
        &request.now
    };
    let _ = request.pseudonymize; // configuration on disk is authoritative for path selection
    match request.case_id.as_str() {
        "WRITE-MANIFEST-001" => {
            outcome.highlevel = classify(
                store.write_entry_with_recipients_at("alpha", &entry, &identity, now, None),
            );
        }
        "WRITE-MANIFEST-002" => {
            outcome.highlevel = classify(
                store.write_entry_with_recipients_at("alpha", &entry, &identity, now, None),
            );
            let created = store.load_manifest(&identity).ok().map(|m| m.created);
            let mut replacement = entry.clone();
            replacement
                .data
                .insert("value".into(), serde_json::json!("two"));
            outcome.highlevel = classify(store.write_entry_with_recipients_at(
                "alpha",
                &replacement,
                &identity,
                now,
                None,
            ));
            if let (Some(old), Ok(new)) = (created, store.load_manifest(&identity)) {
                outcome.created_preserved = old == new.created;
            }
        }
        "DELETE-MANIFEST-001" => {
            outcome.highlevel = classify(
                store.write_entry_with_recipients_at("alpha", &entry, &identity, now, None),
            );
            let created = store.load_manifest(&identity).ok().map(|m| m.created);
            outcome.highlevel = classify(store.delete_entry_with_identity("alpha", &identity));
            if let (Some(old), Ok(new)) = (created, store.load_manifest(&identity)) {
                outcome.created_preserved = old == new.created;
            }
        }
        "MANIFEST-MISSING-001" => {
            outcome.direct =
                classify(store.update_manifest_entry("alpha", b"ciphertext", &identity));
        }
        "MANIFEST-MISSING-002" => {
            outcome.direct = classify(store.remove_manifest_entry("alpha", &identity));
        }
        "MANIFEST-BOUNDARY-UPDATE-REMOVE-001" | "MANIFEST-BOUNDARY-UPDATE-REMOVE-002" => {
            seed_boundary_manifest(
                &actual_root,
                &identity,
                request.case_id == "MANIFEST-BOUNDARY-UPDATE-REMOVE-002",
            )?;
            let created = store.load_manifest(&identity).ok().map(|m| m.created);
            outcome.direct =
                classify(store.update_manifest_entry("alpha", b"ciphertext", &identity));
            if let Ok(manifest) = store.load_manifest(&identity) {
                outcome.direct_generation = manifest.generation;
                outcome.direct_record_present = manifest.entries.contains_key("alpha");
                outcome.direct_entry_mtime_utc = manifest
                    .entries
                    .get("alpha")
                    .is_some_and(|e| is_utc_timestamp(&e.mtime));
            }
            outcome.highlevel = classify(store.remove_manifest_entry("alpha", &identity));
            if let Ok(manifest) = store.load_manifest(&identity) {
                outcome.remove_generation = manifest.generation;
                outcome.remove_record_present = manifest.entries.contains_key("alpha");
                outcome.created_preserved = created.is_some_and(|old| old == manifest.created);
            }
        }
        "MANIFEST-GENERATION-I64MAX-001" => {
            seed_i64max_manifest(&actual_root, &identity)?;
            let created = store.load_manifest(&identity).ok().map(|m| m.created);
            outcome.direct =
                classify(store.update_manifest_entry("alpha", b"ciphertext", &identity));
            if let Ok(manifest) = store.load_manifest(&identity) {
                outcome.direct_generation = manifest.generation;
                outcome.direct_record_present = manifest.entries.contains_key("alpha");
            }
            outcome.highlevel = classify(store.remove_manifest_entry("alpha", &identity));
            if let Ok(manifest) = store.load_manifest(&identity) {
                outcome.remove_generation = manifest.generation;
                outcome.remove_record_present = manifest.entries.contains_key("alpha");
                outcome.created_preserved = created.is_some_and(|old| old == manifest.created);
            }
        }
        "MANIFEST-MALFORMED-001" => {
            fs::write(
                actual_root.join("manifest.age"),
                b"malformed manifest bytes",
            )
            .map_err(|e| e.to_string())?;
            outcome.direct =
                classify(store.update_manifest_entry("alpha", b"ciphertext", &identity));
            outcome.direct_malformed_preserved = fs::read(actual_root.join("manifest.age"))
                .map(|bytes| bytes == b"malformed manifest bytes")
                .unwrap_or(false);
            outcome.highlevel = classify(
                store.write_entry_with_recipients_at("alpha", &entry, &identity, now, None),
            );
            outcome.highlevel_malformed_preserved = fs::read(actual_root.join("manifest.age"))
                .map(|bytes| bytes == b"malformed manifest bytes")
                .unwrap_or(false);
        }
        "MANIFEST-MALFORMED-002" => {
            outcome.highlevel = classify(
                store.write_entry_with_recipients_at("alpha", &entry, &identity, now, None),
            );
            fs::write(
                actual_root.join("manifest.age"),
                b"malformed manifest bytes",
            )
            .map_err(|e| e.to_string())?;
            outcome.direct = classify(store.remove_manifest_entry("alpha", &identity));
            outcome.direct_malformed_preserved = fs::read(actual_root.join("manifest.age"))
                .map(|bytes| bytes == b"malformed manifest bytes")
                .unwrap_or(false);
            outcome.highlevel = classify(store.delete_entry_with_identity("alpha", &identity));
            outcome.highlevel_malformed_preserved = fs::read(actual_root.join("manifest.age"))
                .map(|bytes| bytes == b"malformed manifest bytes")
                .unwrap_or(false);
        }
        _ => return Err("unknown case_id".into()),
    }
    outcome.manifest_exists = actual_root.join("manifest.age").is_file();
    outcome.entry_exists = store
        .entry_exists("alpha", &identity)
        .map_err(|error| error.to_string())?;
    if let Ok(manifest) = store.load_manifest(&identity) {
        outcome.generation = manifest.generation;
        outcome.alpha_record_present = manifest.entries.contains_key("alpha");
        outcome.created_nonzero = manifest.created != "0001-01-01T00:00:00Z";
        outcome.updated_nonzero = is_utc_timestamp(&manifest.updated);
        outcome.entry_mtime_nonzero = manifest
            .entries
            .values()
            .all(|e| is_utc_timestamp(&e.mtime));
    }
    Ok(outcome)
}

fn is_utc_timestamp(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok_and(|dt| dt.offset() == UtcOffset::UTC)
}

fn seed_boundary_manifest(
    root: &std::path::Path,
    identity: &symvault_crypto::Identity,
    nonzero_created: bool,
) -> Result<(), String> {
    let created = if nonzero_created {
        "2026-09-08T10:11:12Z"
    } else {
        "0001-01-01T00:00:00Z"
    };
    let manifest = serde_json::json!({
        "version": 1,
        "generation": 2147483647i64,
        "created": created,
        "updated": "0001-01-01T00:00:00Z",
        "entries": {}
    });
    let plaintext = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let recipient = parse_recipient(&recipient_string(identity)).map_err(|e| e.to_string())?;
    let ciphertext = encrypt(&plaintext, &[recipient]).map_err(|e| e.to_string())?;
    fs::write(root.join("manifest.age"), ciphertext).map_err(|e| e.to_string())
}

fn main() {
    match run() {
        Ok(outcome) => {
            serde_json::to_writer(io::stdout(), &outcome).unwrap();
            println!();
        }
        Err(error) => {
            eprintln!("manifest-sequence-adapter: {error}");
            process::exit(1);
        }
    }
}

fn seed_i64max_manifest(
    root: &std::path::Path,
    identity: &symvault_crypto::Identity,
) -> Result<(), String> {
    let manifest = serde_json::json!({
        "version": 1,
        "generation": 9223372036854775807i64,
        "created": "0001-01-01T00:00:00Z",
        "updated": "0001-01-01T00:00:00Z",
        "entries": {}
    });
    let plaintext = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let recipient = parse_recipient(&recipient_string(identity)).map_err(|e| e.to_string())?;
    let ciphertext = encrypt(&plaintext, &[recipient]).map_err(|e| e.to_string())?;
    fs::write(root.join("manifest.age"), ciphertext).map_err(|e| e.to_string())
}
