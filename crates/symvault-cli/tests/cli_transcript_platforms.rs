//! Every Go transcript names the hosts it may be replayed on
//! (`replay_platforms`). A test whose recording is not valid for a host must be
//! visibly ignored there (`#[cfg_attr(not(target_os = "macos"), ignore = ...)]`),
//! never silently passed or compiled out; a test whose recording is valid for
//! Linux must not be gated.
#![deny(unsafe_code)]

use std::{fs, path::Path};

const KNOWN: [&str; 3] = ["linux", "macos", "windows"];

fn platforms(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .expect("replay_platforms is an array")
        .iter()
        .map(|p| p.as_str().expect("platform name").to_owned())
        .collect()
}

/// Attribute lines directly above `fn <name>(` in `source`, or `None`.
fn attributes_of<'a>(source: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let lines: Vec<&str> = source.lines().collect();
    let needle = format!("fn {name}(");
    let at = lines.iter().position(|l| {
        let t = l.trim_start();
        t.starts_with(&needle) || t.starts_with(&format!("pub {needle}"))
    })?;
    // Attributes (possibly wrapped by rustfmt) up to the previous item.
    let mut start = at;
    while start > 0 {
        let previous = lines[start - 1].trim();
        if previous.is_empty() || previous.ends_with('}') || previous.ends_with(';') {
            break;
        }
        start -= 1;
    }
    Some(lines[start..at].to_vec())
}

#[test]
fn transcripts_declare_replay_platforms_and_tests_are_gated_accordingly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let transcripts = root.join("../../testdata/port/cli-transcripts");
    let mut checked = 0;
    let mut gated = 0;
    for entry in fs::read_dir(&transcripts).expect("transcript directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let stem = file.split('.').next().unwrap().to_owned();
        let transcript: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read transcript")).expect("json");
        let default = platforms(
            transcript
                .get("replay_platforms")
                .unwrap_or_else(|| panic!("{file}: no replay_platforms")),
        );
        let source_path = root.join("tests").join(format!("{stem}.rs"));
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|e| panic!("{file}: test source {}: {e}", source_path.display()));
        for (test, record) in transcript["tests"].as_object().expect("tests") {
            let effective = record
                .get("replay_platforms")
                .map_or_else(|| default.clone(), platforms);
            assert!(!effective.is_empty(), "{file}::{test}: empty platform list");
            for platform in &effective {
                assert!(
                    KNOWN.contains(&platform.as_str()),
                    "{file}::{test}: unknown platform {platform}"
                );
            }
            let attributes = attributes_of(&source, test)
                .unwrap_or_else(|| panic!("{file}: no test function `{test}` in {stem}.rs"));
            // rustfmt may split the attribute over several lines.
            let attribute_text = attributes.join(" ");
            let is_gated = attribute_text.contains("cfg_attr(")
                && attribute_text.contains("target_os")
                && attribute_text.contains("ignore =")
                && attribute_text.contains("SKIP (");
            let needs_gate = !effective.iter().any(|p| p == "linux");
            assert_eq!(
                is_gated, needs_gate,
                "{file}::{test}: recorded for {effective:?}; the test must be visibly ignored \
                 on other hosts (cfg_attr(not(target_os = ...), ignore = \"SKIP (...)\")) \
                 exactly when linux is not listed"
            );
            checked += 1;
            gated += usize::from(is_gated);
        }
    }
    assert!(checked > 50, "only {checked} recorded tests checked");
    assert!(gated > 0 && gated < checked, "{gated}/{checked} gated");
}
