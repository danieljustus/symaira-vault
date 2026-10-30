use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use symvault_sync::importer::parse_1pux;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    kind: String,
    input_base64: Option<String>,
    #[cfg(unix)]
    #[serde(default)]
    files: Vec<PassFile>,
    expected: Vec<Value>,
    failed: bool,
    error_contains: Option<String>,
    /// Go's complete error text (mutation cases).
    error: Option<String>,
}

#[test]
fn onepux_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/onepass.json"
    )))
    .expect("parse source-bound fixture");

    let cases: Vec<Case> = fixture
        .cases
        .into_iter()
        .filter(|case| case.kind == "onepux")
        .collect();
    // 9 named cases plus the generated mutation sweep over the reference export.
    assert_eq!(cases.len(), 206, "fixture cardinality is part of the gate");
    let mut failures = Vec::new();
    for case in cases {
        let name = &case.name;
        let input = base64::engine::general_purpose::STANDARD
            .decode(case.input_base64.as_deref().expect("onepux input"))
            .expect("decode onepux input");
        let result = parse_1pux(&input);
        if case.failed {
            match result {
                Ok(entries) => {
                    failures.push(format!("{name}: rust accepted {} entries", entries.len()))
                }
                Err(error) => {
                    let text = error.to_string();
                    if let Some(go) = &case.error {
                        if &text != go {
                            failures.push(format!(
                                "{name}: error differs\n  go:   {go}\n  rust: {text}"
                            ));
                        }
                    } else if let Some(expected) = &case.error_contains
                        && !text.contains(expected)
                    {
                        failures.push(format!("{name}: error {text:?} lacks {expected:?}"));
                    }
                }
            }
        } else {
            match result {
                Ok(entries) => {
                    let actual = serde_json::to_value(entries).expect("serialize onepux entries");
                    if actual != Value::Array(case.expected.clone()) {
                        failures.push(format!(
                            "{name}: entries differ\n  go:   {}\n  rust: {actual}",
                            Value::Array(case.expected)
                        ));
                    }
                }
                Err(error) => failures.push(format!("{name}: rust error {error}")),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} 1PUX cases differ from Go:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[cfg(unix)]
#[derive(Deserialize)]
struct PassFile {
    path: String,
    #[serde(default)]
    content: String,
    content_base64: Option<String>,
}

#[cfg(unix)]
impl PassFile {
    fn bytes(&self) -> Vec<u8> {
        self.content_base64
            .as_deref()
            .map(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .unwrap()
            })
            .unwrap_or_else(|| self.content.as_bytes().to_vec())
    }
}

#[cfg(unix)]
#[test]
fn pass_content_matches_source_bound_go_fixture() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/sync/onepass.json")).unwrap();
    for case in fixture.cases.into_iter().filter(|c| c.kind == "pass") {
        let mut files = case.files;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let expected: Vec<symvault_sync::importer::ImportedEntry> =
            serde_json::from_value(Value::Array(case.expected)).expect("Go oracle entries");
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("store");
        for file in files {
            let path = store.join(&file.path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, file.bytes()).unwrap();
        }
        let gpg = root.path().join("fake-gpg");
        std::fs::write(&gpg, "#!/bin/sh\ncat \"$4\"\n").unwrap();
        std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            symvault_sync::importer::import_pass_with_gpg(&store, &gpg).unwrap(),
            expected
        );
    }
}
