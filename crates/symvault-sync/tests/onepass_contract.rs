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
}

#[test]
fn onepux_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/onepass.json"
    )))
    .expect("parse source-bound fixture");

    for case in fixture
        .cases
        .into_iter()
        .filter(|case| case.kind == "onepux")
    {
        let input = base64::engine::general_purpose::STANDARD
            .decode(case.input_base64.expect("onepux input"))
            .expect("decode onepux input");
        let result = parse_1pux(&input);
        if case.failed {
            let error = result.expect_err(&case.name);
            if let Some(expected) = case.error_contains {
                assert!(
                    error.to_string().contains(&expected),
                    "{}: error {:?} did not contain {:?}",
                    case.name,
                    error,
                    expected
                );
            }
        } else {
            let entries = result.expect(&case.name);
            let actual = serde_json::to_value(entries).expect("serialize onepux entries");
            assert_eq!(actual, Value::Array(case.expected), "{}", case.name);
        }
    }
}

#[cfg(unix)]
#[derive(Deserialize)]
struct PassFile {
    path: String,
    content: String,
}

#[cfg(unix)]
#[test]
fn pass_content_matches_source_bound_go_fixture() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/sync/onepass.json")).unwrap();
    for case in fixture.cases.into_iter().filter(|c| c.kind == "pass") {
        let mut files = case.files;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let entries: Vec<_> = files
            .iter()
            .map(|f| {
                symvault_sync::importer::parse_pass_entry(std::path::Path::new(&f.path), &f.content)
            })
            .collect();
        // The oracle uses Unix filenames, including a literal backslash.
        #[cfg(unix)]
        assert_eq!(
            serde_json::to_value(&entries).unwrap(),
            Value::Array(case.expected)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let root = tempfile::tempdir().unwrap();
            let store = root.path().join("store");
            for file in files {
                let path = store.join(file.path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, file.content).unwrap();
            }
            let gpg = root.path().join("fake-gpg");
            std::fs::write(&gpg, "#!/bin/sh\ncat \"$4\"\n").unwrap();
            std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                symvault_sync::importer::import_pass_with_gpg(&store, &gpg).unwrap(),
                entries
            );
        }
    }
}
