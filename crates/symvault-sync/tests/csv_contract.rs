use base64::Engine;
use serde_json::Value;
use std::collections::BTreeMap;
use symvault_sync::importer::{self, Format};

#[test]
fn csv_profiles_and_paths_match_production_go() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/sync/csv.json")).unwrap();
    assert_eq!(
        fixture["commit"],
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    let mut bitwarden_cases = 0usize;
    let mut dispatch_cases = 0usize;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["format"].as_str().unwrap();
        // Go's importer.New resolves the name exactly; a name without an
        // importer (the generic json/yaml extensions, a wrong-case or padded
        // name) fails before any input is read.
        let format = match importer::format_from_name(name) {
            Ok(format) => format,
            Err(error) => {
                assert!(case["failed"].as_bool().unwrap(), "{}", case["name"]);
                assert_eq!(
                    error.to_string(),
                    case["error"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(case["entries"], serde_json::json!([]), "{}", case["name"]);
                dispatch_cases += 1;
                continue;
            }
        };
        let input = case
            .get("input_b64")
            .and_then(Value::as_str)
            .map(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap_or_else(|error| {
                        panic!("{} has invalid input_b64: {error}", case["name"])
                    })
            })
            .unwrap_or_else(|| {
                case.get("input")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .as_bytes()
                    .to_vec()
            });
        let result = if let Some(mapping) = case.get("mapping").and_then(Value::as_str) {
            let (field, column) = mapping
                .split_once('=')
                .unwrap_or_else(|| panic!("{} has invalid mapping", case["name"]));
            let mapping = BTreeMap::from([(field.to_owned(), column.to_owned())]);
            importer::parse_csv(&input, Some(&mapping))
        } else {
            importer::parse(format, &input)
        };
        assert_eq!(
            result.is_err(),
            case["failed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        if format == Format::Bitwarden {
            bitwarden_cases += 1;
            // Bitwarden diagnostics are Go's encoding/json text, byte for byte.
            let actual = result.as_ref().err().map(ToString::to_string);
            assert_eq!(
                actual.as_deref().unwrap_or(""),
                case.get("error").and_then(Value::as_str).unwrap_or(""),
                "{}",
                case["name"]
            );
        }
        if let Ok(entries) = result {
            assert_eq!(
                serde_json::to_value(entries).unwrap(),
                case["entries"],
                "{}",
                case["name"]
            );
        }
    }
    let expected_bitwarden = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["format"] == "bitwarden")
        .count();
    let expected_dispatch = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| importer::format_from_name(case["format"].as_str().unwrap()).is_err())
        .count();
    assert_eq!(bitwarden_cases, expected_bitwarden);
    assert_eq!(dispatch_cases, expected_dispatch);
    // Guard against a fixture that silently loses its Bitwarden/dispatch corpus.
    assert!(bitwarden_cases >= 171, "{bitwarden_cases} bitwarden cases");
    assert_eq!(dispatch_cases, 6);
    for (input, expected) in fixture["paths"].as_object().unwrap() {
        assert_eq!(importer::normalize_path(input), expected.as_str().unwrap());
    }
    for (input, expected) in fixture["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .zip(fixture["prefix_results"].as_array().unwrap())
    {
        assert_eq!(
            importer::apply_prefix(input[0].as_str().unwrap(), input[1].as_str().unwrap()),
            expected.as_str().unwrap()
        );
    }
}

/// Go keeps an imported path as raw bytes; the text form (one U+FFFD per
/// invalid byte) is what `encoding/json` emits, so two paths that differ only
/// in their invalid bytes are the same text but still two paths.
#[test]
fn chrome_csv_keeps_distinct_invalid_byte_paths() {
    let input = b"name,url,username,password,note\n\xFF,https://one.example,u1,p1,\n\xFE,https://two.example,u2,p2,\n\xFF,https://three.example,u3,p3,\n";
    let entries = importer::parse(Format::Chrome, input).expect("Go imports these rows");
    let paths: Vec<&[u8]> = entries.iter().map(|entry| entry.path_bytes()).collect();
    assert_eq!(paths, [&b"\xFF"[..], b"\xFE", b"\xFF-2"]);
    assert_eq!(entries[0].path, "\u{FFFD}");
    assert_eq!(entries[1].path, "\u{FFFD}");
    assert_eq!(entries[2].path, "\u{FFFD}-2");
    assert_eq!(entries[0].raw_path.as_deref(), Some(&b"\xFF"[..]));
    // A valid path carries no raw copy: the text is the path.
    let valid = importer::parse(
        Format::Chrome,
        b"name,url,username,password,note\nok,https://a.example,u,p,\n",
    )
    .unwrap();
    assert_eq!(valid[0].raw_path, None);
    assert_eq!(valid[0].path_bytes(), b"ok");
}

#[test]
fn generic_csv_keeps_equal_invalid_paths_and_raw_value_lengths() {
    let input = b"title,password,notes\n\xFF,pw\xFF\xFE,n\xE2\x82\n\xFF,\xC3\xA9,\n";
    let entries = importer::parse(Format::Csv, input).expect("generic CSV never collides");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path_bytes(), b"\xFF");
    assert_eq!(entries[1].path_bytes(), b"\xFF");
    // The stored text re-encodes every invalid byte; Go's 4096-byte limit
    // counts the bytes of the imported string.
    assert_eq!(entries[0].data["password"], "pw\u{FFFD}\u{FFFD}");
    assert_eq!(entries[0].value_len("password"), Some(4));
    assert_eq!(entries[0].value_len("notes"), Some(3));
    assert_eq!(entries[0].data["notes"], "n\u{FFFD}\u{FFFD}");
    // A valid value keeps its text length and needs no raw length.
    assert_eq!(entries[1].value_len("password"), Some(2));
    assert!(entries[1].raw_value_len.is_empty());
    assert_eq!(entries[1].value_len("absent"), None);
}

#[test]
fn csv_profile_paths_from_a_url_host_are_text() {
    // `strings.ToLower` turns an invalid byte into U+FFFD before the path is
    // normalized, so a host path is valid text and de-duplicates as text.
    let input = b"name,url,username,password,note\n,https://a\xFF.example/x,u,p,\n,https://a\xFE.example/x,u,p,\n";
    let entries = importer::parse(Format::Chrome, input).unwrap();
    assert_eq!(entries[0].path, "a\u{FFFD}.example");
    assert_eq!(entries[1].path, "a\u{FFFD}.example-2");
    assert_eq!(entries[0].raw_path, None);
}

#[test]
fn imported_totp_matches_production_go_validation_and_shape() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/sync/csv.json")).unwrap();
    for case in fixture["totps"].as_array().unwrap() {
        match importer::parse_totp(case["input"].as_str().unwrap()) {
            Ok(value) => {
                assert_eq!(case["error"], "");
                assert_eq!(value, case["value"]);
            }
            Err(error) => {
                assert_eq!(error, case["error"].as_str().unwrap(), "{}", case["input"]);
            }
        }
    }
}

#[test]
fn csv_detection_matches_production_profile_priority() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/sync/csv.json")).unwrap();
    for (header, expected) in fixture["headers"]
        .as_array()
        .unwrap()
        .iter()
        .zip(fixture["detected"].as_array().unwrap())
    {
        let header: Vec<String> = serde_json::from_value(header.clone()).unwrap();
        let actual = match importer::detect_csv_profile(&header) {
            Format::Apple => "apple",
            Format::Chrome => "chrome",
            Format::Firefox => "firefox",
            Format::Csv => "csv",
            _ => unreachable!(),
        };
        assert_eq!(actual, expected.as_str().unwrap(), "{header:?}");
    }
}
