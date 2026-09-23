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
    for case in fixture["cases"].as_array().unwrap() {
        let format = match case["format"].as_str().unwrap() {
            "csv" => Format::Csv,
            "bitwarden" => Format::Bitwarden,
            "apple" => Format::Apple,
            "chrome" => Format::Chrome,
            "firefox" => Format::Firefox,
            _ => unreachable!(),
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
        if case["name"] == "chrome_distinct_invalid_titles" {
            let error = result.expect_err("Rust cannot safely represent these distinct Go paths");
            assert!(error.to_string().contains("distinct CSV paths"));
            continue;
        }
        assert_eq!(
            result.is_err(),
            case["failed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        if let Ok(entries) = result {
            assert_eq!(
                serde_json::to_value(entries).unwrap(),
                case["entries"],
                "{}",
                case["name"]
            );
        }
    }
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

#[test]
fn chrome_csv_rejects_distinct_invalid_byte_paths_that_collapse_in_rust() {
    let input = b"name,url,username,password,note\n\xFF,https://one.example,u1,p1,\n\xFE,https://two.example,u2,p2,\n";
    let error = importer::parse(Format::Chrome, input)
        .expect_err("distinct byte paths cannot share one Rust UTF-8 path");
    assert!(error.to_string().contains("distinct CSV paths"));
    assert!(error.to_string().contains('\u{FFFD}'));
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

#[test]
fn delimited_and_bitwarden_parsers_accept_inputs_over_100_mib() {
    const LIMIT: usize = 100 * 1024 * 1024;
    let large_field = "x".repeat(LIMIT + 1);
    let mut csv = b"title,username,password,url,notes,otp,name,note,OTPAuth,ignored\nentry,user,pw,https://example.test,n,,entry,n,,".to_vec();
    csv.extend_from_slice(large_field.as_bytes());
    csv.push(b'\n');
    for format in [Format::Csv, Format::Apple, Format::Chrome, Format::Firefox] {
        let entries = importer::parse(format, &csv)
            .unwrap_or_else(|error| panic!("{format:?} rejected CSV over 100 MiB: {error}"));
        assert_eq!(entries.len(), 1, "{format:?}");
    }

    let mut bitwarden = br#"{"items":[{"type":1,"name":"entry","notes":""#.to_vec();
    bitwarden.extend_from_slice(large_field.as_bytes());
    bitwarden.extend_from_slice(br#""}]}"#);
    let entries = importer::parse(Format::Bitwarden, &bitwarden)
        .expect("Bitwarden parser accepts input over 100 MiB");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].data["notes"].as_str().unwrap().len(), LIMIT + 1);
}
