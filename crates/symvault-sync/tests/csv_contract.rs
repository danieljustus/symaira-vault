use base64::Engine;
use serde_json::Value;
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
        let result = importer::parse(format, &input);
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
