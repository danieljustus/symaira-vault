use serde_json::Value;
use std::collections::BTreeSet;
use symvault_mcp::{ProtocolHandler, handle_line};

fn normalize_text(text: &str) -> (String, usize) {
    let mut output = String::new();
    let mut remaining = text;
    let mut seen = BTreeSet::new();
    while let Some(start) = remaining.find("<!-- DATA_") {
        output.push_str(&remaining[..start]);
        remaining = &remaining[start..];
        let marker = remaining.get(10..26).expect("16-byte marker");
        assert!(
            marker
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert!(remaining[26..].starts_with(" label="));
        let open_end = remaining.find(" -->").expect("opening boundary") + 4;
        let close = format!("<!-- /DATA_{marker} -->");
        let close_start = remaining[open_end..]
            .find(&close)
            .expect("matching closing boundary")
            + open_end;
        assert!(
            seen.insert(marker.to_owned()),
            "marker reused between independent wrappers"
        );
        let placeholder = format!("<MARKER_{}>", seen.len());
        output.push_str(&remaining[..open_end].replacen(marker, &placeholder, 1));
        output.push_str(&remaining[open_end..close_start]);
        output.push_str(&close.replacen(marker, &placeholder, 1));
        remaining = &remaining[close_start + close.len()..];
    }
    output.push_str(remaining);
    (output, seen.len())
}

fn normalize(value: &mut Value) -> usize {
    match value {
        Value::String(s) => {
            let (text, count) = normalize_text(s);
            *s = text;
            count
        }
        Value::Array(items) => items.iter_mut().map(normalize).sum(),
        Value::Object(map) => map.values_mut().map(normalize).sum(),
        _ => 0,
    }
}

#[test]
fn prompts_replay_real_go_protocol_with_validated_random_boundaries() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/mcp/prompts.json")).unwrap();
    assert_eq!(
        fixture["oracle"]["commit_sha"],
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    for case in fixture["cases"].as_array().unwrap() {
        let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
        let mut actual = Vec::new();
        let mut counts = Vec::new();
        for input in case["input"].as_array().unwrap() {
            if let Some(response) = handle_line(input.as_str().unwrap(), &mut handler).unwrap() {
                let mut value: Value = serde_json::from_str(&response).unwrap();
                if value["error"]["data"].is_string() {
                    assert!(!value["error"]["data"].as_str().unwrap().is_empty());
                    value["error"]["data"] = Value::String("<runtime-error-text>".into());
                }
                counts.push(normalize(&mut value));
                actual.push(value);
            }
        }
        assert_eq!(
            serde_json::to_value(counts).unwrap(),
            case["marker_counts"],
            "{}",
            case["name"]
        );
        assert_eq!(Value::Array(actual), case["output"], "{}", case["name"]);
    }
}
