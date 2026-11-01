//! Replays the strings recorded from the pinned gopkg.in/yaml.v3
//! (`testdata/port/cli/yaml-scalars.json`, written and re-verified by
//! `scripts/rust-port/cmd/yamlscalargen`, `make yaml-scalar-differential`)
//! against the Rust renderer in six positions: map value, map key, sequence
//! item, a field of a mapping inside a sequence inside a mapping, a value two
//! mappings deep, and the document root. Every byte must match.

use std::path::Path;

use serde_json::Value;
use symvault_gojson::yaml::{Node, to_string};

const FIXTURE: &str = "../../testdata/port/cli/yaml-scalars.json";
const EXPECTED_ROWS: usize = 299;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    let raw = std::fs::read_to_string(&path).expect("read yaml-scalars fixture");
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse yaml-scalars fixture")
}

fn text(row: &Value, key: &str) -> String {
    row[key]
        .as_str()
        .unwrap_or_else(|| panic!("row field {key}"))
        .to_owned()
}

fn replay(row: &Value) -> Vec<String> {
    let value = text(row, "value");
    let string = |text: &str| Node::Str(text.to_owned());
    let positions: [(&str, Node); 6] = [
        ("map_value", Node::Map(vec![("k".into(), string(&value))])),
        ("map_key", Node::Map(vec![(value.clone(), string("v"))])),
        ("seq_item", Node::Seq(vec![string(&value)])),
        (
            "nested",
            Node::Map(vec![(
                "list".into(),
                Node::Seq(vec![Node::Map(vec![("k".into(), string(&value))])]),
            )]),
        ),
        (
            "deep",
            Node::Map(vec![(
                "a".into(),
                Node::Map(vec![(
                    "b".into(),
                    Node::Map(vec![("c".into(), string(&value))]),
                )]),
            )]),
        ),
        ("root", string(&value)),
    ];
    positions
        .iter()
        .filter_map(|(position, node)| {
            let want = text(row, position);
            let got = to_string(node);
            (want != got)
                .then(|| format!("{value:?} as {position}\n    want {want:?}\n    got  {got:?}"))
        })
        .collect()
}

#[test]
fn strings_render_like_the_pinned_yaml_v3_in_every_position() {
    let fixture = fixture();
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["provenance"]["module"], "gopkg.in/yaml.v3");
    assert_eq!(fixture["provenance"]["version"], "v3.0.1");
    let rows = fixture["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), EXPECTED_ROWS, "recorded values");
    let failures: Vec<String> = rows.iter().flat_map(replay).collect();
    assert!(
        failures.is_empty(),
        "{} of {} renders differ from yaml.v3:\n{}",
        failures.len(),
        rows.len() * 6,
        failures.join("\n")
    );
}

/// Negative control: a corrupted expectation is reported, so a green replay is
/// not a vacuous one.
#[test]
fn a_corrupted_expectation_is_detected() {
    let mut fixture = fixture();
    let row = &mut fixture["rows"][0];
    let corrupted = format!("{}x", text(row, "map_value"));
    row["map_value"] = Value::String(corrupted);
    assert_eq!(replay(row).len(), 1);
}
