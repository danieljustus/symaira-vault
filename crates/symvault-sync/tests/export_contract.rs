use serde::Deserialize;
use std::collections::BTreeMap;
use symvault_sync::export::{self, ExportEntry};
#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    entries: Vec<ExportEntry>,
    mapping: Option<BTreeMap<String, String>>,
    json: String,
    csv: String,
    notices: String,
}
#[test]
fn export_matches_production_go_bytes_and_attachment_notices() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/sync/export.json")).unwrap();
    assert_eq!(fixture.cases.len(), 5);
    for case in fixture.cases {
        let mapping = case.mapping.unwrap_or_default();
        let (mut json, mut csv, mut notices) = (Vec::new(), Vec::new(), Vec::new());
        export::json_with_mapping(&mut json, &case.entries, &mapping).unwrap();
        export::csv_with_mapping(&mut csv, &case.entries, &mapping, Some(&mut notices)).unwrap();
        let mut streamed = Vec::new();
        let mut stream = export::JsonStream::new(&mut streamed, &mapping);
        for entry in &case.entries {
            stream.write_entry(entry).unwrap();
        }
        stream.finish().unwrap();
        assert_eq!(
            streamed,
            case.json.as_bytes(),
            "{} streamed JSON",
            case.name
        );
        assert_eq!(json, case.json.as_bytes(), "{} JSON", case.name);
        assert_eq!(csv, case.csv.as_bytes(), "{} CSV", case.name);
        assert_eq!(notices, case.notices.as_bytes(), "{} notices", case.name);
    }
}

#[test]
fn export_propagates_output_and_notice_failures() {
    struct Fail;
    impl std::io::Write for Fail {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic sink failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let entries = [ExportEntry {
        path: "fixture".into(),
        data: BTreeMap::from([("file_b64_0".into(), serde_json::json!("synthetic"))]),
    }];
    assert!(
        export::JsonStream::new(&mut Fail, &BTreeMap::new())
            .finish()
            .is_err()
    );
    assert!(export::json(&mut Fail, &entries).is_err());
    assert!(export::csv(&mut Fail, &entries).is_err());
    assert!(
        export::csv_with_mapping(Vec::new(), &entries, &BTreeMap::new(), Some(&mut Fail)).is_err()
    );
}
