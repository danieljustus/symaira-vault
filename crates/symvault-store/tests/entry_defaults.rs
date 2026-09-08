use symvault_store::Entry;

#[test]
fn missing_entry_times_use_go_zero_time_on_wire() {
    let serialized = serde_json::to_value(Entry::default()).unwrap();
    assert_eq!(serialized["meta"]["created"], "0001-01-01T00:00:00Z");
    assert_eq!(serialized["meta"]["updated"], "0001-01-01T00:00:00Z");

    let decoded: Entry = serde_json::from_value(serde_json::json!({
        "data": {},
        "meta": {},
        "secret_meta": {}
    }))
    .unwrap();
    assert_eq!(decoded.metadata.created, "0001-01-01T00:00:00Z");
    assert_eq!(decoded.metadata.updated, "0001-01-01T00:00:00Z");
}
