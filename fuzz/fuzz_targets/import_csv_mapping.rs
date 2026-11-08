#![no_main]

//! CSV field-mapping parser (`--mapping field=column,...`) and its use by the
//! CSV importer. Mirrors Go `FuzzParseMapping`. Input layout: the first line
//! is the mapping text, the remainder is the CSV source.

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::{parse_csv, parse_mapping};

fuzz_target!(|input: &[u8]| {
    let split = input
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(input.len());
    let (mapping_bytes, rest) = input.split_at(split);
    let csv = rest.get(1..).unwrap_or_default();
    let Ok(mapping_text) = std::str::from_utf8(mapping_bytes) else {
        return;
    };

    let first = parse_mapping(mapping_text);
    let second = parse_mapping(mapping_text);
    assert_eq!(first, second, "non-deterministic mapping");

    if mapping_text.is_empty() {
        assert_eq!(first, Ok(Default::default()), "empty mapping is empty");
    }
    if let Ok(mapping) = &first {
        for (field, column) in mapping {
            assert!(!field.is_empty() && !column.is_empty());
            assert_eq!(field.trim(), field);
            assert_eq!(column.trim(), column);
        }
        let a = parse_csv(csv, Some(mapping));
        let b = parse_csv(csv, Some(mapping));
        assert_eq!(a.is_ok(), b.is_ok(), "non-deterministic mapped CSV outcome");
        if let (Ok(a), Ok(b)) = (a, b) {
            assert_eq!(a, b);
        }
    }
});
