#![no_main]

//! Bitwarden JSON importer over untrusted bytes (Go `FuzzBitwardenImporterParse`).

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::parse_bitwarden;

fuzz_target!(|input: &[u8]| {
    let first = parse_bitwarden(input);
    let second = parse_bitwarden(input);
    match (first, second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "non-deterministic Bitwarden entries"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("non-deterministic Bitwarden outcome"),
    }
});
