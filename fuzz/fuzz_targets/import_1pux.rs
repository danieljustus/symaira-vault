#![no_main]

//! 1Password 1PUX (zip) importer over untrusted bytes (Go `FuzzOnePUXImporterParse`).

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::parse_1pux;

fuzz_target!(|input: &[u8]| {
    let first = parse_1pux(input);
    let second = parse_1pux(input);
    match (first, second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "non-deterministic 1PUX entries"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("non-deterministic 1PUX outcome"),
    }
});
