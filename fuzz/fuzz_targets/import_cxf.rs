#![no_main]

//! FIDO Credential Exchange Format (zip) importer over untrusted bytes.
//! The Go fuzzers had no CXF target; the parser shares the zip/JSON surface
//! with 1PUX and is equally untrusted input.

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::parse_cxf;

fuzz_target!(|input: &[u8]| {
    let first = parse_cxf(input);
    let second = parse_cxf(input);
    match (first, second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "non-deterministic CXF entries"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("non-deterministic CXF outcome"),
    }
});
