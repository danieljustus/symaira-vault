#![no_main]

//! CSV importer (generic + Apple/Chrome/Firefox profiles) over untrusted bytes.
//! Mirrors Go `FuzzCSVImporterParse`: no panic and a deterministic outcome.
//! The first input byte selects the profile; the rest is the CSV source.

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::{
    Format, csv_header_record, detect_csv_profile, parse, parse_csv_profile,
};

const FORMATS: [Format; 4] = [Format::Csv, Format::Apple, Format::Chrome, Format::Firefox];

fuzz_target!(|input: &[u8]| {
    let Some((&selector, csv)) = input.split_first() else {
        return;
    };
    let format = FORMATS[usize::from(selector) % FORMATS.len()];

    let first = parse_csv_profile(format, csv, None);
    let second = parse_csv_profile(format, csv, None);
    match (&first, &second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "non-deterministic CSV entries"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("non-deterministic CSV outcome"),
    }

    // The dispatching entrypoint must agree with the direct call.
    let dispatched = parse(format, csv);
    assert_eq!(first.is_ok(), dispatched.is_ok());

    // Header sniffing as the CLI does it before choosing a profile.
    if let Some(header) = csv_header_record(csv) {
        let _ = detect_csv_profile(&header);
    }
});
