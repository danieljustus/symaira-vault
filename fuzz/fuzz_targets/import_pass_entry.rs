#![no_main]

//! `pass` entry parser (Go `FuzzParsePassEntry`) and the TOTP normaliser it
//! feeds (Go `FuzzParseTOTP`). `import_pass` itself walks a directory and runs
//! gpg, so it is not fuzzed here; this is its pure decrypted-bytes parser.
//! The first input byte selects the target (even: pass entry, odd: TOTP).

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use symvault_sync::importer::{parse_pass_entry_bytes, parse_totp_bytes};

fuzz_target!(|input: &[u8]| {
    let Some((&selector, content)) = input.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        let entry = parse_pass_entry_bytes(Path::new("fuzz/entry"), content);
        assert!(
            entry.data.contains_key("password"),
            "password key missing in pass entry"
        );
        assert_eq!(
            entry,
            parse_pass_entry_bytes(Path::new("fuzz/entry"), content),
            "non-deterministic pass entry"
        );
    } else {
        let first = parse_totp_bytes(content);
        assert_eq!(first, parse_totp_bytes(content), "non-deterministic TOTP");
        if let Ok(Value::Object(object)) = first {
            match object.get("secret") {
                Some(Value::String(secret)) => assert!(!secret.is_empty()),
                other => panic!("TOTP secret missing or not a string: {other:?}"),
            }
        }
    }
});
