#![no_main]

//! Import path normaliser (Go `FuzzNormalizePath`) and prefix joiner.

use libfuzzer_sys::fuzz_target;
use symvault_sync::importer::{apply_prefix, normalize_path};

fuzz_target!(|input: &[u8]| {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let normalized = normalize_path(text);
    assert_eq!(normalized, normalize_path(text), "non-deterministic path");
    assert!(!normalized.contains(".."), "parent segment survived");
    assert!(!normalized.contains(' '), "space survived");
    for forbidden in ['"', '*', '?', '<', '>', '|', ':', '\\'] {
        assert!(!normalized.contains(forbidden), "{forbidden:?} survived");
    }
    // Joining two normalised halves must not reintroduce a parent segment and
    // must keep the path half verbatim at the end (apply_prefix only trims the
    // prefix, so the prefix side is not compared byte for byte).
    let mid = text.len() / 2;
    if text.is_char_boundary(mid) {
        let (prefix, path) = text.split_at(mid);
        let (prefix, path) = (normalize_path(prefix), normalize_path(path));
        let joined = apply_prefix(&prefix, &path);
        assert!(
            !joined.contains(".."),
            "parent segment after join: {joined:?}"
        );
        assert!(
            joined.ends_with(&path),
            "path half lost: {joined:?} / {path:?}"
        );
    }
});
