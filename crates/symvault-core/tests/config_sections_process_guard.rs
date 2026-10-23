//! CFG-003: the process-wide once-only guard for `clipboard.printByDefault`.
//!
//! Go keeps the guard in a package-level atomic, so the deprecation warning
//! appears on the first load that meets the key and never again in that
//! process. This lives in its own test binary — a process of its own — because
//! the guard is global and no other test may touch it first.

use symvault_core::config::Config;

const DOCUMENT: &[u8] = b"clipboard:\n  printByDefault: false\n";
const WARNING: &str = "clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead";

#[test]
fn the_process_guard_warns_once_and_a_discarded_load_does_not_consume_it() {
    // A load that drops its warnings has shown the operator nothing, so it must
    // leave the message available for a load that does.
    Config::load_from_bytes(DOCUMENT).expect("document loads");
    Config::load_from_bytes(DOCUMENT).expect("document loads again");

    let (_, first) = Config::load_from_bytes_with_warnings(DOCUMENT).expect("loads");
    assert_eq!(
        first,
        vec![WARNING.to_owned()],
        "first reporting load warns"
    );

    let (_, second) = Config::load_from_bytes_with_warnings(DOCUMENT).expect("loads");
    assert!(second.is_empty(), "the warning fires once per process");

    // The guard covers only this key; the others warn on every load.
    let (_, other) =
        Config::load_from_bytes_with_warnings(b"envWhitelist:\n  - HOME\n").expect("loads");
    assert_eq!(other.len(), 1, "envWhitelist still warns on a later load");
}
