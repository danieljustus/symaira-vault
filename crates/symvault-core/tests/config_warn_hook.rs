//! CONFIG-RESID: the process-wide warning sink, Go's `config.SetWarnFunc`.
//!
//! A process of its own, because the sink and the `clipboard.printByDefault`
//! guard are global.

use std::sync::Mutex;

use symvault_core::config::{Config, set_warn_hook};

static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record(message: &str) {
    SEEN.lock().expect("sink").push(message.to_owned());
}

fn take() -> Vec<String> {
    std::mem::take(&mut *SEEN.lock().expect("sink"))
}

const ENV: &str =
    "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead";
const APPROVAL: &str = "approval_required is deprecated and will be removed in a future version";
const PRINT: &str = "clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead";

#[test]
fn the_sink_receives_every_load_warning_even_when_the_load_fails() {
    // Without a sink a load drops its warnings and does not use up the
    // once-per-process guard.
    Config::load_from_bytes(b"clipboard:\n  printByDefault: true\n").expect("loads");
    assert!(take().is_empty());

    assert!(set_warn_hook(record));
    assert!(!set_warn_hook(record), "one sink per process");

    // One load, one warning per deprecated key, in Go's load order.
    Config::load_from_bytes(
        b"clipboard:\n  printByDefault: true\nmcp:\n  approval_required: true\nenvWhitelist: [a]\n",
    )
    .expect("loads");
    assert_eq!(take(), [ENV, APPROVAL, PRINT]);

    // printByDefault warns once per process; the others on every load.
    Config::load_from_bytes(
        b"clipboard:\n  printByDefault: true\nmcp:\n  approval_required: true\nenvWhitelist: [a]\n",
    )
    .expect("loads");
    assert_eq!(take(), [ENV, APPROVAL]);

    // Go warns and then rejects: the warning is not lost with the document.
    let error = Config::load_from_bytes(b"envWhitelist: [a]\nmcp:\n  bind: ''\n")
        .expect_err("empty bind is rejected");
    assert_eq!(error.to_string(), "mcp.bind must not be empty");
    assert_eq!(take(), [ENV]);

    // A document that does not decode warns about nothing, a null list is nil.
    Config::load_from_bytes(b"envWhitelist: [a]\nmcp:\n  port: abc\n").expect_err("type error");
    Config::load_from_bytes(b"envWhitelist: null\n").expect("loads");
    assert!(take().is_empty());
}
