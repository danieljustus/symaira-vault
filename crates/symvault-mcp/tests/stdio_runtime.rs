use std::io::{BufRead, Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use symvault_mcp::{ProtocolHandler, run_stdio, run_stdio_until};

#[test]
fn stdio_transport_flushes_initialize_and_call_responses() {
    let input = Cursor::new(
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health","arguments":{}}}
"#,
    );
    let mut output = Vec::new();
    let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
    run_stdio(input, &mut output, &mut handler).expect("stdio loop succeeds");
    let responses = String::from_utf8(output).expect("responses are UTF-8");
    assert_eq!(responses.lines().count(), 2);
    assert!(responses.contains(r#""id":1"#));
    assert!(responses.contains(r#""id":2"#));
}

#[test]
fn stdio_transport_drops_unterminated_final_fragment() {
    let input = Cursor::new(
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health","arguments":{}}}"#,
    );
    let mut output = Vec::new();
    let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
    run_stdio(input, &mut output, &mut handler).expect("stdio loop succeeds");
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
}

/// Raises the shutdown flag the first time the loop blocks to read, like a
/// SIGTERM arriving while the server waits for its next frame.
struct SignalWhileBlocked<'a> {
    inner: Cursor<&'static [u8]>,
    flag: &'a AtomicBool,
}

impl Read for SignalWhileBlocked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl BufRead for SignalWhileBlocked<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.flag.store(true, Ordering::Release);
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}

#[test]
fn cancelled_stdio_answers_the_frame_it_was_blocked_on_then_stops() {
    // Go checks its context only between frames: a read already blocked when
    // the signal arrives still yields one answered frame, and no more.
    let flag = AtomicBool::new(false);
    let input = SignalWhileBlocked {
        inner: Cursor::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}
{"jsonrpc":"2.0","id":2,"method":"ping"}
"#,
        ),
        flag: &flag,
    };
    let mut output = Vec::new();
    let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
    run_stdio_until(input, &mut output, &mut handler, || {
        flag.load(Ordering::Acquire)
    })
    .expect("cancelled stdio loop succeeds");
    let responses = String::from_utf8(output).unwrap();
    assert_eq!(responses.lines().count(), 1, "{responses}");
    assert!(responses.contains(r#""id":1"#));
}

#[test]
fn stdio_cancelled_before_the_first_read_answers_nothing() {
    let input = Cursor::new(
        &br#"{"jsonrpc":"2.0","id":1,"method":"ping"}
"#[..],
    );
    let mut output = Vec::new();
    let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
    run_stdio_until(input, &mut output, &mut handler, || true).expect("loop succeeds");
    assert!(output.is_empty());
}
