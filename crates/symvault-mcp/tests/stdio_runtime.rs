use std::io::Cursor;
use symvault_mcp::{ProtocolHandler, run_stdio};

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
