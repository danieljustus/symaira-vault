//! Private native contract launcher; this is not a shipped CLI command.
use std::{net::TcpListener, sync::atomic::AtomicBool};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    println!("{}", listener.local_addr().unwrap());
    symvault_mcp::broker::serve_connect_passthrough(
        listener,
        vec!["127.0.0.1".into()],
        true,
        &AtomicBool::new(false),
        true,
    )
    .unwrap();
}
