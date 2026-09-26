use std::{
    net::{SocketAddr, TcpListener},
    sync::{Arc, atomic::AtomicBool},
};

pub(crate) fn validate_address(address: &str) -> Result<SocketAddr, String> {
    let address = address
        .parse::<SocketAddr>()
        .map_err(|_| "broker address must be a socket address".to_owned())?;
    if !address.ip().is_loopback() {
        return Err("broker listener must bind to a loopback address".into());
    }
    Ok(address)
}

pub(crate) fn bind(address: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(address).map_err(|error| format!("listen on {address}: {error}"))
}

pub(crate) fn serve(
    listener: TcpListener,
    strict: bool,
    passthrough: Vec<String>,
) -> Result<(), String> {
    let proxy_url = format!(
        "http://{}",
        listener.local_addr().map_err(|error| error.to_string())?
    );
    println!("Symaira Vault egress broker listening on {proxy_url}");
    println!(
        "Rust broker supports only explicit --passthrough CONNECT tunnels; template TLS interception and credential injection are unavailable."
    );
    println!("Export the following in the agent's environment:");
    println!("  HTTPS_PROXY={proxy_url}");
    println!("  HTTP_PROXY={proxy_url}");
    println!("  NO_PROXY=127.0.0.1,localhost");
    if strict {
        println!("Strict mode: requests outside the passthrough allowlist are rejected with 403.");
    }
    println!("Passthrough hosts (no TLS interception): {passthrough:?}");
    let stopping = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stopping))
        .map_err(|error| format!("register broker interrupt handler: {error}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stopping))
        .map_err(|error| format!("register broker termination handler: {error}"))?;
    symvault_mcp::broker::serve_connect_passthrough(listener, passthrough, strict, &stopping, false)
}
