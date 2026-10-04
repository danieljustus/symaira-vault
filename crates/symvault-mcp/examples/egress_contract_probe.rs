//! Private native fixture launcher. It is not part of the installed CLI.
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpListener,
    path::PathBuf,
};
use symvault_mcp::broker::{EgressBroker, EgressOptions};

fn main() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let value = |name: &str| {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let root = PathBuf::from(value("--root").ok_or("private fixture root required")?);
    let identity_bytes =
        symvault_sync::safeio::read_bounded(&root.join("identity.age"), 24 * 1024 * 1024)
            .map_err(|_| "read private fixture identity")?
            .ok_or("missing private fixture identity")?;
    let identity = symvault_crypto::decrypt_identity(
        &identity_bytes,
        &symvault_crypto::SecretBytes::new(b"correct horse battery staple"),
    )
    .map_err(|_| "unlock private fixture")?;
    let store = symvault_store::Store::open_with_legacy_migration(&root, &identity)
        .map_err(|_| "open private fixture")?;
    let broker = EgressBroker::new(
        &root,
        &store,
        &identity,
        EgressOptions {
            strict: args.iter().any(|a| a == "--strict=true"),
            allow_private: args.iter().any(|a| a == "--allow-private=true"),
            passthrough: value("--passthrough")
                .map(|v| vec![v.to_owned()])
                .unwrap_or_default(),
            upstream_ca_pem: value("--upstream-ca")
                .map(fs::read)
                .transpose()
                .map_err(|_| "read fixture root")?,
        },
    )?;
    symvault_sync::safeio::write_atomic(&root.join("probe-ca.pem"), broker.ca_pem().as_bytes())
        .map_err(|_| "write fixture broker root")?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "bind private fixture")?;
    println!(
        "{}",
        listener
            .local_addr()
            .map_err(|_| "inspect fixture address")?
    );
    io::stdout().flush().map_err(|_| "flush fixture startup")?;
    broker.with_running(listener, || {
        let mut stop = [0];
        let _ = io::stdin().read_exact(&mut stop);
        Ok(())
    })
}
