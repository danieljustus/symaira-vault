//! Standalone and child-owned broker share one runtime and credential boundary.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    net::{TcpListener, ToSocketAddrs},
    path::Path,
    sync::mpsc,
    time::Duration,
};
use symvault_crypto::Identity;
use symvault_mcp::broker::{EgressBroker, EgressOptions};
use symvault_store::Store;

fn prepare<'a>(
    root: &'a Path,
    store: &'a Store,
    identity: &'a Identity,
    addr: &str,
    strict: bool,
    passthrough: &[String],
) -> Result<(EgressBroker<'a>, TcpListener, BTreeMap<String, String>), String> {
    let broker = EgressBroker::new(
        root,
        store,
        identity,
        EgressOptions {
            strict,
            passthrough: parse_hosts(passthrough)?,
            ..EgressOptions::default()
        },
    )?;
    let addresses = addr
        .to_socket_addrs()
        .map_err(|_| "listen: invalid broker address")?
        .take(33)
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses.iter().any(|a| !a.ip().is_loopback())
    {
        return Err("listen: broker address must be loopback".into());
    }
    let listener = TcpListener::bind(addresses.as_slice())
        .map_err(|_| "listen: cannot bind broker address")?;
    let proxy = format!(
        "http://{}",
        listener
            .local_addr()
            .map_err(|_| "inspect broker address")?
    );
    let ca = root.join("broker-ca.pem");
    symvault_sync::safeio::write_atomic(&ca, broker.ca_pem().as_bytes())
        .map_err(|_| "write CA certificate")?;
    let ca = ca.to_str().ok_or("broker CA path is not UTF-8")?.to_owned();
    let environment = BTreeMap::from([
        ("HTTPS_PROXY".into(), proxy.clone()),
        ("HTTP_PROXY".into(), proxy),
        ("SSL_CERT_FILE".into(), ca.clone()),
        ("NODE_EXTRA_CA_CERTS".into(), ca.clone()),
        ("REQUESTS_CA_BUNDLE".into(), ca),
        ("NO_PROXY".into(), "127.0.0.1,localhost".into()),
    ]);
    Ok((broker, listener, environment))
}

pub(crate) fn with_broker<T: Send>(
    root: &Path,
    store: &Store,
    identity: &Identity,
    strict: bool,
    passthrough: &[String],
    action: impl FnOnce(BTreeMap<String, String>) -> Result<T, String>,
) -> Result<T, String> {
    let (broker, listener, environment) =
        prepare(root, store, identity, "127.0.0.1:0", strict, passthrough)
            .map_err(|error| format!("start broker: {error}"))?;
    broker.with_running(listener, || action(environment))
}

pub(crate) fn run(
    root: &Path,
    store: &Store,
    identity: &Identity,
    addr: &str,
    strict: bool,
    passthrough: &[String],
) -> Result<(), String> {
    let (broker, listener, environment) =
        prepare(root, store, identity, addr, strict, passthrough)?;
    let hosts = parse_hosts(passthrough)?;
    let (sender, receiver) = mpsc::channel();
    let stop = broker.shutdown();
    ctrlc::set_handler(move || {
        let _ = stop.cancel();
        let _ = sender.send(());
    })
    .map_err(|_| "register broker stop handler")?;
    println!(
        "Symaira Vault egress broker listening on {}",
        environment["HTTPS_PROXY"]
    );
    println!("CA certificate written to {}", environment["SSL_CERT_FILE"]);
    println!("Export the following in the agent's environment:");
    for key in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "NO_PROXY",
    ] {
        println!("  {key}={}", environment[key]);
    }
    if strict {
        println!("Strict mode: requests to hosts without a template are rejected with 403.");
    }
    if !hosts.is_empty() {
        println!(
            "Passthrough hosts (no TLS interception): [{}]",
            hosts.join(" ")
        );
    }
    io::stdout().flush().map_err(|_| "flush broker startup")?;
    broker.with_running(listener, || {
        loop {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(()) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("broker stop handler disconnected".into());
                }
                Err(mpsc::RecvTimeoutError::Timeout) if broker.is_stopping() => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    })
}

// pflag StringSlice is CSV, including doubled quotes and repeated flag values.
fn parse_hosts(arguments: &[String]) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    for argument in arguments {
        if argument.is_empty() {
            continue;
        }
        let mut characters = argument.chars().peekable();
        loop {
            let mut field = String::new();
            if characters.peek() == Some(&'"') {
                characters.next();
                loop {
                    match characters.next() {
                        Some('"') if characters.peek() == Some(&'"') => {
                            characters.next();
                            field.push('"');
                        }
                        Some('"') => break,
                        Some(c) => field.push(c),
                        None => return Err("invalid broker passthrough CSV".into()),
                    }
                }
                if characters.peek().is_some_and(|c| *c != ',') {
                    return Err("invalid broker passthrough CSV".into());
                }
            } else {
                while let Some(c) = characters.peek().copied().filter(|c| *c != ',') {
                    characters.next();
                    if c == '"' {
                        return Err("invalid broker passthrough CSV".into());
                    }
                    field.push(c);
                }
            }
            hosts.push(field);
            if characters.next().is_none() {
                break;
            }
        }
    }
    Ok(hosts)
}
