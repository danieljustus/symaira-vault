//! Private native fixture launcher; never part of the installed CLI.
use serde::Deserialize;
use std::{
    fs,
    io::{self, BufRead, Read},
    path::PathBuf,
    thread,
    time::Duration,
};
use symvault_mcp::{
    ReadOnlyRuntimeConfig, RequestContext, StoreReadOnlyRuntime, ToolCallRuntime,
    broker::ApiTransportOptions,
};

#[derive(Deserialize)]
struct Spec {
    root: PathBuf,
    output: PathBuf,
    dns_server: String,
    ca_file: Option<PathBuf>,
    timeout_ms: u64,
}

fn main() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .ok_or("private fixture spec required")?;
    let spec: Spec = serde_json::from_slice(&fs::read(path).map_err(|_| "read fixture spec")?)
        .map_err(|_| "parse fixture spec")?;
    let encrypted =
        symvault_sync::safeio::read_bounded(&spec.root.join("identity.age"), 24 * 1024 * 1024)
            .map_err(|_| "read fixture identity")?
            .ok_or("missing fixture identity")?;
    let identity = symvault_crypto::decrypt_identity(
        &encrypted,
        &symvault_crypto::SecretBytes::new(b"correct horse battery staple"),
    )
    .map_err(|_| "unlock fixture identity")?;
    let roots = spec
        .ca_file
        .as_ref()
        .map(|path| {
            fs::read(path)
                .map_err(|_| "read scoped fixture root")
                .and_then(|bytes| {
                    reqwest::Certificate::from_pem(&bytes).map_err(|_| "parse scoped fixture root")
                })
        })
        .transpose()?
        .into_iter()
        .collect();
    let runtime = StoreReadOnlyRuntime::open(
        &spec.root,
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "api-native".into(),
            approval_mode: "none".into(),
            can_run_commands: true,
            allowed_paths: vec!["*".into()],
            available_tools: vec!["execute_api_request".into()],
            ..ReadOnlyRuntimeConfig::default()
        },
        None,
        None,
    )?
    .with_api_transport_options(ApiTransportOptions {
        upstream_root_certificates: roots,
        dns_server: Some(
            spec.dns_server
                .parse()
                .map_err(|_| "parse fixture DNS address")?,
        ),
    });
    let context = RequestContext::default().with_timeout(Duration::from_millis(spec.timeout_ms));
    let cancellation = context.clone();
    let reader = thread::spawn(move || {
        let mut command = String::new();
        let _ = io::stdin().lock().take(32).read_line(&mut command);
        if command == "cancel\n" {
            cancellation.cancel();
        }
    });
    let arguments = serde_json::json!({"template":"fixture", "endpoint":"/v1/status"});
    runtime
        .authorize("execute_api_request", &arguments)
        .map_err(|_| "fixture authorization failed")?;
    let output = match runtime.call_with_context("execute_api_request", &arguments, &context) {
        Ok(result) => {
            serde_json::json!({"is_error":result.is_error,"text":result.text,"handler_error":false})
        }
        Err(error) => serde_json::json!({"is_error":true,"text":error,"handler_error":true}),
    };
    reader
        .join()
        .map_err(|_| "join fixture cancellation reader")?;
    symvault_sync::safeio::write_atomic(
        &spec.output,
        &serde_json::to_vec(&output).map_err(|_| "serialize fixture result")?,
    )
    .map_err(|_| "write fixture result")?;
    println!("completed one actual encrypted API call");
    Ok(())
}
