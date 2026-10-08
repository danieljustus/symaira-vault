//! Credential-owning forward proxy. The CLI never enables the fixture seams.

use super::connect;
use crate::{
    http::{HttpShutdown, shutdown::ConnectionGuard},
    store_adapter as api,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use reqwest::{Client, Method, Url, redirect::Policy};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use symvault_crypto::Identity;
use symvault_store::Store;
use zeroize::{Zeroize, Zeroizing};

const BODY_LIMIT: usize = 16 * 1024 * 1024;
const HEADER_LIMIT: usize = 64 * 1024;
const WORKERS: usize = 4;
const QUEUED: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(60);
const BUILTINS: [&str; 17] = [
    "anthropic",
    "cloudflare",
    "gemini",
    "github",
    "gitlab",
    "linear",
    "notion",
    "npm",
    "openai",
    "openrouter",
    "perplexity",
    "resend",
    "sentry",
    "slack",
    "stripe",
    "telegram",
    "vercel",
];

#[derive(Default)]
pub struct EgressOptions {
    pub strict: bool,
    pub passthrough: Vec<String>,
    /// Explicit in-process fixture/application seam. The shipped CLI keeps false.
    pub allow_private: bool,
    /// Adds only a fixture trust root to this runtime, never to installed trust.
    pub upstream_ca_pem: Option<Vec<u8>>,
}

/// Borrows the unlocked store/identity until all service work has joined.
pub struct EgressBroker<'a> {
    store: &'a Store,
    identity: &'a Identity,
    root: &'a Path,
    options: EgressOptions,
    templates: BTreeMap<String, String>,
    ca: CertifiedIssuer<'static, KeyPair>,
    cancellation: HttpShutdown,
    dns_server: Option<SocketAddr>,
}

impl<'a> EgressBroker<'a> {
    pub fn new(
        root: &'a Path,
        store: &'a Store,
        identity: &'a Identity,
        options: EgressOptions,
    ) -> Result<Self, String> {
        if options.passthrough.len() > 256 || options.passthrough.iter().any(|h| h.len() > 1024) {
            return Err("broker passthrough exceeds its 256-host/1024-byte limits".into());
        }
        let templates = load_catalog(root)?;
        let now = time::OffsetDateTime::now_utc();
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(|_| "prepare broker CA")?;
        params
            .distinguished_name
            .push(DnType::CommonName, "symvault egress broker (ephemeral)");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);
        let key = KeyPair::generate().map_err(|_| "generate broker CA key")?;
        let ca = CertifiedIssuer::self_signed(params, key).map_err(|_| "generate broker CA")?;
        Ok(Self {
            store,
            identity,
            root,
            options,
            templates,
            ca,
            cancellation: HttpShutdown::default(),
            dns_server: None,
        })
    }

    /// Selects an explicit in-process DNS server for an application or fixture.
    /// The shipped CLI keeps the default system DNS configuration.
    #[must_use]
    pub fn with_dns_server(mut self, server: SocketAddr) -> Self {
        self.dns_server = Some(server);
        self
    }

    #[must_use]
    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }

    #[must_use]
    pub fn shutdown(&self) -> HttpShutdown {
        self.cancellation.clone()
    }

    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.cancellation.is_cancelled().unwrap_or(true)
    }

    /// Runs a foreground action while the proxy is owned by this scope. On any
    /// return or unwind, close admission/transports and join all service workers.
    pub fn with_running<T: Send>(
        &self,
        listener: TcpListener,
        action: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        if !listener
            .local_addr()
            .map_err(|_| "inspect broker listener")?
            .ip()
            .is_loopback()
        {
            return Err("broker listener must bind to loopback".into());
        }
        thread::scope(|scope| {
            let worker = scope.spawn(|| self.serve(listener));
            struct StopOnDrop(HttpShutdown);
            impl Drop for StopOnDrop {
                fn drop(&mut self) {
                    let _ = self.0.cancel();
                }
            }
            let stop = StopOnDrop(self.cancellation.clone());
            let result = action();
            drop(stop);
            let service = worker.join().map_err(|_| "broker service worker failed")?;
            match result {
                Err(error) => Err(error),
                Ok(value) => {
                    service?;
                    Ok(value)
                }
            }
        })
    }

    fn serve(&self, listener: TcpListener) -> Result<(), String> {
        listener
            .set_nonblocking(true)
            .map_err(|_| "configure broker listener")?;
        thread::scope(|scope| {
            let (sender, receiver) = mpsc::sync_channel::<(TcpStream, ConnectionGuard)>(QUEUED);
            let receiver = Arc::new(Mutex::new(receiver));
            for _ in 0..WORKERS {
                let receiver = receiver.clone();
                scope.spawn(move || {
                    while !self.cancellation.is_cancelled().unwrap_or(true) {
                        let next = receiver
                            .lock()
                            .expect("broker admission queue")
                            .recv_timeout(Duration::from_millis(25));
                        match next {
                            Ok((stream, _ownership)) => {
                                let _ = self.handle_client(stream);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
            }
            let result = (|| {
                while !self
                    .cancellation
                    .is_cancelled()
                    .map_err(|_| "inspect broker stop")?
                {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connect::configure_accepted_client(&stream)
                                .map_err(|_| "configure broker client")?;
                            let Some(ownership) = self
                                .cancellation
                                .register(&stream)
                                .map_err(|_| "own broker client")?
                            else {
                                break;
                            };
                            let _ = sender.try_send((stream, ownership));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => return Err("accept broker client".into()),
                    }
                }
                Ok(())
            })();
            drop(sender);
            self.cancellation
                .cancel()
                .map_err(|_| "cancel broker I/O")?;
            result
        })
    }

    fn leaf(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|_| "prepare broker leaf")?;
        params.distinguished_name.push(DnType::CommonName, host);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(1);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().map_err(|_| "generate broker leaf key")?;
        let certificate = params
            .signed_by(&key, &self.ca)
            .map_err(|_| "sign broker leaf")?;
        let private = Zeroizing::new(key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "configure broker TLS versions")?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), self.ca.der().clone()],
                PrivatePkcs8KeyDer::from(private.to_vec()).into(),
            )
            .map_err(|_| "configure broker TLS leaf")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    fn handle_client(&self, stream: TcpStream) -> Result<(), String> {
        let socket =
            connect::Socket::new(stream, &self.cancellation).map_err(|_| "configure broker I/O")?;
        let mut transport = Transport::Plain(socket);
        let request = match read_request(&mut transport) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(_) => return write_error(&mut transport, 400, "invalid proxy request"),
        };
        if request.method != "CONNECT" {
            return self.forward(&mut transport, request, None);
        }
        let Some((host, addresses)) = connect::resolve_connect_target(
            &request.target,
            self.options.allow_private,
            &self.cancellation,
            self.dns_server,
        ) else {
            return write_error(&mut transport, 403, "CONNECT target is blocked");
        };
        if !request.body.is_empty() {
            return write_error(&mut transport, 400, "CONNECT body is unsupported");
        }
        if self
            .options
            .passthrough
            .iter()
            .any(|p| connect::host_matches(p, &host))
        {
            // Checked dialing owns the complete dial sequence with cancellation;
            // the admitted socket is used for the tunnel, never probed and dropped.
            let Some(upstream) = connect::connect_checked_addresses(&addresses, &self.cancellation)
            else {
                return write_error(&mut transport, 502, "cannot reach upstream");
            };
            let Transport::Plain(mut client) = transport else {
                unreachable!()
            };
            let Some(_owned) = self
                .cancellation
                .register(&upstream)
                .map_err(|_| "own broker upstream")?
            else {
                return Ok(());
            };
            let mut upstream = connect::Socket::new(upstream, &self.cancellation)
                .map_err(|_| "configure broker upstream")?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .map_err(|_| "write CONNECT response")?;
            let mut client_reader = client.duplicate().map_err(|_| "duplicate broker client")?;
            let mut upstream_writer = upstream
                .duplicate()
                .map_err(|_| "duplicate broker upstream")?;
            thread::scope(|scope| {
                scope.spawn(move || {
                    let _ = io::copy(&mut client_reader, &mut upstream_writer);
                    let _ = upstream_writer.stream.shutdown(Shutdown::Write);
                });
                let _ = io::copy(&mut upstream, &mut client);
                let _ = client.stream.shutdown(Shutdown::Write);
            });
            return Ok(());
        }
        // Interception admits the inner request in forward before any upstream dial.
        let tls = self.leaf(&host)?;
        transport
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|_| "write CONNECT response")?;
        let Transport::Plain(socket) = transport else {
            unreachable!()
        };
        socket
            .stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| "set TLS deadline")?;
        let connection = ServerConnection::new(tls).map_err(|_| "start broker TLS")?;
        let mut transport = Transport::Tls(Box::new(StreamOwned::new(connection, socket)));
        // One request at a time on the intercepted connection; responses explicitly
        // close it. Clients can establish another CONNECT without a shared cache.
        match read_request(&mut transport) {
            Ok(Some(inner)) if inner.method != "CONNECT" => {
                self.forward(&mut transport, inner, Some(&request.target))
            }
            _ => write_error(&mut transport, 400, "invalid intercepted request"),
        }
    }

    fn forward(
        &self,
        transport: &mut Transport,
        mut request: Request,
        tunnel: Option<&str>,
    ) -> Result<(), String> {
        // Keep the original HTTP path for authorization: Url normalizes dot
        // segments, while Go's request ACL sees the percent-decoded raw path.
        let Ok(original_uri) = request.target.parse::<http::Uri>() else {
            return write_error(transport, 400, "invalid request target");
        };
        let Ok(path_bytes) = api::api_percent_decoded_bytes(original_uri.path(), false) else {
            return write_error(transport, 400, "invalid request path");
        };
        let Ok(authorization_path) = std::str::from_utf8(&path_bytes) else {
            return write_error(transport, 400, "invalid request path");
        };
        if authorization_path
            .split('/')
            .any(|part| matches!(part, "." | ".."))
            || request.target.contains('\\')
        {
            return write_error(transport, 403, "ambiguous request path is blocked");
        }
        let target = if request.target.starts_with('/') {
            let host = request
                .headers
                .get("host")
                .ok_or("missing proxy authority")?;
            format!(
                "{}://{host}{}",
                if tunnel.is_some() { "https" } else { "http" },
                request.target
            )
        } else {
            request.target.clone()
        };
        let Ok(mut url) = Url::parse(&target) else {
            return write_error(transport, 400, "invalid request target");
        };
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            return write_error(transport, 400, "invalid request target");
        }
        if let Some(authority) = tunnel {
            let expected = Url::parse(&format!("https://{authority}/"))
                .map_err(|_| "invalid CONNECT authority")?;
            if url.scheme() != "https" || !same_authority(&url, &expected) {
                return write_error(
                    transport,
                    403,
                    "intercepted authority differs from CONNECT target",
                );
            }
        }
        // Absolute-form uses the URI authority; the caller's Host cannot select
        // a different credential catalog entry or upstream destination.
        let host = connect::canonical_host(url.host_str().unwrap());
        let definition = match self.templates.get(&host) {
            Some(name) => match api::load_api_template_definition(self.root, name) {
                Ok(definition) => Some(definition),
                Err(_) => return write_error(transport, 500, "cannot load template for host"),
            },
            None if self.options.strict => {
                return write_error(
                    transport,
                    403,
                    "no template for host; strict mode rejects unmatched hosts",
                );
            }
            None => None,
        };
        if let Some(definition) = &definition {
            let Ok(base) = Url::parse(&definition.base_url) else {
                return write_error(transport, 500, "invalid template for host");
            };
            if validate_definition(definition).is_err() || !same_authority(&base, &url) {
                return write_error(transport, 403, "request authority differs from template");
            }
            if !self.options.allow_private && url.scheme() != "https" {
                return write_error(transport, 403, "credential templates require HTTPS");
            }
            if !definition.allowed_methods.is_empty()
                && !definition
                    .allowed_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&request.method))
            {
                return write_error(transport, 403, "method not allowed by template");
            }
            let mut endpoint_budget = 8 * 1024 * 1024;
            if !definition.allowed_endpoints.is_empty()
                && !definition
                    .allowed_endpoints
                    .iter()
                    .any(|p| endpoint_matches(p, authorization_path, &mut endpoint_budget))
            {
                return write_error(transport, 403, "endpoint not allowed by template");
            }
        }
        let Some(addresses) = checked_addresses(
            &url,
            self.options.allow_private,
            &self.cancellation,
            self.dns_server,
        ) else {
            return write_error(transport, 403, "upstream target is blocked");
        };
        let mut known = Zeroizing::new(Vec::<String>::new());
        strip_hop_headers(&mut request.headers);
        request.headers.remove("host");
        request.headers.remove("content-length");
        if let Some(definition) = &definition {
            let Ok(path) = api::api_entry_path(&definition.entry_ref) else {
                return write_error(transport, 500, "invalid credential entry reference");
            };
            let Ok(mut entry) = self.store.read_session(self.identity).get(&path) else {
                return write_error(transport, 500, "cannot load credentials for host");
            };
            let fields = SecretFields(std::mem::take(&mut entry.data));
            for value in fields.0.values() {
                collect_strings(value, &mut known);
            }
            let prepared = (|| {
                let values = SecretStrings(api::resolve_api_substitutions(
                    &definition.substitutions,
                    &fields.0,
                )?);
                let endpoint = format!(
                    "{}{}",
                    url.path(),
                    url.query().map_or(String::new(), |q| format!("?{q}"))
                );
                let authority = url.origin().ascii_serialization();
                let rendered = api::api_request_url(
                    &authority,
                    &endpoint,
                    &definition.substitutions,
                    &values.0,
                )?;
                known.extend(api::api_path_substitution_redaction_values(
                    &authority,
                    &endpoint,
                    &definition.substitutions,
                    &values.0,
                    &rendered,
                )?);
                known.extend(api::api_query_substitution_redaction_values(
                    &authority,
                    &endpoint,
                    &definition.substitutions,
                    &values.0,
                )?);
                for value in values.0.values() {
                    known.extend(api::api_substitution_redaction_values(value));
                }
                url = Url::parse(&rendered).map_err(|_| "invalid rendered request")?;
                if !definition.substitutions.is_empty() {
                    let body = std::str::from_utf8(&request.body)
                        .map_err(|_| "substituted request body must be UTF-8")?;
                    let rendered = Zeroizing::new(api::apply_api_body_substitutions(
                        body,
                        &definition.substitutions,
                        &values.0,
                    ));
                    if rendered.len() > BODY_LIMIT {
                        return Err("substituted body exceeds limits".into());
                    }
                    request.body.zeroize();
                    request.body.extend_from_slice(rendered.as_bytes());
                }
                api::overlay_api_headers(&mut request.headers, definition.default_headers.clone());
                let (auth_header, auth_query) = api::api_auth(&definition.auth_type, &fields.0)?;
                if let Some((name, value)) = auth_header {
                    known.push(value.clone());
                    if let Some(value) = value.strip_prefix("Basic ") {
                        known.push(value.to_owned());
                    }
                    api::set_api_header(&mut request.headers, &name, value);
                }
                if let Some((name, value)) = auth_query {
                    known.push(api::api_query_escape(&value));
                    url = Url::parse(&api::set_api_query_parameter(url.as_str(), &name, &value)?)
                        .map_err(|_| "invalid authenticated request")?;
                }
                api::apply_api_header_substitutions(
                    &mut request.headers,
                    &definition.substitutions,
                    &values.0,
                );
                Ok::<(), String>(())
            })();
            if prepared.is_err() {
                return write_error(
                    transport,
                    500,
                    "cannot resolve credentials or substitutions for host",
                );
            }
        }
        strip_hop_headers(&mut request.headers);
        request.headers.retain(|name, _| {
            !name.eq_ignore_ascii_case("host") && !name.eq_ignore_ascii_case("content-length")
        });
        let result = self.fetch(&url, &addresses, &request);
        // No raw reqwest errors or credential-bearing URL is a user-visible error.
        let Ok(ForwardResponse {
            status,
            mut headers,
            body: bytes,
        }) = result
        else {
            return write_error(transport, 502, "upstream request failed");
        };
        let body = sanitize_bytes(&bytes, &known);
        for (_, value) in &mut headers {
            *value = api::sanitize_api_value(value, &known).0;
        }
        write_response(transport, status, &headers, &body)
    }

    fn fetch(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        request: &Request,
    ) -> Result<ForwardResponse, ()> {
        let host = url.host_str().ok_or(())?;
        let mut builder = Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .no_proxy()
            .redirect(Policy::none())
            .resolve_to_addrs(host, addresses);
        if let Some(pem) = &self.options.upstream_ca_pem {
            builder =
                builder.add_root_certificate(reqwest::Certificate::from_pem(pem).map_err(|_| ())?);
        }
        let client = builder.build().map_err(|_| ())?;
        let mut headers = reqwest::header::HeaderMap::new();
        let mut header_size = 0usize;
        for (name, value) in &request.headers {
            header_size = header_size.saturating_add(name.len() + value.len() + 4);
            if header_size > HEADER_LIMIT {
                return Err(());
            }
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?,
                reqwest::header::HeaderValue::from_str(value).map_err(|_| ())?,
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        runtime.block_on(async {
            let mut response = self
                .await_network(
                    client
                        .request(
                            Method::from_bytes(request.method.as_bytes()).map_err(|_| ())?,
                            url.clone(),
                        )
                        .headers(headers)
                        .body(request.body.clone())
                        .send(),
                )
                .await?;
            let status = response.status().as_u16();
            let mut headers = Vec::new();
            let mut header_size = 0usize;
            for (name, value) in response.headers() {
                header_size = header_size.saturating_add(name.as_str().len() + value.len() + 4);
                if header_size > HEADER_LIMIT {
                    return Err(());
                }
                headers.push((
                    name.as_str().to_owned(),
                    value.to_str().map_err(|_| ())?.to_owned(),
                ));
            }
            let nominated = headers
                .iter()
                .filter(|(name, _)| name == "connection")
                .flat_map(|(_, value)| value.split(',').map(|s| s.trim().to_ascii_lowercase()))
                .collect::<Vec<_>>();
            headers
                .retain(|(name, _)| name != "content-length" && !is_hop_header(name, &nominated));
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = self.await_network(response.chunk()).await? {
                if chunk.len() > BODY_LIMIT.saturating_sub(body.len()) {
                    return Err(());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(ForwardResponse {
                status,
                headers,
                body,
            })
        })
    }
    async fn await_network<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, reqwest::Error>>,
    ) -> Result<T, ()> {
        let mut future = std::pin::pin!(future);
        loop {
            if self.is_stopping() {
                return Err(());
            }
            match tokio::time::timeout(Duration::from_millis(10), &mut future).await {
                Ok(result) => return result.map_err(|_| ()),
                Err(_) => continue,
            }
        }
    }
}

fn load_catalog(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut names = BUILTINS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    match fs::read_dir(root.join("templates")) {
        Ok(entries) => {
            for (index, entry) in entries.take(257).enumerate() {
                if index == 256 {
                    return Err("broker template directory exceeds 256 entries".into());
                }
                let entry = entry.map_err(|_| "read broker template catalog")?;
                if let Some(name) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| n.strip_suffix(".yaml"))
                {
                    names.insert(name.to_owned());
                }
                if names.len() > 256 {
                    return Err("broker catalog exceeds 256 templates".into());
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("read broker template catalog".into()),
    }
    let mut catalog = BTreeMap::new();
    for name in names {
        let definition =
            api::load_api_template_definition(root, &name).map_err(|_| "load broker template")?;
        validate_definition(&definition)?;
        let base = Url::parse(&definition.base_url).map_err(|_| "invalid broker template URL")?;
        if !matches!(base.scheme(), "https" | "http")
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err("invalid broker template authority".into());
        }
        let host = base.host_str().ok_or("missing broker template host")?;
        if catalog
            .insert(connect::canonical_host(host), name)
            .is_some()
        {
            return Err("ambiguous broker templates for one host".into());
        }
    }
    Ok(catalog)
}

fn validate_definition(definition: &super::ApiTemplateDefinition) -> Result<(), String> {
    api::validate_api_template_definition(definition).map_err(|_| "invalid broker template")?;
    if !matches!(
        definition.auth_type.as_str(),
        "bearer" | "basic" | "header" | "query_param" | "none"
    ) {
        return Err("unsupported broker authentication type".into());
    }
    if definition.auth_type == "none" && definition.substitutions.is_empty() {
        return Err("auth_type none requires substitutions".into());
    }
    Ok(())
}

fn checked_addresses(
    url: &Url,
    allow_private: bool,
    cancellation: &HttpShutdown,
    dns_server: Option<SocketAddr>,
) -> Option<Vec<SocketAddr>> {
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default()?;
    connect::resolve_destination(host, port, allow_private, cancellation, dns_server)
}

fn same_authority(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn endpoint_matches(pattern: &str, path: &str, budget: &mut usize) -> bool {
    pattern
        .strip_suffix("/*")
        .is_some_and(|prefix| path.starts_with(&format!("{prefix}/")))
        || symvault_core::policy::glob_match_with_budget(pattern, path, budget)
}

struct ForwardResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
}

fn sanitize_bytes(bytes: &[u8], known: &[String]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                output.extend_from_slice(api::sanitize_api_value(text, known).0.as_bytes());
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                let text =
                    std::str::from_utf8(&remaining[..valid]).expect("validated UTF-8 prefix");
                output.extend_from_slice(api::sanitize_api_value(text, known).0.as_bytes());
                let invalid = error.error_len().unwrap_or(remaining.len() - valid);
                output.extend_from_slice(&remaining[valid..valid + invalid]);
                remaining = &remaining[valid + invalid..];
            }
        }
    }
    output
}

fn is_hop_header(name: &str, nominated: &[String]) -> bool {
    nominated.iter().any(|n| n.eq_ignore_ascii_case(name))
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "keep-alive"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

fn strip_hop_headers(headers: &mut BTreeMap<String, String>) {
    let nominated = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect::<Vec<_>>();
    headers.retain(|name, _| !is_hop_header(name, &nominated));
}

struct SecretStrings(BTreeMap<String, String>);
impl Drop for SecretStrings {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

struct SecretFields(BTreeMap<String, Value>);
impl Drop for SecretFields {
    fn drop(&mut self) {
        fn erase(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => {
                    for v in a {
                        erase(v);
                    }
                }
                Value::Object(o) => {
                    for v in o.values_mut() {
                        erase(v);
                    }
                }
                _ => {}
            }
        }
        for value in self.0.values_mut() {
            erase(value);
        }
    }
}
fn collect_strings(value: &Value, known: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.is_empty() => known.push(s.clone()),
        Value::Array(a) => {
            for v in a {
                collect_strings(v, known);
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                collect_strings(v, known);
            }
        }
        _ => {}
    }
}

enum Transport {
    Plain(connect::Socket),
    Tls(Box<StreamOwned<ServerConnection, connect::Socket>>),
}
impl Transport {
    fn deadline(&self, remaining: Duration) -> io::Result<()> {
        let socket = match self {
            Self::Plain(s) => &s.stream,
            Self::Tls(s) => &s.sock.stream,
        };
        socket.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
    }
}
impl Read for Transport {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(b),
            Self::Tls(s) => s.read(b),
        }
    }
}
impl Write for Transport {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(b),
            Self::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.target.zeroize();
        self.body.zeroize();
        for v in self.headers.values_mut() {
            v.zeroize();
        }
    }
}

fn token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

fn read_line(stream: &mut Transport, limit: usize, until: Instant) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        stream.deadline(
            until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::other("proxy deadline"))?,
        )?;
        let mut byte = [0];
        match stream.read(&mut byte)? {
            0 if bytes.is_empty() => return Ok(bytes),
            0 => return Err(io::Error::other("incomplete proxy line")),
            _ => bytes.push(byte[0]),
        }
        if bytes.ends_with(b"\r\n") {
            return Ok(bytes);
        }
    }
    Err(io::Error::other("proxy line exceeds limits"))
}

fn read_request(stream: &mut Transport) -> io::Result<Option<Request>> {
    let until = Instant::now() + Duration::from_secs(30);
    let line = read_line(stream, 8192, until)?;
    if line.is_empty() {
        return Ok(None);
    }
    let first = std::str::from_utf8(&line)
        .map_err(|_| io::Error::other("invalid request line"))?
        .trim_end_matches("\r\n");
    let parts = first.split(' ').collect::<Vec<_>>();
    if parts.len() != 3
        || !token(parts[0].as_bytes())
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
        || parts[1].is_empty()
        || parts[1].bytes().any(|b| b <= 32 || b == 127)
    {
        return Err(io::Error::other("invalid request line"));
    }
    let mut request = Request {
        method: parts[0].to_owned(),
        target: parts[1].to_owned(),
        headers: BTreeMap::new(),
        body: Vec::new(),
    };
    let mut size = line.len();
    loop {
        let line = read_line(stream, HEADER_LIMIT.saturating_sub(size), until)?;
        size += line.len();
        if line == b"\r\n" {
            break;
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| io::Error::other("invalid header"))?
            .trim_end_matches("\r\n");
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid header"))?;
        if !token(name.as_bytes()) || value.bytes().any(|b| b == 127 || b < 32 && b != b'\t') {
            return Err(io::Error::other("invalid header"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_owned();
        if let Some(old) = request.headers.get_mut(&name) {
            if matches!(
                name.as_str(),
                "content-length" | "transfer-encoding" | "host"
            ) {
                return Err(io::Error::other("ambiguous framing"));
            }
            old.push_str(if name == "cookie" { "; " } else { ", " });
            old.push_str(&value);
        } else {
            request.headers.insert(name, value);
        }
    }
    if !request.headers.contains_key("host") {
        return Err(io::Error::other("missing Host"));
    }
    let length = request
        .headers
        .get("content-length")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::other("invalid Content-Length"))?
        .unwrap_or(0);
    if length > BODY_LIMIT
        || request.headers.contains_key("transfer-encoding")
            && request.headers.contains_key("content-length")
    {
        return Err(io::Error::other("invalid body framing"));
    }
    if let Some(expect) = request.headers.remove("expect") {
        if !expect.eq_ignore_ascii_case("100-continue") {
            return Err(io::Error::other("unsupported expectation"));
        }
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        stream.flush()?;
    }
    let until = Instant::now() + TIMEOUT;
    if let Some(encoding) = request.headers.get("transfer-encoding") {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(io::Error::other("unsupported transfer encoding"));
        }
        let mut framing = 0usize;
        loop {
            let line = read_line(stream, 1024, until)?;
            framing += line.len();
            if framing > HEADER_LIMIT {
                return Err(io::Error::other("chunk framing exceeds limits"));
            }
            let text = std::str::from_utf8(&line)
                .map_err(|_| io::Error::other("invalid chunk"))?
                .trim_end_matches("\r\n");
            let size = usize::from_str_radix(text.split(';').next().unwrap_or_default(), 16)
                .map_err(|_| io::Error::other("invalid chunk"))?;
            if size == 0 {
                loop {
                    let line = read_line(stream, HEADER_LIMIT.saturating_sub(framing), until)?;
                    framing += line.len();
                    if line == b"\r\n" {
                        break;
                    }
                    if line.is_empty() {
                        return Err(io::Error::other("incomplete trailer"));
                    }
                }
                break;
            }
            if size > BODY_LIMIT.saturating_sub(request.body.len()) {
                return Err(io::Error::other("body exceeds limits"));
            }
            read_body(stream, &mut request.body, size, until)?;
            let mut crlf = Vec::new();
            read_body(stream, &mut crlf, 2, until)?;
            if crlf != b"\r\n" {
                return Err(io::Error::other("invalid chunk terminator"));
            }
        }
    } else {
        read_body(stream, &mut request.body, length, until)?;
    }
    Ok(Some(request))
}

fn read_body(
    stream: &mut Transport,
    body: &mut Vec<u8>,
    count: usize,
    until: Instant,
) -> io::Result<()> {
    let end = body.len() + count;
    let mut buffer = [0; 8192];
    while body.len() < end {
        stream.deadline(
            until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::other("body deadline"))?,
        )?;
        let count = stream.read(&mut buffer[..8192.min(end - body.len())])?;
        if count == 0 {
            return Err(io::Error::other("incomplete body"));
        }
        body.extend_from_slice(&buffer[..count]);
        buffer.zeroize();
    }
    Ok(())
}

fn write_error(stream: &mut Transport, status: u16, message: &str) -> Result<(), String> {
    write_response(
        stream,
        status,
        &Vec::from([
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("x-content-type-options".into(), "nosniff".into()),
        ]),
        format!("{message}\n").as_bytes(),
    )
}
fn write_response(
    stream: &mut Transport,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), String> {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .map_err(|_| "write broker response")?;
    for (name, value) in headers {
        if token(name.as_bytes()) && !value.bytes().any(|b| b == 127 || b < 32 && b != b'\t') {
            write!(stream, "{name}: {value}\r\n").map_err(|_| "write broker headers")?;
        }
    }
    stream
        .write_all(b"\r\n")
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|_| "write broker body".into())
}
