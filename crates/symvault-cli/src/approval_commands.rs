//! Approval-device pairing client from Go `cmd/device_approval.go`.
//!
//! Pair codes are minted by the already-running Go server over its
//! loopback-only endpoint. The request is pinned to the server certificate
//! recorded by that process and proves access to the vault's enroll secret.

use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use getifaddrs::{Address, InterfaceFlags};
use hmac::{Hmac, Mac};
use qrcode::{Color as QrColor, EcLevel, QrCode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

const RUNTIME_PORT: &str = ".runtime-port";
const RUNTIME_TLS: &str = ".runtime-tls-cert";
const ENROLL_SECRET: &str = "mcp-server.enroll-secret";
const DEVICE_ENROLL_CODE: &str = "/api/v1/devices/enroll-code";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RuntimePort {
    port: u16,
    #[serde(default)]
    bind: String,
}

#[derive(Debug, Deserialize)]
struct RuntimeTls {
    certificate: String,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigTlsFallback {
    mcp: Option<ConfigMcpTlsFallback>,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigMcpTlsFallback {
    #[serde(default)]
    tls_cert_file: String,
    #[serde(default)]
    tls_key_file: String,
}

#[derive(Debug, Deserialize)]
struct EnrollCode {
    code: String,
    expires_at: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct PairingPayload<'a> {
    host: &'a str,
    port: u16,
    code: &'a str,
    fingerprint: &'a str,
}

pub(crate) fn pair(vault: &Path, host: Option<&str>, quiet: bool) -> Result<(), String> {
    let (port, bind) = runtime_server(vault)?;
    if !bind.is_empty() && is_loopback_bind(&bind) {
        return Err(format!(
            "'symvault serve' is bound to {bind} (loopback-only) — a phone on the LAN cannot reach it. Restart the server with --bind 0.0.0.0 (all interfaces) or --bind <lan-ip>, then run 'approval-pair' again"
        ));
    }
    let host = select_host(host, detect_lan_ipv4)?;
    let minted =
        mint_enroll_code(vault, port).map_err(|error| format!("mint pairing code: {error}"))?;
    if minted.code.is_empty() || minted.fingerprint.is_empty() {
        return Err("decode approval response: missing code or fingerprint".to_owned());
    }
    let payload = PairingPayload {
        host: &host,
        port,
        code: &minted.code,
        fingerprint: &minted.fingerprint,
    };
    let output = render_pair_output(&payload, &minted.expires_at, terminal_width())?;
    if !quiet {
        print!("{output}");
    }
    Ok(())
}

fn is_loopback_bind(bind: &str) -> bool {
    let bind = bind.trim();
    bind.eq_ignore_ascii_case("localhost")
        || bind
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn select_pair_host(candidates: Vec<Ipv4Addr>) -> Result<String, String> {
    match candidates.as_slice() {
        [] => Err("could not auto-detect a LAN address; pass --host <ip> explicitly".to_owned()),
        [host] => Ok(host.to_string()),
        _ => {
            let mut message =
                String::from("multiple network addresses found; pass --host to pick one:\n");
            for host in candidates {
                message.push_str(&format!("  {host}\n"));
            }
            Err(message)
        }
    }
}

fn select_host(
    explicit_host: Option<&str>,
    detect: impl FnOnce() -> Result<Vec<Ipv4Addr>, String>,
) -> Result<String, String> {
    if let Some(host) = explicit_host.filter(|host| !host.trim().is_empty()) {
        return Ok(host.trim().to_owned());
    }
    select_pair_host(detect().unwrap_or_default())
}

fn detect_lan_ipv4() -> Result<Vec<Ipv4Addr>, String> {
    let interfaces = getifaddrs::InterfaceFilter::new()
        .v4()
        .get()
        .map_err(|error| error.to_string())?;
    let mut addresses = Vec::new();
    for interface in interfaces {
        if let Address::V4(address) = interface.address {
            let ip = address.address;
            if is_lan_ipv4(interface.flags, ip) {
                addresses.push(ip);
            }
        }
    }
    Ok(addresses)
}

fn is_lan_ipv4(flags: InterfaceFlags, ip: Ipv4Addr) -> bool {
    flags.contains(InterfaceFlags::UP)
        && !flags.contains(InterfaceFlags::LOOPBACK)
        && !ip.is_loopback()
        && !ip.is_link_local()
}

fn mint_enroll_code(vault: &Path, port: u16) -> Result<EnrollCode, String> {
    let certificate_path = runtime_tls_certificate(vault)?;
    let certificate = symvault_sync::safeio::read_bounded(&certificate_path, 1024 * 1024)
        .map_err(|_| "read server TLS certificate".to_owned())?
        .ok_or_else(|| "read server TLS certificate".to_owned())?;
    let pinned_certificate = reqwest::Certificate::from_pem(&certificate)
        .map_err(|_| "parse server TLS certificate".to_owned())?;

    let secret = symvault_sync::safeio::read_bounded(&vault.join(ENROLL_SECRET), 64)
        .map_err(|error| format!("load vault-ownership proof secret: {error}"))?
        .ok_or_else(|| "load vault-ownership proof secret: file not found".to_owned())?;
    if secret.len() != 32 {
        return Err("load vault-ownership proof secret: invalid secret length".to_owned());
    }
    let secret = Zeroizing::new(secret);
    let timestamp = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|error| format!("format approval timestamp: {error}"))?
        .format(&Rfc3339)
        .map_err(|error| format!("format approval timestamp: {error}"))?;
    let proof = enroll_proof(&secret, timestamp.as_bytes());

    let client = reqwest::blocking::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only([pinned_certificate])
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("create approval HTTP client: {error}"))?;
    let url = format!("https://127.0.0.1:{port}{DEVICE_ENROLL_CODE}");
    let mut response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Enroll-Timestamp", &timestamp)
        .header("X-Enroll-Proof", &proof)
        .body(Vec::new())
        .send()
        .map_err(|error| {
            format!("call {DEVICE_ENROLL_CODE} (is 'symvault serve' running with TLS?): {error}")
        })?;
    let status = response.status();
    let mut body = Vec::new();
    Read::take(&mut response, MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("decode approval response: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("decode approval response: response too large".to_owned());
    }
    if !status.is_success() {
        #[derive(Deserialize)]
        struct ApiError {
            error: String,
        }
        if let Ok(api_error) = serde_json::from_slice::<ApiError>(&body)
            && !api_error.error.trim().is_empty()
        {
            return Err(format!("approval server: {}", api_error.error));
        }
        return Err(format!("approval server returned HTTP {}", status.as_u16()));
    }
    serde_json::from_slice(&body).map_err(|error| format!("decode approval response: {error}"))
}

fn runtime_server(vault: &Path) -> Result<(u16, String), String> {
    let path = vault.join(RUNTIME_PORT);
    let data = symvault_sync::safeio::read_bounded(&path, 4096)
        .map_err(|error| format!("read running server metadata: {error}"))?
        .ok_or_else(|| {
            "could not find the running server's port — is 'symvault serve' running?".to_owned()
        })?;
    if let Ok(record) = serde_json::from_slice::<RuntimePort>(&data)
        && record.port > 0
    {
        return Ok((record.port, record.bind));
    }
    std::str::from_utf8(&data)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .map(|port| (port, String::new()))
        .ok_or_else(|| {
            "could not find the running server's port — is 'symvault serve' running?".to_owned()
        })
}

fn runtime_tls_certificate(vault: &Path) -> Result<PathBuf, String> {
    let runtime_path = vault.join(RUNTIME_TLS);
    if let Ok(Some(data)) = symvault_sync::safeio::read_bounded(&runtime_path, 64 * 1024)
        && let Ok(record) = serde_json::from_slice::<RuntimeTls>(&data)
        && !record.certificate.trim().is_empty()
    {
        return Ok(PathBuf::from(record.certificate));
    }

    let config_path = vault.join("config.yaml");
    let config_data = symvault_sync::safeio::read_bounded(&config_path, 1024 * 1024)
        .map_err(|_| "could not find valid running server TLS metadata or config.yaml".to_owned())?
        .ok_or_else(|| {
            "could not find valid running server TLS metadata or config.yaml".to_owned()
        })?;
    let config: ConfigTlsFallback = serde_yaml_ng::from_slice(&config_data).map_err(|_| {
        "could not find valid running server TLS metadata or config.yaml".to_owned()
    })?;
    let mcp = config.mcp.unwrap_or_default();
    if mcp.tls_cert_file.trim().is_empty() || mcp.tls_key_file.trim().is_empty() {
        return Ok(vault.join("mcp-server.crt"));
    }
    Ok(PathBuf::from(mcp.tls_cert_file.trim()))
}

fn enroll_proof(secret: &[u8], timestamp: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp);
    use std::fmt::Write as _;
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

fn render_pair_output(
    payload: &PairingPayload<'_>,
    expires_at: &str,
    width: usize,
) -> Result<String, String> {
    let data = serde_json::to_string(payload).map_err(|error| error.to_string())?;
    let qr = render_qr_for_width(&data, width);
    let mut output = String::from("\n=== Approval Device Pairing ===\n\n");
    match qr {
        Ok(art) => {
            output.push_str(&art);
            output.push('\n');
        }
        Err(error) => output.push_str(&format!("(QR code not shown: {error})\n\n")),
    }
    output.push_str("Scan this with the Symaira Vault iOS app, or enter it manually:\n\n");
    output.push_str(&format!(
        "  Host:        {}\n  Port:        {}\n  Code:        {}\n  Fingerprint: {}\n\nExpires: {}\n",
        payload.host, payload.port, payload.code, payload.fingerprint, expires_at
    ));
    Ok(output)
}

fn render_qr_for_width(data: &str, width: usize) -> Result<String, String> {
    const MIN_QR_WIDTH: usize = 41;
    if width > 0 && width < MIN_QR_WIDTH {
        return Err(format!(
            "terminal too narrow for QR code; need at least {MIN_QR_WIDTH} columns"
        ));
    }
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|error| format!("qr encode: {error}"))?;
    let size = code.width();
    let total_size = size + 8;
    let mut output = String::new();
    for y in (0..total_size).step_by(2) {
        for x in 0..total_size {
            let top = qr_is_dark(&code, x, y, size);
            let bottom = qr_is_dark(&code, x, y + 1, size);
            output.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push('\n');
    }
    Ok(output)
}

fn qr_is_dark(code: &QrCode, x: usize, y: usize, size: usize) -> bool {
    x >= 4 && y >= 4 && x < size + 4 && y < size + 4 && code[(x - 4, y - 4)] == QrColor::Dark
}

fn terminal_width() -> usize {
    terminal_size::terminal_size_of(std::io::stderr())
        .map(|(terminal_size::Width(width), _)| usize::from(width))
        .unwrap_or(80)
}

// Device pairing and the local approval queue share the CLI command module
// boundary, but keep their protocol helpers isolated from each other.
mod queue;
pub(crate) use queue::{decide, list};

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        PairingPayload, enroll_proof, is_lan_ipv4, is_loopback_bind, render_pair_output,
        render_qr_for_width, select_host, select_pair_host,
    };
    use getifaddrs::InterfaceFlags;

    #[test]
    fn enroll_proof_matches_go_hmac_sha256_hex_contract() {
        let proof = enroll_proof(b"test-secret", b"2026-09-28T12:34:56Z");
        assert_eq!(
            proof,
            "78da2bf77a77af6b9696f5828e7a317bac893d676f767cdee7992169740cef6d"
        );
    }

    #[test]
    fn automatic_host_matches_go_single_empty_and_ambiguous_cases() {
        assert_eq!(
            select_pair_host(vec![Ipv4Addr::new(192, 168, 1, 42)]).unwrap(),
            "192.168.1.42"
        );
        assert_eq!(
            select_pair_host(Vec::new()).unwrap_err(),
            "could not auto-detect a LAN address; pass --host <ip> explicitly"
        );
        assert!(
            select_pair_host(vec![
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(10, 0, 0, 8)
            ])
            .unwrap_err()
            .contains("multiple network addresses found; pass --host to pick one:")
        );
    }

    #[test]
    fn explicit_host_is_trimmed_and_skips_interface_detection() {
        assert_eq!(
            select_host(Some(" 192.168.1.42 "), || {
                panic!("explicit --host must bypass interface detection")
            })
            .unwrap(),
            "192.168.1.42"
        );
    }

    #[test]
    fn only_loopback_runtime_bind_is_rejected() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn lan_detection_excludes_down_loopback_and_link_local_interfaces() {
        let up = InterfaceFlags::UP;
        assert!(is_lan_ipv4(up, Ipv4Addr::new(192, 168, 1, 42)));
        assert!(!is_lan_ipv4(
            InterfaceFlags::empty(),
            Ipv4Addr::new(192, 168, 1, 42)
        ));
        assert!(!is_lan_ipv4(
            up | InterfaceFlags::LOOPBACK,
            Ipv4Addr::new(192, 168, 1, 42)
        ));
        assert!(!is_lan_ipv4(up, Ipv4Addr::LOCALHOST));
        assert!(!is_lan_ipv4(up, Ipv4Addr::new(169, 254, 10, 2)));
    }

    #[test]
    fn qr_width_failure_keeps_manual_fallback() {
        let payload = PairingPayload {
            host: "192.168.1.42",
            port: 8443,
            code: "ABCD1234",
            fingerprint: "sha256:test",
        };
        let fallback = render_pair_output(&payload, "2026-09-28T12:34:56Z", 40).unwrap();
        assert!(fallback.contains("QR code not shown: terminal too narrow"));
        assert!(fallback.contains("  Code:        ABCD1234\n"));
        let qr = render_qr_for_width(r#"{"host":"192.168.1.42"}"#, 80).unwrap();
        assert!(qr.chars().any(|glyph| matches!(glyph, '█' | '▀' | '▄')));
    }
}
