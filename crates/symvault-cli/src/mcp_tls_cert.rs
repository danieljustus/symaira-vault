//! Go-compatible cached certificate for the native MCP HTTP listener.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};
use zeroize::Zeroizing;

const CERT_FILE: &str = "mcp-server.crt";
const KEY_FILE: &str = "mcp-server.key";
const RENEWAL_WINDOW: Duration = Duration::days(30);

pub(crate) fn ensure_tls_cert(vault: &Path) -> Result<(PathBuf, PathBuf), String> {
    let cert = vault.join(CERT_FILE);
    let key = vault.join(KEY_FILE);
    let now = OffsetDateTime::now_utc();
    let present = |path: &Path| match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err("MCP TLS certificate or key is not a regular file".to_owned()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect MCP TLS certificate: {error}")),
    };
    if present(&cert)? && present(&key)? {
        let data = symvault_sync::safeio::read_bounded(&cert, 1024 * 1024)
            .map_err(|error| format!("read cached MCP TLS certificate: {error}"))?
            .ok_or_else(|| "cached MCP TLS certificate disappeared".to_owned())?;
        let (_, pem) = parse_x509_pem(&data)
            .map_err(|error| format!("parse cached MCP TLS certificate: {error}"))?;
        let (_, parsed) = parse_x509_certificate(&pem.contents)
            .map_err(|error| format!("parse cached MCP TLS certificate: {error}"))?;
        if parsed.validity().not_after.timestamp() > (now + RENEWAL_WINDOW).unix_timestamp() {
            return Ok((cert, key));
        }
        eprintln!(
            "cached MCP TLS certificate expires within 30 days; regenerating (paired approval devices must be re-paired)"
        );
    }
    generate_tls_cert(&cert, &key, now)?;
    Ok((cert, key))
}

fn generate_tls_cert(cert: &Path, key: &Path, now: OffsetDateTime) -> Result<(), String> {
    let mut params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])
    .map_err(|error| format!("prepare MCP TLS certificate: {error}"))?;
    params.not_before = now;
    params.not_after = now + Duration::days(365);
    params
        .distinguished_name
        .push(DnType::CommonName, "symaira-vault-mcp");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Symaira Vault MCP Server");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let private_key =
        KeyPair::generate().map_err(|error| format!("generate MCP TLS key: {error}"))?;
    let certificate = params
        .self_signed(&private_key)
        .map_err(|error| format!("generate MCP TLS certificate: {error}"))?;
    let private_pem = Zeroizing::new(private_key.serialize_pem());
    symvault_sync::safeio::write_atomic(key, private_pem.as_bytes())
        .map_err(|error| format!("write MCP TLS key: {error}"))?;
    if let Err(error) = symvault_sync::safeio::write_atomic(cert, certificate.pem().as_bytes()) {
        let _ = fs::remove_file(key);
        return Err(format!("write MCP TLS certificate: {error}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_certificate_is_reused_until_renewal_window() {
        let vault = tempfile::tempdir().unwrap();
        let (cert, key) = ensure_tls_cert(vault.path()).unwrap();
        let first = fs::read(&cert).unwrap();
        assert!(fs::metadata(&key).unwrap().is_file());
        let (_, pem) = parse_x509_pem(&first).unwrap();
        let (_, parsed) = parse_x509_certificate(&pem.contents).unwrap();
        assert!(parsed.subject_alternative_name().unwrap().is_some());
        assert_eq!(
            ensure_tls_cert(vault.path()).unwrap(),
            (cert.clone(), key.clone())
        );
        assert_eq!(fs::read(&cert).unwrap(), first);

        generate_tls_cert(&cert, &key, OffsetDateTime::now_utc() - Duration::days(350)).unwrap();
        let expiring = fs::read(&cert).unwrap();
        ensure_tls_cert(vault.path()).unwrap();
        assert_ne!(fs::read(&cert).unwrap(), expiring);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_cached_key() {
        let vault = tempfile::tempdir().unwrap();
        let victim = vault.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, vault.path().join(KEY_FILE)).unwrap();
        assert!(ensure_tls_cert(vault.path()).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
    }
}
