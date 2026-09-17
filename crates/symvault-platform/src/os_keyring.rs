//! Native operating-system keyring adapter.
//!
//! The keyring crate selects Keychain, Secret Service, or Credential Manager
//! for the target OS. This wrapper keeps the composite-key contract in the
//! Rust platform seam and translates provider-specific absence/errors without
//! exposing provider diagnostics to session callers.

#[cfg(any(test, target_os = "macos"))]
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use keyring_core::Entry;
use symvault_core::session::{Keyring, SessionError, split_keyring_key};

#[cfg(any(test, target_os = "macos"))]
const MACOS_GO_BASE64_PREFIX: &str = "go-keyring-base64:";
#[cfg(any(test, target_os = "macos"))]
const MACOS_GO_ENCODED_PREFIX: &str = "go-keyring-encoded:";

/// OS-backed keyring selected by the target platform.
#[derive(Default)]
pub struct OsKeyring;

impl OsKeyring {
    fn entry(key: &str) -> Result<Entry, SessionError> {
        let Some((service, account)) = split_keyring_key(key) else {
            return Err(SessionError::Keyring("invalid keyring key".to_owned()));
        };
        keyring::Entry::store_status()
            .as_ref()
            .map_err(|_| SessionError::Keyring("native OS keyring unavailable".to_owned()))?;

        #[cfg(target_os = "windows")]
        {
            let target = windows_target_name(service, account);
            let modifiers = std::collections::HashMap::from([("target", target.as_str())]);
            Entry::new_with_modifiers(service, account, &modifiers)
                .map_err(|_| SessionError::Keyring("native OS keyring unavailable".to_owned()))
        }

        #[cfg(not(target_os = "windows"))]
        {
            Entry::new(service, account)
                .map_err(|_| SessionError::Keyring("native OS keyring unavailable".to_owned()))
        }
    }

    fn provider_error(_: keyring::Error) -> SessionError {
        // Provider errors may include account/service details. Keep them out of
        // the session error surface and logs.
        SessionError::Keyring("native OS keyring operation failed".to_owned())
    }

    fn decode_provider_value(value: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        #[cfg(target_os = "macos")]
        {
            decode_macos_provider_value(&value)
        }

        #[cfg(not(target_os = "macos"))]
        {
            Ok(value)
        }
    }

    fn encode_provider_value(value: &[u8]) -> Vec<u8> {
        #[cfg(target_os = "macos")]
        {
            encode_macos_provider_value(value)
        }

        #[cfg(not(target_os = "macos"))]
        {
            value.to_vec()
        }
    }
}

#[cfg(any(test, target_os = "macos"))]
fn decode_macos_provider_value(value: &[u8]) -> Result<Vec<u8>, SessionError> {
    let value = String::from_utf8(value.to_vec())
        .map_err(|_| SessionError::Keyring("native OS keyring value malformed".to_owned()))?;
    let value = value.trim();
    if let Some(encoded) = value.strip_prefix(MACOS_GO_BASE64_PREFIX) {
        return B64
            .decode(encoded)
            .map_err(|_| SessionError::Keyring("native OS keyring value malformed".to_owned()));
    }
    if let Some(encoded) = value.strip_prefix(MACOS_GO_ENCODED_PREFIX) {
        return decode_hex(encoded)
            .ok_or_else(|| SessionError::Keyring("native OS keyring value malformed".to_owned()));
    }
    Ok(value.as_bytes().to_vec())
}

#[cfg(any(test, target_os = "macos"))]
fn encode_macos_provider_value(value: &[u8]) -> Vec<u8> {
    format!("{MACOS_GO_BASE64_PREFIX}{}", B64.encode(value)).into_bytes()
}

#[cfg(any(test, target_os = "macos"))]
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

#[cfg(any(test, target_os = "macos"))]
fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_target_name(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_codec_reads_current_and_legacy_go_values() {
        let payload = b"binary\0value\xff\n";
        let current = encode_macos_provider_value(payload);
        assert_eq!(decode_macos_provider_value(&current).unwrap(), payload);

        let legacy = format!("{MACOS_GO_ENCODED_PREFIX}{}\n", hex_encode(payload));
        assert_eq!(
            decode_macos_provider_value(legacy.as_bytes()).unwrap(),
            payload
        );
    }

    #[test]
    fn macos_codec_rejects_malformed_encoded_values() {
        for value in [
            format!("{MACOS_GO_BASE64_PREFIX}not-base64"),
            format!("{MACOS_GO_ENCODED_PREFIX}abc"),
            format!("{MACOS_GO_ENCODED_PREFIX}zz"),
        ] {
            assert!(matches!(
                decode_macos_provider_value(value.as_bytes()),
                Err(SessionError::Keyring(message)) if message == "native OS keyring value malformed"
            ));
        }
    }

    #[test]
    fn windows_target_matches_go_credential_manager_address() {
        assert_eq!(windows_target_name("symvault", "alice"), "symvault:alice");
        assert_eq!(
            windows_target_name("service:with:colon", "user@example"),
            "service:with:colon:user@example"
        );
    }

    fn hex_encode(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl Keyring for OsKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        let value = Self::entry(key)?.get_secret().map_err(|error| {
            if matches!(error, keyring::Error::NoEntry) {
                SessionError::NotFound
            } else {
                Self::provider_error(error)
            }
        })?;
        Self::decode_provider_value(value)
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        Self::entry(key)?
            .set_secret(&Self::encode_provider_value(value))
            .map_err(Self::provider_error)
    }

    fn delete(&self, key: &str) -> Result<(), SessionError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(Self::provider_error(error)),
        }
    }
}
