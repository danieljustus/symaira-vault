//! Native operating-system keyring adapter.
//!
//! The keyring crate selects Keychain, Secret Service, or Credential Manager
//! for the target OS. This wrapper keeps the composite-key contract in the
//! Rust platform seam and translates provider-specific absence/errors without
//! exposing provider diagnostics to session callers.

#[cfg(target_os = "macos")]
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use keyring::Entry;
use symvault_core::session::{Keyring, SessionError, split_keyring_key};

#[cfg(target_os = "macos")]
const MACOS_GO_BASE64_PREFIX: &str = "go-keyring-base64:";

/// OS-backed keyring selected by the target platform.
#[derive(Default)]
pub struct OsKeyring;

impl OsKeyring {
    fn entry(key: &str) -> Result<Entry, SessionError> {
        let Some((service, account)) = split_keyring_key(key) else {
            return Err(SessionError::Keyring("invalid keyring key".to_owned()));
        };
        Entry::new(service, account)
            .map_err(|_| SessionError::Keyring("native OS keyring unavailable".to_owned()))
    }

    fn provider_error(_: keyring::Error) -> SessionError {
        // Provider errors may include account/service details. Keep them out of
        // the session error surface and logs.
        SessionError::Keyring("native OS keyring operation failed".to_owned())
    }

    fn decode_provider_value(value: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        #[cfg(target_os = "macos")]
        {
            let value = String::from_utf8(value).map_err(|_| {
                SessionError::Keyring("native OS keyring value malformed".to_owned())
            })?;
            if let Some(encoded) = value.strip_prefix(MACOS_GO_BASE64_PREFIX) {
                return B64.decode(encoded).map_err(|_| {
                    SessionError::Keyring("native OS keyring value malformed".to_owned())
                });
            }
            Ok(value.into_bytes())
        }

        #[cfg(not(target_os = "macos"))]
        {
            Ok(value)
        }
    }

    fn encode_provider_value(value: &[u8]) -> Vec<u8> {
        #[cfg(target_os = "macos")]
        {
            format!("{MACOS_GO_BASE64_PREFIX}{}", B64.encode(value)).into_bytes()
        }

        #[cfg(not(target_os = "macos"))]
        {
            value.to_vec()
        }
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
