//! Native operating-system keyring adapter.
//!
//! The keyring crate selects Keychain, Secret Service, or Credential Manager
//! for the target OS. This wrapper keeps the composite-key contract in the
//! Rust platform seam and translates provider-specific absence/errors without
//! exposing provider diagnostics to session callers.

use keyring::Entry;
use symvault_core::session::{Keyring, SessionError, split_keyring_key};

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
}

impl Keyring for OsKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        Self::entry(key)?.get_secret().map_err(|error| {
            if matches!(error, keyring::Error::NoEntry) {
                SessionError::NotFound
            } else {
                Self::provider_error(error)
            }
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        Self::entry(key)?
            .set_secret(value)
            .map_err(Self::provider_error)
    }

    fn delete(&self, key: &str) -> Result<(), SessionError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(Self::provider_error(error)),
        }
    }
}
