//! Security-framework adapter for the Touch ID passphrase item.
//!
//! This talks to Keychain Services directly (issue #1034): no `security`
//! subprocess, no go-keyring value wrapper. The item is exactly Go's: a
//! generic password whose service is `symvault-biometric:<vault dir>`, whose
//! account is `passphrase`, and whose data is the raw passphrase bytes, so an
//! item written by either implementation is readable by the other.
//!
//! Lookups and deletes honour the process keychain search list; new items go to
//! the default keychain, and the duplicate fallback updates only there. That is
//! Go's behaviour (see `touchid_darwin.go`), and the same split is what lets the
//! tests aim every call at a disposable keychain instead of the operator's.
//!
//! The biometric prompt is not here: it stays with [`crate::MacOsTouchId`].

use security_framework::{
    base::Error as SecurityError,
    item::{ItemClass, ItemSearchOptions, Limit, SearchResult},
    os::macos::keychain::SecKeychain,
};
use symvault_core::keychain_status::{
    BIOMETRIC_ACCOUNT, BiometricItemStore, ERR_SEC_DUPLICATE_ITEM, ERR_SEC_ITEM_NOT_FOUND,
    ERR_SEC_PARAM, KeychainStatusError, Zeroizing, biometric_service_name, keychain_status_error,
    truncate_at_nul,
};

/// Touch ID passphrase items in the macOS Keychain.
#[derive(Default)]
pub struct SecurityBiometricItems {
    /// Receives new items and is the only keychain an in-place update touches.
    /// `None` is the default keychain, as in Go.
    target: Option<SecKeychain>,
    /// Keychains that lookups and deletes consult. `None` is the search list.
    search: Option<Vec<SecKeychain>>,
}

fn convert(error: &SecurityError) -> KeychainStatusError {
    keychain_status_error(error.code())
        .or_else(|| keychain_status_error(ERR_SEC_PARAM))
        .expect("a non-zero status always maps to an error")
}

impl SecurityBiometricItems {
    /// The production configuration: default keychain, process search list.
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    /// Aims every call at explicit keychains. Used with disposable keychains so
    /// no test ever reads or writes the operator's.
    #[must_use]
    pub fn scoped(target: SecKeychain, search: Vec<SecKeychain>) -> Self {
        Self {
            target: Some(target),
            search: Some(search),
        }
    }

    fn target(&self) -> Result<SecKeychain, KeychainStatusError> {
        match &self.target {
            Some(keychain) => Ok(keychain.clone()),
            None => SecKeychain::default().map_err(|error| convert(&error)),
        }
    }

    fn query(&self, vault: &str) -> ItemSearchOptions {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(&biometric_service_name(vault))
            .account(BIOMETRIC_ACCOUNT);
        if let Some(search) = &self.search {
            query.keychains(search);
        }
        query
    }
}

impl BiometricItemStore for SecurityBiometricItems {
    fn exists(&self, vault: &str) -> Result<bool, KeychainStatusError> {
        // Attributes only: never asks for the data, so it cannot raise a
        // keychain access prompt for an item another binary created.
        match self
            .query(vault)
            .load_attributes(true)
            .limit(Limit::Max(1))
            .search()
        {
            Ok(_) => Ok(true),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(convert(&error)),
        }
    }

    fn save(&self, vault: &str, passphrase: &[u8]) -> Result<(), KeychainStatusError> {
        let secret = truncate_at_nul(passphrase);
        let service = biometric_service_name(vault);
        // Go deletes first and ignores the result: the delete can miss while the
        // add still lands (login keychain default but not in the search list).
        let _ = self.query(vault).delete();
        let target = self.target()?;
        match target.add_generic_password(&service, BIOMETRIC_ACCOUNT, secret) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
                // Update in place, scoped to the keychain the add targeted: a
                // search-list lookup would miss the item and turn -25299 into
                // -25300.
                let (_, mut item) = target
                    .find_generic_password(&service, BIOMETRIC_ACCOUNT)
                    .map_err(|error| convert(&error))?;
                item.set_password(secret).map_err(|error| convert(&error))
            }
            Err(error) => Err(convert(&error)),
        }
    }

    fn load(&self, vault: &str) -> Result<Zeroizing<Vec<u8>>, KeychainStatusError> {
        let results = self
            .query(vault)
            .load_data(true)
            .limit(Limit::Max(1))
            .search()
            .map_err(|error| convert(&error))?;
        let Some(SearchResult::Data(data)) = results.into_iter().next() else {
            // Go: a result that is not data is errSecParam.
            return Err(keychain_status_error(ERR_SEC_PARAM).expect("non-zero"));
        };
        let mut data = Zeroizing::new(data);
        let end = truncate_at_nul(&data).len();
        data.truncate(end);
        Ok(data)
    }

    fn delete(&self, vault: &str) -> Result<(), KeychainStatusError> {
        match self.query(vault).delete() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(convert(&error)),
        }
    }
}
