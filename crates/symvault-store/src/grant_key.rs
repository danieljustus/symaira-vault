//! Grant-signing key loading with the Go-compatible keyring contract.

use std::{io, path::Path};

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
use std::fs;

use symvault_core::session::Keyring;
use symvault_crypto::{Identity, SecretBytes};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "symaira";
const KEYRING_ACCOUNT_PREFIX: &str = "grant-signing-key:";
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const KEY_FILE_NAME: &str = "grant-signing-key";
const KEY_BYTES: usize = 32;
const KEY_HEX_BYTES: usize = KEY_BYTES * 2;
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const AGE_HEADER: &[u8] = b"age-encryption.org/";

/// Returns the keyring address used by Go's grant-sharing server.
pub fn grant_keyring_address(directory: &Path) -> io::Result<String> {
    let directory = directory.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "grant key path is not valid UTF-8")
    })?;
    if directory.contains('|') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "grant key path contains a reserved separator",
        ));
    }
    Ok(format!("{KEYRING_SERVICE}|{KEYRING_ACCOUNT_PREFIX}{directory}"))
}

/// Loads or creates the 32-byte grant HMAC key.
///
/// On darwin, linux, and windows, persistence is delegated to the supplied
/// keyring. The caller may provide the process-local fallback adapter used by
/// the platform layer. Other targets use Go's encrypted file fallback.
pub fn load_or_create_grant_signing_key(
    directory: &Path,
    keyring: &dyn Keyring,
    _identity: Option<&Identity>,
) -> io::Result<SecretBytes> {
    if !directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "grant key directory does not exist",
        ));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = keyring;
        return load_or_create_file_key(directory, _identity);
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let address = grant_keyring_address(directory)?;
        if let Ok(encoded) = keyring.get(&address) {
            let encoded = Zeroizing::new(encoded);
            if let Ok(key) = decode_key(&encoded) {
                return Ok(key);
            }
        }

        let mut bytes = Zeroizing::new(vec![0u8; KEY_BYTES]);
        getrandom::fill(&mut bytes)
            .map_err(|error| io::Error::other(format!("generate grant signing key: {error}")))?;
        let encoded = Zeroizing::new(encode_key(&bytes));
        keyring
            .set(&address, encoded.as_bytes())
            .map_err(|error| io::Error::other(format!("store grant signing key: {error}")))?;
        Ok(SecretBytes::new(&bytes))
    }
}

fn encode_key(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_key(encoded: &[u8]) -> io::Result<SecretBytes> {
    if !encoded.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid grant signing key encoding",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_BYTES));
    for pair in encoded.chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid grant signing key encoding")
        })?;
        let low = hex_digit(pair[1]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid grant signing key encoding")
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(SecretBytes::new(&bytes))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn load_or_create_file_key(
    directory: &Path,
    identity: Option<&Identity>,
) -> io::Result<SecretBytes> {
    let root_cap = crate::open_directory_nofollow(directory)?;
    let _lock = crate::open_root_write_lock(&root_cap, directory).map_err(store_error_to_io)?;
    let path = directory.join(KEY_FILE_NAME);
    match read_file_key(&root_cap, &path) {
        Ok(data) => {
            let encrypted = data.starts_with(AGE_HEADER);
            let data = Zeroizing::new(data);
            let plaintext = if encrypted {
                let identity = identity.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "grant signing key identity is required",
                    )
                })?;
                let decrypted = symvault_crypto::decrypt(&data, identity)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
                Zeroizing::new(decrypted)
            } else {
                data
            };
            if plaintext.len() != KEY_BYTES {
                let mut bytes = Zeroizing::new(vec![0u8; KEY_BYTES]);
                getrandom::fill(&mut bytes).map_err(|error| {
                    io::Error::other(format!("generate grant signing key: {error}"))
                })?;
                let output = encrypt_file_key(&bytes, identity)?;
                write_file_key(&root_cap, &path, &output)?;
                return Ok(SecretBytes::new(&bytes));
            }
            if !encrypted {
                if let Some(identity) = identity {
                    let output = encrypt_file_key(&plaintext, Some(identity))?;
                    write_file_key(&root_cap, &path, &output)?;
                }
            }
            Ok(SecretBytes::new(&plaintext))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut bytes = Zeroizing::new(vec![0u8; KEY_BYTES]);
            getrandom::fill(&mut bytes)
                .map_err(|error| io::Error::other(format!("generate grant signing key: {error}")))?;
            let output = encrypt_file_key(&bytes, identity)?;
            write_file_key(&root_cap, &path, &output)?;
            Ok(SecretBytes::new(&bytes))
        }
        Err(error) => Err(error),
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
))]
fn read_file_key(root_cap: &fs::File, path: &Path) -> io::Result<Vec<u8>> {
    crate::rooted::read(root_cap, Path::new(KEY_FILE_NAME), path).map_err(store_error_to_io)
}

#[cfg(all(
    not(unix),
    not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
))]
fn read_file_key(_root_cap: &fs::File, path: &Path) -> io::Result<Vec<u8>> {
    crate::read_regular(path).map_err(store_error_to_io)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn write_file_key(root_cap: &fs::File, path: &Path, bytes: &[u8]) -> io::Result<()> {
    crate::publication::replace(path, bytes, root_cap).map_err(store_error_to_io)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn store_error_to_io(error: crate::StoreError) -> io::Error {
    match error {
        crate::StoreError::Read { source, .. } | crate::StoreError::Write { source, .. } => source,
        crate::StoreError::MissingFile(_) => io::Error::new(
            io::ErrorKind::NotFound,
            "grant signing key file does not exist",
        ),
        crate::StoreError::Limit { .. } => io::Error::new(
            io::ErrorKind::InvalidData,
            "grant signing key file exceeds the store read limit",
        ),
        crate::StoreError::Symlink(_) | crate::StoreError::NotRegularFile(_) => {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "grant signing key path is not a regular file",
            )
        }
        other => io::Error::other(other.to_string()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn encrypt_file_key(bytes: &[u8], identity: Option<&Identity>) -> io::Result<Vec<u8>> {
    let Some(identity) = identity else {
        return Ok(bytes.to_vec());
    };
    let recipient = symvault_crypto::parse_recipient(&symvault_crypto::recipient_string(identity))
        .map_err(|error| io::Error::other(error.to_string()))?;
    symvault_crypto::encrypt(bytes, &[recipient])
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use symvault_core::session::MemoryKeyring;

    #[test]
    fn keyring_roundtrip_uses_go_address_and_hex_payload() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keyring = MemoryKeyring::new();
        let first = load_or_create_grant_signing_key(directory.path(), &keyring, None)
            .expect("create grant key");
        assert_eq!(first.as_bytes().len(), KEY_BYTES);

        let address = grant_keyring_address(directory.path()).expect("address");
        let encoded = keyring.get(&address).expect("keyring value");
        assert_eq!(encoded.len(), KEY_HEX_BYTES);
        assert!(encoded.iter().all(|byte| byte.is_ascii_hexdigit()));

        let second = load_or_create_grant_signing_key(directory.path(), &keyring, None)
            .expect("load grant key");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert!(!directory.path().join("grant-signing-key").exists());
    }

    #[test]
    fn malformed_keyring_value_is_rejected_without_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keyring = MemoryKeyring::new();
        let address = grant_keyring_address(directory.path()).expect("address");
        keyring
            .set(&address, b"not-a-32-byte-hex-key")
            .expect("seed malformed key");
        let replacement = load_or_create_grant_signing_key(directory.path(), &keyring, None)
            .expect("replace malformed key");
        assert_eq!(replacement.as_bytes().len(), KEY_BYTES);
        let encoded = keyring.get(&address).expect("replacement key");
        assert_eq!(encoded.len(), KEY_HEX_BYTES);
        assert_ne!(encoded, b"not-a-32-byte-hex-key");
    }

    #[test]
    fn valid_non_32_byte_hex_key_is_preserved_like_go() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keyring = MemoryKeyring::new();
        let address = grant_keyring_address(directory.path()).expect("address");
        keyring.set(&address, b"ab").expect("seed short key");
        let loaded = load_or_create_grant_signing_key(directory.path(), &keyring, None)
            .expect("load short key");
        assert_eq!(loaded.as_bytes(), &[0xab]);
    }
}
