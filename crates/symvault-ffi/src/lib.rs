#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow C ABI for the mobile crypto slice. Returned buffers belong to Rust
//! and must be released with [`symvault_buffer_free`]. Inputs are borrowed.

use std::{
    path::Path,
    ptr, slice, str,
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_crypto::{
    SecretBytes, decrypt, decrypt_scrypt, encrypt, encrypt_scrypt, fingerprint, generate_identity,
    identity_string, parse_identity, parse_recipient, recipient_string,
};
use symvault_store::{Entry, Store};
use zeroize::Zeroize;

/// Owned byte buffer returned across the C ABI.
#[repr(C)]
pub struct SymvaultBuffer {
    data: *mut u8,
    len: usize,
}

/// Result of one FFI operation. `error` is nonempty on failure.
#[repr(C)]
pub struct SymvaultResult {
    output: SymvaultBuffer,
    error: SymvaultBuffer,
}

fn empty_buffer() -> SymvaultBuffer {
    SymvaultBuffer {
        data: ptr::null_mut(),
        len: 0,
    }
}

fn owned_buffer(bytes: Vec<u8>) -> SymvaultBuffer {
    if bytes.is_empty() {
        return empty_buffer();
    }
    let mut boxed = bytes.into_boxed_slice();
    let buffer = SymvaultBuffer {
        data: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    buffer
}

fn result(output: Result<Vec<u8>, String>) -> SymvaultResult {
    match output {
        Ok(bytes) => SymvaultResult {
            output: owned_buffer(bytes),
            error: empty_buffer(),
        },
        Err(message) => SymvaultResult {
            output: empty_buffer(),
            error: owned_buffer(message.into_bytes()),
        },
    }
}

fn ffi(operation: impl FnOnce() -> Result<Vec<u8>, String>) -> SymvaultResult {
    result(operation())
}

fn utc_now_rfc3339() -> Result<String, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    let seconds = i64::try_from(elapsed.as_secs())
        .map_err(|_| "system clock is outside RFC3339 range".to_owned())?;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);

    // Civil date from days since 1970-01-01 (proleptic Gregorian calendar).
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days / 146_097
    } else {
        (shifted_days - 146_096) / 146_097
    };
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let nanos = elapsed.subsec_nanos();
    let fraction = if nanos == 0 {
        String::new()
    } else {
        format!(".{}", format!("{nanos:09}").trim_end_matches('0'))
    };
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}Z"
    ))
}

unsafe fn input<'a>(data: *const u8, len: usize, label: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if len > isize::MAX as usize {
        return Err(format!("{label} is too large"));
    }
    if data.is_null() {
        return Err(format!("{label} is null"));
    }
    // SAFETY: the caller promises `data` points to `len` readable bytes.
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

unsafe fn text<'a>(data: *const u8, len: usize, label: &str) -> Result<&'a str, String> {
    str::from_utf8(unsafe { input(data, len, label)? })
        .map(str::trim)
        .map_err(|_| format!("{label} is not UTF-8"))
}

unsafe fn utf8<'a>(data: *const u8, len: usize, label: &str) -> Result<&'a str, String> {
    str::from_utf8(unsafe { input(data, len, label)? }).map_err(|_| format!("{label} is not UTF-8"))
}

/// Frees a buffer returned in a result. A zero-length buffer is a no-op.
///
/// # Safety
/// A nonempty buffer must be an unfreed buffer returned by this crate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_buffer_free(buffer: SymvaultBuffer) {
    if buffer.len == 0 || buffer.data.is_null() {
        return;
    }
    // SAFETY: callers must pass a buffer allocated by `owned_buffer`, exactly
    // once. The allocation is wiped before being released.
    unsafe {
        let raw = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
        slice::from_raw_parts_mut(buffer.data, buffer.len).zeroize();
        drop(Box::from_raw(raw));
    }
}

/// Generates an age X25519 identity string.
#[unsafe(no_mangle)]
pub extern "C" fn symvault_generate_identity() -> SymvaultResult {
    ffi(|| {
        let identity = generate_identity();
        Ok(identity_string(&identity).as_bytes().to_vec())
    })
}

/// Derives the age recipient string from a private identity.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_identity_public_key(
    identity: *const u8,
    identity_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity = parse_identity(identity).map_err(|error| error.to_string())?;
        Ok(recipient_string(&identity).into_bytes())
    })
}

/// Computes the Go-compatible fingerprint for a public key string.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_public_key_fingerprint(
    public_key: *const u8,
    public_key_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let public_key = unsafe { text(public_key, public_key_len, "public key")? };
        Ok(fingerprint(public_key).into_bytes())
    })
}

/// Encrypts bytes for an age recipient.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_encrypt_with_public_key(
    recipient: *const u8,
    recipient_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let recipient = unsafe { text(recipient, recipient_len, "recipient")? };
        let recipient = parse_recipient(recipient).map_err(|error| error.to_string())?;
        let plaintext = unsafe { input(plaintext, plaintext_len, "plaintext")? };
        if plaintext.is_empty() {
            return Err("plaintext is empty".to_owned());
        }
        encrypt(plaintext, std::slice::from_ref(&recipient)).map_err(|error| error.to_string())
    })
}

/// Decrypts bytes with an age X25519 identity.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_decrypt_with_identity(
    identity: *const u8,
    identity_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity = parse_identity(identity).map_err(|error| error.to_string())?;
        let ciphertext = unsafe { input(ciphertext, ciphertext_len, "ciphertext")? };
        if ciphertext.is_empty() {
            return Err("ciphertext is empty".to_owned());
        }
        decrypt(ciphertext, &identity).map_err(|error| error.to_string())
    })
}

/// Encrypts bytes with the legacy age scrypt envelope used by the Go API.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_encrypt_with_passphrase(
    passphrase: *const u8,
    passphrase_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let passphrase = unsafe { input(passphrase, passphrase_len, "passphrase")? };
        if passphrase.is_empty() {
            return Err("passphrase is empty".to_owned());
        }
        str::from_utf8(passphrase).map_err(|_| "passphrase is not UTF-8".to_owned())?;
        let plaintext = unsafe { input(plaintext, plaintext_len, "plaintext")? };
        if plaintext.is_empty() {
            return Err("plaintext is empty".to_owned());
        }
        encrypt_scrypt(plaintext, &SecretBytes::new(passphrase), 18)
            .map_err(|error| error.to_string())
    })
}

/// Decrypts a legacy age scrypt envelope with a passphrase.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_decrypt_with_passphrase(
    passphrase: *const u8,
    passphrase_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let passphrase = unsafe { input(passphrase, passphrase_len, "passphrase")? };
        if passphrase.is_empty() {
            return Err("passphrase is empty".to_owned());
        }
        str::from_utf8(passphrase).map_err(|_| "passphrase is not UTF-8".to_owned())?;
        let ciphertext = unsafe { input(ciphertext, ciphertext_len, "ciphertext")? };
        if ciphertext.is_empty() {
            return Err("ciphertext is empty".to_owned());
        }
        decrypt_scrypt(ciphertext, &SecretBytes::new(passphrase)).map_err(|error| error.to_string())
    })
}

/// Reads a decrypted entry as Go-compatible JSON.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_read_entry_json(
    vault_dir: *const u8,
    vault_dir_len: usize,
    entry_path: *const u8,
    entry_path_len: usize,
    identity: *const u8,
    identity_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        let entry_path = unsafe { utf8(entry_path, entry_path_len, "entry path")? };
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity = parse_identity(identity).map_err(|error| error.to_string())?;
        let store =
            Store::open(Path::new(vault_dir), &identity).map_err(|error| error.to_string())?;
        let entry = store
            .get(entry_path, &identity)
            .map_err(|error| error.to_string())?;
        symvault_gojson::to_string(&entry)
            .map(String::into_bytes)
            .map_err(|error| error.to_string())
    })
}

/// Parses a Go mobile Entry JSON payload and writes the encrypted entry.
/// Success has empty output and empty error buffers.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_write_entry_json(
    vault_dir: *const u8,
    vault_dir_len: usize,
    entry_path: *const u8,
    entry_path_len: usize,
    entry_json: *const u8,
    entry_json_len: usize,
    identity: *const u8,
    identity_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        let entry_path = unsafe { utf8(entry_path, entry_path_len, "entry path")? };
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity =
            parse_identity(identity).map_err(|error| format!("validate identity: {error}"))?;
        let entry_bytes = unsafe { input(entry_json, entry_json_len, "entry JSON")? };
        // encoding/json replaces invalid UTF-8 with U+FFFD before decoding.
        let entry_json = String::from_utf8_lossy(entry_bytes);
        let entry_value = serde_json::from_str::<serde_json::Value>(&entry_json)
            .map_err(|error| format!("unmarshal entry: {error}"))?;
        // encoding/json accepts top-level null for a non-pointer struct and
        // leaves it zero-valued; Entry's custom Go unmarshaller initializes
        // its data map afterwards.
        let entry = if entry_value.is_null() {
            Entry::default()
        } else {
            serde_json::from_value::<Entry>(entry_value)
                .map_err(|error| format!("unmarshal entry: {error}"))?
        };
        let store = Store::open(Path::new(vault_dir), &identity)
            .map_err(|error| format!("open vault: {error}"))?;
        let now = utc_now_rfc3339().map_err(|error| format!("write entry: {error}"))?;
        store
            .write_entry_at(entry_path, &entry, &identity, &now, false, None)
            .map_err(|error| format!("write entry: {error}"))?;
        Ok(Vec::new())
    })
}

/// Lists matching vault entry paths as a JSON array.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_list_entries_json(
    vault_dir: *const u8,
    vault_dir_len: usize,
    prefix: *const u8,
    prefix_len: usize,
    identity: *const u8,
    identity_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        let prefix = unsafe { utf8(prefix, prefix_len, "prefix")? };
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity = parse_identity(identity).map_err(|error| error.to_string())?;
        let store =
            Store::open(Path::new(vault_dir), &identity).map_err(|error| error.to_string())?;
        let paths = store.list(&identity).map_err(|error| error.to_string())?;
        let paths: Vec<_> = paths
            .into_iter()
            .filter(|path| path.starts_with(prefix))
            .collect();
        symvault_gojson::to_string(&paths)
            .map(String::into_bytes)
            .map_err(|error| error.to_string())
    })
}

/// Returns a single byte: one for intact manifest, zero for missing or tampered entries.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_verify_manifest_integrity(
    vault_dir: *const u8,
    vault_dir_len: usize,
    identity: *const u8,
    identity_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        let identity = unsafe { text(identity, identity_len, "identity")? };
        let identity = parse_identity(identity).map_err(|error| error.to_string())?;
        let store =
            Store::open(Path::new(vault_dir), &identity).map_err(|error| error.to_string())?;
        let checked = store
            .verify_manifest(&identity)
            .map_err(|error| error.to_string())?;
        Ok(vec![u8::from(
            checked.missing.is_empty() && checked.tampered.is_empty(),
        )])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::fs;

    fn take(buffer: SymvaultBuffer) -> Vec<u8> {
        if buffer.len == 0 {
            return Vec::new();
        }
        // SAFETY: test inputs are outputs allocated by this crate.
        let bytes = unsafe { slice::from_raw_parts(buffer.data, buffer.len) }.to_vec();
        unsafe { symvault_buffer_free(buffer) };
        bytes
    }

    fn output(result: SymvaultResult) -> Result<Vec<u8>, String> {
        let error = take(result.error);
        if !error.is_empty() {
            unsafe { symvault_buffer_free(result.output) };
            return Err(String::from_utf8(error).unwrap());
        }
        Ok(take(result.output))
    }

    #[test]
    fn identity_public_key_and_fingerprint_round_trip() {
        let identity = output(symvault_generate_identity()).unwrap();
        let public_key = unsafe {
            output(symvault_identity_public_key(
                identity.as_ptr(),
                identity.len(),
            ))
            .unwrap()
        };
        let fingerprint = unsafe {
            output(symvault_public_key_fingerprint(
                public_key.as_ptr(),
                public_key.len(),
            ))
            .unwrap()
        };
        assert_eq!(fingerprint.len(), 39);
    }

    #[test]
    fn recipient_encryption_round_trips() {
        let identity = output(symvault_generate_identity()).unwrap();
        let public_key = unsafe {
            output(symvault_identity_public_key(
                identity.as_ptr(),
                identity.len(),
            ))
            .unwrap()
        };
        let plaintext = b"\xff\0mobile ffi payload";
        let ciphertext = unsafe {
            output(symvault_encrypt_with_public_key(
                public_key.as_ptr(),
                public_key.len(),
                plaintext.as_ptr(),
                plaintext.len(),
            ))
            .unwrap()
        };
        let decrypted = unsafe {
            output(symvault_decrypt_with_identity(
                identity.as_ptr(),
                identity.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
            .unwrap()
        };
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn passphrase_encryption_round_trips_and_wrong_key_errors() {
        let passphrase = b"test passphrase";
        let plaintext = b"\xff\0mobile ffi payload";
        let ciphertext = unsafe {
            output(symvault_encrypt_with_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                plaintext.as_ptr(),
                plaintext.len(),
            ))
            .unwrap()
        };
        let decrypted = unsafe {
            output(symvault_decrypt_with_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
            .unwrap()
        };
        assert_eq!(decrypted, plaintext);

        let wrong_passphrase = b"wrong";
        let failure = unsafe {
            output(symvault_decrypt_with_passphrase(
                wrong_passphrase.as_ptr(),
                wrong_passphrase.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
        };
        assert!(failure.is_err());
    }

    #[test]
    fn invalid_utf8_is_reported_without_crossing_the_abi() {
        let invalid = [0xff];
        let error = unsafe {
            output(symvault_identity_public_key(
                invalid.as_ptr(),
                invalid.len(),
            ))
            .unwrap_err()
        };
        assert!(error.contains("not UTF-8"));
    }

    #[test]
    fn empty_plaintext_and_ciphertext_match_go_errors() {
        let identity = output(symvault_generate_identity()).unwrap();
        let public_key = unsafe {
            output(symvault_identity_public_key(
                identity.as_ptr(),
                identity.len(),
            ))
            .unwrap()
        };
        let passphrase = b"test passphrase";

        let encrypt_error = unsafe {
            output(symvault_encrypt_with_public_key(
                public_key.as_ptr(),
                public_key.len(),
                ptr::null(),
                0,
            ))
            .unwrap_err()
        };
        assert_eq!(encrypt_error, "plaintext is empty");

        let passphrase_encrypt_error = unsafe {
            output(symvault_encrypt_with_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                ptr::null(),
                0,
            ))
            .unwrap_err()
        };
        assert_eq!(passphrase_encrypt_error, "plaintext is empty");

        let decrypt_error = unsafe {
            output(symvault_decrypt_with_identity(
                identity.as_ptr(),
                identity.len(),
                ptr::null(),
                0,
            ))
            .unwrap_err()
        };
        assert_eq!(decrypt_error, "ciphertext is empty");

        let passphrase_decrypt_error = unsafe {
            output(symvault_decrypt_with_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                ptr::null(),
                0,
            ))
            .unwrap_err()
        };
        assert_eq!(passphrase_decrypt_error, "ciphertext is empty");
    }

    #[test]
    fn oversized_inputs_are_rejected_before_slice_creation() {
        let error = unsafe {
            output(symvault_public_key_fingerprint(
                ptr::null(),
                isize::MAX as usize + 1,
            ))
            .unwrap_err()
        };
        assert_eq!(error, "public key is too large");
    }

    #[test]
    fn mobile_read_bridge_replays_go_vault_fixture() {
        const IDENTITY: &[u8] =
            b"AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/store/store.json"
        )))
        .unwrap();
        let vault = &fixture["vaults"][0];
        let root = tempfile::tempdir().unwrap();
        for file in vault["migration"]["after"]["files"].as_array().unwrap() {
            let path = root.path().join(file["path"].as_str().unwrap());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                path,
                STANDARD.decode(file["content"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        let root_bytes = root.path().to_str().unwrap().as_bytes();
        for expected in vault["entries"].as_array().unwrap() {
            let entry_path = expected["path"].as_str().unwrap().as_bytes();
            let entry = unsafe {
                output(symvault_read_entry_json(
                    root_bytes.as_ptr(),
                    root_bytes.len(),
                    entry_path.as_ptr(),
                    entry_path.len(),
                    IDENTITY.as_ptr(),
                    IDENTITY.len(),
                ))
                .unwrap()
            };
            assert_eq!(
                entry,
                expected["expected_json"].as_str().unwrap().as_bytes()
            );
        }

        let prefix = b"nested/";
        let listed = unsafe {
            output(symvault_list_entries_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                prefix.as_ptr(),
                prefix.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(listed, br#"["nested/large"]"#);

        let valid = unsafe {
            output(symvault_verify_manifest_integrity(
                root_bytes.as_ptr(),
                root_bytes.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(valid, [1]);
        fs::write(root.path().join("entries/minimal.age"), b"tampered").unwrap();
        let invalid = unsafe {
            output(symvault_verify_manifest_integrity(
                root_bytes.as_ptr(),
                root_bytes.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(invalid, [0]);
    }

    #[test]
    fn mobile_write_bridge_matches_go_json_validation_and_manifest_contract() {
        const IDENTITY: &[u8] =
            b"AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/store/store.json"
        )))
        .unwrap();
        let vault = &fixture["vaults"][0];
        let root = tempfile::tempdir().unwrap();
        for file in vault["migration"]["after"]["files"].as_array().unwrap() {
            let path = root.path().join(file["path"].as_str().unwrap());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                path,
                STANDARD.decode(file["content"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        let root_bytes = root.path().to_str().unwrap().as_bytes();
        let entry_path = b"mobile/contracts/write-entry";
        let entry_json = br#"{"data":{"username":"ffi-user","password":"ffi-secret"}}"#;

        let intact = unsafe {
            output(symvault_verify_manifest_integrity(
                root_bytes.as_ptr(),
                root_bytes.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(intact, [1], "Go fixture starts with an intact manifest");

        let written = unsafe {
            output(symvault_write_entry_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                entry_path.as_ptr(),
                entry_path.len(),
                entry_json.as_ptr(),
                entry_json.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
        }
        .unwrap();
        assert!(
            written.is_empty(),
            "Go error-only API has no success payload"
        );

        let read = unsafe {
            output(symvault_read_entry_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                entry_path.as_ptr(),
                entry_path.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
        }
        .unwrap();
        let read: serde_json::Value = serde_json::from_slice(&read).unwrap();
        assert_eq!(read["data"]["username"], "ffi-user");
        assert_eq!(read["data"]["password"], "ffi-secret");
        assert_eq!(read["meta"]["version"], 1);
        assert_ne!(read["meta"]["created"], "0001-01-01T00:00:00Z");
        assert_eq!(read["meta"]["created"], read["meta"]["updated"]);

        let listed = unsafe {
            output(symvault_list_entries_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                b"mobile/".as_ptr(),
                b"mobile/".len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
        }
        .unwrap();
        let listed: Vec<String> = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed, ["mobile/contracts/write-entry"]);

        // An intact manifest after the new write proves the writer updated its
        // encrypted manifest entry instead of only publishing the .age file.
        let intact_after_write = unsafe {
            output(symvault_verify_manifest_integrity(
                root_bytes.as_ptr(),
                root_bytes.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(intact_after_write, [1]);

        let malformed = b"{";
        let malformed_error = unsafe {
            output(symvault_write_entry_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                entry_path.as_ptr(),
                entry_path.len(),
                malformed.as_ptr(),
                malformed.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
        }
        .unwrap_err();
        assert!(malformed_error.starts_with("unmarshal entry:"));

        let unsafe_path = b"../outside";
        let unsafe_path_error = unsafe {
            output(symvault_write_entry_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                unsafe_path.as_ptr(),
                unsafe_path.len(),
                entry_json.as_ptr(),
                entry_json.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
        }
        .unwrap_err();
        assert!(unsafe_path_error.starts_with("write entry:"));

        let invalid_identity = b"not-an-identity";
        let identity_error = unsafe {
            output(symvault_write_entry_json(
                root_bytes.as_ptr(),
                root_bytes.len(),
                entry_path.as_ptr(),
                entry_path.len(),
                entry_json.as_ptr(),
                entry_json.len(),
                invalid_identity.as_ptr(),
                invalid_identity.len(),
            ))
        }
        .unwrap_err();
        assert!(identity_error.starts_with("validate identity:"));

        let intact_after_errors = unsafe {
            output(symvault_verify_manifest_integrity(
                root_bytes.as_ptr(),
                root_bytes.len(),
                IDENTITY.as_ptr(),
                IDENTITY.len(),
            ))
            .unwrap()
        };
        assert_eq!(intact_after_errors, [1]);
    }
}
