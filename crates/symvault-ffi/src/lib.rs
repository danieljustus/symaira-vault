#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow C ABI for the mobile crypto slice. Returned buffers belong to Rust
//! and must be released with [`symvault_buffer_free`]. Inputs are borrowed.

use std::{ptr, slice, str};

use symvault_crypto::{
    SecretBytes, decrypt, decrypt_scrypt, encrypt, encrypt_scrypt, fingerprint, generate_identity,
    identity_string, parse_identity, parse_recipient, recipient_string,
};
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

unsafe fn input<'a>(data: *const u8, len: usize, label: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
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
        decrypt_scrypt(ciphertext, &SecretBytes::new(passphrase)).map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
