//! Narrow C ABI over [`crate::api`].
//!
//! Contract (see `swift/Sources/CSymvaultFFI/include/symvault_ffi.h`):
//!
//! * Inputs are `(pointer, length)` byte pairs; a null pointer is accepted only
//!   with length zero. Text arguments must be UTF-8.
//! * Every function returns a status: `0` success, `1` the Go-identical error
//!   text is in `*err`, `2` an internal panic was contained, `3` the arguments
//!   were unusable (null with a length, or invalid UTF-8).
//! * Results are returned in a Rust-allocated [`SvBuf`] that the caller releases
//!   with [`symvault_buf_free`], which zeroizes before freeing. `*out` and
//!   `*err` are always initialized to empty first.
//! * No panic crosses the boundary: each call runs under `catch_unwind` (the
//!   `ffi` Cargo profile keeps `panic = "unwind"`; under `panic = "abort"` a bug
//!   aborts the process instead, it can never unwind into Swift).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use zeroize::{Zeroize, Zeroizing};

use crate::api;

/// Bytes allocated by this library.
#[repr(C)]
pub struct SvBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl SvBuf {
    const fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Moves `bytes` into an exactly sized allocation owned by the caller. The
    /// source is zeroized when it drops, so no stale copy of a secret is left
    /// behind by a reallocation (`shrink_to_fit`) or by an ignored out-parameter.
    fn from_secret(bytes: &Zeroizing<Vec<u8>>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let boxed = bytes.as_slice().to_vec().into_boxed_slice();
        let len = boxed.len();
        Self {
            ptr: Box::into_raw(boxed).cast::<u8>(),
            len,
        }
    }
}

const OK: i32 = 0;
const ERR: i32 = 1;
const PANIC: i32 = 2;
const BAD_ARGS: i32 = 3;

enum Payload {
    Nothing,
    /// Zeroized on drop, including when the caller passed no `out` pointer.
    Bytes(Zeroizing<Vec<u8>>),
    Flag(bool),
}

/// An argument failure carries its own text.
struct BadArgs(String);

/// # Safety
/// `ptr` must point to `len` readable bytes whenever `len > 0`.
unsafe fn bytes<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], BadArgs> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(BadArgs(format!("argument {name} is null")));
    }
    // SAFETY: guaranteed by the caller as documented above.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// Same as [`bytes`].
unsafe fn text<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a str, BadArgs> {
    // SAFETY: forwarded contract.
    let raw = unsafe { bytes(ptr, len, name) }?;
    std::str::from_utf8(raw).map_err(|_| BadArgs(format!("argument {name} is not valid UTF-8")))
}

/// # Safety
/// `out`, `err` and `flag` must each be null or valid for one write.
unsafe fn run(
    out: *mut SvBuf,
    err: *mut SvBuf,
    flag: *mut i32,
    call: impl FnOnce() -> Result<Result<Payload, String>, BadArgs>,
) -> i32 {
    // SAFETY: the caller supplies writable out-parameters or null.
    unsafe {
        if !out.is_null() {
            out.write(SvBuf::empty());
        }
        if !err.is_null() {
            err.write(SvBuf::empty());
        }
        if !flag.is_null() {
            flag.write(0);
        }
    }
    let outcome = catch_unwind(AssertUnwindSafe(call));
    let (status, message, payload) = match outcome {
        Ok(Err(BadArgs(message))) => (BAD_ARGS, Some(message), None),
        Ok(Ok(Err(message))) => (ERR, Some(message), None),
        Ok(Ok(Ok(payload))) => (OK, None, Some(payload)),
        Err(_) => (
            PANIC,
            Some("internal error: panic contained at the FFI boundary".to_owned()),
            None,
        ),
    };
    // SAFETY: as above.
    unsafe {
        if let Some(message) = message
            && !err.is_null()
        {
            err.write(SvBuf::from_secret(&Zeroizing::new(message.into_bytes())));
        }
        match payload {
            Some(Payload::Bytes(data)) if !out.is_null() => out.write(SvBuf::from_secret(&data)),
            Some(Payload::Flag(value)) if !flag.is_null() => flag.write(i32::from(value)),
            _ => {}
        }
    }
    status
}

fn ok_text(result: Result<impl AsRef<str>, String>) -> Result<Result<Payload, String>, BadArgs> {
    Ok(result.map(|text| Payload::Bytes(Zeroizing::new(text.as_ref().as_bytes().to_vec()))))
}

fn ok_bytes(result: Result<impl AsRef<[u8]>, String>) -> Result<Result<Payload, String>, BadArgs> {
    Ok(result.map(|data| Payload::Bytes(Zeroizing::new(data.as_ref().to_vec()))))
}

/// Releases a buffer returned by this library, zeroizing it first.
///
/// # Safety
/// `buf` must come from this library and not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_buf_free(buf: SvBuf) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    // SAFETY: `from_vec` produced exactly this boxed slice.
    let mut owned = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) };
    owned.zeroize();
}

/// Returns the ABI revision; bump when any signature changes.
#[unsafe(no_mangle)]
pub extern "C" fn symvault_ffi_abi_version() -> u32 {
    1
}

/// `GenerateIdentity() (string, error)`.
///
/// # Safety
/// Out-parameters must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_generate_identity(out: *mut SvBuf, err: *mut SvBuf) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            ok_text(api::generate_identity())
        })
    }
}

/// `IdentityPublicKey(identity) (string, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_identity_public_key(
    identity: *const u8,
    identity_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let identity = text(identity, identity_len, "identity")?;
            ok_text(api::identity_public_key(identity))
        })
    }
}

/// `PublicKeyFingerprint(pubkey) string` (cannot fail).
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_public_key_fingerprint(
    pubkey: *const u8,
    pubkey_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let pubkey = text(pubkey, pubkey_len, "pubkey")?;
            ok_text(Ok::<_, String>(api::public_key_fingerprint(pubkey)))
        })
    }
}

/// `EncryptWithPublicKey(recipient, plaintext) ([]byte, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_encrypt_with_public_key(
    recipient: *const u8,
    recipient_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let recipient = text(recipient, recipient_len, "recipient")?;
            let plaintext = bytes(plaintext, plaintext_len, "plaintext")?;
            ok_bytes(api::encrypt_with_public_key(recipient, plaintext))
        })
    }
}

/// `DecryptWithIdentity(identity, ciphertext) ([]byte, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_decrypt_with_identity(
    identity: *const u8,
    identity_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let identity = text(identity, identity_len, "identity")?;
            let ciphertext = bytes(ciphertext, ciphertext_len, "ciphertext")?;
            ok_bytes(api::decrypt_with_identity(identity, ciphertext))
        })
    }
}

/// `EncryptWithPassphrase(passphrase, plaintext) ([]byte, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_encrypt_with_passphrase(
    passphrase: *const u8,
    passphrase_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let passphrase = bytes(passphrase, passphrase_len, "passphrase")?;
            let plaintext = bytes(plaintext, plaintext_len, "plaintext")?;
            ok_bytes(api::encrypt_with_passphrase(passphrase, plaintext))
        })
    }
}

/// `DecryptWithPassphrase(passphrase, ciphertext) ([]byte, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_decrypt_with_passphrase(
    passphrase: *const u8,
    passphrase_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let passphrase = bytes(passphrase, passphrase_len, "passphrase")?;
            let ciphertext = bytes(ciphertext, ciphertext_len, "ciphertext")?;
            ok_bytes(api::decrypt_with_passphrase(passphrase, ciphertext))
        })
    }
}

/// `InitVault(vaultDir, passphrase) error`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_init_vault(
    vault_dir: *const u8,
    vault_dir_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(std::ptr::null_mut(), err, std::ptr::null_mut(), || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let passphrase = bytes(passphrase, passphrase_len, "passphrase")?;
            Ok(api::init_vault(vault_dir, passphrase).map(|()| Payload::Nothing))
        })
    }
}

/// `OpenVaultWithPassphrase(vaultDir, passphrase) (string, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_open_vault_with_passphrase(
    vault_dir: *const u8,
    vault_dir_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let passphrase = bytes(passphrase, passphrase_len, "passphrase")?;
            ok_text(api::open_vault_with_passphrase(vault_dir, passphrase))
        })
    }
}

/// `ReadEntryJSON(vaultDir, entryPath, identity) (string, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_read_entry_json(
    vault_dir: *const u8,
    vault_dir_len: usize,
    entry_path: *const u8,
    entry_path_len: usize,
    identity: *const u8,
    identity_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let entry_path = text(entry_path, entry_path_len, "entryPath")?;
            let identity = text(identity, identity_len, "identity")?;
            ok_text(api::read_entry_json(vault_dir, entry_path, identity))
        })
    }
}

/// `WriteEntryJSON(vaultDir, entryPath, entryJSON, identity) error`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
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
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(std::ptr::null_mut(), err, std::ptr::null_mut(), || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let entry_path = text(entry_path, entry_path_len, "entryPath")?;
            let entry_json = text(entry_json, entry_json_len, "entryJSON")?;
            let identity = text(identity, identity_len, "identity")?;
            Ok(
                api::write_entry_json(vault_dir, entry_path, entry_json, identity)
                    .map(|()| Payload::Nothing),
            )
        })
    }
}

/// `ListEntriesJSON(vaultDir, prefix, identity) (string, error)`.
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_list_entries_json(
    vault_dir: *const u8,
    vault_dir_len: usize,
    prefix: *const u8,
    prefix_len: usize,
    identity: *const u8,
    identity_len: usize,
    out: *mut SvBuf,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(out, err, std::ptr::null_mut(), || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let prefix = text(prefix, prefix_len, "prefix")?;
            let identity = text(identity, identity_len, "identity")?;
            ok_text(api::list_entries_json(vault_dir, prefix, identity))
        })
    }
}

/// `VerifyManifestIntegrity(vaultDir, identity) (bool, error)`; the boolean is
/// written to `*ok` (1 or 0).
///
/// # Safety
/// Pointer/length pairs must be valid; out-parameters null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_verify_manifest_integrity(
    vault_dir: *const u8,
    vault_dir_len: usize,
    identity: *const u8,
    identity_len: usize,
    ok: *mut i32,
    err: *mut SvBuf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(std::ptr::null_mut(), err, ok, || {
            let vault_dir = text(vault_dir, vault_dir_len, "vaultDir")?;
            let identity = text(identity, identity_len, "identity")?;
            Ok(api::verify_manifest_integrity(vault_dir, identity).map(Payload::Flag))
        })
    }
}

/// Test hook: runs a closure that panics, proving containment.
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_ffi_selftest_panic(err: *mut SvBuf) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        run(
            std::ptr::null_mut(),
            err,
            std::ptr::null_mut(),
            || -> Result<Result<Payload, String>, BadArgs> { panic!("selftest panic") },
        )
    }
}
