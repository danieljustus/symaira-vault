#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow C ABI for the mobile crypto slice. Returned buffers belong to Rust
//! and must be released with [`symvault_buffer_free`]. Inputs are borrowed.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    ptr, slice, str,
    sync::atomic::{AtomicU64, Ordering},
};

use symvault_crypto::{
    Argon2idParams, FailureClass, SecretBytes, ZeroKeyAuthority, classify_zero_key_candidate,
    decrypt, decrypt_argon2id, decrypt_identity, decrypt_scrypt, encrypt,
    encrypt_identity_argon2id, encrypt_scrypt, fingerprint, generate_identity, identity_string,
    needs_kdf_migration, parse_identity, parse_recipient, recipient_string,
    recover_zero_key_identity,
};
use symvault_store::{Entry, Store, utc_now_string};
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

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("file is a symlink: {}", path.display()));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(format!("file is not a regular file: {}", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let parent = path
        .parent()
        .ok_or_else(|| "vault path has no parent".to_owned())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "vault path has an invalid filename".to_owned())?;
    for _ in 0..32 {
        let temporary = parent.join(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            Ok::<_, std::io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result.map_err(|error| error.to_string());
    }
    Err("could not allocate a temporary vault file".to_owned())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{label} is a symlink: {}", path.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect {label}: {error}")),
    }
}

fn read_private_regular(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("read {label}: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} is a symlink: {}", path.display()));
    }
    if !metadata.is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    if metadata.len() > symvault_store::MAX_FILE_BYTES {
        return Err(format!(
            "{label} exceeds {} bytes",
            symvault_store::MAX_FILE_BYTES
        ));
    }
    let file = fs::File::open(path).map_err(|error| format!("read {label}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(symvault_store::MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.len() as u64 > symvault_store::MAX_FILE_BYTES {
        return Err(format!(
            "{label} exceeds {} bytes",
            symvault_store::MAX_FILE_BYTES
        ));
    }
    Ok(bytes)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string());
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn zero_key_authorities(raw: &[u8]) -> Result<Vec<String>, String> {
    let text = str::from_utf8(raw)
        .map_err(|_| "zero-key recovery requires valid recipients.txt authority".to_owned())?;
    let mut seen = HashSet::new();
    let mut authorities = Vec::new();
    for line in text.lines() {
        if line.len() > 64 * 1024 {
            return Err("zero-key recovery requires valid recipients.txt authority".to_owned());
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let recipient = parse_recipient(line)
            .map_err(|_| "zero-key recovery requires valid recipients.txt authority".to_owned())?;
        let recipient = recipient.to_string();
        if seen.insert(recipient.clone()) {
            authorities.push(recipient);
        }
    }
    if authorities.is_empty() {
        return Err("zero-key recovery requires valid recipients.txt authority".to_owned());
    }
    Ok(authorities)
}

fn heal_zero_key_identity(
    root: &Path,
    identity_path: &Path,
    raw: &[u8],
    passphrase: &[u8],
) -> Result<symvault_crypto::Identity, String> {
    let recipients_path = root.join("recipients.txt");
    let recipients_snapshot = read_private_regular(&recipients_path, "recipients file")
        .map_err(|_| "zero-key recovery requires a trusted recipients.txt".to_owned())?;
    let authorities = zero_key_authorities(&recipients_snapshot)?;
    let identity = authorities.iter().find_map(|recipient| {
        let expected_fingerprint = fingerprint(recipient);
        let authority = ZeroKeyAuthority::both(recipient, &expected_fingerprint);
        recover_zero_key_identity(raw, passphrase.len(), authority).ok()
    });
    let identity = identity.ok_or_else(|| "zero-key recovery failed".to_owned())?;

    let store = Store::open(root, &identity).map_err(|error| error.to_string())?;
    rewrite_identity_with_lock(
        &store,
        IdentityRewrite {
            identity_path,
            original: raw,
            identity: &identity,
            passphrase,
            params: Argon2idParams::default(),
            authority: Some((&recipients_path, &recipients_snapshot)),
            migration_config: None,
            operation: "zero-key recovery",
        },
    )?;
    Ok(identity)
}

struct IdentityRewrite<'a> {
    identity_path: &'a Path,
    original: &'a [u8],
    identity: &'a symvault_crypto::Identity,
    passphrase: &'a [u8],
    params: Argon2idParams,
    authority: Option<(&'a Path, &'a [u8])>,
    migration_config: Option<(&'a Path, &'a [u8])>,
    operation: &'a str,
}

fn rewrite_identity_with_lock(store: &Store, request: IdentityRewrite<'_>) -> Result<(), String> {
    let IdentityRewrite {
        identity_path,
        original,
        identity,
        passphrase,
        params,
        authority,
        migration_config,
        operation,
    } = request;
    let backup_path = identity_path.with_extension("age.bak");
    let result = store.with_write_lock(|_| {
        let rewrite = (|| {
            let current_identity =
                read_private_regular(identity_path, "identity file").map_err(|_| {
                    format!("identity changed before {operation}; refusing to re-key the vault")
                })?;
            if current_identity != original {
                return Err(format!(
                    "identity changed before {operation}; refusing to re-key the vault"
                ));
            }
            if let Some((authority_path, expected_authority)) = authority {
                let current_authority = read_private_regular(authority_path, "recipients file")
                    .map_err(|_| {
                        "zero-key recovery authority changed; refusing to re-key the vault"
                            .to_owned()
                    })?;
                if current_authority != expected_authority {
                    return Err(
                        "zero-key recovery authority changed; refusing to re-key the vault"
                            .to_owned(),
                    );
                }
            }
            let config_replacement = if let Some((config_path, expected_config)) = migration_config
            {
                let current_config = read_private_regular(config_path, "vault config")
                    .map_err(|_| "vault config changed before KDF migration".to_owned())?;
                if current_config != expected_config {
                    return Err("vault config changed before KDF migration".to_owned());
                }
                Some((config_path, migrated_kdf_config(&current_config)?))
            } else {
                None
            };
            let replacement =
                encrypt_identity_argon2id(identity, &SecretBytes::new(passphrase), params)
                    .map_err(|error| format!("save migrated identity: {error}"))?;
            write_private_new(&backup_path, original).map_err(|error| {
                format!("write identity backup (existing backups are preserved): {error}")
            })?;
            if let Err(error) = write_private_atomic(identity_path, &replacement) {
                let _ = fs::remove_file(&backup_path);
                return Err(format!("save migrated identity: {error}"));
            }
            let verification = (|| {
                let bytes = read_private_regular(identity_path, "identity file")?;
                let verified = decrypt_identity(&bytes, &SecretBytes::new(passphrase))
                    .map_err(|error| format!("verify migrated identity: {error}"))?;
                if recipient_string(&verified) != recipient_string(identity) {
                    return Err("verify migrated identity: identity mismatch".to_owned());
                }
                Ok(())
            })();
            if let Err(error) = verification {
                write_private_atomic(identity_path, original)
                    .map_err(|restore| format!("{error}; restore original identity: {restore}"))?;
                let _ = fs::remove_file(&backup_path);
                return Err(error);
            }
            if let Some((config_path, config_bytes)) = config_replacement
                && let Err(error) = write_private_atomic(config_path, &config_bytes)
            {
                write_private_atomic(identity_path, original).map_err(|restore| {
                    format!("save migrated config: {error}; restore original identity: {restore}")
                })?;
                let _ = fs::remove_file(&backup_path);
                return Err(format!("save migrated config: {error}"));
            }
            Ok(())
        })();
        Ok(rewrite)
    });
    match result {
        Ok(rewrite) => rewrite,
        Err(error) => Err(error.to_string()),
    }
}

struct MobileKdfMigrationSettings {
    params: Argon2idParams,
    config_snapshot: Vec<u8>,
}

fn mobile_kdf_migration_settings(
    root: &Path,
) -> Result<Option<MobileKdfMigrationSettings>, String> {
    let raw = read_private_regular(&root.join("config.yaml"), "vault config")?;
    let text = str::from_utf8(&raw).map_err(|_| "vault config is not UTF-8".to_owned())?;
    let values = vault_yaml_scalars(text);
    let enabled = match values.get("auto_migrate_kdf").map(String::as_str) {
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some(_) => return Err("vault auto_migrate_kdf must be true or false".to_owned()),
        None => false,
    };
    if !enabled {
        return Ok(None);
    }
    let mut params = Argon2idParams::default();
    if let Some(value) = values.get("argon2id_time") {
        if let Ok(value) = value.parse::<u32>() {
            if value > 0 {
                params.time = value;
            }
        } else {
            return Err("vault argon2id_time is invalid".to_owned());
        }
    }
    if let Some(value) = values.get("argon2id_memory") {
        if let Ok(value) = value.parse::<u32>() {
            if value > 0 {
                params.memory_kib = value;
            }
        } else {
            return Err("vault argon2id_memory is invalid".to_owned());
        }
    }
    if let Some(value) = values.get("argon2id_threads") {
        if let Ok(value) = value.parse::<u32>() {
            if value > 0 {
                params.threads = value;
            }
        } else {
            return Err("vault argon2id_threads is invalid".to_owned());
        }
    }
    Ok(Some(MobileKdfMigrationSettings {
        params,
        config_snapshot: raw,
    }))
}

fn migrated_kdf_config(raw: &[u8]) -> Result<Vec<u8>, String> {
    let text = str::from_utf8(raw).map_err(|_| "vault config is not UTF-8".to_owned())?;
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let header = lines
        .iter()
        .position(|line| line.split('#').next().unwrap_or_default().trim() == "vault:")
        .ok_or_else(|| "vault config has no vault mapping".to_owned())?;
    let parent_indent = lines[header].len() - lines[header].trim_start_matches(' ').len();
    let child_indent = lines
        .iter()
        .skip(header + 1)
        .find_map(|line| {
            let content = line.split('#').next().unwrap_or_default();
            if content.trim().is_empty() {
                return None;
            }
            let indent = content.len() - content.trim_start_matches(' ').len();
            (indent > parent_indent).then_some(indent)
        })
        .unwrap_or(parent_indent + 2);
    let mut format_index = None;
    let mut remove_indices = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(header + 1) {
        let content = line.split('#').next().unwrap_or_default();
        if content.trim().is_empty() {
            continue;
        }
        let indent = content.len() - content.trim_start_matches(' ').len();
        if indent <= parent_indent {
            break;
        }
        if indent != child_indent {
            continue;
        }
        let Some((key, _)) = content.trim().split_once(':') else {
            continue;
        };
        match key.trim().trim_matches(['"', '\'']) {
            "format_version" => format_index = Some(index),
            "scrypt_work_factor" => remove_indices.push(index),
            _ => {}
        }
    }
    let replacement = format!("{}format_version: 2", " ".repeat(child_indent));
    if let Some(index) = format_index {
        lines[index] = replacement;
    } else {
        lines.insert(header + 1, replacement);
    }
    for index in remove_indices.into_iter().rev() {
        lines.remove(index);
    }
    let mut output = lines.join("\n").into_bytes();
    if text.ends_with('\n') {
        output.push(b'\n');
    }
    Ok(output)
}

fn vault_yaml_scalars(text: &str) -> HashMap<String, String> {
    let mut scalars = HashMap::new();
    let mut vault_indent = None;
    let mut child_indent = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let indent = line.len() - line.trim_start_matches(' ').len();
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(['"', '\'']);
        let value = value.trim();
        if indent == 0 {
            vault_indent = (key == "vault" && value.is_empty()).then_some(indent);
            child_indent = None;
            continue;
        }
        let Some(parent_indent) = vault_indent else {
            continue;
        };
        if indent <= parent_indent {
            vault_indent = None;
            child_indent = None;
            continue;
        }
        let depth = *child_indent.get_or_insert(indent);
        if indent != depth {
            continue;
        }
        let value = value.split('#').next().unwrap_or_default().trim();
        let value = value.trim_matches(['"', '\'']);
        scalars.insert(key.to_owned(), value.to_owned());
    }
    scalars
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

/// Decrypts a Symaira Vault Argon2id age envelope.
///
/// This is deliberately separate from [`symvault_decrypt_with_passphrase`],
/// which matches the Go mobile API's legacy scrypt behavior.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_decrypt_with_passphrase_argon2id(
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
        decrypt_argon2id(ciphertext, &SecretBytes::new(passphrase))
            .map_err(|error| error.to_string())
    })
}

/// Initializes a Go-compatible mobile vault at `vault_dir` with an Argon2id
/// protected master identity. Success returns empty output and error buffers.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_init_vault(
    vault_dir: *const u8,
    vault_dir_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        if vault_dir.is_empty() {
            return Err("vaultDir is empty".to_owned());
        }
        let passphrase = unsafe { input(passphrase, passphrase_len, "passphrase")? };
        if passphrase.is_empty() {
            return Err("passphrase is empty".to_owned());
        }
        str::from_utf8(passphrase).map_err(|_| "passphrase is not UTF-8".to_owned())?;

        let root = Path::new(vault_dir);
        let entries = root.join("entries");
        reject_symlink(root, "vault directory")?;
        reject_symlink(&entries, "entries directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&entries)
                .map_err(|error| format!("create vault dir: {error}"))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&entries).map_err(|error| format!("create vault dir: {error}"))?;
        reject_symlink(root, "vault directory")?;
        reject_symlink(&entries, "entries directory")?;
        let root = fs::canonicalize(root).map_err(|error| format!("create vault dir: {error}"))?;

        let config_path =
            serde_json::to_string(vault_dir).map_err(|error| format!("marshal config: {error}"))?;
        let config = format!("vaultDir: {config_path}\nvault:\n  format_version: 2\n");
        write_private_atomic(&root.join("config.yaml"), config.as_bytes())
            .map_err(|error| format!("write config: {error}"))?;

        let identity = generate_identity();
        let ciphertext = encrypt_identity_argon2id(
            &identity,
            &SecretBytes::new(passphrase),
            Argon2idParams::default(),
        )
        .map_err(|error| format!("save identity with argon2id: {error}"))?;
        write_private_atomic(&root.join("identity.age"), &ciphertext)
            .map_err(|error| format!("save identity: {error}"))?;
        Ok(Vec::new())
    })
}

/// Opens a Go-compatible vault with a passphrase and returns its master
/// identity string in a Rust-owned buffer.
///
/// # Safety
/// Each nonempty input pointer must reference `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symvault_open_vault_with_passphrase(
    vault_dir: *const u8,
    vault_dir_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> SymvaultResult {
    ffi(|| {
        let vault_dir = unsafe { utf8(vault_dir, vault_dir_len, "vault directory")? };
        if vault_dir.is_empty() {
            return Err("vaultDir is empty".to_owned());
        }
        let passphrase = unsafe { input(passphrase, passphrase_len, "passphrase")? };
        if passphrase.is_empty() {
            return Err("passphrase is empty".to_owned());
        }
        str::from_utf8(passphrase).map_err(|_| "passphrase is not UTF-8".to_owned())?;

        reject_symlink(Path::new(vault_dir), "vault directory")?;
        let root = fs::canonicalize(vault_dir).map_err(|error| format!("open vault: {error}"))?;
        let identity_path = root.join("identity.age");
        let metadata = fs::symlink_metadata(&identity_path)
            .map_err(|error| format!("read identity file: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "identity file is a symlink: {}",
                identity_path.display()
            ));
        }
        if !metadata.is_file() {
            return Err(format!(
                "identity file is not a regular file: {}",
                identity_path.display()
            ));
        }
        if metadata.len() > symvault_store::MAX_FILE_BYTES {
            return Err(format!(
                "identity file exceeds {} bytes",
                symvault_store::MAX_FILE_BYTES
            ));
        }
        let ciphertext = read_private_regular(&identity_path, "identity file")?;
        let identity = match decrypt_identity(&ciphertext, &SecretBytes::new(passphrase)) {
            Ok(identity) => identity,
            Err(_error)
                if classify_zero_key_candidate(&ciphertext) == FailureClass::ZeroKeyCandidate =>
            {
                heal_zero_key_identity(&root, &identity_path, &ciphertext, passphrase)?
            }
            Err(error) => return Err(format!("load identity: {error}")),
        };
        let store = Store::open(&root, &identity).map_err(|error| error.to_string())?;
        if needs_kdf_migration(&ciphertext)
            && let Some(settings) = mobile_kdf_migration_settings(&root)?
        {
            rewrite_identity_with_lock(
                &store,
                IdentityRewrite {
                    identity_path: &identity_path,
                    original: &ciphertext,
                    identity: &identity,
                    passphrase,
                    params: settings.params,
                    authority: None,
                    migration_config: Some((&root.join("config.yaml"), &settings.config_snapshot)),
                    operation: "KDF migration",
                },
            )?;
        }
        Ok(identity_string(&identity).as_bytes().to_vec())
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
        let mut entry_value = serde_json::from_str::<serde_json::Value>(&entry_json)
            .map_err(|error| format!("unmarshal entry: {error}"))?;
        // encoding/json accepts top-level null for a non-pointer struct and
        // leaves it zero-valued; Entry's custom Go unmarshaller initializes
        // its data map afterwards.
        let entry = if entry_value.is_null() {
            Entry::default()
        } else {
            if let Some(data) = entry_value.get_mut("data") {
                coerce_go_json_any_numbers(data)
                    .map_err(|error| format!("unmarshal entry: {error}"))?;
            }
            serde_json::from_value::<Entry>(entry_value)
                .map_err(|error| format!("unmarshal entry: {error}"))?
        };
        let store = Store::open(Path::new(vault_dir), &identity)
            .map_err(|error| format!("open vault: {error}"))?;
        let now = utc_now_string(Path::new(vault_dir))
            .map_err(|error| format!("write entry: {error}"))?;
        store
            .write_entry_at(entry_path, &entry, &identity, &now, false, None)
            .map_err(|error| format!("write entry: {error}"))?;
        Ok(Vec::new())
    })
}

/// Go's encoding/json decodes numbers held by `map[string]any` as float64.
/// Convert only Entry.data, whose values use that dynamic representation.
fn coerce_go_json_any_numbers(value: &mut serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Number(number) => {
            let float = number
                .as_f64()
                .ok_or_else(|| "number cannot be represented as float64".to_owned())?;
            *number = serde_json::Number::from_f64(float)
                .ok_or_else(|| "number cannot be represented as float64".to_owned())?;
        }
        serde_json::Value::Array(values) => {
            for value in values {
                coerce_go_json_any_numbers(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                coerce_go_json_any_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
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
    fn init_and_open_vault_with_passphrase_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        let vault_bytes = vault.to_str().unwrap().as_bytes();
        let passphrase = b"ffi init test passphrase";
        let initialized = unsafe {
            output(symvault_init_vault(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            ))
        };
        assert_eq!(initialized.unwrap(), b"");
        assert!(vault.join("entries").is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(vault.join("entries"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for name in ["config.yaml", "identity.age"] {
                assert_eq!(
                    fs::metadata(vault.join(name)).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }

        let identity = unsafe {
            output(symvault_open_vault_with_passphrase(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            ))
        }
        .unwrap();
        let identity = str::from_utf8(&identity).unwrap();
        assert!(parse_identity(identity).is_ok());

        let wrong_passphrase = b"wrong passphrase";
        let failure = unsafe {
            output(symvault_open_vault_with_passphrase(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                wrong_passphrase.as_ptr(),
                wrong_passphrase.len(),
            ))
        };
        assert!(failure.is_err());
    }

    #[test]
    fn open_vault_with_passphrase_reads_go_mobile_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/go-mobile-vault.json"
        )))
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("go-vault");
        fs::create_dir_all(vault.join("entries")).unwrap();
        let vault_string = vault.to_str().unwrap();
        let quoted_path = serde_json::to_string(vault_string).unwrap();
        fs::write(
            vault.join("config.yaml"),
            format!("vaultDir: {quoted_path}\nvault:\n  format_version: 2\n"),
        )
        .unwrap();
        let identity_bytes = base64::engine::general_purpose::STANDARD
            .decode(fixture["identity_age_base64"].as_str().unwrap())
            .unwrap();
        fs::write(vault.join("identity.age"), identity_bytes).unwrap();

        let vault_bytes = vault_string.as_bytes();
        let passphrase = fixture["passphrase"].as_str().unwrap().as_bytes();
        let identity = unsafe {
            output(symvault_open_vault_with_passphrase(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            ))
        }
        .unwrap();
        assert_eq!(
            str::from_utf8(&identity).unwrap(),
            fixture["identity"].as_str().unwrap()
        );
    }

    #[test]
    fn open_vault_heals_go_zero_key_fixture_only_with_recipient_authority() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/crypto/age-kdf.json"
        )))
        .unwrap();
        let zero_case = &fixture["zero_key_cases"][0];
        let original = base64::engine::general_purpose::STANDARD
            .decode(zero_case["ciphertext"].as_str().unwrap())
            .unwrap();
        let expected_recipient = zero_case["expected_recipient"].as_str().unwrap();
        let expected_identity = fixture["identities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|identity| identity["recipient"] == expected_recipient)
            .unwrap()["identity"]
            .as_str()
            .unwrap();
        let passphrase = "x".repeat(zero_case["passphrase_length"].as_u64().unwrap() as usize);

        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("zero-key-vault");
        fs::create_dir_all(vault.join("entries")).unwrap();
        let vault_string = vault.to_str().unwrap();
        let quoted_path = serde_json::to_string(vault_string).unwrap();
        fs::write(
            vault.join("config.yaml"),
            format!("vaultDir: {quoted_path}\nvault:\n  format_version: 2\n"),
        )
        .unwrap();
        fs::write(vault.join("identity.age"), &original).unwrap();
        fs::write(
            vault.join("recipients.txt"),
            format!("{expected_recipient}\n"),
        )
        .unwrap();

        let vault_bytes = vault_string.as_bytes();
        let passphrase_bytes = passphrase.as_bytes();
        let identity = unsafe {
            output(symvault_open_vault_with_passphrase(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                passphrase_bytes.as_ptr(),
                passphrase_bytes.len(),
            ))
        }
        .unwrap();
        assert_eq!(str::from_utf8(&identity).unwrap(), expected_identity);
        assert_eq!(fs::read(vault.join("identity.age.bak")).unwrap(), original);
        let healed = fs::read(vault.join("identity.age")).unwrap();
        let reopened = decrypt_identity(&healed, &SecretBytes::new(passphrase_bytes)).unwrap();
        assert_eq!(recipient_string(&reopened), expected_recipient);

        let rejected = temp.path().join("wrong-authority-vault");
        fs::create_dir_all(rejected.join("entries")).unwrap();
        fs::write(
            rejected.join("config.yaml"),
            format!(
                "vaultDir: {}\nvault:\n  format_version: 2\n",
                serde_json::to_string(rejected.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        fs::write(rejected.join("identity.age"), &original).unwrap();
        let wrong_recipient = fixture["identities"][1]["recipient"].as_str().unwrap();
        fs::write(
            rejected.join("recipients.txt"),
            format!("{wrong_recipient}\n"),
        )
        .unwrap();
        let rejected_bytes = rejected.to_str().unwrap().as_bytes();
        let error = unsafe {
            output(symvault_open_vault_with_passphrase(
                rejected_bytes.as_ptr(),
                rejected_bytes.len(),
                passphrase_bytes.as_ptr(),
                passphrase_bytes.len(),
            ))
        }
        .unwrap_err();
        assert!(error.contains("zero-key recovery failed"));
        assert_eq!(fs::read(rejected.join("identity.age")).unwrap(), original);
        assert!(!rejected.join("identity.age.bak").exists());

        let backup_occupied = temp.path().join("backup-occupied-vault");
        fs::create_dir_all(backup_occupied.join("entries")).unwrap();
        fs::write(
            backup_occupied.join("config.yaml"),
            format!(
                "vaultDir: {}\nvault:\n  format_version: 2\n",
                serde_json::to_string(backup_occupied.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        fs::write(backup_occupied.join("identity.age"), &original).unwrap();
        fs::write(
            backup_occupied.join("recipients.txt"),
            format!("{expected_recipient}\n"),
        )
        .unwrap();
        let sentinel_backup = b"keep prior identity backup";
        fs::write(backup_occupied.join("identity.age.bak"), sentinel_backup).unwrap();
        let occupied_bytes = backup_occupied.to_str().unwrap().as_bytes();
        let error = unsafe {
            output(symvault_open_vault_with_passphrase(
                occupied_bytes.as_ptr(),
                occupied_bytes.len(),
                passphrase_bytes.as_ptr(),
                passphrase_bytes.len(),
            ))
        }
        .unwrap_err();
        assert!(error.contains("existing backups are preserved"));
        assert_eq!(
            fs::read(backup_occupied.join("identity.age")).unwrap(),
            original
        );
        assert_eq!(
            fs::read(backup_occupied.join("identity.age.bak")).unwrap(),
            sentinel_backup
        );
    }

    #[test]
    fn open_vault_migrates_go_scrypt_identity_only_when_opted_in() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/ffi/kdf-migration.json"
        )))
        .unwrap();
        let original = STANDARD
            .decode(fixture["ciphertext"].as_str().unwrap())
            .unwrap();
        let expected_identity = fixture["identity"].as_str().unwrap();
        let passphrase = b"rust-interop-fixture-passphrase-v1";

        let temp = tempfile::tempdir().unwrap();
        let make_vault = |name: &str, auto_migrate: bool| {
            let vault = temp.path().join(name);
            fs::create_dir_all(vault.join("entries")).unwrap();
            let quoted_path = serde_json::to_string(vault.to_str().unwrap()).unwrap();
            fs::write(
                vault.join("config.yaml"),
                format!(
                    "vaultDir: {quoted_path}\nvault:\n  format_version: 1\n  scrypt_work_factor: 18\n  auto_migrate_kdf: {auto_migrate}\n  argon2id_time: 1\n  argon2id_memory: 32\n  argon2id_threads: 1\n"
                ),
            )
            .unwrap();
            fs::write(vault.join("identity.age"), &original).unwrap();
            vault
        };
        let vault = make_vault("migrate", true);
        let vault_bytes = vault.to_str().unwrap().as_bytes();
        let opened = unsafe {
            output(symvault_open_vault_with_passphrase(
                vault_bytes.as_ptr(),
                vault_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            ))
        }
        .unwrap();
        assert_eq!(str::from_utf8(&opened).unwrap(), expected_identity);
        assert_eq!(fs::read(vault.join("identity.age.bak")).unwrap(), original);
        let migrated_config = fs::read_to_string(vault.join("config.yaml")).unwrap();
        assert!(migrated_config.contains("format_version: 2"));
        assert!(migrated_config.contains("auto_migrate_kdf: true"));
        assert!(!migrated_config.contains("scrypt_work_factor"));
        let migrated = fs::read(vault.join("identity.age")).unwrap();
        assert!(needs_kdf_migration(&original));
        assert!(!needs_kdf_migration(&migrated));
        let reopened = decrypt_identity(&migrated, &SecretBytes::new(passphrase)).unwrap();
        assert_eq!(
            recipient_string(&reopened),
            recipient_string(&parse_identity(expected_identity).unwrap())
        );

        let wrong_pass_vault = make_vault("wrong-pass", true);
        let wrong_vault_bytes = wrong_pass_vault.to_str().unwrap().as_bytes();
        let wrong_passphrase = b"not the fixture passphrase";
        let error = unsafe {
            output(symvault_open_vault_with_passphrase(
                wrong_vault_bytes.as_ptr(),
                wrong_vault_bytes.len(),
                wrong_passphrase.as_ptr(),
                wrong_passphrase.len(),
            ))
        }
        .unwrap_err();
        assert!(error.contains("load identity"));
        assert_eq!(
            fs::read(wrong_pass_vault.join("identity.age")).unwrap(),
            original
        );
        assert!(!wrong_pass_vault.join("identity.age.bak").exists());

        let disabled = make_vault("disabled", false);
        let disabled_bytes = disabled.to_str().unwrap().as_bytes();
        output(unsafe {
            symvault_open_vault_with_passphrase(
                disabled_bytes.as_ptr(),
                disabled_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            )
        })
        .unwrap();
        assert_eq!(fs::read(disabled.join("identity.age")).unwrap(), original);
        assert!(!disabled.join("identity.age.bak").exists());

        let backup_occupied = make_vault("backup-occupied", true);
        let prior_backup = b"pre-existing migration backup";
        fs::write(backup_occupied.join("identity.age.bak"), prior_backup).unwrap();
        let occupied_bytes = backup_occupied.to_str().unwrap().as_bytes();
        let error = unsafe {
            output(symvault_open_vault_with_passphrase(
                occupied_bytes.as_ptr(),
                occupied_bytes.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            ))
        }
        .unwrap_err();
        assert!(error.contains("existing backups are preserved"));
        assert_eq!(
            fs::read(backup_occupied.join("identity.age")).unwrap(),
            original
        );
        assert_eq!(
            fs::read(backup_occupied.join("identity.age.bak")).unwrap(),
            prior_backup
        );

        let changed = make_vault("changed-identity", true);
        let changed_bytes = b"changed identity bytes";
        fs::write(changed.join("identity.age"), changed_bytes).unwrap();
        let expected_identity_parsed = parse_identity(expected_identity).unwrap();
        let changed_store = Store::open(&changed, &expected_identity_parsed).unwrap();
        let error = rewrite_identity_with_lock(
            &changed_store,
            IdentityRewrite {
                identity_path: &changed.join("identity.age"),
                original: &original,
                identity: &expected_identity_parsed,
                passphrase,
                params: Argon2idParams {
                    time: 1,
                    memory_kib: 32,
                    threads: 1,
                },
                authority: None,
                migration_config: None,
                operation: "KDF migration",
            },
        )
        .unwrap_err();
        assert!(error.contains("identity changed"));
        assert_eq!(
            fs::read(changed.join("identity.age")).unwrap(),
            changed_bytes
        );
        assert!(!changed.join("identity.age.bak").exists());

        let changed_authority = make_vault("changed-authority", true);
        let recipient_path = changed_authority.join("recipients.txt");
        fs::write(&recipient_path, b"changed authority\n").unwrap();
        let authority_store = Store::open(&changed_authority, &expected_identity_parsed).unwrap();
        let error = rewrite_identity_with_lock(
            &authority_store,
            IdentityRewrite {
                identity_path: &changed_authority.join("identity.age"),
                original: &original,
                identity: &expected_identity_parsed,
                passphrase,
                params: Argon2idParams {
                    time: 1,
                    memory_kib: 32,
                    threads: 1,
                },
                authority: Some((&recipient_path, b"original authority\n")),
                migration_config: None,
                operation: "zero-key recovery",
            },
        )
        .unwrap_err();
        assert!(error.contains("authority changed"));
        assert_eq!(
            fs::read(changed_authority.join("identity.age")).unwrap(),
            original
        );
        assert!(!changed_authority.join("identity.age.bak").exists());
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
    fn explicit_argon2id_ffi_export_decrypts_go_crypto_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/port/crypto/age-kdf.json"
        )))
        .unwrap();
        let case = fixture["argon2id_cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "current_tiny_fixture_params")
            .unwrap();
        let passphrase = b"rust-interop-fixture-passphrase-v1";
        let ciphertext = STANDARD
            .decode(case["ciphertext"].as_str().unwrap())
            .unwrap();
        let expected = case["plaintext"].as_str().unwrap().as_bytes();

        let decrypted = unsafe {
            output(symvault_decrypt_with_passphrase_argon2id(
                passphrase.as_ptr(),
                passphrase.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
            .unwrap()
        };
        assert_eq!(decrypted, expected);

        // The existing Go mobile API uses age scrypt; keep that export's
        // behavior separate from this additive Argon2id operation.
        let legacy_result = unsafe {
            output(symvault_decrypt_with_passphrase(
                passphrase.as_ptr(),
                passphrase.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
        };
        assert!(legacy_result.is_err());

        let wrong_passphrase = b"wrong-passphrase";
        let wrong_key = unsafe {
            output(symvault_decrypt_with_passphrase_argon2id(
                wrong_passphrase.as_ptr(),
                wrong_passphrase.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            ))
        };
        assert!(wrong_key.is_err());
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
        let entry_json = br#"{"data":{"username":"ffi-user","password":"ffi-secret","large_integer":9007199254740993,"decimal":1.234567890123456789,"exponent":1e+30,"nested":{"integer":9007199254740993,"values":[1e-7,1e+30]}}}"#;

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
        assert_eq!(read["data"]["large_integer"].as_i64(), None);
        assert_eq!(
            read["data"]["large_integer"].as_f64(),
            Some(9_007_199_254_740_992_f64)
        );
        assert_eq!(read["data"]["decimal"].as_f64(), Some(1.2345678901234567));
        assert_eq!(read["data"]["exponent"].as_f64(), Some(1e30));
        assert_eq!(read["data"]["nested"]["integer"].as_i64(), None);
        assert_eq!(
            read["data"]["nested"]["integer"].as_f64(),
            Some(9_007_199_254_740_992_f64)
        );
        assert_eq!(read["data"]["nested"]["values"][0].as_f64(), Some(1e-7));
        assert_eq!(read["data"]["nested"]["values"][1].as_f64(), Some(1e30));
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
