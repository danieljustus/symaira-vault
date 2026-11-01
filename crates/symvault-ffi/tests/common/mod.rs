//! Shared harness: the C ABI as a safe call, and the recorded-fixture checker.
//!
//! Every call goes through the exported `extern "C"` functions, so a replay
//! exercises the same entry points Swift links against.

#![allow(unsafe_code, dead_code)]

use std::fs;
use std::path::Path;
use std::slice;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use symvault_ffi::abi::{self, SvBuf};

/// Where the recorded fixture lives, relative to this crate.
pub const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/ffi/mobilebind.json"
);

pub const FUNCTIONS: [&str; 13] = [
    "GenerateIdentity",
    "IdentityPublicKey",
    "PublicKeyFingerprint",
    "EncryptWithPublicKey",
    "DecryptWithIdentity",
    "EncryptWithPassphrase",
    "DecryptWithPassphrase",
    "InitVault",
    "OpenVaultWithPassphrase",
    "ReadEntryJSON",
    "WriteEntryJSON",
    "ListEntriesJSON",
    "VerifyManifestIntegrity",
];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub ok: bool,
    pub string: Option<String>,
    pub bytes: Option<Vec<u8>>,
    pub flag: Option<bool>,
    pub error: String,
}

pub fn b64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).expect("fixture base64")
}

pub fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

fn s<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Resolves plaintext/ciphertext arguments (inline, pattern or seed reference).
fn plaintext(args: &Value) -> Vec<u8> {
    match args.get("plaintext_pattern_len").and_then(Value::as_u64) {
        Some(length) if length > 0 => pattern(length as usize),
        _ => b64(s(args, "plaintext_b64")),
    }
}

fn ciphertext(args: &Value, seed: &Value) -> Vec<u8> {
    let Some(reference) = args.get("ciphertext_ref").and_then(Value::as_str) else {
        return b64(s(args, "ciphertext_b64"));
    };
    let (kind, name) = reference.split_once(':').expect("ciphertext_ref");
    let table = if kind == "scrypt" {
        "scrypt_ciphertexts_b64"
    } else {
        "x25519_ciphertexts_b64"
    };
    let mut data = b64(seed[table][name].as_str().expect("seed ciphertext"));
    if let Some(edit) = args.get("ciphertext_edit").and_then(Value::as_str) {
        let (operation, argument) = edit.split_once(':').expect("edit");
        let offset: usize = argument.parse().expect("edit offset");
        match operation {
            "flip" => data[offset] ^= 0x80,
            "truncate" => data.truncate(offset),
            other => panic!("unknown edit {other}"),
        }
    }
    data
}

struct Out {
    buf: SvBuf,
    err: SvBuf,
    flag: i32,
}

impl Out {
    fn new() -> Self {
        let empty = || SvBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        Self {
            buf: empty(),
            err: empty(),
            flag: 0,
        }
    }
}

fn take(buf: SvBuf) -> Vec<u8> {
    if buf.ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: the buffer was produced by the library and is released right after.
    let data = unsafe { slice::from_raw_parts(buf.ptr, buf.len) }.to_vec();
    // SAFETY: `buf` came from the library and is freed exactly once here.
    unsafe { abi::symvault_buf_free(buf) };
    data
}

fn finish(status: i32, mut out: Out, kind: &str) -> Outcome {
    let error = take(std::mem::replace(
        &mut out.err,
        SvBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
        },
    ));
    if status != 0 {
        assert_eq!(status, 1, "unexpected ABI status {status}");
        return Outcome {
            ok: false,
            error: String::from_utf8(error).expect("error text is UTF-8"),
            ..Outcome::default()
        };
    }
    assert!(error.is_empty(), "error buffer set on success");
    let mut outcome = Outcome {
        ok: true,
        ..Outcome::default()
    };
    match kind {
        "string" => outcome.string = Some(String::from_utf8(take(out.buf)).expect("UTF-8 result")),
        "bytes" => outcome.bytes = Some(take(out.buf)),
        "bool" => outcome.flag = Some(out.flag == 1),
        _ => {}
    }
    outcome
}

/// Calls one bridge function through the C ABI.
pub fn call(function: &str, args: &Value, seed: &Value) -> Outcome {
    let identity = s(args, "identity").as_bytes();
    let vault_dir = s(args, "vaultDir").as_bytes();
    let passphrase = s(args, "passphrase").as_bytes();
    let entry_path = s(args, "entryPath").as_bytes();
    let entry_json = s(args, "entryJSON").as_bytes();
    let prefix = s(args, "prefix").as_bytes();
    let recipient = s(args, "recipient").as_bytes();
    let pubkey = s(args, "pubkey").as_bytes();
    let plain = plaintext(args);
    let cipher = ciphertext(args, seed);
    let mut out = Out::new();
    // SAFETY: every pointer/length pair borrows a live slice for the call.
    let (status, kind) = unsafe {
        match function {
            "GenerateIdentity" => (
                abi::symvault_generate_identity(&mut out.buf, &mut out.err),
                "string",
            ),
            "IdentityPublicKey" => (
                abi::symvault_identity_public_key(
                    identity.as_ptr(),
                    identity.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "string",
            ),
            "PublicKeyFingerprint" => (
                abi::symvault_public_key_fingerprint(
                    pubkey.as_ptr(),
                    pubkey.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "string",
            ),
            "EncryptWithPublicKey" => (
                abi::symvault_encrypt_with_public_key(
                    recipient.as_ptr(),
                    recipient.len(),
                    plain.as_ptr(),
                    plain.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "bytes",
            ),
            "DecryptWithIdentity" => (
                abi::symvault_decrypt_with_identity(
                    identity.as_ptr(),
                    identity.len(),
                    cipher.as_ptr(),
                    cipher.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "bytes",
            ),
            "EncryptWithPassphrase" => (
                abi::symvault_encrypt_with_passphrase(
                    passphrase.as_ptr(),
                    passphrase.len(),
                    plain.as_ptr(),
                    plain.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "bytes",
            ),
            "DecryptWithPassphrase" => (
                abi::symvault_decrypt_with_passphrase(
                    passphrase.as_ptr(),
                    passphrase.len(),
                    cipher.as_ptr(),
                    cipher.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "bytes",
            ),
            "InitVault" => (
                abi::symvault_init_vault(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    passphrase.as_ptr(),
                    passphrase.len(),
                    &mut out.err,
                ),
                "none",
            ),
            "OpenVaultWithPassphrase" => (
                abi::symvault_open_vault_with_passphrase(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    passphrase.as_ptr(),
                    passphrase.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "string",
            ),
            "ReadEntryJSON" => (
                abi::symvault_read_entry_json(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    entry_path.as_ptr(),
                    entry_path.len(),
                    identity.as_ptr(),
                    identity.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "string",
            ),
            "WriteEntryJSON" => (
                abi::symvault_write_entry_json(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    entry_path.as_ptr(),
                    entry_path.len(),
                    entry_json.as_ptr(),
                    entry_json.len(),
                    identity.as_ptr(),
                    identity.len(),
                    &mut out.err,
                ),
                "none",
            ),
            "ListEntriesJSON" => (
                abi::symvault_list_entries_json(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    prefix.as_ptr(),
                    prefix.len(),
                    identity.as_ptr(),
                    identity.len(),
                    &mut out.buf,
                    &mut out.err,
                ),
                "string",
            ),
            "VerifyManifestIntegrity" => (
                abi::symvault_verify_manifest_integrity(
                    vault_dir.as_ptr(),
                    vault_dir.len(),
                    identity.as_ptr(),
                    identity.len(),
                    &mut out.flag,
                    &mut out.err,
                ),
                "bool",
            ),
            other => panic!("unknown function {other}"),
        }
    };
    finish(status, out, kind)
}

// ---------------------------------------------------------------------------
// Normalization shared with the Go generator.
// ---------------------------------------------------------------------------

pub fn normalize_paths(text: &str, root: &str) -> String {
    let mut text = text.replace(&format!("/private{root}"), "$ROOT");
    text = text.replace(root, "$ROOT");
    text
}

fn is_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.ends_with('Z') {
        return false;
    }
    let shape = b"dddd-dd-ddTdd:dd:dd";
    let head = &bytes[..19];
    if !head.iter().zip(shape).all(|(byte, kind)| match kind {
        b'd' => byte.is_ascii_digit(),
        other => byte == other,
    }) {
        return false;
    }
    let tail = &value[19..value.len() - 1];
    tail.is_empty()
        || (tail.starts_with('.')
            && (2..=10).contains(&tail.len())
            && tail[1..].bytes().all(|byte| byte.is_ascii_digit()))
}

pub fn normalize_timestamps(text: &str) -> String {
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(text) else {
        return text.to_owned();
    };
    let Some(Value::Object(meta)) = document.get("meta") else {
        return text.to_owned();
    };
    let mut result = text.to_owned();
    for key in ["created", "updated"] {
        if let Some(Value::String(value)) = meta.get(key)
            && is_rfc3339_utc(value)
        {
            result = result.replacen(
                &format!("\"{key}\":\"{value}\""),
                &format!("\"{key}\":\"<TIMESTAMP>\""),
                1,
            );
        }
    }
    result
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Fixture checking.
// ---------------------------------------------------------------------------

pub fn load_fixture() -> Value {
    let text = fs::read_to_string(FIXTURE).expect("read fixture");
    // Fixtures are LF; tolerate a CRLF checkout.
    serde_json::from_str(&text.replace("\r\n", "\n")).expect("fixture JSON")
}

fn charset_ok(body: &str, charset: &str) -> bool {
    match charset {
        "bech32-upper" => body
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "bech32-lower" => body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        _ => true,
    }
}

/// Largest grease stanza rust-age emits: 3 + 15 (tag) + 4*9 (args) + 1 header
/// bytes plus a 99-byte body in base64 lines.
const GREASE_MAX: usize = 200;

fn grease_stanza_present(data: &[u8]) -> bool {
    let head = &data[..data.len().min(600)];
    let text = String::from_utf8_lossy(head);
    let end = text.find("\n--- ").unwrap_or(text.len());
    text[..end]
        .lines()
        .filter(|line| line.starts_with("-> "))
        .filter(|line| {
            line[3..]
                .split(' ')
                .next()
                .is_some_and(|tag| tag.ends_with("-grease"))
        })
        .count()
        == 1
}

fn check_shape(outcome: &Outcome, shape: &Value) -> Result<(), String> {
    if !outcome.ok {
        return Err(format!("unexpected error: {}", outcome.error));
    }
    let length = shape["length"].as_u64().unwrap_or(0) as usize;
    if let Some(text) = &outcome.string {
        let prefix = shape["string_prefix"].as_str().unwrap_or("");
        if !text.starts_with(prefix) || text.len() != length {
            return Err(format!(
                "string shape mismatch: {} bytes, prefix {prefix}",
                text.len()
            ));
        }
        if !charset_ok(
            &text[prefix.len()..],
            shape["string_charset"].as_str().unwrap_or(""),
        ) {
            return Err("charset mismatch".to_owned());
        }
    }
    if let Some(data) = &outcome.bytes {
        let prefix = b64(shape["bytes_prefix_b64"].as_str().unwrap_or(""));
        if !data.starts_with(&prefix) {
            return Err(format!(
                "bytes shape mismatch: prefix, {} bytes",
                data.len()
            ));
        }
        if data.len() != length {
            // rust-age appends one random `*-grease` stanza to X25519 headers
            // (Go's age does not): 8..=190 extra bytes, same payload.
            let grease = data.starts_with(b"age-encryption.org/v1\n-> X25519 ")
                && (length + 1..=length + GREASE_MAX).contains(&data.len())
                && grease_stanza_present(data);
            if !grease {
                return Err(format!(
                    "bytes shape mismatch: {} bytes, want {length}",
                    data.len()
                ));
            }
        }
        if let Some(factor) = shape.get("scrypt_work_factor").and_then(Value::as_u64) {
            let header = String::from_utf8_lossy(&data[..data.len().min(200)]).into_owned();
            let line = header.lines().nth(1).unwrap_or("");
            if !line.ends_with(&format!(" {factor}")) {
                return Err(format!("scrypt stanza {line:?} lacks work factor {factor}"));
            }
        }
    }
    Ok(())
}

/// Compares an outcome with a recorded `want` (exact values, not shapes).
fn check_exact(
    outcome: &Outcome,
    want: &Value,
    root: &str,
    normalize: &[&str],
) -> Result<(), String> {
    let wants_ok = want["ok"].as_bool().unwrap_or(false);
    if outcome.ok != wants_ok {
        return Err(format!(
            "ok={} but fixture ok={wants_ok}; error {:?}; want error {:?}",
            outcome.ok,
            outcome.error,
            want["error"].as_str().unwrap_or("")
        ));
    }
    if !wants_ok {
        let got = normalize_paths(&outcome.error, root);
        let expected = want["error"].as_str().unwrap_or("");
        return if got == expected {
            Ok(())
        } else {
            Err(format!(
                "error text differs:\n   got: {got}\n  want: {expected}"
            ))
        };
    }
    if let Some(expected) = want["string"].as_str() {
        let mut got = normalize_paths(outcome.string.as_deref().unwrap_or("<none>"), root);
        if normalize.contains(&"timestamps") {
            got = normalize_timestamps(&got);
        }
        if got != expected {
            return Err(format!(
                "string differs:\n   got: {got}\n  want: {expected}"
            ));
        }
    }
    if let Some(expected) = want["bytes_b64"].as_str()
        && outcome.bytes.as_deref() != Some(b64(expected).as_slice())
    {
        return Err("bytes differ".to_owned());
    }
    if let Some(length) = want["bytes_len"].as_u64() {
        let data = outcome.bytes.as_deref().unwrap_or(&[]);
        if data.len() as u64 != length
            || sha256_hex(data) != want["bytes_sha256"].as_str().unwrap_or("")
        {
            return Err("large bytes differ (length or sha256)".to_owned());
        }
    }
    if let Some(expected) = want["bool"].as_bool()
        && outcome.flag != Some(expected)
    {
        return Err(format!("bool {:?}, want {expected}", outcome.flag));
    }
    Ok(())
}

fn substitute_out(args: &Value, produced: &Outcome) -> Value {
    let mut args = args.clone();
    let object = args.as_object_mut().expect("args object");
    for key in ["identity", "recipient", "pubkey"] {
        if object.get(key).and_then(Value::as_str) == Some("$OUT") {
            object.insert(
                key.to_owned(),
                Value::String(produced.string.clone().unwrap_or_default()),
            );
        }
    }
    if object.get("ciphertext_b64").and_then(Value::as_str) == Some("$OUT") {
        let data = produced.bytes.clone().unwrap_or_default();
        object.insert(
            "ciphertext_b64".to_owned(),
            Value::String(STANDARD.encode(data)),
        );
    }
    args
}

fn run_step(step: &Value, seed: &Value, root: &str) -> Result<(), String> {
    let function = step["function"].as_str().expect("function");
    let args = step["args"].clone();
    let args = expand_root(&args, root);
    let outcome = call(function, &args, seed);
    let normalize: Vec<&str> = step["normalize"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let want = &step["want"];
    if let Some(shape) = want.get("shape") {
        check_shape(&outcome, shape)?;
        if shape["distinct_across_calls"].as_bool().unwrap_or(false) {
            let again = call(function, &args, seed);
            if again == outcome {
                return Err("two calls produced identical output".to_owned());
            }
        }
        if let Some(roundtrip) = shape.get("roundtrip") {
            let rt_function = roundtrip["function"].as_str().expect("roundtrip function");
            let rt_args = expand_root(&substitute_out(&roundtrip["args"], &outcome), root);
            let rt_outcome = call(rt_function, &rt_args, seed);
            match roundtrip["want"].get("shape") {
                Some(rt_shape) => {
                    check_shape(&rt_outcome, rt_shape).map_err(|e| format!("roundtrip: {e}"))?
                }
                None => check_exact(&rt_outcome, &roundtrip["want"], root, &[])
                    .map_err(|e| format!("roundtrip {rt_function}: {e}"))?,
            }
        }
        return Ok(());
    }
    check_exact(&outcome, want, root, &normalize)
}

fn expand_root(args: &Value, root: &str) -> Value {
    let mut args = args.clone();
    if let Some(Value::String(dir)) = args.get_mut("vaultDir") {
        *dir = dir.replace("$ROOT", root);
    }
    args
}

fn materialize(files: &[Value], dir: &Path, root: &str) {
    fs::create_dir_all(dir).expect("create vault dir");
    for file in files {
        let target = dir.join(file["path"].as_str().expect("path"));
        let mode = file["mode"].as_u64().unwrap_or(0o600) as u32;
        if file["dir"].as_bool().unwrap_or(false) {
            fs::create_dir_all(&target).expect("create dir");
            set_mode(&target, mode);
            continue;
        }
        fs::create_dir_all(target.parent().expect("parent")).expect("create parent");
        let data = b64(file["b64"].as_str().unwrap_or(""));
        let text = String::from_utf8_lossy(&data).replace("$ROOT", root);
        let data = if std::str::from_utf8(&data).is_ok() {
            text.into_bytes()
        } else {
            data
        };
        fs::write(&target, data).expect("write file");
        set_mode(&target, mode);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn mutate(vault: &Path, mutation: &Value) {
    let target = vault.join(mutation["path"].as_str().expect("path"));
    match mutation["op"].as_str().expect("op") {
        "remove" => {
            let _ = fs::remove_dir_all(&target).or_else(|_| fs::remove_file(&target));
        }
        "write" => {
            fs::create_dir_all(target.parent().expect("parent")).expect("parent");
            let data = match mutation["b64"].as_str() {
                Some(text) if !text.is_empty() => b64(text),
                _ => mutation["text"].as_str().unwrap_or("").as_bytes().to_vec(),
            };
            fs::write(&target, data).expect("mutation write");
        }
        "flip" => {
            let mut data = fs::read(&target).expect("flip read");
            data[mutation["offset"].as_u64().unwrap_or(0) as usize] ^= 0x01;
            fs::write(&target, data).expect("flip write");
        }
        "truncate" => {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .expect("truncate open");
            file.set_len(mutation["size"].as_u64().unwrap_or(0))
                .expect("truncate");
        }
        "mkdir" => fs::create_dir_all(&target).expect("mkdir"),
        "symlink" => {
            #[cfg(unix)]
            {
                let _ = fs::remove_file(&target);
                std::os::unix::fs::symlink(mutation["target"].as_str().expect("target"), &target)
                    .expect("symlink");
            }
        }
        other => panic!("unknown mutation {other}"),
    }
}

fn check_after(after: &Value, base: &Path, root: &str) -> Result<(), String> {
    if let Some(tree) = after.get("tree").and_then(Value::as_array) {
        let mut actual: Vec<String> = Vec::new();
        collect(base, base, &mut actual);
        actual.sort();
        let expected: Vec<String> = tree
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        if actual != expected {
            return Err(format!("tree {actual:?}, want {expected:?}"));
        }
    }
    if let Some(files) = after.get("files").and_then(Value::as_object) {
        for (name, state) in files {
            let path = base.join(name);
            let meta = fs::metadata(&path).map_err(|e| format!("{name}: {e}"))?;
            if meta.is_dir() != state["dir"].as_bool().unwrap_or(false) {
                return Err(format!("{name}: directory flag differs"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if u64::from(mode) != state["mode"].as_u64().unwrap_or(0) {
                    return Err(format!(
                        "{name}: mode {mode:o}, want {:o}",
                        state["mode"].as_u64().unwrap_or(0)
                    ));
                }
            }
            if let Some(text) = state["text"].as_str() {
                let got =
                    normalize_paths(&fs::read_to_string(&path).map_err(|e| e.to_string())?, root);
                if got != text {
                    return Err(format!(
                        "{name} text differs:\n   got: {got:?}\n  want: {text:?}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn collect(base: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        let path = entry.path();
        out.push(
            path.strip_prefix(base)
                .expect("prefix")
                .to_string_lossy()
                .replace('\\', "/"),
        );
        if path.is_dir() {
            collect(base, &path, out);
        }
    }
}

/// Recorded Go behavior the Rust side deliberately does not reproduce yet
/// (`testdata/port/ffi/known-divergences.json`, shared with the Swift test).
/// The replay fails if an entry stops being needed.
fn known_divergences() -> Vec<(String, String)> {
    let text = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/ffi/known-divergences.json"
    ))
    .expect("read known-divergences.json");
    let document: Value = serde_json::from_str(&text).expect("known-divergences JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().expect("id").to_owned(),
                entry["reason"].as_str().expect("reason").to_owned(),
            )
        })
        .collect()
}

/// Replays every case; returns per-function step counts and all mismatches.
pub fn replay(fixture: &Value) -> (std::collections::BTreeMap<String, usize>, Vec<String>) {
    let mut counts = std::collections::BTreeMap::new();
    let mut failures = Vec::new();
    let divergences = known_divergences();
    let seed = &fixture["seed"];
    let files = seed["vault"]["files"]
        .as_array()
        .expect("seed files")
        .clone();
    for case in fixture["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_string_lossy().into_owned();
        let vault = temp.path().join("vault");
        if case["vault"].as_bool().unwrap_or(false) {
            materialize(&files, &vault, &root);
        }
        for mutation in case["mutations"].as_array().into_iter().flatten() {
            mutate(&vault, mutation);
        }
        for (index, step) in case["steps"].as_array().expect("steps").iter().enumerate() {
            let function = step["function"].as_str().expect("function").to_owned();
            *counts.entry(function).or_insert(0) += 1;
            let result = run_step(step, seed, &root);
            if let Some((_, why)) = divergences.iter().find(|(case, _)| case == id) {
                match result {
                    Err(reason) => eprintln!("KNOWN DIVERGENCE {id}: {why}\n  {reason}"),
                    Ok(()) => failures.push(format!(
                        "{id}: listed in KNOWN_DIVERGENCES but now matches Go; remove the entry"
                    )),
                }
            } else if let Err(reason) = result {
                failures.push(format!(
                    "{id} step {index} ({}): {reason}",
                    step["function"]
                ));
            }
        }
        if let Some(after) = case.get("after") {
            let base = expand_root(&case["steps"][0]["args"], &root);
            let base = Path::new(base["vaultDir"].as_str().unwrap_or("")).to_path_buf();
            if let Err(reason) = check_after(after, &base, &root) {
                failures.push(format!("{id} after-state: {reason}"));
            }
        }
    }
    (counts, failures)
}
