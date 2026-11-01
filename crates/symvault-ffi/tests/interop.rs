//! Cross-compatibility with the real Go functions (FFI-001).
//!
//! `mobilebindgen --drive` answers JSON-line calls with the raw result of the
//! actual `pkg/mobilebind` code, so every direction below runs against Go
//! itself, not a recording. Set `SYMVAULT_FFI_GO_DRIVER` to the built driver
//! (`make ffi-differential` does); without it the test prints a visible SKIP.

mod common;

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Outcome, call};
use serde_json::{Value, json};

struct Go {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Go {
    fn start(binary: &str) -> Self {
        let mut child = Command::new(binary)
            .arg("--drive")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start Go driver");
        let stdin = child.stdin.take().expect("driver stdin");
        let stdout = BufReader::new(child.stdout.take().expect("driver stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn call(&mut self, function: &str, args: &Value) -> Outcome {
        let request = json!({ "function": function, "args": args });
        writeln!(self.stdin, "{request}").expect("write request");
        self.stdin.flush().expect("flush request");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let response: Value = serde_json::from_str(&line).expect("driver response JSON");
        Outcome {
            ok: response["ok"].as_bool().unwrap_or(false),
            string: response["string"].as_str().map(str::to_owned),
            bytes: response["bytes_b64"]
                .as_str()
                .map(|text| STANDARD.decode(text).expect("driver base64")),
            flag: response["bool"].as_bool(),
            error: response["error"].as_str().unwrap_or("").to_owned(),
        }
    }
}

impl Drop for Go {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn driver() -> Option<Go> {
    match std::env::var("SYMVAULT_FFI_GO_DRIVER") {
        Ok(path) if !path.is_empty() => Some(Go::start(&path)),
        _ => {
            eprintln!(
                "SKIP interop: SYMVAULT_FFI_GO_DRIVER is not set (run `make ffi-differential`)"
            );
            None
        }
    }
}

fn rust(function: &str, args: &Value) -> Outcome {
    call(function, args, &Value::Null)
}

fn text(outcome: &Outcome) -> String {
    assert!(outcome.ok, "call failed: {}", outcome.error);
    outcome.string.clone().expect("string result")
}

fn bytes(outcome: &Outcome) -> Vec<u8> {
    assert!(outcome.ok, "call failed: {}", outcome.error);
    outcome.bytes.clone().expect("bytes result")
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

type Side<'a> = &'a dyn Fn(&str, &Value) -> Outcome;

const PASSPHRASE: &str = "correct horse battery staple";
const ENTRIES: [(&str, &str); 3] = [
    (
        "work/github",
        r#"{"data":{"password":"pa$$w0rd","username":"dj","n":1.5},"meta":{"tags":["a","b"]}}"#,
    ),
    (
        "personal/email",
        r#"{"data":{"password":"héllo <&> wörld","url":"https://example.org"}}"#,
    ),
    (
        "notes/é-ü",
        r#"{"data":{"note":"multi\nline","nested":{"k":[1,2,{"z":null}]}}}"#,
    ),
];

/// `writer` initializes the vault and writes `ENTRIES`; `reader` must unlock
/// the same identity, read, list and verify exactly what `writer` sees, and
/// then write into the same vault so that `writer` reads it back.
fn vault_round(writer: Side, reader: Side, dir: &str) {
    let init = writer(
        "InitVault",
        &json!({"vaultDir": dir, "passphrase": PASSPHRASE}),
    );
    assert!(init.ok, "InitVault: {}", init.error);
    let open = json!({"vaultDir": dir, "passphrase": PASSPHRASE});
    let identity = text(&writer("OpenVaultWithPassphrase", &open));
    assert_eq!(
        identity,
        text(&reader("OpenVaultWithPassphrase", &open)),
        "both sides unlock the same master identity"
    );
    assert!(identity.starts_with("AGE-SECRET-KEY-1"));

    for (path, entry) in ENTRIES {
        let args =
            json!({"vaultDir": dir, "entryPath": path, "entryJSON": entry, "identity": identity});
        let outcome = writer("WriteEntryJSON", &args);
        assert!(outcome.ok, "write {path}: {}", outcome.error);
    }
    check_agreement(
        writer,
        reader,
        dir,
        &identity,
        &ENTRIES.map(|(path, _)| path),
    );

    let back = json!({"vaultDir": dir, "entryPath": "interop/back", "identity": identity,
        "entryJSON": r#"{"data":{"from":"reader"}}"#});
    let outcome = reader("WriteEntryJSON", &back);
    assert!(outcome.ok, "write back: {}", outcome.error);
    let mut all: Vec<&str> = ENTRIES.iter().map(|(path, _)| *path).collect();
    all.push("interop/back");
    check_agreement(reader, writer, dir, &identity, &all);
}

fn check_agreement(left: Side, right: Side, dir: &str, identity: &str, paths: &[&str]) {
    for path in paths {
        let args = json!({"vaultDir": dir, "entryPath": path, "identity": identity});
        let (l, r) = (left("ReadEntryJSON", &args), right("ReadEntryJSON", &args));
        assert!(l.ok && r.ok, "read {path}: {} / {}", l.error, r.error);
        assert_eq!(l.string, r.string, "ReadEntryJSON {path}");
    }
    let list = json!({"vaultDir": dir, "prefix": "", "identity": identity});
    let (l, r) = (
        left("ListEntriesJSON", &list),
        right("ListEntriesJSON", &list),
    );
    assert!(l.ok && r.ok, "list: {} / {}", l.error, r.error);
    assert_eq!(l.string, r.string, "ListEntriesJSON");
    let listed: Vec<String> = serde_json::from_str(&text(&l)).expect("list JSON");
    for path in paths {
        assert!(
            listed.iter().any(|item| item == path),
            "{path} missing from {listed:?}"
        );
    }
    let prefixed = json!({"vaultDir": dir, "prefix": "work/", "identity": identity});
    assert_eq!(
        left("ListEntriesJSON", &prefixed).string,
        right("ListEntriesJSON", &prefixed).string
    );
    let verify = json!({"vaultDir": dir, "identity": identity});
    for side in [left, right] {
        let outcome = side("VerifyManifestIntegrity", &verify);
        assert!(outcome.ok, "verify: {}", outcome.error);
        assert_eq!(outcome.flag, Some(true), "manifest verifies");
    }
}

#[test]
fn go_written_vault_is_read_by_rust_and_rust_written_vault_is_read_by_go() {
    let Some(mut go) = driver() else { return };
    let temp = tempfile::tempdir().expect("tempdir");
    let go_cell = RefCell::new(&mut go);
    let go_side = |function: &str, args: &Value| go_cell.borrow_mut().call(function, args);
    let rust_side = |function: &str, args: &Value| rust(function, args);

    let dir_a = temp.path().join("go-first");
    vault_round(&go_side, &rust_side, dir_a.to_str().expect("utf-8 path"));
    eprintln!("INTEROP vault written by Go: Rust reads, lists, verifies and writes back");
    let dir_b = temp.path().join("rust-first");
    vault_round(&rust_side, &go_side, dir_b.to_str().expect("utf-8 path"));
    eprintln!("INTEROP vault written by Rust: Go reads, lists, verifies and writes back");
}

#[test]
fn ciphertexts_and_identities_cross_decrypt_in_both_directions() {
    let Some(mut go) = driver() else { return };
    let secret = text(&rust("GenerateIdentity", &json!({})));
    assert!(secret.starts_with("AGE-SECRET-KEY-1"));
    let recipient = text(&rust("IdentityPublicKey", &json!({"identity": secret})));
    assert_eq!(
        recipient,
        text(&go.call("IdentityPublicKey", &json!({"identity": secret})))
    );
    assert_eq!(
        text(&rust("PublicKeyFingerprint", &json!({"pubkey": recipient}))),
        text(&go.call("PublicKeyFingerprint", &json!({"pubkey": recipient})))
    );
    let go_secret = text(&go.call("GenerateIdentity", &json!({})));
    assert_eq!(
        text(&rust("IdentityPublicKey", &json!({"identity": go_secret}))),
        text(&go.call("IdentityPublicKey", &json!({"identity": go_secret})))
    );

    let message: Vec<u8> = (0..70_000u32).map(|n| (n % 251) as u8).collect();
    let plain = b64(&message);
    // X25519, Rust -> Go and Go -> Rust (two 64 KiB chunks plus a tail).
    let sealed = bytes(&rust(
        "EncryptWithPublicKey",
        &json!({"recipient": recipient, "plaintext_b64": plain}),
    ));
    assert_eq!(
        bytes(&go.call(
            "DecryptWithIdentity",
            &json!({"identity": secret, "ciphertext_b64": b64(&sealed)})
        )),
        message
    );
    let sealed = bytes(&go.call(
        "EncryptWithPublicKey",
        &json!({"recipient": recipient, "plaintext_b64": plain}),
    ));
    assert_eq!(
        bytes(&rust(
            "DecryptWithIdentity",
            &json!({"identity": secret, "ciphertext_b64": b64(&sealed)})
        )),
        message
    );
    // Passphrase, both directions.
    let sealed = bytes(&rust(
        "EncryptWithPassphrase",
        &json!({"passphrase": "pässwörd", "plaintext_b64": plain}),
    ));
    assert_eq!(
        bytes(&go.call(
            "DecryptWithPassphrase",
            &json!({"passphrase": "pässwörd", "ciphertext_b64": b64(&sealed)})
        )),
        message
    );
    let sealed = bytes(&go.call(
        "EncryptWithPassphrase",
        &json!({"passphrase": "pässwörd", "plaintext_b64": plain}),
    ));
    assert_eq!(
        bytes(&rust(
            "DecryptWithPassphrase",
            &json!({"passphrase": "pässwörd", "ciphertext_b64": b64(&sealed)})
        )),
        message
    );

    // A wrong key fails with the same text on both sides.
    let other = text(&go.call("GenerateIdentity", &json!({})));
    let sealed = bytes(&go.call(
        "EncryptWithPublicKey",
        &json!({"recipient": recipient, "plaintext_b64": b64(b"x")}),
    ));
    let args = json!({"identity": other, "ciphertext_b64": b64(&sealed)});
    let (g, r) = (
        go.call("DecryptWithIdentity", &args),
        rust("DecryptWithIdentity", &args),
    );
    assert!(!g.ok && !r.ok);
    assert_eq!(g.error, r.error);
    eprintln!(
        "INTEROP crypto: identities, fingerprints, X25519 and passphrase ciphertexts agree both ways"
    );
}
