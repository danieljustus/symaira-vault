//! Cross-compatibility with the real Go functions (FFI-001), replayed.
//!
//! `mobilebindgen --drive` answered JSON-line calls with the raw result of the
//! actual `pkg/mobilebind` code when the observations in
//! `testdata/port/cli-observations/ffi_interop.json` were recorded. Replay keeps
//! the directions that need no Go alive: the vaults the recording left behind
//! (one initialised and written by Go, one by Rust, both extended by the other
//! side) are installed and the current Rust code must unlock them, read, list and
//! verify exactly what Go reported for them; Go-sealed ciphertexts are decrypted
//! by Rust, and the Rust-sealed ciphertexts Go decrypted at capture time are
//! decrypted by Rust again. A missing recording fails the test.
//!
//! What replay cannot repeat is Go opening something the *current* Rust code
//! just wrote; that direction is exercised by a capture only.

mod common;

#[path = "../../symvault-cli/tests/common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::cell::RefCell;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Outcome, call};
use go_oracle_ext::Observations;
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

/// Pinned Go oracle: the clean checkout the `mobilebindgen` driver is built from.
const ORACLE_COMMIT: &str = "c069d3f2b17d704525cedc1bd42840cc6a3e9896";

/// The run directories a recorded vault must not carry (`config.yaml` records
/// its `vaultDir`, the backup marker the backup path): the vault itself and the
/// scratch directory around it become `<VAULT>` / `<TMP>`, and replay resolves
/// them to the current run's directories.
fn masks(dir: &Path) -> Vec<(&Path, &'static str)> {
    let mut subs = vec![(dir, "<VAULT>")];
    subs.extend(dir.parent().map(|parent| (parent, "<TMP>")));
    subs
}

fn snapshot(dir: &Path) -> Value {
    fn walk(
        base: &Path,
        dir: &Path,
        subs: &[(&Path, &str)],
        out: &mut serde_json::Map<String, Value>,
    ) {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .expect("read dir")
            .flatten()
            .map(|entry| entry.path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(base, &path, subs, out);
            } else {
                let relative = path.strip_prefix(base).expect("under base");
                out.insert(
                    relative.display().to_string(),
                    json!(STANDARD.encode(go_oracle_ext::mask_paths(
                        &fs::read(&path).expect("read file"),
                        subs
                    ))),
                );
            }
        }
    }
    let mut out = serde_json::Map::new();
    walk(dir, dir, &masks(dir), &mut out);
    Value::Object(out)
}

fn install(dir: &Path, tree: &Value) {
    let subs = masks(dir);
    for (relative, content) in tree.as_object().expect("tree object") {
        let path = dir.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("tree dir");
        fs::write(
            &path,
            go_oracle_ext::unmask_paths(
                &STANDARD
                    .decode(content.as_str().expect("b64"))
                    .expect("base64"),
                &subs,
            ),
        )
        .expect("tree file");
    }
}

/// What `side` reports about the vault: the unlocked identity, every entry, both
/// listings and the manifest verdict.
fn report(side: Side, dir: &str, passphrase: &str, paths: &[&str]) -> Value {
    let identity = text(&side(
        "OpenVaultWithPassphrase",
        &json!({"vaultDir": dir, "passphrase": passphrase}),
    ));
    let mut reads = serde_json::Map::new();
    for path in paths {
        let outcome = side(
            "ReadEntryJSON",
            &json!({"vaultDir": dir, "entryPath": path, "identity": identity}),
        );
        assert!(outcome.ok, "read {path}: {}", outcome.error);
        reads.insert((*path).to_owned(), json!(outcome.string));
    }
    let list = |prefix: &str| {
        side(
            "ListEntriesJSON",
            &json!({"vaultDir": dir, "prefix": prefix, "identity": identity}),
        )
        .string
    };
    let verify = side(
        "VerifyManifestIntegrity",
        &json!({"vaultDir": dir, "identity": identity}),
    );
    assert!(verify.ok, "verify: {}", verify.error);
    json!({
        "identity": identity,
        "reads": reads,
        "list": list(""),
        "list_work": list("work/"),
        "verify": verify.flag,
    })
}

const ALL_PATHS: [&str; 4] = ["work/github", "personal/email", "notes/é-ü", "interop/back"];

/// Both vault directions: `first` initialises and writes, the other side reads
/// and writes back. The record holds the final vault and Go's report of it.
fn vault_direction(first_is_go: bool, go: &mut Go, dir: &Path) -> Value {
    let dir_text = dir.to_str().expect("utf-8 path").to_owned();
    let go_cell = RefCell::new(&mut *go);
    let go_side = |function: &str, args: &Value| go_cell.borrow_mut().call(function, args);
    let rust_side = |function: &str, args: &Value| rust(function, args);
    if first_is_go {
        vault_round(&go_side, &rust_side, &dir_text);
    } else {
        vault_round(&rust_side, &go_side, &dir_text);
    }
    json!({
        "tree": snapshot(dir),
        "go": report(&go_side, &dir_text, PASSPHRASE, &ALL_PATHS),
    })
}

#[test]
fn go_written_vault_is_read_by_rust_and_rust_written_vault_is_read_by_go() {
    let observations = Observations::begin(
        "ffi_interop",
        "go_written_vault_is_read_by_rust_and_rust_written_vault_is_read_by_go",
        Some(ORACLE_COMMIT),
    );
    let temp = tempfile::tempdir().expect("tempdir");
    for (name, first_is_go) in [("go-first", true), ("rust-first", false)] {
        let record = observations.observe(name, |driver| {
            let mut go = Go::start(driver.to_str().expect("driver path"));
            vault_direction(
                first_is_go,
                &mut go,
                &temp.path().join(format!("capture-{name}")),
            )
        });
        // Install the recorded final vault and make the current Rust code read
        // exactly what Go reported for it.
        let dir = temp.path().join(format!("replay-{name}"));
        fs::create_dir_all(&dir).expect("replay dir");
        install(&dir, &record["tree"]);
        let dir_text = dir.to_str().expect("utf-8 path");
        let now = report(&|f, a| rust(f, a), dir_text, PASSPHRASE, &ALL_PATHS);
        assert_eq!(now, record["go"], "{name}: Rust vs the recorded Go report");
        assert!(
            record["go"]["identity"]
                .as_str()
                .is_some_and(|id| id.starts_with("AGE-SECRET-KEY-1")),
            "{name}: recorded identity"
        );
        assert_eq!(record["go"]["verify"], json!(true));
        let written = if first_is_go { "Go" } else { "Rust" };
        eprintln!(
            "INTEROP vault written by {written}: recorded Go report matches current Rust reads, listings and manifest verdict ({} entries)",
            record["go"]["reads"].as_object().map_or(0, |m| m.len())
        );
    }
    assert_eq!(observations.count(), 2);
}

#[test]
fn ciphertexts_and_identities_cross_decrypt_in_both_directions() {
    let observations = Observations::begin(
        "ffi_interop",
        "ciphertexts_and_identities_cross_decrypt_in_both_directions",
        Some(ORACLE_COMMIT),
    );
    let message: Vec<u8> = (0..70_000u32).map(|n| (n % 251) as u8).collect();
    let plain = b64(&message);
    let record = observations.observe("crypto", |driver| {
        let mut go = Go::start(driver.to_str().expect("driver path"));
        let secret = text(&rust("GenerateIdentity", &json!({})));
        let recipient = text(&rust("IdentityPublicKey", &json!({"identity": secret})));
        assert_eq!(
            recipient,
            text(&go.call("IdentityPublicKey", &json!({"identity": secret})))
        );
        let fingerprint = text(&go.call("PublicKeyFingerprint", &json!({"pubkey": recipient})));
        assert_eq!(
            text(&rust("PublicKeyFingerprint", &json!({"pubkey": recipient}))),
            fingerprint
        );
        let go_secret = text(&go.call("GenerateIdentity", &json!({})));
        let go_public = text(&go.call("IdentityPublicKey", &json!({"identity": go_secret})));
        assert_eq!(
            text(&rust("IdentityPublicKey", &json!({"identity": go_secret}))),
            go_public
        );
        // X25519 and passphrase, Rust -> Go and Go -> Rust.
        let rust_x = bytes(&rust(
            "EncryptWithPublicKey",
            &json!({"recipient": recipient, "plaintext_b64": plain}),
        ));
        assert_eq!(
            bytes(&go.call(
                "DecryptWithIdentity",
                &json!({"identity": secret, "ciphertext_b64": b64(&rust_x)})
            )),
            message
        );
        let go_x = bytes(&go.call(
            "EncryptWithPublicKey",
            &json!({"recipient": recipient, "plaintext_b64": plain}),
        ));
        assert_eq!(
            bytes(&rust(
                "DecryptWithIdentity",
                &json!({"identity": secret, "ciphertext_b64": b64(&go_x)})
            )),
            message
        );
        let rust_p = bytes(&rust(
            "EncryptWithPassphrase",
            &json!({"passphrase": "pässwörd", "plaintext_b64": plain}),
        ));
        assert_eq!(
            bytes(&go.call(
                "DecryptWithPassphrase",
                &json!({"passphrase": "pässwörd", "ciphertext_b64": b64(&rust_p)})
            )),
            message
        );
        let go_p = bytes(&go.call(
            "EncryptWithPassphrase",
            &json!({"passphrase": "pässwörd", "plaintext_b64": plain}),
        ));
        assert_eq!(
            bytes(&rust(
                "DecryptWithPassphrase",
                &json!({"passphrase": "pässwörd", "ciphertext_b64": b64(&go_p)})
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
        json!({
            "secret": secret, "recipient": recipient, "fingerprint": fingerprint,
            "go_secret": go_secret, "go_public": go_public,
            "rust_x25519_b64": b64(&rust_x), "go_x25519_b64": b64(&go_x),
            "rust_passphrase_b64": b64(&rust_p), "go_passphrase_b64": b64(&go_p),
            "wrong_identity": other, "wrong_ciphertext_b64": b64(&sealed),
            "wrong_key_error": g.error,
        })
    });

    // Replay against the current Rust code.
    let text_of = |value: &Value| value.as_str().expect("recorded string").to_owned();
    let secret = text_of(&record["secret"]);
    let recipient = text_of(&record["recipient"]);
    assert_eq!(
        text(&rust("IdentityPublicKey", &json!({"identity": secret}))),
        recipient
    );
    assert_eq!(
        text(&rust("PublicKeyFingerprint", &json!({"pubkey": recipient}))),
        text_of(&record["fingerprint"])
    );
    assert_eq!(
        text(&rust(
            "IdentityPublicKey",
            &json!({"identity": text_of(&record["go_secret"])})
        )),
        text_of(&record["go_public"])
    );
    for (key, function, credential, value) in [
        (
            "rust_x25519_b64",
            "DecryptWithIdentity",
            "identity",
            secret.clone(),
        ),
        (
            "go_x25519_b64",
            "DecryptWithIdentity",
            "identity",
            secret.clone(),
        ),
        (
            "rust_passphrase_b64",
            "DecryptWithPassphrase",
            "passphrase",
            "pässwörd".to_owned(),
        ),
        (
            "go_passphrase_b64",
            "DecryptWithPassphrase",
            "passphrase",
            "pässwörd".to_owned(),
        ),
    ] {
        let mut args = json!({"ciphertext_b64": record[key]});
        args[credential] = json!(value);
        assert_eq!(bytes(&rust(function, &args)), message, "{key}");
    }
    let args = json!({
        "identity": record["wrong_identity"], "ciphertext_b64": record["wrong_ciphertext_b64"]
    });
    let wrong = rust("DecryptWithIdentity", &args);
    assert!(!wrong.ok);
    assert_eq!(wrong.error, text_of(&record["wrong_key_error"]));
    assert_eq!(observations.count(), 1);
    eprintln!(
        "INTEROP crypto: recorded Go answers and Go/Rust-sealed ciphertexts agree with current Rust"
    );
}
