use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn temporary_root(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-cli-differential-{name}-{suffix}"))
}

struct TempFixture(Vec<PathBuf>);

impl TempFixture {
    fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self(paths.into_iter().collect())
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

// Compare search results against a freshly built Go index. The pinned Go
// writer can leave a same-count disk index stale when its asynchronous warmup
// races UpdateEntry. Persistent index interoperability is tested separately;
// this CLI oracle checks current entry contents, not that cache race.
fn run_search(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    match fs::remove_file(root.join(".search-index")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove synthetic search index: {error}"),
    }
    run(binary, args, root, home)
}

fn run_with_input(binary: &Path, args: &[&str], root: &Path, home: &Path, input: &[u8]) -> Output {
    let mut child = Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("CLI stdin")
        .write_all(input)
        .expect("write CLI input");
    child.wait_with_output().expect("wait for CLI")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn first_json(stdout: &[u8], command: &str) -> serde_json::Value {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("{command} did not write a JSON value: {stdout:?}"))
        .unwrap_or_else(|error| panic!("{command} JSON: {error}; stdout={stdout:?}"))
}

fn first_json_output(output: &Output, command: &str) -> serde_json::Value {
    if output.stdout.is_empty() {
        panic!(
            "{command} emitted no JSON: status={}; stdout={:?}; stderr={:?}",
            exit_status_detail(output.status),
            output.stdout,
            output.stderr
        );
    }
    first_json(&output.stdout, command)
}

fn exit_status_detail(status: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        format!(
            "success={} code={:?} signal={:?}",
            status.success(),
            status.code(),
            status.signal()
        )
    }
    #[cfg(not(unix))]
    {
        format!("success={} code={:?}", status.success(), status.code())
    }
}

fn assert_initialized(root: &Path) {
    assert!(root.join("config.yaml").is_file());
    let identity = fs::read(root.join("identity.age")).expect("identity");
    assert!(identity.starts_with(b"age-encryption.org/v1\n"));
    assert!(root.join(".git").is_dir());
    assert!(root.join(".gitignore").is_file());
}

#[test]
fn init_list_get_match_go_cli_on_a_disposable_vault() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("home");
    let rust_root = temporary_root("rust");
    let go_root = temporary_root("go");
    fs::create_dir_all(&home).expect("home");

    let rust_init = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_init, "Rust init");
    assert_initialized(&rust_root);

    let go_recipients_list = run(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "recipients", "list"],
        &rust_root,
        &home,
    );
    let rust_recipients_list = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "recipients", "list"],
        &rust_root,
        &home,
    );
    assert_success(&go_recipients_list, "Go recipients list");
    assert_success(&rust_recipients_list, "Rust recipients list");
    assert_eq!(rust_recipients_list.stdout, go_recipients_list.stdout);

    for action in ["push", "pull"] {
        let go_git = run(
            &go_binary,
            &["--vault", rust_root.to_str().unwrap(), "git", action],
            &rust_root,
            &home,
        );
        let rust_git = run(
            &rust_binary,
            &["--vault", rust_root.to_str().unwrap(), "git", action],
            &rust_root,
            &home,
        );
        assert_success(&go_git, &format!("Go git {action}"));
        assert_success(&rust_git, &format!("Rust git {action}"));
        assert_eq!(rust_git.stdout, go_git.stdout, "git {action}");
    }

    let go_set = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.password",
            "--value",
            "secret",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_set, "Go set");

    let go_list = run(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    let rust_list = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    assert_success(&go_list, "Go list");
    assert_success(&rust_list, "Rust list");
    assert_eq!(go_list.stdout, b"work/github\n");
    assert_eq!(rust_list.stdout, go_list.stdout);

    let go_get = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    let rust_get = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_get, "Go get");
    assert_success(&rust_get, "Rust get");
    assert_eq!(go_get.stdout, b"secret\n");
    assert_eq!(rust_get.stdout, go_get.stdout);

    let go_set_url = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.url",
            "--value",
            "https://github.com/login",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_set_url, "Go set URL");

    let go_get_url = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.url",
            "--print",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_get_url, "Go get URL after set");
    assert_eq!(go_get_url.stdout, b"https://github.com/login\n");

    let go_find_secret = run_search(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "secret"],
        &rust_root,
        &home,
    );
    assert_success(&go_find_secret, "Go find");
    assert_eq!(go_find_secret.stdout, b"work/github (matches: password)\n");
    let index_after_go_find = fs::read(rust_root.join(".search-index")).ok();

    let rust_find_secret = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "secret"],
        &rust_root,
        &home,
    );
    assert_success(&rust_find_secret, "Rust find");
    assert_eq!(
        rust_find_secret.stdout,
        b"work/github (matches: password)\n"
    );
    let index_after_rust_find = fs::read(rust_root.join(".search-index")).ok();
    assert_eq!(
        index_after_rust_find, index_after_go_find,
        "Rust find changed the Go encrypted search index"
    );
    let go_find_url = run_search(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "--url",
            "github.com",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_find_url = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "--url",
            "github.com",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_find_url, "Go find URL");
    assert_success(&rust_find_url, "Rust find URL");
    assert_eq!(
        first_json_output(&rust_find_url, "Rust find URL"),
        first_json_output(&go_find_url, "Go find URL")
    );
    let go_find_scoped = run_search(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "secret",
            "--url",
            "github.com",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_find_scoped = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "secret",
            "--url",
            "github.com",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_find_scoped, "Go scoped find");
    assert_success(&rust_find_scoped, "Rust scoped find");
    assert_eq!(
        first_json_output(&rust_find_scoped, "Rust scoped find"),
        first_json_output(&go_find_scoped, "Go scoped find")
    );
    let go_set_unicode = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.note",
            "--value",
            "ÄPFEL",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_set_unicode, "Go set Unicode search value");
    let go_find_unicode = run_search(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "äpfel"],
        &rust_root,
        &home,
    );
    let rust_find_unicode = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "äpfel"],
        &rust_root,
        &home,
    );
    assert_success(&go_find_unicode, "Go Unicode find");
    assert_success(&rust_find_unicode, "Rust Unicode find");
    assert_eq!(rust_find_unicode.stdout, go_find_unicode.stdout);
    let go_set_unicode_special = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.locale",
            "--value",
            "İSTANBUL ΟΣ",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(
        &go_set_unicode_special,
        "Go set special Unicode search value",
    );
    let go_find_unicode_special = run_search(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "istanbul"],
        &rust_root,
        &home,
    );
    let rust_find_unicode_special = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "find", "istanbul"],
        &rust_root,
        &home,
    );
    assert_success(&go_find_unicode_special, "Go special Unicode find");
    assert_success(&rust_find_unicode_special, "Rust special Unicode find");
    assert_eq!(
        rust_find_unicode_special.stdout,
        go_find_unicode_special.stdout
    );
    let go_find_empty = run_search(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "no-such-value",
        ],
        &rust_root,
        &home,
    );
    let rust_find_empty = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "find",
            "no-such-value",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_find_empty, "Go find empty");
    assert_success(&rust_find_empty, "Rust find empty");
    assert_eq!(rust_find_empty.stdout, go_find_empty.stdout);
    assert!(String::from_utf8_lossy(&go_find_empty.stderr).ends_with("No matches found\n"));
    assert!(String::from_utf8_lossy(&rust_find_empty.stderr).ends_with("No matches found\n"));

    let go_generate = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "generate",
            "--length",
            "16",
            "--store",
            "generated.password",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_generate = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "generate",
            "--length",
            "16",
            "--store",
            "generated.password",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_generate, "Go generate store");
    assert_success(&rust_generate, "Rust generate store");
    assert_eq!(
        first_json_output(&rust_generate, "Rust generate store"),
        first_json_output(&go_generate, "Go generate store")
    );

    let go_json = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_json = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_json, "Go get JSON");
    assert_success(&rust_json, "Rust get JSON");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rust_json.stdout).expect("Rust JSON"),
        serde_json::from_slice::<serde_json::Value>(&go_json.stdout).expect("Go JSON")
    );

    let rust_set = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/github.username",
            "--value",
            "alice",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_set, "Rust set update");
    let go_updated = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    let rust_updated = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_updated, "Go get after Rust set");
    assert_success(&rust_updated, "Rust get after Rust set");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rust_updated.stdout)
            .expect("Rust updated JSON"),
        serde_json::from_slice::<serde_json::Value>(&go_updated.stdout).expect("Go updated JSON")
    );

    let go_create = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "set",
            "work/to-delete.password",
            "--value",
            "temporary",
            "--force",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_create, "Go set delete fixture");
    let rust_delete = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "delete",
            "work/to-delete",
            "--yes",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_delete, "Rust delete");
    let go_list_after_delete = run(
        &go_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    let rust_list_after_delete = run(
        &rust_binary,
        &["--vault", rust_root.to_str().unwrap(), "list"],
        &rust_root,
        &home,
    );
    assert_success(&go_list_after_delete, "Go list after Rust delete");
    assert_success(&rust_list_after_delete, "Rust list after delete");
    assert_eq!(rust_list_after_delete.stdout, go_list_after_delete.stdout);

    let import_source = home.join("import.csv");
    fs::write(
        &import_source,
        b"title,username,password\nImported,import-user,import-secret\n",
    )
    .expect("write import source");
    let rust_import = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "import",
            import_source.to_str().unwrap(),
            "--format",
            "csv",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_import, "Rust import");
    let go_imported = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "Imported",
            "--output",
            "json",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_imported, "Go get after Rust import");
    assert_eq!(
        first_json_output(&go_imported, "Go imported entry")["Fields"]["username"],
        "import-user"
    );

    let go_export = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "export",
            "--format",
            "json",
            "--yes",
        ],
        &rust_root,
        &home,
    );
    let rust_export = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "export",
            "--format",
            "json",
            "--yes",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_export, "Go export");
    assert_success(&rust_export, "Rust export");
    assert_eq!(
        first_json_output(&rust_export, "Rust export"),
        first_json_output(&go_export, "Go export")
    );

    let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}
"#;
    for (name, binary) in [("Go MCP", &go_binary), ("Rust MCP", &rust_binary)] {
        let output = run_with_input(
            binary,
            &[
                "--vault",
                rust_root.to_str().unwrap(),
                "mcp",
                "--stdio",
                "--agent",
                "default",
            ],
            &rust_root,
            &home,
            initialize,
        );
        assert_success(&output, name);
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{name} initialize response is not JSON: {error}; stdout={:?}; stderr={:?}",
                    output.stdout, output.stderr
                )
            });
        assert!(
            response.get("result").is_some(),
            "{name} initialize lacks result"
        );
    }

    let recipient = "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y";
    let go_add_recipient = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "recipients",
            "add",
            recipient,
            "--reencrypt",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_add_recipient, "Go recipient add and re-encrypt");
    let rust_get_after_add = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    assert_success(
        &rust_get_after_add,
        "Rust get after Go recipient re-encrypt",
    );
    assert_eq!(rust_get_after_add.stdout, b"secret\n");
    let rust_remove_recipient = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "recipients",
            "remove",
            recipient,
            "--yes",
        ],
        &rust_root,
        &home,
    );
    assert_success(
        &rust_remove_recipient,
        "Rust recipient remove and re-encrypt",
    );
    let rust_get_after_remove = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_get_after_remove, "Rust get after recipient removal");
    assert_eq!(rust_get_after_remove.stdout, b"secret\n");
    let go_remove_missing = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "recipients",
            "remove",
            recipient,
            "--yes",
        ],
        &rust_root,
        &home,
    );
    assert!(!go_remove_missing.status.success());
    assert!(String::from_utf8_lossy(&go_remove_missing.stderr).contains("not found"));

    let archive_base = temporary_root("backup-roundtrip");
    let go_backup = run(
        &go_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "backup",
            archive_base.to_str().unwrap(),
            "--exclude-git",
        ],
        &rust_root,
        &home,
    );
    assert_success(&go_backup, "Go backup");
    let archive = PathBuf::from(format!("{}.tar.gz", archive_base.display()));
    assert!(archive.is_file(), "Go backup did not create {:?}", archive);

    let rust_restore_root = temporary_root("rust-restore");
    let rust_restore = run(
        &rust_binary,
        &[
            "--vault",
            rust_restore_root.to_str().unwrap(),
            "restore",
            archive.to_str().unwrap(),
        ],
        &rust_restore_root,
        &home,
    );
    assert_success(&rust_restore, "Rust restore of Go backup");
    let rust_get_restored = run(
        &rust_binary,
        &[
            "--vault",
            rust_restore_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &rust_restore_root,
        &home,
    );
    assert_success(&rust_get_restored, "Rust get after Go backup restore");
    assert_eq!(rust_get_restored.stdout, b"secret\n");

    let rust_backup = run(
        &rust_binary,
        &[
            "--vault",
            rust_root.to_str().unwrap(),
            "backup",
            archive_base.to_str().unwrap(),
            "--exclude-git",
        ],
        &rust_root,
        &home,
    );
    assert_success(&rust_backup, "Rust backup");
    assert_eq!(rust_backup.stdout, go_backup.stdout);
    let go_restore_root = temporary_root("go-restore");
    let go_restore = run(
        &go_binary,
        &[
            "--vault",
            go_restore_root.to_str().unwrap(),
            "restore",
            archive.to_str().unwrap(),
        ],
        &go_restore_root,
        &home,
    );
    assert_success(&go_restore, "Go restore of Rust backup");
    let go_get_restored = run(
        &go_binary,
        &[
            "--vault",
            go_restore_root.to_str().unwrap(),
            "get",
            "work/github.password",
            "--print",
        ],
        &go_restore_root,
        &home,
    );
    assert_success(&go_get_restored, "Go get after Rust backup restore");
    assert_eq!(go_get_restored.stdout, b"secret\n");

    let go_init = run(
        &go_binary,
        &[
            "--vault",
            go_root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &go_root,
        &home,
    );
    assert_success(&go_init, "Go init");
    assert_initialized(&go_root);

    fs::remove_dir_all(home).expect("cleanup home");
    fs::remove_dir_all(rust_root).expect("cleanup Rust vault");
    fs::remove_dir_all(go_root).expect("cleanup Go vault");
    fs::remove_dir_all(rust_restore_root).expect("cleanup Rust restore vault");
    fs::remove_dir_all(go_restore_root).expect("cleanup Go restore vault");
    fs::remove_file(archive).expect("cleanup backup archive");
}

#[test]
fn export_cancel_happens_before_vault_open() {
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("cancel-home");
    let root = temporary_root("cancel-vault");
    fs::create_dir_all(&home).expect("home");
    let rust = run_with_input(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "export",
            "--format",
            "json",
        ],
        &root,
        &home,
        b"n\n",
    );
    assert_success(&rust, "Rust export cancel");
    let stderr = String::from_utf8_lossy(&rust.stderr);
    assert!(stderr.contains("Export canceled."), "stderr={stderr:?}");
    assert!(
        !rust
            .stdout
            .windows(b"No entries found".len())
            .any(|window| { window == b"No entries found" })
    );

    if let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") {
        let go = run_with_input(
            &PathBuf::from(go_binary),
            &[
                "--vault",
                root.to_str().unwrap(),
                "export",
                "--format",
                "json",
            ],
            &root,
            &home,
            b"n\n",
        );
        assert_success(&go, "Go export cancel");
        assert_eq!(go.stdout, rust.stdout);
    }

    fs::remove_dir_all(home).expect("cleanup home");
    if root.exists() {
        fs::remove_dir_all(root).expect("cleanup vault");
    }
}

#[test]
fn add_noninteractive_matches_go_and_preserves_existing_entries() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("add-home");
    let root = temporary_root("add-vault");
    let corrupt_path = root.join("entries/work/corrupt.age");
    fs::create_dir_all(&home).expect("home");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_success(&init, "Rust init for add differential");

    let go_explicit = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/go-explicit",
            "--value",
            "StrongPass123!",
            "--username",
            "alice",
            "--url",
            "https://github.com/login",
            "--notes",
            "primary",
            "--type",
            "password",
            "--usage-hint",
            "login password",
            "--auto-rotate",
            "--expires-at",
            "2030-01-02T03:04:05Z",
        ],
        &root,
        &home,
    );
    assert_success(&go_explicit, "Go explicit add");
    let rust_get_go = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/go-explicit.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&rust_get_go, "Rust get Go explicit add");
    assert_eq!(rust_get_go.stdout, b"StrongPass123!\n");

    let rust_explicit = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/rust-explicit",
            "--value",
            "AnotherStrong123!",
            "--username",
            "bob",
            "--url",
            "https://example.test/login",
            "--notes",
            "secondary",
            "--type",
            "password",
            "--usage-hint",
            "secondary password",
            "--auto-rotate",
            "--expires-at",
            "2030-01-02T03:04:05Z",
        ],
        &root,
        &home,
    );
    assert_success(&rust_explicit, "Rust explicit add");
    let go_get_rust = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/rust-explicit.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&go_get_rust, "Go get Rust explicit add");
    assert_eq!(go_get_rust.stdout, b"AnotherStrong123!\n");

    let go_stdin = run_with_input(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/go-stdin",
            "--stdin-value",
        ],
        &root,
        &home,
        b"GoStdinStrong123!\n",
    );
    assert_success(&go_stdin, "Go stdin add");
    let rust_get_stdin = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/go-stdin.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&rust_get_stdin, "Rust get Go stdin add");
    assert_eq!(rust_get_stdin.stdout, b"GoStdinStrong123!\n");

    let rust_stdin = run_with_input(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/rust-stdin",
            "--stdin-value",
        ],
        &root,
        &home,
        b"RustStdinStrong123!\n",
    );
    assert_success(&rust_stdin, "Rust stdin add");
    let go_get_stdin = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/rust-stdin.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&go_get_stdin, "Go get Rust stdin add");
    assert_eq!(go_get_stdin.stdout, b"RustStdinStrong123!\n");

    let rust_generated = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/rust-generated",
            "--generate",
            "--length",
            "24",
        ],
        &root,
        &home,
    );
    assert_success(&rust_generated, "Rust generated add");
    let go_get_generated = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/rust-generated.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&go_get_generated, "Go get Rust generated add");
    assert_eq!(go_get_generated.stdout.trim_ascii().len(), 24);

    let totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let go_totp = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/go-totp",
            "--value",
            "TotpPassword123!",
            "--totp-secret",
            totp_secret,
            "--totp-issuer",
            "Example",
            "--totp-account",
            "alice@example.test",
        ],
        &root,
        &home,
    );
    assert_success(&go_totp, "Go TOTP add");
    let rust_get_totp = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/go-totp.totp",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&rust_get_totp, "Rust get Go TOTP add");
    assert!(String::from_utf8_lossy(&rust_get_totp.stdout).contains(totp_secret));

    let rust_totp = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/rust-totp",
            "--value",
            "RustTotpPassword123!",
            "--totp-secret",
            totp_secret,
            "--totp-issuer",
            "Example",
            "--totp-account",
            "bob@example.test",
        ],
        &root,
        &home,
    );
    assert_success(&rust_totp, "Rust TOTP add");
    let go_get_totp = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/rust-totp.totp",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&go_get_totp, "Go get Rust TOTP add");
    assert!(String::from_utf8_lossy(&go_get_totp.stdout).contains(totp_secret));

    let go_invalid_totp = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/invalid-totp",
            "--value",
            "InvalidTotpPassword123!",
            "--totp-secret",
            "not-a-totp-secret",
        ],
        &root,
        &home,
    );
    assert!(!go_invalid_totp.status.success());
    let rust_invalid_get = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/invalid-totp.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert!(!rust_invalid_get.status.success());

    let rust_duplicate = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/go-explicit",
            "--value",
            "Replacement123!",
        ],
        &root,
        &home,
    );
    assert!(!rust_duplicate.status.success());
    assert!(String::from_utf8_lossy(&rust_duplicate.stderr).contains("already exists"));

    fs::create_dir_all(corrupt_path.parent().unwrap()).expect("corrupt parent");
    fs::write(&corrupt_path, b"damaged ciphertext").expect("corrupt entry");
    let rust_corrupt = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/corrupt",
            "--value",
            "ShouldNotOverwrite123!",
        ],
        &root,
        &home,
    );
    assert!(!rust_corrupt.status.success());
    assert!(String::from_utf8_lossy(&rust_corrupt.stderr).contains("already exists"));
    assert_eq!(
        fs::read(&corrupt_path).expect("read corrupt entry"),
        b"damaged ciphertext"
    );

    fs::remove_dir_all(home).expect("cleanup home");
    fs::remove_dir_all(root).expect("cleanup add vault");
}

#[test]
fn verify_matches_go_for_missing_rebuild_and_tampered_manifest() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("verify-home");
    let root = temporary_root("verify-vault");
    fs::create_dir_all(&home).expect("home");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_success(&init, "Rust init for verify differential");

    // Go's Vault.Open repairs a missing manifest before VerifyManifestIntegrity;
    // run it first so the CLI comparison observes that production behavior.
    let go_missing = run(
        &go_binary,
        &["--vault", root.to_str().unwrap(), "verify"],
        &root,
        &home,
    );
    let rust_missing = run(
        &rust_binary,
        &["--vault", root.to_str().unwrap(), "verify"],
        &root,
        &home,
    );
    assert_success(&go_missing, "Go verify missing manifest");
    assert_success(&rust_missing, "Rust verify after Go manifest repair");
    assert_eq!(rust_missing.status.code(), go_missing.status.code());
    assert_eq!(
        rust_missing.stdout, go_missing.stdout,
        "missing manifest stdout"
    );
    for output in [&go_missing, &rust_missing] {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "Manifest verification: 0 entries match, 0 missing, 0 tampered, 0 unknown"
            )
        );
    }

    let go_rebuild = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "verify",
            "--rebuild-only",
        ],
        &root,
        &home,
    );
    let rust_rebuild = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "verify",
            "--rebuild-only",
        ],
        &root,
        &home,
    );
    assert_success(&go_rebuild, "Go verify rebuild-only");
    assert_success(&rust_rebuild, "Rust verify rebuild-only");
    assert_eq!(rust_rebuild.status.code(), go_rebuild.status.code());
    assert_eq!(rust_rebuild.stdout, go_rebuild.stdout, "rebuild stdout");
    assert!(
        String::from_utf8_lossy(&go_rebuild.stderr)
            .contains("Manifest rebuilt from on-disk entries.")
    );
    assert!(
        String::from_utf8_lossy(&rust_rebuild.stderr)
            .contains("Manifest rebuilt from on-disk entries.")
    );

    let add = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "add",
            "work/verify",
            "--value",
            "VerifyStrong123!",
        ],
        &root,
        &home,
    );
    assert_success(&add, "Go add for verify differential");
    let verify_entry = root.join("entries/work/verify.age");
    assert!(
        verify_entry.is_file(),
        "Go add entry path: {verify_entry:?}"
    );
    fs::write(&verify_entry, b"tampered ciphertext").expect("tamper entry");

    let go_tampered = run(
        &go_binary,
        &["--vault", root.to_str().unwrap(), "verify"],
        &root,
        &home,
    );
    let rust_tampered = run(
        &rust_binary,
        &["--vault", root.to_str().unwrap(), "verify"],
        &root,
        &home,
    );
    assert!(
        !go_tampered.status.success(),
        "Go tampered verify unexpectedly succeeded"
    );
    assert!(
        !rust_tampered.status.success(),
        "Rust tampered verify unexpectedly succeeded"
    );
    assert_eq!(rust_tampered.status.code(), go_tampered.status.code());
    assert_eq!(rust_tampered.stdout, go_tampered.stdout, "tampered stdout");
    for output in [&go_tampered, &rust_tampered] {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "Manifest verification: 0 entries match, 0 missing, 1 tampered, 0 unknown"
            )
        );
    }

    fs::remove_dir_all(home).expect("cleanup verify home");
    fs::remove_dir_all(root).expect("cleanup verify vault");
}

#[test]
fn file_add_get_roundtrip_matches_go_cli() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("file-home");
    let root = temporary_root("file-vault");
    let fixture_dir = temporary_root("file-fixtures");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&fixture_dir).expect("fixture directory");
    let go_source = fixture_dir.join("certificate-go.p12");
    let rust_source = fixture_dir.join("certificate-rust.p12");
    let go_output = fixture_dir.join("go-output.p12");
    let rust_output = fixture_dir.join("rust-output.p12");
    let go_content = b"go-binary-attachment\0\xff";
    let rust_content = b"rust-binary-attachment\0\x01\x02";
    fs::write(&go_source, go_content).expect("Go fixture");
    fs::write(&rust_source, rust_content).expect("Rust fixture");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_success(&init, "Rust init for file differential");

    let go_add = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "add",
            "work/go-file",
            "--field",
            "cert_p12",
            "--from",
            go_source.to_str().unwrap(),
            "--type",
            "certificate",
        ],
        &root,
        &home,
    );
    assert_success(&go_add, "Go file add");
    let rust_get = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/go-file#cert_p12",
            "--out",
            rust_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&rust_get, "Rust get Go attachment");
    assert_eq!(fs::read(&rust_output).expect("Rust output"), go_content);

    // Exercise Go's chunked-v1 reader, CR/LF-tolerant base64 decoder, and
    // query-field precedence. The embedded #file selector wins over the
    // conflicting --field value in both CLIs.
    for (field, value) in [
        ("file", "chunked-v1:part1,part2"),
        ("part1", "Z\r\n2"),
        ("part2", "8="),
        ("chunk_count", "2"),
    ] {
        let set = run(
            &go_binary,
            &[
                "--vault",
                root.to_str().unwrap(),
                "set",
                &format!("work/chunked.{field}"),
                "--value",
                value,
                "--force",
            ],
            &root,
            &home,
        );
        assert_success(&set, &format!("Go set chunk {field}"));
    }
    let chunk_go_output = fixture_dir.join("chunk-go-output.bin");
    let chunk_rust_output = fixture_dir.join("chunk-rust-output.bin");
    let go_chunk_get = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/chunked#file",
            "--field",
            "wrong_field",
            "--out",
            chunk_go_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    let rust_chunk_get = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/chunked#file",
            "--field",
            "wrong_field",
            "--out",
            chunk_rust_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&go_chunk_get, "Go chunked file get");
    assert_success(&rust_chunk_get, "Rust chunked file get");
    assert_eq!(
        fs::read(&chunk_rust_output).expect("Rust chunk output"),
        fs::read(&chunk_go_output).expect("Go chunk output")
    );
    assert_eq!(
        fs::read(&chunk_rust_output).expect("Rust chunk output"),
        b"go"
    );

    let mismatch = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "set",
            "work/chunked.chunk_count",
            "--value",
            "3",
            "--force",
        ],
        &root,
        &home,
    );
    assert_success(&mismatch, "Go set mismatched chunk count");
    let go_chunk_mismatch = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/chunked#file",
            "--out",
            chunk_go_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    let rust_chunk_mismatch = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/chunked#file",
            "--out",
            chunk_rust_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert!(!go_chunk_mismatch.status.success());
    assert!(!rust_chunk_mismatch.status.success());

    let rust_add = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "add",
            "work/rust-file",
            "--field",
            "cert_p12",
            "--from",
            rust_source.to_str().unwrap(),
            "--type",
            "certificate",
        ],
        &root,
        &home,
    );
    assert_success(&rust_add, "Rust file add");
    let go_get = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "get",
            "work/rust-file#cert_p12",
            "--out",
            go_output.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&go_get, "Go get Rust attachment");
    assert_eq!(fs::read(&go_output).expect("Go output"), rust_content);

    let shred_source = fixture_dir.join("shred-me.bin");
    fs::write(&shred_source, b"remove-after-write").expect("shred fixture");
    let rust_shred = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "add",
            "work/shred-file",
            "--field",
            "secret_blob",
            "--from",
            shred_source.to_str().unwrap(),
            "--shred",
        ],
        &root,
        &home,
    );
    assert_success(&rust_shred, "Rust file add shred");
    assert!(
        !shred_source.exists(),
        "--shred must remove source after write"
    );

    fs::remove_dir_all(home).expect("cleanup file home");
    fs::remove_dir_all(root).expect("cleanup file vault");
    fs::remove_dir_all(fixture_dir).expect("cleanup file fixtures");
}

#[test]
fn file_use_materializes_and_cleans_attachment_like_go_cli() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("file-use-home");
    let root = temporary_root("file-use-vault");
    let fixture_dir = temporary_root("file-use-fixtures");
    let _fixture_cleanup = TempFixture::new([home.clone(), root.clone(), fixture_dir.clone()]);
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&fixture_dir).expect("fixture directory");
    let source = fixture_dir.join("certificate.p12");
    let marker_go = fixture_dir.join("go-marker");
    let marker_rust = fixture_dir.join("rust-marker");
    let content = b"file-use-secret\0\xff";
    fs::write(&source, content).expect("source fixture");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_success(&init, "Rust init for file use differential");
    let add = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "add",
            "work/file-use",
            "--field",
            "cert_p12",
            "--from",
            source.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&add, "Go file add for file use");

    let script = |marker: &Path| {
        format!(
            "test -f \"$SYMVAULT_FILE_CERT_P12\"; printf '%s' \"$SYMVAULT_FILE_CERT_P12\" > {} ; cat \"$SYMVAULT_FILE_CERT_P12\"",
            marker.display()
        )
    };
    let go_use = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            &script(&marker_go),
        ],
        &root,
        &home,
    );
    let rust_use = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            &script(&marker_rust),
        ],
        &root,
        &home,
    );
    assert_success(&go_use, "Go file use");
    assert_success(&rust_use, "Rust file use");
    assert_eq!(rust_use.stdout, go_use.stdout, "file use stdout");
    assert!(!String::from_utf8_lossy(&rust_use.stdout).contains("file-use-secret"));
    assert!(!String::from_utf8_lossy(&rust_use.stderr).contains("file-use-secret"));
    let go_materialized = fs::read_to_string(&marker_go).expect("Go marker");
    let rust_materialized = fs::read_to_string(&marker_rust).expect("Rust marker");
    assert!(!Path::new(&go_materialized).exists(), "Go file cleanup");
    assert!(!Path::new(&rust_materialized).exists(), "Rust file cleanup");

    let go_failure = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            "test -f \"$SYMVAULT_FILE_CERT_P12\"; exit 7",
        ],
        &root,
        &home,
    );
    let rust_failure = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            "test -f \"$SYMVAULT_FILE_CERT_P12\"; exit 7",
        ],
        &root,
        &home,
    );
    assert!(!go_failure.status.success());
    assert!(!rust_failure.status.success());

    let timeout_script = |marker: &Path| {
        format!(
            "printf '%s' \"$SYMVAULT_FILE_CERT_P12\" > {}; exec sleep 5",
            marker.display()
        )
    };
    let go_timeout_marker = fixture_dir.join("go-timeout-marker");
    let rust_timeout_marker = fixture_dir.join("rust-timeout-marker");
    let go_timeout = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--timeout",
            "20ms",
            "--",
            "sh",
            "-c",
            &timeout_script(&go_timeout_marker),
        ],
        &root,
        &home,
    );
    let rust_timeout_started = Instant::now();
    let rust_timeout = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--timeout",
            "20ms",
            "--",
            "sh",
            "-c",
            &timeout_script(&rust_timeout_marker),
        ],
        &root,
        &home,
    );
    let assert_timeout_and_cleanup = |output: &Output, marker: &Path, command: &str| {
        assert!(!output.status.success(), "{command} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("timed out"),
            "{command} did not report a timeout: stderr={}\nstdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        match fs::read_to_string(marker) {
            Ok(materialized) => assert!(
                !Path::new(materialized.trim()).exists(),
                "{command} left materialized payload at {}",
                materialized.trim()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A 20ms deadline can expire before the shell starts. In that
                // case it cannot have created a payload marker; run() has
                // still reaped the CLI process before returning.
            }
            Err(error) => panic!("read {command} timeout marker: {error}"),
        }
    };
    assert_timeout_and_cleanup(&go_timeout, &go_timeout_marker, "Go file use timeout");
    assert_timeout_and_cleanup(&rust_timeout, &rust_timeout_marker, "Rust file use timeout");
    assert!(rust_timeout_started.elapsed().as_secs() < 2);

    let sentinel = fixture_dir.join("sentinel");
    fs::write(&sentinel, b"must-survive").expect("sentinel");
    let symlink_script = format!(
        "rm \"$SYMVAULT_FILE_CERT_P12\"; ln -s {} \"$SYMVAULT_FILE_CERT_P12\"",
        sentinel.display()
    );
    let rust_symlink = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            &symlink_script,
        ],
        &root,
        &home,
    );
    assert_success(&rust_symlink, "Rust file use symlink replacement");
    assert_eq!(
        fs::read(&sentinel).expect("sentinel after cleanup"),
        b"must-survive"
    );

    let hardlink = fixture_dir.join("hardlink");
    let hardlink_script = format!(
        "ln \"$SYMVAULT_FILE_CERT_P12\" {}; rm \"$SYMVAULT_FILE_CERT_P12\"",
        hardlink.display()
    );
    let rust_hardlink = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            &hardlink_script,
        ],
        &root,
        &home,
    );
    assert_success(&rust_hardlink, "Rust file use hardlink cleanup");
    assert_eq!(
        fs::read(&hardlink).expect("hardlink after cleanup"),
        vec![0; content.len()]
    );

    let descendant_started = Instant::now();
    let descendant = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "file",
            "use",
            "work/file-use#cert_p12",
            "--",
            "sh",
            "-c",
            "sleep 5 &",
        ],
        &root,
        &home,
    );
    assert_success(&descendant, "Rust file use background descendant");
    assert!(descendant_started.elapsed().as_secs() < 2);
}

#[test]
fn builtin_templates_match_go_cli() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = temporary_root("template-home");
    let root = temporary_root("template-vault");
    fs::create_dir_all(&home).unwrap();
    assert_success(
        &run(
            &rust_binary,
            &["init", "--auth", "passphrase"],
            &root,
            &home,
        ),
        "init template vault",
    );
    assert_success(
        &run(
            &rust_binary,
            &[
                "set",
                "work/item.password",
                "--value",
                "<strong&secret>123!",
                "--force",
            ],
            &root,
            &home,
        ),
        "set template value",
    );
    for kind in [
        "env",
        "docker-compose",
        "k8s-secret",
        "github-actions",
        "terraform",
    ] {
        for refs in [
            vec!["TOKEN=work/item.password", "İΣ=op://work/item/password"],
            vec!["--prefix", "work/"],
            vec!["--dry-run", "TOKEN=missing.password"],
        ] {
            let mut args = vec!["template", "generate", "--type", kind, "--name", "sample"];
            args.extend(refs);
            let go = run(&go_binary, &args, &root, &home);
            let rust = run(&rust_binary, &args, &root, &home);
            assert_success(&go, kind);
            assert_success(&rust, kind);
            assert_eq!(rust.stdout, go.stdout, "{kind} {args:?}");
        }
    }
    let output = root.join("rendered.env");
    let args = [
        "template",
        "generate",
        "--type",
        "env",
        "--output",
        output.to_str().unwrap(),
        "TOKEN=work/item.password",
    ];
    assert_success(&run(&go_binary, &args, &root, &home), "Go template file");
    let expected = fs::read(&output).unwrap();
    fs::remove_file(&output).unwrap();
    assert_success(
        &run(&rust_binary, &args, &root, &home),
        "Rust template file",
    );
    assert_eq!(fs::read(&output).unwrap(), expected);
    let custom = home.join(".config/symvault/templates");
    fs::create_dir_all(&custom).unwrap();
    fs::write(custom.join("env.tmpl"), "custom override").unwrap();
    let rejected = run(
        &rust_binary,
        &[
            "template",
            "generate",
            "--type",
            "env",
            "TOKEN=work/item.password",
        ],
        &root,
        &home,
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("custom Go templates"));
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn get_flags_parity_matches_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let root = temporary_root("get-flags");
    let home = temporary_root("get-flags-home");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();

    let init = run(
        &rust_binary,
        &["init", "--auth", "passphrase"],
        &root,
        &home,
    );
    assert_success(&init, "Rust init for get flags parity");

    let add = run(
        &rust_binary,
        &[
            "add",
            "test/secret-entry",
            "--value",
            "DifferentialSecret123!",
            "--force",
        ],
        &root,
        &home,
    );
    assert_success(&add, "Rust add secret");

    // --length
    let go_len = run(
        &go_binary,
        &["get", "test/secret-entry.password", "--length"],
        &root,
        &home,
    );
    let rust_len = run(
        &rust_binary,
        &["get", "test/secret-entry.password", "--length"],
        &root,
        &home,
    );
    assert_success(&go_len, "Go get --length");
    assert_success(&rust_len, "Rust get --length");
    assert_eq!(rust_len.stdout, go_len.stdout, "--length stdout");

    // --digest
    let go_digest = run(
        &go_binary,
        &["get", "test/secret-entry.password", "--digest"],
        &root,
        &home,
    );
    let rust_digest = run(
        &rust_binary,
        &["get", "test/secret-entry.password", "--digest"],
        &root,
        &home,
    );
    assert_success(&go_digest, "Go get --digest");
    assert_success(&rust_digest, "Rust get --digest");
    assert_eq!(rust_digest.stdout, go_digest.stdout, "--digest stdout");

    // --metadata
    let go_meta = run(
        &go_binary,
        &["get", "test/secret-entry.password", "--metadata"],
        &root,
        &home,
    );
    let rust_meta = run(
        &rust_binary,
        &["get", "test/secret-entry.password", "--metadata"],
        &root,
        &home,
    );
    assert_success(&go_meta, "Go get --metadata");
    assert_success(&rust_meta, "Rust get --metadata");
    assert_eq!(rust_meta.stdout, go_meta.stdout, "--metadata stdout");

    // --length --quiet
    let go_quiet = run(
        &go_binary,
        &["get", "test/secret-entry.password", "--length", "--quiet"],
        &root,
        &home,
    );
    let rust_quiet = run(
        &rust_binary,
        &["get", "test/secret-entry.password", "--length", "--quiet"],
        &root,
        &home,
    );
    assert_success(&go_quiet, "Go get --length --quiet");
    assert_success(&rust_quiet, "Rust get --length --quiet");
    assert!(rust_quiet.stdout.is_empty());
    assert_eq!(rust_quiet.stdout, go_quiet.stdout);

    // Mutual exclusivity
    let go_mut = run(
        &go_binary,
        &["get", "test/secret-entry.password", "--length", "--digest"],
        &root,
        &home,
    );
    let rust_mut = run(
        &rust_binary,
        &["get", "test/secret-entry.password", "--length", "--digest"],
        &root,
        &home,
    );
    assert_eq!(rust_mut.status.code(), Some(9));
    assert_eq!(go_mut.status.code(), Some(9));
    assert_eq!(rust_mut.status, go_mut.status);
    assert_eq!(rust_mut.stderr, go_mut.stderr);

    // Missing field error
    let go_missing_field = run(
        &go_binary,
        &["get", "test/secret-entry", "--length"],
        &root,
        &home,
    );
    let rust_missing_field = run(
        &rust_binary,
        &["get", "test/secret-entry", "--length"],
        &root,
        &home,
    );
    assert_eq!(rust_missing_field.status.code(), Some(9));
    assert_eq!(go_missing_field.status.code(), Some(9));
    assert_eq!(rust_missing_field.status, go_missing_field.status);
    assert_eq!(rust_missing_field.stderr, go_missing_field.stderr);

    // Missing entry error
    let go_missing_entry = run(
        &go_binary,
        &["get", "missing/entry.password", "--length"],
        &root,
        &home,
    );
    let rust_missing_entry = run(
        &rust_binary,
        &["get", "missing/entry.password", "--length"],
        &root,
        &home,
    );
    assert_eq!(rust_missing_entry.status.code(), Some(9));
    assert_eq!(go_missing_entry.status.code(), Some(9));
    assert_eq!(rust_missing_entry.status, go_missing_entry.status);
    assert_eq!(rust_missing_entry.stderr, go_missing_entry.stderr);

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn set_totp_flags_parity_matches_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_root = temporary_root("set-totp-go");
    let go_home = temporary_root("set-totp-go-home");
    let rust_root = temporary_root("set-totp-rust");
    let rust_home = temporary_root("set-totp-rust-home");
    for (root, home) in [(&go_root, &go_home), (&rust_root, &rust_home)] {
        fs::create_dir_all(root).unwrap();
        fs::create_dir_all(home).unwrap();
        let init = run(&rust_binary, &["init", "--auth", "passphrase"], root, home);
        assert_success(&init, "init for set totp");
    }

    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let set_args = [
        "set",
        "work/totp-entry",
        "--value",
        "StrongPassword123!",
        "--force",
        "--totp-secret",
        secret,
        "--totp-issuer",
        "SymairaCorp",
        "--totp-account",
        "alice@corp.test",
    ];
    let go_set = run(&go_binary, &set_args, &go_root, &go_home);
    let rust_set = run(&rust_binary, &set_args, &rust_root, &rust_home);
    assert_success(&go_set, "Go set with TOTP");
    assert_success(&rust_set, "Rust set with TOTP");

    let get_json_args = ["get", "work/totp-entry", "--output", "json"];
    let go_json = run(&go_binary, &get_json_args, &go_root, &go_home);
    let rust_json = run(&rust_binary, &get_json_args, &rust_root, &rust_home);
    assert_success(&go_json, "Go get TOTP entry JSON");
    assert_success(&rust_json, "Rust get TOTP entry JSON");

    let go_val: serde_json::Value = serde_json::from_slice(&go_json.stdout).unwrap();
    let rust_val: serde_json::Value = serde_json::from_slice(&rust_json.stdout).unwrap();
    assert_eq!(go_val["Fields"]["password"], rust_val["Fields"]["password"]);
    assert_eq!(go_val["Fields"]["totp"], rust_val["Fields"]["totp"]);
    assert_eq!(go_val["TOTP"]["period"], rust_val["TOTP"]["period"]);
    // Each process evaluates the live code independently; a 30-second boundary
    // can make different valid codes even when both implementations match.

    // Weak/short secret rejection parity
    let bad_set_args = [
        "set",
        "work/bad-totp",
        "--value",
        "StrongPassword123!",
        "--force",
        "--totp-secret",
        "SHORT",
    ];
    let go_bad = run(&go_binary, &bad_set_args, &go_root, &go_home);
    let rust_bad = run(&rust_binary, &bad_set_args, &rust_root, &rust_home);
    assert!(!go_bad.status.success());
    assert!(!rust_bad.status.success());
    assert_eq!(rust_bad.status.code(), Some(1));
    assert_eq!(go_bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rust_bad.stderr).contains("TOTP secret too short"));
    assert!(String::from_utf8_lossy(&go_bad.stderr).contains("TOTP secret too short"));

    fs::remove_dir_all(go_root).unwrap();
    fs::remove_dir_all(go_home).unwrap();
    fs::remove_dir_all(rust_root).unwrap();
    fs::remove_dir_all(rust_home).unwrap();
}

#[test]
fn template_name_and_prefix_parity_matches_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let root = temporary_root("template-prefix");
    let home = temporary_root("template-prefix-home");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();

    let init = run(
        &rust_binary,
        &["init", "--auth", "passphrase"],
        &root,
        &home,
    );
    assert_success(&init, "init for template prefix test");

    for (path, val) in [
        ("deploy/api", "apisecret12345"),
        ("deploy/db", "dbsecret12345"),
    ] {
        let add = run(
            &rust_binary,
            &["add", path, "--value", val, "--force"],
            &root,
            &home,
        );
        assert_success(&add, "add entry for template");
    }

    let env_args = [
        "template", "generate", "--type", "env", "--prefix", "deploy/",
    ];
    let go_env = run(&go_binary, &env_args, &root, &home);
    let rust_env = run(&rust_binary, &env_args, &root, &home);
    assert_success(&go_env, "Go template generate env prefix");
    assert_success(&rust_env, "Rust template generate env prefix");
    assert_eq!(rust_env.stdout, go_env.stdout, "template env prefix stdout");

    let k8s_args = [
        "template",
        "generate",
        "--type",
        "k8s-secret",
        "--name",
        "cluster-secrets",
        "--prefix",
        "deploy/",
    ];
    let go_k8s = run(&go_binary, &k8s_args, &root, &home);
    let rust_k8s = run(&rust_binary, &k8s_args, &root, &home);
    assert_success(&go_k8s, "Go template generate k8s name prefix");
    assert_success(&rust_k8s, "Rust template generate k8s name prefix");
    assert_eq!(
        rust_k8s.stdout, go_k8s.stdout,
        "template k8s name prefix stdout"
    );

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(home).unwrap();
}
