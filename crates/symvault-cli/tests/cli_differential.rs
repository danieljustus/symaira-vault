use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_root(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-cli-differential-{name}-{suffix}"))
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
        return format!(
            "success={} code={:?} signal={:?}",
            status.success(),
            status.code(),
            status.signal()
        );
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

    let go_find_secret = run(
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
    let go_find_url = run(
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
    let go_find_scoped = run(
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
    let go_find_unicode = run(
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
    let go_find_unicode_special = run(
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
    let go_find_empty = run(
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
