use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

fn run(binary: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", home.join(".tmp"))
        .env("TMP", home.join(".tmp"))
        .env("TEMP", home.join(".tmp"))
        .env("SYMVAULT_PASSPHRASE", "fixture-passphrase-123")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .output()
        .expect("run intake command")
}

#[test]
fn parent_dry_run_limits_and_ocr_match_go() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let temp = TempDir::new().expect("create disposable root");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("create disposable HOME");
    fs::create_dir_all(home.join(".tmp")).expect("create disposable temp directory");
    let image = temp.path().join("scan.png");
    fs::write(&image, b"\x89PNG\r\n\x1a\nfixture").expect("write image fixture");
    let ocr = temp.path().join("ocr.txt");
    fs::write(
        &ocr,
        "username: alice\npassword: hidden-value\napi key: token-value\nnote: ignored\n",
    )
    .expect("write OCR fixture");
    let image_arg = image.to_str().unwrap();
    let ocr_arg = ocr.to_str().unwrap();

    let args = ["intake", image_arg, "--dry-run", "--ocr-text", ocr_arg];
    let go_output = run(&go, &home, &args);
    let rust_output = run(rust, &home, &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);
    assert!(String::from_utf8_lossy(&rust_output.stdout).contains("field: password"));
    assert!(!String::from_utf8_lossy(&rust_output.stdout).contains("hidden-value"));
    assert!(!String::from_utf8_lossy(&rust_output.stdout).contains("token-value"));

    let args = [
        "intake",
        image_arg,
        "--dry-run",
        "--ocr-text",
        ocr_arg,
        "--json",
    ];
    let go_output = run(&go, &home, &args);
    let rust_output = run(rust, &home, &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);
    assert!(!String::from_utf8_lossy(&rust_output.stdout).contains("hidden-value"));

    let second = temp.path().join("second.txt");
    fs::write(&second, "note: second\n").expect("write second source");
    let second_arg = second.to_str().unwrap();
    let args = [
        "intake",
        image_arg,
        second_arg,
        "--dry-run",
        "--max-files",
        "1",
    ];
    let go_output = run(&go, &home, &args);
    let rust_output = run(rust, &home, &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);

    let args = [
        "intake",
        image_arg,
        second_arg,
        "--dry-run",
        "--batch-limit",
        "1",
    ];
    let go_output = run(&go, &home, &args);
    let rust_output = run(rust, &home, &args);
    assert_eq!(rust_output.status.code(), go_output.status.code());
    assert_eq!(rust_output.stdout, go_output.stdout);
    assert_eq!(rust_output.stderr, go_output.stderr);

    #[cfg(not(target_os = "macos"))]
    {
        let args = ["intake", image_arg, "--move-to-trash"];
        let go_output = run(&go, &home, &args);
        let rust_output = run(rust, &home, &args);
        assert_eq!(rust_output.status.code(), go_output.status.code());
        assert_eq!(rust_output.stdout, go_output.stdout);
        assert_eq!(rust_output.stderr, go_output.stderr);
        assert_eq!(fs::read(&image).unwrap(), b"\x89PNG\r\n\x1a\nfixture");
    }
}
