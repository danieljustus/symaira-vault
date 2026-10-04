use std::process::Command;

#[test]
fn mcp_http_flags_match_go_surface_and_default_loopback() {
    let binary = env!("CARGO_BIN_EXE_symvault");
    for args in [&["mcp", "--help"][..], &["mcp", "serve", "--help"][..]] {
        let output = Command::new(binary)
            .args(args)
            .output()
            .expect("run native MCP help");
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        for flag in [
            "--agent",
            "--bind",
            "--port",
            "--stdio",
            "--tls-cert",
            "--tls-key",
            "--tls-ca",
        ] {
            assert!(help.contains(flag), "missing Go MCP flag {flag} in {help}");
        }
        assert!(
            help.contains("127.0.0.1"),
            "HTTP default must remain loopback: {help}"
        );
        assert!(help.contains("8080"), "HTTP default port changed: {help}");
    }
}

#[test]
fn mcp_http_rejects_wildcard_bind() {
    let binary = env!("CARGO_BIN_EXE_symvault");
    let root = tempfile::tempdir().expect("private real-vault fixture");
    let command = || {
        let mut command = Command::new(binary);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SYMVAULT_") {
                command.env_remove(key);
            }
        }
        command
            .current_dir(root.path())
            .env("HOME", root.path())
            .env("USERPROFILE", root.path())
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("XDG_CACHE_HOME", root.path().join("cache"))
            .env("SYMVAULT_VAULT", root.path().join("vault"))
            .env("SYMVAULT_TEST_KEYRING", "memory")
            .env("SYMVAULT_PASSPHRASE", "public-wildcard-fixture")
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
            .env("SYMVAULT_NO_ENV_WARNING", "1");
        command
    };
    let missing = command()
        .args(["mcp", "--bind", "0.0.0.0"])
        .output()
        .unwrap();
    assert_eq!(
        missing.status.code(),
        Some(3),
        "Go checks vault initialization before HTTP bootstrap"
    );
    let initialized = command()
        .args(["init", "--auth", "passphrase"])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "initialize actual encrypted fixture: {:?}",
        initialized.stderr
    );
    let output = command()
        .args(["mcp", "--bind", "0.0.0.0"])
        .output()
        .expect("run fail-closed MCP runtime");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MCP HTTP wildcard binds are unavailable; choose a concrete IP"),
        "unexpected error: {stderr}"
    );
}
