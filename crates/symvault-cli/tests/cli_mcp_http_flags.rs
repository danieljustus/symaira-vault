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
    let output = Command::new(binary)
        .args(["mcp", "--bind", "0.0.0.0"])
        .output()
        .expect("run fail-closed MCP option");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("native MCP HTTP wildcard binds are unavailable; choose a concrete IP"),
        "unexpected error: {stderr}"
    );
}
