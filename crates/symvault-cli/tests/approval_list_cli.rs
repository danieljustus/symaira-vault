//! Source-bound `approval list` security-boundary differential.
//!
//! Go's command rejects a runtime listener on a non-loopback address before
//! attempting TLS or sending the vault proof. This exercises the same CLI
//! branch in Rust and pins its message to the production Go command source.

use std::{fs, process::Command};

use tempfile::tempdir;

const GO_COMMAND: &str = include_str!("../../../cmd/approval.go");
const GO_LOCAL_HANDLER: &str = include_str!("../../../internal/approval/local.go");
const LOOPBACK_ERROR: &str =
    "approval CLI requires a server bound to loopback; running server is bound to %q";

#[test]
fn approval_list_refuses_non_loopback_server_like_go() {
    assert!(GO_COMMAND.contains(LOOPBACK_ERROR));
    assert!(GO_COMMAND.contains("approval.PathLocalApprovals"));
    assert!(GO_LOCAL_HANDLER.contains("verifyEnrollProof"));
    assert!(GO_LOCAL_HANDLER.contains("h.isLoopback == nil || !h.isLoopback(host)"));

    let vault = tempdir().expect("temporary vault");
    fs::write(vault.path().join("identity.age"), "fixture").expect("identity marker");
    fs::write(vault.path().join("config.yaml"), "{}\n").expect("config marker");
    fs::write(
        vault.path().join(".runtime-port"),
        r#"{"port":9443,"bind":"0.0.0.0"}"#,
    )
    .expect("runtime server metadata");

    let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .arg("--vault")
        .arg(vault.path())
        .args(["approval", "list"])
        .output()
        .expect("run approval list");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("approval CLI requires a server bound to loopback; running server is bound to \"0.0.0.0\""),
        "unexpected error: {stderr}"
    );
}
