use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

fn has_flag(command: &Value, kind: &str, name: &str) -> bool {
    command[kind]
        .as_array()
        .is_some_and(|flags| flags.iter().any(|flag| flag["name"] == name))
}

fn check_shell_syntax(shell: &str, script: &[u8]) {
    let mut child = match Command::new(shell)
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("start {shell} syntax check: {error}"),
    };
    child
        .stdin
        .take()
        .expect("syntax checker stdin")
        .write_all(script)
        .expect("write completion script to syntax checker");
    let result = child.wait_with_output().expect("wait for syntax checker");
    assert!(
        result.status.success(),
        "{shell} rejected generated script: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn shell_completions_are_generated_from_the_cli_and_match_go_commands_and_flags() {
    let oracle: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/command-tree.json"))
            .expect("Go command-tree fixture");
    assert!(
        !oracle["oracle"]["commit_sha"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    let commands = oracle["commands"].as_array().expect("Go commands");
    let root = commands
        .iter()
        .find(|command| command["path"] == "symvault")
        .expect("Go root command");
    let add = commands
        .iter()
        .find(|command| command["path"] == "symvault add")
        .expect("Go add command");
    let add_name = add["name"].as_str().expect("Go add command name");
    assert!(has_flag(root, "persistent_flags", "vault"));
    assert!(has_flag(add, "local_flags", "length"));

    for (shell, marker) in [
        ("bash", "complete -F"),
        ("zsh", "#compdef symvault"),
        ("fish", "complete -c symvault"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
            .args(["completion", shell])
            .output()
            .unwrap_or_else(|error| panic!("run Rust {shell} completion: {error}"));
        assert!(
            output.status.success(),
            "Rust {shell} completion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "Rust {shell} emitted no script");
        let script = String::from_utf8(output.stdout).expect("completion output is UTF-8");
        assert!(
            script.contains(marker),
            "Rust {shell} did not emit a shell script"
        );
        for expected in ["symvault", add_name, "vault", "length"] {
            assert!(
                script.contains(expected),
                "Rust {shell} script omits {expected}"
            );
        }
        if shell == "bash" || shell == "zsh" {
            check_shell_syntax(shell, script.as_bytes());
        }
    }
}
