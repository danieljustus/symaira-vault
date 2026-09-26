#![cfg(unix)] // SIGTERM lifecycle is currently exercised on Unix; Windows skips this test.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn configured_command(binary: &Path, home: &Path, tmp: &Path, vault: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(vault)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", tmp)
        .env("TMP", tmp)
        .env("TEMP", tmp)
        .env("SYMVAULT_PASSPHRASE", "broker-signal-fixture")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env_remove("SYMVAULT_VAULT");
    command
}

fn wait_for_listener(child: &mut ChildGuard, address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll broker startup") {
            panic!("broker exited before listening: {status}");
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "broker did not bind {address}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn stop_with_sigterm(child: &ChildGuard) {
    let status = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .expect("send SIGTERM to broker");
    assert!(status.success(), "send SIGTERM: {status}");
}

fn finish_with_timeout(child: &mut ChildGuard) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll broker shutdown") {
            return status;
        }
        if Instant::now() >= deadline {
            panic!("broker did not stop within five seconds after SIGTERM");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn broker_rejects_connect_and_stops_on_sigterm() {
    let binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let temp = TempDir::new().expect("temporary test root");
    let home = temp.path().join("home");
    let tmp = temp.path().join("tmp");
    let vault = temp.path().join("vault");
    std::fs::create_dir_all(&home).expect("create HOME");
    std::fs::create_dir_all(&tmp).expect("create TMPDIR");

    let initialized = configured_command(binary, &home, &tmp, &vault)
        .args(["init", "--auth", "passphrase"])
        .output()
        .expect("initialize broker test vault");
    assert!(
        initialized.status.success(),
        "initialize vault: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
    let address = reserved.local_addr().expect("read reserved loopback port");
    drop(reserved);
    let address_arg = address.to_string();
    let mut child = ChildGuard(
        configured_command(binary, &home, &tmp, &vault)
            .args([
                "broker",
                "--addr",
                address_arg.as_str(),
                "--strict",
                "--passthrough",
                "example.com",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start broker"),
    );
    wait_for_listener(&mut child, address);

    let mut proxy = TcpStream::connect(address).expect("connect to loopback broker");
    proxy
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set broker response timeout");
    proxy
        .write_all(b"CONNECT 192.168.1.1:443 HTTP/1.1\r\nHost: 192.168.1.1:443\r\n\r\n")
        .expect("send rejected CONNECT without DNS");
    let mut response = Vec::new();
    proxy
        .read_to_end(&mut response)
        .expect("read rejected CONNECT response");
    let response = String::from_utf8(response).expect("decode proxy response");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response:?}"
    );
    assert!(
        response.contains("CONNECT target is blocked"),
        "{response:?}"
    );

    stop_with_sigterm(&child);
    assert_eq!(finish_with_timeout(&mut child).code(), Some(0));
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err(),
        "broker listener remained open after exit"
    );
}
