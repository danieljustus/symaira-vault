#![deny(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use symvault_crypto::{
    Identity, SecretBytes, decrypt, decrypt_identity, encrypt, encrypt_identity_scrypt,
    generate_identity, parse_recipient, recipient_string,
};
use symvault_sync::{Device, DeviceRegistry, GoTime};

struct TestVault {
    path: PathBuf,
    identity: Identity,
    passphrase: String,
}

impl TestVault {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sv-test-vault-{}-{}-{}",
            name,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join("entries")).unwrap();
        fs::create_dir_all(path.join(".symvault/pairing")).unwrap();

        let identity = generate_identity();
        let passphrase = "correct-test-passphrase-123".to_owned();

        // Write config.yaml
        let config = format!("vaultDir: \"{}\"\nformat_version: 1\n", path.display());
        fs::write(path.join("config.yaml"), config).unwrap();

        // Write identity.age
        let sec_pass = SecretBytes::new(passphrase.as_bytes());
        let enc_id = encrypt_identity_scrypt(&identity, &sec_pass, 18).unwrap();
        fs::write(path.join("identity.age"), enc_id).unwrap();

        // Write recipients.txt
        let pubkey = recipient_string(&identity);
        fs::write(path.join("recipients.txt"), format!("{pubkey}\n")).unwrap();

        Self {
            path,
            identity,
            passphrase,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_symvault"))
            .env("SYMVAULT_PASSPHRASE", &self.passphrase)
            .env("HOME", &self.path)
            .env("USERPROFILE", &self.path)
            .arg("--vault")
            .arg(&self.path)
            .args(args)
            .output()
            .unwrap()
    }

    fn write_secret_entry(&self, name: &str, content: &[u8]) {
        let own_pubkey = recipient_string(&self.identity);
        let recip = parse_recipient(&own_pubkey).unwrap();
        let ciphertext = encrypt(content, &[recip]).unwrap();
        let file_path = self.path.join("entries").join(format!("{name}.age"));
        fs::write(file_path, ciphertext).unwrap();
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn device_pair_creates_pairing_file_and_prints_token_info() {
    let vault = TestVault::new("pair");
    let output = vault.run(&["device", "pair"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("=== Pairing Token ==="));
    assert!(stdout.contains("Token: "));
    assert!(stdout.contains("This device's public key: "));
    assert!(stdout.contains("Key fingerprint: "));

    // Verify .symvault/pairing/<token>.json was created
    let pairing_dir = vault.path.join(".symvault/pairing");
    let entries: Vec<_> = fs::read_dir(pairing_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let pairing_file_path = entries[0].as_ref().unwrap().path();
    assert!(pairing_file_path.to_string_lossy().ends_with(".json"));

    let content = fs::read(&pairing_file_path).unwrap();
    let pf = symvault_sync::parse_pairing_file(&content).unwrap();
    assert_eq!(pf.public_key, recipient_string(&vault.identity));
    assert_eq!(
        pairing_file_path.file_stem().unwrap().to_str().unwrap(),
        pf.token
    );
}

#[test]
fn device_join_and_accept_file_transport_end_to_end() {
    let primary = TestVault::new("primary");
    primary.write_secret_entry("mysecret", b"sensitive-data-payload");

    // 1. Primary generates pairing token
    let output = primary.run(&["device", "pair"]);
    assert!(output.status.success());

    let pairing_dir = primary.path.join(".symvault/pairing");
    let entries: Vec<_> = fs::read_dir(&pairing_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let pairing_file = entries[0].as_ref().unwrap().path();
    let token = pairing_file
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // 2. Joining device joins using --pairing-file
    let join_dir = std::env::temp_dir().join(format!("sv-join-{}", std::process::id()));
    let _ = fs::remove_dir_all(&join_dir);

    let join_output = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .env("SYMVAULT_PASSPHRASE", "joining-device-passphrase-123")
        .env("HOME", &join_dir)
        .arg("--vault")
        .arg(&join_dir)
        .args([
            "device",
            "join",
            "--pairing-file",
            pairing_file.to_str().unwrap(),
            &token,
            "--name",
            "joining-laptop",
        ])
        .output()
        .unwrap();

    assert!(
        join_output.status.success(),
        "join stderr: {}",
        String::from_utf8_lossy(&join_output.stderr)
    );

    // Verify joining device vault initialized
    assert!(join_dir.join("identity.age").exists());
    assert!(join_dir.join("config.yaml").exists());
    assert!(join_dir.join("recipients.txt").exists());

    // Verify response artifact in joining vault
    let resp_file = join_dir
        .join(".symvault/pairing")
        .join(format!("{token}-response.json"));
    assert!(resp_file.exists());
    let resp_bytes = fs::read(&resp_file).unwrap();
    let join_resp = symvault_sync::parse_join_response(&resp_bytes).unwrap();
    assert_eq!(join_resp.token, token);
    assert_eq!(join_resp.name, "joining-laptop");

    // Read joining identity to verify decrypt capability later
    let join_sec_pass = SecretBytes::new(b"joining-device-passphrase-123");
    let join_id_bytes = fs::read(join_dir.join("identity.age")).unwrap();
    let join_identity = decrypt_identity(&join_id_bytes, &join_sec_pass).unwrap();
    assert_eq!(recipient_string(&join_identity), join_resp.public_key);

    // 3. Deliver response artifact to primary vault
    let primary_resp_file = primary
        .path
        .join(".symvault/pairing")
        .join(format!("{token}-response.json"));
    fs::copy(&resp_file, &primary_resp_file).unwrap();

    // 4. Primary accepts device
    let accept_output = primary.run(&["device", "accept", &token]);
    assert!(
        accept_output.status.success(),
        "accept stderr: {}",
        String::from_utf8_lossy(&accept_output.stderr)
    );

    // Verify response artifact was removed on accept
    assert!(!primary_resp_file.exists());

    // Verify joining device's public key was added to primary's recipients.txt
    let recipients_content = fs::read_to_string(primary.path.join("recipients.txt")).unwrap();
    assert!(recipients_content.contains(&join_resp.public_key));

    // 5. Verify the entry was re-encrypted and joining device can decrypt it
    let reencrypted_entry = fs::read(primary.path.join("entries/mysecret.age")).unwrap();
    let decrypted_by_joining = decrypt(&reencrypted_entry, &join_identity).unwrap();
    assert_eq!(decrypted_by_joining, b"sensitive-data-payload");

    // Primary can still decrypt as well
    let decrypted_by_primary = decrypt(&reencrypted_entry, &primary.identity).unwrap();
    assert_eq!(decrypted_by_primary, b"sensitive-data-payload");

    let _ = fs::remove_dir_all(&join_dir);
}

#[test]
fn device_add_with_pair_flag_and_revoke_flow() {
    let primary = TestVault::new("add-primary");
    primary.write_secret_entry("credential", b"top-secret");

    let primary_pubkey = recipient_string(&primary.identity);
    let token = "0123456789ABCDEF0123456789ABCDEF";
    let qr_data = format!("{token}:{primary_pubkey}");

    let add_dir = std::env::temp_dir().join(format!("sv-add-{}", std::process::id()));
    let _ = fs::remove_dir_all(&add_dir);

    // Run device add --pair on second device
    let add_output = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .env("SYMVAULT_PASSPHRASE", "second-device-passphrase-123")
        .env("HOME", &add_dir)
        .arg("--vault")
        .arg(&add_dir)
        .args([
            "device",
            "add",
            "--pair",
            &qr_data,
            "--name",
            "second-device",
        ])
        .output()
        .unwrap();

    assert!(
        add_output.status.success(),
        "add stderr: {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let joined_file = add_dir
        .join(".symvault/pairing")
        .join(format!("{token}-joined.json"));
    assert!(joined_file.exists());
    let joined_bytes = fs::read(&joined_file).unwrap();
    let joined_resp = symvault_sync::parse_join_response(&joined_bytes).unwrap();

    let sec_id_bytes = fs::read(add_dir.join("identity.age")).unwrap();
    let sec_identity = decrypt_identity(
        &sec_id_bytes,
        &SecretBytes::new(b"second-device-passphrase-123"),
    )
    .unwrap();

    // Deliver to primary and accept
    let primary_joined = primary
        .path
        .join(".symvault/pairing")
        .join(format!("{token}-joined.json"));
    fs::copy(&joined_file, &primary_joined).unwrap();

    // Add device to registry on primary so revoke can find it by name
    let dm = DeviceRegistry::new(&primary.path);
    dm.add(Device {
        name: "second-device".to_owned(),
        public_key: joined_resp.public_key.clone(),
        added_at: GoTime::now(),
        last_seen: None,
    })
    .unwrap();

    let accept_output = primary.run(&["device", "accept", token]);
    assert!(accept_output.status.success());

    // Both can decrypt
    let reencrypted = fs::read(primary.path.join("entries/credential.age")).unwrap();
    assert_eq!(decrypt(&reencrypted, &sec_identity).unwrap(), b"top-secret");
    assert_eq!(
        decrypt(&reencrypted, &primary.identity).unwrap(),
        b"top-secret"
    );

    // Revoke second-device with --yes
    let revoke_output = primary.run(&["device", "revoke", "second-device", "--yes"]);
    assert!(
        revoke_output.status.success(),
        "revoke stderr: {}",
        String::from_utf8_lossy(&revoke_output.stderr)
    );

    // Verify removed from registry and recipients.txt
    assert!(dm.get("second-device").unwrap().is_none());
    let recipients_after = fs::read_to_string(primary.path.join("recipients.txt")).unwrap();
    assert!(!recipients_after.contains(&joined_resp.public_key));

    // Verify revoked device can no longer decrypt newly re-encrypted entries
    let post_revoke_entry = fs::read(primary.path.join("entries/credential.age")).unwrap();
    assert!(decrypt(&post_revoke_entry, &sec_identity).is_err());
    assert_eq!(
        decrypt(&post_revoke_entry, &primary.identity).unwrap(),
        b"top-secret"
    );

    let _ = fs::remove_dir_all(&add_dir);
}

#[test]
fn cannot_revoke_current_device() {
    let vault = TestVault::new("self-revoke");
    let dm = DeviceRegistry::new(&vault.path);
    dm.add(Device {
        name: "current-machine".to_owned(),
        public_key: recipient_string(&vault.identity),
        added_at: GoTime::now(),
        last_seen: None,
    })
    .unwrap();

    let output = vault.run(&["device", "revoke", "current-machine", "--yes"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot revoke the current device"));
}

#[test]
fn invalid_pairing_token_format_is_refused() {
    let vault = TestVault::new("invalid-token");
    let output = vault.run(&["device", "accept", "invalid/traversal/token"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid pairing token"));
}

#[cfg(unix)]
#[test]
fn accept_refuses_symlinked_entries_root() {
    let vault = TestVault::new("symlink-entries");
    let real_entries = vault.path.join("real_entries");
    fs::create_dir_all(&real_entries).unwrap();
    fs::remove_dir_all(vault.path.join("entries")).unwrap();
    std::os::unix::fs::symlink(&real_entries, vault.path.join("entries")).unwrap();

    let token = "0123456789ABCDEF0123456789ABCDEF";
    let join_resp = symvault_sync::JoinResponse {
        token: token.to_owned(),
        name: "test-device".to_owned(),
        public_key: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned(),
        created_at: symvault_sync::GoTime::now(),
    };
    let encoded = symvault_sync::marshal_join_response(&join_resp).unwrap();
    fs::write(
        vault
            .path
            .join(format!(".symvault/pairing/{token}-joined.json")),
        encoded,
    )
    .unwrap();

    let output = vault.run(&["device", "accept", token]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsafe symlink entries root"));
}

#[test]
fn accept_refuses_non_directory_entries_root() {
    let vault = TestVault::new("file-entries");
    fs::remove_dir_all(vault.path.join("entries")).unwrap();
    fs::write(vault.path.join("entries"), b"regular file entries").unwrap();

    let token = "0123456789ABCDEF0123456789ABCDEF";
    let join_resp = symvault_sync::JoinResponse {
        token: token.to_owned(),
        name: "test-device".to_owned(),
        public_key: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned(),
        created_at: symvault_sync::GoTime::now(),
    };
    let encoded = symvault_sync::marshal_join_response(&join_resp).unwrap();
    fs::write(
        vault
            .path
            .join(format!(".symvault/pairing/{token}-joined.json")),
        encoded,
    )
    .unwrap();

    let output = vault.run(&["device", "accept", token]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vault entries root is not a directory"));
}
