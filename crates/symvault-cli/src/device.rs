//! PAIRING-001 CLI implementation: device pair, join, accept, list, add, revoke.

use crate::session_input as input;
use input::read_passphrase;
use serde::Serialize;
use std::{
    collections::HashSet,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use symvault_core::config::{Config, GitConfig};
use symvault_crypto::{
    Identity, Recipient, SecretBytes, decrypt_identity, encrypt_identity_scrypt, fingerprint,
    generate_identity, identity_string, parse_identity, parse_recipient, recipient_string,
    reencrypt,
};
use symvault_sync::{
    CommitOptions, DeviceRegistry, GitRepository, GoTime, JoinResponse, PairingFile,
    RecipientsFile, generate_token, marshal_join_response, marshal_pairing_file,
    parse_join_response, parse_pairing_file, response_filenames, safeio, validate_pairing_token,
};

#[derive(Serialize)]
struct ListedDevice<'a> {
    name: &'a str,
    public_key: &'a str,
    added_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<String>,
}

#[derive(Serialize)]
struct Listing<'a> {
    // Go's outer map is sorted, while the inner structs retain field order.
    count: usize,
    devices: Vec<ListedDevice<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unmanaged_recipients: Vec<String>,
}

fn seconds(time: GoTime) -> String {
    let mut value = time.to_rfc3339_nano();
    if let Some(start) = value.find('.') {
        let end = value[start..]
            .find(['Z', '+', '-'])
            .map(|offset| start + offset)
            .unwrap_or(value.len());
        value.replace_range(start..end, "");
    }
    value
}

fn short_key(key: &str) -> Vec<u8> {
    // Go slices bytes, not Unicode scalars. Write bytes, without lossy decoding.
    if key.len() > 16 {
        [key.as_bytes()[..16].to_vec(), b"...".to_vec()].concat()
    } else {
        key.as_bytes().to_vec()
    }
}

fn truncate_pubkey(pubkey: &str) -> String {
    String::from_utf8_lossy(&short_key(pubkey)).into_owned()
}

fn is_initialized(vault: &Path) -> bool {
    vault.join("identity.age").is_file() && vault.join("config.yaml").is_file()
}

fn joined_config(vault: &Path) -> Result<Vec<u8>, String> {
    let config = Config {
        vault_dir: vault.to_str().ok_or("vault path must be UTF-8")?.to_owned(),
        git: Some(GitConfig::default()),
        ..Config::default()
    };
    config
        .to_yaml_bytes()
        .map_err(|e| format!("serialize config: {e}"))
}

pub(crate) fn unlock_vault(vault: &Path) -> Result<Identity, String> {
    if !is_initialized(vault) {
        return Err("vault is not initialized (run 'symvault init' first)".to_owned());
    }
    let runtime = crate::runtime_session_manager();
    unlock_vault_with_runtime(vault, &runtime)
}

fn unlock_vault_with_runtime(
    vault: &Path,
    runtime: &crate::RuntimeSession,
) -> Result<Identity, String> {
    let vault_string = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    let config_path = vault.join("config.yaml");
    let config = Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
    let config_bytes = safeio::read(&config_path)
        .map_err(|e| format!("read config: {e}"))?
        .ok_or_else(|| "configuration is missing".to_owned())?;

    // A cached private identity is the fastest path and deliberately avoids
    // reading or decrypting the on-disk envelope. SessionManager renews the
    // idle timestamp when `refresh` is true, matching Go's vault reads.
    if let Ok(cached) = runtime
        .manager
        .load_identity(vault_string, true)
        .map(zeroize::Zeroizing::new)
        && let Ok(text) = std::str::from_utf8(&cached)
        && let Ok(identity) = parse_identity(text.trim())
    {
        return Ok(identity);
    }

    let id_path = vault.join("identity.age");
    let data = safeio::read(&id_path)
        .map_err(|e| format!("read identity: {e}"))?
        .ok_or_else(|| "vault is not initialized (run 'symvault init' first)".to_owned())?;

    // Prefer the encrypted session passphrase before invoking Touch ID or a
    // prompt. A bad/expired cache is recoverable and falls through to the
    // normal authentication path.
    if let Ok(cached) = runtime
        .manager
        .load_passphrase(vault_string)
        .map(zeroize::Zeroizing::new)
        && let Ok(identity) = decrypt_identity(&data, &SecretBytes::new(&cached))
    {
        save_unlocked_session(runtime, vault_string, &config, &cached, &identity)?;
        return Ok(identity);
    }

    let passphrase = crate::unlock_passphrase(&config_bytes, &config, vault, runtime)?;
    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let identity = decrypt_identity(&data, &sec_pass).map_err(|e| format!("unlock vault: {e}"))?;
    if !input::env_passphrase_selected(&config_bytes) {
        save_unlocked_session(
            runtime,
            vault_string,
            &config,
            passphrase.as_bytes(),
            &identity,
        )?;
    }
    Ok(identity)
}

fn save_unlocked_session(
    runtime: &crate::RuntimeSession,
    vault: &str,
    config: &Config,
    passphrase: &[u8],
    identity: &Identity,
) -> Result<(), String> {
    let ttl = if config.session_timeout.is_zero() {
        Duration::from_secs(15 * 60)
    } else {
        config.session_timeout
    };
    let max_lifetime = if config.session_max_lifetime.is_zero() {
        Duration::from_secs(8 * 60 * 60)
    } else {
        config.session_max_lifetime
    };
    runtime
        .manager
        .save_passphrase(vault, passphrase, ttl, max_lifetime)
        .map_err(|error| format!("save session: {error}"))?;
    let cached_identity = identity_string(identity);
    runtime
        .manager
        .save_identity(vault, cached_identity.as_bytes(), ttl, max_lifetime)
        .map_err(|error| format!("save identity session: {error}"))
}

fn get_all_recipients_for_encryption(
    vault: &Path,
    identity: &Identity,
) -> Result<Vec<Recipient>, String> {
    let own_pubkey = recipient_string(identity);
    let mut seen = HashSet::new();
    seen.insert(own_pubkey.clone());

    let mut result = Vec::new();
    let own_recip =
        parse_recipient(&own_pubkey).map_err(|e| format!("parse identity recipient: {e}"))?;
    result.push(own_recip);

    let rm = RecipientsFile::new(vault);
    let additional = rm
        .load_strings()
        .map_err(|e| format!("load recipients: {e}"))?
        .unwrap_or_default();

    for r_str in additional {
        if seen.insert(r_str.clone()) {
            let recip =
                parse_recipient(&r_str).map_err(|e| format!("parse recipient {r_str}: {e}"))?;
            result.push(recip);
        }
    }
    Ok(result)
}

fn reencrypt_all_entries(
    vault: &Path,
    identity: &Identity,
    recipients: &[Recipient],
) -> Result<(), String> {
    let entries_dir = vault.join("entries");
    match std::fs::symlink_metadata(&entries_dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "unsafe symlink entries root {:?}",
                    entries_dir.display()
                ));
            }
            if !file_type.is_dir() {
                return Err(format!(
                    "vault entries root is not a directory: {}",
                    entries_dir.display()
                ));
            }
            walk_and_reencrypt(&entries_dir, identity, recipients)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("stat {}: {err}", entries_dir.display())),
    }
    let manifest_path = vault.join("manifest.age");
    if manifest_path.is_file() {
        let store = symvault_store::Store::open(vault, identity)
            .map_err(|e| format!("open store for manifest rebuild: {e}"))?;
        store
            .rebuild_manifest(identity)
            .map_err(|e| format!("rebuild manifest: {e}"))?;
    }
    Ok(())
}

fn walk_and_reencrypt(
    dir: &Path,
    identity: &Identity,
    recipients: &[Recipient],
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!("unsafe symlink entry {:?}", path.display()));
        }
        if file_type.is_dir() {
            walk_and_reencrypt(&path, identity, recipients)?;
        } else if file_type.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("age")
        {
            let raw = safeio::read(&path)
                .map_err(|e| format!("read {}: {e}", path.display()))?
                .ok_or_else(|| format!("file not found: {}", path.display()))?;
            let reencrypted = reencrypt(&raw, identity, recipients)
                .map_err(|e| format!("re-encrypt {}: {e}", path.display()))?;
            safeio::write_atomic(&path, &reencrypted)
                .map_err(|e| format!("write {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

fn auto_commit_and_push(vault: &Path, message: &str) {
    if let Ok(repo) = GitRepository::open(vault) {
        if let Err(e) = repo.commit(CommitOptions {
            message: message.to_owned(),
            ..Default::default()
        }) {
            eprintln!("Warning: could not auto-commit/push: {e}");
        } else if Config::load(vault.join("config.yaml"))
            .ok()
            .and_then(|config| config.git)
            .is_some_and(|git| git.auto_push)
        {
            let result = repo.push("origin");
            if !result.success && !result.skipped {
                eprintln!("Warning: could not auto-push: {:?}", result.error);
            }
        }
    }
}

pub(super) fn pair(vault: &Path, quiet: bool) -> Result<(), String> {
    let identity = unlock_vault(vault)?;
    let token = generate_token().map_err(|e| format!("generate token: {e}"))?;
    let public_key = recipient_string(&identity);

    let pairing_data = PairingFile {
        token: token.clone(),
        public_key: public_key.clone(),
        created_at: GoTime::now(),
    };

    let pairing_dir = vault.join(".symvault").join("pairing");
    safeio::create_dir_all(&pairing_dir).map_err(|e| format!("create pairing dir: {e}"))?;
    let encoded =
        marshal_pairing_file(&pairing_data).map_err(|e| format!("save pairing file: {e}"))?;
    safeio::write_atomic(&pairing_dir.join(format!("{token}.json")), &encoded)
        .map_err(|e| format!("save pairing file: {e}"))?;

    auto_commit_and_push(vault, &format!("Pairing token {token}"));

    if !quiet {
        let fp = fingerprint(&public_key);
        let pairing_rel = Path::new(".symvault")
            .join("pairing")
            .join(format!("{token}.json"));
        print!("\n=== Pairing Token ===\n");
        println!("Token: {token}\n");
        println!("This device's public key: {public_key}");
        println!("Key fingerprint:          {fp} (SHA-256)");
        print!("\nOn the joining device, run:\n");
        println!("  symvault device join <remote-url> {token}\n");
        println!(
            "Without a git remote, share {} by any channel and run:",
            pairing_rel.display()
        );
        println!("  symvault device join --pairing-file <path-to-token.json> {token}\n");
        println!("After the joining device has submitted its key, run:");
        println!("  symvault device accept {token}\n");
    }
    Ok(())
}

pub(super) fn join(
    vault: &Path,
    args: &[String],
    name: Option<String>,
    pairing_file: Option<PathBuf>,
    quiet: bool,
) -> Result<(), String> {
    let (token, pairing_pf, is_file_transport) = if let Some(ref pf_path) = pairing_file {
        if args.len() != 1 {
            return Err("with --pairing-file, pass only the pairing token: 'device join --pairing-file <path> <token>'".to_owned());
        }
        let token = args[0].trim().to_owned();
        validate_pairing_token(&token).map_err(|e| format!("invalid pairing token: {e}"))?;
        let pf_data = std::fs::read(pf_path).map_err(|e| format!("read pairing file: {e}"))?;
        let pf = parse_pairing_file(&pf_data).map_err(|e| format!("{e}"))?;
        if !pf.token.is_empty() && pf.token != token {
            return Err(format!(
                "pairing file token {:?} does not match the given token {:?}",
                pf.token, token
            ));
        }
        if pf.public_key.is_empty() || !pf.public_key.starts_with("age1") {
            return Err("invalid pairing file: missing or malformed public_key".to_owned());
        }
        (token, pf, true)
    } else {
        if args.len() != 2 {
            return Err(format!(
                "accepts between 1 and 2 arg(s), received {} — either '<remote-url> <token>' or '--pairing-file <path> <token>'",
                args.len()
            ));
        }
        let remote_url = args[0].trim();
        let token = args[1].trim().to_owned();
        validate_pairing_token(&token).map_err(|e| format!("invalid pairing token: {e}"))?;

        if is_initialized(vault) {
            return Err(format!(
                "vault already initialized at {}. Use a different --vault or remove the existing vault first",
                vault.display()
            ));
        }

        eprintln!("Cloning vault from {remote_url} ...");
        safeio::create_dir_all(vault).map_err(|e| format!("create vault dir: {e}"))?;
        let status = std::process::Command::new("git")
            .env_remove("SYMVAULT_PASSPHRASE")
            .arg("clone")
            .arg("--")
            .arg(remote_url)
            .arg(vault)
            .status()
            .map_err(|e| format!("clone vault: {e}"))?;
        if !status.success() {
            return Err(format!("clone vault: git clone failed with {status}"));
        }

        let pairing_path = vault
            .join(".symvault")
            .join("pairing")
            .join(format!("{token}.json"));
        let pf_data = safeio::read(&pairing_path)
            .map_err(|e| format!("invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: {e}"))?
            .ok_or_else(|| "invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: file not found".to_owned())?;
        let pf = parse_pairing_file(&pf_data).map_err(|e| format!("invalid pairing file: {e}"))?;
        (token, pf, false)
    };

    if is_file_transport && is_initialized(vault) {
        return Err(format!(
            "vault already initialized at {}. Use a different --vault or remove the existing vault first",
            vault.display()
        ));
    }

    if is_file_transport {
        eprintln!(
            "Pairing without git transport using {}",
            pairing_file.as_ref().unwrap().display()
        );
    }
    eprintln!(
        "Pairing with device (public key: {})",
        truncate_pubkey(&pairing_pf.public_key)
    );

    let passphrase = read_passphrase("Enter passphrase for this device (minimum 12 characters): ")?;
    if passphrase.len() < 12 {
        return Err("passphrase must be at least 12 characters".to_owned());
    }

    let identity = generate_identity();
    let my_pubkey = recipient_string(&identity);

    safeio::create_dir_all(&vault.join("entries"))
        .map_err(|e| format!("create entries dir: {e}"))?;
    safeio::create_dir_all(&vault.join(".symvault").join("pairing"))
        .map_err(|e| format!("create pairing dir: {e}"))?;

    let config_content = joined_config(vault)?;
    safeio::write_atomic(&vault.join("config.yaml"), &config_content)
        .map_err(|e| format!("write config: {e}"))?;

    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let enc_id = encrypt_identity_scrypt(&identity, &sec_pass, 18)
        .map_err(|e| format!("save identity: {e}"))?;
    safeio::write_atomic(&vault.join("identity.age"), &enc_id)
        .map_err(|e| format!("save identity: {e}"))?;

    let recipients_content = format!(
        "# Symaira Vault vault recipients\n# Added by device join\n{}\n",
        pairing_pf.public_key
    );
    safeio::write_atomic(&vault.join("recipients.txt"), recipients_content.as_bytes())
        .map_err(|e| format!("write recipients: {e}"))?;

    let device_name = name.unwrap_or_else(|| format!("device-{token}"));
    let joined_data = JoinResponse {
        token: token.clone(),
        name: device_name.clone(),
        public_key: my_pubkey.clone(),
        created_at: GoTime::now(),
    };

    let response_filename = if is_file_transport {
        format!("{token}-response.json")
    } else {
        format!("{token}-joined.json")
    };

    let response_encoded =
        marshal_join_response(&joined_data).map_err(|e| format!("save joined file: {e}"))?;
    let response_path = vault
        .join(".symvault")
        .join("pairing")
        .join(&response_filename);
    safeio::write_atomic(&response_path, &response_encoded)
        .map_err(|e| format!("save joined file: {e}"))?;

    if is_file_transport {
        println!(
            "\nResponse artifact written to: {}\n",
            response_path.display()
        );
    }

    let cleanup_pairing = vault
        .join(".symvault")
        .join("pairing")
        .join(format!("{token}.json"));
    let _ = std::fs::remove_file(cleanup_pairing);

    if let Ok(repo) = GitRepository::open(vault) {
        let _ = repo.commit(CommitOptions {
            message: format!("Device join: {device_name} (token {token})"),
            ..Default::default()
        });
    }

    eprintln!("=== Join Successful ===");
    if !quiet {
        let fp = fingerprint(&my_pubkey);
        println!("\nDevice name:     {device_name}");
        println!("Key type:        age X25519");
        println!("Your public key: {my_pubkey}");
        println!("Key fingerprint: {fp} (SHA-256)\n");
        println!("IMPORTANT: Entries cannot be decrypted yet.");
        println!("On the existing device, run:");
        println!("  symvault device accept {token}\n");
    }

    if !is_file_transport && let Ok(repo) = GitRepository::open(vault) {
        let res = repo.push("origin");
        if !res.success && !res.skipped {
            eprintln!("Warning: Could not push joined file: {:?}", res.error);
            eprintln!("Push manually with: symvault git push");
        }
    }

    Ok(())
}

pub(super) fn accept(vault: &Path, token: &str, quiet: bool) -> Result<(), String> {
    validate_pairing_token(token).map_err(|e| format!("invalid pairing token: {e}"))?;
    let identity = unlock_vault(vault)?;

    let mut jf_data = None;
    let mut found_name = String::new();
    for name in response_filenames(token) {
        let candidate_path = vault.join(".symvault").join("pairing").join(&name);
        if let Ok(Some(data)) = safeio::read(&candidate_path) {
            jf_data = Some(data);
            found_name = name;
            break;
        }
    }

    let jf_data = jf_data.ok_or_else(|| {
        format!(
            "no join request found for token {token}. Ensure the joining device has completed 'symvault device join' and the response artifact ({token}-joined.json or {token}-response.json) is present in the vault"
        )
    })?;

    let jf = parse_join_response(&jf_data)
        .map_err(|e| format!("parse joined file {found_name}: {e}"))?;

    let fp = fingerprint(&jf.public_key);
    if !quiet {
        print!("\n=== Joining Device Request ===\n");
        println!("Device name:     {}", jf.name);
        println!("Key type:        age X25519");
        println!("Public key:      {}", jf.public_key);
        println!("Key fingerprint: {fp} (SHA-256)\n");
    }

    eprintln!(
        "Accepting join from device: {} (public key: {})",
        jf.name,
        truncate_pubkey(&jf.public_key)
    );

    let rm = RecipientsFile::new(vault);
    rm.add(&jf.public_key)
        .map_err(|e| format!("add recipient: {e}"))?;

    let all_recipients = get_all_recipients_for_encryption(vault, &identity)?;
    eprintln!(
        "Re-encrypting all entries for {} recipient(s)...",
        all_recipients.len()
    );

    reencrypt_all_entries(vault, &identity, &all_recipients)?;

    let _ = std::fs::remove_file(vault.join(".symvault").join("pairing").join(&found_name));

    auto_commit_and_push(vault, &format!("Accept device join: {}", jf.name));

    if !quiet {
        print!("\n=== Pairing Complete ===\n");
        println!("Device {:?} can now access all vault entries.\n", jf.name);
        println!(
            "On the joining device, run 'symvault git pull' to fetch the re-encrypted entries."
        );
    }

    Ok(())
}

pub(super) fn add(
    vault: &Path,
    pair: bool,
    args: &[String],
    name: Option<String>,
) -> Result<(), String> {
    if !pair {
        return Err(
            "use 'symvault device add --pair <token:publickey>' to pair a device".to_owned(),
        );
    }
    if args.is_empty() {
        return Err(
            "missing pairing data. Usage: symvault device add --pair <token> or <token:publickey>"
                .to_owned(),
        );
    }

    let raw = args[0].trim();
    let (token, existing_pubkey) = if let Some(idx) = raw.find(':') {
        (&raw[..idx], &raw[idx + 1..])
    } else {
        (raw, "")
    };

    validate_pairing_token(token).map_err(|e| format!("invalid pairing token: {e}"))?;
    if !existing_pubkey.starts_with("age1") || existing_pubkey.len() < 50 {
        return Err("invalid public key in pairing data: expected age1... format".to_owned());
    }

    if is_initialized(vault) {
        return Err(format!(
            "vault already initialized at {}. Use a different --vault or remove the existing vault first",
            vault.display()
        ));
    }

    let passphrase = read_passphrase("Enter passphrase for this device (minimum 12 characters): ")?;
    if passphrase.len() < 12 {
        return Err("passphrase must be at least 12 characters".to_owned());
    }

    let identity = generate_identity();
    let my_pubkey = recipient_string(&identity);

    safeio::create_dir_all(&vault.join("entries"))
        .map_err(|e| format!("create entries dir: {e}"))?;
    safeio::create_dir_all(&vault.join(".symvault").join("pairing"))
        .map_err(|e| format!("create pairing dir: {e}"))?;

    let config_content = joined_config(vault)?;
    safeio::write_atomic(&vault.join("config.yaml"), &config_content)
        .map_err(|e| format!("write config: {e}"))?;

    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let enc_id = encrypt_identity_scrypt(&identity, &sec_pass, 18)
        .map_err(|e| format!("save identity: {e}"))?;
    safeio::write_atomic(&vault.join("identity.age"), &enc_id)
        .map_err(|e| format!("save identity: {e}"))?;

    let recipients_content = format!(
        "# Symaira Vault vault recipients\n# Added by device add --pair\n{}\n",
        existing_pubkey
    );
    safeio::write_atomic(&vault.join("recipients.txt"), recipients_content.as_bytes())
        .map_err(|e| format!("write recipients: {e}"))?;

    let device_name = name.unwrap_or_else(|| format!("device-{token}"));
    let joined_data = JoinResponse {
        token: token.to_owned(),
        name: device_name.clone(),
        public_key: my_pubkey.clone(),
        created_at: GoTime::now(),
    };

    let response_encoded =
        marshal_join_response(&joined_data).map_err(|e| format!("save joined file: {e}"))?;
    safeio::write_atomic(
        &vault
            .join(".symvault")
            .join("pairing")
            .join(format!("{token}-joined.json")),
        &response_encoded,
    )
    .map_err(|e| format!("save joined file: {e}"))?;

    let fp = fingerprint(&my_pubkey);
    eprintln!("=== Pairing Setup Complete ===");
    eprintln!("Device name:     {device_name}");
    eprintln!("Key type:        age X25519");
    eprintln!("Your public key: {my_pubkey}");
    eprintln!("Key fingerprint: {fp} (SHA-256)\n");
    eprintln!("IMPORTANT: Entries cannot be decrypted yet.");
    eprintln!("On the original device, run:");
    eprintln!("  symvault device accept {token}\n");
    eprintln!("After accepting, pull the re-encrypted entries:");
    eprintln!("  symvault git pull");

    Ok(())
}

pub(super) fn revoke(vault: &Path, name: &str, yes: bool, quiet: bool) -> Result<(), String> {
    if !is_initialized(vault) {
        return Err("vault is not initialized (run 'symvault init' first)".to_owned());
    }
    let identity = unlock_vault(vault)?;

    let dm = DeviceRegistry::new(vault);
    let device = dm
        .get(name)
        .map_err(|e| format!("cannot look up device: {e}"))?
        .ok_or_else(|| format!("device {name:?} not found in device registry"))?;

    let current_pubkey = recipient_string(&identity);
    if device.public_key == current_pubkey {
        return Err(format!(
            "cannot revoke the current device {name:?} (this device's identity would be lost)"
        ));
    }

    if !yes {
        eprint!("This will revoke device {name:?} and re-encrypt all entries.\nContinue? [y/N]: ");
        let mut answer = String::new();
        let stdin = io::stdin();
        stdin
            .lock()
            .read_line(&mut answer)
            .map_err(|e| format!("read confirmation: {e}"))?;
        if answer.trim().to_lowercase() != "y" {
            eprintln!("Canceled");
            return Ok(());
        }
    }

    dm.remove(name)
        .map_err(|e| format!("remove device from registry: {e}"))?;

    let rm = RecipientsFile::new(vault);
    let _ = rm.remove(&device.public_key);

    let all_recipients = get_all_recipients_for_encryption(vault, &identity)?;
    eprintln!(
        "Re-encrypting all entries for {} recipient(s)...",
        all_recipients.len()
    );

    reencrypt_all_entries(vault, &identity, &all_recipients)?;

    auto_commit_and_push(vault, &format!("Revoke device: {name}"));

    if !quiet {
        print!("\nDevice {name:?} has been revoked and all entries re-encrypted.\n");
    }

    Ok(())
}

pub(super) fn list(vault: &Path, format: &str, json: bool, quiet: bool) -> Result<(), String> {
    let devices = DeviceRegistry::new(vault)
        .list()
        .map_err(|e| format!("list devices: {e}"))?;
    let keys: HashSet<&str> = devices
        .devices()
        .iter()
        .map(|d| d.public_key.as_str())
        .collect();
    // Go intentionally suppresses recipients-file errors for this read-only view.
    let unmanaged: Vec<String> = RecipientsFile::new(vault)
        .load_strings()
        .unwrap_or_default()
        .unwrap_or_default()
        .into_iter()
        .filter(|key| !keys.contains(key.as_str()))
        .collect();
    if format == "yaml" && !json {
        return Err("device list YAML output is not yet ported".to_owned());
    }
    if quiet {
        return Ok(());
    }
    let mut out = Vec::new();
    if json || format == "json" {
        let listing = Listing {
            count: devices.devices().len(),
            devices: devices
                .devices()
                .iter()
                .map(|d| ListedDevice {
                    name: &d.name,
                    public_key: &d.public_key,
                    added_at: seconds(d.added_at),
                    last_seen: d.last_seen.map(seconds),
                })
                .collect(),
            unmanaged_recipients: unmanaged,
        };
        // Go's encoder disables HTML escaping but always escapes these separators.
        let encoded = serde_json::to_string(&listing)
            .map_err(|e| e.to_string())?
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        out.extend_from_slice(encoded.as_bytes());
        out.push(b'\n');
    } else {
        if devices.devices().is_empty() {
            out.extend_from_slice(b"No devices registered.\n");
            if !unmanaged.is_empty() {
                out.push(b'\n');
            }
        } else {
            write!(out, "Devices ({}):\n\n", devices.devices().len()).map_err(|e| e.to_string())?;
            for d in devices.devices() {
                write!(out, "  {}\n    Public Key: ", d.name).map_err(|e| e.to_string())?;
                out.extend_from_slice(&short_key(&d.public_key));
                write!(
                    out,
                    "\n    Added:      {}\n    Last Seen:  {}\n\n",
                    seconds(d.added_at),
                    d.last_seen
                        .map(seconds)
                        .unwrap_or_else(|| "never".to_owned())
                )
                .map_err(|e| e.to_string())?;
            }
        }
        if !unmanaged.is_empty() {
            out.extend_from_slice(b"Unmanaged recipients in recipients.txt:\n");
            for key in unmanaged {
                out.extend_from_slice(b"  ");
                out.extend_from_slice(&short_key(&key));
                out.push(b'\n');
            }
            if !devices.devices().is_empty() {
                out.push(b'\n');
            }
        }
    }
    std::io::stdout()
        .lock()
        .write_all(&out)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Arc};
    use symvault_core::session::{MemoryKeyring, SessionManager};
    use symvault_platform::FallbackKeyring;

    fn fixture_runtime() -> crate::RuntimeSession {
        let keyring = FallbackKeyring::new(Arc::new(MemoryKeyring::new()), true);
        crate::RuntimeSession {
            manager: SessionManager::with_system_clock(keyring.clone()),
            keyring: Some(keyring),
            memory_only: false,
        }
    }

    fn encrypted_fixture() -> (PathBuf, Identity, String) {
        let root = std::env::temp_dir().join(format!(
            "symvault-device-unlock-{}-{}",
            std::process::id(),
            GoTime::now().to_rfc3339_nano().replace([':', '.', '-'], "")
        ));
        fs::create_dir_all(&root).expect("create fixture vault");
        let identity = generate_identity();
        let passphrase = "fixture-device-passphrase".to_owned();
        let config = Config {
            vault_dir: root.to_string_lossy().into_owned(),
            ..Config::default()
        };
        fs::write(root.join("config.yaml"), config.to_yaml_bytes().unwrap()).unwrap();
        let encrypted =
            encrypt_identity_scrypt(&identity, &SecretBytes::new(passphrase.as_bytes()), 10)
                .unwrap();
        fs::write(root.join("identity.age"), encrypted).unwrap();
        (root, identity, passphrase)
    }

    #[test]
    fn cached_identity_and_passphrase_open_the_same_encrypted_fixture() {
        let (root, expected, passphrase) = encrypted_fixture();
        let vault = root.to_str().unwrap().to_owned();

        let identity_runtime = fixture_runtime();
        let identity_bytes = identity_string(&expected);
        identity_runtime
            .manager
            .save_identity(
                &vault,
                identity_bytes.as_bytes(),
                Duration::from_secs(60),
                Duration::from_secs(600),
            )
            .unwrap();
        let cached = unlock_vault_with_runtime(&root, &identity_runtime).unwrap();
        assert_eq!(recipient_string(&cached), recipient_string(&expected));

        let passphrase_runtime = fixture_runtime();
        passphrase_runtime
            .manager
            .save_passphrase(
                &vault,
                passphrase.as_bytes(),
                Duration::from_secs(60),
                Duration::from_secs(600),
            )
            .unwrap();
        let cached_passphrase = unlock_vault_with_runtime(&root, &passphrase_runtime).unwrap();
        assert_eq!(
            recipient_string(&cached_passphrase),
            recipient_string(&expected)
        );
        assert!(!passphrase_runtime.manager.is_identity_expired(&vault));
        let _ = fs::remove_dir_all(root);
    }
}
