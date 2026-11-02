//! Fault-injection probe for `scripts/rust-port/data_safety_contract.py`.
//!
//! Installs a deliberately broken pre-mutation guard and runs the real store
//! gate against `<vault>`. Production binaries never contain this code; it only
//! exists so the contract harness can prove its negative controls.
//!
//!   data_safety_probe <vault> <backup-dir> <mode>
//!
//! Modes: `corrupt` damages the archive and keeps the real verification (the
//! gate must refuse and write no marker); `short-circuit` damages the archive
//! and skips the restore verification (the gate wrongly accepts, so the
//! harness's own independent restore comparison has to fail).

use std::{fs, path::Path, process::ExitCode};

use symvault_store::data_safety::{BackupReceipt, PreMutationGuard, ensure_marker, install_guard};
use symvault_sync::data_safety::{verify_backup, write_backup};

struct Broken {
    dir: std::path::PathBuf,
    skip_verification: bool,
}

fn damage(archive: &Path) {
    let mut bytes = fs::read(archive).expect("read archive");
    // Flip bytes in the middle of the deflate stream and drop the trailer.
    let middle = bytes.len() / 2;
    let end = middle + 16.min(bytes.len() - middle);
    for byte in &mut bytes[middle..end] {
        *byte ^= 0xff;
    }
    fs::write(archive, bytes).expect("write damaged archive");
}

impl PreMutationGuard for Broken {
    fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String> {
        let archive = write_backup(vault, &self.dir)?;
        damage(&archive);
        if !self.skip_verification {
            verify_backup(vault, &archive, &self.dir).inspect_err(|_| {
                let _ = fs::remove_file(&archive);
            })?;
        }
        // Reaching here means verification was skipped or did not notice.
        Ok(BackupReceipt {
            path: archive,
            sha256: String::new(),
            bytes: 0,
            files: 0,
        })
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let [_, vault, dir, mode] = arguments.as_slice() else {
        eprintln!("usage: data_safety_probe <vault> <backup-dir> <corrupt|short-circuit>");
        return ExitCode::from(2);
    };
    let skip_verification = match mode.as_str() {
        "corrupt" => false,
        "short-circuit" => true,
        other => {
            eprintln!("unknown mode {other}");
            return ExitCode::from(2);
        }
    };
    install_guard(Box::new(Broken {
        dir: dir.into(),
        skip_verification,
    }));
    match ensure_marker(Path::new(vault)) {
        Ok(()) => {
            println!("gate accepted");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("gate refused: {error}");
            ExitCode::from(1)
        }
    }
}
