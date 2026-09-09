use std::{env, fs};

use symvault_store::audit::{AuditKey, LogEntry, Logger, RotationConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args().nth(1).ok_or("usage: audit-emit <output>")?;
    let key = AuditKey::new(b"audit-fixture-old-key-0000000000")?;
    let mut logger = Logger::open(
        &output,
        key,
        RotationConfig {
            max_file_size: u64::MAX,
            max_backups: 5,
            max_age: None,
        },
    )?;
    logger.append(LogEntry {
        timestamp: "2026-01-01T00:00:00Z".into(),
        agent: "rust-emitter".into(),
        action: "get".into(),
        path: "safe/fixture".into(),
        ok: true,
        ..Default::default()
    })?;
    logger.append(LogEntry {
        timestamp: "2026-01-01T00:00:01Z".into(),
        agent: "rust-emitter".into(),
        action: "set".into(),
        path: "safe/fixture".into(),
        field: "password".into(),
        ok: false,
        reason: "write_denied".into(),
        ..Default::default()
    })?;
    // Readback keeps this example's stdout empty; callers inspect the file.
    let _ = fs::metadata(output)?;
    Ok(())
}
