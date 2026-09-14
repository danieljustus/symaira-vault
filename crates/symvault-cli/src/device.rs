//! Read-only PAIRING-001 CLI slice. Mutating commands remain unexposed until
//! unlock, encrypted identity setup, re-encryption and git orchestration exist.
use serde::Serialize;
use std::{collections::HashSet, io::Write, path::Path};
use symvault_sync::{DeviceRegistry, GoTime, RecipientsFile};

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
