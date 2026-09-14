//! Device registry backing `device add`, `device list` and `device revoke`
//! (`PAIRING-001`).
//!
//! The Go oracle is `internal/vault.DeviceManager` at the frozen baseline
//! commit, persisting `<vault-dir>/.symvault/devices.json`. This is the half of
//! the pairing seam that touches the filesystem: the artifact codec in
//! [`crate::pairing`] is pure, this module is not.
//!
//! Three things are contract, not implementation detail, and all three are
//! frozen in `testdata/port/pairing/contract.json`:
//!
//! - the exact `devices.json` bytes, including Go's HTML escaping of a device
//!   name and the `last_seen` field disappearing when it is unset;
//! - the ordering rules — a new device appends, a device re-added under an
//!   existing name is replaced *in place* rather than moved to the end, and a
//!   removal keeps the surviving order;
//! - what fails: removing an unknown name, removing from a registry that does
//!   not exist yet, and every operation once the file is unparsable.
//!
//! Writes are symlink-hardened and atomic, matching `vault.SafeWriteFile`: the
//! target is refused if it is a symlink or any non-regular file, and the
//! replacement is staged, fsynced and renamed, so an interrupted write cannot
//! leave a half-written registry behind.

use crate::pairing::{GoTime, encode_go_string};
use crate::safeio::{self, SafeIoError};
use serde_json::Value;
use std::path::PathBuf;

/// Directory inside the vault that holds vault-private state, matching Go's
/// `config.DefaultVaultSubdir`.
pub const VAULT_SUBDIR: &str = ".symvault";

/// Registry filename inside [`VAULT_SUBDIR`].
pub const DEVICES_FILE: &str = "devices.json";

/// Mode the registry directory is created with, matching Go's `0o700`.
pub const DIR_MODE: u32 = safeio::DIR_MODE;

/// Mode the registry file is created with, matching Go's `0o600`.
pub const FILE_MODE: u32 = safeio::FILE_MODE;

/// Failures the registry can report.
#[derive(Debug)]
pub enum DeviceError {
    /// The registry file could not be read or written, or is a symlink or
    /// other non-regular file that was refused rather than followed.
    Io(SafeIoError),
    /// The registry file is not a JSON array of devices.
    Malformed(String),
    /// A device timestamp was not a strict RFC3339 value.
    Time(String),
    /// `remove` was asked for a name the registry does not hold.
    NotFound(String),
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "device registry: {source}"),
            Self::Malformed(detail) => write!(f, "parse devices file: {detail}"),
            Self::Time(detail) => write!(f, "parse devices file: {detail}"),
            Self::NotFound(name) => write!(f, "device {name:?} not found"),
        }
    }
}

impl From<SafeIoError> for DeviceError {
    fn from(source: SafeIoError) -> Self {
        Self::Io(source)
    }
}

impl std::error::Error for DeviceError {}

/// A device in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Human-readable device name; the registry key.
    pub name: String,
    /// The device's age public key.
    pub public_key: String,
    /// When the device was registered.
    pub added_at: GoTime,
    /// Last time the device was seen, omitted from the file when unset.
    pub last_seen: Option<GoTime>,
}

/// What a registry read found.
///
/// Go distinguishes a nil slice from an empty one here, and the distinction is
/// observable: a registry file containing `null` unmarshals to nil and marshals
/// back as `null`, while a missing file yields an empty, non-nil slice that
/// marshals as `[]`. [`DeviceList::Null`] is that nil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceList {
    /// The file held JSON `null`; Go's nil slice.
    Null,
    /// The file held an array, or did not exist at all.
    Devices(Vec<Device>),
}

impl DeviceList {
    /// The devices found, treating `null` as none — which is how Go's `append`,
    /// lookup and removal all treat a nil slice.
    pub fn devices(&self) -> &[Device] {
        match self {
            Self::Null => &[],
            Self::Devices(devices) => devices,
        }
    }

    /// Serializes exactly as Go's `json.Marshal` would render the value this
    /// came from: `null` stays `null`, an array stays a compact array.
    pub fn to_compact_json(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Devices(devices) => {
                let mut out = String::from("[");
                for (index, device) in devices.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    append_device(&mut out, device, None);
                }
                out.push(']');
                out
            }
        }
    }
}

/// The device registry for one vault directory.
#[derive(Debug, Clone)]
pub struct DeviceRegistry {
    vault_dir: PathBuf,
}

impl DeviceRegistry {
    /// Binds a registry to `vault_dir`. Nothing is touched on disk until a read
    /// or a write happens, matching `vault.NewDeviceManager`.
    pub fn new(vault_dir: impl Into<PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
        }
    }

    /// Path of the registry file: `<vault-dir>/.symvault/devices.json`.
    pub fn path(&self) -> PathBuf {
        self.vault_dir.join(VAULT_SUBDIR).join(DEVICES_FILE)
    }

    /// Reads the registry. A missing file is an empty registry, not an error.
    pub fn load(&self) -> Result<DeviceList, DeviceError> {
        let path = self.path();
        let Some(data) = safeio::read(&path)? else {
            return Ok(DeviceList::Devices(Vec::new()));
        };
        parse_devices(&data)
    }

    /// Reads the registry; the name `list` mirrors Go's `ListDevices`, which is
    /// a straight delegation to the loader.
    pub fn list(&self) -> Result<DeviceList, DeviceError> {
        self.load()
    }

    /// Replaces the registry file with `devices`.
    pub fn save(&self, devices: &[Device]) -> Result<(), DeviceError> {
        let path = self.path();
        let parent = path.parent().expect("registry path always has a parent");
        safeio::create_dir_all(parent)?;
        Ok(safeio::write_atomic(
            &path,
            marshal_devices(devices).as_bytes(),
        )?)
    }

    /// Adds `device`, replacing an existing entry with the same name in place.
    pub fn add(&self, device: Device) -> Result<(), DeviceError> {
        let mut devices = self.load()?.devices().to_vec();
        if let Some(existing) = devices.iter_mut().find(|held| held.name == device.name) {
            *existing = device;
        } else {
            devices.push(device);
        }
        self.save(&devices)
    }

    /// Removes the device named `name`, reporting [`DeviceError::NotFound`] if
    /// the registry does not hold it. Name matching is case-sensitive.
    pub fn remove(&self, name: &str) -> Result<(), DeviceError> {
        let devices = self.load()?;
        let remaining: Vec<Device> = devices
            .devices()
            .iter()
            .filter(|device| device.name != name)
            .cloned()
            .collect();
        if remaining.len() == devices.devices().len() {
            return Err(DeviceError::NotFound(name.to_owned()));
        }
        self.save(&remaining)
    }

    /// Looks up a device by name. A missing registry is not an error; it simply
    /// holds nothing.
    pub fn get(&self, name: &str) -> Result<Option<Device>, DeviceError> {
        Ok(self
            .load()?
            .devices()
            .iter()
            .find(|device| device.name == name)
            .cloned())
    }
}

/// Renders the registry file exactly as `json.MarshalIndent(devices, "", "  ")`
/// does: two-space indent, Go's HTML escaping, `last_seen` omitted when unset,
/// and a bare `[]` for an empty registry.
fn marshal_devices(devices: &[Device]) -> String {
    if devices.is_empty() {
        return "[]".to_owned();
    }
    let mut out = String::from("[\n");
    for (index, device) in devices.iter().enumerate() {
        append_device(&mut out, device, Some(2));
        if index + 1 < devices.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    out
}

/// Appends one device object. `indent` is the object's own indentation in
/// spaces for the pretty form, or `None` for the compact form Go's
/// `json.Marshal` produces.
fn append_device(out: &mut String, device: &Device, indent: Option<usize>) {
    let mut fields: Vec<(&str, String)> = vec![
        ("name", device.name.clone()),
        ("public_key", device.public_key.clone()),
        ("added_at", device.added_at.to_rfc3339_nano()),
    ];
    if let Some(last_seen) = device.last_seen {
        fields.push(("last_seen", last_seen.to_rfc3339_nano()));
    }
    match indent {
        None => {
            out.push('{');
            for (index, (name, value)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                encode_go_string(name, out);
                out.push(':');
                encode_go_string(value, out);
            }
            out.push('}');
        }
        Some(width) => {
            let outer = " ".repeat(width);
            let inner = " ".repeat(width + 2);
            out.push_str(&outer);
            out.push_str("{\n");
            for (index, (name, value)) in fields.iter().enumerate() {
                out.push_str(&inner);
                encode_go_string(name, out);
                out.push_str(": ");
                encode_go_string(value, out);
                if index + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&outer);
            out.push('}');
        }
    }
}

fn parse_devices(data: &[u8]) -> Result<DeviceList, DeviceError> {
    let value: Value =
        serde_json::from_slice(data).map_err(|error| DeviceError::Malformed(error.to_string()))?;
    match value {
        Value::Null => Ok(DeviceList::Null),
        Value::Array(items) => {
            let mut devices = Vec::with_capacity(items.len());
            for item in &items {
                devices.push(parse_device(item)?);
            }
            Ok(DeviceList::Devices(devices))
        }
        other => Err(DeviceError::Malformed(format!(
            "cannot unmarshal {} into a device array",
            match other {
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Object(_) => "object",
                _ => "value",
            }
        ))),
    }
}

fn parse_device(value: &Value) -> Result<Device, DeviceError> {
    let Value::Object(object) = value else {
        return Err(DeviceError::Malformed(
            "cannot unmarshal a non-object into a device".to_owned(),
        ));
    };
    let string = |key: &str| -> Result<String, DeviceError> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(text)) => Ok(text.clone()),
            Some(_) => Err(DeviceError::Malformed(format!(
                "cannot unmarshal a non-string into Device.{key}"
            ))),
        }
    };
    let time = |key: &str| -> Result<Option<GoTime>, DeviceError> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => GoTime::parse_rfc3339(text)
                .map(Some)
                .map_err(|error| DeviceError::Time(error.to_string())),
            Some(_) => Err(DeviceError::Malformed(format!(
                "cannot unmarshal a non-string into Device.{key}"
            ))),
        }
    };
    Ok(Device {
        name: string("name")?,
        public_key: string("public_key")?,
        added_at: time("added_at")?.unwrap_or(GoTime::ZERO),
        last_seen: time("last_seen")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;

    fn device(name: &str) -> Device {
        Device {
            name: name.to_owned(),
            public_key: "age1fixture".to_owned(),
            added_at: GoTime::parse_rfc3339("2026-09-14T18:45:00Z").unwrap(),
            last_seen: None,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("symvault-devices-{tag}-{}", std::process::id()));
        let _ = stdfs::remove_dir_all(&dir);
        dir
    }

    /// A symlinked registry must be refused, not followed: otherwise anyone who
    /// can plant a link in the vault directory redirects both the read and the
    /// 0600 write to a file of their choosing.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_registry_is_refused_for_both_read_and_write() {
        let dir = scratch("symlink");
        let registry = DeviceRegistry::new(&dir);
        let target = dir.join("elsewhere.json");
        stdfs::create_dir_all(dir.join(VAULT_SUBDIR)).unwrap();
        stdfs::write(&target, b"[]").unwrap();
        std::os::unix::fs::symlink(&target, registry.path()).unwrap();

        assert!(matches!(
            registry.load(),
            Err(DeviceError::Io(SafeIoError::NotRegularFile))
        ));
        assert!(matches!(
            registry.save(&[device("laptop")]),
            Err(DeviceError::Io(SafeIoError::NotRegularFile))
        ));
        assert_eq!(
            stdfs::read(&target).unwrap(),
            b"[]",
            "the link target was written through"
        );
        let _ = stdfs::remove_dir_all(dir);
    }

    /// The write is staged and renamed, so no partially written registry is
    /// ever visible and no staging file is left behind on success.
    #[test]
    fn a_successful_write_leaves_no_staging_file() {
        let dir = scratch("staging");
        let registry = DeviceRegistry::new(&dir);
        registry.save(&[device("laptop")]).unwrap();
        let entries: Vec<String> = stdfs::read_dir(dir.join(VAULT_SUBDIR))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![DEVICES_FILE.to_owned()]);
        let _ = stdfs::remove_dir_all(dir);
    }

    #[test]
    fn a_registry_round_trips_through_its_own_file() {
        let dir = scratch("roundtrip");
        let registry = DeviceRegistry::new(&dir);
        let mut seen = device("seen");
        seen.last_seen = Some(GoTime::parse_rfc3339("2026-09-14T20:00:00.25Z").unwrap());
        registry.save(&[seen.clone(), device("unseen")]).unwrap();
        assert_eq!(
            registry.load().unwrap(),
            DeviceList::Devices(vec![seen, device("unseen")])
        );
        let _ = stdfs::remove_dir_all(dir);
    }
}
