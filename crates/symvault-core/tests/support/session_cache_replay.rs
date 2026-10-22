//! Replay engine for the Go-derived SESSION-001 cache lifecycle fixture.
//!
//! Shared by `symvault-core` (in-memory scenarios, concurrency) and
//! `symvault-platform` (fallback keyring scenarios) so one implementation
//! interprets `testdata/port/session/contract.json`.
#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use symvault_core::session::{Clock, Keyring, MemoryKeyring, SessionError, SessionManager};

pub const VAULT: &str = "fixture-vault";
const NOW_SECONDS: u64 = 1_900_000_000;
const ACCOUNTS: [&str; 3] = ["session", "identity", "wrap-key"];

#[derive(Debug, Deserialize)]
pub struct Contract {
    pub schema_version: u8,
    pub scenarios: Vec<Scenario>,
    pub concurrency: Vec<Concurrency>,
    pub storage: Storage,
}

#[derive(Debug, Deserialize)]
pub struct Storage {
    pub backend: String,
    pub filesystem_imports: Vec<String>,
    pub on_disk_files: u64,
}

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub backend: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
pub struct Step {
    pub op: String,
    #[serde(default)]
    pub secret: String,
    pub ttl_ns: Option<u64>,
    pub max_lifetime_ns: Option<u64>,
    #[serde(default)]
    pub account: String,
    pub saved_ago_ns: Option<i64>,
    pub last_access_ago_ns: Option<i64>,
    #[serde(default)]
    pub set: Map<String, Value>,
    #[serde(default)]
    pub remove: Vec<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub fault_get: bool,
    #[serde(default)]
    pub fault_set: bool,
    #[serde(default)]
    pub fault_delete: bool,
    #[serde(default)]
    pub fault_accounts: Vec<String>,
    pub expect: Expect,
}

#[derive(Debug, Deserialize)]
pub struct Expect {
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub value: String,
    pub flag: Option<bool>,
    #[serde(default)]
    pub present: Vec<String>,
    #[serde(default)]
    pub changed: Vec<String>,
    pub fallback_active: Option<bool>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Shape {
    pub session_fields: Vec<String>,
    pub identity_fields: Vec<String>,
    pub wrap_key_encoding: String,
    pub nonce_bytes: usize,
    pub timestamps_utc_z: bool,
    pub ttl_ns: i64,
    pub max_lifetime_ns: i64,
    pub identity_inherits_session_saved_at: bool,
    pub ciphertext_adds_16_byte_tag: bool,
}

#[derive(Debug, Deserialize)]
pub struct Concurrency {
    pub name: String,
    pub workers: usize,
    pub iterations: usize,
    pub workload: Vec<String>,
    pub permitted_results: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub probe_expected: BTreeMap<String, bool>,
    #[serde(default)]
    pub revokers: usize,
    pub final_present: Vec<String>,
    pub final_load_results: Vec<String>,
    #[serde(default)]
    pub after_sequential_save: String,
}

pub fn contract() -> Contract {
    const CONTENT: &[u8] = include_bytes!("../../../../testdata/port/session/contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated session contract")
}

/// A fixed clock: Go observes wall time, so the fixture only stores ages and the
/// replay resolves them against this instant.
pub struct TestClock;
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECONDS)
    }
}

#[derive(Default)]
struct Fault {
    get: bool,
    set: bool,
    delete: bool,
    accounts: Vec<String>,
}

impl Fault {
    fn hits(&self, key: &str) -> bool {
        self.accounts.is_empty()
            || self
                .accounts
                .iter()
                .any(|account| key.ends_with(&format!("|{account}")))
    }
}

/// Transport double: an in-memory keyring with fault injection and raw access
/// that bypasses faults. All session decisions stay in `SessionManager`.
#[derive(Default)]
pub struct FaultyKeyring {
    inner: MemoryKeyring,
    fault: Mutex<Fault>,
}

fn fault_error() -> SessionError {
    SessionError::Keyring("fixture keyring fault".into())
}

impl FaultyKeyring {
    fn key(account: &str) -> String {
        format!("symvault:{VAULT}|{account}")
    }
    pub fn raw(&self, account: &str) -> Option<Vec<u8>> {
        self.inner.get(&Self::key(account)).ok()
    }
    fn put_raw(&self, account: &str, value: &[u8]) {
        self.inner.set(&Self::key(account), value).unwrap();
    }
    fn drop_raw(&self, account: &str) {
        self.inner.delete(&Self::key(account)).unwrap();
    }
    fn set_fault(&self, fault: Fault) {
        *self.fault.lock().unwrap() = fault;
    }
    fn faulted(&self, key: &str, pick: impl Fn(&Fault) -> bool) -> bool {
        let fault = self.fault.lock().unwrap();
        pick(&fault) && fault.hits(key)
    }
}

impl Keyring for FaultyKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        if self.faulted(key, |f| f.get) {
            return Err(fault_error());
        }
        self.inner.get(key)
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        if self.faulted(key, |f| f.set) {
            return Err(fault_error());
        }
        self.inner.set(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), SessionError> {
        if self.faulted(key, |f| f.delete) {
            return Err(fault_error());
        }
        self.inner.delete(key)
    }
}

/// Maps a Rust error to the class vocabulary the Go generator records.
pub fn classify(error: &SessionError) -> &'static str {
    match error {
        SessionError::Keyring(_) => "keyring_unavailable",
        SessionError::NotFound => "not_found",
        SessionError::Expired("TTL is zero or negative") => "expired_zero_ttl",
        SessionError::Expired("no passphrase data available") => "expired_no_data",
        SessionError::Expired(_) => "expired",
        SessionError::Malformed(_) => "malformed",
        SessionError::LegacyPlaintext => "legacy_plaintext",
        SessionError::Crypto(_) => "decrypt_failed",
        SessionError::WrapKeyMissing => "wrap_key_missing",
        SessionError::WrapKeyInvalid(_) => "wrap_key_invalid",
    }
}

fn class_of<T>(result: &Result<T, SessionError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(error) => classify(error),
    }
}

/// Everything a scenario run is built from. `fallback_active` is `Some` only for
/// the fallback backend.
pub struct Harness {
    pub primary: Arc<FaultyKeyring>,
    pub manager: SessionManager,
    pub fallback_active: Option<Box<dyn Fn() -> bool>>,
}

pub fn memory_harness() -> Harness {
    let primary = Arc::new(FaultyKeyring::default());
    Harness {
        manager: SessionManager::new(primary.clone(), Arc::new(TestClock)),
        primary,
        fallback_active: None,
    }
}

fn rfc3339(nanos: i128) -> String {
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = nanos.rem_euclid(1_000_000_000);
    let days = seconds.div_euclid(86_400) as i64;
    let rem = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    let mut suffix = String::new();
    if fraction != 0 {
        suffix = format!("{fraction:09}");
        while suffix.ends_with('0') {
            suffix.pop();
        }
        suffix.insert(0, '.');
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{suffix}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

fn stamp(ago_ns: i64) -> Value {
    let now = i128::from(NOW_SECONDS) * 1_000_000_000;
    Value::String(rfc3339(now - i128::from(ago_ns)))
}

fn json_of(raw: &[u8]) -> Option<Value> {
    serde_json::from_slice(raw).ok()
}

type Snapshot = BTreeMap<&'static str, Vec<u8>>;

fn snapshot(primary: &FaultyKeyring) -> Snapshot {
    ACCOUNTS
        .iter()
        .filter_map(|account| primary.raw(account).map(|raw| (*account, raw)))
        .collect()
}

fn present(snapshot: &Snapshot) -> Vec<String> {
    ACCOUNTS
        .iter()
        .filter_map(|account| {
            let raw = snapshot.get(account)?;
            let mut name = account.replace('-', "_");
            if *account == "wrap-key" {
                let valid = std::str::from_utf8(raw)
                    .ok()
                    .and_then(|text| B64.decode(text).ok())
                    .is_some_and(|decoded| decoded.len() == 32);
                if !valid {
                    name.push_str(":invalid");
                }
            }
            Some(name)
        })
        .collect()
}

fn changed(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    ACCOUNTS
        .iter()
        .filter(|account| {
            let (b, a) = (before.get(*account), after.get(*account));
            match (b, a) {
                (None, None) => false,
                (Some(b), Some(a)) => {
                    // Records are compared as JSON values: key order is a
                    // serializer detail, not cache state.
                    match (json_of(b), json_of(a)) {
                        (Some(b), Some(a)) => b != a,
                        _ => b != a,
                    }
                }
                _ => true,
            }
        })
        .map(|account| account.replace('-', "_"))
        .collect()
}

fn utc_z(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.ends_with('Z') {
        return false;
    }
    let body = &text[..text.len() - 1];
    let (date_time, fraction) = match body.split_once('.') {
        Some((head, fraction)) => (head, Some(fraction)),
        None => (body, None),
    };
    let shape: Vec<char> = date_time.chars().collect();
    let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    shape.len() == 19
        && digit_positions.iter().all(|i| shape[*i].is_ascii_digit())
        && shape[4] == '-'
        && shape[7] == '-'
        && shape[10] == 'T'
        && shape[13] == ':'
        && shape[16] == ':'
        && fraction.is_none_or(|digits| {
            !digits.is_empty()
                && digits.len() <= 9
                && digits.chars().all(|c| c.is_ascii_digit())
                && !digits.ends_with('0')
        })
}

fn shape(primary: &FaultyKeyring) -> Shape {
    let record = |account: &str| -> Map<String, Value> {
        let raw = primary.raw(account).expect("inspect needs the record");
        match serde_json::from_slice::<Value>(&raw).expect("record is JSON") {
            Value::Object(map) => map,
            other => panic!("record is not an object: {other}"),
        }
    };
    let keys = |map: &Map<String, Value>| {
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        keys
    };
    let text = |map: &Map<String, Value>, key: &str| map[key].as_str().unwrap().to_owned();
    let (session, identity) = (record("session"), record("identity"));
    let wrap = primary.raw("wrap-key").unwrap_or_default();
    let wrap_ok = std::str::from_utf8(&wrap)
        .ok()
        .and_then(|text| B64.decode(text).ok())
        .is_some_and(|decoded| decoded.len() == 32);
    Shape {
        session_fields: keys(&session),
        identity_fields: keys(&identity),
        wrap_key_encoding: if wrap_ok {
            "base64_std_32_bytes".into()
        } else {
            "other".into()
        },
        nonce_bytes: B64.decode(text(&session, "nonce")).unwrap().len(),
        timestamps_utc_z: utc_z(&text(&session, "saved_at"))
            && utc_z(&text(&session, "last_access"))
            && utc_z(&text(&identity, "saved_at")),
        ttl_ns: session["ttl_ns"].as_i64().unwrap_or(0),
        max_lifetime_ns: session
            .get("max_lifetime_ns")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        identity_inherits_session_saved_at: session["saved_at"] == identity["saved_at"],
        ciphertext_adds_16_byte_tag: B64
            .decode(text(&session, "encrypted_passphrase"))
            .unwrap()
            .len()
            == "s3cret".len() + 16,
    }
}

fn edit(primary: &FaultyKeyring, step: &Step) {
    let raw = primary
        .raw(&step.account)
        .unwrap_or_else(|| panic!("edit: missing {}", step.account));
    let Value::Object(mut fields) = serde_json::from_slice::<Value>(&raw).unwrap() else {
        panic!("edit: record is not an object");
    };
    if let Some(ago) = step.saved_ago_ns {
        fields.insert("saved_at".into(), stamp(ago));
    }
    if let Some(ago) = step.last_access_ago_ns {
        fields.insert("last_access".into(), stamp(ago));
    }
    for (key, value) in &step.set {
        fields.insert(key.clone(), value.clone());
    }
    for key in &step.remove {
        fields.remove(key);
    }
    primary.put_raw(&step.account, &serde_json::to_vec(&fields).unwrap());
}

fn duration(value: Option<u64>) -> Duration {
    Duration::from_nanos(value.expect("save step carries durations"))
}

/// Result of one operation: error class (or `ok`), loaded text, boolean probe.
pub struct Outcome {
    pub result: &'static str,
    pub value: String,
    pub flag: Option<bool>,
}

fn text(result: Result<Vec<u8>, SessionError>) -> Outcome {
    match result {
        Ok(bytes) => Outcome {
            result: "ok",
            value: String::from_utf8(bytes).unwrap(),
            flag: None,
        },
        Err(error) => Outcome {
            result: classify(&error),
            value: String::new(),
            flag: None,
        },
    }
}

fn unit(result: Result<(), SessionError>) -> Outcome {
    Outcome {
        result: class_of(&result),
        value: String::new(),
        flag: None,
    }
}

fn boolean(result: Result<bool, SessionError>) -> Outcome {
    match result {
        Ok(flag) => Outcome {
            result: "ok",
            value: String::new(),
            flag: Some(flag),
        },
        Err(error) => Outcome {
            result: classify(&error),
            value: String::new(),
            flag: None,
        },
    }
}

/// Runs a session operation by its fixture name. Shared with the concurrency
/// workload so both replays exercise one dispatch table.
pub fn run_manager_op(manager: &SessionManager, op: &str, step: Option<&Step>) -> Option<Outcome> {
    Some(match op {
        "save_passphrase" => {
            let step = step.expect("save needs a step");
            unit(manager.save_passphrase(
                VAULT,
                step.secret.as_bytes(),
                duration(step.ttl_ns),
                duration(step.max_lifetime_ns),
            ))
        }
        "save_identity" => {
            let step = step.expect("save needs a step");
            unit(manager.save_identity(
                VAULT,
                step.secret.as_bytes(),
                duration(step.ttl_ns),
                duration(step.max_lifetime_ns),
            ))
        }
        "load_passphrase" => text(manager.load_passphrase(VAULT)),
        "load_identity" => text(manager.load_identity(VAULT, true)),
        "peek_identity" => text(manager.load_identity(VAULT, false)),
        "is_session_expired" => Outcome {
            result: "ok",
            value: String::new(),
            flag: Some(manager.is_session_expired(VAULT)),
        },
        "is_identity_expired" => Outcome {
            result: "ok",
            value: String::new(),
            flag: Some(manager.is_identity_expired(VAULT)),
        },
        "clear_session" => unit(manager.revoke(VAULT)),
        "clear_identity" => unit(manager.clear_identity(VAULT)),
        "has_legacy_plaintext" => boolean(manager.has_legacy_plaintext_session(VAULT)),
        "migrate_session" => boolean(manager.migrate_session(VAULT)),
        _ => return None,
    })
}

/// Replays one scenario and returns the number of observation steps checked.
pub fn replay(scenario: &Scenario, harness: &Harness) -> usize {
    let mut observed = 0;
    for (index, step) in scenario.steps.iter().enumerate() {
        let context = format!("{} step {index} ({})", scenario.name, step.op);
        let before = snapshot(&harness.primary);
        match step.op.as_str() {
            "edit" => {
                edit(&harness.primary, step);
                continue;
            }
            "raw_set" => {
                harness.primary.put_raw(
                    &step.account,
                    step.value.as_deref().expect("raw_set value").as_bytes(),
                );
                continue;
            }
            "raw_delete" => {
                harness.primary.drop_raw(&step.account);
                continue;
            }
            "set_fault" => {
                harness.primary.set_fault(Fault {
                    get: step.fault_get,
                    set: step.fault_set,
                    delete: step.fault_delete,
                    accounts: step.fault_accounts.clone(),
                });
                continue;
            }
            _ => {}
        }
        let outcome = if step.op == "inspect" {
            let actual = shape(&harness.primary);
            assert_eq!(
                Some(&actual),
                step.expect.shape.as_ref(),
                "{context}: record shape"
            );
            Outcome {
                result: "",
                value: String::new(),
                flag: None,
            }
        } else {
            run_manager_op(&harness.manager, &step.op, Some(step))
                .unwrap_or_else(|| panic!("{context}: unknown op"))
        };
        let after = snapshot(&harness.primary);
        assert_eq!(outcome.result, step.expect.result, "{context}: result");
        assert_eq!(outcome.value, step.expect.value, "{context}: value");
        assert_eq!(outcome.flag, step.expect.flag, "{context}: flag");
        assert_eq!(present(&after), step.expect.present, "{context}: present");
        assert_eq!(
            changed(&before, &after),
            step.expect.changed,
            "{context}: changed"
        );
        if let Some(active) = &harness.fallback_active {
            assert_eq!(
                Some(active()),
                step.expect.fallback_active,
                "{context}: fallback_active"
            );
        }
        observed += 1;
    }
    observed
}

/// Replays a concurrency case with real threads. Mirrors the Go invariants:
/// permitted results only, no torn records, and the recorded final state.
pub fn replay_concurrency(case: &Concurrency) {
    let harness = memory_harness();
    let manager = Arc::new(harness.manager);
    let primary = harness.primary;
    let hour = Duration::from_secs(3600).as_nanos() as u64;
    let save = |manager: &SessionManager, op: &str| {
        let step = Step {
            op: op.into(),
            secret: if op == "save_identity" {
                "id-1".into()
            } else {
                "s3cret".into()
            },
            ttl_ns: Some(hour),
            max_lifetime_ns: Some(8 * hour),
            account: String::new(),
            saved_ago_ns: None,
            last_access_ago_ns: None,
            set: Map::new(),
            remove: Vec::new(),
            value: None,
            fault_get: false,
            fault_set: false,
            fault_delete: false,
            fault_accounts: Vec::new(),
            expect: Expect {
                result: String::new(),
                value: String::new(),
                flag: None,
                present: Vec::new(),
                changed: Vec::new(),
                fallback_active: None,
                shape: None,
            },
        };
        run_manager_op(manager, op, Some(&step)).unwrap()
    };
    if case.workload[0] != "save_passphrase" {
        assert_eq!(save(&manager, "save_passphrase").result, "ok");
        assert_eq!(save(&manager, "save_identity").result, "ok");
    }
    let failures = Mutex::new(Vec::<String>::new());
    std::thread::scope(|scope| {
        for _ in 0..case.workers {
            scope.spawn(|| {
                for _ in 0..case.iterations {
                    for name in &case.workload {
                        let outcome = save_or_op(&manager, name, &save);
                        if let Some(want) = case.probe_expected.get(name) {
                            if outcome.flag != Some(*want) {
                                failures.lock().unwrap().push(format!(
                                    "{name} returned {:?}, want {want}",
                                    outcome.flag
                                ));
                            }
                            continue;
                        }
                        let permitted = &case.permitted_results[name];
                        if !permitted.iter().any(|item| item == outcome.result) {
                            failures.lock().unwrap().push(format!(
                                "{name} returned {} outside {permitted:?}",
                                outcome.result
                            ));
                        }
                    }
                }
            });
        }
        for _ in 0..case.revokers {
            scope.spawn(|| {
                for _ in 0..case.iterations {
                    let outcome = run_manager_op(&manager, "clear_session", None).unwrap();
                    if outcome.result != "ok" {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("clear_session returned {}", outcome.result));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(failures.is_empty(), "{}: {failures:?}", case.name);
    for account in ["session", "identity"] {
        if let Some(raw) = primary.raw(account) {
            assert!(
                serde_json::from_slice::<Value>(&raw).is_ok(),
                "{}: torn {account} record",
                case.name
            );
        }
    }
    if case.revokers > 0 {
        assert_eq!(
            run_manager_op(&manager, "clear_session", None)
                .unwrap()
                .result,
            "ok"
        );
    }
    assert_eq!(
        present(&snapshot(&primary)),
        case.final_present
            .iter()
            .map(|name| name.replace('-', "_"))
            .collect::<Vec<_>>(),
        "{}: final entries",
        case.name
    );
    let final_load = run_manager_op(&manager, "load_passphrase", None).unwrap();
    assert!(
        case.final_load_results
            .iter()
            .any(|item| item == final_load.result),
        "{}: final load {} outside {:?}",
        case.name,
        final_load.result,
        case.final_load_results
    );
    if !case.after_sequential_save.is_empty() {
        assert_eq!(save(&manager, "save_passphrase").result, "ok");
        let recovered = run_manager_op(&manager, "load_passphrase", None).unwrap();
        assert_eq!(recovered.result, case.after_sequential_save);
        assert_eq!(recovered.value, "s3cret");
    }
}

fn save_or_op(
    manager: &SessionManager,
    name: &str,
    save: &dyn Fn(&SessionManager, &str) -> Outcome,
) -> Outcome {
    if name.starts_with("save_") {
        save(manager, name)
    } else {
        run_manager_op(manager, name, None).unwrap_or_else(|| panic!("unknown workload op {name}"))
    }
}
