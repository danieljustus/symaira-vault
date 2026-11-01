//! `prepare_payment` policy enforcement and spend tracking, ported from
//! `internal/payment/{decimal,enforcer,tracker}.go` and the enforcer wiring in
//! `internal/mcp/server/server.go`.
//!
//! Amounts are exact rationals, exactly like Go's `math/big.Rat`, so a
//! per-day total such as `25.50 + 10.25` is persisted as the same
//! `RatString` (`143/4`) Go writes. The state file shape, the `0600`/`0700`
//! modes and the fail-open behaviour of an unreadable tracker at startup are
//! kept as observed in the oracle.

use serde::Deserialize;
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use symvault_core::go_quote;

/// Go's `maxDecimalLen`: byte length cap applied before any parsing.
const MAX_DECIMAL_LEN: usize = 30;

// ---------------------------------------------------------------------------
// Minimal arbitrary-precision arithmetic (inputs are <= 30 bytes, so the
// simple algorithms below are more than fast enough).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Nat(Vec<u32>);

impl Nat {
    fn zero() -> Self {
        Self(Vec::new())
    }

    fn from_u32(value: u32) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self(vec![value])
        }
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    fn is_one(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 1
    }

    fn trim(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    fn mul_small_add(&mut self, multiplier: u32, addend: u32) {
        let mut carry = u64::from(addend);
        for limb in &mut self.0 {
            let value = u64::from(*limb) * u64::from(multiplier) + carry;
            *limb = (value & 0xffff_ffff) as u32;
            carry = value >> 32;
        }
        if carry != 0 {
            self.0.push(carry as u32);
        }
    }

    /// Parses ASCII digits in `radix` (<= 10). Returns `None` for an empty
    /// string or a digit outside the radix.
    fn parse_radix(digits: &str, radix: u32) -> Option<Self> {
        if digits.is_empty() {
            return None;
        }
        let mut value = Self::zero();
        for byte in digits.bytes() {
            let digit = u32::from(byte.checked_sub(b'0')?);
            if digit >= radix {
                return None;
            }
            value.mul_small_add(radix, digit);
        }
        Some(value.trim())
    }

    fn cmp_nat(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }

    fn add(&self, other: &Self) -> Self {
        let length = self.0.len().max(other.0.len());
        let mut result = Vec::with_capacity(length + 1);
        let mut carry = 0_u64;
        for index in 0..length {
            let value = u64::from(self.0.get(index).copied().unwrap_or(0))
                + u64::from(other.0.get(index).copied().unwrap_or(0))
                + carry;
            result.push((value & 0xffff_ffff) as u32);
            carry = value >> 32;
        }
        if carry != 0 {
            result.push(carry as u32);
        }
        Self(result).trim()
    }

    /// `self - other`; requires `self >= other`.
    fn sub(&self, other: &Self) -> Self {
        let mut result = Vec::with_capacity(self.0.len());
        let mut borrow = 0_i64;
        for index in 0..self.0.len() {
            let mut value = i64::from(self.0[index])
                - i64::from(other.0.get(index).copied().unwrap_or(0))
                - borrow;
            if value < 0 {
                value += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result.push(value as u32);
        }
        Self(result).trim()
    }

    fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut result = vec![0_u32; self.0.len() + other.0.len() + 1];
        for (i, left) in self.0.iter().enumerate() {
            let mut carry = 0_u64;
            for (j, right) in other.0.iter().enumerate() {
                let value = u64::from(*left) * u64::from(*right) + u64::from(result[i + j]) + carry;
                result[i + j] = (value & 0xffff_ffff) as u32;
                carry = value >> 32;
            }
            let mut index = i + other.0.len();
            while carry != 0 {
                let value = u64::from(result[index]) + carry;
                result[index] = (value & 0xffff_ffff) as u32;
                carry = value >> 32;
                index += 1;
            }
        }
        Self(result).trim()
    }

    fn bit_len(&self) -> usize {
        match self.0.last() {
            None => 0,
            Some(top) => (self.0.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    fn bit(&self, index: usize) -> bool {
        self.0
            .get(index / 32)
            .is_some_and(|limb| limb >> (index % 32) & 1 == 1)
    }

    fn shl1_or(&mut self, bit: bool) {
        let mut carry = u32::from(bit);
        for limb in &mut self.0 {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            self.0.push(carry);
        }
    }

    fn set_bit(&mut self, index: usize) {
        let limb = index / 32;
        if self.0.len() <= limb {
            self.0.resize(limb + 1, 0);
        }
        self.0[limb] |= 1 << (index % 32);
    }

    /// Schoolbook bitwise long division; `divisor` must be non-zero.
    fn divrem(&self, divisor: &Self) -> (Self, Self) {
        let mut quotient = Self::zero();
        let mut remainder = Self::zero();
        for index in (0..self.bit_len()).rev() {
            remainder.shl1_or(self.bit(index));
            if remainder.cmp_nat(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient.set_bit(index);
            }
        }
        (quotient.trim(), remainder.trim())
    }

    fn gcd(&self, other: &Self) -> Self {
        let (mut a, mut b) = (self.clone(), other.clone());
        while !b.is_zero() {
            let (_, remainder) = a.divrem(&b);
            a = b;
            b = remainder;
        }
        a
    }

    fn to_decimal(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let ten_pow_nine = Self::from_u32(1_000_000_000);
        let mut chunks = Vec::new();
        let mut rest = self.clone();
        while !rest.is_zero() {
            let (quotient, remainder) = rest.divrem(&ten_pow_nine);
            chunks.push(remainder.0.first().copied().unwrap_or(0));
            rest = quotient;
        }
        let mut text = chunks.pop().unwrap_or(0).to_string();
        while let Some(chunk) = chunks.pop() {
            text.push_str(&format!("{chunk:09}"));
        }
        text
    }
}

/// A normalized signed rational, the subset of `big.Rat` this package uses.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rat {
    negative: bool,
    numerator: Nat,
    denominator: Nat,
}

impl Rat {
    fn new(negative: bool, numerator: Nat, denominator: Nat) -> Self {
        if numerator.is_zero() {
            return Self {
                negative: false,
                numerator,
                denominator: Nat::from_u32(1),
            };
        }
        let divisor = numerator.gcd(&denominator);
        let (numerator, denominator) = if divisor.is_one() {
            (numerator, denominator)
        } else {
            (numerator.divrem(&divisor).0, denominator.divrem(&divisor).0)
        };
        Self {
            negative,
            numerator,
            denominator,
        }
    }

    /// `big.Rat.SetString` restricted to the shapes `parseAmount` admits
    /// (digits, one optional leading `-`, at most one `.` or `/`).
    fn set_string(text: &str) -> Option<Self> {
        if let Some(separator) = text.find('/') {
            let (left, right) = (&text[..separator], &text[separator + 1..]);
            let (negative, digits) = match left.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, left),
            };
            let numerator = parse_base0(digits)?;
            let denominator = parse_base0(right)?;
            if denominator.is_zero() {
                return None;
            }
            return Some(Self::new(negative, numerator, denominator));
        }
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (whole, fraction) = rest.split_once('.').unwrap_or((rest, ""));
        if whole.is_empty() && fraction.is_empty() {
            return None;
        }
        let digits = format!("{whole}{fraction}");
        let numerator = Nat::parse_radix(&digits, 10)?;
        let mut denominator = Nat::from_u32(1);
        for _ in 0..fraction.len() {
            denominator.mul_small_add(10, 0);
        }
        Some(Self::new(negative, numerator, denominator))
    }

    fn add(&self, other: &Self) -> Self {
        let left = self.numerator.mul(&other.denominator);
        let right = other.numerator.mul(&self.denominator);
        let denominator = self.denominator.mul(&other.denominator);
        let (negative, numerator) = if self.negative == other.negative {
            (self.negative, left.add(&right))
        } else {
            match left.cmp_nat(&right) {
                Ordering::Less => (other.negative, right.sub(&left)),
                _ => (self.negative, left.sub(&right)),
            }
        };
        Self::new(negative, numerator, denominator)
    }

    fn cmp_rat(&self, other: &Self) -> Ordering {
        match (self.numerator.is_zero(), other.numerator.is_zero()) {
            (true, true) => return Ordering::Equal,
            (true, false) => {
                return if other.negative {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            (false, true) => {
                return if self.negative {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (false, false) => {}
        }
        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (negative, _) => {
                let left = self.numerator.mul(&other.denominator);
                let right = other.numerator.mul(&self.denominator);
                let ordering = left.cmp_nat(&right);
                if negative {
                    ordering.reverse()
                } else {
                    ordering
                }
            }
        }
    }

    /// Go's `Rat.RatString`: `a/b`, or just `a` when the denominator is 1.
    fn rat_string(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        if self.denominator.is_one() {
            format!("{sign}{}", self.numerator.to_decimal())
        } else {
            format!(
                "{sign}{}/{}",
                self.numerator.to_decimal(),
                self.denominator.to_decimal()
            )
        }
    }
}

/// `Int.SetString(s, 0)` / `nat.scan(r, 0, false)` over ASCII digits: a
/// leading `0` followed by more digits selects base 8, so `08` and `09`
/// fail while `010` is eight.
fn parse_base0(digits: &str) -> Option<Nat> {
    if digits.len() > 1 && digits.starts_with('0') {
        Nat::parse_radix(&digits[1..], 8)
    } else {
        Nat::parse_radix(digits, 10)
    }
}

/// Port of `parseAmount`: validates length and alphabet, then parses.
fn parse_amount(text: &str) -> Result<Rat, String> {
    let invalid = || format!("invalid amount {}", go_quote(text));
    if text.is_empty() || text.len() > MAX_DECIMAL_LEN {
        return Err(invalid());
    }
    let (mut saw_dot, mut saw_slash, mut has_digit) = (false, false, false);
    for (index, character) in text.char_indices() {
        match character {
            '-' if index == 0 => {}
            '.' if !saw_slash && !saw_dot => saw_dot = true,
            '/' if !saw_slash && !saw_dot => saw_slash = true,
            '0'..='9' => has_digit = true,
            _ => return Err(invalid()),
        }
    }
    if !has_digit {
        return Err(invalid());
    }
    Rat::set_string(text).ok_or_else(invalid)
}

fn add_rat_strings(left: &str, right: &str) -> Result<String, String> {
    let left_value = parse_amount(left)
        .map_err(|error| format!("parse {} as decimal: {error}", go_quote(left)))?;
    let right_value = parse_amount(right)
        .map_err(|error| format!("parse {} as decimal: {error}", go_quote(right)))?;
    Ok(left_value.add(&right_value).rat_string())
}

// ---------------------------------------------------------------------------
// Policy configuration
// ---------------------------------------------------------------------------

fn lenient_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Scalar {
        Text(String),
        Number(serde_yaml_ng::Number),
        Flag(bool),
        Null(()),
    }
    Ok(match Scalar::deserialize(deserializer)? {
        Scalar::Text(text) => text,
        Scalar::Number(number) => number.to_string(),
        Scalar::Flag(flag) => flag.to_string(),
        Scalar::Null(()) => String::new(),
    })
}

/// `config.PaymentMaxAmount`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PaymentMaxAmount {
    #[serde(default, deserialize_with = "lenient_string")]
    pub per_transaction: String,
    #[serde(default, deserialize_with = "lenient_string")]
    pub per_day: String,
}

/// `config.PaymentPolicy`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PaymentPolicy {
    #[serde(default, deserialize_with = "lenient_string")]
    pub instrument: String,
    #[serde(default)]
    pub allowed_merchants: Vec<String>,
    #[serde(default)]
    pub max_amount: PaymentMaxAmount,
    #[serde(default, deserialize_with = "lenient_string")]
    pub currency: String,
}

#[derive(Deserialize, Default)]
struct RawAgent {
    #[serde(default, rename = "paymentPolicy")]
    payment_policy: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawPaymentConfig {
    #[serde(default, rename = "paymentPolicies")]
    payment_policies: Option<BTreeMap<String, PaymentPolicy>>,
    #[serde(default)]
    agents: Option<BTreeMap<String, RawAgent>>,
}

/// Loads the payment policy the named agent references, as `server.New` does
/// (`agent.PaymentPolicyValue()` looked up in `cfg.PaymentPolicies`). Returns
/// the policy name with the policy, or `None` when the agent has none, the
/// policy is unknown, or the config cannot be read.
#[must_use]
pub fn load_agent_payment_policy(
    config_path: &Path,
    agent: &str,
) -> Option<(String, PaymentPolicy)> {
    let bytes = fs::read(config_path).ok()?;
    let raw: RawPaymentConfig = serde_yaml_ng::from_slice(&bytes).ok()?;
    let name = raw.agents?.remove(agent)?.payment_policy?;
    if name.is_empty() {
        return None;
    }
    let policy = raw.payment_policies?.remove(&name)?;
    Some((name, policy))
}

/// Go's `config.DefaultDataDir()`: `$XDG_DATA_HOME` or `~/.local/share`,
/// then `symaira-vault`.
#[must_use]
pub fn default_data_dir() -> PathBuf {
    let base = match std::env::var("XDG_DATA_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = if cfg!(windows) {
                std::env::var("USERPROFILE")
            } else {
                std::env::var("HOME")
            };
            match home {
                Ok(home) if !home.is_empty() => PathBuf::from(home).join(".local").join("share"),
                _ => PathBuf::new(),
            }
        }
    };
    base.join("symaira-vault")
}

/// `paymentStatePath`: `<data>/payment-state/<sha256(vaultDir)[:12]>/<policy>/
/// daily-totals.json`.
#[must_use]
pub fn payment_state_path(vault_dir: &str, policy_name: &str) -> PathBuf {
    payment_state_path_in(&default_data_dir(), vault_dir, policy_name)
}

/// [`payment_state_path`] under an explicit data directory.
#[must_use]
pub fn payment_state_path_in(data_dir: &Path, vault_dir: &str, policy_name: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(vault_dir.as_bytes());
    let short: String = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    data_dir
        .join("payment-state")
        .join(short)
        .join(policy_name)
        .join("daily-totals.json")
}

// ---------------------------------------------------------------------------
// Daily totals tracker
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct DailyTotalsFile {
    #[serde(default)]
    entries: Option<BTreeMap<String, Option<BTreeMap<String, String>>>>,
}

/// UTC date key (`2006-01-02`) for "today".
fn today_utc() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

/// `payment.DailyTotals`.
#[derive(Debug)]
pub struct DailyTotals {
    entries: BTreeMap<String, BTreeMap<String, String>>,
    path: PathBuf,
}

impl DailyTotals {
    /// `LoadDailyTotals`: a missing file is an empty tracker; unreadable or
    /// unparsable state is an error.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::load_on(path.into(), &today_utc())
    }

    fn load_on(path: PathBuf, today: &str) -> Result<Self, String> {
        let mut tracker = Self {
            entries: BTreeMap::new(),
            path,
        };
        let data = match fs::read(&tracker.path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(tracker),
            Err(error) => return Err(format!("read daily totals: {error}")),
        };
        let file: DailyTotalsFile = serde_json::from_slice(&data)
            .map_err(|error| format!("parse daily totals: {error}"))?;
        if let Some(entries) = file.entries {
            tracker.entries = entries
                .into_iter()
                .map(|(policy, dates)| (policy, dates.unwrap_or_default()))
                .collect();
        }
        tracker.expire_old_entries(today);
        Ok(tracker)
    }

    fn expire_old_entries(&mut self, today: &str) {
        for dates in self.entries.values_mut() {
            dates.retain(|date, _| date.as_str() >= today);
        }
        self.entries.retain(|_, dates| !dates.is_empty());
    }

    /// `TodayTotal`: `"0"` when nothing is recorded.
    #[must_use]
    pub fn today_total(&self, policy_name: &str) -> String {
        self.entries
            .get(policy_name)
            .and_then(|dates| dates.get(&today_utc()))
            .cloned()
            .unwrap_or_else(|| "0".into())
    }

    /// `AddToToday`: adds exactly and persists the whole state.
    pub fn add_to_today(&mut self, policy_name: &str, amount: &str) -> Result<(), String> {
        let today = today_utc();
        let current = self
            .entries
            .get(policy_name)
            .and_then(|dates| dates.get(&today))
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| "0".into());
        let sum =
            add_rat_strings(&current, amount).map_err(|error| format!("add amounts: {error}"))?;
        self.entries
            .entry(policy_name.to_owned())
            .or_default()
            .insert(today.clone(), sum);
        self.save(&today)
    }

    fn save(&mut self, today: &str) -> Result<(), String> {
        self.expire_old_entries(today);
        let data = self.render();
        let directory = self.path.parent().unwrap_or_else(|| Path::new(""));
        create_private_dir(directory)
            .map_err(|error| format!("create payment state dir: {error}"))?;
        write_private_file(&self.path, data.as_bytes())
            .map_err(|error| format!("write daily totals: {error}"))
    }

    /// `json.MarshalIndent(file, "", "  ")` of `{"entries": ...}`.
    fn render(&self) -> String {
        let quote = |text: &str| symvault_gojson::to_string(text).unwrap_or_default();
        if self.entries.is_empty() {
            return "{\n  \"entries\": {}\n}".into();
        }
        let mut out = String::from("{\n  \"entries\": {\n");
        let mut policies = self.entries.iter().peekable();
        while let Some((policy, dates)) = policies.next() {
            out.push_str(&format!("    {}: {{\n", quote(policy)));
            let mut items = dates.iter().peekable();
            while let Some((date, total)) = items.next() {
                out.push_str(&format!("      {}: {}", quote(date), quote(total)));
                out.push_str(if items.peek().is_some() { ",\n" } else { "\n" });
            }
            out.push_str("    }");
            out.push_str(if policies.peek().is_some() {
                ",\n"
            } else {
                "\n"
            });
        }
        out.push_str("  }\n}");
        out
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(data)
}

// ---------------------------------------------------------------------------
// Enforcer
// ---------------------------------------------------------------------------

/// One `prepare_payment` request as the enforcer sees it.
#[derive(Clone, Copy, Debug)]
pub struct PaymentRequest<'a> {
    pub entry_path: &'a str,
    pub merchant: &'a str,
    pub amount: &'a str,
    pub currency: &'a str,
}

/// `payment.Enforcer`.
#[derive(Debug)]
pub struct Enforcer {
    policy: PaymentPolicy,
    tracker: Option<Mutex<DailyTotals>>,
}

/// `strings.ToLower(strings.TrimSpace(s))` with per-rune simple lowering.
fn go_lower_trimmed(text: &str) -> String {
    text.trim().chars().map(simple_lower).collect()
}

fn simple_lower(character: char) -> char {
    let mut lowered = character.to_lowercase();
    match (lowered.next(), lowered.next()) {
        (Some(single), None) => single,
        // U+0130 is the only multi-rune lowering; Go's simple mapping is 'i'.
        _ => 'i',
    }
}

fn simple_upper(character: char) -> char {
    let mut upper = character.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => character,
    }
}

/// `strings.EqualFold` approximated by comparing simple case mappings.
fn equal_fold(left: &str, right: &str) -> bool {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();
    loop {
        match (left_chars.next(), right_chars.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) => {
                if a != b
                    && simple_lower(a) != simple_lower(b)
                    && simple_upper(a) != simple_upper(b)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

impl Enforcer {
    /// `NewEnforcer`.
    #[must_use]
    pub fn new(policy: PaymentPolicy, tracker: Option<DailyTotals>) -> Self {
        Self {
            policy,
            tracker: tracker.map(Mutex::new),
        }
    }

    /// `NewEnforcerFromFile`.
    pub fn from_file(
        policy: PaymentPolicy,
        state_path: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let tracker =
            DailyTotals::load(state_path).map_err(|error| format!("load daily totals: {error}"))?;
        Ok(Self::new(policy, Some(tracker)))
    }

    /// `PolicyName` (the instrument path).
    #[must_use]
    pub fn policy_name(&self) -> &str {
        &self.policy.instrument
    }

    fn denied(reason: &str, detail: &str) -> String {
        format!("payment policy denied: {reason} \u{2014} {detail}")
    }

    /// `Check`: the Go error text on denial.
    pub fn check(&self, request: &PaymentRequest<'_>) -> Result<(), String> {
        let policy = &self.policy;
        if !policy.allowed_merchants.is_empty() {
            let wanted = go_lower_trimmed(request.merchant);
            if !policy
                .allowed_merchants
                .iter()
                .any(|merchant| go_lower_trimmed(merchant) == wanted)
            {
                return Err(Self::denied(
                    "merchant_not_allowed",
                    &format!(
                        "merchant {} not in allowed list",
                        go_quote(request.merchant)
                    ),
                ));
            }
        }

        if !policy.currency.is_empty()
            && !equal_fold(request.currency.trim(), policy.currency.trim())
        {
            return Err(Self::denied(
                "currency_mismatch",
                &format!(
                    "requested currency {} does not match policy currency {}",
                    go_quote(request.currency),
                    go_quote(&policy.currency)
                ),
            ));
        }

        let amount =
            parse_amount(request.amount).map_err(|error| format!("invalid amount: {error}"))?;

        if !policy.max_amount.per_transaction.is_empty() {
            let limit = parse_amount(&policy.max_amount.per_transaction)
                .map_err(|error| format!("invalid per_transaction limit: {error}"))?;
            if amount.cmp_rat(&limit) == Ordering::Greater {
                return Err(Self::denied(
                    "over_per_transaction",
                    &format!(
                        "amount {} exceeds per-transaction limit {}",
                        request.amount, policy.max_amount.per_transaction
                    ),
                ));
            }
        }

        if !policy.max_amount.per_day.is_empty()
            && let Some(tracker) = &self.tracker
        {
            let day_limit = parse_amount(&policy.max_amount.per_day)
                .map_err(|error| format!("invalid per_day limit: {error}"))?;
            let mut today_total = tracker.lock().map_or_else(
                |_| "0".to_owned(),
                |tracker| tracker.today_total(&policy.instrument),
            );
            if today_total.is_empty() {
                today_total = "0".into();
            }
            let today = parse_amount(&today_total)
                .map_err(|error| format!("invalid today total: {error}"))?;
            if today.add(&amount).cmp_rat(&day_limit) == Ordering::Greater {
                return Err(Self::denied(
                    "over_per_day",
                    &format!(
                        "amount {} + today's total {} would exceed per-day limit {}",
                        request.amount, today_total, policy.max_amount.per_day
                    ),
                ));
            }
        }
        Ok(())
    }

    /// `RecordApproved`.
    pub fn record_approved(&self, request: &PaymentRequest<'_>) -> Result<(), String> {
        let Some(tracker) = &self.tracker else {
            return Ok(());
        };
        let mut tracker = tracker
            .lock()
            .map_err(|_| "payment tracker unavailable".to_owned())?;
        tracker.add_to_today(&self.policy.instrument, request.amount)
    }
}

/// `server.New`'s enforcer attachment: a missing or unusable policy/tracker
/// leaves the server without an enforcer (Go ignores `NewEnforcerFromFile`
/// errors).
#[must_use]
pub fn load_enforcer(config_path: &Path, agent: &str, vault_dir: &str) -> Option<Enforcer> {
    let (name, policy) = load_agent_payment_policy(config_path, agent)?;
    Enforcer::from_file(policy, payment_state_path(vault_dir, &name)).ok()
}

/// `fsutil.ValidatePath` + `validateRawEntryPath` + the depth limit, with
/// Go's wording. Returns the JSON-RPC error text for an invalid entry path.
pub(crate) fn validate_entry_path(path: &str) -> Result<(), String> {
    const MAX_DEPTH: usize = 64;
    let trimmed = path.trim();
    let invalid =
        |reason: &str| format!("entry path {}: invalid path: {reason}", go_quote(trimmed));
    if trimmed.is_empty() {
        return Err(invalid("path is empty"));
    }
    if trimmed.contains('\0') {
        return Err(invalid("path contains null byte"));
    }
    if let Some(control) = trimmed.chars().find(|c| (*c as u32) < 0x20) {
        return Err(invalid(&format!(
            "path contains control character 0x{:02x}",
            control as u32
        )));
    }
    let normalized = trimmed.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(invalid("path must be relative"));
    }
    let segments: Vec<&str> = normalized.split('/').collect();
    if segments.contains(&"..") {
        return Err(invalid("path contains '..' segment"));
    }
    if segments.len() > 1 && segments.contains(&"") {
        return Err(invalid("path contains empty segment (double slash)"));
    }
    if segments.contains(&".") {
        return Err(format!(
            "entry path {} contains invalid path segment \".\"",
            go_quote(trimmed)
        ));
    }
    if path.replace('\\', "/").split('/').count() > MAX_DEPTH {
        return Err("vault resource limit exceeded".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rat(text: &str) -> String {
        parse_amount(text).map_or_else(|error| format!("ERR {error}"), |value| value.rat_string())
    }

    #[test]
    fn rat_string_matches_go_big_rat() {
        assert_eq!(rat("75.00"), "75");
        assert_eq!(rat("25.50"), "51/2");
        assert_eq!(rat("-1/2"), "-1/2");
        assert_eq!(rat("0.30"), "3/10");
        assert_eq!(rat(".5"), "1/2");
        assert_eq!(rat("5."), "5");
        assert_eq!(rat("007"), "7");
        // Leading zero selects octal in the p/q form.
        assert_eq!(rat("010/2"), "4");
        assert_eq!(rat("08/2"), "ERR invalid amount \"08/2\"");
        assert_eq!(rat("3/0"), "ERR invalid amount \"3/0\"");
        assert_eq!(rat("1/2/3"), "ERR invalid amount \"1/2/3\"");
        assert_eq!(rat("1.2.3"), "ERR invalid amount \"1.2.3\"");
        assert_eq!(rat("abc"), "ERR invalid amount \"abc\"");
        assert_eq!(rat("-"), "ERR invalid amount \"-\"");
        assert_eq!(rat("1-"), "ERR invalid amount \"1-\"");
    }

    #[test]
    fn exact_sums_do_not_lose_precision() {
        assert_eq!(add_rat_strings("51/2", "10.25").unwrap(), "143/4");
        assert_eq!(
            add_rat_strings("0.1", "0.2").unwrap(),
            "3/10",
            "decimal addition is exact"
        );
        assert_eq!(add_rat_strings("1", "-1").unwrap(), "0");
        assert_eq!(
            add_rat_strings("99999999999999999999999999999", "1").unwrap(),
            "100000000000000000000000000000"
        );
    }
}
