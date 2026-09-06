#![deny(unsafe_code)]

//! Secret redaction core: detectors, Shannon entropy heuristic, and fail-closed scanner.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Marker substituted for detected secret values.
pub const MARKER: &str = "[REDACTED]";

/// Marker returned when scanner output is withheld/blocked.
pub const BLOCKED_TEXT: &str = "[REDACTED: output withheld]";

/// Opt-in environment variable name enabling strict blocking mode.
pub const ENV_STRICT_MODE: &str = "SYMVAULT_REDACT_STRICT_MODE";

/// Minimum length for a literal exact-value detector match.
pub const MIN_EXACT_VALUE_LEN: usize = 4;

/// Minimum token length for the entropy heuristic detector.
pub const MIN_TOKEN_LEN: usize = 20;

/// Shannon entropy floor in bits per character for the entropy heuristic.
pub const MIN_ENTROPY_BITS_PER_CHAR: f64 = 4.85;

/// Confidence classification of a detector match.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// High-confidence match (exact value, verified credential format).
    High,
    /// Low-confidence heuristic match (entropy-based candidate).
    Low,
}

impl Confidence {
    /// Human-readable label for confidence tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when a detector fails during scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactError(String);

impl RedactError {
    /// Creates a new detector error.
    #[must_use]
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RedactError {}

/// Detector scans text for secrets and replaces matches with `MARKER`.
pub trait Detector: Send + Sync {
    /// Canonical detector name for audit metadata.
    fn name(&self) -> &str;
    /// Confidence tier of this detector.
    fn confidence(&self) -> Confidence;
    /// Redacts matches in place, returning the redacted text and match count.
    fn redact(&self, text: &str) -> Result<(String, usize), RedactError>;
}

/// Detector matching literal occurrences of known secrets.
pub struct ExactValueDetector {
    values: Vec<String>,
}

impl ExactValueDetector {
    /// Creates a new `ExactValueDetector`, filtering out secrets shorter than `MIN_EXACT_VALUE_LEN`.
    #[must_use]
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let filtered = values
            .into_iter()
            .filter_map(|s| {
                let s = s.as_ref();
                if s.len() >= MIN_EXACT_VALUE_LEN {
                    Some(s.to_string())
                } else {
                    None
                }
            })
            .collect();
        Self { values: filtered }
    }
}

// Custom Debug implementation to prevent secret values from leaking into logs/snapshots.
impl fmt::Debug for ExactValueDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactValueDetector")
            .field("pattern_count", &self.values.len())
            .field("min_len", &MIN_EXACT_VALUE_LEN)
            .finish()
    }
}

impl Detector for ExactValueDetector {
    fn name(&self) -> &str {
        "exact_value"
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn redact(&self, text: &str) -> Result<(String, usize), RedactError> {
        let mut current = text.to_string();
        let mut total = 0;
        for v in &self.values {
            let (next, count) = replace_all_value(&current, v);
            current = next;
            total += count;
        }
        Ok((current, total))
    }
}

fn replace_all_value(text: &str, value: &str) -> (String, usize) {
    if value.is_empty() {
        return (text.to_string(), 0);
    }
    let count = text.matches(value).count();
    if count == 0 {
        return (text.to_string(), 0);
    }
    (text.replace(value, MARKER), count)
}

/// Conservative Shannon entropy heuristic detector for random secret tokens.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EntropyDetector;

impl EntropyDetector {
    /// Creates a new `EntropyDetector`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy_heuristic"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn redact(&self, text: &str) -> Result<(String, usize), RedactError> {
        let spans = tokenize(text);
        if spans.is_empty() {
            return Ok((text.to_string(), 0));
        }

        let mut out = String::with_capacity(text.len());
        let mut last_end = 0;
        let mut count = 0;

        for (start, end) in spans {
            if end - start < MIN_TOKEN_LEN {
                continue;
            }
            if shannon_entropy(&text[start..end]) < MIN_ENTROPY_BITS_PER_CHAR {
                continue;
            }
            out.push_str(&text[last_end..start]);
            out.push_str(MARKER);
            last_end = end;
            count += 1;
        }
        out.push_str(&text[last_end..]);

        if count == 0 {
            Ok((text.to_string(), 0))
        } else {
            Ok((out, count))
        }
    }
}

/// Checks whether a character belongs to candidate entropy tokens.
#[must_use]
pub fn is_entropy_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+=_.~!@#$%^&*".contains(c)
}

fn tokenize(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = None;

    for (idx, c) in text.char_indices() {
        if is_entropy_token_char(c) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            spans.push((s, idx));
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

/// Computes empirical Shannon entropy in bits per character.
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let total = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Options configuring a scan invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Strict mode blocks output when high-confidence secrets match.
    pub strict: bool,
    /// Correlation ID tied to audit events.
    pub correlation_id: Option<String>,
}

/// Finding metadata produced by a detector during scanning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that reported the match.
    pub detector: String,
    /// Confidence tier.
    pub confidence: Confidence,
    /// Number of matches.
    pub count: usize,
}

/// Safe metadata-only audit event emitted on detection or block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Detector that triggered the event.
    pub detector: String,
    /// Originating channel label (e.g. `stdout`).
    pub channel: String,
    /// Match confidence.
    pub confidence: Confidence,
    /// Number of redacted occurrences.
    pub redacted_count: usize,
    /// Whether output delivery was blocked.
    pub blocked: bool,
    /// Request correlation ID.
    pub correlation_id: Option<String>,
}

/// Outcome of a scan invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Safe output text (original text, redacted text, or blocked marker).
    pub text: String,
    /// Findings reported during scanning.
    pub findings: Vec<Finding>,
    /// Whether output delivery was blocked.
    pub blocked: bool,
}

/// Error returned on detector failure during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// Safe result that must be surfaced to avoid leaking partial secrets.
    pub safe_result: ScanResult,
    /// Failure message.
    pub message: String,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ScanError {}

/// Callback invoked for each emitted audit event.
pub type AuditCallback = Box<dyn FnMut(&AuditEvent) + Send + Sync>;

/// Scanner running a sequence of detectors over text with fail-closed semantics.
pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
    channel: String,
    audit: Option<AuditCallback>,
}

impl Scanner {
    /// Creates a new `Scanner` with the given detector sequence.
    #[must_use]
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            channel: String::new(),
            audit: None,
        }
    }

    /// Sets the channel label (e.g. `stdout`) for emitted audit events.
    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    /// Sets the audit callback for emitted audit events.
    pub fn set_audit<F>(&mut self, audit: F)
    where
        F: FnMut(&AuditEvent) + Send + Sync + 'static,
    {
        self.audit = Some(Box::new(audit));
    }

    /// Scans text through all configured detectors in sequence.
    ///
    /// # Errors
    ///
    /// Returns `ScanError` if any detector fails. The error carries a safe
    /// `safe_result` with blocked text to guarantee fail-closed security.
    pub fn scan(&mut self, text: &str, opts: &ScanOptions) -> Result<ScanResult, ScanError> {
        if self.detectors.is_empty() {
            return Ok(ScanResult {
                text: text.to_string(),
                findings: Vec::new(),
                blocked: false,
            });
        }

        let mut current = text.to_string();
        let mut findings = Vec::new();
        let mut high_confidence_hit = false;

        for d in &self.detectors {
            match d.redact(&current) {
                Ok((redacted, count)) => {
                    if count > 0 {
                        findings.push(Finding {
                            detector: d.name().to_string(),
                            confidence: d.confidence(),
                            count,
                        });
                        if d.confidence() == Confidence::High {
                            high_confidence_hit = true;
                        }
                    }
                    current = redacted;
                }
                Err(err) => {
                    let event = AuditEvent {
                        detector: d.name().to_string(),
                        channel: self.channel.clone(),
                        confidence: d.confidence(),
                        redacted_count: 0,
                        blocked: true,
                        correlation_id: opts.correlation_id.clone(),
                    };
                    if let Some(ref mut audit_fn) = self.audit {
                        audit_fn(&event);
                    }
                    return Err(ScanError {
                        safe_result: ScanResult {
                            text: BLOCKED_TEXT.to_string(),
                            findings: Vec::new(),
                            blocked: true,
                        },
                        message: format!("redact: detector {:?} failed: {}", d.name(), err),
                    });
                }
            }
        }

        let blocked = opts.strict && high_confidence_hit;
        for f in &findings {
            let event = AuditEvent {
                detector: f.detector.clone(),
                channel: self.channel.clone(),
                confidence: f.confidence,
                redacted_count: f.count,
                blocked,
                correlation_id: opts.correlation_id.clone(),
            };
            if let Some(ref mut audit_fn) = self.audit {
                audit_fn(&event);
            }
        }

        if blocked {
            Ok(ScanResult {
                text: BLOCKED_TEXT.to_string(),
                findings,
                blocked: true,
            })
        } else {
            Ok(ScanResult {
                text: current,
                findings,
                blocked: false,
            })
        }
    }
}

/// Evaluates if an environment variable string represents a truthy opt-in value.
#[must_use]
pub fn is_truthy(v: &str) -> bool {
    matches!(
        v,
        "1" | "t" | "T" | "true" | "TRUE" | "True" | "yes" | "YES" | "Yes" | "on" | "ON" | "On"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_value_detector_masks_debug() {
        let d = ExactValueDetector::new(["mysecretpass"]);
        let debug_str = format!("{d:?}");
        assert!(!debug_str.contains("mysecretpass"));
        assert!(debug_str.contains("pattern_count: 1"));
    }

    #[test]
    fn exact_value_detector_replaces_and_counts() {
        let d = ExactValueDetector::new(["super-secret"]);
        let (out, count) = d.redact("pass is super-secret!").expect("redact");
        assert_eq!(count, 1);
        assert_eq!(out, "pass is [REDACTED]!");
    }

    #[test]
    fn exact_value_ignores_short_values() {
        let d = ExactValueDetector::new(["abc", "a", ""]);
        let (out, count) = d.redact("abc is short").expect("redact");
        assert_eq!(count, 0);
        assert_eq!(out, "abc is short");
    }

    #[test]
    fn entropy_bounds_and_properties() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        let e = shannon_entropy("0123456789abcdef");
        assert!((e - 4.0).abs() < 1e-9);
    }

    #[test]
    fn scanner_no_detectors_is_passthrough() {
        let mut s = Scanner::new(vec![]);
        let res = s
            .scan("hello world", &ScanOptions::default())
            .expect("scan");
        assert_eq!(res.text, "hello world");
        assert!(!res.blocked);
        assert!(res.findings.is_empty());
    }

    #[test]
    fn scanner_strict_mode_blocks_high_confidence() {
        let mut s = Scanner::new(vec![Box::new(ExactValueDetector::new(["secretvalue"]))]);
        let res = s
            .scan(
                "output secretvalue",
                &ScanOptions {
                    strict: true,
                    correlation_id: Some("corr-test".into()),
                },
            )
            .expect("scan");
        assert!(res.blocked);
        assert_eq!(res.text, BLOCKED_TEXT);
        assert_eq!(res.findings.len(), 1);
    }

    #[test]
    fn scanner_strict_mode_does_not_block_low_confidence() {
        let mut s = Scanner::new(vec![Box::new(EntropyDetector::new())]);
        let res = s
            .scan(
                "token: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~ end",
                &ScanOptions {
                    strict: true,
                    correlation_id: None,
                },
            )
            .expect("scan");
        assert!(!res.blocked);
        assert!(res.text.contains(MARKER));
    }

    struct FailingDetector;
    impl Detector for FailingDetector {
        fn name(&self) -> &str {
            "failing"
        }
        fn confidence(&self) -> Confidence {
            Confidence::High
        }
        fn redact(&self, _text: &str) -> Result<(String, usize), RedactError> {
            Err(RedactError::new("boom"))
        }
    }

    #[test]
    fn scanner_fails_closed_on_detector_error() {
        let mut s = Scanner::new(vec![Box::new(FailingDetector)]);
        let err = s
            .scan("unredacted secret", &ScanOptions::default())
            .expect_err("should fail");
        assert!(err.safe_result.blocked);
        assert_eq!(err.safe_result.text, BLOCKED_TEXT);
    }

    #[test]
    fn truthy_opt_in_table() {
        for v in [
            "1", "t", "T", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On",
        ] {
            assert!(is_truthy(v), "should be truthy: {v}");
        }
        for v in ["", "0", "false", "no", "off", "random", "TRUE "] {
            assert!(!is_truthy(v), "should not be truthy: {v}");
        }
    }
}
