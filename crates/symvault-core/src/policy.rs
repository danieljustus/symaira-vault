use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::result::Result as StdResult;
use std::{cmp::Reverse, fmt};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The action returned by a policy rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Deny,
    Prompt,
    RequireBiometry,
    /// Kept so validation can report unknown actions instead of rejecting them
    /// during deserialization.
    Other(String),
}

impl Default for Action {
    fn default() -> Self {
        Self::Other(String::new())
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Action {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Prompt => "prompt",
            Self::RequireBiometry => "require_biometry",
            Self::Other(value) => value,
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

struct ActionVisitor;

impl<'de> Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a policy action string")
    }

    fn visit_str<E>(self, value: &str) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match value {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            "prompt" => Action::Prompt,
            "require_biometry" => Action::RequireBiometry,
            other => Action::Other(other.to_owned()),
        })
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor)
    }
}

/// A policy document made up of ordered rules.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Policy {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One prioritized policy rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub conditions: Conditions,
    #[serde(default)]
    pub action: Action,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RateLimitCondition {
    #[serde(default)]
    pub max_reads_per_hour: i32,
    #[serde(default)]
    pub max_reads_per_day: i32,
}

/// Conditions supported by the pure policy matcher.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Conditions {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub time_of_day: Option<TimeRange>,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub rate_limit: Option<RateLimitCondition>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub max_secrets: i32,
}

/// A time-of-day range in `HH:MM` form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
}

impl TimeRange {
    /// Parses both endpoints, returning the same boundary shape used by the
    /// Go oracle (`HH:MM`, with no seconds or timezone).
    pub fn parse(&self) -> StdResult<(u8, u8, u8, u8), String> {
        let start = parse_hhmm(&self.start)
            .map_err(|error| format!("invalid start time {:?}: {error}", self.start))?;
        let end = parse_hhmm(&self.end)
            .map_err(|error| format!("invalid end time {:?}: {error}", self.end))?;
        Ok((start.0, start.1, end.0, end.1))
    }

    /// Returns whether `now` is in the range. The start is inclusive and the
    /// end is exclusive for normal ranges. Equal endpoints intentionally follow
    /// the Go implementation's all-day/wrap-around behavior.
    #[must_use]
    pub fn contains(&self, now: UtcTime) -> bool {
        let Ok((start_hour, start_minute, end_hour, end_minute)) = self.parse() else {
            return false;
        };
        let start = u32::from(start_hour) * 3600 + u32::from(start_minute) * 60;
        let end = u32::from(end_hour) * 3600 + u32::from(end_minute) * 60;
        let current = now.seconds_since_midnight();
        if end <= start {
            current >= start || current < end
        } else {
            current >= start && current < end
        }
    }
}

fn parse_hhmm(value: &str) -> StdResult<(u8, u8), String> {
    let Some((hour, minute)) = value.split_once(':') else {
        return Err(format!(
            "parsing time {:?} as \"15:04\": cannot parse {:?} as \"15\"",
            value, value
        ));
    };
    if hour.len() != 2 || minute.len() != 2 {
        return Err(format!(
            "parsing time {:?} as \"15:04\": cannot parse {:?} as \"15\"",
            value, value
        ));
    }
    let hour_value = hour.parse::<u8>().map_err(|_| {
        format!(
            "parsing time {:?} as \"15:04\": cannot parse {:?} as \"15\"",
            value, hour
        )
    })?;
    let minute_value = minute.parse::<u8>().map_err(|_| {
        format!(
            "parsing time {:?} as \"15:04\": cannot parse {:?} as \"04\"",
            value, minute
        )
    })?;
    if hour_value > 23 {
        return Err(format!("parsing time {:?}: hour out of range", value));
    }
    if minute_value > 59 {
        return Err(format!("parsing time {:?}: minute out of range", value));
    }
    Ok((hour_value, minute_value))
}

/// An explicit UTC clock value supplied by the caller.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct UtcTime {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl UtcTime {
    #[must_use]
    pub const fn from_hms(hour: u8, minute: u8, second: u8) -> Option<Self> {
        if hour < 24 && minute < 60 && second < 60 {
            Some(Self {
                hour,
                minute,
                second,
            })
        } else {
            None
        }
    }

    pub fn parse_rfc3339(value: &str) -> StdResult<Self, String> {
        let time = value
            .split_once('T')
            .map(|(_, time)| time)
            .unwrap_or(value)
            .trim_end_matches('Z');
        let time = time
            .split_once('.')
            .map(|(prefix, _)| prefix)
            .unwrap_or(time);
        let mut parts = time.split(':');
        let hour = parts
            .next()
            .ok_or_else(|| format!("invalid UTC time {value:?}"))?;
        let minute = parts
            .next()
            .ok_or_else(|| format!("invalid UTC time {value:?}"))?;
        let second = parts
            .next()
            .ok_or_else(|| format!("invalid UTC time {value:?}"))?;
        if parts.next().is_some() {
            return Err(format!("invalid UTC time {value:?}"));
        }
        let parsed = Self::from_hms(
            hour.parse()
                .map_err(|_| format!("invalid UTC time {value:?}"))?,
            minute
                .parse()
                .map_err(|_| format!("invalid UTC time {value:?}"))?,
            second
                .parse()
                .map_err(|_| format!("invalid UTC time {value:?}"))?,
        );
        parsed.ok_or_else(|| format!("invalid UTC time {value:?}"))
    }

    #[must_use]
    pub const fn seconds_since_midnight(self) -> u32 {
        self.hour as u32 * 3600 + self.minute as u32 * 60 + self.second as u32
    }
}

/// Explicit evaluation input. It contains no filesystem, environment, clock,
/// limiter, or audit callback dependencies.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct EvalContext {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default)]
    pub action_type: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub now: UtcTime,
    #[serde(default)]
    pub secrets_accessed: i32,
}

/// The stable result shape of an evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Result {
    pub action: Action,
    pub rule_name: String,
    pub matched: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyValidationError {
    messages: Vec<String>,
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.messages.join("\n"))
    }
}

impl std::error::Error for PolicyValidationError {}

impl Policy {
    /// Validates syntax and semantic rule fields without loading YAML or files.
    pub fn validate(&self) -> std::result::Result<(), PolicyValidationError> {
        let mut messages = Vec::new();
        if self.version.is_empty() {
            messages.push("policy version is required".to_owned());
        }
        if self.rules.is_empty() {
            messages.push("policy must contain at least one rule".to_owned());
        }

        let mut seen_names = HashMap::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                messages.push(format!("rule at index {index}: name is required"));
            } else if let Some(first_index) = seen_names.insert(rule.name.clone(), index) {
                messages.push(format!(
                    "rule {:?} at index {index}: duplicate name (first seen at index {first_index})",
                    rule.name
                ));
            }

            if !rule.action.is_valid() {
                messages.push(format!(
                    "rule {:?}: invalid action {:?} (valid: allow, deny, prompt, require_biometry)",
                    rule.name,
                    rule.action.as_str()
                ));
            }
            if let Err(message) = validate_conditions(&rule.conditions) {
                messages.push(format!("rule {:?}: {message}", rule.name));
            }
        }

        if messages.is_empty() {
            Ok(())
        } else {
            Err(PolicyValidationError { messages })
        }
    }
}

fn validate_conditions(conditions: &Conditions) -> std::result::Result<(), String> {
    if let Some(time_range) = &conditions.time_of_day {
        time_range
            .parse()
            .map_err(|error| format!("invalid time_of_day: {error}"))?;
    }
    if !conditions.action.is_empty()
        && !matches!(
            conditions.action.as_str(),
            "read" | "write" | "delete" | "run" | "list" | "get" | "set" | "find"
        )
    {
        return Err(format!("invalid action type {:?}", conditions.action));
    }
    Ok(())
}

/// A deterministic policy engine. Rules are copied and sorted by descending
/// priority, preserving source order for equal priorities.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    rules: Vec<Rule>,
}

impl Engine {
    pub fn new<P>(policies: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<Policy>,
    {
        let mut rules = Vec::new();
        for policy in policies {
            rules.extend(policy.borrow().rules.iter().cloned());
        }
        rules.sort_by_key(|rule| Reverse(rule.priority));
        Self { rules }
    }

    #[must_use]
    pub fn evaluate(&self, context: EvalContext) -> Result {
        for rule in &self.rules {
            if matches_rule(rule, &context) {
                return Result {
                    action: rule.action.clone(),
                    rule_name: rule.name.clone(),
                    matched: true,
                };
            }
        }
        default_result()
    }
}

#[must_use]
pub fn default_result() -> Result {
    Result {
        action: Action::Deny,
        rule_name: String::new(),
        matched: false,
    }
}

fn matches_rule(rule: &Rule, context: &EvalContext) -> bool {
    let conditions = &rule.conditions;
    if !conditions.agent_id.is_empty() && !match_string(&conditions.agent_id, &context.agent_id) {
        return false;
    }
    if !conditions.path.is_empty() && !match_path(&conditions.path, &context.path) {
        return false;
    }
    if !conditions.tags.is_empty() && !match_any_tag(&conditions.tags, &context.tags) {
        return false;
    }
    if !conditions.working_dir.is_empty()
        && !match_path(&conditions.working_dir, &context.working_dir)
    {
        return false;
    }
    if conditions
        .time_of_day
        .as_ref()
        .is_some_and(|time_range| !time_range.contains(context.now))
    {
        return false;
    }
    if !conditions.env_vars.is_empty() && !match_env_vars(&conditions.env_vars, &context.env_vars) {
        return false;
    }
    if !conditions.action.is_empty() && !match_string(&conditions.action, &context.action_type) {
        return false;
    }
    if !conditions.allowed_tools.is_empty()
        && !match_allowed_tool(&conditions.allowed_tools, &context.tool_name)
    {
        return false;
    }
    // The Go branch mutates AgentRateLimiter state. Pure POLICY-001 callers do
    // not supply that side effect, so a rate-limited rule cannot match here.
    if conditions.rate_limit.is_some() {
        return false;
    }
    if conditions.max_secrets > 0 && context.secrets_accessed >= conditions.max_secrets {
        return false;
    }
    true
}

fn match_string(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

fn match_any_tag(required: &[String], actual: &[String]) -> bool {
    required
        .iter()
        .any(|required| actual.iter().any(|tag| tag == required))
}

fn match_env_vars(required: &BTreeMap<String, String>, actual: &BTreeMap<String, String>) -> bool {
    required.iter().all(|(key, pattern)| {
        actual
            .get(key)
            .is_some_and(|value| match_string(pattern, value))
    })
}

fn match_allowed_tool(allowed: &[String], tool_name: &str) -> bool {
    allowed.is_empty() || tool_name.is_empty() || allowed.iter().any(|tool| tool == tool_name)
}

fn path_separator() -> char {
    if cfg!(windows) { '\\' } else { '/' }
}

fn is_path_separator(character: char) -> bool {
    if cfg!(windows) {
        character == '/' || character == '\\'
    } else {
        character == '/'
    }
}

fn clean_path(value: &str) -> String {
    let separator = path_separator();
    let absolute = value.chars().next().is_some_and(is_path_separator);
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let push_part = |part: &str, parts: &mut Vec<String>| match part {
        "" | "." => {}
        ".." => {
            if parts.last().is_some_and(|last| last != "..") {
                parts.pop();
            } else if !absolute {
                parts.push("..".to_owned());
            }
        }
        other => parts.push(other.to_owned()),
    };
    for character in value.chars() {
        if is_path_separator(character) {
            push_part(&current, &mut parts);
            current.clear();
        } else {
            current.push(character);
        }
    }
    push_part(&current, &mut parts);
    let joined = parts.join(&separator.to_string());
    if absolute {
        format!("{separator}{joined}")
    } else {
        joined
    }
}

fn match_path(pattern: &str, value: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let clean = clean_path(value);
    if pattern == clean || glob_match(pattern, &clean) {
        return true;
    }
    let separator = path_separator().to_string();
    if let Some(prefix) = pattern.strip_suffix(&format!("{separator}**")) {
        let prefix = prefix.trim_end_matches(path_separator());
        if !prefix.is_empty()
            && (clean == prefix || clean.starts_with(&format!("{prefix}{separator}")))
        {
            return true;
        }
    }
    if pattern.ends_with(path_separator()) {
        let prefix = pattern.trim_end_matches(path_separator());
        if !prefix.is_empty()
            && (clean == prefix || clean.starts_with(&format!("{prefix}{separator}")))
        {
            return true;
        }
    }
    !pattern.chars().any(|character| "*?[".contains(character))
        && (clean == pattern || clean.starts_with(&format!("{pattern}{separator}")))
}

#[derive(Clone, Debug)]
enum GlobToken {
    Star,
    Any,
    Literal(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let Some(tokens) = parse_glob(pattern) else {
        return false;
    };
    let value: Vec<char> = value.chars().collect();
    let mut memo = HashMap::new();
    glob_match_at(&tokens, &value, 0, 0, &mut memo)
}

fn parse_glob(pattern: &str) -> Option<Vec<GlobToken>> {
    let characters: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        match characters[index] {
            '*' => {
                tokens.push(GlobToken::Star);
                index += 1;
            }
            '?' => {
                tokens.push(GlobToken::Any);
                index += 1;
            }
            '[' => {
                let (token, next) = parse_class(&characters, index)?;
                tokens.push(token);
                index = next;
            }
            '\\' if !cfg!(windows) => {
                index += 1;
                tokens.push(GlobToken::Literal(*characters.get(index)?));
                index += 1;
            }
            literal => {
                tokens.push(GlobToken::Literal(literal));
                index += 1;
            }
        }
    }
    Some(tokens)
}

fn parse_class(characters: &[char], start: usize) -> Option<(GlobToken, usize)> {
    let mut index = start + 1;
    let negated = characters
        .get(index)
        .is_some_and(|character| *character == '^');
    if negated {
        index += 1;
    }
    let mut ranges = Vec::new();
    while index < characters.len() {
        if characters[index] == ']' && !ranges.is_empty() {
            return Some((GlobToken::Class { negated, ranges }, index + 1));
        }
        let low = class_character(characters, &mut index)?;
        let high = if characters.get(index) == Some(&'-') {
            index += 1;
            class_character(characters, &mut index)?
        } else {
            low
        };
        ranges.push((low, high));
    }
    None
}

fn class_character(characters: &[char], index: &mut usize) -> Option<char> {
    let character = *characters.get(*index)?;
    if character == '\\' && !cfg!(windows) {
        *index += 1;
        let escaped = *characters.get(*index)?;
        *index += 1;
        return Some(escaped);
    }
    if character == '-' || character == ']' {
        return None;
    }
    *index += 1;
    Some(character)
}

fn glob_match_at(
    pattern: &[GlobToken],
    value: &[char],
    pattern_index: usize,
    value_index: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pattern_index, value_index)) {
        return *result;
    }
    let result = match pattern.get(pattern_index) {
        None => value_index == value.len(),
        Some(GlobToken::Star) => {
            glob_match_at(pattern, value, pattern_index + 1, value_index, memo)
                || value.get(value_index).is_some_and(|character| {
                    *character != path_separator()
                        && glob_match_at(pattern, value, pattern_index, value_index + 1, memo)
                })
        }
        Some(GlobToken::Any) => value.get(value_index).is_some_and(|character| {
            *character != path_separator()
                && glob_match_at(pattern, value, pattern_index + 1, value_index + 1, memo)
        }),
        Some(GlobToken::Literal(expected)) => {
            value
                .get(value_index)
                .is_some_and(|actual| actual == expected)
                && glob_match_at(pattern, value, pattern_index + 1, value_index + 1, memo)
        }
        Some(GlobToken::Class { negated, ranges }) => {
            value.get(value_index).is_some_and(|actual| {
                let matched = ranges
                    .iter()
                    .any(|(low, high)| low <= actual && actual <= high);
                (if *negated { !matched } else { matched })
                    && glob_match_at(pattern, value, pattern_index + 1, value_index + 1, memo)
            })
        }
    };
    memo.insert((pattern_index, value_index), result);
    result
}

#[cfg(test)]
mod tests {
    use super::{TimeRange, UtcTime, match_path};

    #[test]
    fn equal_time_range_matches_all_times() {
        let range = TimeRange {
            start: "09:00".into(),
            end: "09:00".into(),
        };
        assert!(range.contains(UtcTime::from_hms(3, 0, 0).unwrap()));
        assert!(range.contains(UtcTime::from_hms(9, 0, 0).unwrap()));
    }

    #[test]
    fn invalid_time_range_does_not_match() {
        let range = TimeRange {
            start: "25:00".into(),
            end: "09:00".into(),
        };
        assert!(!range.contains(UtcTime::default()));
    }

    #[cfg(unix)]
    #[test]
    fn unix_path_matching_preserves_backslash_semantics() {
        assert!(!match_path("fixture/*", r"fixture\child"));
        assert!(match_path(r"fixture\*", "fixture*"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_matching_uses_backslash_as_separator() {
        assert!(match_path(r"fixture\*", r"fixture\child"));
        assert!(!match_path("fixture/*", r"fixture\child"));
    }
}
