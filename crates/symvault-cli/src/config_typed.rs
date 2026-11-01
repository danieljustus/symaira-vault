//! yaml.v3's typed-decode errors of `config.Config`, for `config set`.
//!
//! After writing the file, Go's `config set` reloads it with
//! `yaml.Unmarshal` into the typed `config.Config`; every field whose YAML
//! value cannot become the Go field type contributes one line of
//! `yaml: unmarshal errors:\n  line N: cannot unmarshal !!tag `value` into
//! <go type>`. This module walks the rendered document against the field types
//! of the Go structs (`config_schema.rs`, generated from the Go source) and
//! reproduces those lines with `decode.go`'s rules:
//!
//! * a string field takes any scalar; a bool field takes `true`/`false` and the
//!   YAML 1.1 spellings `y/n/yes/no/on/off`; an int field takes an int or a
//!   float (truncated); a `time.Duration` takes only a string that
//!   `time.ParseDuration` accepts, so `12`, `1.5` and `true` are errors;
//! * `null` decodes to the zero value everywhere;
//! * a scalar for a struct, slice or map, and a collection for a scalar field,
//!   is an error naming the Go type (`[]string`, `config.VaultConfig`, ...);
//! * a value longer than ten bytes is cut to its first seven BYTES plus `...`,
//!   which can end inside a UTF-8 sequence, so errors are bytes, not strings.

use std::str::FromStr;

use symvault_gojson::resolve::{Resolved, resolve};
use yaml_edit::{ScalarStyle, ScalarValue, YamlNode};

use crate::config_schema::GO_CONFIG_STRUCTS;

/// The `yaml: unmarshal errors:` block yaml.v3 returns for `source`, or `None`
/// when every field decodes. Bytes, because the truncated value may split a
/// multi-byte character.
pub(crate) fn unmarshal_errors(source: &str) -> Option<Vec<u8>> {
    let file = yaml_edit::YamlFile::from_str(source).ok()?;
    let document = file.documents().next()?;
    let root = document.as_mapping()?;
    let mut errors = Vec::new();
    let context = Context { source };
    decode_mapping_fields(&context, root.iter(), "Config", &mut errors);
    if errors.is_empty() {
        return None;
    }
    let mut message = b"yaml: unmarshal errors:".to_vec();
    for error in errors {
        message.extend_from_slice(b"\n  ");
        message.extend_from_slice(&error);
    }
    Some(message)
}

struct Context<'a> {
    source: &'a str,
}

impl Context<'_> {
    /// yaml.v3's `Node.Line` (1-based).
    fn line(&self, node: &YamlNode) -> usize {
        let start = (node.byte_range().start as usize).min(self.source.len());
        1 + self.source.as_bytes()[..start]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
    }
}

/// A scalar as the decoder sees it: the tag `resolve` (or a quote) chose, the
/// resolved value and the node text.
struct Scalar {
    tag: &'static str,
    resolved: Resolved,
    value: String,
    /// Quoted and block scalars are strings by indication, never resolved.
    indicated_string: bool,
}

fn scalar_of(node: &YamlNode) -> Option<Scalar> {
    let scalar = node.as_scalar()?;
    let value = scalar.as_string();
    let indicated_string = ScalarValue::from_scalar(scalar).style() != ScalarStyle::Plain;
    let resolved = if indicated_string {
        Resolved::Str
    } else {
        resolve(&value)
    };
    Some(Scalar {
        tag: resolved.tag(),
        resolved,
        value,
        indicated_string,
    })
}

fn struct_fields(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    GO_CONFIG_STRUCTS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, fields)| *fields)
}

/// `reflect.Type.String()` of a field type: struct names live in package
/// `config`, `time.Duration` and `time.Time` already carry their package.
fn display_type(go_type: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            if struct_fields(word).is_some() {
                out.push_str("config.");
            }
            out.push_str(word);
            word.clear();
        }
    };
    for character in go_type.chars() {
        if character.is_alphanumeric() || character == '_' {
            word.push(character);
        } else if character == '.' {
            // `time.Duration`: the package qualifier stays, the name is not a config struct.
            out.push_str(&word);
            out.push('.');
            word.clear();
        } else {
            flush(&mut word, &mut out);
            out.push(character);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn terror(
    context: &Context<'_>,
    node: &YamlNode,
    tag: &str,
    go_type: &str,
    errors: &mut Vec<Vec<u8>>,
) {
    let mut line = format!("line {}: cannot unmarshal {tag}", context.line(node)).into_bytes();
    if tag != "!!seq" && tag != "!!map" {
        let value = scalar_of(node)
            .map(|scalar| scalar.value)
            .unwrap_or_default();
        line.extend_from_slice(b" `");
        if value.len() > 10 {
            // Go: value[:7] on bytes.
            line.extend_from_slice(&value.as_bytes()[..7]);
            line.extend_from_slice(b"...");
        } else {
            line.extend_from_slice(value.as_bytes());
        }
        line.push(b'`');
    }
    line.extend_from_slice(format!(" into {}", display_type(go_type)).as_bytes());
    errors.push(line);
}

/// The tag yaml.v3 prints for a node it cannot decode into `go_type`.
fn node_tag(node: &YamlNode) -> &'static str {
    if node.as_mapping().is_some() {
        "!!map"
    } else if node.as_sequence().is_some() {
        "!!seq"
    } else {
        scalar_of(node).map_or("!!str", |scalar| scalar.tag)
    }
}

fn decode_mapping_fields(
    context: &Context<'_>,
    entries: impl Iterator<Item = (YamlNode, YamlNode)>,
    struct_name: &str,
    errors: &mut Vec<Vec<u8>>,
) {
    let Some(fields) = struct_fields(struct_name) else {
        return;
    };
    for (key, value) in entries {
        let Some(key) = scalar_of(&key).map(|scalar| scalar.value) else {
            continue;
        };
        if let Some((_, go_type)) = fields.iter().find(|(name, _)| *name == key) {
            decode(context, &value, go_type, errors);
        }
    }
}

fn decode(context: &Context<'_>, node: &YamlNode, go_type: &str, errors: &mut Vec<Vec<u8>>) {
    let go_type = go_type.strip_prefix('*').unwrap_or(go_type);
    if node.as_alias().is_some() || node.as_tagged().is_some() {
        return;
    }
    let scalar = scalar_of(node);
    if let Some(scalar) = &scalar
        && matches!(scalar.resolved, Resolved::Null)
        && !scalar.indicated_string
    {
        return; // `d.null`: the zero value, no error.
    }
    if let Some(element) = go_type.strip_prefix("[]") {
        if let Some(sequence) = node.as_sequence() {
            for item in sequence.values() {
                decode(context, &item, element, errors);
            }
        } else {
            terror(context, node, node_tag(node), go_type, errors);
        }
        return;
    }
    if let Some(element) = go_type.strip_prefix("map[string]") {
        if let Some(mapping) = node.as_mapping() {
            for (_, value) in mapping.iter() {
                decode(context, &value, element, errors);
            }
        } else {
            terror(context, node, node_tag(node), go_type, errors);
        }
        return;
    }
    if struct_fields(go_type).is_some() {
        if let Some(mapping) = node.as_mapping() {
            decode_mapping_fields(context, mapping.iter(), go_type, errors);
        } else {
            terror(context, node, node_tag(node), go_type, errors);
        }
        return;
    }
    let Some(scalar) = scalar else {
        terror(context, node, node_tag(node), go_type, errors);
        return;
    };
    let accepted = match go_type {
        "string" | "time.Time" => true,
        "bool" => match scalar.resolved {
            Resolved::Bool(_) => true,
            Resolved::Str => matches!(
                scalar.value.as_str(),
                "y" | "Y"
                    | "yes"
                    | "Yes"
                    | "YES"
                    | "on"
                    | "On"
                    | "ON"
                    | "n"
                    | "N"
                    | "no"
                    | "No"
                    | "NO"
                    | "off"
                    | "Off"
                    | "OFF"
            ),
            _ => false,
        },
        "int" | "int64" => match scalar.resolved {
            Resolved::Int(_) => true,
            // A float is truncated unless it exceeds int64 (NaN compares false).
            Resolved::Float(number) => number <= 9.223_372_036_854_775_807e18,
            _ => false,
        },
        "time.Duration" => {
            matches!(scalar.resolved, Resolved::Str)
                && symvault_core::config::parse_go_duration(&scalar.value).is_ok()
        }
        // A Go type this table does not model decodes anything.
        _ => true,
    };
    if !accepted {
        terror(context, node, scalar.tag, go_type, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(source: &str) -> String {
        String::from_utf8_lossy(&unmarshal_errors(source).unwrap_or_default()).into_owned()
    }

    #[test]
    fn durations_take_only_parseable_strings() {
        assert_eq!(errors("sessionTimeout: 20m\n"), "");
        assert_eq!(errors("sessionTimeout: \"0\"\n"), "");
        assert_eq!(errors("sessionTimeout: null\n"), "");
        for (text, tag, shown) in [
            ("12", "!!int", "12"),
            ("0", "!!int", "0"),
            ("1.5", "!!float", "1.5"),
            ("true", "!!bool", "true"),
            ("2026-10-31", "!!timestamp", "2026-10-31"),
            ("not-a-duration", "!!str", "not-a-d..."),
            ("abcdefgh", "!!str", "abcdefgh"),
        ] {
            assert_eq!(
                errors(&format!("sessionTimeout: {text}\n")),
                format!(
                    "yaml: unmarshal errors:\n  line 1: cannot unmarshal {tag} `{shown}` into time.Duration"
                ),
                "{text}"
            );
        }
        assert_eq!(
            errors("sessionTimeout: [1]\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!seq into time.Duration"
        );
        assert_eq!(
            errors("sessionTimeout:\n  a: 1\n"),
            "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!map into time.Duration"
        );
    }

    #[test]
    fn long_values_are_cut_at_seven_bytes_even_inside_a_character() {
        let bytes = unmarshal_errors("sessionTimeout: ééééééééééé\n").expect("error");
        let text = [
            &b"yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `"[..],
            &[0xC3, 0xA9, 0xC3, 0xA9, 0xC3, 0xA9, 0xC3],
            &b"...` into time.Duration"[..],
        ]
        .concat();
        assert_eq!(bytes, text);
    }

    #[test]
    fn other_typed_fields_follow_decode_go() {
        assert_eq!(errors("useTouchID: yes\ngit:\n  auto_push: off\n"), "");
        assert_eq!(errors("authMethod: 12\ndefaultAgent: true\n"), "");
        assert_eq!(errors("clipboard:\n  auto_clear_duration: 1.5\n"), "");
        assert_eq!(
            errors("useTouchID: 12\nmcp:\n  port: abc\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!int `12` into bool\n  line 3: cannot unmarshal !!str `abc` into int"
        );
        assert_eq!(
            errors(
                "mcp:\n  trusted_proxy_ips: x\nagents:\n  cli:\n    allowedPaths: y\n    approvalTimeout: 30\n"
            ),
            "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!str `x` into []string\n  line 5: cannot unmarshal !!str `y` into []string\n  line 6: cannot unmarshal !!int `30` into time.Duration"
        );
        assert_eq!(
            errors("vault: 5\nagents: x\n"),
            "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!int `5` into config.VaultConfig\n  line 2: cannot unmarshal !!str `x` into map[string]config.AgentProfile"
        );
    }
}
