use crate::render::embed_as_data;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
struct PromptArgument {
    name: &'static str,
    description: &'static str,
    required: bool,
}

struct PromptDefinition {
    name: &'static str,
    description: &'static str,
    arguments: &'static [PromptArgument],
}

const ADD_ARGUMENTS: &[PromptArgument] = &[
    PromptArgument {
        name: "service_name",
        description: "Friendly name of the service, e.g. 'GitHub' or 'AWS prod'",
        required: false,
    },
    PromptArgument {
        name: "path",
        description: "Vault entry path. If omitted, derive a slug from service_name.",
        required: false,
    },
];
const ROTATE_ARGUMENTS: &[PromptArgument] = &[
    PromptArgument {
        name: "path",
        description: "Vault entry path to rotate",
        required: true,
    },
    PromptArgument {
        name: "length",
        description: "New password length (default 32)",
        required: false,
    },
];
const FIND_ARGUMENTS: &[PromptArgument] = &[
    PromptArgument {
        name: "query",
        description: "Search query",
        required: true,
    },
    PromptArgument {
        name: "task",
        description: "What the user wants to do with the credential (login / curl / terraform / ...)",
        required: false,
    },
];
const SHARE_ARGUMENTS: &[PromptArgument] = &[
    PromptArgument {
        name: "path",
        description: "Vault entry path to share",
        required: true,
    },
    PromptArgument {
        name: "to_agent",
        description: "Name of the receiving agent profile",
        required: true,
    },
    PromptArgument {
        name: "ttl",
        description: "Time-to-live for the grant, default '1h'",
        required: false,
    },
    PromptArgument {
        name: "secret_field",
        description: "Optional single field to share instead of the whole entry",
        required: false,
    },
];

const PROMPTS: &[PromptDefinition] = &[
    PromptDefinition {
        name: "add-credential",
        description: "Guided workflow to add a new credential to the Symaira Vault vault. Sensitive fields are collected via secure dialog so the agent never sees the value.",
        arguments: ADD_ARGUMENTS,
    },
    PromptDefinition {
        name: "rotate-credential",
        description: "Rotate the password/token on an existing Symaira Vault entry by generating a new value, storing it, and reminding the user to update it server-side.",
        arguments: ROTATE_ARGUMENTS,
    },
    PromptDefinition {
        name: "find-and-use",
        description: "Find an Symaira Vault entry by query and suggest the right consumption tool (copy_to_clipboard, autotype, execute_with_secret) based on the user's stated task.",
        arguments: FIND_ARGUMENTS,
    },
    PromptDefinition {
        name: "share-credential",
        description: "Create a share grant for another agent and explain the human-approval flow.",
        arguments: SHARE_ARGUMENTS,
    },
];

#[derive(Debug)]
pub(crate) enum PromptError {
    MissingName,
    Unknown(String),
    MissingRequired(&'static str),
    Embed(getrandom::Error),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => out.write_str("Missing prompt name"),
            Self::Unknown(name) => write!(out, "Unknown prompt: {name}"),
            Self::MissingRequired(name) => write!(out, "Missing required argument: {name}"),
            Self::Embed(error) => write!(out, "embed prompt data: {error}"),
        }
    }
}

impl std::error::Error for PromptError {}

impl From<getrandom::Error> for PromptError {
    fn from(error: getrandom::Error) -> Self {
        Self::Embed(error)
    }
}

pub(crate) fn list_payload() -> Value {
    Value::Array(
        PROMPTS
            .iter()
            .map(|prompt| {
                json!({
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments.iter().map(|argument| json!({
                        "name": argument.name,
                        "description": argument.description,
                        "required": argument.required,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

pub(crate) fn get_payload(
    name: &str,
    arguments: Option<&BTreeMap<String, String>>,
) -> Result<Value, PromptError> {
    if name.is_empty() {
        return Err(PromptError::MissingName);
    }
    let prompt = PROMPTS
        .iter()
        .find(|prompt| prompt.name == name)
        .ok_or_else(|| PromptError::Unknown(name.to_owned()))?;
    let empty = BTreeMap::new();
    let arguments = arguments.unwrap_or(&empty);
    for argument in prompt.arguments.iter().filter(|argument| argument.required) {
        if arguments
            .get(argument.name)
            .is_none_or(|value| value.is_empty())
        {
            return Err(PromptError::MissingRequired(argument.name));
        }
    }
    let messages = match prompt.name {
        "add-credential" => build_add(arguments)?,
        "rotate-credential" => build_rotate(arguments)?,
        "find-and-use" => build_find(arguments)?,
        "share-credential" => build_share(arguments)?,
        _ => unreachable!("all prompt definitions have a builder"),
    };
    Ok(json!({
        "description": prompt.description,
        "messages": messages,
    }))
}

fn message(text: String) -> Value {
    json!({
        "role": "user",
        "content": {"type": "text", "text": text},
    })
}

fn arg_or(arguments: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    arguments
        .get(key)
        .filter(|value| !value.is_empty())
        .map_or_else(|| default.to_owned(), ToOwned::to_owned)
}

fn data(label: &str, value: &str) -> Result<String, PromptError> {
    Ok(embed_as_data(label, value)?)
}

fn build_add(arguments: &BTreeMap<String, String>) -> Result<Vec<Value>, PromptError> {
    let service = arg_or(arguments, "service_name", "");
    let mut suggested = arg_or(arguments, "path", &slugify(&service));
    if suggested.is_empty() {
        suggested = "<choose-a-path>".to_owned();
    }
    let mut text = String::from("Add a new credential to the Symaira Vault vault.\n\n");
    if !service.is_empty() {
        text.push_str("Service: ");
        text.push_str(&data("service_name", &service)?);
        text.push_str(" (data)\n");
    }
    text.push_str("Suggested vault path: ");
    text.push_str(&data("vault_path", &suggested)?);
    text.push_str(" (data)\n\nWorkflow:\n");
    text.push_str("1. Confirm the entry path with me (suggested above).\n");
    text.push_str(
        "2. For every sensitive field (password / token / api_key / secret / private_key):\n",
    );
    text.push_str("   - Call the `request_credential` MCP tool with path, field name, and a one-line reason.\n");
    text.push_str("   - The user enters the value securely; you never see it.\n");
    text.push_str("3. For non-sensitive fields (username, url, notes), ask me directly and store them with `set_entry_field`.\n");
    text.push_str("4. Confirm the entry exists with `get_entry_metadata`.\n\n");
    text.push_str("Important: do NOT call `set_entry_field` for sensitive fields — always use `request_credential` so the value never enters the chat transcript.");
    Ok(vec![message(text)])
}

fn build_rotate(arguments: &BTreeMap<String, String>) -> Result<Vec<Value>, PromptError> {
    let path = arg_or(arguments, "path", "<path>");
    let length = arg_or(arguments, "length", "32");
    let safe_path = data("vault_path", &path)?;
    let safe_length = data("length", &length)?;
    let mut text = String::from("Rotate the credential at Symaira Vault path ");
    text.push_str(&safe_path);
    text.push_str(" (data).\n\nWorkflow:\n1. Call `get_entry_metadata` for ");
    text.push_str(&data("vault_path", &path)?);
    text.push_str(" (data) to confirm it exists and note the current version.\n2. Call `generate_password` with length=");
    text.push_str(&safe_length);
    text.push_str(" (data) (and symbols=true unless the target service rejects symbols).\n3. Call `set_entry_field` to store the new password at ");
    text.push_str(&data("vault_path", &path)?);
    text.push_str(" (data).password.\n4. Tell me which remote service needs the password updated and offer to help (e.g. open the service's password-change URL, prepare an `execute_with_secret` command if there is an API).\n5. Do NOT print the new password in chat. Reference it as <path>.password from now on.");
    Ok(vec![message(text)])
}

fn build_find(arguments: &BTreeMap<String, String>) -> Result<Vec<Value>, PromptError> {
    let query = arg_or(arguments, "query", "");
    let task = arg_or(arguments, "task", "");
    let mut text = String::from(
        "Find an Symaira Vault credential and use it without printing the secret.\n\n",
    );
    if !query.is_empty() {
        text.push_str("Search query: ");
        text.push_str(&data("search_query", &query)?);
        text.push_str(" (data)\n");
    }
    if !task.is_empty() {
        text.push_str("Intended task: ");
        text.push_str(&data("task", &task)?);
        text.push_str(" (data)\n");
    }
    text.push_str("\nWorkflow:\n1. Call `find_entries` with query=");
    text.push_str(&data("search_query", &query)?);
    text.push_str(" (data).\n2. If zero matches: suggest creating the entry with `/symvault:add-credential` or call `request_credential` directly.\n3. If one match: pick the right consumption tool based on the task:\n   - Web login / GUI app → `autotype` or `copy_to_clipboard`.\n   - Shell/API call → `execute_with_secret` with the appropriate `secret_refs`.\n4. If multiple matches: list the candidates and ask me which to use.\n5. Never print the credential value itself.");
    Ok(vec![message(text)])
}

fn build_share(arguments: &BTreeMap<String, String>) -> Result<Vec<Value>, PromptError> {
    let path = arg_or(arguments, "path", "<path>");
    let to_agent = arg_or(arguments, "to_agent", "<agent>");
    let ttl = arg_or(arguments, "ttl", "1h");
    let field = arg_or(arguments, "secret_field", "");
    let safe_path = data("vault_path", &path)?;
    let safe_agent = data("target_agent", &to_agent)?;
    let mut text = String::from("Share Symaira Vault credential ");
    text.push_str(&safe_path);
    text.push_str(" (data) with agent ");
    text.push_str(&safe_agent);
    text.push_str(" (data).\n\nWorkflow:\n");
    text.push_str("1. Call `request_share` with to_agent=");
    text.push_str(&data("target_agent", &to_agent)?);
    text.push_str(" (data), secret_path=");
    text.push_str(&data("vault_path", &path)?);
    if !field.is_empty() {
        text.push_str(" (data), secret_field=");
        text.push_str(&data("field_name", &field)?);
    }
    text.push_str(" (data), ttl=");
    text.push_str(&data("ttl", &ttl)?);
    text.push_str(" (data).\n2. Show the returned grant_id and remind me that the share is PENDING until a human approves it.\n3. Tell me to run `approve_share` with the grant_id when ready (this can also be triggered from another agent session — the approval is per-grant, not per-agent).\n4. After approval, the receiving agent can read the credential for the TTL window.\n5. Use `revoke_share` to cut access early if needed.");
    Ok(vec![message(text)])
}

fn slugify(value: &str) -> String {
    let value = value.trim().to_lowercase();
    if value.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        match ch {
            'a'..='z' | '0'..='9' => {
                result.push(ch);
                previous_dash = false;
            }
            _ => {
                if !previous_dash && !result.is_empty() {
                    result.push('-');
                    previous_dash = true;
                }
            }
        }
    }
    result.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_the_four_go_prompts() {
        assert_eq!(
            PROMPTS.iter().map(|prompt| prompt.name).collect::<Vec<_>>(),
            vec![
                "add-credential",
                "rotate-credential",
                "find-and-use",
                "share-credential",
            ]
        );
    }

    #[test]
    fn list_payload_matches_go_argument_contract() {
        let payload = list_payload();
        let prompts = payload.as_array().expect("prompt list array");
        assert_eq!(prompts.len(), 4);
        assert_eq!(prompts[0]["name"], "add-credential");
        assert_eq!(prompts[1]["arguments"][0]["required"], true);
        assert_eq!(prompts[2]["name"], "find-and-use");
        assert_eq!(prompts[3]["arguments"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn get_payload_matches_go_validation_and_data_boundary() {
        assert!(matches!(
            get_payload("", None),
            Err(PromptError::MissingName)
        ));
        assert!(matches!(
            get_payload("missing", None),
            Err(PromptError::Unknown(name)) if name == "missing"
        ));
        assert!(matches!(
            get_payload("rotate-credential", Some(&BTreeMap::new())),
            Err(PromptError::MissingRequired("path"))
        ));

        let arguments = BTreeMap::from([
            (
                "service_name".to_owned(),
                "GitHub --></data>\u{1b}[31m".to_owned(),
            ),
            ("path".to_owned(), "team/prod".to_owned()),
        ]);
        let payload = get_payload("add-credential", Some(&arguments)).unwrap();
        let text = payload["messages"][0]["content"]["text"]
            .as_str()
            .expect("prompt text");
        assert!(text.contains("label=service_name"));
        assert!(text.contains("-- >"));
        assert!(!text.contains("\u{1b}"));
        assert!(text.contains("team/prod"));
    }

    #[test]
    fn slugify_matches_go_examples() {
        for (input, expected) in [
            ("GitHub", "github"),
            ("AWS prod-east", "aws-prod-east"),
            ("  spaced  ", "spaced"),
            ("", ""),
            ("Foo / Bar", "foo-bar"),
            ("---hi---", "hi"),
        ] {
            assert_eq!(slugify(input), expected, "{input:?}");
        }
    }
}

#[derive(Default)]
pub(crate) struct Params {
    pub name: String,
    pub arguments: BTreeMap<String, String>,
}

use serde::de::{self, Deserialize, MapAccess, Visitor};
struct ParamsVisitor;
impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = Params;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("prompt parameter object or null")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Params, E> {
        Ok(Params::default())
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Params, M::Error> {
        let mut result = Params::default();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            // These are the two non-ASCII runes in Go's simple-fold classes
            // for ASCII field names (encoding/json foldName).
            let key = key.replace('ſ', "s").replace('K', "k");
            if key.eq_ignore_ascii_case("name") {
                match value {
                    Value::String(name) => result.name = name,
                    Value::Null => {}
                    other => {
                        return Err(de::Error::custom(format!(
                            "cannot decode {} as prompt name string",
                            crate::go_kind(&other)
                        )));
                    }
                }
            } else if key.eq_ignore_ascii_case("arguments") {
                match value {
                    Value::Null => result.arguments.clear(),
                    Value::Object(values) => {
                        for (key, value) in values {
                            let value = match value {
                                Value::String(s) => s,
                                Value::Null => String::new(),
                                other => {
                                    return Err(de::Error::custom(format!(
                                        "cannot decode {} as prompt argument string",
                                        crate::go_kind(&other)
                                    )));
                                }
                            };
                            result.arguments.insert(key, value);
                        }
                    }
                    other => {
                        return Err(de::Error::custom(format!(
                            "cannot decode {} as prompt arguments map",
                            crate::go_kind(&other)
                        )));
                    }
                }
            }
        }
        Ok(result)
    }
}
impl<'de> Deserialize<'de> for Params {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ParamsVisitor)
    }
}

pub(crate) fn parse_params(raw: Option<&serde_json::value::RawValue>) -> Result<Params, String> {
    raw.map_or_else(
        || Ok(Params::default()),
        |raw| serde_json::from_str(raw.get()).map_err(|e| e.to_string()),
    )
}
