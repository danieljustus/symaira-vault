//! MCP-001: the JSON-RPC envelope, the initialize handshake and the line-framed
//! stdio dispatch loop, ported from `internal/mcp/transport` and
//! `internal/mcp/server/protocol.go` at the pinned Go oracle.
//!
//! The observable contract is the exact byte stream the server writes, so the
//! types here mirror the oracle's Go struct field order rather than a shape that
//! would read more naturally in Rust. `serde` emits struct fields in declaration
//! order, so [`Message`]'s fields are declared in the Go order
//! (`error`, `jsonrpc`, `method`, `id`, `params`, `result`) and the `omitempty`
//! tags become `skip_serializing_if`.
//!
//! An `id` is carried as a raw JSON value, never decoded into a Rust type: the
//! oracle echoes the client's ID bytes back verbatim, and an explicit
//! `"id": null` is a *present* ID — a four-byte value — not an absent one. That
//! distinction is what separates a request from a notification.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

mod call;
mod prompts;
pub mod render;
mod tools;
pub use call::{ToolCallResult, ToolCallRuntime};
pub use tools::ToolListConfig;

/// The newest protocol version this server speaks.
pub const LATEST_SUPPORTED_PROTOCOL_VERSION: &str = "2025-11-25";

/// The version the HTTP transport defaults to. Kept here because it is part of
/// the same oracle constant block; MCP-001 itself only exercises stdio.
pub const DEFAULT_HTTP_PROTOCOL_VERSION: &str = "2025-03-26";

/// Every protocol version the server accepts, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The deepest nesting a frame may carry and still be dispatched.
///
/// Counted as total depth, including the enclosing frame object. The oracle
/// bounds nesting through `encoding/json`, which dispatches a frame 10000 levels
/// deep and rejects 10001; the generator measures that boundary by binary search
/// rather than copying the constant. Rust needs an explicit guard because `serde_json`'s own
/// recursion limit does not apply here: the deep payload lands in a field the
/// `Message` struct ignores, and skipping an ignored field uses a non-recursive
/// scanner. Without this check Rust would accept frames the oracle rejects —
/// the more permissive side of a divergence, and the one that matters for stack
/// safety once `params` is actually decoded by MCP-002/003.
pub const MAX_ACCEPTED_NESTING_DEPTH: usize = 10_000;

/// JSON-RPC 2.0 error codes used by the oracle.
pub mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const SERVER_ERROR: i32 = -32000;
}

/// Surfaced to every client in the initialize response so agents can discover
/// the "consume a secret without seeing it" pattern instead of dead-ending on a
/// redacted reference. Byte-identical to the oracle's `serverInstructions`.
pub const SERVER_INSTRUCTIONS: &str = concat!(
    "SymVault redacts secret values by default: get_entry and get_entry_value ",
    "return a reference (a \"handle\", e.g. op://path/field) instead of the plaintext, plus a per-field ",
    "\"usage\" hint. Do not try to resolve that reference yourself — you are not meant to see the value.\n",
    "\n",
    "To consume a secret without seeing it:\n",
    "  - run_command / execute_with_secret: pass \"path.field\" (not the op:// handle) as an env map value, ",
    "e.g. {\"env\": {\"GH_TOKEN\": \"github.token\"}}. SymVault resolves and injects it; only the child ",
    "process sees the value.\n",
    "  - copy_to_clipboard / autotype: for interactive, human-facing use.\n",
    "  - request_credential: ask the user to supply or confirm a credential directly.\n",
    "\n",
    "If a tool call is denied (run_denied / not in allowed_tools), the error names the exact profile fix — ",
    "read it before giving up. See docs/agent-integration.md for the full recipe and a runner-profile example."
);

/// A JSON-RPC 2.0 message. Field order matches the Go oracle's struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<RpcError>,
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "str_is_empty", default)]
    pub method: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_present_raw"
    )]
    pub id: Option<Box<RawValue>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_present_raw"
    )]
    pub params: Option<Box<RawValue>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_present_raw"
    )]
    pub result: Option<Box<RawValue>>,
}

fn str_is_empty(value: &str) -> bool {
    value.is_empty()
}

/// Distinguishes an absent key from a key whose value is `null`.
///
/// `Option<Box<RawValue>>` would otherwise collapse an explicit `"id": null`
/// into `None` and turn a request into a notification — the client would then
/// wait forever for an answer the server decided not to send. serde only calls
/// this when the key is present, so `#[serde(default)]` covers the absent case
/// and everything reaching here is a present value, `null` included. This
/// mirrors the oracle, where the field is a `json.RawMessage` and the emptiness
/// test is `len(ID) == 0`, which four bytes of `null` do not satisfy.
fn deserialize_present_raw<'de, D>(deserializer: D) -> Result<Option<Box<RawValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Box::<RawValue>::deserialize(deserializer)?;
    // `json.Marshal` runs `compact` over a RawMessage on the way out, which
    // drops interior whitespace and escapes `<`, `>` and `&`. Normalising on
    // the way in means the echoed value carries the oracle's bytes without the
    // encoder having to special-case raw fields. It stays a textual transform,
    // so an id beyond i64 survives exactly.
    let compacted = symvault_gojson::compact(raw.get());
    RawValue::from_string(compacted)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Tools support. `listChanged` is `omitempty` in the oracle, so a false value
/// serializes the capability as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "is_false", default)]
    pub list_changed: bool,
}

/// Resources support.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "is_false", default)]
    pub subscribe: bool,
    #[serde(rename = "listChanged", skip_serializing_if = "is_false", default)]
    pub list_changed: bool,
}

/// Prompts support.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "is_false", default)]
    pub list_changed: bool,
}

/// Logging support. Carries no fields in the oracle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingCapability {}

/// Server capabilities. Field order matches the Go oracle's struct, because the
/// emitted key order is part of the byte contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prompts: Option<PromptsCapability>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub logging: Option<LoggingCapability>,
}

/// Information about the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// The result of an `initialize` request. Field order matches the Go oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(skip_serializing_if = "str_is_empty", default)]
    pub instructions: String,
}

/// A JSON-RPC 2.0 error. Field order matches the Go oracle's struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<serde_json::Value>,
    pub message: String,
    pub code: i32,
}

impl Message {
    /// A notification carries no `id` at all. An explicit `"id": null` is a
    /// present ID and therefore a request, matching the oracle's `len(ID) == 0`.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    pub fn is_request(&self) -> bool {
        !self.method.is_empty() && !self.is_notification()
    }

    pub fn is_response(&self) -> bool {
        self.result.is_some() || self.error.is_some()
    }

    /// Builds a response whose result is a typed value, preserving that type's
    /// declared field order.
    fn response_from<T: Serialize>(id: Option<Box<RawValue>>, result: &T) -> Result<Self, Error> {
        let raw = serde_json::value::to_raw_value(result).map_err(Error::Serialize)?;
        Ok(Message {
            error: None,
            jsonrpc: "2.0".to_string(),
            method: String::new(),
            id,
            params: None,
            result: Some(raw),
        })
    }

    fn response(id: Option<Box<RawValue>>, result: serde_json::Value) -> Result<Self, Error> {
        let raw = serde_json::value::to_raw_value(&result).map_err(Error::Serialize)?;
        Ok(Message {
            error: None,
            jsonrpc: "2.0".to_string(),
            method: String::new(),
            id,
            params: None,
            result: Some(raw),
        })
    }

    fn error_response(
        id: Option<Box<RawValue>>,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> Self {
        Message {
            error: Some(RpcError {
                data,
                message: message.to_string(),
                code,
            }),
            jsonrpc: "2.0".to_string(),
            method: String::new(),
            id,
            params: None,
            result: None,
        }
    }
}

/// Failures the dispatch loop itself can raise, as opposed to protocol errors,
/// which travel back to the client as an [`RpcError`].
#[derive(Debug)]
pub enum Error {
    Serialize(serde_json::Error),
    Catalog(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Serialize(e) => write!(f, "serialize: {e}"),
            Error::Catalog(e) => write!(f, "tool catalog: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// `true` when the version is one the server speaks.
pub fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Echoes a supported request back and otherwise negotiates down to the latest
/// version. An unknown version is never an error.
pub fn negotiate_protocol_version(requested: &str) -> &str {
    if !requested.is_empty() && is_supported_protocol_version(requested) {
        requested
    } else {
        LATEST_SUPPORTED_PROTOCOL_VERSION
    }
}

/// Extracts the requested protocol version from an `initialize` params value,
/// reproducing `encoding/json`'s decoding of the oracle's `InitializeParams`.
///
/// Three of its behaviors are load-bearing and none of them are serde defaults:
///
///   - `null` is a no-op against any target, so `"params": null` and
///     `"protocolVersion": null` both leave the zero value and negotiate to the
///     latest version. serde would reject both, refusing the handshake to a
///     client sending entirely legal JSON-RPC.
///   - Field names match case-insensitively when no exact match exists, so
///     `PROTOCOLVERSION` selects a real version. serde would ignore the key and
///     silently negotiate a *different* version than the oracle.
///   - `clientInfo` is typed `*ClientInfo`, so a non-object there is an error.
///     Ignoring it would make this port more permissive than the oracle, which
///     is the wrong direction.
///
/// `capabilities` is a `json.RawMessage` in the oracle and accepts anything.
fn requested_protocol_version(params: &RawValue) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(params.get()).map_err(|err| err.to_string())?;

    let object = match &value {
        serde_json::Value::Null => return Ok(String::new()),
        serde_json::Value::Object(map) => map,
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type server.InitializeParams",
                go_kind(other)
            ));
        }
    };

    // Go prefers an exact field match and falls back to a case-insensitive one.
    let lookup = |name: &str| -> Option<&serde_json::Value> {
        object.get(name).or_else(|| {
            object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
    };

    if let Some(client_info) = lookup("clientInfo") {
        match client_info {
            serde_json::Value::Null | serde_json::Value::Object(_) => {}
            other => {
                return Err(format!(
                    "json: cannot unmarshal {} into Go struct field InitializeParams.clientInfo of type server.ClientInfo",
                    go_kind(other)
                ));
            }
        }
    }

    match lookup("protocolVersion") {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(version)) => Ok(version.clone()),
        Some(other) => Err(format!(
            "json: cannot unmarshal {} into Go struct field InitializeParams.protocolVersion of type string",
            go_kind(other)
        )),
    }
}

/// Go's name for a JSON value's kind, as it appears in decoder errors. The text
/// is masked in the differential, but a non-empty diagnostic is still asserted.
fn go_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Handles MCP protocol messages for one connection.
pub struct ProtocolHandler {
    server_name: String,
    server_version: String,
    tool_list_config: ToolListConfig,
    tool_call_runtime: Option<std::sync::Arc<dyn ToolCallRuntime>>,
    initialized: bool,
}

impl ProtocolHandler {
    pub fn new(server_name: impl Into<String>, server_version: impl Into<String>) -> Self {
        ProtocolHandler {
            server_name: server_name.into(),
            server_version: server_version.into(),
            tool_list_config: ToolListConfig::default(),
            tool_call_runtime: None,
            initialized: false,
        }
    }

    /// Constructs a handler with explicitly injected runtime/profile inputs for
    /// the native tools/list surface. No capability detection occurs here.
    pub fn with_tool_list_config(
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        tool_list_config: ToolListConfig,
    ) -> Self {
        ProtocolHandler {
            server_name: server_name.into(),
            server_version: server_version.into(),
            tool_list_config,
            tool_call_runtime: None,
            initialized: false,
        }
    }

    /// Constructs a handler with an explicitly injected tools/call runtime.
    /// The runtime is the only path to storage and policy; construction itself
    /// performs no vault or platform probing.
    pub fn with_tool_call_runtime(
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        runtime: std::sync::Arc<dyn ToolCallRuntime>,
    ) -> Self {
        ProtocolHandler {
            server_name: server_name.into(),
            server_version: server_version.into(),
            tool_list_config: ToolListConfig::default(),
            tool_call_runtime: Some(runtime),
            initialized: false,
        }
    }

    pub fn set_tool_list_config(&mut self, tool_list_config: ToolListConfig) {
        self.tool_list_config = tool_list_config;
    }

    pub fn set_tool_call_runtime(&mut self, runtime: Option<std::sync::Arc<dyn ToolCallRuntime>>) {
        self.tool_call_runtime = runtime;
    }

    /// Whether `initialize` has been handled on this connection.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Dispatches one parsed message. `Ok(None)` means "write nothing", which is
    /// the entire contract for notifications.
    pub fn handle_message(&mut self, msg: &Message) -> Result<Option<Message>, Error> {
        if msg.is_response() {
            return Ok(None);
        }
        match msg.method.as_str() {
            "initialize" => self.handle_initialize(msg).map(Some),
            "initialized" | "notifications/initialized" => Ok(None),
            "ping" => Message::response(msg.id.clone(), serde_json::json!({})).map(Some),
            "tools/list" => self.handle_tools_list(msg).map(Some),
            "tools/call" => self.handle_tools_call(msg).map(Some),
            "prompts/list" | "prompts/get" => self.handle_prompts(msg).map(Some),
            _ => {
                if msg.is_notification() {
                    return Ok(None);
                }
                Ok(Some(Message::error_response(
                    msg.id.clone(),
                    error_code::METHOD_NOT_FOUND,
                    &format!("Method not found: {}", msg.method),
                    None,
                )))
            }
        }
    }

    fn handle_initialize(&mut self, msg: &Message) -> Result<Message, Error> {
        // Absent params is not an error: the oracle's ParseParams returns early
        // and negotiation proceeds with an empty requested version.
        let requested = match &msg.params {
            None => String::new(),
            Some(raw) => match requested_protocol_version(raw) {
                Ok(version) => version,
                Err(err) => {
                    return Ok(Message::error_response(
                        msg.id.clone(),
                        error_code::INVALID_PARAMS,
                        "Invalid params",
                        Some(serde_json::Value::String(err)),
                    ));
                }
            },
        };

        let negotiated = negotiate_protocol_version(&requested);

        let result = InitializeResult {
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: false,
                }),
                resources: None,
                prompts: Some(PromptsCapability {
                    list_changed: false,
                }),
                logging: None,
            },
            server_info: ServerInfo {
                name: self.server_name.clone(),
                version: self.server_version.clone(),
            },
            protocol_version: negotiated.to_string(),
            instructions: SERVER_INSTRUCTIONS.to_string(),
        };

        self.initialized = true;
        Message::response_from(msg.id.clone(), &result)
    }

    fn handle_prompts(&self, msg: &Message) -> Result<Message, Error> {
        if !self.initialized {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::SERVER_ERROR,
                "Server not initialized",
                None,
            ));
        }
        if msg.method == "prompts/list" {
            return Message::response(
                msg.id.clone(),
                serde_json::json!({"prompts": prompts::list_payload()}),
            );
        }
        let params = match prompts::parse_params(msg.params.as_deref()) {
            Ok(params) => params,
            Err(error) => {
                return Ok(Message::error_response(
                    msg.id.clone(),
                    error_code::INVALID_PARAMS,
                    "Invalid params",
                    Some(serde_json::Value::String(error)),
                ));
            }
        };
        match prompts::get_payload(&params.name, Some(&params.arguments)) {
            Ok(payload) => Message::response(msg.id.clone(), payload),
            Err(error) => {
                let code = if matches!(error, prompts::PromptError::Embed(_)) {
                    error_code::INTERNAL_ERROR
                } else {
                    error_code::INVALID_PARAMS
                };
                Ok(Message::error_response(
                    msg.id.clone(),
                    code,
                    &error.to_string(),
                    None,
                ))
            }
        }
    }

    fn handle_tools_list(&self, msg: &Message) -> Result<Message, Error> {
        if !self.initialized {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::SERVER_ERROR,
                "Server not initialized",
                None,
            ));
        }

        let include_all = msg
            .params
            .as_deref()
            .and_then(|params| serde_json::from_str::<serde_json::Value>(params.get()).ok())
            .and_then(|params| {
                params
                    .get("include_all_tools")
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false);
        let tools =
            tools::list_tools(&self.tool_list_config, include_all).map_err(Error::Catalog)?;
        Message::response(msg.id.clone(), serde_json::json!({"tools": tools}))
    }

    fn handle_tools_call(&self, msg: &Message) -> Result<Message, Error> {
        if !self.initialized {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::SERVER_ERROR,
                "Server not initialized",
                None,
            ));
        }

        // Go checks the server pointer before parsing params. Keep this order
        // so a locked default handler returns vault-locked even for malformed
        // arguments, without probing any platform or storage capability.
        let Some(runtime) = self.tool_call_runtime.as_ref() else {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::INTERNAL_ERROR,
                "vault locked: run 'symvault unlock' first",
                None,
            ));
        };

        let (name, arguments) = match call::parse_params(msg.params.as_deref().map(RawValue::get)) {
            Ok(params) => params,
            Err(error) => {
                return Ok(Message::error_response(
                    msg.id.clone(),
                    error_code::INVALID_PARAMS,
                    "Invalid params",
                    Some(serde_json::Value::String(error)),
                ));
            }
        };
        if !arguments.is_object() {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::INTERNAL_ERROR,
                &format!(
                    "parse arguments: json: cannot unmarshal {} into Go value of type map[string]interface {{}}",
                    go_kind(&arguments)
                ),
                None,
            ));
        }
        let known = tools::contains_tool(&name).map_err(Error::Catalog)?;
        if !known {
            return Ok(Message::error_response(
                msg.id.clone(),
                error_code::INTERNAL_ERROR,
                &format!("unknown tool: {name}"),
                None,
            ));
        }
        if let Err(result) = runtime.authorize(&name, &arguments) {
            return Message::response(msg.id.clone(), call::payload(result));
        }
        match runtime.call(&name, &arguments) {
            Ok(result) => Message::response(msg.id.clone(), call::payload(result)),
            Err(error) => Ok(Message::error_response(
                msg.id.clone(),
                error_code::INTERNAL_ERROR,
                &error,
                None,
            )),
        }
    }
}

/// Feeds one raw input line through the handler and returns the line the server
/// would write to stdout, or `None` when it writes nothing.
///
/// This mirrors the oracle's `handleLine` exactly, including the order of its
/// guards: a malformed frame answers `-32700` and the stream keeps going, and a
/// blank line is *not* skipped — the oracle reads with the delimiter retained,
/// so an empty line arrives as `"\n"` and reaches the decoder.
pub fn handle_line(line: &str, handler: &mut ProtocolHandler) -> Result<Option<String>, Error> {
    if max_nesting_depth(line) > MAX_ACCEPTED_NESTING_DEPTH {
        return encode(&Message::error_response(
            None,
            error_code::PARSE_ERROR,
            "Parse error",
            Some(serde_json::Value::String(
                "exceeded max nesting depth".to_string(),
            )),
        ))
        .map(Some);
    }

    // Go's json.Unmarshal treats a literal `null` as a no-op against any target,
    // so the oracle ends up with a zero-valued Message whose jsonrpc is empty
    // and answers -32600. serde instead fails to build the struct, which would
    // have answered -32700. Neither is safer; matching the oracle is free.
    if line.trim() == "null" {
        return encode(&Message::error_response(
            None,
            error_code::INVALID_REQUEST,
            "Invalid Request",
            Some(serde_json::Value::String("jsonrpc must be 2.0".to_string())),
        ))
        .map(Some);
    }

    let msg: Message = match serde_json::from_str(line) {
        Ok(msg) => msg,
        Err(err) => {
            return encode(&Message::error_response(
                None,
                error_code::PARSE_ERROR,
                "Parse error",
                Some(serde_json::Value::String(err.to_string())),
            ))
            .map(Some);
        }
    };

    if msg.jsonrpc != "2.0" {
        return encode(&Message::error_response(
            msg.id.clone(),
            error_code::INVALID_REQUEST,
            "Invalid Request",
            Some(serde_json::Value::String("jsonrpc must be 2.0".to_string())),
        ))
        .map(Some);
    }

    if msg.is_notification() {
        handler.handle_message(&msg)?;
        return Ok(None);
    }

    if msg.method.is_empty() {
        return encode(&Message::error_response(
            msg.id.clone(),
            error_code::INVALID_REQUEST,
            "Invalid Request",
            Some(serde_json::Value::String("method is required".to_string())),
        ))
        .map(Some);
    }

    let mut response = handler.handle_message(&msg)?.unwrap_or_else(|| {
        Message::error_response(
            msg.id.clone(),
            error_code::INTERNAL_ERROR,
            "Internal error",
            None,
        )
    });

    if response.id.is_none() {
        response.id = msg.id.clone();
    }

    encode(&response).map(Some)
}

/// Feeds one raw input line as *bytes*.
///
/// The oracle's frames are `[]byte` and it does not require valid UTF-8: a
/// frame whose id contains invalid bytes is accepted and those bytes are echoed
/// back on stdout verbatim. Rust does not reproduce that. `serde_json`'s
/// `RawValue` is backed by `str`, so a byte-verbatim echo is unreachable without
/// replacing the JSON envelope wholesale, and the adjudicated behavior is to
/// reject the frame fail-closed with `-32700`.
///
/// That is a deliberate, recorded divergence — see the `divergences` block in
/// `testdata/port/mcp/stdio-hygiene.json` — and it is the stricter of the two:
/// the oracle's behavior places attacker-chosen invalid bytes onto the same
/// stdout stream the client parses for framing.
pub fn handle_line_bytes(
    line: &[u8],
    handler: &mut ProtocolHandler,
) -> Result<Option<String>, Error> {
    match std::str::from_utf8(line) {
        Ok(text) => handle_line(text, handler),
        Err(err) => encode(&Message::error_response(
            None,
            error_code::PARSE_ERROR,
            "Parse error",
            Some(serde_json::Value::String(err.to_string())),
        ))
        .map(Some),
    }
}

/// Runs a whole input stream and returns every line written to stdout.
///
/// Input is split the way the oracle's reader splits it: on `\n`, with a
/// trailing newline producing no extra empty frame.
pub fn run_stream(input: &str, handler: &mut ProtocolHandler) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for line in terminated_lines(input) {
        if let Some(written) = handle_line(line, handler)? {
            out.push(written);
        }
    }
    Ok(out)
}

/// Splits a stream the way the oracle's reader consumes it: into *newline-
/// terminated* frames only.
///
/// A trailing fragment with no newline is dropped. That is not a tidiness
/// choice — the oracle reads with `ReadString('\n')`, which returns the partial
/// data together with `io.EOF`, and the read loop returns on `io.EOF` before
/// looking at what it just read. So the last line of a stream that ends without
/// a newline is never dispatched and is never answered. A client that omits the
/// final newline gets silence, not an error.
fn terminated_lines(input: &str) -> impl Iterator<Item = &str> {
    let mut rest = input;
    std::iter::from_fn(move || match rest.find('\n') {
        Some(idx) => {
            let line = &rest[..idx];
            rest = &rest[idx + 1..];
            Some(line)
        }
        None => None,
    })
}

/// Deepest `[`/`{` nesting in a frame, ignoring brackets inside string literals.
///
/// A scan rather than a parse: it has to run before the frame is decoded, and it
/// must not itself recurse, or it would reintroduce the stack exhaustion it
/// exists to prevent.
fn max_nesting_depth(line: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in line.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Encodes a frame the way the oracle's `json.Marshal` would.
///
/// The escaping matters because the method name and the echoed id are
/// attacker-chosen: `serde_json` would put raw `<`, `>` and `&` onto the same
/// stdout stream the client parses for framing, where Go emits `\u003c` and
/// friends.
fn encode(msg: &Message) -> Result<String, Error> {
    symvault_gojson::to_string(msg).map_err(Error::Serialize)
}
