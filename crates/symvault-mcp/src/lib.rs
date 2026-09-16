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

/// The newest protocol version this server speaks.
pub const LATEST_SUPPORTED_PROTOCOL_VERSION: &str = "2025-11-25";

/// The version the HTTP transport defaults to. Kept here because it is part of
/// the same oracle constant block; MCP-001 itself only exercises stdio.
pub const DEFAULT_HTTP_PROTOCOL_VERSION: &str = "2025-03-26";

/// Every protocol version the server accepts, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

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
    Box::<RawValue>::deserialize(deserializer).map(Some)
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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Serialize(e) => write!(f, "serialize: {e}"),
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

/// The parameters of an `initialize` request. Only `protocolVersion` affects the
/// response; `clientInfo` and `capabilities` are accepted and ignored, as in the
/// oracle.
#[derive(Debug, Deserialize)]
struct InitializeParams {
    #[serde(default, rename = "protocolVersion")]
    protocol_version: String,
}

/// Handles MCP protocol messages for one connection.
pub struct ProtocolHandler {
    server_name: String,
    server_version: String,
    initialized: bool,
}

impl ProtocolHandler {
    pub fn new(server_name: impl Into<String>, server_version: impl Into<String>) -> Self {
        ProtocolHandler {
            server_name: server_name.into(),
            server_version: server_version.into(),
            initialized: false,
        }
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
            Some(raw) => match serde_json::from_str::<InitializeParams>(raw.get()) {
                Ok(params) => params.protocol_version,
                Err(err) => {
                    return Ok(Message::error_response(
                        msg.id.clone(),
                        error_code::INVALID_PARAMS,
                        "Invalid params",
                        Some(serde_json::Value::String(err.to_string())),
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
}

/// Feeds one raw input line through the handler and returns the line the server
/// would write to stdout, or `None` when it writes nothing.
///
/// This mirrors the oracle's `handleLine` exactly, including the order of its
/// guards: a malformed frame answers `-32700` and the stream keeps going, and a
/// blank line is *not* skipped — the oracle reads with the delimiter retained,
/// so an empty line arrives as `"\n"` and reaches the decoder.
pub fn handle_line(line: &str, handler: &mut ProtocolHandler) -> Result<Option<String>, Error> {
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

/// Runs a whole input stream and returns every line written to stdout.
///
/// Input is split the way the oracle's reader splits it: on `\n`, with a
/// trailing newline producing no extra empty frame.
pub fn run_stream(input: &str, handler: &mut ProtocolHandler) -> Result<Vec<String>, Error> {
    let body = input.strip_suffix('\n').unwrap_or(input);
    if body.is_empty() && input.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in body.split('\n') {
        if let Some(written) = handle_line(line, handler)? {
            out.push(written);
        }
    }
    Ok(out)
}

fn encode(msg: &Message) -> Result<String, Error> {
    serde_json::to_string(msg).map_err(Error::Serialize)
}
