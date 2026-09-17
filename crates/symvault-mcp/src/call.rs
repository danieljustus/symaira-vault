use serde_json::Value;

/// A result returned by an MCP tool handler.
#[derive(Clone, Debug, Default)]
pub struct ToolCallResult {
    pub text: String,
    pub is_error: bool,
    pub structured_content: Option<Value>,
}

impl ToolCallResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
            ..Self::default()
        }
    }

    pub fn structured(text: impl Into<String>, value: Value) -> Self {
        Self {
            text: text.into(),
            structured_content: Some(value),
            ..Self::default()
        }
    }
}

/// Injected runtime boundary for `tools/call`.
///
/// The protocol layer owns ordering and wire semantics. The runtime owns the
/// actual vault/store and policy implementation, which keeps this crate free
/// of ambient vault, keychain, GUI, and clipboard access. Authorization is
/// deliberately a separate step and happens before `call` can touch storage.
pub trait ToolCallRuntime: Send + Sync {
    /// Return a tool-result error for a denied call, matching Go's
    /// `validateToolAccess` path. This is not a JSON-RPC transport error.
    fn authorize(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult>;

    /// Execute an authorized tool. Handler failures become JSON-RPC internal
    /// errors, matching Go's `executeTool` dispatch boundary.
    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String>;
}

pub(crate) fn parse_params(raw: Option<&str>) -> Result<(String, Value), String> {
    let Some(raw) = raw else {
        return Ok((String::new(), Value::Object(serde_json::Map::new())));
    };
    let value: Value = serde_json::from_str(raw).map_err(|err| err.to_string())?;
    let Some(object) = value.as_object() else {
        if value.is_null() {
            return Ok((String::new(), Value::Object(serde_json::Map::new())));
        }
        return Err("invalid tools/call params: expected object".to_string());
    };

    let name = match object.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(name)) => name.clone(),
        Some(_) => return Err("invalid tools/call name: expected string".to_string()),
    };
    let arguments = match object.get("arguments") {
        None | Some(Value::Null) => Value::Object(serde_json::Map::new()),
        Some(arguments) => arguments.clone(),
    };
    Ok((name, arguments))
}

pub(crate) fn payload(result: ToolCallResult) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "content".to_string(),
        serde_json::json!([{
            "type": "text",
            "text": crate::render::sanitize_for_mcp(&result.text),
        }]),
    );
    payload.insert("isError".to_string(), Value::Bool(result.is_error));
    if let Some(structured) = result.structured_content {
        payload.insert("structuredContent".to_string(), structured);
    }
    Value::Object(payload)
}
