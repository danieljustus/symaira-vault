//! Minimal Streamable HTTP request adapter for the existing MCP protocol handler.
//! The socket listener stays with the caller; this module owns `/mcp` request
//! checks and response framing for one request.

use crate::{
    Error, Message, ProtocolHandler, error_code, handle_line, is_supported_protocol_version,
};

pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub accept: &'a str,
    pub protocol_version: &'a str,
    pub body: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
}

/// Handles the initialize-sized `/mcp` HTTP slice using the shared JSON-RPC
/// handler. The caller owns TCP, authentication, and connection lifecycle.
pub fn handle_request(
    request: HttpRequest<'_>,
    handler: &mut ProtocolHandler,
) -> Result<HttpResponse, Error> {
    if request.method != "POST" {
        return error(405, None, error_code::INVALID_REQUEST, "method not allowed");
    }
    if request.path != "/mcp" {
        return Ok(HttpResponse {
            status: 404,
            headers: vec![
                ("Content-Type", "text/plain; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            body: b"404 page not found\n".to_vec(),
        });
    }
    if !is_json_content_type(request.content_type) {
        return error(
            415,
            None,
            error_code::INVALID_REQUEST,
            "Content-Type must be application/json",
        );
    }
    if !accepts_response(request.accept) {
        return error(
            406,
            None,
            error_code::INVALID_REQUEST,
            "Accept must include application/json and text/event-stream",
        );
    }
    if request.body.len() > 1_048_576 {
        return error(413, None, error_code::PARSE_ERROR, "request body too large");
    }

    let version = request.protocol_version.trim();
    if !version.is_empty() && !is_supported_protocol_version(version) {
        let id = serde_json::from_str::<Message>(request.body)
            .ok()
            .and_then(|message| message.id);
        return error(
            400,
            id,
            error_code::INVALID_REQUEST,
            "unsupported MCP-Protocol-Version",
        );
    }

    match handle_line(request.body, handler)? {
        Some(mut body) => {
            body.push('\n');
            Ok(HttpResponse {
                status: 200,
                headers: vec![("Content-Type", "application/json")],
                body: body.into_bytes(),
            })
        }
        None => Ok(HttpResponse {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        }),
    }
}

fn error(
    status: u16,
    id: Option<Box<serde_json::value::RawValue>>,
    code: i32,
    message: &str,
) -> Result<HttpResponse, Error> {
    let mut body = crate::encode(&Message::error_response(id, code, message, None))?;
    body.push('\n');
    let mut headers = vec![("Content-Type", "application/json")];
    if status == 405 {
        headers.push(("Allow", "POST"));
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.into_bytes(),
    })
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn accepts_response(value: &str) -> bool {
    let mut json = false;
    let mut event_stream = false;
    for part in value.split(',') {
        let media_type = part.split(';').next().unwrap_or_default().trim();
        match media_type.to_ascii_lowercase().as_str() {
            "*/*" | "application/*" | "application/json" => json = true,
            "text/event-stream" => event_stream = true,
            _ => {}
        }
    }
    json && event_stream
}
