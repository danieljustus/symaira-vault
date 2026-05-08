import { MCPMessage, MCPError } from "./types";

let messageId = 0;

export function generateId(): string {
  return `${++messageId}`;
}

export function buildRequest(method: string, params?: unknown): MCPMessage {
  return {
    jsonrpc: "2.0",
    id: generateId(),
    method,
    params,
  };
}

export function buildToolsListRequest(): MCPMessage {
  return buildRequest("tools/list");
}

export function buildToolCallRequest(
  name: string,
  arguments_: Record<string, unknown>
): MCPMessage {
  return buildRequest("tools/call", { name, arguments: arguments_ });
}

export function buildInitializeRequest(): MCPMessage {
  return buildRequest("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: {
      name: "openpass-editor-plugin",
      version: "1.0.0",
    },
  });
}

export function buildPingRequest(): MCPMessage {
  return buildRequest("ping");
}

export function isResponse(message: MCPMessage): boolean {
  return message.jsonrpc === "2.0" && ("result" in message || "error" in message);
}

export function extractResult<T>(message: MCPMessage): T {
  if (message.error) {
    const err = message.error as MCPError;
    throw new Error(`MCP Error ${err.code}: ${err.message}`);
  }
  return message.result as T;
}

export function parseMessage(data: string): MCPMessage {
  try {
    return JSON.parse(data) as MCPMessage;
  } catch (e) {
    throw new Error(`Invalid JSON-RPC message: ${e}`);
  }
}
