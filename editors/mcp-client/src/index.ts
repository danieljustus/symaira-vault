/**
 * Public API exports for @symaira/mcp-client
 */

export { SymairaMCPClient, ClientOptions, validateBaseUrl } from "./client";
export { SymairaTools } from "./tools";
export {
  buildAuthHeaders,
  readToken,
  readConfig,
  resolveAgentProfile,
  getVaultPath,
  AuthHeaders,
} from "./auth";
export {
  maskValue,
  maskObject,
  maskEntryData,
} from "./masking";
export {
  SymairaError,
  SymairaAuthError,
  SymairaConnectionError,
  SymairaToolError,
  SymairaURLError,
} from "./errors";
export {
  buildRequest,
  buildToolsListRequest,
  buildToolCallRequest,
  buildInitializeRequest,
  buildPingRequest,
  parseMessage,
  extractResult,
} from "./protocol";
export type {
  Entry,
  EntryMetadata,
  ToolResult,
  MCPMessage,
  MCPError,
  AgentProfile,
  ServerConfig,
  HealthResponse,
} from "./types";
