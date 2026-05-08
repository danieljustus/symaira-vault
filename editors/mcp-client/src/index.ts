/**
 * Public API exports for @openpass/mcp-client
 */

export { OpenPassMCPClient, ClientOptions } from "./client";
export { OpenPassTools } from "./tools";
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
  OpenPassError,
  OpenPassAuthError,
  OpenPassConnectionError,
  OpenPassToolError,
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
