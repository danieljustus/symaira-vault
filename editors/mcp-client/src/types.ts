export interface Entry {
  path: string;
  data: Record<string, unknown>;
  meta: EntryMetadata;
}

export interface EntryMetadata {
  created: string;
  updated: string;
  version: number;
}

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError: boolean;
}

export interface MCPMessage {
  jsonrpc: "2.0";
  id?: string | number;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: MCPError;
}

export interface MCPError {
  code: number;
  message: string;
  data?: unknown;
}

export interface AgentProfile {
  allowedPaths: string[];
  canWrite: boolean;
  canRunCommands: boolean;
  canUseClipboard: boolean;
  canUseAutotype: boolean;
  canManageConfig: boolean;
  approvalMode: string;
  redactFields: string[];
}

export interface ServerConfig {
  bind: string;
  port: number;
  agents: Record<string, AgentProfile>;
}

export interface HealthResponse {
  status: string;
  version?: string;
}
