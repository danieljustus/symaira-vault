/**
 * Main Symaira Vault MCP HTTP client.
 * Communicates with symvault serve via JSON-RPC 2.0 over HTTP.
 */

import {
  buildToolCallRequest,
  buildInitializeRequest,
  buildPingRequest,
  buildToolsListRequest,
  parseMessage,
  extractResult,
} from "./protocol";
import { buildAuthHeaders, AuthHeaders } from "./auth";
import { MCPMessage, ToolResult } from "./types";
import { SymairaConnectionError, SymairaToolError, SymairaURLError } from "./errors";

export interface ClientOptions {
  baseUrl?: string;
  agentName?: string;
  vaultPath?: string;
  timeoutMs?: number;
}

/**
 * Validate that a URL points to a loopback address.
 * Only allows http/https protocols and loopback hostnames:
 * 127.0.0.1, localhost, ::1, [::1], 0.0.0.0
 */
export function validateBaseUrl(urlString: string): void {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new SymairaURLError(`Invalid URL: "${urlString}"`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SymairaURLError(
      `Only http and https protocols are allowed, got "${url.protocol}"`
    );
  }

  const LOOPBACK_HOSTNAMES = new Set([
    "127.0.0.1",
    "localhost",
    "::1",
    "[::1]",
    "0.0.0.0",
  ]);

  if (!LOOPBACK_HOSTNAMES.has(url.hostname)) {
    throw new SymairaURLError(
      `URL must point to a loopback address (127.0.0.1, localhost, ::1, 0.0.0.0), got "${url.hostname}"`
    );
  }
}

export class SymairaMCPClient {
  private baseUrl: string;
  private headers: AuthHeaders;
  private timeoutMs: number;
  private initialized = false;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = options.baseUrl || "http://127.0.0.1:8080";
    validateBaseUrl(this.baseUrl);
    const agentName = options.agentName || "vscode";
    this.headers = buildAuthHeaders(agentName, options.vaultPath);
    this.timeoutMs = options.timeoutMs || 30000;
  }

  /**
   * Initialize the MCP session.
   */
  async initialize(): Promise<void> {
    const initRequest = buildInitializeRequest();
    await this.sendMessage(initRequest);
    this.initialized = true;
  }

  /**
   * Check server health.
   */
  async health(): Promise<unknown> {
    const response = await fetch(`${this.baseUrl}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new SymairaConnectionError(
        `Health check failed: ${response.status} ${response.statusText}`
      );
    }

    return response.json();
  }

  /**
   * Ping the server via MCP.
   */
  async ping(): Promise<void> {
    const pingRequest = buildPingRequest();
    await this.sendMessage(pingRequest);
  }

  /**
   * List available MCP tools.
   */
  async listTools(): Promise<unknown> {
    const request = buildToolsListRequest();
    const response = await this.sendMessage(request);
    return extractResult(response);
  }

  /**
   * Call an MCP tool by name with arguments.
   */
  async callTool(
    name: string,
    arguments_: Record<string, unknown>
  ): Promise<ToolResult> {
    if (!this.initialized) {
      await this.initialize();
    }

    const request = buildToolCallRequest(name, arguments_);

    try {
      const response = await this.sendMessage(request);
      const result = extractResult<{
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      }>(response);

      return {
        content: result.content || [],
        isError: result.isError || false,
      };
    } catch (error) {
      throw new SymairaToolError(
        name,
        `Tool '${name}' failed: ${error}`,
        error
      );
    }
  }

  /**
   * Send a JSON-RPC message to the MCP server.
   */
  private async sendMessage(message: MCPMessage): Promise<MCPMessage> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...this.headers,
        },
        body: JSON.stringify(message),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        if (response.status === 401) {
          throw new SymairaConnectionError(
            "Authentication failed. Check your MCP token."
          );
        }
        throw new SymairaConnectionError(
          `HTTP ${response.status}: ${response.statusText}`
        );
      }

      const text = await response.text();
      return parseMessage(text);
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof SymairaConnectionError) {
        throw error;
      }

      if ((error as Error).name === "AbortError") {
        throw new SymairaConnectionError(
          `Request timed out after ${this.timeoutMs}ms`
        );
      }

      throw new SymairaConnectionError(
        `Failed to connect to Symaira Vault server at ${this.baseUrl}: ${error}`
      );
    }
  }

  /**
   * Close the client (no-op for HTTP mode).
   */
  close(): void {
    this.initialized = false;
  }
}
