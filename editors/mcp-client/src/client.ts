/**
 * Main OpenPass MCP HTTP client.
 * Communicates with openpass serve via JSON-RPC 2.0 over HTTP.
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
import { OpenPassConnectionError, OpenPassToolError } from "./errors";

export interface ClientOptions {
  baseUrl?: string;
  agentName?: string;
  vaultPath?: string;
  timeoutMs?: number;
}

export class OpenPassMCPClient {
  private baseUrl: string;
  private headers: AuthHeaders;
  private timeoutMs: number;
  private initialized = false;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = options.baseUrl || "http://127.0.0.1:8080";
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
      throw new OpenPassConnectionError(
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
      throw new OpenPassToolError(
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
          throw new OpenPassConnectionError(
            "Authentication failed. Check your MCP token."
          );
        }
        throw new OpenPassConnectionError(
          `HTTP ${response.status}: ${response.statusText}`
        );
      }

      const text = await response.text();
      return parseMessage(text);
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof OpenPassConnectionError) {
        throw error;
      }

      if ((error as Error).name === "AbortError") {
        throw new OpenPassConnectionError(
          `Request timed out after ${this.timeoutMs}ms`
        );
      }

      throw new OpenPassConnectionError(
        `Failed to connect to OpenPass server at ${this.baseUrl}: ${error}`
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
