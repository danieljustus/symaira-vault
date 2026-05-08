/**
 * Typed tool wrappers for OpenPass MCP tools.
 * Provides convenient methods for each MCP tool.
 */

import { OpenPassMCPClient } from "./client";
import { ToolResult } from "./types";

export class OpenPassTools {
  constructor(private client: OpenPassMCPClient) {}

  async health(): Promise<ToolResult> {
    return this.client.callTool("health", {});
  }

  async getAuthStatus(): Promise<ToolResult> {
    return this.client.callTool("get_auth_status", {});
  }

  async listEntries(prefix?: string): Promise<ToolResult> {
    return this.client.callTool("list_entries", prefix ? { prefix } : {});
  }

  async getEntry(
    path: string,
    includeMetadata?: boolean
  ): Promise<ToolResult> {
    return this.client.callTool("get_entry", {
      path,
      include_metadata: includeMetadata ?? false,
    });
  }

  async getEntryMetadata(path: string): Promise<ToolResult> {
    return this.client.callTool("get_entry_metadata", { path });
  }

  async findEntries(query: string): Promise<ToolResult> {
    return this.client.callTool("find_entries", { query });
  }

  async generatePassword(length = 32, symbols = true): Promise<ToolResult> {
    return this.client.callTool("generate_password", { length, symbols });
  }

  async generateTotp(path: string): Promise<ToolResult> {
    return this.client.callTool("generate_totp", { path });
  }

  async copyToClipboard(path: string): Promise<ToolResult> {
    return this.client.callTool("copy_to_clipboard", { path });
  }

  async autotype(path: string, field?: string): Promise<ToolResult> {
    return this.client.callTool("autotype", { path, field });
  }

  async setEntryField(
    path: string,
    field: string,
    value: string
  ): Promise<ToolResult> {
    return this.client.callTool("set_entry_field", { path, field, value });
  }

  async deleteEntry(path: string): Promise<ToolResult> {
    return this.client.callTool("delete_entry", { path });
  }

  async runCommand(
    command: string[],
    options: {
      env?: Record<string, string>;
      working_dir?: string;
      timeout?: number;
    } = {}
  ): Promise<ToolResult> {
    return this.client.callTool("run_command", {
      command,
      ...options,
    });
  }

  async secureInput(
    path: string,
    field: string,
    description?: string
  ): Promise<ToolResult> {
    return this.client.callTool("secure_input", {
      path,
      field,
      description,
    });
  }
}
