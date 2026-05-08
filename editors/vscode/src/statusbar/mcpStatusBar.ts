import * as vscode from "vscode";
import { OpenPassMCPClient } from "@openpass/mcp-client";

export class MCPStatusBar {
  private statusBarItem: vscode.StatusBarItem;
  private client: OpenPassMCPClient;
  private refreshInterval: NodeJS.Timeout | undefined;
  private isConnected = false;

  constructor(client: OpenPassMCPClient) {
    this.client = client;
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = "openpass.quickPickVault";
    this.updateStatus(false);
  }

  show(): void {
    this.statusBarItem.show();
    this.startPolling();
  }

  hide(): void {
    this.statusBarItem.hide();
    this.stopPolling();
  }

  dispose(): void {
    this.stopPolling();
    this.statusBarItem.dispose();
  }

  async checkConnection(): Promise<boolean> {
    try {
      await this.client.health();
      return true;
    } catch {
      return false;
    }
  }

  private async poll(): Promise<void> {
    const connected = await this.checkConnection();
    if (connected !== this.isConnected) {
      this.isConnected = connected;
      this.updateStatus(connected);
    }
  }

  private updateStatus(connected: boolean): void {
    this.isConnected = connected;
    if (connected) {
      this.statusBarItem.text = "$(shield) OpenPass";
      this.statusBarItem.backgroundColor = undefined;
      this.statusBarItem.tooltip = "OpenPass MCP server is connected. Click to open vault.";
    } else {
      this.statusBarItem.text = "$(shield-x) OpenPass";
      this.statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
      this.statusBarItem.tooltip = "OpenPass MCP server is unreachable. Check that 'openpass serve' is running.";
    }
  }

  private startPolling(): void {
    this.stopPolling();
    void this.poll();
    this.refreshInterval = setInterval(() => void this.poll(), 10000);
  }

  private stopPolling(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = undefined;
    }
  }
}
