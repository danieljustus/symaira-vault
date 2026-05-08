import * as vscode from "vscode";
import { OpenPassMCPClient, OpenPassTools } from "@openpass/mcp-client";
import { injectCursorContext } from "./cursorContext";

let client: OpenPassMCPClient | undefined;
let tools: OpenPassTools | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("openpass.cursor");
  const baseUrl = config.get<string>("baseUrl", "http://127.0.0.1:8080");
  const agentName = config.get<string>("agentName", "cursor");

  client = new OpenPassMCPClient({ baseUrl, agentName });
  tools = new OpenPassTools(client);

  const refreshCmd = vscode.commands.registerCommand(
    "openpass.cursor.refreshContext",
    async () => {
      await injectCursorContext(tools!);
    }
  );

  context.subscriptions.push(refreshCmd);

  if (config.get<boolean>("injectCursorrules", true)) {
    injectCursorContext(tools).catch((err) => {
      console.error("Failed to inject Cursor context:", err);
    });
  }
}

export function deactivate(): void {
  client?.close();
}
