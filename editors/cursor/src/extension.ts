import * as vscode from "vscode";
import { SymairaMCPClient, SymairaTools } from "@symaira/mcp-client";
import { injectCursorContext } from "./cursorContext";

let client: SymairaMCPClient | undefined;
let tools: SymairaTools | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("symaira.cursor");
  const baseUrl = config.get<string>("baseUrl", "http://127.0.0.1:8080");
  const agentName = config.get<string>("agentName", "cursor");

  client = new SymairaMCPClient({ baseUrl, agentName });
  tools = new SymairaTools(client);

  const refreshCmd = vscode.commands.registerCommand(
    "symaira.cursor.refreshContext",
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
