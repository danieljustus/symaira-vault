import * as vscode from "vscode";
import { OpenPassTools } from "@openpass/mcp-client";
import { insertSecret } from "./insertSecret";
import { copyToClipboard } from "./copyToClipboard";

export async function quickPickVault(tools: OpenPassTools): Promise<void> {
  try {
    const result = await tools.listEntries();
    if (result.isError) {
      const errorText = result.content[0]?.text || "Unknown error";
      void vscode.window.showErrorMessage(`Failed to list vault entries: ${errorText}`);
      return;
    }

    const text = result.content[0]?.text || "[]";
    const entries = JSON.parse(text) as string[];

    if (entries.length === 0) {
      void vscode.window.showInformationMessage("Vault is empty.");
      return;
    }

    const selected = await vscode.window.showQuickPick(entries, {
      placeHolder: "Select a vault entry",
    });

    if (!selected) {
      return;
    }

    const action = await vscode.window.showQuickPick(
      [
        { label: "Insert as ${openpass:...}", action: "insert" },
        { label: "Copy to Clipboard", action: "copy" },
      ],
      { placeHolder: `What to do with "${selected}"?` }
    );

    if (!action) {
      return;
    }

    if (action.action === "insert") {
      await insertSecret(selected);
    } else if (action.action === "copy") {
      await copyToClipboard(tools, selected);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Failed to open vault: ${message}`);
  }
}
