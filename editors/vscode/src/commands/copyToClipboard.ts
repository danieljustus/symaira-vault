import * as vscode from "vscode";
import { SymairaTools } from "@symaira/mcp-client";

export async function copyToClipboard(tools: SymairaTools, path: string): Promise<void> {
  try {
    const result = await tools.copyToClipboard(path);
    if (result.isError) {
      const errorText = result.content[0]?.text || "Unknown error";
      void vscode.window.showErrorMessage(`Failed to copy: ${errorText}`);
      return;
    }

    void vscode.window.showInformationMessage(`Copied secret from "${path}" to clipboard.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Failed to copy: ${message}`);
  }
}
