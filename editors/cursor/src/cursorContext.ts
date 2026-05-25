import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { SymairaTools, maskValue } from "@symaira/mcp-client";

const CONTEXT_MARKER_START = "<!-- SYMAIRA VAULT CONTEXT -->";
const CONTEXT_MARKER_END = "<!-- END SYMAIRA VAULT CONTEXT -->";

export async function injectCursorContext(tools: SymairaTools): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    return;
  }

  const config = vscode.workspace.getConfiguration("symvault.cursor");
  const contextFile = config.get<string>("contextFile", ".cursorrules");

  for (const folder of workspaceFolders) {
    const cursorrulesPath = path.join(folder.uri.fsPath, contextFile);
    await updateCursorrulesFile(cursorrulesPath, tools);
  }
}

async function updateCursorrulesFile(
  filePath: string,
  tools: SymairaTools
): Promise<void> {
  try {
    const result = await tools.listEntries();
    const entries = parseEntries(result);

    const contextBlock = buildContextBlock(entries);

    let content = "";
    if (fs.existsSync(filePath)) {
      content = fs.readFileSync(filePath, "utf-8");
    }

    const newContent = replaceOrAppendContext(content, contextBlock);
    fs.writeFileSync(filePath, newContent, "utf-8");
  } catch (error) {
    console.error(`Failed to update ${filePath}:`, error);
  }
}

function parseEntries(result: { content: Array<{ type: string; text: string }> }): string[] {
  const entries: string[] = [];
  for (const item of result.content) {
    if (item.type === "text") {
      try {
        const data = JSON.parse(item.text);
        if (Array.isArray(data)) {
          entries.push(...data);
        }
      } catch {
      }
    }
  }
  return entries;
}

function buildContextBlock(entries: string[]): string {
  if (entries.length === 0) {
    return `${CONTEXT_MARKER_START}\nNo Symaira Vault secrets available.\n${CONTEXT_MARKER_END}`;
  }

  const lines = [
    CONTEXT_MARKER_START,
    "",
    "The following secrets are available in Symaira Vault:",
    "",
  ];

  for (const entry of entries) {
    lines.push(`- ${entry} (value: ${maskValue(entry)})`);
  }

  lines.push("");
  lines.push(
    "To use a secret, reference it with: ${symvault:<path>} or use the Symaira Vault commands."
  );
  lines.push("");
  lines.push(CONTEXT_MARKER_END);

  return lines.join("\n");
}

function replaceOrAppendContext(content: string, contextBlock: string): string {
  const startIdx = content.indexOf(CONTEXT_MARKER_START);
  const endIdx = content.indexOf(CONTEXT_MARKER_END);

  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    return (
      content.slice(0, startIdx) + contextBlock + content.slice(endIdx + CONTEXT_MARKER_END.length)
    );
  }

  if (content.trim().length > 0) {
    return content.trimEnd() + "\n\n" + contextBlock + "\n";
  }

  return contextBlock + "\n";
}
