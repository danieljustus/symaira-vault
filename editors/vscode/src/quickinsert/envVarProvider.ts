import * as vscode from "vscode";
import { OpenPassTools } from "@openpass/mcp-client";

export class EnvVarCompletionProvider implements vscode.CompletionItemProvider {
  private tools: OpenPassTools;

  constructor(tools: OpenPassTools) {
    this.tools = tools;
  }

  async provideCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken,
    _context: vscode.CompletionContext
  ): Promise<vscode.CompletionItem[] | undefined> {
    const lineText = document.lineAt(position).text;
    const prefix = lineText.substring(0, position.character);

    const match = prefix.match(/\$\{openpass:([^}]*)$/);
    if (!match) {
      return undefined;
    }

    const searchTerm = match[1] || "";

    try {
      const result = await this.tools.listEntries();
      if (result.isError) {
        return undefined;
      }

      const text = result.content[0]?.text || "[]";
      const entries = JSON.parse(text) as string[];

      const filtered = searchTerm
        ? entries.filter((e) => e.toLowerCase().includes(searchTerm.toLowerCase()))
        : entries;

      return filtered.map((entry) => {
        const item = new vscode.CompletionItem(
          entry,
          vscode.CompletionItemKind.Value
        );
        item.insertText = `${entry}}`;
        item.detail = "OpenPass vault entry";
        item.documentation = new vscode.MarkdownString(
          `Inserts a reference to the OpenPass vault entry \`${entry}\`.`
        );
        item.range = new vscode.Range(
          position.translate(0, -searchTerm.length - "${openpass:".length),
          position
        );
        return item;
      });
    } catch {
      return undefined;
    }
  }
}
