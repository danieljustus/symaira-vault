import * as vscode from "vscode";
import { OpenPassTools, maskValue } from "@openpass/mcp-client";
import { VaultTreeItem } from "./vaultTreeItem";

export class VaultTreeProvider implements vscode.TreeDataProvider<VaultTreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<VaultTreeItem | undefined | void> =
    new vscode.EventEmitter<VaultTreeItem | undefined | void>();
  readonly onDidChangeTreeData: vscode.Event<VaultTreeItem | undefined | void> =
    this._onDidChangeTreeData.event;

  private tools: OpenPassTools;
  private entries: string[] = [];

  constructor(tools: OpenPassTools) {
    this.tools = tools;
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: VaultTreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: VaultTreeItem): Promise<VaultTreeItem[]> {
    if (!element) {
      return this.getRootEntries();
    }

    if (element.type === "entry") {
      return this.getEntryFields(element.path);
    }

    return [];
  }

  private async getRootEntries(): Promise<VaultTreeItem[]> {
    try {
      const result = await this.tools.listEntries();
      if (result.isError) {
        return [
          new VaultTreeItem(
            "Error loading vault",
            "entry",
            "",
            undefined,
            undefined,
            vscode.TreeItemCollapsibleState.None
          ),
        ];
      }

      const text = result.content[0]?.text || "[]";
      this.entries = JSON.parse(text) as string[];

      return this.entries.map(
        (path) =>
          new VaultTreeItem(
            path,
            "entry",
            path,
            undefined,
            undefined,
            vscode.TreeItemCollapsibleState.Collapsed
          )
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return [
        new VaultTreeItem(
          `Error: ${message}`,
          "entry",
          "",
          undefined,
          undefined,
          vscode.TreeItemCollapsibleState.None
        ),
      ];
    }
  }

  private async getEntryFields(path: string): Promise<VaultTreeItem[]> {
    try {
      const result = await this.tools.getEntry(path, true);
      if (result.isError) {
        return [
          new VaultTreeItem(
            "Error loading entry",
            "field",
            path,
            undefined,
            undefined,
            vscode.TreeItemCollapsibleState.None
          ),
        ];
      }

      const text = result.content[0]?.text || "{}";
      const entry = JSON.parse(text) as {
        data: Record<string, unknown>;
        meta?: Record<string, unknown>;
      };

      const fields: VaultTreeItem[] = [];

      for (const [key, value] of Object.entries(entry.data)) {
        const masked = typeof value === "string" ? maskValue(value) : maskValue(JSON.stringify(value));
        fields.push(
          new VaultTreeItem(
            `${key}: ${masked}`,
            "field",
            path,
            key,
            typeof value === "string" ? value : JSON.stringify(value),
            vscode.TreeItemCollapsibleState.None
          )
        );
      }

      if (entry.meta) {
        const metaStr = Object.entries(entry.meta)
          .map(([k, v]) => `${k}: ${String(v)}`)
          .join(", ");
        fields.push(
          new VaultTreeItem(
            `meta: ${metaStr}`,
            "field",
            path,
            "meta",
            undefined,
            vscode.TreeItemCollapsibleState.None
          )
        );
      }

      return fields;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return [
        new VaultTreeItem(
          `Error: ${message}`,
          "field",
          path,
          undefined,
          undefined,
          vscode.TreeItemCollapsibleState.None
        ),
      ];
    }
  }
}
