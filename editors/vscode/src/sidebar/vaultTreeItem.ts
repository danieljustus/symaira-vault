import * as vscode from "vscode";
import { maskValue } from "@symaira/mcp-client";

export type VaultTreeItemType = "entry" | "field" | "folder";

export class VaultTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly type: VaultTreeItemType,
    public readonly path: string,
    public readonly fieldName?: string,
    public readonly value?: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState = vscode.TreeItemCollapsibleState.None
  ) {
    super(label, collapsibleState);

    this.tooltip = this.buildTooltip();
    this.description = this.buildDescription();
    this.iconPath = this.buildIcon();
    this.contextValue = type;
  }

  private buildTooltip(): string {
    if (this.type === "field" && this.fieldName) {
      return `${this.fieldName}: ${maskValue(this.value ?? "")}`;
    }
    return this.path;
  }

  private buildDescription(): string {
    if (this.type === "field" && this.fieldName) {
      return `${this.fieldName}: ${maskValue(this.value ?? "")}`;
    }
    return "";
  }

  private buildIcon(): vscode.ThemeIcon {
    switch (this.type) {
      case "folder":
        return new vscode.ThemeIcon("folder");
      case "entry":
        return new vscode.ThemeIcon("shield");
      case "field":
        return new vscode.ThemeIcon("key");
      default:
        return new vscode.ThemeIcon("shield");
    }
  }
}
