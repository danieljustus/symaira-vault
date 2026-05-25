import * as vscode from "vscode";
import { SymairaMCPClient, SymairaTools } from "@symaira/mcp-client";
import { VaultTreeProvider } from "./sidebar/vaultTreeProvider";
import { VaultTreeItem } from "./sidebar/vaultTreeItem";
import { insertSecret } from "./commands/insertSecret";
import { copyToClipboard } from "./commands/copyToClipboard";
import { generatePassword } from "./commands/generatePassword";
import { quickPickVault } from "./commands/quickPickVault";
import { MCPStatusBar } from "./statusbar/mcpStatusBar";
import { EnvVarCompletionProvider } from "./quickinsert/envVarProvider";

let client: SymairaMCPClient | undefined;
let tools: SymairaTools | undefined;
let treeProvider: VaultTreeProvider | undefined;
let statusBar: MCPStatusBar | undefined;
let completionDisposable: vscode.Disposable | undefined;

function getConfig(): {
  baseUrl: string;
  vaultPath: string;
  agentName: string;
  timeoutMs: number;
} {
  const config = vscode.workspace.getConfiguration("symaira");
  return {
    baseUrl: config.get<string>("baseUrl", "http://127.0.0.1:8080"),
    vaultPath: config.get<string>("vaultPath", ""),
    agentName: config.get<string>("agentName", "vscode"),
    timeoutMs: config.get<number>("timeoutMs", 30000),
  };
}

function createClient(): SymairaMCPClient {
  const cfg = getConfig();
  return new SymairaMCPClient({
    baseUrl: cfg.baseUrl,
    agentName: cfg.agentName,
    vaultPath: cfg.vaultPath || undefined,
    timeoutMs: cfg.timeoutMs,
  });
}

export function activate(context: vscode.ExtensionContext): void {
  void vscode.commands.executeCommand("setContext", "symaira.enabled", true);

  client = createClient();
  tools = new SymairaTools(client);
  treeProvider = new VaultTreeProvider(tools);
  statusBar = new MCPStatusBar(client);

  const treeView = vscode.window.createTreeView("symaira.vault", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  statusBar.show();

  const completionProvider = new EnvVarCompletionProvider(tools);
  completionDisposable = vscode.languages.registerCompletionItemProvider(
    [{ scheme: "file" }, { scheme: "untitled" }],
    completionProvider,
    "${symaira:"
  );

  const commands: vscode.Disposable[] = [
    vscode.commands.registerCommand("symaira.refreshVault", () => {
      treeProvider?.refresh();
    }),
    vscode.commands.registerCommand("symaira.openSettings", () => {
      void vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "symaira"
      );
    }),
    vscode.commands.registerCommand(
      "symaira.insertSecret",
      (item?: VaultTreeItem) => {
        const path = item?.path;
        if (path) {
          void insertSecret(path);
        } else {
          void quickPickVault(tools!);
        }
      }
    ),
    vscode.commands.registerCommand(
      "symaira.copyToClipboard",
      (item?: VaultTreeItem) => {
        const path = item?.path;
        if (path) {
          void copyToClipboard(tools!, path);
        } else {
          void quickPickVault(tools!);
        }
      }
    ),
    vscode.commands.registerCommand("symaira.generatePassword", () => {
      void generatePassword(tools!);
    }),
    vscode.commands.registerCommand("symaira.quickPickVault", () => {
      void quickPickVault(tools!);
    }),
  ];

  const configChangeDisposable = vscode.workspace.onDidChangeConfiguration(
    (event) => {
      if (event.affectsConfiguration("symaira")) {
        client?.close();
        client = createClient();
        tools = new SymairaTools(client);
        treeProvider = new VaultTreeProvider(tools);
        statusBar?.dispose();
        statusBar = new MCPStatusBar(client);
        statusBar.show();
        treeView.dispose();
        void vscode.window.createTreeView("symaira.vault", {
          treeDataProvider: treeProvider,
          showCollapseAll: true,
        });
      }
    }
  );

  context.subscriptions.push(
    treeView,
    ...commands,
    configChangeDisposable,
    statusBar,
    completionDisposable
  );
}

export function deactivate(): void {
  client?.close();
  client = undefined;
  tools = undefined;
  treeProvider = undefined;
  statusBar?.dispose();
  statusBar = undefined;
  completionDisposable?.dispose();
  completionDisposable = undefined;
}
