import * as vscode from "vscode";
import { OpenPassMCPClient, OpenPassTools } from "@openpass/mcp-client";
import { VaultTreeProvider } from "./sidebar/vaultTreeProvider";
import { VaultTreeItem } from "./sidebar/vaultTreeItem";
import { insertSecret } from "./commands/insertSecret";
import { copyToClipboard } from "./commands/copyToClipboard";
import { generatePassword } from "./commands/generatePassword";
import { quickPickVault } from "./commands/quickPickVault";
import { MCPStatusBar } from "./statusbar/mcpStatusBar";
import { EnvVarCompletionProvider } from "./quickinsert/envVarProvider";

let client: OpenPassMCPClient | undefined;
let tools: OpenPassTools | undefined;
let treeProvider: VaultTreeProvider | undefined;
let statusBar: MCPStatusBar | undefined;
let completionDisposable: vscode.Disposable | undefined;

function getConfig(): {
  baseUrl: string;
  vaultPath: string;
  agentName: string;
  timeoutMs: number;
} {
  const config = vscode.workspace.getConfiguration("openpass");
  return {
    baseUrl: config.get<string>("baseUrl", "http://127.0.0.1:8080"),
    vaultPath: config.get<string>("vaultPath", ""),
    agentName: config.get<string>("agentName", "vscode"),
    timeoutMs: config.get<number>("timeoutMs", 30000),
  };
}

function createClient(): OpenPassMCPClient {
  const cfg = getConfig();
  return new OpenPassMCPClient({
    baseUrl: cfg.baseUrl,
    agentName: cfg.agentName,
    vaultPath: cfg.vaultPath || undefined,
    timeoutMs: cfg.timeoutMs,
  });
}

export function activate(context: vscode.ExtensionContext): void {
  void vscode.commands.executeCommand("setContext", "openpass.enabled", true);

  client = createClient();
  tools = new OpenPassTools(client);
  treeProvider = new VaultTreeProvider(tools);
  statusBar = new MCPStatusBar(client);

  const treeView = vscode.window.createTreeView("openpass.vault", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  statusBar.show();

  const completionProvider = new EnvVarCompletionProvider(tools);
  completionDisposable = vscode.languages.registerCompletionItemProvider(
    [{ scheme: "file" }, { scheme: "untitled" }],
    completionProvider,
    "${openpass:"
  );

  const commands: vscode.Disposable[] = [
    vscode.commands.registerCommand("openpass.refreshVault", () => {
      treeProvider?.refresh();
    }),
    vscode.commands.registerCommand("openpass.openSettings", () => {
      void vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "openpass"
      );
    }),
    vscode.commands.registerCommand(
      "openpass.insertSecret",
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
      "openpass.copyToClipboard",
      (item?: VaultTreeItem) => {
        const path = item?.path;
        if (path) {
          void copyToClipboard(tools!, path);
        } else {
          void quickPickVault(tools!);
        }
      }
    ),
    vscode.commands.registerCommand("openpass.generatePassword", () => {
      void generatePassword(tools!);
    }),
    vscode.commands.registerCommand("openpass.quickPickVault", () => {
      void quickPickVault(tools!);
    }),
  ];

  const configChangeDisposable = vscode.workspace.onDidChangeConfiguration(
    (event) => {
      if (event.affectsConfiguration("openpass")) {
        client?.close();
        client = createClient();
        tools = new OpenPassTools(client);
        treeProvider = new VaultTreeProvider(tools);
        statusBar?.dispose();
        statusBar = new MCPStatusBar(client);
        statusBar.show();
        treeView.dispose();
        void vscode.window.createTreeView("openpass.vault", {
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
