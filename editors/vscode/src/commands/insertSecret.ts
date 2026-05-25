import * as vscode from "vscode";

export async function insertSecret(path: string): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showWarningMessage("No active text editor to insert into.");
    return;
  }

  const placeholder = `\${symvault:${path}}`;

  await editor.edit((editBuilder) => {
    editBuilder.insert(editor.selection.active, placeholder);
  });

  void vscode.window.showInformationMessage(`Inserted ${placeholder}`);
}
