import * as vscode from "vscode";
import { SymairaTools, maskValue } from "@symaira/mcp-client";

export async function generatePassword(tools: SymairaTools): Promise<void> {
  const lengthInput = await vscode.window.showInputBox({
    prompt: "Password length",
    value: "32",
    validateInput: (value) => {
      const num = parseInt(value, 10);
      if (isNaN(num) || num < 1 || num > 128) {
        return "Please enter a number between 1 and 128.";
      }
      return undefined;
    },
  });

  if (lengthInput === undefined) {
    return;
  }

  const length = parseInt(lengthInput, 10);

  const symbols = await vscode.window.showQuickPick(["Yes", "No"], {
    placeHolder: "Include symbols?",
  });

  if (symbols === undefined) {
    return;
  }

  const includeSymbols = symbols === "Yes";

  try {
    const result = await tools.generatePassword(length, includeSymbols);
    if (result.isError) {
      const errorText = result.content[0]?.text || "Unknown error";
      void vscode.window.showErrorMessage(`Failed to generate password: ${errorText}`);
      return;
    }

    const password = result.content[0]?.text || "";
    const masked = maskValue(password);

    const action = await vscode.window.showInformationMessage(
      `Generated password: ${masked}`,
      "Copy to Clipboard",
      "Insert at Cursor"
    );

    if (action === "Copy to Clipboard") {
      await vscode.env.clipboard.writeText(password);
      void vscode.window.showInformationMessage("Password copied to clipboard.");
    } else if (action === "Insert at Cursor") {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await editor.edit((editBuilder) => {
          editBuilder.insert(editor.selection.active, password);
        });
      } else {
        void vscode.window.showWarningMessage("No active text editor to insert into.");
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Failed to generate password: ${message}`);
  }
}
