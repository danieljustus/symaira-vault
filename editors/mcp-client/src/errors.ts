/**
 * Error classification for Symaira Vault MCP client.
 */

export class SymairaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SymairaError";
  }
}

export class SymairaAuthError extends SymairaError {
  constructor(message: string) {
    super(message);
    this.name = "SymairaAuthError";
  }
}

export class SymairaConnectionError extends SymairaError {
  constructor(message: string) {
    super(message);
    this.name = "SymairaConnectionError";
  }
}

export class SymairaToolError extends SymairaError {
  public readonly toolName: string;
  public readonly toolError?: unknown;

  constructor(toolName: string, message: string, toolError?: unknown) {
    super(message);
    this.name = "SymairaToolError";
    this.toolName = toolName;
    this.toolError = toolError;
  }
}

export class SymairaURLError extends SymairaError {
  constructor(message: string) {
    super(message);
    this.name = "SymairaURLError";
  }
}
