/**
 * Error classification for OpenPass MCP client.
 */

export class OpenPassError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenPassError";
  }
}

export class OpenPassAuthError extends OpenPassError {
  constructor(message: string) {
    super(message);
    this.name = "OpenPassAuthError";
  }
}

export class OpenPassConnectionError extends OpenPassError {
  constructor(message: string) {
    super(message);
    this.name = "OpenPassConnectionError";
  }
}

export class OpenPassToolError extends OpenPassError {
  public readonly toolName: string;
  public readonly toolError?: unknown;

  constructor(toolName: string, message: string, toolError?: unknown) {
    super(message);
    this.name = "OpenPassToolError";
    this.toolName = toolName;
    this.toolError = toolError;
  }
}
