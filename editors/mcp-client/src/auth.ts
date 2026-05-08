import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as yaml from "yaml";
import { ServerConfig, AgentProfile } from "./types";

const DEFAULT_VAULT_PATH = path.join(os.homedir(), ".openpass");

export interface AuthHeaders {
  Authorization: string;
  "X-OpenPass-Agent": string;
  "MCP-Protocol-Version": string;
}

export function getVaultPath(): string {
  return process.env.OPENPASS_VAULT || DEFAULT_VAULT_PATH;
}

export function readToken(vaultPath?: string): string {
  const vault = vaultPath || getVaultPath();
  const tokenPath = path.join(vault, "mcp-token");

  if (!fs.existsSync(tokenPath)) {
    throw new OpenPassAuthError(
      `MCP token not found at ${tokenPath}. Run 'openpass serve' to generate one.`
    );
  }

  const stats = fs.statSync(tokenPath);
  const mode = stats.mode & 0o777;
  if (mode & 0o044) {
    console.warn(
      `Warning: MCP token file at ${tokenPath} is world-readable (mode ${mode.toString(8)}). Consider restricting permissions.`
    );
  }

  return fs.readFileSync(tokenPath, "utf-8").trim();
}

/**
 * Read and parse the OpenPass config.yaml.
 */
export function readConfig(vaultPath?: string): ServerConfig {
  const vault = vaultPath || getVaultPath();
  const configPath = path.join(vault, "config.yaml");

  if (!fs.existsSync(configPath)) {
    return { bind: "127.0.0.1", port: 8080, agents: {} };
  }

  const content = fs.readFileSync(configPath, "utf-8");
  const parsed = yaml.parse(content) || {};

  return {
    bind: parsed.bind || "127.0.0.1",
    port: parsed.port || 8080,
    agents: parsed.agents || {},
  };
}

/**
 * Resolve agent profile from config.
 */
export function resolveAgentProfile(
  agentName: string,
  vaultPath?: string
): AgentProfile | undefined {
  const config = readConfig(vaultPath);
  return config.agents[agentName];
}

/**
 * Build HTTP headers for MCP requests.
 */
export function buildAuthHeaders(
  agentName: string,
  vaultPath?: string
): AuthHeaders {
  const token = readToken(vaultPath);
  return {
    Authorization: `Bearer ${token}`,
    "X-OpenPass-Agent": agentName,
    "MCP-Protocol-Version": "2025-11-25",
  };
}

export class OpenPassAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenPassAuthError";
  }
}
