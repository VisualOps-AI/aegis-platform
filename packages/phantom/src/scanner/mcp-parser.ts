import { readFileSync } from "node:fs";
import { resolve, basename } from "node:path";
import type { MCPConfig, MCPServerConfig } from "@aegis/shared";

interface ParseResult {
  config: MCPConfig;
  source: string;
  format: "claude-desktop" | "claude-code" | "raw";
}

const KNOWN_CONFIG_PATHS: Record<string, string[]> = {
  win32: [
    "%APPDATA%/Claude/claude_desktop_config.json",
    "%USERPROFILE%/.claude.json",
  ],
  darwin: [
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.claude.json",
  ],
  linux: ["~/.config/Claude/claude_desktop_config.json", "~/.claude.json"],
};

export function parseMCPConfig(configPath: string): ParseResult {
  const resolved = resolve(configPath);
  const raw = readFileSync(resolved, "utf-8");
  const parsed = JSON.parse(raw);

  const format = detectFormat(parsed, resolved);
  const config = normalizeConfig(parsed, format);

  return { config, source: resolved, format };
}

function detectFormat(
  parsed: Record<string, unknown>,
  path: string
): ParseResult["format"] {
  const name = basename(path);

  if (name === "claude_desktop_config.json" && "mcpServers" in parsed) {
    return "claude-desktop";
  }

  if ("mcpServers" in parsed) {
    return "claude-code";
  }

  return "raw";
}

function normalizeConfig(
  parsed: Record<string, unknown>,
  format: ParseResult["format"]
): MCPConfig {
  if (format === "claude-desktop" || format === "claude-code") {
    const servers = parsed["mcpServers"] as Record<string, unknown>;
    const normalized: Record<string, MCPServerConfig> = {};

    for (const [name, config] of Object.entries(servers)) {
      normalized[name] = normalizeServer(config as Record<string, unknown>);
    }

    return { mcpServers: normalized };
  }

  if ("servers" in parsed) {
    const servers = parsed["servers"] as Record<string, unknown>;
    const normalized: Record<string, MCPServerConfig> = {};

    for (const [name, config] of Object.entries(servers)) {
      normalized[name] = normalizeServer(config as Record<string, unknown>);
    }

    return { mcpServers: normalized };
  }

  throw new Error(
    `Unrecognized MCP config format. Expected "mcpServers" or "servers" key.`
  );
}

function normalizeServer(raw: Record<string, unknown>): MCPServerConfig {
  const server: MCPServerConfig = {
    command: (raw["command"] as string) ?? "",
  };

  if (raw["args"]) server.args = raw["args"] as string[];
  if (raw["env"]) server.env = raw["env"] as Record<string, string>;
  if (raw["url"]) server.url = raw["url"] as string;

  if (raw["transport"]) {
    server.transport = raw["transport"] as MCPServerConfig["transport"];
  } else if (server.url) {
    server.transport = "sse";
  } else {
    server.transport = "stdio";
  }

  return server;
}

export function expandConfigPath(template: string): string {
  return template
    .replace(/%(\w+)%/g, (_, key) => process.env[key] ?? "")
    .replace(/^~/, process.env["HOME"] ?? process.env["USERPROFILE"] ?? "");
}

export function getDefaultConfigPaths(): string[] {
  const platform = process.platform as keyof typeof KNOWN_CONFIG_PATHS;
  const templates = KNOWN_CONFIG_PATHS[platform] ?? [];
  return templates.map(expandConfigPath);
}
