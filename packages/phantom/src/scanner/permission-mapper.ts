import type {
  MCPConfig,
  MCPServerConfig,
  MCPToolDefinition,
  ToolCapability,
} from "@aegis/shared";
import { inferCapabilities } from "./tool-graph.js";

export interface PermissionProfile {
  server: string;
  config: MCPServerConfig;
  tools: MCPToolDefinition[];
  aggregateCapabilities: ToolCapability;
  risks: PermissionRisk[];
  authModel: AuthModel;
}

export interface PermissionRisk {
  type:
    | "god-key"
    | "no-auth"
    | "env-leak"
    | "broad-filesystem"
    | "unrestricted-exec"
    | "unrestricted-network"
    | "cross-server-access";
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  evidence: string;
}

export interface AuthModel {
  type: "none" | "env-token" | "oauth" | "api-key" | "unknown";
  credentials: string[];
  shared: boolean;
}

const SENSITIVE_ENV_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /token/i,
  /password/i,
  /auth/i,
  /credential/i,
  /private[_-]?key/i,
];

export function mapPermissions(
  config: MCPConfig,
  toolsByServer: Map<string, MCPToolDefinition[]>
): PermissionProfile[] {
  const profiles: PermissionProfile[] = [];
  const allCredentials = new Set<string>();

  for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
    const tools = toolsByServer.get(name) ?? [];
    const aggregateCapabilities = aggregateToolCapabilities(tools);
    const authModel = detectAuthModel(serverConfig, allCredentials);
    const risks = assessPermissionRisks(
      name,
      serverConfig,
      tools,
      aggregateCapabilities,
      authModel
    );

    profiles.push({
      server: name,
      config: serverConfig,
      tools,
      aggregateCapabilities,
      risks,
      authModel,
    });
  }

  detectCrossServerRisks(profiles, allCredentials);

  return profiles;
}

function aggregateToolCapabilities(
  tools: MCPToolDefinition[]
): ToolCapability {
  const aggregate: ToolCapability = {
    reads: [],
    writes: [],
    executes: [],
    network: false,
    filesystem: false,
    database: false,
    messaging: false,
  };

  for (const tool of tools) {
    const caps = inferCapabilities(tool);

    for (const key of ["reads", "writes", "executes"] as const) {
      const existing = aggregate[key] as string[];
      const incoming = caps[key] as string[];
      Object.assign(aggregate, { [key]: [...new Set([...existing, ...incoming])] });
    }

    for (const key of [
      "network",
      "filesystem",
      "database",
      "messaging",
    ] as const) {
      if (caps[key]) {
        Object.assign(aggregate, { [key]: true });
      }
    }
  }

  return aggregate;
}

function detectAuthModel(
  config: MCPServerConfig,
  allCredentials: Set<string>
): AuthModel {
  const env = config.env ?? {};
  const credentials: string[] = [];

  for (const key of Object.keys(env)) {
    if (SENSITIVE_ENV_PATTERNS.some((p) => p.test(key))) {
      credentials.push(key);
      allCredentials.add(env[key]);
    }
  }

  if (credentials.length === 0) {
    return { type: "none", credentials: [], shared: false };
  }

  const type = credentials.some((c) => /oauth/i.test(c))
    ? "oauth"
    : credentials.some((c) => /api[_-]?key/i.test(c))
      ? "api-key"
      : "env-token";

  return { type, credentials, shared: false };
}

function assessPermissionRisks(
  serverName: string,
  config: MCPServerConfig,
  tools: MCPToolDefinition[],
  capabilities: ToolCapability,
  authModel: AuthModel
): PermissionRisk[] {
  const risks: PermissionRisk[] = [];

  if (authModel.type === "none" && tools.length > 0) {
    risks.push({
      type: "no-auth",
      severity: "high",
      description: `Server "${serverName}" has no authentication credentials configured`,
      evidence: `No sensitive environment variables found in server config`,
    });
  }

  const execTools = (capabilities.executes as string[]);
  if (execTools.length > 0) {
    risks.push({
      type: "unrestricted-exec",
      severity: "critical",
      description: `Server "${serverName}" has execution capabilities with no restrictions`,
      evidence: `Tools with exec signals: ${execTools.join(", ")}`,
    });
  }

  if (capabilities.network && capabilities.filesystem) {
    risks.push({
      type: "broad-filesystem",
      severity: "high",
      description: `Server "${serverName}" combines filesystem and network access — potential exfiltration vector`,
      evidence: `Server has both filesystem and network capabilities`,
    });
  }

  const env = config.env ?? {};
  for (const [key, value] of Object.entries(env)) {
    if (value && value.length < 256 && !SENSITIVE_ENV_PATTERNS.some((p) => p.test(key))) continue;
    if (SENSITIVE_ENV_PATTERNS.some((p) => p.test(key)) && value?.includes("sk-")) {
      risks.push({
        type: "env-leak",
        severity: "medium",
        description: `Server "${serverName}" has a potentially hardcoded secret in env var "${key}"`,
        evidence: `Env var "${key}" contains a value matching known API key patterns`,
      });
    }
  }

  return risks;
}

function detectCrossServerRisks(
  profiles: PermissionProfile[],
  allCredentials: Set<string>
): void {
  const credToServers = new Map<string, string[]>();

  for (const profile of profiles) {
    const env = profile.config.env ?? {};
    for (const value of Object.values(env)) {
      if (allCredentials.has(value)) {
        const servers = credToServers.get(value) ?? [];
        servers.push(profile.server);
        credToServers.set(value, servers);
      }
    }
  }

  for (const [, servers] of credToServers) {
    if (servers.length > 1) {
      for (const profile of profiles) {
        if (servers.includes(profile.server)) {
          profile.authModel.shared = true;
          profile.risks.push({
            type: "god-key",
            severity: "critical",
            description: `Credential shared across servers: ${servers.join(", ")} — God Key pattern detected`,
            evidence: `Same credential value used by ${servers.length} MCP servers`,
          });
        }
      }
    }
  }
}
