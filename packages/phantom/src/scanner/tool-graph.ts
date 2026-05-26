import type {
  MCPToolDefinition,
  ToolCapability,
  ToolNode,
  ToolEdge,
  ToolGraph,
} from "@aegis/shared";

const CAPABILITY_SIGNALS: Record<keyof ToolCapability, string[]> = {
  reads: [
    "read",
    "get",
    "fetch",
    "list",
    "search",
    "query",
    "select",
    "view",
    "cat",
    "head",
    "tail",
    "find",
    "glob",
    "grep",
  ],
  writes: [
    "write",
    "create",
    "update",
    "put",
    "patch",
    "set",
    "insert",
    "edit",
    "modify",
    "append",
    "delete",
    "remove",
    "drop",
  ],
  executes: [
    "exec",
    "run",
    "execute",
    "shell",
    "bash",
    "cmd",
    "spawn",
    "eval",
    "invoke",
    "call",
  ],
  network: [
    "http",
    "fetch",
    "request",
    "api",
    "url",
    "webhook",
    "send",
    "post",
    "email",
    "slack",
    "notify",
    "message",
  ],
  filesystem: [
    "file",
    "dir",
    "directory",
    "path",
    "folder",
    "fs",
    "disk",
    "volume",
    "mount",
  ],
  database: [
    "db",
    "database",
    "sql",
    "query",
    "table",
    "collection",
    "record",
    "row",
    "mongo",
    "postgres",
    "redis",
  ],
  messaging: [
    "email",
    "slack",
    "message",
    "notify",
    "alert",
    "sms",
    "chat",
    "discord",
    "webhook",
    "publish",
  ],
};

const RISK_WEIGHTS: Record<keyof ToolCapability, number> = {
  reads: 0.1,
  writes: 0.3,
  executes: 0.5,
  network: 0.3,
  filesystem: 0.2,
  database: 0.3,
  messaging: 0.2,
};

const DANGEROUS_CHAINS: Array<{
  from: keyof ToolCapability;
  to: keyof ToolCapability;
  relationship: ToolEdge["relationship"];
  riskMultiplier: number;
}> = [
  {
    from: "reads",
    to: "network",
    relationship: "exfiltration",
    riskMultiplier: 2.5,
  },
  {
    from: "reads",
    to: "messaging",
    relationship: "exfiltration",
    riskMultiplier: 2.5,
  },
  {
    from: "database",
    to: "network",
    relationship: "exfiltration",
    riskMultiplier: 3.0,
  },
  {
    from: "database",
    to: "messaging",
    relationship: "exfiltration",
    riskMultiplier: 3.0,
  },
  {
    from: "reads",
    to: "writes",
    relationship: "mutation",
    riskMultiplier: 1.5,
  },
  {
    from: "reads",
    to: "executes",
    relationship: "escalation",
    riskMultiplier: 3.0,
  },
  {
    from: "network",
    to: "executes",
    relationship: "escalation",
    riskMultiplier: 3.5,
  },
  {
    from: "network",
    to: "writes",
    relationship: "mutation",
    riskMultiplier: 2.0,
  },
  {
    from: "database",
    to: "writes",
    relationship: "mutation",
    riskMultiplier: 2.0,
  },
  {
    from: "filesystem",
    to: "executes",
    relationship: "escalation",
    riskMultiplier: 3.0,
  },
];

export function buildToolGraph(tools: MCPToolDefinition[]): ToolGraph {
  const nodes = new Map<string, ToolNode>();
  const edges: ToolEdge[] = [];

  for (const tool of tools) {
    const capabilities = inferCapabilities(tool);
    const riskScore = calculateRiskScore(capabilities);
    nodes.set(tool.name, { tool, capabilities, riskScore });
  }

  for (const [nameA, nodeA] of nodes) {
    for (const [nameB, nodeB] of nodes) {
      if (nameA === nameB) continue;

      for (const chain of DANGEROUS_CHAINS) {
        const fromCap = nodeA.capabilities[chain.from];
        const toCap = nodeB.capabilities[chain.to];
        const fromActive = Array.isArray(fromCap)
          ? fromCap.length > 0
          : fromCap;
        const toActive = Array.isArray(toCap) ? toCap.length > 0 : toCap;

        if (fromActive && toActive) {
          const baseRisk =
            (nodeA.riskScore + nodeB.riskScore) / 2;
          edges.push({
            from: nameA,
            to: nameB,
            relationship: chain.relationship,
            risk: Math.min(1.0, baseRisk * chain.riskMultiplier),
          });
        }
      }
    }
  }

  return { nodes, edges };
}

export function inferCapabilities(
  tool: MCPToolDefinition
): ToolCapability {
  const text =
    `${tool.name} ${tool.description} ${serializeSchema(tool.inputSchema)}`.toLowerCase();

  const capabilities: ToolCapability = {
    reads: [],
    writes: [],
    executes: [],
    network: false,
    filesystem: false,
    database: false,
    messaging: false,
  };

  for (const [cap, signals] of Object.entries(CAPABILITY_SIGNALS)) {
    const matches = signals.filter((s) => text.includes(s));
    const key = cap as keyof ToolCapability;

    if (typeof capabilities[key] === "boolean") {
      Object.assign(capabilities, { [key]: matches.length > 0 });
    } else {
      Object.assign(capabilities, { [key]: matches });
    }
  }

  return capabilities;
}

function calculateRiskScore(capabilities: ToolCapability): number {
  let score = 0;

  for (const [cap, weight] of Object.entries(RISK_WEIGHTS)) {
    const val = capabilities[cap as keyof ToolCapability];
    if (typeof val === "boolean") {
      score += val ? weight : 0;
    } else if (Array.isArray(val)) {
      score += val.length > 0 ? weight : 0;
    }
  }

  return Math.min(1.0, score);
}

function serializeSchema(schema: unknown): string {
  if (!schema || typeof schema !== "object") return "";
  return JSON.stringify(schema);
}

export function getHighRiskEdges(graph: ToolGraph, threshold = 0.6): ToolEdge[] {
  return graph.edges
    .filter((e) => e.risk >= threshold)
    .sort((a, b) => b.risk - a.risk);
}

export function getExfiltrationPaths(graph: ToolGraph): ToolEdge[] {
  return graph.edges.filter((e) => e.relationship === "exfiltration");
}

export function getEscalationPaths(graph: ToolGraph): ToolEdge[] {
  return graph.edges.filter((e) => e.relationship === "escalation");
}
