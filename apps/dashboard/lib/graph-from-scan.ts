import type { ScanReport } from "@aegis/shared";
import type { AttackGraphData } from "@/components/attack-graph";

export function buildGraphFromScan(scan: ScanReport): AttackGraphData {
  const allFindings = scan.results.flatMap((r) => r.findings);
  const toolSet = new Map<string, { server: string; riskScore: number; capabilities: Set<string> }>();
  const edgeSet = new Map<string, { from: string; to: string; relationship: string; risk: number }>();

  for (const finding of allFindings) {
    const severityWeight =
      finding.severity === "critical" ? 9
        : finding.severity === "high" ? 7
          : finding.severity === "medium" ? 5
            : finding.severity === "low" ? 3
              : 1;

    if (!toolSet.has(finding.tool)) {
      toolSet.set(finding.tool, {
        server: finding.tool.split(":")[0] || finding.tool,
        riskScore: severityWeight,
        capabilities: new Set(),
      });
    } else {
      const existing = toolSet.get(finding.tool)!;
      existing.riskScore = Math.max(existing.riskScore, severityWeight);
    }

    inferCapabilities(finding.tool, finding.category, toolSet);

    for (let i = 0; i < finding.attackChain.length - 1; i++) {
      const from = finding.attackChain[i].tool;
      const to = finding.attackChain[i + 1].tool;
      if (from === to) continue;

      ensureTool(from, toolSet, finding);
      ensureTool(to, toolSet, finding);

      const relationship = inferRelationship(finding.category);
      const key = `${from}→${to}`;

      if (!edgeSet.has(key)) {
        edgeSet.set(key, {
          from,
          to,
          relationship,
          risk: severityWeight,
        });
      } else {
        const existing = edgeSet.get(key)!;
        existing.risk = Math.max(existing.risk, severityWeight);
      }
    }
  }

  const nodes = Array.from(toolSet.entries()).map(([id, info]) => ({
    id,
    server: info.server,
    riskScore: info.riskScore,
    capabilities: {
      reads: info.capabilities.has("reads") ? ["yes"] : [],
      writes: info.capabilities.has("writes") ? ["yes"] : [],
      executes: info.capabilities.has("executes") ? ["yes"] : [],
      network: info.capabilities.has("network"),
      filesystem: info.capabilities.has("filesystem"),
      database: info.capabilities.has("database"),
      messaging: info.capabilities.has("messaging"),
    },
  }));

  const edges = Array.from(edgeSet.values()).map((e) => ({
    ...e,
    relationship: e.relationship as "data-flow" | "escalation" | "exfiltration" | "mutation",
  }));

  return { nodes, edges };
}

function ensureTool(
  toolId: string,
  toolSet: Map<string, { server: string; riskScore: number; capabilities: Set<string> }>,
  finding: { severity: string },
): void {
  if (!toolSet.has(toolId)) {
    toolSet.set(toolId, {
      server: toolId.split(":")[0] || toolId,
      riskScore: finding.severity === "critical" ? 9 : finding.severity === "high" ? 7 : 5,
      capabilities: new Set(),
    });
  }
}

function inferCapabilities(
  tool: string,
  category: string,
  toolSet: Map<string, { server: string; riskScore: number; capabilities: Set<string> }>,
): void {
  const info = toolSet.get(tool);
  if (!info) return;

  const lower = tool.toLowerCase();
  if (lower.includes("read") || lower.includes("get") || lower.includes("list")) info.capabilities.add("reads");
  if (lower.includes("write") || lower.includes("create") || lower.includes("edit")) info.capabilities.add("writes");
  if (lower.includes("exec") || lower.includes("shell") || lower.includes("run")) info.capabilities.add("executes");
  if (lower.includes("http") || lower.includes("fetch") || lower.includes("send")) info.capabilities.add("network");
  if (lower.includes("file") || lower.includes("fs") || lower.includes("dir")) info.capabilities.add("filesystem");
  if (lower.includes("db") || lower.includes("sql") || lower.includes("query")) info.capabilities.add("database");
  if (lower.includes("slack") || lower.includes("email") || lower.includes("message")) info.capabilities.add("messaging");

  if (category === "indirect-injection") info.capabilities.add("network");
  if (category === "auth-boundary") info.capabilities.add("filesystem");
}

function inferRelationship(category: string): string {
  switch (category) {
    case "tool-chain":
    case "multi-agent":
      return "escalation";
    case "indirect-injection":
    case "context-poison":
      return "data-flow";
    case "supply-chain":
      return "mutation";
    case "auth-boundary":
      return "exfiltration";
    default:
      return "data-flow";
  }
}
