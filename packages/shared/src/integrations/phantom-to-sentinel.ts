import type {
  Finding,
  ScanReport,
  DetectionRule,
  DetectionPattern,
} from "../types/index.js";

export function generateSentinelRules(report: ScanReport): DetectionRule[] {
  return report.results.flatMap((result) =>
    result.findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .map((finding) => findingToRule(finding))
  );
}

function findingToRule(finding: Finding): DetectionRule {
  const pattern = buildPattern(finding);

  return {
    id: `phantom-${finding.id.slice(0, 8)}`,
    name: `[Phantom] ${finding.title}`,
    description: finding.description,
    source: "phantom",
    findingId: finding.id,
    pattern,
    action: finding.severity === "critical" ? "block" : "alert",
    severity: finding.severity === "critical" ? "critical" : "high",
    enabled: true,
    createdAt: new Date().toISOString(),
  };
}

function buildPattern(finding: Finding): DetectionPattern {
  if (finding.category === "tool-chain" && finding.attackChain.length > 1) {
    return {
      type: "sequence",
      sequence: finding.attackChain.map((s) => s.tool),
    };
  }

  if (
    finding.owasp.includes("AG05:PRIVILEGE_ESCALATION") ||
    finding.owasp.includes("AG04:IDENTITY_ABUSE")
  ) {
    return {
      type: "tool-call",
      toolName: finding.tool,
    };
  }

  return {
    type: "tool-call",
    toolName: finding.tool,
  };
}

export function formatSentinelHeuristic(rule: DetectionRule): string {
  const lines: string[] = [];
  lines.push(`# ${rule.name}`);
  lines.push(`# Source: Phantom scan (${rule.findingId})`);
  lines.push(`# Severity: ${rule.severity}`);
  lines.push(`# Action: ${rule.action}`);
  lines.push("");

  if (rule.pattern.type === "sequence") {
    lines.push(`type: sequence`);
    lines.push(`tools: [${rule.pattern.sequence?.join(", ")}]`);
    lines.push(`window: ${rule.pattern.window ?? 300}s`);
  } else if (rule.pattern.type === "tool-call") {
    lines.push(`type: tool-call`);
    lines.push(`tool: ${rule.pattern.toolName}`);
  }

  return lines.join("\n");
}
