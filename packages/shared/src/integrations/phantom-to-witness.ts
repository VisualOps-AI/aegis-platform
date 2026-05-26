import type { Finding, ScanReport, SandboxPolicy, SandboxRule } from "../types/index.js";

interface WitnessYamlPolicy {
  witness_version: string;
  policy_name: string;
  generated_by: string;
  generated_at: string;
  scan_id: string;
  defaults: { decision: string; sandbox: string };
  tools: Record<string, WitnessToolPolicy>;
  risk_thresholds: { auto_approve_max: number; require_approval_min: number };
}

interface WitnessToolPolicy {
  default: string;
  rules: Array<{
    match: string;
    decision: string;
    reason: string;
  }>;
  allowed_paths?: string[];
  denied_paths?: string[];
  allowed_domains?: string[];
}

export function generateWitnessPolicies(report: ScanReport): SandboxPolicy[] {
  return report.results.flatMap((result) =>
    result.findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .map((finding) => findingToPolicy(finding))
  );
}

export function generateWitnessYaml(report: ScanReport): string {
  const policies = generateWitnessPolicies(report);
  const yaml = buildYamlPolicy(report, policies);
  return serializeYaml(yaml);
}

function findingToPolicy(finding: Finding): SandboxPolicy {
  const rules = buildRulesFromFinding(finding);

  return {
    id: `phantom-${finding.id.slice(0, 8)}`,
    name: `Auto: ${finding.title}`,
    description: finding.description,
    source: "phantom",
    findingId: finding.id,
    rules,
    riskThreshold: finding.severity === "critical" ? 0.9 : 0.7,
    enabled: true,
    createdAt: new Date().toISOString(),
  };
}

function buildRulesFromFinding(finding: Finding): SandboxRule[] {
  const rules: SandboxRule[] = [];

  if (finding.category === "auth-boundary") {
    rules.push({
      match: { tool: finding.tool },
      action: "shadow",
      risk: 0.8,
    });
  }

  if (finding.category === "tool-chain") {
    for (const step of finding.attackChain) {
      rules.push({
        match: { tool: step.tool },
        action: "shadow",
        risk: 0.7,
      });
    }
  }

  if (
    finding.owasp.includes("AG05:PRIVILEGE_ESCALATION") ||
    finding.owasp.includes("AG06:DATA_EXFILTRATION")
  ) {
    rules.push({
      match: { tool: finding.tool },
      action: "deny",
      risk: 0.9,
    });
  }

  return rules;
}

function buildYamlPolicy(
  report: ScanReport,
  policies: SandboxPolicy[]
): WitnessYamlPolicy {
  const tools: Record<string, WitnessToolPolicy> = {};

  for (const policy of policies) {
    for (const rule of policy.rules) {
      const toolName = rule.match.tool ?? "*";
      if (!tools[toolName]) {
        tools[toolName] = {
          default: "require_approval",
          rules: [],
        };
      }

      tools[toolName].rules.push({
        match: rule.match.command?.toString() ?? ".*",
        decision: rule.action === "deny" ? "deny" : "allow_shadow",
        reason: `phantom:${policy.findingId?.slice(0, 8) ?? "auto"}`,
      });
    }
  }

  const maxSeverity = report.summary.bySeverity.critical > 0 ? 0.2 : 0.3;

  return {
    witness_version: "0.1.0",
    policy_name: `phantom-generated-${report.id.slice(0, 8)}`,
    generated_by: "aegis-phantom",
    generated_at: new Date().toISOString(),
    scan_id: report.id,
    defaults: { decision: "deny", sandbox: "shadow_workspace" },
    tools,
    risk_thresholds: {
      auto_approve_max: maxSeverity,
      require_approval_min: 0.7,
    },
  };
}

function serializeYaml(obj: WitnessYamlPolicy): string {
  const lines: string[] = [];
  lines.push(`witness_version: "${obj.witness_version}"`);
  lines.push(`policy_name: "${obj.policy_name}"`);
  lines.push(`generated_by: "${obj.generated_by}"`);
  lines.push(`generated_at: "${obj.generated_at}"`);
  lines.push(`scan_id: "${obj.scan_id}"`);
  lines.push("");
  lines.push("defaults:");
  lines.push(`  decision: ${obj.defaults.decision}`);
  lines.push(`  sandbox: ${obj.defaults.sandbox}`);
  lines.push("");
  lines.push("tools:");

  for (const [tool, policy] of Object.entries(obj.tools)) {
    lines.push(`  ${tool}:`);
    lines.push(`    default: ${policy.default}`);
    if (policy.rules.length > 0) {
      lines.push("    rules:");
      for (const rule of policy.rules) {
        lines.push(`      - match: "${rule.match}"`);
        lines.push(`        decision: ${rule.decision}`);
        lines.push(`        reason: "${rule.reason}"`);
      }
    }
  }

  lines.push("");
  lines.push("risk_thresholds:");
  lines.push(`  auto_approve_max: ${obj.risk_thresholds.auto_approve_max}`);
  lines.push(
    `  require_approval_min: ${obj.risk_thresholds.require_approval_min}`
  );

  return lines.join("\n") + "\n";
}
