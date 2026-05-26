import type { Finding, OwaspAgenticCategory, ScanReport } from "@aegis/shared";

interface OwaspEntry {
  id: OwaspAgenticCategory;
  name: string;
  description: string;
  mitigations: string[];
}

const OWASP_AGENTIC_TOP_10: OwaspEntry[] = [
  {
    id: "AG01:EXCESSIVE_AGENCY",
    name: "Excessive Agency",
    description:
      "The agent has more capabilities, permissions, or autonomy than required for its intended purpose.",
    mitigations: [
      "Apply least-privilege to tool access",
      "Restrict agent scope to minimum required tools",
      "Implement approval workflows for sensitive operations",
    ],
  },
  {
    id: "AG02:BEHAVIOR_HIJACKING",
    name: "Behavior Hijacking",
    description:
      "Agent behavior is redirected through prompt injection, context manipulation, or adversarial inputs.",
    mitigations: [
      "Implement input validation and sanitization",
      "Use system prompt hardening techniques",
      "Deploy prompt injection detection (Sentinel)",
    ],
  },
  {
    id: "AG03:TOOL_MISUSE",
    name: "Tool Misuse",
    description:
      "Tools are used outside their intended purpose or in unintended combinations.",
    mitigations: [
      "Define and enforce tool usage policies",
      "Monitor tool call patterns for anomalies",
      "Implement tool call sequence validation",
    ],
  },
  {
    id: "AG04:IDENTITY_ABUSE",
    name: "Identity & Credential Abuse",
    description:
      "Agent identity is spoofed, credentials are shared or leaked, or authentication is bypassed.",
    mitigations: [
      "Use unique credentials per MCP server",
      "Implement credential rotation",
      "Use OAuth2 with scoped tokens",
    ],
  },
  {
    id: "AG05:PRIVILEGE_ESCALATION",
    name: "Privilege Escalation",
    description:
      "Access is elevated beyond authorized levels through tool chaining, credential reuse, or boundary bypass.",
    mitigations: [
      "Isolate high-privilege tools in separate sessions",
      "Implement step-up authentication for sensitive operations",
      "Monitor for privilege escalation patterns",
    ],
  },
  {
    id: "AG06:DATA_EXFILTRATION",
    name: "Data Exfiltration",
    description:
      "Sensitive data is extracted through unintended channels by combining read and send capabilities.",
    mitigations: [
      "Deploy DLP scanning on tool outputs",
      "Separate read and network tools into different sessions",
      "Use network allowlists for outbound connections",
    ],
  },
  {
    id: "AG07:SUPPLY_CHAIN",
    name: "Supply Chain Compromise",
    description:
      "MCP servers, tool definitions, or dependencies are compromised or poisoned.",
    mitigations: [
      "Verify MCP server authenticity and integrity",
      "Pin MCP server versions",
      "Audit tool descriptions for poisoning",
    ],
  },
  {
    id: "AG08:CONTEXT_MANIPULATION",
    name: "Context Manipulation",
    description:
      "Agent context is poisoned through multi-turn attacks, injected tool outputs, or accumulated manipulation.",
    mitigations: [
      "Implement context isolation between tasks",
      "Validate tool outputs before adding to context",
      "Use Witness shadow timelines to detect context drift",
    ],
  },
  {
    id: "AG09:MULTI_AGENT_TRUST",
    name: "Multi-Agent Trust Exploitation",
    description:
      "Trust relationships between agents are exploited for lateral movement or policy bypass.",
    mitigations: [
      "Implement zero-trust between agents",
      "Require explicit authorization for inter-agent requests",
      "Audit inter-agent communication",
    ],
  },
  {
    id: "AG10:AUDIT_EVASION",
    name: "Audit Evasion",
    description:
      "Actions evade logging, monitoring, or accountability mechanisms.",
    mitigations: [
      "Use immutable audit logs (Witness)",
      "Log all tool calls with full input/output",
      "Implement cryptographic receipts for critical actions",
    ],
  },
];

export function mapToOwasp(report: ScanReport): OwaspMapping[] {
  const categoryMap = new Map<OwaspAgenticCategory, Finding[]>();

  for (const result of report.results) {
    for (const finding of result.findings) {
      for (const cat of finding.owasp) {
        const existing = categoryMap.get(cat) ?? [];
        existing.push(finding);
        categoryMap.set(cat, existing);
      }
    }
  }

  return OWASP_AGENTIC_TOP_10.map((entry) => ({
    ...entry,
    findings: categoryMap.get(entry.id) ?? [],
    status: getComplianceStatus(categoryMap.get(entry.id) ?? []),
  }));
}

export interface OwaspMapping extends OwaspEntry {
  findings: Finding[];
  status: "pass" | "warn" | "fail";
}

function getComplianceStatus(findings: Finding[]): "pass" | "warn" | "fail" {
  if (findings.length === 0) return "pass";
  if (findings.some((f) => f.severity === "critical" || f.severity === "high"))
    return "fail";
  return "warn";
}

export function getOwaspEntry(
  id: OwaspAgenticCategory
): OwaspEntry | undefined {
  return OWASP_AGENTIC_TOP_10.find((e) => e.id === id);
}
