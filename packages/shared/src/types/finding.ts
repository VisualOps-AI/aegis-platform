export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AttackCategory =
  | "auth-boundary"
  | "tool-chain"
  | "indirect-injection"
  | "multi-agent"
  | "supply-chain"
  | "context-poison";

export type OwaspAgenticCategory =
  | "AG01:EXCESSIVE_AGENCY"
  | "AG02:BEHAVIOR_HIJACKING"
  | "AG03:TOOL_MISUSE"
  | "AG04:IDENTITY_ABUSE"
  | "AG05:PRIVILEGE_ESCALATION"
  | "AG06:DATA_EXFILTRATION"
  | "AG07:SUPPLY_CHAIN"
  | "AG08:CONTEXT_MANIPULATION"
  | "AG09:MULTI_AGENT_TRUST"
  | "AG10:AUDIT_EVASION";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  owasp: OwaspAgenticCategory[];
  tool: string;
  attackChain: AttackStep[];
  evidence: string;
  reproduction: string;
  remediation: string;
  timestamp: string;
}

export interface AttackStep {
  tool: string;
  action: string;
  input: Record<string, unknown>;
  output?: string;
  success: boolean;
}

export interface AttackResult {
  module: AttackCategory;
  findings: Finding[];
  duration: number;
  toolsTested: number;
  chainsTested: number;
}

export interface ScanReport {
  id: string;
  timestamp: string;
  target: string;
  duration: number;
  results: AttackResult[];
  summary: ReportSummary;
}

export interface ReportSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<AttackCategory, number>;
  byOwasp: Partial<Record<OwaspAgenticCategory, number>>;
  riskScore: number;
}
