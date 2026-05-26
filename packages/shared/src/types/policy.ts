export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  source: "phantom" | "manual" | "witness";
  findingId?: string;
  pattern: DetectionPattern;
  action: "alert" | "block" | "shadow" | "kill";
  severity: "critical" | "high" | "medium" | "low";
  enabled: boolean;
  createdAt: string;
}

export interface DetectionPattern {
  type: "tool-call" | "sequence" | "parameter" | "frequency";
  toolName?: string;
  parameterMatch?: Record<string, string | RegExp>;
  sequence?: string[];
  threshold?: number;
  window?: number;
}

export interface SandboxPolicy {
  id: string;
  name: string;
  description: string;
  source: "phantom" | "manual";
  findingId?: string;
  rules: SandboxRule[];
  riskThreshold: number;
  enabled: boolean;
  createdAt: string;
}

export interface SandboxRule {
  match: {
    tool?: string;
    command?: string | RegExp;
    path?: string;
  };
  action: "allow" | "deny" | "shadow";
  risk: number;
}
