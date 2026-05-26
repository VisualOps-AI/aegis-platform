export type {
  Severity,
  AttackCategory,
  OwaspAgenticCategory,
  Finding,
  AttackStep,
  AttackResult,
  ScanReport,
  ReportSummary,
  MCPConfig,
  MCPServerConfig,
  MCPToolDefinition,
  MCPToolSchema,
  MCPPropertySchema,
  ToolCapability,
  ToolNode,
  ToolEdge,
  ToolGraph,
  DetectionRule,
  DetectionPattern,
  SandboxPolicy,
  SandboxRule,
} from "./types/index.js";

export {
  generateSentinelRules,
  formatSentinelHeuristic,
  generateWitnessPolicies,
  generateWitnessYaml,
  auditEventToAlert,
  batchAuditEvents,
} from "./integrations/index.js";

export type { WitnessAuditEvent } from "./integrations/index.js";
