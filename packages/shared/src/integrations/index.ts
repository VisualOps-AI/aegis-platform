export { generateSentinelRules, formatSentinelHeuristic } from "./phantom-to-sentinel.js";
export { generateWitnessPolicies, generateWitnessYaml } from "./phantom-to-witness.js";
export { auditEventToAlert, batchAuditEvents } from "./witness-to-sentinel.js";
export type { WitnessAuditEvent } from "./witness-to-sentinel.js";
