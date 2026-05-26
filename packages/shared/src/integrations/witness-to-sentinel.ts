import type { DetectionRule } from "../types/index.js";

export interface WitnessAuditEvent {
  id: string;
  sessionId: string;
  type: "tool_call" | "shadow_exec" | "policy_deny" | "timeline_merge" | "timeline_reject";
  tool: string;
  action: string;
  input: Record<string, unknown>;
  output?: string;
  risk: number;
  decision: "allow" | "deny" | "shadow";
  timestamp: string;
}

export function auditEventToAlert(event: WitnessAuditEvent): DetectionRule | null {
  if (event.type === "policy_deny" || event.type === "timeline_reject") {
    return {
      id: `witness-${event.id.slice(0, 8)}`,
      name: `[Witness] Denied: ${event.tool} — ${event.action}`,
      description: `Witness ${event.type === "policy_deny" ? "policy denied" : "rejected timeline for"} tool "${event.tool}" action "${event.action}" with risk ${event.risk}`,
      source: "witness",
      pattern: {
        type: "tool-call",
        toolName: event.tool,
      },
      action: event.risk >= 0.8 ? "kill" : "alert",
      severity: event.risk >= 0.8 ? "critical" : "high",
      enabled: true,
      createdAt: new Date().toISOString(),
    };
  }

  if (event.type === "shadow_exec" && event.risk >= 0.7) {
    return {
      id: `witness-shadow-${event.id.slice(0, 8)}`,
      name: `[Witness] High-Risk Shadow: ${event.tool}`,
      description: `Witness shadow-executed "${event.tool}" with risk ${event.risk}. Review shadow diff for unexpected changes.`,
      source: "witness",
      pattern: {
        type: "tool-call",
        toolName: event.tool,
      },
      action: "alert",
      severity: "high",
      enabled: true,
      createdAt: new Date().toISOString(),
    };
  }

  return null;
}

export function batchAuditEvents(
  events: WitnessAuditEvent[]
): DetectionRule[] {
  return events
    .map(auditEventToAlert)
    .filter((rule): rule is DetectionRule => rule !== null);
}
