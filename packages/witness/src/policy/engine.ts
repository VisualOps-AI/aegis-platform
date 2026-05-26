import type { WitnessPolicy, ToolPolicy, PolicyDecisionType } from './parser.js';

export interface PolicyDecision {
  decision: PolicyDecisionType;
  reason?: string;
  riskScore: number;
}

const RISK_SCORES: Record<PolicyDecisionType, number> = {
  deny: 1.0,
  require_approval: 0.7,
  allow_shadow: 0.3,
  allow: 0.0,
};

export class PolicyEngine {
  private policy: WitnessPolicy;

  constructor(policy: WitnessPolicy) {
    this.policy = policy;
  }

  evaluate(toolName: string, args: Record<string, unknown>): PolicyDecision {
    const toolPolicy = this.policy.tools[toolName];

    if (!toolPolicy) {
      return this.fromDecision(this.policy.defaults.decision);
    }

    if (toolName === 'terminal.exec') {
      return this.evaluateTerminalExec(toolPolicy, args);
    }

    if (toolName === 'filesystem.write') {
      return this.evaluateFilesystemWrite(toolPolicy, args);
    }

    return this.fromDecision(toolPolicy.default);
  }

  private evaluateTerminalExec(
    toolPolicy: ToolPolicy,
    args: Record<string, unknown>,
  ): PolicyDecision {
    const command = typeof args['command'] === 'string' ? args['command'] : '';

    if (toolPolicy.rules) {
      for (const rule of toolPolicy.rules) {
        const regex = new RegExp(rule.match);
        if (regex.test(command)) {
          return this.fromDecision(rule.decision, rule.reason);
        }
      }
    }

    return this.fromDecision(toolPolicy.default);
  }

  private evaluateFilesystemWrite(
    toolPolicy: ToolPolicy,
    args: Record<string, unknown>,
  ): PolicyDecision {
    const path = typeof args['path'] === 'string' ? args['path'] : '';

    if (toolPolicy.denied_paths) {
      for (const pattern of toolPolicy.denied_paths) {
        if (globMatch(pattern, path)) {
          return this.fromDecision('deny', `path matches denied pattern: ${pattern}`);
        }
      }
    }

    if (toolPolicy.allowed_paths) {
      for (const pattern of toolPolicy.allowed_paths) {
        if (globMatch(pattern, path)) {
          return this.fromDecision(toolPolicy.default);
        }
      }
      return this.fromDecision('deny', 'path not in allowed_paths');
    }

    return this.fromDecision(toolPolicy.default);
  }

  private fromDecision(decision: PolicyDecisionType, reason?: string): PolicyDecision {
    return {
      decision,
      reason,
      riskScore: RISK_SCORES[decision],
    };
  }
}

function globMatch(pattern: string, path: string): boolean {
  if (pattern === path) return true;

  if (pattern.startsWith('**/')) {
    const suffix = pattern.slice(3);
    if (suffix.includes('*')) {
      const prefix = suffix.replace(/\*+/g, '');
      return path.includes(prefix);
    }
    return path.endsWith(suffix) || path.includes(suffix.startsWith('/') ? suffix : `/${suffix}`);
  }

  if (pattern.endsWith('/**')) {
    const prefix = pattern.slice(0, -3);
    return path.startsWith(prefix) || path === prefix;
  }

  if (pattern.includes('**')) {
    const [before, after] = pattern.split('**');
    const cleanAfter = after.replace(/\*+/g, '');
    return path.startsWith(before) && (cleanAfter === '' || path.includes(cleanAfter));
  }

  if (pattern.includes('*')) {
    const parts = pattern.split('*');
    let pos = 0;
    for (const part of parts) {
      if (part === '') continue;
      const idx = path.indexOf(part, pos);
      if (idx === -1) return false;
      pos = idx + part.length;
    }
    return true;
  }

  return false;
}
