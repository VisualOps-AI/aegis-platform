import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

export interface ToolRule {
  match: string;
  decision: PolicyDecisionType;
  reason?: string;
}

export type PolicyDecisionType = 'allow' | 'deny' | 'require_approval' | 'allow_shadow';

export interface ToolPolicy {
  default: PolicyDecisionType;
  rules?: ToolRule[];
  allowed_paths?: string[];
  denied_paths?: string[];
  allowed_domains?: string[];
  redact_headers?: string[];
}

export interface AgentPolicy {
  id: string;
  allowed_tools: string[];
}

export interface PolicyDefaults {
  decision: PolicyDecisionType;
  sandbox: string;
}

export interface RiskThresholds {
  auto_approve_max: number;
  require_approval_min: number;
}

export interface WitnessPolicy {
  witness_version: string;
  policy_name: string;
  defaults: PolicyDefaults;
  agents: AgentPolicy[];
  tools: Record<string, ToolPolicy>;
  risk_thresholds: RiskThresholds;
}

export function loadPolicy(configPath: string): WitnessPolicy {
  const raw = readFileSync(configPath, 'utf-8');
  return parse(raw) as WitnessPolicy;
}

export function loadDefaultPolicy(): WitnessPolicy {
  return {
    witness_version: '0.1.0',
    policy_name: 'default',
    defaults: {
      decision: 'require_approval',
      sandbox: 'shadow_workspace',
    },
    agents: [
      {
        id: '*',
        allowed_tools: ['filesystem.read', 'filesystem.write', 'terminal.exec'],
      },
    ],
    tools: {
      'terminal.exec': {
        default: 'require_approval',
        rules: [
          { match: 'rm -rf', decision: 'deny', reason: 'destructive_delete' },
          { match: 'sudo', decision: 'deny', reason: 'privilege_escalation' },
        ],
      },
      'filesystem.write': {
        default: 'allow_shadow',
        allowed_paths: ['./src/**', './tests/**'],
        denied_paths: ['**/.env*', '**/secrets/**'],
      },
    },
    risk_thresholds: {
      auto_approve_max: 0.3,
      require_approval_min: 0.7,
    },
  };
}
