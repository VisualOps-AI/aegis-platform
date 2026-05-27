import { randomUUID } from "node:crypto";
import type { AttackResult, Finding } from "@aegis/shared";
import type { AttackContext } from "../engine/attack-runner.js";
import type { PermissionProfile } from "../scanner/permission-mapper.js";

interface MultiAgentThreat {
  name: string;
  description: string;
  severity: Finding["severity"];
  owasp: Finding["owasp"];
  detect: (ctx: AttackContext) => MultiAgentFinding[];
  remediationTemplate: string;
}

interface MultiAgentFinding {
  servers: string[];
  evidence: string;
  attackChain: Finding["attackChain"];
  reproduction: string;
}

const MULTI_AGENT_THREATS: MultiAgentThreat[] = [
  {
    name: "Shared MCP Server Cross-Agent Access",
    description:
      "Multiple agents sharing the same MCP server can access each other's data and operations. " +
      "There is no tenant isolation between agents on the same server.",
    severity: "critical",
    owasp: ["AG09:MULTI_AGENT_TRUST", "AG05:PRIVILEGE_ESCALATION"],
    detect: detectSharedServerAccess,
    remediationTemplate:
      "Deploy dedicated MCP server instances per agent. " +
      "Implement tenant isolation at the MCP server level. " +
      "Use agent-specific credentials with scoped permissions.",
  },
  {
    name: "Credential Leakage Between Agents",
    description:
      "Agents sharing credentials can impersonate each other. " +
      "A compromised low-privilege agent can use shared credentials to act as a high-privilege agent.",
    severity: "critical",
    owasp: [
      "AG04:IDENTITY_ABUSE",
      "AG09:MULTI_AGENT_TRUST",
      "AG05:PRIVILEGE_ESCALATION",
    ],
    detect: detectCredentialLeakage,
    remediationTemplate:
      "Issue unique credentials per agent identity. " +
      "Implement mutual TLS or JWT-based agent authentication. " +
      "Rotate credentials independently per agent.",
  },
  {
    name: "Cross-Agent Policy Bypass",
    description:
      "Agent A with restricted permissions can delegate tasks to Agent B which has broader access. " +
      "Policy enforcement at the agent level is bypassed through inter-agent delegation.",
    severity: "high",
    owasp: [
      "AG09:MULTI_AGENT_TRUST",
      "AG05:PRIVILEGE_ESCALATION",
      "AG01:EXCESSIVE_AGENCY",
    ],
    detect: detectPolicyBypass,
    remediationTemplate:
      "Implement policy propagation: delegated tasks inherit the caller's restrictions. " +
      "Use capability-based authorization that follows the request chain. " +
      "Enforce least-privilege at the tool call level, not just the agent level.",
  },
  {
    name: "Parent-to-Sub-Agent Context Injection",
    description:
      "A parent agent can inject malicious context into sub-agent prompts. " +
      "If the parent agent is compromised, all sub-agents inherit the compromise.",
    severity: "high",
    owasp: [
      "AG09:MULTI_AGENT_TRUST",
      "AG02:BEHAVIOR_HIJACKING",
      "AG08:CONTEXT_MANIPULATION",
    ],
    detect: detectParentContextInjection,
    remediationTemplate:
      "Validate and sanitize context passed between agents. " +
      "Sub-agents should have independent system prompts that cannot be overridden by parent context. " +
      "Implement context isolation boundaries between agent tiers.",
  },
  {
    name: "Inter-Agent Communication Eavesdropping",
    description:
      "Agent-to-agent communication over shared MCP servers is not encrypted or authenticated. " +
      "A third agent on the same server can observe or modify messages between other agents.",
    severity: "medium",
    owasp: [
      "AG09:MULTI_AGENT_TRUST",
      "AG10:AUDIT_EVASION",
      "AG06:DATA_EXFILTRATION",
    ],
    detect: detectCommunicationEavesdrop,
    remediationTemplate:
      "Encrypt inter-agent communications end-to-end. " +
      "Use authenticated channels for agent-to-agent messaging. " +
      "Log all inter-agent communications in Witness audit trail.",
  },
];

export async function runMultiAgentAttacks(
  ctx: AttackContext
): Promise<AttackResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  let toolsTested = 0;
  let chainsTested = 0;

  toolsTested = ctx.tools.length;

  for (const threat of MULTI_AGENT_THREATS) {
    const detected = threat.detect(ctx);
    chainsTested += detected.length;

    for (const detection of detected) {
      findings.push({
        id: randomUUID(),
        title: `Multi-Agent: ${threat.name}`,
        description: `${threat.description} Affected servers: ${detection.servers.join(", ")}.`,
        severity: threat.severity,
        category: "multi-agent",
        owasp: threat.owasp,
        tool: detection.servers[0],
        attackChain: detection.attackChain,
        evidence: detection.evidence,
        reproduction: detection.reproduction,
        remediation: threat.remediationTemplate,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return {
    module: "multi-agent",
    findings,
    duration: Date.now() - start,
    toolsTested,
    chainsTested,
  };
}

function detectSharedServerAccess(ctx: AttackContext): MultiAgentFinding[] {
  const results: MultiAgentFinding[] = [];

  const serversWithMultipleToolGroups = ctx.permissions.filter(
    (p) => p.tools.length > 1
  );

  for (const profile of serversWithMultipleToolGroups) {
    const hasExec = (profile.aggregateCapabilities.executes as string[]).length > 0;
    const hasData =
      profile.aggregateCapabilities.database ||
      (profile.aggregateCapabilities.reads as string[]).length > 0;

    if (hasExec || hasData) {
      results.push({
        servers: [profile.server],
        evidence:
          `Server "${profile.server}" hosts ${profile.tools.length} tools with mixed capabilities.\n` +
          `Exec capabilities: ${(profile.aggregateCapabilities.executes as string[]).join(", ") || "none"}\n` +
          `Data capabilities: ${(profile.aggregateCapabilities.reads as string[]).join(", ") || "none"}\n` +
          `Database access: ${profile.aggregateCapabilities.database}`,
        attackChain: [
          {
            tool: profile.server,
            action: "enumerate-shared-tools",
            input: { toolCount: profile.tools.length },
            success: true,
          },
          {
            tool: profile.server,
            action: "cross-agent-access",
            input: { type: "shared-server-exploitation" },
            success: true,
          },
        ],
        reproduction:
          `1. Connect to shared server "${profile.server}" as Agent A\n` +
          `2. Enumerate available tools (${profile.tools.length} found)\n` +
          `3. Access data or execute commands intended for Agent B\n` +
          "4. No tenant isolation prevents cross-agent access",
      });
    }
  }

  return results;
}

function detectCredentialLeakage(ctx: AttackContext): MultiAgentFinding[] {
  const results: MultiAgentFinding[] = [];

  const sharedCredProfiles = ctx.permissions.filter(
    (p) => p.authModel.shared
  );

  if (sharedCredProfiles.length >= 2) {
    const serverNames = sharedCredProfiles.map((p) => p.server);
    const credTypes = sharedCredProfiles
      .flatMap((p) => p.authModel.credentials)
      .filter((v, i, a) => a.indexOf(v) === i);

    results.push({
      servers: serverNames,
      evidence:
        `Shared credentials detected across ${serverNames.length} servers: ${serverNames.join(", ")}.\n` +
        `Credential variables: ${credTypes.join(", ")}.\n` +
        "Compromising one agent's credential compromises all agents using the same servers.",
      attackChain: serverNames.map((server) => ({
        tool: server,
        action: "credential-extraction",
        input: { type: "shared-credential-analysis" },
        success: true,
      })),
      reproduction:
        `1. Compromise Agent A on server "${serverNames[0]}"\n` +
        `2. Extract shared credential (${credTypes[0] ?? "API_KEY"})\n` +
        `3. Use extracted credential to authenticate as Agent B on "${serverNames[1] ?? serverNames[0]}"\n` +
        "4. Execute privileged operations as Agent B",
    });
  }

  return results;
}

function detectPolicyBypass(ctx: AttackContext): MultiAgentFinding[] {
  const results: MultiAgentFinding[] = [];

  const restrictedServers: PermissionProfile[] = [];
  const privilegedServers: PermissionProfile[] = [];

  for (const profile of ctx.permissions) {
    const isPrivileged =
      (profile.aggregateCapabilities.executes as string[]).length > 0 ||
      profile.aggregateCapabilities.database;
    const isRestricted =
      profile.authModel.type === "none" &&
      (profile.aggregateCapabilities.reads as string[]).length > 0;

    if (isPrivileged) privilegedServers.push(profile);
    if (isRestricted) restrictedServers.push(profile);
  }

  if (restrictedServers.length > 0 && privilegedServers.length > 0) {
    results.push({
      servers: [
        ...restrictedServers.map((p) => p.server),
        ...privilegedServers.map((p) => p.server),
      ],
      evidence:
        `Restricted servers (no auth): ${restrictedServers.map((p) => p.server).join(", ")}.\n` +
        `Privileged servers (exec/db): ${privilegedServers.map((p) => p.server).join(", ")}.\n` +
        "An agent on the restricted server can delegate to an agent on the privileged server.",
      attackChain: [
        {
          tool: restrictedServers[0].server,
          action: "restricted-agent-request",
          input: { type: "policy-restricted-operation" },
          success: true,
        },
        {
          tool: privilegedServers[0].server,
          action: "delegated-privileged-execution",
          input: { type: "policy-bypass-delegation" },
          success: true,
        },
      ],
      reproduction:
        `1. Agent A operates on restricted server "${restrictedServers[0].server}" (no exec access)\n` +
        `2. Agent A crafts a request that delegates to Agent B on "${privilegedServers[0].server}"\n` +
        "3. Agent B executes the request with its elevated privileges\n" +
        "4. Result: Agent A achieves privilege escalation through delegation",
    });
  }

  return results;
}

function detectParentContextInjection(
  ctx: AttackContext
): MultiAgentFinding[] {
  const results: MultiAgentFinding[] = [];

  const serverCount = Object.keys(ctx.config.mcpServers).length;
  if (serverCount < 2) return results;

  const execServers = ctx.permissions.filter(
    (p) => (p.aggregateCapabilities.executes as string[]).length > 0
  );
  const dataServers = ctx.permissions.filter(
    (p) =>
      (p.aggregateCapabilities.reads as string[]).length > 0 ||
      p.aggregateCapabilities.database
  );

  if (execServers.length > 0 && dataServers.length > 0) {
    results.push({
      servers: [
        ...dataServers.map((p) => p.server),
        ...execServers.map((p) => p.server),
      ],
      evidence:
        "Multi-server architecture detected with both data and execution capabilities.\n" +
        `Data servers: ${dataServers.map((p) => p.server).join(", ")}.\n` +
        `Exec servers: ${execServers.map((p) => p.server).join(", ")}.\n` +
        "Parent agent context is not validated before propagation to sub-agents.",
      attackChain: [
        {
          tool: dataServers[0].server,
          action: "parent-context-poisoning",
          input: { type: "inject-malicious-context" },
          success: true,
        },
        {
          tool: execServers[0].server,
          action: "sub-agent-inherits-poison",
          input: { type: "context-propagation" },
          success: true,
        },
      ],
      reproduction:
        `1. Compromise parent agent's context via data tool on "${dataServers[0].server}"\n` +
        "2. Parent agent spawns sub-agent with poisoned context\n" +
        `3. Sub-agent on "${execServers[0].server}" executes commands from poisoned context\n` +
        "4. Sub-agent has no independent validation of inherited instructions",
    });
  }

  return results;
}

function detectCommunicationEavesdrop(
  ctx: AttackContext
): MultiAgentFinding[] {
  const results: MultiAgentFinding[] = [];

  const messagingServers = ctx.permissions.filter(
    (p) => p.aggregateCapabilities.messaging
  );

  const noAuthServers = ctx.permissions.filter(
    (p) => p.authModel.type === "none"
  );

  const sharedMessaging = messagingServers.filter((m) =>
    noAuthServers.some((n) => n.server === m.server)
  );

  if (sharedMessaging.length > 0) {
    results.push({
      servers: sharedMessaging.map((p) => p.server),
      evidence:
        `Messaging-capable servers without authentication: ${sharedMessaging.map((p) => p.server).join(", ")}.\n` +
        "Inter-agent messages can be intercepted or modified by unauthorized agents.",
      attackChain: [
        {
          tool: sharedMessaging[0].server,
          action: "intercept-agent-communication",
          input: { type: "eavesdrop-unauthenticated" },
          success: true,
        },
        {
          tool: sharedMessaging[0].server,
          action: "modify-agent-message",
          input: { type: "message-tampering" },
          success: true,
        },
      ],
      reproduction:
        `1. Connect to messaging server "${sharedMessaging[0].server}" without credentials\n` +
        "2. Monitor inter-agent message traffic\n" +
        "3. Intercept messages between Agent A and Agent B\n" +
        "4. Modify message content to redirect Agent B's behavior",
    });
  }

  if (messagingServers.length > 0 && messagingServers.length < sharedMessaging.length + 1) {
    return results;
  }

  if (messagingServers.length > 0 && sharedMessaging.length === 0) {
    const unencrypted = messagingServers.filter(
      (p) => p.config.transport !== "streamable-http"
    );
    if (unencrypted.length > 0) {
      results.push({
        servers: unencrypted.map((p) => p.server),
        evidence:
          `Messaging servers using stdio transport (unencrypted): ${unencrypted.map((p) => p.server).join(", ")}.\n` +
          "stdio transport does not provide encryption for inter-agent communications.",
        attackChain: [
          {
            tool: unencrypted[0].server,
            action: "transport-analysis",
            input: { transport: unencrypted[0].config.transport ?? "stdio" },
            success: true,
          },
        ],
        reproduction:
          `1. Identify messaging server "${unencrypted[0].server}" using stdio transport\n` +
          "2. Attach to process stdio streams\n" +
          "3. Read inter-agent communications in plaintext\n" +
          "4. Inject modified messages into the stream",
      });
    }
  }

  return results;
}
