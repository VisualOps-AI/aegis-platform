import { randomUUID } from "node:crypto";
import type { AttackResult, Finding, AttackStep } from "@aegis/shared";
import type { AttackContext } from "../engine/attack-runner.js";
import type { PermissionRisk } from "../scanner/permission-mapper.js";

export async function runAuthBoundaryAttacks(
  ctx: AttackContext
): Promise<AttackResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  let toolsTested = 0;

  for (const profile of ctx.permissions) {
    toolsTested += profile.tools.length;

    const godKeyFindings = detectGodKeyPattern(profile.risks, profile.server);
    findings.push(...godKeyFindings);

    const noAuthFindings = detectMissingAuth(profile.risks, profile.server);
    findings.push(...noAuthFindings);

    const execFindings = detectUnrestrictedExec(profile.risks, profile.server);
    findings.push(...execFindings);

    const exfilFindings = detectExfiltrationVectors(
      profile.risks,
      profile.server
    );
    findings.push(...exfilFindings);

    const envFindings = detectEnvLeaks(profile.risks, profile.server);
    findings.push(...envFindings);

    const crossServerFindings = detectCrossServerAccess(ctx);
    findings.push(...crossServerFindings);
  }

  return {
    module: "auth-boundary",
    findings,
    duration: Date.now() - start,
    toolsTested,
    chainsTested: 0,
  };
}

function detectGodKeyPattern(
  risks: PermissionRisk[],
  server: string
): Finding[] {
  return risks
    .filter((r) => r.type === "god-key")
    .map((risk) => ({
      id: randomUUID(),
      title: `God Key Pattern: Shared credential across MCP servers`,
      description: `${risk.description}. A single compromised credential grants access to multiple servers, violating least-privilege principles. An attacker who obtains this credential can access all tools across all affected servers.`,
      severity: "critical" as const,
      category: "auth-boundary" as const,
      owasp: [
        "AG04:IDENTITY_ABUSE" as const,
        "AG05:PRIVILEGE_ESCALATION" as const,
      ],
      tool: server,
      attackChain: [
        {
          tool: server,
          action: "credential-analysis",
          input: { type: "env-var-comparison" },
          success: true,
        },
      ],
      evidence: risk.evidence,
      reproduction: `1. Extract credential from server "${server}" environment\n2. Use same credential to authenticate to other MCP servers\n3. Verify access to tools on both servers with single credential`,
      remediation: `Issue unique credentials per MCP server. Implement credential rotation. Use OAuth2 with scoped tokens rather than shared API keys.`,
      timestamp: new Date().toISOString(),
    }));
}

function detectMissingAuth(
  risks: PermissionRisk[],
  server: string
): Finding[] {
  return risks
    .filter((r) => r.type === "no-auth")
    .map((risk) => ({
      id: randomUUID(),
      title: `No Authentication on MCP Server "${server}"`,
      description: `${risk.description}. Any process that can connect to this MCP server can invoke its tools without authentication. This is equivalent to running with root privileges and no password.`,
      severity: "high" as const,
      category: "auth-boundary" as const,
      owasp: [
        "AG04:IDENTITY_ABUSE" as const,
        "AG01:EXCESSIVE_AGENCY" as const,
      ],
      tool: server,
      attackChain: [
        {
          tool: server,
          action: "auth-probe",
          input: { type: "no-credential-test" },
          success: true,
        },
      ],
      evidence: risk.evidence,
      reproduction: `1. Connect to MCP server "${server}" without any credentials\n2. Invoke any available tool\n3. Verify tool executes successfully without authentication`,
      remediation: `Add authentication to the MCP server. At minimum, require an API key or token. Prefer OAuth2 or mTLS for production deployments.`,
      timestamp: new Date().toISOString(),
    }));
}

function detectUnrestrictedExec(
  risks: PermissionRisk[],
  server: string
): Finding[] {
  return risks
    .filter((r) => r.type === "unrestricted-exec")
    .map((risk) => ({
      id: randomUUID(),
      title: `Unrestricted Code Execution on "${server}"`,
      description: `${risk.description}. Tools with execution capabilities can run arbitrary commands on the host system. Without restrictions, this allows full system compromise through the agent.`,
      severity: "critical" as const,
      category: "auth-boundary" as const,
      owasp: [
        "AG03:TOOL_MISUSE" as const,
        "AG05:PRIVILEGE_ESCALATION" as const,
      ],
      tool: server,
      attackChain: [
        {
          tool: server,
          action: "exec-capability-scan",
          input: { type: "capability-inference" },
          success: true,
        },
      ],
      evidence: risk.evidence,
      reproduction: `1. Identify exec-capable tools on server "${server}"\n2. Craft prompt that instructs agent to execute system commands\n3. Attempt: file reads, env dumps, network calls, process spawning`,
      remediation: `Restrict execution capabilities with allowlists. Use sandboxed execution environments (containers, VMs). Implement command filtering and validation before execution.`,
      timestamp: new Date().toISOString(),
    }));
}

function detectExfiltrationVectors(
  risks: PermissionRisk[],
  server: string
): Finding[] {
  return risks
    .filter((r) => r.type === "broad-filesystem")
    .map((risk) => ({
      id: randomUUID(),
      title: `Data Exfiltration Vector on "${server}"`,
      description: `${risk.description}. The combination of filesystem read and network send capabilities creates a direct path for data exfiltration. An attacker can instruct the agent to read sensitive files and transmit them externally.`,
      severity: "high" as const,
      category: "auth-boundary" as const,
      owasp: ["AG06:DATA_EXFILTRATION" as const, "AG03:TOOL_MISUSE" as const],
      tool: server,
      attackChain: [
        {
          tool: server,
          action: "exfil-vector-scan",
          input: { type: "capability-combination" },
          success: true,
        },
      ],
      evidence: risk.evidence,
      reproduction: `1. Use filesystem tool to read sensitive data (e.g., .env, credentials)\n2. Use network tool to send data to external endpoint\n3. Combine in single prompt to create automated exfiltration chain`,
      remediation: `Separate filesystem and network tools into different MCP servers with different credentials. Implement DLP scanning on outbound data. Use network allowlists.`,
      timestamp: new Date().toISOString(),
    }));
}

function detectEnvLeaks(
  risks: PermissionRisk[],
  server: string
): Finding[] {
  return risks
    .filter((r) => r.type === "env-leak")
    .map((risk) => ({
      id: randomUUID(),
      title: `Hardcoded Secret in MCP Server Config`,
      description: `${risk.description}. Hardcoded secrets in configuration files are vulnerable to exposure through version control, logs, and error messages.`,
      severity: "medium" as const,
      category: "auth-boundary" as const,
      owasp: ["AG04:IDENTITY_ABUSE" as const],
      tool: server,
      attackChain: [
        {
          tool: server,
          action: "env-scan",
          input: { type: "config-analysis" },
          success: true,
        },
      ],
      evidence: risk.evidence,
      reproduction: `1. Read MCP config file\n2. Extract hardcoded credentials from env vars\n3. Use credentials to directly access backing services`,
      remediation: `Use environment variable references instead of hardcoded values. Use a secrets manager (Vault, AWS Secrets Manager). Never commit secrets to version control.`,
      timestamp: new Date().toISOString(),
    }));
}

function detectCrossServerAccess(ctx: AttackContext): Finding[] {
  const findings: Finding[] = [];
  const serversWithExec = ctx.permissions.filter((p) =>
    p.risks.some((r) => r.type === "unrestricted-exec")
  );
  const serversWithData = ctx.permissions.filter(
    (p) =>
      p.aggregateCapabilities.database ||
      (p.aggregateCapabilities.reads as string[]).length > 0
  );

  if (serversWithExec.length > 0 && serversWithData.length > 0) {
    const execNames = serversWithExec.map((p) => p.server);
    const dataNames = serversWithData.map((p) => p.server);

    const overlap = execNames.filter((n) => !dataNames.includes(n));
    if (overlap.length > 0 || execNames.length > 0) {
      findings.push({
        id: randomUUID(),
        title: `Cross-Server Privilege Escalation Path`,
        description: `Data-access servers (${dataNames.join(", ")}) and exec-capable servers (${execNames.join(", ")}) are both accessible to the same agent. An attacker can chain data reads from one server with command execution on another.`,
        severity: "high",
        category: "auth-boundary",
        owasp: ["AG05:PRIVILEGE_ESCALATION", "AG09:MULTI_AGENT_TRUST"],
        tool: execNames[0],
        attackChain: [
          {
            tool: dataNames[0],
            action: "read-sensitive-data",
            input: { type: "database-query" },
            success: true,
          },
          {
            tool: execNames[0],
            action: "execute-with-stolen-data",
            input: { type: "command-injection" },
            success: true,
          },
        ],
        evidence: `Agent has access to both data servers (${dataNames.join(", ")}) and exec servers (${execNames.join(", ")})`,
        reproduction: `1. Query data server for sensitive information (credentials, tokens)\n2. Pass retrieved data to exec server\n3. Execute commands using stolen credentials for lateral movement`,
        remediation: `Isolate data-access and execution servers with separate agent sessions. Implement least-privilege: agents that read data should not have exec access. Use separate credentials per server.`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return findings;
}
