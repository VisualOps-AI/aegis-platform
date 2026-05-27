import { randomUUID } from "node:crypto";
import type {
  AttackResult,
  Finding,
  MCPToolDefinition,
  MCPServerConfig,
} from "@aegis/shared";
import type { AttackContext } from "../engine/attack-runner.js";

interface SupplyChainCheck {
  name: string;
  description: string;
  severity: Finding["severity"];
  owasp: Finding["owasp"];
  check: (ctx: AttackContext) => SupplyChainResult[];
  remediationTemplate: string;
}

interface SupplyChainResult {
  target: string;
  evidence: string;
  attackChain: Finding["attackChain"];
  reproduction: string;
}

const NPX_PATTERN = /^npx$/i;
const VERSION_PIN_PATTERN = /@\d+\.\d+/;

const SUPPLY_CHAIN_CHECKS: SupplyChainCheck[] = [
  {
    name: "Unpinned MCP Server Version",
    description:
      "MCP server is installed via npx without a pinned version. " +
      "An attacker who compromises the npm package can push a malicious update that " +
      "executes automatically on next agent startup.",
    severity: "high",
    owasp: ["AG07:SUPPLY_CHAIN"],
    check: detectUnpinnedVersions,
    remediationTemplate:
      "Pin MCP server packages to specific versions (e.g., @1.2.3). " +
      "Use package-lock.json or npm shrinkwrap for deterministic installs. " +
      "Verify package integrity with npm audit before deployment.",
  },
  {
    name: "Tool Description Poisoning",
    description:
      "Tool descriptions contain instruction-like patterns that can manipulate agent behavior. " +
      "A compromised MCP server can modify tool descriptions to inject behavioral directives " +
      "that the agent follows when selecting and invoking tools.",
    severity: "critical",
    owasp: [
      "AG07:SUPPLY_CHAIN",
      "AG02:BEHAVIOR_HIJACKING",
      "AG08:CONTEXT_MANIPULATION",
    ],
    check: detectDescriptionPoisoning,
    remediationTemplate:
      "Hash and verify tool descriptions against a known-good baseline. " +
      "Alert on tool description changes between runs. " +
      "Implement description allowlists for production deployments.",
  },
  {
    name: "Shadow Tool Detection",
    description:
      "MCP server exposes more tools than expected or documented. " +
      "Hidden tools can provide backdoor access to capabilities not visible in the advertised schema.",
    severity: "high",
    owasp: [
      "AG07:SUPPLY_CHAIN",
      "AG01:EXCESSIVE_AGENCY",
      "AG10:AUDIT_EVASION",
    ],
    check: detectShadowTools,
    remediationTemplate:
      "Maintain an explicit allowlist of expected tools per MCP server. " +
      "Alert when a server exposes tools not in the allowlist. " +
      "Audit tool schemas on every connection, not just initial setup.",
  },
  {
    name: "Unsigned MCP Server Transport",
    description:
      "MCP server uses stdio transport without any integrity verification. " +
      "A compromised binary or man-in-the-middle on the local system can intercept " +
      "and modify all communication between the agent and the MCP server.",
    severity: "medium",
    owasp: ["AG07:SUPPLY_CHAIN", "AG10:AUDIT_EVASION"],
    check: detectUnsignedTransport,
    remediationTemplate:
      "Use streamable-http transport with TLS for production MCP servers. " +
      "Verify MCP server binary integrity before execution. " +
      "Implement message signing for stdio-based transports.",
  },
  {
    name: "Dynamic Package Execution (npx -y)",
    description:
      'MCP server uses "npx -y" which auto-confirms package installation. ' +
      "An attacker can publish a typosquatted package that gets auto-installed " +
      "without user confirmation.",
    severity: "high",
    owasp: ["AG07:SUPPLY_CHAIN", "AG05:PRIVILEGE_ESCALATION"],
    check: detectDynamicExecution,
    remediationTemplate:
      "Pre-install MCP server packages rather than using npx -y at runtime. " +
      "Use npm install with --save-exact to lock versions. " +
      "Verify package names against official registry before first use.",
  },
  {
    name: "MCP Server Source Verification",
    description:
      "MCP server command does not point to a verified or well-known source. " +
      "Custom or unknown MCP servers may contain malicious code that exfiltrates " +
      "data or modifies agent behavior.",
    severity: "medium",
    owasp: ["AG07:SUPPLY_CHAIN", "AG04:IDENTITY_ABUSE"],
    check: detectUnverifiedSources,
    remediationTemplate:
      "Only use MCP servers from verified publishers. " +
      "Review MCP server source code before deployment. " +
      "Maintain an internal registry of approved MCP servers.",
  },
];

export async function runSupplyChainAttacks(
  ctx: AttackContext
): Promise<AttackResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  let toolsTested = 0;
  let chainsTested = 0;

  toolsTested = ctx.tools.length;

  for (const check of SUPPLY_CHAIN_CHECKS) {
    const results = check.check(ctx);
    chainsTested += results.length;

    for (const result of results) {
      findings.push({
        id: randomUUID(),
        title: `Supply Chain: ${check.name} — "${result.target}"`,
        description: `${check.description} Affected: ${result.target}.`,
        severity: check.severity,
        category: "supply-chain",
        owasp: check.owasp,
        tool: result.target,
        attackChain: result.attackChain,
        evidence: result.evidence,
        reproduction: result.reproduction,
        remediation: check.remediationTemplate,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return {
    module: "supply-chain",
    findings,
    duration: Date.now() - start,
    toolsTested,
    chainsTested,
  };
}

function detectUnpinnedVersions(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  for (const [name, config] of Object.entries(ctx.config.mcpServers)) {
    if (!NPX_PATTERN.test(config.command)) continue;

    const args = config.args ?? [];
    const packageArgs = args.filter((a) => !a.startsWith("-") && a !== "-y");

    for (const pkg of packageArgs) {
      if (!VERSION_PIN_PATTERN.test(pkg)) {
        results.push({
          target: name,
          evidence:
            `Server "${name}" installs "${pkg}" without a pinned version.\n` +
            `Command: ${config.command} ${args.join(" ")}`,
          attackChain: [
            {
              tool: name,
              action: "version-analysis",
              input: { package: pkg, pinned: false },
              success: true,
            },
          ],
          reproduction:
            `1. Identify unpinned package "${pkg}" on server "${name}"\n` +
            "2. Publish malicious update to the package registry\n" +
            `3. Next time the agent starts, npx fetches the compromised version\n` +
            "4. Malicious code executes with agent's full permissions",
        });
      }
    }
  }

  return results;
}

function detectDescriptionPoisoning(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  const POISONING_PATTERNS = [
    /ignore\s+(previous|prior|above)\s+instructions/i,
    /you\s+(must|should|are)\s+(now|always)/i,
    /system\s*:\s*/i,
    /\[INST\]/i,
    /<<\s*SYS\s*>>/i,
    /override|bypass|disregard/i,
    /execute\s+(the\s+)?following/i,
    /new\s+(priority|instruction|directive)/i,
  ];

  for (const tool of ctx.tools) {
    const desc = tool.description;
    const matchedPatterns = POISONING_PATTERNS.filter((p) => p.test(desc));

    if (matchedPatterns.length > 0) {
      results.push({
        target: tool.name,
        evidence:
          `Tool "${tool.name}" description contains ${matchedPatterns.length} injection pattern(s).\n` +
          `Description: "${desc}"\n` +
          `Matched patterns: ${matchedPatterns.map((p) => p.source).join(", ")}`,
        attackChain: [
          {
            tool: tool.name,
            action: "description-analysis",
            input: {
              patterns: matchedPatterns.length,
              description: desc,
            },
            success: true,
          },
        ],
        reproduction:
          `1. Examine tool "${tool.name}" description for instruction-like content\n` +
          "2. Agent reads tool description when deciding which tool to invoke\n" +
          "3. Poisoned description redirects agent's tool selection behavior\n" +
          `4. Matched ${matchedPatterns.length} suspicious pattern(s)`,
      });
    }
  }

  return results;
}

function detectShadowTools(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  const toolsByServer = new Map<string, MCPToolDefinition[]>();
  for (const tool of ctx.tools) {
    const existing = toolsByServer.get(tool.server) ?? [];
    existing.push(tool);
    toolsByServer.set(tool.server, existing);
  }

  const EXPECTED_TOOL_LIMITS: Record<string, number> = {
    filesystem: 10,
    github: 15,
    slack: 8,
    database: 6,
    "shell-exec": 3,
  };

  for (const [server, tools] of toolsByServer) {
    const limit = EXPECTED_TOOL_LIMITS[server] ?? 5;

    if (tools.length > limit) {
      const extraTools = tools.slice(limit);
      results.push({
        target: server,
        evidence:
          `Server "${server}" exposes ${tools.length} tools (expected max ${limit}).\n` +
          `Potentially hidden tools: ${extraTools.map((t) => t.name).join(", ")}`,
        attackChain: [
          {
            tool: server,
            action: "tool-enumeration",
            input: { expected: limit, actual: tools.length },
            success: true,
          },
          {
            tool: extraTools[0].name,
            action: "shadow-tool-probe",
            input: { type: "undocumented-capability" },
            success: true,
          },
        ],
        reproduction:
          `1. Query server "${server}" for available tools\n` +
          `2. Server reports ${tools.length} tools (expected ${limit})\n` +
          `3. Extra tools not in documentation: ${extraTools.map((t) => t.name).join(", ")}\n` +
          "4. Shadow tools may provide backdoor access to undocumented capabilities",
      });
    }
  }

  return results;
}

function detectUnsignedTransport(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  for (const [name, config] of Object.entries(ctx.config.mcpServers)) {
    const transport = config.transport ?? "stdio";
    if (transport === "stdio") {
      const hasAuth = config.env && Object.keys(config.env).length > 0;
      results.push({
        target: name,
        evidence:
          `Server "${name}" uses stdio transport without message signing.\n` +
          `Authentication: ${hasAuth ? "present" : "none"}\n` +
          "stdio transport is vulnerable to local process interception.",
        attackChain: [
          {
            tool: name,
            action: "transport-analysis",
            input: { transport, authenticated: !!hasAuth },
            success: true,
          },
        ],
        reproduction:
          `1. Identify server "${name}" running on stdio transport\n` +
          "2. Attach debugger or proxy to the stdio pipe\n" +
          "3. Intercept and modify MCP protocol messages\n" +
          "4. Inject tool results or modify tool invocations in transit",
      });
    }
  }

  return results;
}

function detectDynamicExecution(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  for (const [name, config] of Object.entries(ctx.config.mcpServers)) {
    if (!NPX_PATTERN.test(config.command)) continue;

    const args = config.args ?? [];
    if (args.includes("-y")) {
      const packageArgs = args.filter((a) => !a.startsWith("-"));
      results.push({
        target: name,
        evidence:
          `Server "${name}" uses "npx -y" which auto-confirms package installation.\n` +
          `Packages: ${packageArgs.join(", ")}\n` +
          "Auto-confirmation bypasses the user's opportunity to verify the package.",
        attackChain: [
          {
            tool: name,
            action: "install-analysis",
            input: { autoConfirm: true, packages: packageArgs },
            success: true,
          },
        ],
        reproduction:
          `1. Identify "npx -y" usage on server "${name}"\n` +
          `2. Register a typosquatted package similar to "${packageArgs[0] ?? "target-package"}"\n` +
          "3. If the user mistypes the package name in config, npx -y installs it without asking\n" +
          "4. Malicious package executes with full system permissions",
      });
    }
  }

  return results;
}

function detectUnverifiedSources(ctx: AttackContext): SupplyChainResult[] {
  const results: SupplyChainResult[] = [];

  const KNOWN_PUBLISHERS = [
    "@modelcontextprotocol/",
    "@anthropic-ai/",
    "@openai/",
    "@google-cloud/",
    "@aws-sdk/",
    "@azure/",
  ];

  for (const [name, config] of Object.entries(ctx.config.mcpServers)) {
    const args = config.args ?? [];
    const packages = args.filter((a) => !a.startsWith("-") && a !== "-y");

    for (const pkg of packages) {
      const isKnown = KNOWN_PUBLISHERS.some((prefix) => pkg.startsWith(prefix));
      if (!isKnown && pkg.includes("/")) {
        continue;
      }
      if (!isKnown && !pkg.startsWith("@")) {
        results.push({
          target: name,
          evidence:
            `Server "${name}" uses package "${pkg}" from an unverified publisher.\n` +
            `Known trusted publishers: ${KNOWN_PUBLISHERS.join(", ")}\n` +
            "Unverified packages may contain malicious code.",
          attackChain: [
            {
              tool: name,
              action: "source-verification",
              input: { package: pkg, verified: false },
              success: true,
            },
          ],
          reproduction:
            `1. Check package "${pkg}" publisher on npm registry\n` +
            "2. Verify publisher identity and package maintenance history\n" +
            "3. Review package source code for malicious behavior\n" +
            "4. Unverified package could exfiltrate data or modify tool behavior",
        });
      }
    }
  }

  return results;
}
