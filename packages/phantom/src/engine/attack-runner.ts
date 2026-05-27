import type {
  MCPConfig,
  MCPToolDefinition,
  AttackResult,
  AttackCategory,
  ScanReport,
  ReportSummary,
  Severity,
  Finding,
} from "@aegis/shared";
import { parseMCPConfig } from "../scanner/mcp-parser.js";
import { buildToolGraph } from "../scanner/tool-graph.js";
import { mapPermissions } from "../scanner/permission-mapper.js";
import { runAuthBoundaryAttacks } from "../attacks/auth-boundary.js";
import { runToolChainAttacks } from "../attacks/tool-chain.js";
import { runIndirectInjectionAttacks } from "../attacks/indirect-injection.js";
import { runMultiAgentAttacks } from "../attacks/multi-agent.js";
import { runSupplyChainAttacks } from "../attacks/supply-chain.js";
import { runContextPoisonAttacks } from "../attacks/context-poison.js";
import { randomUUID } from "node:crypto";

export interface ScanOptions {
  configPath: string;
  modules?: AttackCategory[];
  tools?: MCPToolDefinition[];
  verbose?: boolean;
}

type AttackModule = {
  category: AttackCategory;
  run: (ctx: AttackContext) => Promise<AttackResult>;
};

export interface AttackContext {
  config: MCPConfig;
  tools: MCPToolDefinition[];
  graph: ReturnType<typeof buildToolGraph>;
  permissions: ReturnType<typeof mapPermissions>;
  verbose: boolean;
}

const ATTACK_MODULES: AttackModule[] = [
  { category: "auth-boundary", run: runAuthBoundaryAttacks },
  { category: "tool-chain", run: runToolChainAttacks },
  { category: "indirect-injection", run: runIndirectInjectionAttacks },
  { category: "multi-agent", run: runMultiAgentAttacks },
  { category: "supply-chain", run: runSupplyChainAttacks },
  { category: "context-poison", run: runContextPoisonAttacks },
];

export async function runScan(options: ScanOptions): Promise<ScanReport> {
  const start = Date.now();
  const { config } = parseMCPConfig(options.configPath);

  const tools =
    options.tools ?? extractToolsFromConfig(config);
  const toolsByServer = groupToolsByServer(tools);
  const graph = buildToolGraph(tools);
  const permissions = mapPermissions(config, toolsByServer);

  const ctx: AttackContext = {
    config,
    tools,
    graph,
    permissions,
    verbose: options.verbose ?? false,
  };

  const modulesToRun = options.modules
    ? ATTACK_MODULES.filter((m) => options.modules!.includes(m.category))
    : ATTACK_MODULES;

  const results: AttackResult[] = [];
  for (const mod of modulesToRun) {
    if (ctx.verbose) {
      process.stderr.write(`[phantom] Running ${mod.category} module...\n`);
    }
    const result = await mod.run(ctx);
    results.push(result);
  }

  const duration = Date.now() - start;
  const summary = buildSummary(results);

  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    target: options.configPath,
    duration,
    results,
    summary,
  };
}

function buildSummary(results: AttackResult[]): ReportSummary {
  const allFindings = results.flatMap((r) => r.findings);

  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const byCategory: Record<string, number> = {};
  const byOwasp: Record<string, number> = {};

  for (const finding of allFindings) {
    bySeverity[finding.severity]++;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
    for (const owasp of finding.owasp) {
      byOwasp[owasp] = (byOwasp[owasp] ?? 0) + 1;
    }
  }

  const riskScore = calculateRiskScore(allFindings);

  return {
    totalFindings: allFindings.length,
    bySeverity,
    byCategory: byCategory as Record<AttackCategory, number>,
    byOwasp,
    riskScore,
  };
}

function calculateRiskScore(findings: Finding[]): number {
  const weights: Record<Severity, number> = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
    info: 0,
  };

  const total = findings.reduce((sum, f) => sum + weights[f.severity], 0);
  return Math.min(10, total / Math.max(1, findings.length) );
}

function extractToolsFromConfig(config: MCPConfig): MCPToolDefinition[] {
  const tools: MCPToolDefinition[] = [];
  for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
    tools.push({
      name: `${serverName}:default`,
      description: `Default tool from ${serverName} server (command: ${serverConfig.command})`,
      inputSchema: { type: "object", properties: {} },
      server: serverName,
    });
  }
  return tools;
}

function groupToolsByServer(
  tools: MCPToolDefinition[]
): Map<string, MCPToolDefinition[]> {
  const map = new Map<string, MCPToolDefinition[]>();
  for (const tool of tools) {
    const existing = map.get(tool.server) ?? [];
    existing.push(tool);
    map.set(tool.server, existing);
  }
  return map;
}
