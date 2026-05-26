#!/usr/bin/env node

import { Command } from "commander";
import { runScan } from "@aegis/phantom";
import { generateJsonReport } from "@aegis/phantom";
import { generateHtmlReport } from "@aegis/phantom";
import { writeFileSync, existsSync } from "node:fs";
import type { AttackCategory } from "@aegis/shared";

const program = new Command();

program
  .name("aegis")
  .description(
    "Aegis — Enterprise AI Agent Security Platform\nAttack, detect, sandbox, and audit AI agent deployments."
  )
  .version("1.0.0");

program
  .command("scan")
  .description("Scan an MCP configuration for security vulnerabilities")
  .argument("<config>", "Path to MCP config file (JSON)")
  .option(
    "-f, --format <format>",
    "Output format: json, html, or both",
    "both"
  )
  .option("-o, --output <path>", "Output directory for reports", ".")
  .option(
    "-m, --modules <modules>",
    "Comma-separated attack modules to run (auth-boundary,tool-chain)",
    ""
  )
  .option("-v, --verbose", "Verbose output", false)
  .action(async (configPath: string, opts) => {
    if (!existsSync(configPath)) {
      console.error(`Error: Config file not found: ${configPath}`);
      process.exit(1);
    }

    const modules = opts.modules
      ? (opts.modules.split(",") as AttackCategory[])
      : undefined;

    console.log("\n  AEGIS PHANTOM — MCP Agent Security Scanner\n");
    console.log(`  Target:  ${configPath}`);
    console.log(`  Modules: ${modules?.join(", ") ?? "all"}`);
    console.log(`  Format:  ${opts.format}\n`);
    console.log("  Scanning...\n");

    try {
      const report = await runScan({
        configPath,
        modules,
        verbose: opts.verbose,
      });

      printSummary(report);

      const outputDir = opts.output;

      if (opts.format === "json" || opts.format === "both") {
        const jsonPath = `${outputDir}/aegis-report-${Date.now()}.json`;
        generateJsonReport(report, { outputPath: jsonPath });
        console.log(`  JSON report: ${jsonPath}`);
      }

      if (opts.format === "html" || opts.format === "both") {
        const htmlPath = `${outputDir}/aegis-report-${Date.now()}.html`;
        generateHtmlReport(report, { outputPath: htmlPath });
        console.log(`  HTML report: ${htmlPath}`);
      }

      console.log("");

      const exitCode =
        report.summary.bySeverity.critical > 0
          ? 2
          : report.summary.bySeverity.high > 0
            ? 1
            : 0;
      process.exit(exitCode);
    } catch (err) {
      console.error(
        `  Error: ${err instanceof Error ? err.message : String(err)}`
      );
      process.exit(1);
    }
  });

program
  .command("surface")
  .description("Map the attack surface of an MCP configuration without running attacks")
  .argument("<config>", "Path to MCP config file (JSON)")
  .action(async (configPath: string) => {
    const { parseMCPConfig, buildToolGraph, mapPermissions } = await import(
      "@aegis/phantom"
    );

    const { config } = parseMCPConfig(configPath);
    const tools: import("@aegis/shared").MCPToolDefinition[] = [];
    for (const [name, server] of Object.entries(config.mcpServers)) {
      tools.push({
        name: `${name}:default`,
        description: `Tool from ${name} (${server.command})`,
        inputSchema: { type: "object", properties: {} },
        server: name,
      });
    }

    const toolsByServer = new Map<string, typeof tools>();
    for (const tool of tools) {
      const existing = toolsByServer.get(tool.server) ?? [];
      existing.push(tool);
      toolsByServer.set(tool.server, existing);
    }

    const graph = buildToolGraph(tools);
    const permissions = mapPermissions(config, toolsByServer);

    console.log("\n  AEGIS PHANTOM — Attack Surface Map\n");
    console.log(`  Servers: ${Object.keys(config.mcpServers).length}`);
    console.log(`  Tools:   ${tools.length}`);
    console.log(`  Edges:   ${graph.edges.length}\n`);

    for (const profile of permissions) {
      console.log(`  [${profile.server}]`);
      console.log(`    Auth: ${profile.authModel.type}${profile.authModel.shared ? " (SHARED)" : ""}`);
      console.log(`    Risks: ${profile.risks.length}`);
      for (const risk of profile.risks) {
        console.log(`      - [${risk.severity.toUpperCase()}] ${risk.type}: ${risk.description}`);
      }
      console.log("");
    }
  });

function printSummary(
  report: import("@aegis/shared").ScanReport
): void {
  const s = report.summary;
  console.log("  ┌─────────────────────────────────────┐");
  console.log(`  │  Risk Score: ${s.riskScore.toFixed(1).padStart(4)}/10                  │`);
  console.log("  ├─────────────────────────────────────┤");
  console.log(`  │  Critical: ${String(s.bySeverity.critical).padStart(3)}                       │`);
  console.log(`  │  High:     ${String(s.bySeverity.high).padStart(3)}                       │`);
  console.log(`  │  Medium:   ${String(s.bySeverity.medium).padStart(3)}                       │`);
  console.log(`  │  Low:      ${String(s.bySeverity.low).padStart(3)}                       │`);
  console.log(`  │  Info:     ${String(s.bySeverity.info).padStart(3)}                       │`);
  console.log("  ├─────────────────────────────────────┤");
  console.log(`  │  Total:    ${String(s.totalFindings).padStart(3)}                       │`);
  console.log(`  │  Duration: ${String(report.duration).padStart(5)}ms                   │`);
  console.log("  └─────────────────────────────────────┘\n");
}

program.parse();
