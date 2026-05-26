import { writeFileSync } from "node:fs";
import type { ScanReport } from "@aegis/shared";
import { mapToOwasp } from "./owasp-mapper.js";

export interface JsonReportOptions {
  outputPath?: string;
  pretty?: boolean;
}

export function generateJsonReport(
  report: ScanReport,
  options: JsonReportOptions = {}
): string {
  const owaspMapping = mapToOwasp(report);

  const output = {
    meta: {
      tool: "Aegis Phantom",
      version: "1.0.0",
      scanId: report.id,
      timestamp: report.timestamp,
      target: report.target,
      duration: `${report.duration}ms`,
    },
    summary: {
      riskScore: report.summary.riskScore,
      totalFindings: report.summary.totalFindings,
      bySeverity: report.summary.bySeverity,
      byCategory: report.summary.byCategory,
    },
    owaspCompliance: owaspMapping.map((m) => ({
      id: m.id,
      name: m.name,
      status: m.status,
      findingCount: m.findings.length,
    })),
    findings: report.results.flatMap((r) =>
      r.findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        owasp: f.owasp,
        tool: f.tool,
        description: f.description,
        evidence: f.evidence,
        reproduction: f.reproduction,
        remediation: f.remediation,
        attackChain: f.attackChain,
        timestamp: f.timestamp,
      }))
    ),
    modules: report.results.map((r) => ({
      name: r.module,
      duration: `${r.duration}ms`,
      toolsTested: r.toolsTested,
      chainsTested: r.chainsTested,
      findingCount: r.findings.length,
    })),
  };

  const json = JSON.stringify(output, null, options.pretty !== false ? 2 : 0);

  if (options.outputPath) {
    writeFileSync(options.outputPath, json, "utf-8");
  }

  return json;
}
