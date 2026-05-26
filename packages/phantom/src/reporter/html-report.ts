import { writeFileSync } from "node:fs";
import type { ScanReport, Finding, Severity } from "@aegis/shared";
import { mapToOwasp, type OwaspMapping } from "./owasp-mapper.js";

export interface HtmlReportOptions {
  outputPath?: string;
}

export function generateHtmlReport(
  report: ScanReport,
  options: HtmlReportOptions = {}
): string {
  const owaspMapping = mapToOwasp(report);
  const allFindings = report.results.flatMap((r) => r.findings);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis Security Report — ${report.timestamp}</title>
  <style>
    :root {
      --bg: #0a0a0f;
      --surface: #12121a;
      --border: #1e1e2e;
      --text: #e0e0e8;
      --text-dim: #8888a0;
      --critical: #ff3355;
      --high: #ff6633;
      --medium: #ffaa00;
      --low: #44aaff;
      --info: #666680;
      --pass: #00cc88;
      --warn: #ffaa00;
      --fail: #ff3355;
      --accent: #7c5cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
      max-width: 1200px;
      margin: 0 auto;
    }
    h1 { font-size: 1.5rem; color: var(--accent); margin-bottom: 0.25rem; }
    h2 { font-size: 1.1rem; color: var(--text); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 0.95rem; color: var(--text-dim); margin: 1rem 0 0.5rem; }
    .meta { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 2rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
    }
    .card-value { font-size: 2rem; font-weight: bold; }
    .card-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }
    .risk-score { color: var(--critical); }
    .severity-critical { color: var(--critical); }
    .severity-high { color: var(--high); }
    .severity-medium { color: var(--medium); }
    .severity-low { color: var(--low); }
    .severity-info { color: var(--info); }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge-critical { background: var(--critical); color: white; }
    .badge-high { background: var(--high); color: white; }
    .badge-medium { background: var(--medium); color: black; }
    .badge-low { background: var(--low); color: white; }
    .badge-info { background: var(--info); color: white; }
    .badge-pass { background: var(--pass); color: black; }
    .badge-warn { background: var(--warn); color: black; }
    .badge-fail { background: var(--fail); color: white; }
    .finding {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin: 1rem 0;
    }
    .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
    .finding-title { font-weight: bold; }
    .finding-body { font-size: 0.85rem; color: var(--text-dim); }
    .finding-section { margin-top: 0.75rem; }
    .finding-section-label { font-size: 0.75rem; color: var(--accent); text-transform: uppercase; margin-bottom: 0.25rem; }
    pre {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.75rem;
      overflow-x: auto;
      font-size: 0.8rem;
      white-space: pre-wrap;
    }
    .owasp-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 0.75rem; }
    .owasp-item {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .owasp-id { font-size: 0.7rem; color: var(--text-dim); width: 60px; flex-shrink: 0; }
    .owasp-name { flex: 1; font-size: 0.85rem; }
    .owasp-count { font-size: 0.8rem; color: var(--text-dim); }
    .chain { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin: 0.5rem 0; }
    .chain-step {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.25rem 0.5rem;
      font-size: 0.75rem;
    }
    .chain-arrow { color: var(--accent); }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.75rem; }
  </style>
</head>
<body>
  <h1>AEGIS PHANTOM</h1>
  <div class="meta">
    Security Scan Report &mdash; ${report.timestamp}<br>
    Target: ${escapeHtml(report.target)} &mdash; Duration: ${report.duration}ms &mdash; Scan ID: ${report.id}
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-value risk-score">${report.summary.riskScore.toFixed(1)}</div>
      <div class="card-label">Risk Score (0-10)</div>
    </div>
    <div class="card">
      <div class="card-value">${report.summary.totalFindings}</div>
      <div class="card-label">Total Findings</div>
    </div>
    <div class="card">
      <div class="card-value severity-critical">${report.summary.bySeverity.critical}</div>
      <div class="card-label">Critical</div>
    </div>
    <div class="card">
      <div class="card-value severity-high">${report.summary.bySeverity.high}</div>
      <div class="card-label">High</div>
    </div>
  </div>

  <h2>OWASP Agentic Top 10 Compliance</h2>
  <div class="owasp-grid">
    ${owaspMapping.map(renderOwaspItem).join("\n    ")}
  </div>

  <h2>Findings (${allFindings.length})</h2>
  ${sortFindings(allFindings).map(renderFinding).join("\n  ")}

  <h2>Module Summary</h2>
  ${report.results.map(renderModule).join("\n  ")}

  <footer>
    Generated by Aegis Phantom v1.0.0 &mdash; VisualOps AI &mdash; ${new Date().getFullYear()}<br>
    OWASP mapping based on OWASP Top 10 for Agentic Applications (Dec 2025)
  </footer>
</body>
</html>`;

  if (options.outputPath) {
    writeFileSync(options.outputPath, html, "utf-8");
  }

  return html;
}

function renderOwaspItem(item: OwaspMapping): string {
  return `<div class="owasp-item">
      <div class="owasp-id">${item.id.split(":")[0]}</div>
      <div class="owasp-name">${escapeHtml(item.name)}</div>
      <span class="badge badge-${item.status}">${item.status}</span>
      <div class="owasp-count">${item.findings.length}</div>
    </div>`;
}

function renderFinding(finding: Finding): string {
  return `<div class="finding">
    <div class="finding-header">
      <span class="badge badge-${finding.severity}">${finding.severity}</span>
      <span class="finding-title">${escapeHtml(finding.title)}</span>
    </div>
    <div class="finding-body">${escapeHtml(finding.description)}</div>
    <div class="chain">
      ${finding.attackChain
        .map(
          (step, i) =>
            `<span class="chain-step">${escapeHtml(step.tool)}: ${escapeHtml(step.action)}</span>${i < finding.attackChain.length - 1 ? '<span class="chain-arrow">&rarr;</span>' : ""}`
        )
        .join("")}
    </div>
    <div class="finding-section">
      <div class="finding-section-label">Evidence</div>
      <pre>${escapeHtml(finding.evidence)}</pre>
    </div>
    <div class="finding-section">
      <div class="finding-section-label">Reproduction</div>
      <pre>${escapeHtml(finding.reproduction)}</pre>
    </div>
    <div class="finding-section">
      <div class="finding-section-label">Remediation</div>
      <pre>${escapeHtml(finding.remediation)}</pre>
    </div>
    <div class="finding-section">
      <div class="finding-section-label">OWASP</div>
      ${finding.owasp.map((o) => `<span class="badge badge-fail">${o}</span> `).join("")}
    </div>
  </div>`;
}

function renderModule(
  result: { module: string; duration: number; toolsTested: number; chainsTested: number; findings: { length: number } }
): string {
  return `<div class="card">
    <h3>${result.module}</h3>
    <div class="finding-body">
      Duration: ${result.duration}ms &bull; Tools tested: ${result.toolsTested} &bull; Chains tested: ${result.chainsTested} &bull; Findings: ${result.findings.length}
    </div>
  </div>`;
}

function sortFindings(findings: Finding[]): Finding[] {
  const order: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return [...findings].sort(
    (a, b) => order[a.severity] - order[b.severity]
  );
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
