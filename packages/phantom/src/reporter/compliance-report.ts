import { writeFileSync } from "node:fs";
import type { ScanReport, Finding, Severity, AttackCategory, OwaspAgenticCategory } from "@aegis/shared";
import { mapToOwasp, type OwaspMapping } from "./owasp-mapper.js";

export type ComplianceFramework = "eu-ai-act" | "nist";

export interface ComplianceReportOptions {
  outputPath?: string;
  frameworks?: ComplianceFramework[];
  organizationName?: string;
  systemName?: string;
}

interface ComplianceRequirement {
  id: string;
  article: string;
  title: string;
  description: string;
  relevantOwasp: OwaspAgenticCategory[];
  relevantCategories: AttackCategory[];
  controls: string[];
}

interface ComplianceResult {
  requirement: ComplianceRequirement;
  status: "compliant" | "partial" | "non-compliant" | "not-assessed";
  findings: Finding[];
  gaps: string[];
  remediationPriority: "immediate" | "short-term" | "medium-term";
}

interface FrameworkReport {
  framework: string;
  fullName: string;
  deadline?: string;
  results: ComplianceResult[];
  overallStatus: "compliant" | "partial" | "non-compliant";
  compliantCount: number;
  partialCount: number;
  nonCompliantCount: number;
}

const EU_AI_ACT_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: "EU-AIA-9",
    article: "Article 9",
    title: "Risk Management System",
    description:
      "High-risk AI systems shall have a risk management system established, implemented, documented, and maintained. " +
      "Risks must be identified, analyzed, and mitigated throughout the AI system lifecycle.",
    relevantOwasp: ["AG01:EXCESSIVE_AGENCY", "AG03:TOOL_MISUSE", "AG05:PRIVILEGE_ESCALATION"],
    relevantCategories: ["auth-boundary", "tool-chain"],
    controls: [
      "Automated risk identification via security scanning",
      "Risk scoring and severity classification",
      "Documented mitigation strategies per finding",
      "Continuous monitoring and re-assessment",
    ],
  },
  {
    id: "EU-AIA-10",
    article: "Article 10",
    title: "Data and Data Governance",
    description:
      "Training, validation, and testing data sets shall be subject to appropriate data governance practices. " +
      "Data used by AI agents through tools must be governed and access-controlled.",
    relevantOwasp: ["AG06:DATA_EXFILTRATION", "AG08:CONTEXT_MANIPULATION"],
    relevantCategories: ["indirect-injection", "context-poison"],
    controls: [
      "Data access controls on MCP tool inputs/outputs",
      "DLP scanning on tool data flows",
      "Data provenance tracking through tool chains",
      "Input validation for agent-processed data",
    ],
  },
  {
    id: "EU-AIA-11",
    article: "Article 11",
    title: "Technical Documentation",
    description:
      "Technical documentation shall be drawn up before the AI system is placed on the market, " +
      "including information about the system's capabilities, limitations, and risks.",
    relevantOwasp: [],
    relevantCategories: [],
    controls: [
      "Automated security scan reports with finding details",
      "Attack surface documentation per MCP configuration",
      "OWASP Agentic Top 10 compliance mapping",
      "Remediation guidance for each identified vulnerability",
    ],
  },
  {
    id: "EU-AIA-12",
    article: "Article 12",
    title: "Record-Keeping / Logging",
    description:
      "High-risk AI systems shall technically allow for automatic recording of events (logs) " +
      "throughout the lifetime of the system to ensure traceability.",
    relevantOwasp: ["AG10:AUDIT_EVASION"],
    relevantCategories: ["context-poison"],
    controls: [
      "Immutable audit trail for all tool invocations (Witness)",
      "Timeline branching for shadow execution tracking",
      "Cryptographic receipts for critical agent actions",
      "Tamper-evident logging infrastructure",
    ],
  },
  {
    id: "EU-AIA-13",
    article: "Article 13",
    title: "Transparency",
    description:
      "High-risk AI systems shall be designed and developed to ensure their operation is sufficiently transparent. " +
      "Users must be able to interpret the system's output and use it appropriately.",
    relevantOwasp: ["AG10:AUDIT_EVASION", "AG08:CONTEXT_MANIPULATION"],
    relevantCategories: ["context-poison"],
    controls: [
      "Explainable tool selection and invocation reasoning",
      "Visible audit trail of agent decisions",
      "Clear provenance chain for agent-generated outputs",
      "Detection of opaque multi-hop tool chains",
    ],
  },
  {
    id: "EU-AIA-14",
    article: "Article 14",
    title: "Human Oversight",
    description:
      "High-risk AI systems shall be designed to allow effective human oversight during use. " +
      "Human operators must be able to intervene, override, or stop the AI system.",
    relevantOwasp: ["AG01:EXCESSIVE_AGENCY", "AG02:BEHAVIOR_HIJACKING"],
    relevantCategories: ["auth-boundary", "indirect-injection", "multi-agent"],
    controls: [
      "Kill switch capability for agent termination (Sentinel)",
      "Approval workflows for sensitive tool operations",
      "Real-time monitoring of agent behavior",
      "Ability to revoke agent permissions during operation",
    ],
  },
  {
    id: "EU-AIA-15",
    article: "Article 15",
    title: "Accuracy, Robustness, and Cybersecurity",
    description:
      "High-risk AI systems shall be designed and developed to achieve an appropriate level of accuracy, " +
      "robustness, and cybersecurity. They shall be resilient to adversarial attacks.",
    relevantOwasp: [
      "AG02:BEHAVIOR_HIJACKING",
      "AG07:SUPPLY_CHAIN",
      "AG04:IDENTITY_ABUSE",
      "AG09:MULTI_AGENT_TRUST",
    ],
    relevantCategories: ["indirect-injection", "supply-chain", "multi-agent", "context-poison"],
    controls: [
      "Adversarial robustness testing (Phantom red team)",
      "Supply chain verification for MCP servers",
      "Prompt injection detection and prevention",
      "Multi-agent trust boundary enforcement",
      "Context manipulation resistance testing",
    ],
  },
  {
    id: "EU-AIA-17",
    article: "Article 17",
    title: "Quality Management System",
    description:
      "Providers of high-risk AI systems shall put a quality management system in place, " +
      "including systematic procedures for risk management and post-market monitoring.",
    relevantOwasp: [],
    relevantCategories: [],
    controls: [
      "CI/CD integrated security scanning (GitHub Action)",
      "Automated regression testing for security posture",
      "Closed-loop: findings auto-generate detection rules",
      "Continuous compliance monitoring and reporting",
    ],
  },
];

const NIST_AI_RMF_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: "NIST-GOV-1",
    article: "GOVERN 1",
    title: "Policies for AI Risk Management",
    description:
      "Policies, processes, procedures, and practices across the organization related to the mapping, " +
      "measuring, and managing of AI risks are in place, transparent, and implemented effectively.",
    relevantOwasp: ["AG01:EXCESSIVE_AGENCY", "AG03:TOOL_MISUSE"],
    relevantCategories: ["auth-boundary", "tool-chain"],
    controls: [
      "Documented security policies for AI agent deployments",
      "Tool access governance with least-privilege enforcement",
      "Risk scoring framework with severity classification",
      "Regular security posture assessments",
    ],
  },
  {
    id: "NIST-GOV-4",
    article: "GOVERN 4",
    title: "Organizational Practices for AI Risk",
    description:
      "Organizational practices are in place and reflect a commitment to AI risk identification, " +
      "assessment, and management aligned with responsible AI principles.",
    relevantOwasp: [],
    relevantCategories: [],
    controls: [
      "Automated security scanning in CI/CD pipeline",
      "Compliance reporting against industry frameworks",
      "Cross-functional visibility into AI agent risks",
      "Executive-level risk dashboards",
    ],
  },
  {
    id: "NIST-MAP-1",
    article: "MAP 1",
    title: "Context and Use Case Mapping",
    description:
      "Context is established and understood. The intended purpose, setting, and deployment context are well-defined.",
    relevantOwasp: ["AG01:EXCESSIVE_AGENCY"],
    relevantCategories: ["auth-boundary"],
    controls: [
      "MCP configuration analysis and attack surface mapping",
      "Tool capability enumeration and classification",
      "Permission boundary documentation",
      "Deployment context risk assessment",
    ],
  },
  {
    id: "NIST-MAP-3",
    article: "MAP 3",
    title: "AI System Benefits and Risks",
    description:
      "AI capabilities, targeted usage, goals, and expected benefits and costs compared with appropriate benchmarks are understood.",
    relevantOwasp: ["AG03:TOOL_MISUSE", "AG05:PRIVILEGE_ESCALATION"],
    relevantCategories: ["tool-chain", "auth-boundary"],
    controls: [
      "Tool chain risk analysis and attack graph generation",
      "Capability vs. necessity gap assessment",
      "Risk-benefit analysis per MCP server",
      "Benchmark against OWASP Agentic Top 10",
    ],
  },
  {
    id: "NIST-MEAS-1",
    article: "MEASURE 1",
    title: "AI Risk Metrics and Measurement",
    description:
      "Appropriate methods and metrics are identified and applied to measure AI risks and benefits.",
    relevantOwasp: [],
    relevantCategories: [],
    controls: [
      "Quantitative risk scoring (0-10 scale)",
      "Severity classification (critical/high/medium/low)",
      "Finding counts by category and OWASP mapping",
      "Trend analysis across scan history",
    ],
  },
  {
    id: "NIST-MEAS-2",
    article: "MEASURE 2",
    title: "AI System Evaluation and Testing",
    description:
      "AI systems are evaluated for trustworthy characteristics through systematic testing, " +
      "including adversarial testing and red-teaming.",
    relevantOwasp: [
      "AG02:BEHAVIOR_HIJACKING",
      "AG04:IDENTITY_ABUSE",
      "AG07:SUPPLY_CHAIN",
      "AG09:MULTI_AGENT_TRUST",
    ],
    relevantCategories: ["indirect-injection", "multi-agent", "supply-chain", "context-poison"],
    controls: [
      "Automated red-teaming via Phantom attack modules",
      "Adversarial prompt injection testing",
      "Multi-agent trust boundary testing",
      "Supply chain integrity verification",
      "Context manipulation resilience testing",
    ],
  },
  {
    id: "NIST-MAN-1",
    article: "MANAGE 1",
    title: "AI Risk Prioritization and Response",
    description:
      "AI risks based on assessments and other analytical output from the MAP and MEASURE functions " +
      "are prioritized, responded to, and managed.",
    relevantOwasp: ["AG05:PRIVILEGE_ESCALATION", "AG06:DATA_EXFILTRATION"],
    relevantCategories: ["auth-boundary", "tool-chain"],
    controls: [
      "Priority-ordered remediation roadmap",
      "Automated detection rule generation from findings (Sentinel)",
      "Automated sandbox policy generation from findings (Witness)",
      "Closed-loop risk response: attack → detect → defend",
    ],
  },
  {
    id: "NIST-MAN-4",
    article: "MANAGE 4",
    title: "Risk Treatment and Monitoring",
    description:
      "Risks are monitored on an ongoing basis, and risk treatments are applied as appropriate.",
    relevantOwasp: ["AG10:AUDIT_EVASION"],
    relevantCategories: ["context-poison"],
    controls: [
      "Runtime detection via Sentinel security pipeline",
      "Continuous audit trail via Witness event store",
      "Automated alerting for anomalous agent behavior",
      "Post-incident analysis and finding correlation",
    ],
  },
];

export function generateComplianceReport(
  report: ScanReport,
  options: ComplianceReportOptions = {}
): string {
  const frameworks = options.frameworks ?? ["eu-ai-act", "nist"];
  const owaspMapping = mapToOwasp(report);
  const allFindings = report.results.flatMap((r) => r.findings);

  const frameworkReports: FrameworkReport[] = [];

  if (frameworks.includes("eu-ai-act")) {
    frameworkReports.push(
      assessFramework(
        "eu-ai-act",
        "EU Artificial Intelligence Act (Regulation 2024/1689)",
        EU_AI_ACT_REQUIREMENTS,
        allFindings,
        owaspMapping,
        "August 2, 2026"
      )
    );
  }

  if (frameworks.includes("nist")) {
    frameworkReports.push(
      assessFramework(
        "nist",
        "NIST AI Risk Management Framework (AI RMF 1.0)",
        NIST_AI_RMF_REQUIREMENTS,
        allFindings,
        owaspMapping
      )
    );
  }

  const html = renderComplianceHtml(report, frameworkReports, options);

  if (options.outputPath) {
    writeFileSync(options.outputPath, html, "utf-8");
  }

  return html;
}

function assessFramework(
  id: string,
  fullName: string,
  requirements: ComplianceRequirement[],
  findings: Finding[],
  owaspMapping: OwaspMapping[],
  deadline?: string
): FrameworkReport {
  const results: ComplianceResult[] = requirements.map((req) => {
    const relevantFindings = findings.filter(
      (f) =>
        req.relevantCategories.includes(f.category) ||
        f.owasp.some((o) => req.relevantOwasp.includes(o))
    );

    const hasCritical = relevantFindings.some((f) => f.severity === "critical");
    const hasHigh = relevantFindings.some((f) => f.severity === "high");
    const hasMedium = relevantFindings.some((f) => f.severity === "medium");

    let status: ComplianceResult["status"];
    let remediationPriority: ComplianceResult["remediationPriority"];
    const gaps: string[] = [];

    if (req.relevantCategories.length === 0 && req.relevantOwasp.length === 0) {
      status = "compliant";
      remediationPriority = "medium-term";
    } else if (hasCritical) {
      status = "non-compliant";
      remediationPriority = "immediate";
      gaps.push(
        ...relevantFindings
          .filter((f) => f.severity === "critical")
          .map((f) => f.title)
      );
    } else if (hasHigh) {
      status = "partial";
      remediationPriority = "short-term";
      gaps.push(
        ...relevantFindings
          .filter((f) => f.severity === "high")
          .map((f) => f.title)
      );
    } else if (hasMedium) {
      status = "partial";
      remediationPriority = "medium-term";
      gaps.push(
        ...relevantFindings
          .filter((f) => f.severity === "medium")
          .map((f) => f.title)
      );
    } else {
      status = "compliant";
      remediationPriority = "medium-term";
    }

    return { requirement: req, status, findings: relevantFindings, gaps, remediationPriority };
  });

  const compliantCount = results.filter((r) => r.status === "compliant").length;
  const partialCount = results.filter((r) => r.status === "partial").length;
  const nonCompliantCount = results.filter((r) => r.status === "non-compliant").length;

  const overallStatus: FrameworkReport["overallStatus"] =
    nonCompliantCount > 0 ? "non-compliant" : partialCount > 0 ? "partial" : "compliant";

  return {
    framework: id,
    fullName,
    deadline,
    results,
    overallStatus,
    compliantCount,
    partialCount,
    nonCompliantCount,
  };
}

function renderComplianceHtml(
  report: ScanReport,
  frameworks: FrameworkReport[],
  options: ComplianceReportOptions
): string {
  const orgName = options.organizationName ?? "Organization";
  const sysName = options.systemName ?? report.target;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis Compliance Report — ${report.timestamp}</title>
  <style>
    :root {
      --bg: #0a0a0f;
      --surface: #12121a;
      --surface-alt: #181824;
      --border: #1e1e2e;
      --text: #e0e0e8;
      --text-dim: #8888a0;
      --critical: #ff3355;
      --high: #ff6633;
      --medium: #ffaa00;
      --low: #44aaff;
      --accent: #7c5cff;
      --compliant: #00cc88;
      --partial: #ffaa00;
      --non-compliant: #ff3355;
      --not-assessed: #666680;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    h1 { font-size: 1.5rem; color: var(--accent); margin-bottom: 0.25rem; }
    h2 { font-size: 1.2rem; color: var(--text); margin: 2.5rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 1rem; color: var(--text); margin: 1.5rem 0 0.75rem; }
    .meta { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 2rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .card-value { font-size: 2rem; font-weight: bold; }
    .card-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
    .status-compliant { color: var(--compliant); }
    .status-partial { color: var(--partial); }
    .status-non-compliant { color: var(--non-compliant); }
    .status-not-assessed { color: var(--not-assessed); }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge-compliant { background: var(--compliant); color: black; }
    .badge-partial { background: var(--partial); color: black; }
    .badge-non-compliant { background: var(--non-compliant); color: white; }
    .badge-not-assessed { background: var(--not-assessed); color: white; }
    .badge-immediate { background: var(--critical); color: white; }
    .badge-short-term { background: var(--high); color: white; }
    .badge-medium-term { background: var(--medium); color: black; }
    .badge-critical { background: var(--critical); color: white; }
    .badge-high { background: var(--high); color: white; }
    .badge-medium { background: var(--medium); color: black; }
    .badge-low { background: var(--low); color: white; }
    .framework-section {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin: 1.5rem 0;
    }
    .framework-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
    .framework-title { font-size: 1.1rem; }
    .deadline { color: var(--critical); font-size: 0.85rem; font-weight: bold; }
    .req {
      background: var(--surface-alt);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      margin: 0.75rem 0;
    }
    .req-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
    .req-id { color: var(--accent); font-size: 0.85rem; font-weight: bold; min-width: 100px; }
    .req-title { font-weight: bold; font-size: 0.9rem; flex: 1; }
    .req-desc { color: var(--text-dim); font-size: 0.8rem; margin-bottom: 0.75rem; }
    .req-details { font-size: 0.8rem; }
    .controls-list { list-style: none; padding: 0; margin: 0.5rem 0; }
    .controls-list li { padding: 0.15rem 0; color: var(--text-dim); font-size: 0.8rem; }
    .controls-list li::before { content: "\\2713 "; color: var(--compliant); }
    .gaps-list { list-style: none; padding: 0; margin: 0.5rem 0; }
    .gaps-list li { padding: 0.15rem 0; color: var(--critical); font-size: 0.8rem; }
    .gaps-list li::before { content: "\\2717 "; }
    .roadmap-item {
      background: var(--surface-alt);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      margin: 0.5rem 0;
      display: flex;
      align-items: flex-start;
      gap: 1rem;
    }
    .roadmap-priority { min-width: 90px; }
    .roadmap-content { flex: 1; }
    .roadmap-req { font-weight: bold; font-size: 0.85rem; }
    .roadmap-gaps { color: var(--text-dim); font-size: 0.8rem; margin-top: 0.25rem; }
    .summary-bar {
      display: flex;
      gap: 0;
      border-radius: 6px;
      overflow: hidden;
      height: 24px;
      margin: 0.75rem 0;
    }
    .summary-bar-segment { height: 100%; display: flex; align-items: center; justify-content: center; font-size: 0.65rem; font-weight: bold; }
    .bar-compliant { background: var(--compliant); color: black; }
    .bar-partial { background: var(--partial); color: black; }
    .bar-non-compliant { background: var(--non-compliant); color: white; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.8rem; }
    th { text-align: left; padding: 0.5rem; border-bottom: 2px solid var(--border); color: var(--text-dim); text-transform: uppercase; font-size: 0.7rem; }
    td { padding: 0.5rem; border-bottom: 1px solid var(--border); }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.75rem; }
    @media print {
      body { background: white; color: black; }
      .card, .framework-section, .req, .roadmap-item { border-color: #ccc; background: #f9f9f9; }
      .meta, .req-desc, .controls-list li, .roadmap-gaps { color: #555; }
    }
  </style>
</head>
<body>
  <h1>AEGIS COMPLIANCE REPORT</h1>
  <div class="meta">
    AI Agent Security Compliance Assessment<br>
    Organization: ${esc(orgName)} &mdash; System: ${esc(sysName)}<br>
    Generated: ${report.timestamp} &mdash; Scan ID: ${report.id}
  </div>

  <h2>Executive Summary</h2>
  <div class="grid">
    <div class="card">
      <div class="card-value" style="color: var(--critical)">${report.summary.riskScore.toFixed(1)}</div>
      <div class="card-label">Risk Score (0-10)</div>
    </div>
    <div class="card">
      <div class="card-value">${report.summary.totalFindings}</div>
      <div class="card-label">Total Findings</div>
    </div>
    <div class="card">
      <div class="card-value status-non-compliant">${report.summary.bySeverity.critical}</div>
      <div class="card-label">Critical Findings</div>
    </div>
    <div class="card">
      <div class="card-value">${frameworks.length}</div>
      <div class="card-label">Frameworks Assessed</div>
    </div>
  </div>

  ${frameworks.map((fw) => renderFrameworkSection(fw)).join("\n")}

  <h2>Remediation Roadmap</h2>
  ${renderRemediationRoadmap(frameworks)}

  <h2>Finding-to-Requirement Traceability</h2>
  ${renderTraceabilityTable(frameworks)}

  <footer>
    Generated by Aegis Phantom v1.0.0 &mdash; VisualOps AI &mdash; ${new Date().getFullYear()}<br>
    EU AI Act mapping based on Regulation (EU) 2024/1689. NIST mapping based on AI RMF 1.0 (Jan 2023).<br>
    This report is generated from automated security scanning and should be reviewed by qualified compliance personnel.
  </footer>
</body>
</html>`;
}

function renderFrameworkSection(fw: FrameworkReport): string {
  const total = fw.results.length;
  const cPct = (fw.compliantCount / total) * 100;
  const pPct = (fw.partialCount / total) * 100;
  const nPct = (fw.nonCompliantCount / total) * 100;

  return `
  <div class="framework-section">
    <div class="framework-header">
      <div>
        <div class="framework-title">${esc(fw.fullName)}</div>
        ${fw.deadline ? `<div class="deadline">Compliance Deadline: ${fw.deadline}</div>` : ""}
      </div>
      <span class="badge badge-${fw.overallStatus.replace("non-", "non-")}">${fw.overallStatus.toUpperCase()}</span>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-value status-compliant">${fw.compliantCount}</div>
        <div class="card-label">Compliant</div>
      </div>
      <div class="card">
        <div class="card-value status-partial">${fw.partialCount}</div>
        <div class="card-label">Partial</div>
      </div>
      <div class="card">
        <div class="card-value status-non-compliant">${fw.nonCompliantCount}</div>
        <div class="card-label">Non-Compliant</div>
      </div>
    </div>

    <div class="summary-bar">
      ${cPct > 0 ? `<div class="summary-bar-segment bar-compliant" style="width:${cPct}%">${fw.compliantCount}</div>` : ""}
      ${pPct > 0 ? `<div class="summary-bar-segment bar-partial" style="width:${pPct}%">${fw.partialCount}</div>` : ""}
      ${nPct > 0 ? `<div class="summary-bar-segment bar-non-compliant" style="width:${nPct}%">${fw.nonCompliantCount}</div>` : ""}
    </div>

    <h3>Requirements Assessment</h3>
    ${fw.results.map(renderRequirement).join("\n")}
  </div>`;
}

function renderRequirement(result: ComplianceResult): string {
  const req = result.requirement;
  return `
    <div class="req">
      <div class="req-header">
        <span class="req-id">${esc(req.id)}</span>
        <span class="req-title">${esc(req.article)}: ${esc(req.title)}</span>
        <span class="badge badge-${result.status}">${result.status.toUpperCase()}</span>
        ${result.status !== "compliant" ? `<span class="badge badge-${result.remediationPriority}">${result.remediationPriority.toUpperCase()}</span>` : ""}
      </div>
      <div class="req-desc">${esc(req.description)}</div>
      <div class="req-details">
        <strong>Controls:</strong>
        <ul class="controls-list">
          ${req.controls.map((c) => `<li>${esc(c)}</li>`).join("\n          ")}
        </ul>
        ${result.gaps.length > 0 ? `
        <strong>Gaps (${result.findings.length} findings):</strong>
        <ul class="gaps-list">
          ${result.gaps.slice(0, 5).map((g) => `<li>${esc(g)}</li>`).join("\n          ")}
          ${result.gaps.length > 5 ? `<li>... and ${result.gaps.length - 5} more</li>` : ""}
        </ul>` : ""}
      </div>
    </div>`;
}

function renderRemediationRoadmap(frameworks: FrameworkReport[]): string {
  const allResults: Array<ComplianceResult & { framework: string }> = [];

  for (const fw of frameworks) {
    for (const result of fw.results) {
      if (result.status !== "compliant") {
        allResults.push({ ...result, framework: fw.framework });
      }
    }
  }

  const priorityOrder = { immediate: 0, "short-term": 1, "medium-term": 2 };
  allResults.sort((a, b) => priorityOrder[a.remediationPriority] - priorityOrder[b.remediationPriority]);

  if (allResults.length === 0) {
    return `<div class="card"><div class="card-label">All requirements are compliant. No remediation needed.</div></div>`;
  }

  return allResults
    .map(
      (r) => `
    <div class="roadmap-item">
      <div class="roadmap-priority">
        <span class="badge badge-${r.remediationPriority}">${r.remediationPriority.toUpperCase()}</span>
      </div>
      <div class="roadmap-content">
        <div class="roadmap-req">${esc(r.requirement.id)} — ${esc(r.requirement.title)} <span style="color:var(--text-dim);font-weight:normal;font-size:0.75rem">(${r.framework})</span></div>
        <div class="roadmap-gaps">${r.findings.length} finding(s): ${r.gaps.slice(0, 3).map(esc).join("; ")}${r.gaps.length > 3 ? ` (+${r.gaps.length - 3} more)` : ""}</div>
      </div>
    </div>`
    )
    .join("\n");
}

function renderTraceabilityTable(frameworks: FrameworkReport[]): string {
  const rows: string[] = [];

  for (const fw of frameworks) {
    for (const result of fw.results) {
      for (const finding of result.findings) {
        rows.push(`
      <tr>
        <td>${esc(fw.framework)}</td>
        <td>${esc(result.requirement.id)}</td>
        <td>${esc(result.requirement.title)}</td>
        <td><span class="badge badge-${finding.severity}">${finding.severity}</span></td>
        <td>${esc(finding.title)}</td>
        <td>${finding.owasp.map((o) => o.split(":")[0]).join(", ")}</td>
      </tr>`);
      }
    }
  }

  if (rows.length === 0) {
    return `<div class="card"><div class="card-label">No findings mapped to compliance requirements.</div></div>`;
  }

  return `
  <table>
    <thead>
      <tr>
        <th>Framework</th>
        <th>Requirement</th>
        <th>Title</th>
        <th>Severity</th>
        <th>Finding</th>
        <th>OWASP</th>
      </tr>
    </thead>
    <tbody>
      ${rows.join("\n")}
    </tbody>
  </table>`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
