import { NextResponse } from "next/server";
import { getScan } from "@/lib/scan-store";

export const dynamic = "force-dynamic";

interface ComplianceRequirement {
  id: string;
  title: string;
  status: "compliant" | "partial" | "non-compliant" | "not-assessed";
  findingCount: number;
  criticalCount: number;
  highCount: number;
  gaps: string[];
}

interface ComplianceFramework {
  name: string;
  requirements: ComplianceRequirement[];
  compliantCount: number;
  partialCount: number;
  nonCompliantCount: number;
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const allFindings = scan.results.flatMap((r) => r.findings);

  const euAiAct: ComplianceFramework = assessEuAiAct(allFindings);
  const nist: ComplianceFramework = assessNist(allFindings);

  return NextResponse.json({
    scanId: scan.id,
    riskScore: scan.summary.riskScore,
    frameworks: [euAiAct, nist],
  });
}

function assessEuAiAct(findings: Array<{ severity: string; category: string; owasp: string[] }>): ComplianceFramework {
  const articles = [
    { id: "Art. 9", title: "Risk Management System", categories: ["auth-boundary", "tool-chain"], owasp: ["AG01", "AG03", "AG05"] },
    { id: "Art. 10", title: "Data & Data Governance", categories: ["indirect-injection", "context-poison"], owasp: ["AG06", "AG08"] },
    { id: "Art. 11", title: "Technical Documentation", categories: [] as string[], owasp: [] as string[] },
    { id: "Art. 12", title: "Record-Keeping / Logging", categories: ["context-poison"], owasp: ["AG10"] },
    { id: "Art. 13", title: "Transparency", categories: ["context-poison"], owasp: ["AG10", "AG08"] },
    { id: "Art. 14", title: "Human Oversight", categories: ["auth-boundary", "indirect-injection", "multi-agent"], owasp: ["AG01", "AG02"] },
    { id: "Art. 15", title: "Accuracy, Robustness, Cybersecurity", categories: ["indirect-injection", "supply-chain", "multi-agent", "context-poison"], owasp: ["AG02", "AG04", "AG07", "AG09"] },
    { id: "Art. 17", title: "Quality Management System", categories: [] as string[], owasp: [] as string[] },
  ];

  return buildFramework("EU AI Act", articles, findings);
}

function assessNist(findings: Array<{ severity: string; category: string; owasp: string[] }>): ComplianceFramework {
  const functions = [
    { id: "GOVERN-1", title: "Policies for AI Risk Management", categories: ["auth-boundary", "tool-chain"], owasp: ["AG01", "AG03"] },
    { id: "GOVERN-4", title: "Organizational Practices", categories: [] as string[], owasp: [] as string[] },
    { id: "MAP-1", title: "Context and Use Case Mapping", categories: ["auth-boundary"], owasp: ["AG01"] },
    { id: "MAP-3", title: "AI System Benefits and Risks", categories: ["tool-chain", "auth-boundary"], owasp: ["AG03", "AG05"] },
    { id: "MEASURE-1", title: "AI Risk Metrics", categories: [] as string[], owasp: [] as string[] },
    { id: "MEASURE-2", title: "AI System Evaluation and Testing", categories: ["indirect-injection", "multi-agent", "supply-chain", "context-poison"], owasp: ["AG02", "AG04", "AG07", "AG09"] },
    { id: "MANAGE-1", title: "AI Risk Prioritization", categories: ["auth-boundary", "tool-chain"], owasp: ["AG05", "AG06"] },
    { id: "MANAGE-4", title: "Risk Treatment and Monitoring", categories: ["context-poison"], owasp: ["AG10"] },
  ];

  return buildFramework("NIST AI RMF", functions, findings);
}

function buildFramework(
  name: string,
  requirements: Array<{ id: string; title: string; categories: string[]; owasp: string[] }>,
  findings: Array<{ severity: string; category: string; owasp: string[] }>
): ComplianceFramework {
  const assessed = requirements.map((req) => {
    const relevant = findings.filter(
      (f) =>
        req.categories.includes(f.category) ||
        f.owasp.some((o) => req.owasp.some((ro) => o.startsWith(ro)))
    );

    const criticalCount = relevant.filter((f) => f.severity === "critical").length;
    const highCount = relevant.filter((f) => f.severity === "high").length;

    let status: ComplianceRequirement["status"];
    if (req.categories.length === 0 && req.owasp.length === 0) {
      status = relevant.length === 0 ? "compliant" : "partial";
    } else if (criticalCount > 0) {
      status = "non-compliant";
    } else if (highCount > 0) {
      status = "partial";
    } else if (relevant.length > 0) {
      status = "partial";
    } else {
      status = "compliant";
    }

    const gaps: string[] = [];
    if (criticalCount > 0) gaps.push(`${criticalCount} critical findings require immediate remediation`);
    if (highCount > 0) gaps.push(`${highCount} high-severity findings need short-term fixes`);

    return {
      id: req.id,
      title: req.title,
      status,
      findingCount: relevant.length,
      criticalCount,
      highCount,
      gaps,
    };
  });

  return {
    name,
    requirements: assessed,
    compliantCount: assessed.filter((r) => r.status === "compliant").length,
    partialCount: assessed.filter((r) => r.status === "partial").length,
    nonCompliantCount: assessed.filter((r) => r.status === "non-compliant").length,
  };
}
