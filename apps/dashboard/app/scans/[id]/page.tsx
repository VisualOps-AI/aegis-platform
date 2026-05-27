import { getScan, listScans } from "@/lib/scan-store";
import { notFound } from "next/navigation";
import { RiskGauge } from "@/components/risk-gauge";
import { MetricCard } from "@/components/metric-card";
import { SeverityChart } from "@/components/severity-chart";
import { ModuleSummary } from "@/components/module-summary";
import { FindingsTable } from "@/components/findings-table";
import { AttackGraph } from "@/components/attack-graph";
import { buildGraphFromScan } from "@/lib/graph-from-scan";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) notFound();

  const allFindings = scan.results.flatMap((r) => r.findings);
  const { summary } = scan;

  const scanTime = new Date(scan.timestamp).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return (
    <div>
      <div className="mb-6 animate-in">
        <div className="flex items-center gap-2 mb-1">
          <a
            href="/scans"
            className="text-[10px] uppercase tracking-wider no-underline"
            style={{ color: "var(--text-muted)" }}
          >
            Scans
          </a>
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            /
          </span>
          <span
            className="text-[10px] uppercase tracking-wider"
            style={{ color: "var(--text-dim)" }}
          >
            {scan.id.slice(0, 8)}
          </span>
        </div>
        <h1
          className="text-base font-bold tracking-wide"
          style={{ color: "var(--text)" }}
        >
          Scan Report
        </h1>
        <div
          className="text-[11px] mt-0.5 flex items-center gap-2"
          style={{ color: "var(--text-muted)" }}
        >
          <span>{scanTime}</span>
          <span style={{ color: "var(--border)" }}>|</span>
          <span>{scan.target}</span>
          <span style={{ color: "var(--border)" }}>|</span>
          <span>{scan.duration}ms</span>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-3 mb-3 animate-in stagger-1">
        <RiskGauge score={summary.riskScore} />
        <MetricCard
          label="Total Findings"
          value={summary.totalFindings}
          subtitle={`${scan.results.length} modules`}
        />
        <MetricCard
          label="Critical"
          value={summary.bySeverity.critical}
          color="var(--critical)"
        />
        <MetricCard
          label="High"
          value={summary.bySeverity.high}
          color="var(--high)"
        />
        <MetricCard
          label="Medium"
          value={summary.bySeverity.medium}
          color="var(--medium)"
        />
      </div>

      <div className="grid grid-cols-2 gap-3 mb-3 animate-in stagger-3">
        <SeverityChart bySeverity={summary.bySeverity} />
        <ModuleSummary results={scan.results} />
      </div>

      <div className="mb-6 animate-in stagger-4">
        <AttackGraph data={buildGraphFromScan(scan)} />
      </div>

      <div className="mb-3 animate-in stagger-5">
        <div className="flex items-center justify-between mb-1">
          <h2
            className="text-sm font-bold"
            style={{ color: "var(--text)" }}
          >
            All Findings
          </h2>
          <a
            href={`/scans/${scan.id}/compliance`}
            className="text-[10px] uppercase tracking-wider no-underline px-3 py-1.5"
            style={{
              color: "var(--accent)",
              border: "1px solid var(--accent-dim)",
              borderRadius: "var(--radius)",
            }}
          >
            Compliance View
          </a>
        </div>
      </div>

      <div className="animate-in stagger-6">
        <FindingsTable findings={allFindings} />
      </div>
    </div>
  );
}
