import { getLatestScan } from "@/lib/scan-store";
import { RiskGauge } from "@/components/risk-gauge";
import { MetricCard } from "@/components/metric-card";
import { SeverityChart } from "@/components/severity-chart";
import { OwaspGrid } from "@/components/owasp-grid";
import { ModuleSummary } from "@/components/module-summary";
import { FindingsPreview } from "@/components/findings-preview";
import { ScanTrigger } from "@/components/scan-trigger";

export const dynamic = "force-dynamic";

export default function DashboardHome() {
  const scan = getLatestScan();

  if (!scan) {
    return <EmptyState />;
  }

  const allFindings = scan.results.flatMap((r) => r.findings);
  const { summary } = scan;
  const scanTime = new Date(scan.timestamp).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-6 animate-in">
        <div>
          <h1
            className="text-base font-bold tracking-wide"
            style={{ color: "var(--text)" }}
          >
            Security Overview
          </h1>
          <div
            className="text-[11px] mt-0.5 flex items-center gap-2"
            style={{ color: "var(--text-muted)" }}
          >
            <span>Last scan: {scanTime}</span>
            <span style={{ color: "var(--border)" }}>|</span>
            <span>{scan.target}</span>
            <span style={{ color: "var(--border)" }}>|</span>
            <span>{scan.duration}ms</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ScanTrigger />
          <a
            href={`/scans/${scan.id}`}
            className="text-[10px] uppercase tracking-wider no-underline px-3 py-1.5 transition-colors"
            style={{
              color: "var(--accent)",
              border: "1px solid var(--accent-dim)",
              borderRadius: "var(--radius)",
            }}
          >
            View Full Report
          </a>
        </div>
      </div>

      {/* Top row: Risk gauge + metric cards */}
      <div className="grid grid-cols-5 gap-3 mb-3 animate-in stagger-1">
        <RiskGauge score={summary.riskScore} />
        <MetricCard
          label="Total Findings"
          value={summary.totalFindings}
          subtitle={`${scan.results.length} modules scanned`}
        />
        <MetricCard
          label="Critical"
          value={summary.bySeverity.critical}
          color="var(--critical)"
          subtitle="Immediate action required"
        />
        <MetricCard
          label="High"
          value={summary.bySeverity.high}
          color="var(--high)"
          subtitle="Short-term remediation"
        />
        <MetricCard
          label="Medium"
          value={summary.bySeverity.medium}
          color="var(--medium)"
          subtitle="Planned fixes"
        />
      </div>

      {/* Middle row: Chart + OWASP grid */}
      <div className="grid grid-cols-2 gap-3 mb-3 animate-in stagger-3">
        <SeverityChart bySeverity={summary.bySeverity} />
        <OwaspGrid byOwasp={summary.byOwasp} />
      </div>

      {/* Bottom row: Top findings + module summary */}
      <div className="grid grid-cols-2 gap-3 animate-in stagger-5">
        <FindingsPreview findings={allFindings} />
        <ModuleSummary results={scan.results} />
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div
      className="flex flex-col items-center justify-center py-24 animate-in"
    >
      <div
        className="w-3 h-3 rounded-full mb-6"
        style={{
          background: "var(--accent)",
          boxShadow: "0 0 20px var(--accent-glow), 0 0 40px var(--accent-glow)",
          animation: "pulse-glow 2s ease-in-out infinite",
        }}
      />
      <h1
        className="text-base font-bold tracking-wide mb-2"
        style={{ color: "var(--text)" }}
      >
        No Scans Yet
      </h1>
      <p
        className="text-xs text-center max-w-sm"
        style={{ color: "var(--text-dim)" }}
      >
        Run your first security scan to populate the dashboard.
      </p>
      <div className="mt-4">
        <ScanTrigger />
      </div>
      <p
        className="mt-3 text-[10px]"
        style={{ color: "var(--text-dim)" }}
      >
        or via CLI:
      </p>
      <code
        className="mt-1 text-[11px] px-4 py-2"
        style={{
          color: "var(--accent)",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}
      >
        aegis scan --save config.json
      </code>
    </div>
  );
}
