import type { ScanSummaryItem } from "@/lib/scan-store";

export function ScanCard({ scan }: { scan: ScanSummaryItem }) {
  const time = new Date(scan.timestamp).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  const riskColor =
    scan.riskScore <= 3
      ? "var(--pass)"
      : scan.riskScore <= 6
        ? "var(--warn)"
        : "var(--fail)";

  return (
    <a
      href={`/scans/${scan.id}`}
      className="block no-underline transition-colors"
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "16px 20px",
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <span
            className="text-lg font-bold tabular-nums"
            style={{ color: riskColor, lineHeight: 1 }}
          >
            {scan.riskScore.toFixed(1)}
          </span>
          <div>
            <div className="text-xs" style={{ color: "var(--text)" }}>
              {scan.target}
            </div>
            <div
              className="text-[10px]"
              style={{ color: "var(--text-muted)" }}
            >
              {time}
            </div>
          </div>
        </div>
        <div className="text-right">
          <div
            className="text-sm font-bold tabular-nums"
            style={{ color: "var(--text)" }}
          >
            {scan.totalFindings}
          </div>
          <div
            className="text-[9px] uppercase tracking-wider"
            style={{ color: "var(--text-muted)" }}
          >
            findings
          </div>
        </div>
      </div>
      <div className="flex gap-3 text-[10px] tabular-nums">
        {scan.bySeverity.critical > 0 && (
          <span style={{ color: "var(--critical)" }}>
            {scan.bySeverity.critical} crit
          </span>
        )}
        {scan.bySeverity.high > 0 && (
          <span style={{ color: "var(--high)" }}>
            {scan.bySeverity.high} high
          </span>
        )}
        {scan.bySeverity.medium > 0 && (
          <span style={{ color: "var(--medium)" }}>
            {scan.bySeverity.medium} med
          </span>
        )}
        {scan.bySeverity.low > 0 && (
          <span style={{ color: "var(--low)" }}>
            {scan.bySeverity.low} low
          </span>
        )}
        <span style={{ color: "var(--text-muted)" }}>
          {scan.duration}ms
        </span>
      </div>
    </a>
  );
}
