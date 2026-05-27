import type { Finding } from "@aegis/shared";
import { SeverityBadge } from "./severity-badge";

export function FindingsPreview({ findings }: { findings: Finding[] }) {
  const topFindings = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 5);

  if (topFindings.length === 0) {
    return (
      <div
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "16px 20px",
        }}
      >
        <div
          className="text-[10px] uppercase tracking-wider mb-4"
          style={{ color: "var(--text-muted)" }}
        >
          Top Findings
        </div>
        <div
          className="text-xs py-8 text-center"
          style={{ color: "var(--text-muted)" }}
        >
          No critical or high findings
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "16px 20px",
      }}
    >
      <div
        className="text-[10px] uppercase tracking-wider mb-4"
        style={{ color: "var(--text-muted)" }}
      >
        Top Findings
      </div>
      <div className="space-y-1">
        {topFindings.map((f, i) => (
          <div
            key={f.id}
            className={`animate-in stagger-${Math.min(i + 1, 8)} py-2.5 border-b`}
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <div className="flex items-start gap-2.5">
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium" style={{ color: "var(--text)" }}>
                  {f.title}
                </div>
                <div
                  className="text-[11px] mt-0.5 line-clamp-1"
                  style={{ color: "var(--text-dim)" }}
                >
                  {f.description}
                </div>
                <div className="flex items-center gap-3 mt-1">
                  <span
                    className="text-[9px] uppercase tracking-wider"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {f.tool}
                  </span>
                  <span
                    className="text-[9px] uppercase tracking-wider"
                    style={{ color: "var(--accent-dim)" }}
                  >
                    {f.category}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
