"use client";

import { useState } from "react";

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

interface ComplianceData {
  scanId: string;
  riskScore: number;
  frameworks: ComplianceFramework[];
}

const STATUS_CONFIG = {
  compliant: { color: "var(--pass)", bg: "var(--pass-dim)", label: "Compliant" },
  partial: { color: "var(--warn)", bg: "var(--warn-dim)", label: "Partial" },
  "non-compliant": { color: "var(--fail)", bg: "var(--fail-dim)", label: "Non-Compliant" },
  "not-assessed": { color: "var(--info)", bg: "var(--info-dim)", label: "N/A" },
};

export function ComplianceView({ data }: { data: ComplianceData }) {
  const [activeTab, setActiveTab] = useState(0);
  const framework = data.frameworks[activeTab];

  const total = framework.requirements.length;
  const compliantPct = Math.round((framework.compliantCount / total) * 100);
  const partialPct = Math.round((framework.partialCount / total) * 100);
  const nonCompliantPct = Math.round((framework.nonCompliantCount / total) * 100);

  return (
    <div>
      <div className="flex items-center gap-1 mb-6">
        {data.frameworks.map((fw, i) => (
          <button
            key={fw.name}
            onClick={() => setActiveTab(i)}
            className="text-[10px] uppercase tracking-wider px-3 py-1.5 cursor-pointer border-none transition-colors"
            style={{
              background: activeTab === i ? "var(--accent-glow)" : "transparent",
              color: activeTab === i ? "var(--accent)" : "var(--text-dim)",
              borderRadius: "var(--radius)",
              fontFamily: "inherit",
            }}
          >
            {fw.name}
          </button>
        ))}
      </div>

      <div
        className="mb-6"
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "16px 20px",
        }}
      >
        <div
          className="text-[10px] uppercase tracking-wider mb-3"
          style={{ color: "var(--text-muted)" }}
        >
          Compliance Summary
        </div>

        <div className="flex gap-6 mb-4">
          <ComplianceStat label="Compliant" value={framework.compliantCount} pct={compliantPct} color="var(--pass)" />
          <ComplianceStat label="Partial" value={framework.partialCount} pct={partialPct} color="var(--warn)" />
          <ComplianceStat label="Non-Compliant" value={framework.nonCompliantCount} pct={nonCompliantPct} color="var(--fail)" />
        </div>

        <div
          className="w-full h-2 flex overflow-hidden"
          style={{ borderRadius: "2px", background: "var(--bg)" }}
        >
          <div style={{ width: `${compliantPct}%`, background: "var(--pass)", transition: "width 0.5s" }} />
          <div style={{ width: `${partialPct}%`, background: "var(--warn)", transition: "width 0.5s" }} />
          <div style={{ width: `${nonCompliantPct}%`, background: "var(--fail)", transition: "width 0.5s" }} />
        </div>
      </div>

      <div className="space-y-2">
        {framework.requirements.map((req, i) => {
          const config = STATUS_CONFIG[req.status];
          return (
            <div
              key={req.id}
              className={`animate-in stagger-${Math.min(i + 1, 8)}`}
              style={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderLeft: `3px solid ${config.color}`,
                borderRadius: "var(--radius)",
                padding: "14px 16px",
              }}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="text-[10px] font-bold tracking-wider"
                      style={{ color: "var(--accent)" }}
                    >
                      {req.id}
                    </span>
                    <span className="text-xs" style={{ color: "var(--text)" }}>
                      {req.title}
                    </span>
                  </div>
                  {req.gaps.length > 0 && (
                    <div className="mt-1.5 space-y-0.5">
                      {req.gaps.map((gap, j) => (
                        <div
                          key={j}
                          className="text-[10px] flex items-start gap-1.5"
                          style={{ color: "var(--text-dim)" }}
                        >
                          <span style={{ color: config.color }}>&#x25CF;</span>
                          {gap}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {req.findingCount > 0 && (
                    <span
                      className="text-[10px] tabular-nums"
                      style={{ color: "var(--text-dim)" }}
                    >
                      {req.findingCount} findings
                    </span>
                  )}
                  <span
                    className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5"
                    style={{
                      color: config.color,
                      background: config.bg,
                      borderRadius: "3px",
                      border: `1px solid ${config.color}25`,
                    }}
                  >
                    {config.label}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ComplianceStat({
  label,
  value,
  pct,
  color,
}: {
  label: string;
  value: number;
  pct: number;
  color: string;
}) {
  return (
    <div>
      <div className="flex items-baseline gap-1.5">
        <span className="text-lg font-bold tabular-nums" style={{ color, lineHeight: 1 }}>
          {value}
        </span>
        <span className="text-[10px] tabular-nums" style={{ color: "var(--text-muted)" }}>
          ({pct}%)
        </span>
      </div>
      <div className="text-[9px] uppercase tracking-wider mt-0.5" style={{ color: "var(--text-muted)" }}>
        {label}
      </div>
    </div>
  );
}
