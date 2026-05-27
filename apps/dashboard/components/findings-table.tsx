"use client";

import { useState } from "react";
import type { Finding, Severity, AttackCategory } from "@aegis/shared";
import { SeverityBadge } from "./severity-badge";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CATEGORIES: AttackCategory[] = [
  "auth-boundary",
  "tool-chain",
  "indirect-injection",
  "multi-agent",
  "supply-chain",
  "context-poison",
];

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<AttackCategory | "all">("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const filtered = findings.filter((f) => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
    return true;
  });

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <FilterGroup
          label="Severity"
          options={["all", ...SEVERITIES]}
          value={severityFilter}
          onChange={(v) => setSeverityFilter(v as Severity | "all")}
        />
        <div className="w-px h-4 mx-1" style={{ background: "var(--border)" }} />
        <FilterGroup
          label="Module"
          options={["all", ...CATEGORIES]}
          value={categoryFilter}
          onChange={(v) => setCategoryFilter(v as AttackCategory | "all")}
        />
        <span
          className="text-[10px] ml-auto tabular-nums"
          style={{ color: "var(--text-muted)" }}
        >
          {filtered.length} / {findings.length}
        </span>
      </div>

      <div className="space-y-1">
        {filtered.map((f) => (
          <FindingRow
            key={f.id}
            finding={f}
            isExpanded={expanded.has(f.id)}
            onToggle={() => toggle(f.id)}
          />
        ))}
      </div>

      {filtered.length === 0 && (
        <div
          className="text-xs py-12 text-center"
          style={{ color: "var(--text-muted)" }}
        >
          No findings match filters
        </div>
      )}
    </div>
  );
}

function FilterGroup({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: string[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <span
        className="text-[9px] uppercase tracking-wider mr-1"
        style={{ color: "var(--text-muted)" }}
      >
        {label}:
      </span>
      {options.map((opt) => (
        <button
          key={opt}
          onClick={() => onChange(opt)}
          className="text-[10px] px-2 py-0.5 cursor-pointer border-none transition-colors"
          style={{
            background: value === opt ? "var(--accent-glow)" : "transparent",
            color: value === opt ? "var(--accent)" : "var(--text-dim)",
            borderRadius: "3px",
            fontFamily: "inherit",
          }}
        >
          {opt}
        </button>
      ))}
    </div>
  );
}

function FindingRow({
  finding,
  isExpanded,
  onToggle,
}: {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        overflow: "hidden",
      }}
    >
      <button
        onClick={onToggle}
        className="w-full text-left px-4 py-3 cursor-pointer border-none flex items-start gap-3"
        style={{
          background: "transparent",
          fontFamily: "inherit",
          color: "var(--text)",
        }}
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium">{finding.title}</div>
          <div className="flex items-center gap-3 mt-0.5">
            <span
              className="text-[9px] uppercase tracking-wider"
              style={{ color: "var(--text-muted)" }}
            >
              {finding.tool}
            </span>
            <span
              className="text-[9px] uppercase tracking-wider"
              style={{ color: "var(--accent-dim)" }}
            >
              {finding.category}
            </span>
            {finding.owasp.slice(0, 2).map((o) => (
              <span
                key={o}
                className="text-[9px] tracking-wider"
                style={{ color: "var(--text-muted)" }}
              >
                {o.split(":")[0]}
              </span>
            ))}
          </div>
        </div>
        <span
          className="text-[10px] shrink-0 mt-0.5"
          style={{ color: "var(--text-muted)" }}
        >
          {isExpanded ? "\u25B4" : "\u25BE"}
        </span>
      </button>

      {isExpanded && (
        <div
          className="px-4 pb-4 space-y-3"
          style={{ borderTop: "1px solid var(--border-subtle)" }}
        >
          <div className="pt-3">
            <DetailSection label="Description" content={finding.description} />
          </div>

          {finding.attackChain.length > 0 && (
            <div>
              <div
                className="text-[9px] uppercase tracking-wider mb-2"
                style={{ color: "var(--text-muted)" }}
              >
                Attack Chain
              </div>
              <div className="flex items-center gap-1 flex-wrap">
                {finding.attackChain.map((step, i) => (
                  <div key={i} className="flex items-center gap-1">
                    {i > 0 && (
                      <span
                        className="text-[10px]"
                        style={{ color: "var(--text-muted)" }}
                      >
                        →
                      </span>
                    )}
                    <span
                      className="text-[10px] px-2 py-0.5"
                      style={{
                        background: step.success ? "var(--fail-dim)" : "var(--surface-hover)",
                        color: step.success ? "var(--fail)" : "var(--text-dim)",
                        borderRadius: "3px",
                        border: `1px solid ${step.success ? "var(--fail)" : "var(--border)"}20`,
                      }}
                    >
                      {step.tool}: {step.action}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <DetailSection label="Evidence" content={finding.evidence} mono />
          <DetailSection label="Reproduction" content={finding.reproduction} />
          <DetailSection label="Remediation" content={finding.remediation} />
        </div>
      )}
    </div>
  );
}

function DetailSection({
  label,
  content,
  mono,
}: {
  label: string;
  content: string;
  mono?: boolean;
}) {
  if (!content) return null;

  return (
    <div>
      <div
        className="text-[9px] uppercase tracking-wider mb-1"
        style={{ color: "var(--text-muted)" }}
      >
        {label}
      </div>
      <div
        className="text-[11px] leading-relaxed"
        style={{
          color: "var(--text-dim)",
          ...(mono
            ? {
                background: "var(--bg)",
                padding: "8px 10px",
                borderRadius: "4px",
                border: "1px solid var(--border-subtle)",
                whiteSpace: "pre-wrap" as const,
                wordBreak: "break-all" as const,
              }
            : {}),
        }}
      >
        {content}
      </div>
    </div>
  );
}
