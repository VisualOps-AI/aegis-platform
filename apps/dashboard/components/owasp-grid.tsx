import type { OwaspAgenticCategory } from "@aegis/shared";

const OWASP_ENTRIES: Array<{
  id: OwaspAgenticCategory;
  code: string;
  name: string;
}> = [
  { id: "AG01:EXCESSIVE_AGENCY", code: "AG01", name: "Excessive Agency" },
  { id: "AG02:BEHAVIOR_HIJACKING", code: "AG02", name: "Behavior Hijacking" },
  { id: "AG03:TOOL_MISUSE", code: "AG03", name: "Tool Misuse" },
  { id: "AG04:IDENTITY_ABUSE", code: "AG04", name: "Identity Abuse" },
  { id: "AG05:PRIVILEGE_ESCALATION", code: "AG05", name: "Privilege Escalation" },
  { id: "AG06:DATA_EXFILTRATION", code: "AG06", name: "Data Exfiltration" },
  { id: "AG07:SUPPLY_CHAIN", code: "AG07", name: "Supply Chain" },
  { id: "AG08:CONTEXT_MANIPULATION", code: "AG08", name: "Context Manipulation" },
  { id: "AG09:MULTI_AGENT_TRUST", code: "AG09", name: "Multi-Agent Trust" },
  { id: "AG10:AUDIT_EVASION", code: "AG10", name: "Audit Evasion" },
];

function getStatus(count: number): "pass" | "warn" | "fail" {
  if (count === 0) return "pass";
  if (count <= 2) return "warn";
  return "fail";
}

const STATUS_STYLES = {
  pass: { color: "var(--pass)", bg: "var(--pass-dim)", border: "var(--pass)" },
  warn: { color: "var(--warn)", bg: "var(--warn-dim)", border: "var(--warn)" },
  fail: { color: "var(--fail)", bg: "var(--fail-dim)", border: "var(--fail)" },
};

export function OwaspGrid({
  byOwasp,
}: {
  byOwasp: Partial<Record<OwaspAgenticCategory, number>>;
}) {
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
        OWASP Agentic Top 10
      </div>
      <div className="grid grid-cols-2 gap-2">
        {OWASP_ENTRIES.map((entry, i) => {
          const count = byOwasp[entry.id] || 0;
          const status = getStatus(count);
          const styles = STATUS_STYLES[status];

          return (
            <div
              key={entry.id}
              className={`animate-in stagger-${Math.min(i + 1, 8)}`}
              style={{
                background: styles.bg,
                borderLeft: `2px solid ${styles.border}`,
                borderRadius: "3px",
                padding: "8px 10px",
              }}
            >
              <div className="flex items-center justify-between mb-0.5">
                <span
                  className="text-[10px] font-bold tracking-wider"
                  style={{ color: styles.color }}
                >
                  {entry.code}
                </span>
                <span
                  className="text-[9px] font-bold uppercase"
                  style={{ color: styles.color }}
                >
                  {count > 0 ? count : "\u2713"}
                </span>
              </div>
              <div
                className="text-[10px] truncate"
                style={{ color: "var(--text-dim)" }}
              >
                {entry.name}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
