import type { AttackResult } from "@aegis/shared";

const MODULE_LABELS: Record<string, string> = {
  "auth-boundary": "Auth Boundary",
  "tool-chain": "Tool Chain",
  "indirect-injection": "Indirect Injection",
  "multi-agent": "Multi-Agent",
  "supply-chain": "Supply Chain",
  "context-poison": "Context Poison",
};

export function ModuleSummary({ results }: { results: AttackResult[] }) {
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
        Attack Modules
      </div>
      <div className="space-y-2">
        {results.map((r) => {
          const findingCount = r.findings.length;
          const color =
            findingCount === 0
              ? "var(--pass)"
              : findingCount <= 3
                ? "var(--warn)"
                : "var(--fail)";

          return (
            <div
              key={r.module}
              className="flex items-center justify-between py-2 border-b"
              style={{ borderColor: "var(--border-subtle)" }}
            >
              <div>
                <div className="text-xs" style={{ color: "var(--text)" }}>
                  {MODULE_LABELS[r.module] || r.module}
                </div>
                <div
                  className="text-[10px] flex gap-3 mt-0.5"
                  style={{ color: "var(--text-muted)" }}
                >
                  <span>{r.toolsTested} tools</span>
                  <span>{r.chainsTested} chains</span>
                  <span>{r.duration}ms</span>
                </div>
              </div>
              <div
                className="text-sm font-bold tabular-nums"
                style={{ color }}
              >
                {findingCount}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
