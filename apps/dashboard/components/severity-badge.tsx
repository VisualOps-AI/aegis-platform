import type { Severity } from "@aegis/shared";

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string }> = {
  critical: { color: "var(--critical)", bg: "var(--critical-dim)" },
  high: { color: "var(--high)", bg: "var(--high-dim)" },
  medium: { color: "var(--medium)", bg: "var(--medium-dim)" },
  low: { color: "var(--low)", bg: "var(--low-dim)" },
  info: { color: "var(--info)", bg: "var(--info-dim)" },
};

export function SeverityBadge({
  severity,
  size = "sm",
}: {
  severity: Severity;
  size?: "sm" | "md";
}) {
  const config = SEVERITY_CONFIG[severity];
  const isSmall = size === "sm";

  return (
    <span
      className="inline-flex items-center font-bold uppercase tracking-wider shrink-0"
      style={{
        color: config.color,
        background: config.bg,
        fontSize: isSmall ? "9px" : "10px",
        padding: isSmall ? "2px 6px" : "3px 8px",
        borderRadius: "3px",
        border: `1px solid ${config.color}25`,
        letterSpacing: "0.08em",
        lineHeight: 1.4,
      }}
    >
      {severity}
    </span>
  );
}
