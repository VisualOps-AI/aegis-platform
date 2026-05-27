export function MetricCard({
  label,
  value,
  color,
  subtitle,
}: {
  label: string;
  value: string | number;
  color?: string;
  subtitle?: string;
}) {
  return (
    <div
      className="relative overflow-hidden"
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "16px 20px",
      }}
    >
      {color && (
        <div
          className="absolute top-0 left-0 w-full h-[2px]"
          style={{ background: color }}
        />
      )}
      <div
        className="text-[10px] uppercase tracking-wider mb-2"
        style={{ color: "var(--text-muted)" }}
      >
        {label}
      </div>
      <div
        className="text-2xl font-bold tabular-nums"
        style={{ color: color || "var(--text)", lineHeight: 1.1 }}
      >
        {value}
      </div>
      {subtitle && (
        <div
          className="text-[11px] mt-1.5"
          style={{ color: "var(--text-dim)" }}
        >
          {subtitle}
        </div>
      )}
    </div>
  );
}
