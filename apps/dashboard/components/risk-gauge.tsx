export function RiskGauge({ score }: { score: number }) {
  const radius = 52;
  const stroke = 6;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 10) * circumference;
  const remaining = circumference - progress;

  const color =
    score <= 3 ? "var(--pass)" : score <= 6 ? "var(--warn)" : "var(--fail)";

  const glowColor =
    score <= 3
      ? "rgba(0,204,136,0.3)"
      : score <= 6
        ? "rgba(255,170,0,0.3)"
        : "rgba(255,51,85,0.3)";

  return (
    <div
      className="relative overflow-hidden flex flex-col items-center justify-center"
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "20px",
      }}
    >
      <div
        className="text-[10px] uppercase tracking-wider mb-3 self-start"
        style={{ color: "var(--text-muted)" }}
      >
        Risk Score
      </div>
      <div className="relative" style={{ width: 128, height: 128 }}>
        <svg
          width="128"
          height="128"
          viewBox="0 0 128 128"
          className="transform -rotate-90"
        >
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth={stroke}
          />
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={`${progress} ${remaining}`}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 6px ${glowColor})`,
              transition: "stroke-dasharray 0.8s ease-out",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-3xl font-bold tabular-nums"
            style={{ color, lineHeight: 1 }}
          >
            {score.toFixed(1)}
          </span>
          <span
            className="text-[9px] uppercase tracking-widest mt-1"
            style={{ color: "var(--text-muted)" }}
          >
            / 10
          </span>
        </div>
      </div>
      <div
        className="text-[10px] mt-3 uppercase tracking-wider font-bold"
        style={{ color }}
      >
        {score <= 3 ? "Low Risk" : score <= 6 ? "Moderate" : "High Risk"}
      </div>
    </div>
  );
}
