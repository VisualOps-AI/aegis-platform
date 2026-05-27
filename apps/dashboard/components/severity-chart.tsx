"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { Severity } from "@aegis/shared";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ff3355",
  high: "#ff6633",
  medium: "#ffaa00",
  low: "#44aaff",
  info: "#666680",
};

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function SeverityChart({
  bySeverity,
}: {
  bySeverity: Record<Severity, number>;
}) {
  const data = SEVERITY_ORDER.map((sev) => ({
    name: sev,
    count: bySeverity[sev] || 0,
    fill: SEVERITY_COLORS[sev],
  }));

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
        Findings by Severity
      </div>
      <div style={{ width: "100%", height: 180 }}>
        <ResponsiveContainer>
          <BarChart data={data} barCategoryGap="25%">
            <XAxis
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#8888a0", fontSize: 10, fontFamily: "inherit" }}
              dy={4}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#555568", fontSize: 10, fontFamily: "inherit" }}
              width={28}
              allowDecimals={false}
            />
            <Tooltip
              cursor={{ fill: "rgba(124, 92, 255, 0.06)" }}
              contentStyle={{
                background: "#12121a",
                border: "1px solid #1e1e2e",
                borderRadius: 6,
                fontSize: 11,
                fontFamily: "inherit",
                color: "#e0e0e8",
              }}
              labelStyle={{ color: "#8888a0", fontSize: 10, textTransform: "uppercase" }}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={36}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
