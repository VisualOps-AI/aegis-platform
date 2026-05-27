"use client";

import { useState, useMemo } from "react";

interface GraphNode {
  id: string;
  server: string;
  riskScore: number;
  capabilities: {
    reads: string[];
    writes: string[];
    executes: string[];
    network: boolean;
    filesystem: boolean;
    database: boolean;
    messaging: boolean;
  };
}

interface GraphEdge {
  from: string;
  to: string;
  relationship: "data-flow" | "escalation" | "exfiltration" | "mutation";
  risk: number;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const EDGE_COLORS: Record<string, string> = {
  "data-flow": "#44aaff",
  escalation: "#ff6633",
  exfiltration: "#ff3355",
  mutation: "#ffaa00",
};

const WIDTH = 720;
const HEIGHT = 480;
const CX = WIDTH / 2;
const CY = HEIGHT / 2;

export function AttackGraph({ data }: { data: AttackGraphData }) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<number | null>(null);

  const layout = useMemo(() => {
    const nodes = data.nodes;
    const positions = new Map<string, { x: number; y: number }>();

    const servers = [...new Set(nodes.map((n) => n.server))];

    servers.forEach((server, si) => {
      const serverNodes = nodes.filter((n) => n.server === server);
      const serverAngle = (si / servers.length) * 2 * Math.PI - Math.PI / 2;
      const serverRadius = Math.min(WIDTH, HEIGHT) * 0.3;

      const scx = CX + Math.cos(serverAngle) * serverRadius;
      const scy = CY + Math.sin(serverAngle) * serverRadius;

      serverNodes.forEach((node, ni) => {
        const nodeAngle =
          serverAngle + ((ni - (serverNodes.length - 1) / 2) * 0.4);
        const nodeRadius = 40 + serverNodes.length * 8;
        positions.set(node.id, {
          x: scx + Math.cos(nodeAngle) * nodeRadius,
          y: scy + Math.sin(nodeAngle) * nodeRadius,
        });
      });
    });

    return positions;
  }, [data.nodes]);

  const activeEdges = hoveredNode
    ? data.edges.filter((e) => e.from === hoveredNode || e.to === hoveredNode)
    : data.edges;

  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "16px 20px",
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <div
          className="text-[10px] uppercase tracking-wider"
          style={{ color: "var(--text-muted)" }}
        >
          Attack Surface Graph
        </div>
        <div className="flex items-center gap-3">
          {Object.entries(EDGE_COLORS).map(([rel, color]) => (
            <div key={rel} className="flex items-center gap-1">
              <div
                className="w-3 h-0.5"
                style={{ background: color, borderRadius: 1 }}
              />
              <span
                className="text-[9px] uppercase tracking-wider"
                style={{ color: "var(--text-muted)" }}
              >
                {rel}
              </span>
            </div>
          ))}
        </div>
      </div>

      <svg
        width="100%"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        style={{ overflow: "visible" }}
      >
        <defs>
          {Object.entries(EDGE_COLORS).map(([rel, color]) => (
            <marker
              key={rel}
              id={`arrow-${rel}`}
              viewBox="0 0 10 10"
              refX="10"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={color} opacity={0.7} />
            </marker>
          ))}
        </defs>

        {data.edges.map((edge, i) => {
          const from = layout.get(edge.from);
          const to = layout.get(edge.to);
          if (!from || !to) return null;

          const isActive =
            hoveredNode === null ||
            edge.from === hoveredNode ||
            edge.to === hoveredNode;
          const isHovered = hoveredEdge === i;

          const dx = to.x - from.x;
          const dy = to.y - from.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const nx = dx / dist;
          const ny = dy / dist;
          const offset = 10;

          return (
            <g key={i}>
              <line
                x1={from.x + nx * offset}
                y1={from.y + ny * offset}
                x2={to.x - nx * offset}
                y2={to.y - ny * offset}
                stroke={EDGE_COLORS[edge.relationship]}
                strokeWidth={isHovered ? 2 : 1}
                opacity={isActive ? 0.6 : 0.1}
                markerEnd={`url(#arrow-${edge.relationship})`}
                style={{ transition: "opacity 0.2s" }}
              />
              <line
                x1={from.x + nx * offset}
                y1={from.y + ny * offset}
                x2={to.x - nx * offset}
                y2={to.y - ny * offset}
                stroke="transparent"
                strokeWidth={8}
                onMouseEnter={() => setHoveredEdge(i)}
                onMouseLeave={() => setHoveredEdge(null)}
                style={{ cursor: "pointer" }}
              />
            </g>
          );
        })}

        {data.nodes.map((node) => {
          const pos = layout.get(node.id);
          if (!pos) return null;

          const isActive =
            hoveredNode === null || hoveredNode === node.id ||
            activeEdges.some((e) => e.from === node.id || e.to === node.id);

          const baseRadius = 6 + node.riskScore * 0.8;
          const color =
            node.riskScore <= 3
              ? "var(--pass)"
              : node.riskScore <= 6
                ? "var(--warn)"
                : "var(--fail)";

          return (
            <g
              key={node.id}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              style={{ cursor: "pointer", transition: "opacity 0.2s" }}
              opacity={isActive ? 1 : 0.25}
            >
              <circle
                cx={pos.x}
                cy={pos.y}
                r={baseRadius + 3}
                fill={color}
                opacity={0.15}
              />
              <circle
                cx={pos.x}
                cy={pos.y}
                r={baseRadius}
                fill="var(--bg)"
                stroke={color}
                strokeWidth={1.5}
              />
              <text
                x={pos.x}
                y={pos.y + baseRadius + 12}
                textAnchor="middle"
                fill="var(--text-dim)"
                fontSize="9"
                fontFamily="inherit"
              >
                {node.id.length > 16 ? node.id.slice(0, 14) + ".." : node.id}
              </text>
            </g>
          );
        })}
      </svg>

      {hoveredNode && (
        <NodeTooltip
          node={data.nodes.find((n) => n.id === hoveredNode)!}
          edges={data.edges.filter(
            (e) => e.from === hoveredNode || e.to === hoveredNode
          )}
        />
      )}

      {hoveredEdge !== null && !hoveredNode && (
        <EdgeTooltip edge={data.edges[hoveredEdge]} />
      )}

      <div className="flex items-center justify-between mt-3 pt-3" style={{ borderTop: "1px solid var(--border-subtle)" }}>
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          {data.nodes.length} tools — {data.edges.length} relationships
        </span>
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          {data.edges.filter((e) => e.relationship === "exfiltration").length} exfiltration paths
        </span>
      </div>
    </div>
  );
}

function NodeTooltip({
  node,
  edges,
}: {
  node: GraphNode;
  edges: GraphEdge[];
}) {
  const caps = [];
  if (node.capabilities.filesystem) caps.push("FS");
  if (node.capabilities.network) caps.push("NET");
  if (node.capabilities.database) caps.push("DB");
  if (node.capabilities.messaging) caps.push("MSG");
  if (node.capabilities.executes.length > 0) caps.push("EXEC");

  return (
    <div
      className="text-[10px] mt-2 px-3 py-2 flex items-center gap-4"
      style={{
        background: "var(--bg)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
      }}
    >
      <span style={{ color: "var(--text)" }}>{node.id}</span>
      <span style={{ color: "var(--text-muted)" }}>server: {node.server}</span>
      <span style={{ color: "var(--text-muted)" }}>risk: {node.riskScore.toFixed(1)}</span>
      <span style={{ color: "var(--accent)" }}>{caps.join(" ")}</span>
      <span style={{ color: "var(--text-muted)" }}>{edges.length} connections</span>
    </div>
  );
}

function EdgeTooltip({ edge }: { edge: GraphEdge }) {
  return (
    <div
      className="text-[10px] mt-2 px-3 py-2 flex items-center gap-3"
      style={{
        background: "var(--bg)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
      }}
    >
      <span style={{ color: "var(--text)" }}>{edge.from}</span>
      <span style={{ color: EDGE_COLORS[edge.relationship] }}>→ {edge.relationship}</span>
      <span style={{ color: "var(--text)" }}>{edge.to}</span>
      <span style={{ color: "var(--text-muted)" }}>risk: {edge.risk.toFixed(1)}</span>
    </div>
  );
}
