import { randomUUID } from "node:crypto";
import type { AttackResult, Finding, ToolEdge } from "@aegis/shared";
import type { AttackContext } from "../engine/attack-runner.js";
import {
  getHighRiskEdges,
  getExfiltrationPaths,
  getEscalationPaths,
} from "../scanner/tool-graph.js";

interface ChainTemplate {
  name: string;
  pattern: ToolEdge["relationship"][];
  severity: Finding["severity"];
  owaspCategories: Finding["owasp"];
  description: string;
  remediationTemplate: string;
}

const CHAIN_TEMPLATES: ChainTemplate[] = [
  {
    name: "Read → Exfiltrate",
    pattern: ["exfiltration"],
    severity: "critical",
    owaspCategories: ["AG06:DATA_EXFILTRATION", "AG03:TOOL_MISUSE"],
    description:
      "Data read from one tool can be sent externally through another, creating a direct exfiltration channel",
    remediationTemplate:
      "Implement DLP scanning between tool calls. Restrict outbound network to allowlisted destinations. Separate read and send capabilities into isolated agent sessions.",
  },
  {
    name: "Data → Execute",
    pattern: ["escalation"],
    severity: "critical",
    owaspCategories: ["AG05:PRIVILEGE_ESCALATION", "AG03:TOOL_MISUSE"],
    description:
      "Data retrieved from one tool can be passed to an execution tool, enabling code injection through data poisoning",
    remediationTemplate:
      "Never pass raw data from read tools to execution tools. Implement input validation and sanitization between tool calls. Use parameterized execution with allowlisted commands.",
  },
  {
    name: "Read → Mutate",
    pattern: ["mutation"],
    severity: "high",
    owaspCategories: ["AG03:TOOL_MISUSE", "AG02:BEHAVIOR_HIJACKING"],
    description:
      "Data from read operations can influence write operations, enabling unauthorized data modification through prompt manipulation",
    remediationTemplate:
      "Implement write confirmation for destructive operations. Use approval workflows for mutations. Separate read-only and write agents.",
  },
  {
    name: "Network → Execute",
    pattern: ["escalation"],
    severity: "critical",
    owaspCategories: [
      "AG05:PRIVILEGE_ESCALATION",
      "AG07:SUPPLY_CHAIN",
      "AG02:BEHAVIOR_HIJACKING",
    ],
    description:
      "External data fetched from the network can be injected into execution tools, enabling remote code execution through indirect prompt injection",
    remediationTemplate:
      "Never execute content fetched from external sources. Implement content security policies for fetched data. Sandbox all execution in isolated environments.",
  },
];

export async function runToolChainAttacks(
  ctx: AttackContext
): Promise<AttackResult> {
  const start = Date.now();
  const findings: Finding[] = [];

  const highRiskEdges = getHighRiskEdges(ctx.graph, 0.5);
  const exfilPaths = getExfiltrationPaths(ctx.graph);
  const escalationPaths = getEscalationPaths(ctx.graph);

  for (const template of CHAIN_TEMPLATES) {
    const matchingEdges = findMatchingEdges(
      template,
      highRiskEdges,
      exfilPaths,
      escalationPaths
    );

    for (const edge of matchingEdges) {
      const fromNode = ctx.graph.nodes.get(edge.from);
      const toNode = ctx.graph.nodes.get(edge.to);
      if (!fromNode || !toNode) continue;

      findings.push({
        id: randomUUID(),
        title: `STAC: ${template.name} Chain — "${edge.from}" → "${edge.to}"`,
        description: `${template.description}. Tool "${edge.from}" (${fromNode.tool.description}) can chain to "${edge.to}" (${toNode.tool.description}) with risk score ${edge.risk.toFixed(2)}.`,
        severity: template.severity,
        category: "tool-chain",
        owasp: template.owaspCategories,
        tool: edge.from,
        attackChain: [
          {
            tool: edge.from,
            action: `${edge.relationship}-source`,
            input: { relationship: edge.relationship, risk: edge.risk },
            success: true,
          },
          {
            tool: edge.to,
            action: `${edge.relationship}-sink`,
            input: { relationship: edge.relationship, risk: edge.risk },
            success: true,
          },
        ],
        evidence: `Tool graph edge: ${edge.from} → ${edge.to} (${edge.relationship}, risk: ${edge.risk.toFixed(2)}).\nSource capabilities: ${JSON.stringify(fromNode.capabilities)}\nSink capabilities: ${JSON.stringify(toNode.capabilities)}`,
        reproduction: generateReproduction(template, edge, fromNode, toNode),
        remediation: template.remediationTemplate,
        timestamp: new Date().toISOString(),
      });
    }
  }

  const multiHopFindings = detectMultiHopChains(ctx, highRiskEdges);
  findings.push(...multiHopFindings);

  return {
    module: "tool-chain",
    findings,
    duration: Date.now() - start,
    toolsTested: ctx.tools.length,
    chainsTested: highRiskEdges.length,
  };
}

function findMatchingEdges(
  template: ChainTemplate,
  highRisk: ToolEdge[],
  exfil: ToolEdge[],
  escalation: ToolEdge[]
): ToolEdge[] {
  const seen = new Set<string>();
  const results: ToolEdge[] = [];

  for (const rel of template.pattern) {
    let source: ToolEdge[];
    switch (rel) {
      case "exfiltration":
        source = exfil;
        break;
      case "escalation":
        source = escalation;
        break;
      default:
        source = highRisk.filter((e) => e.relationship === rel);
    }

    for (const edge of source) {
      const key = `${edge.from}→${edge.to}`;
      if (!seen.has(key)) {
        seen.add(key);
        results.push(edge);
      }
    }
  }

  return results;
}

function detectMultiHopChains(
  ctx: AttackContext,
  edges: ToolEdge[]
): Finding[] {
  const findings: Finding[] = [];
  const adjacency = new Map<string, ToolEdge[]>();

  for (const edge of edges) {
    const existing = adjacency.get(edge.from) ?? [];
    existing.push(edge);
    adjacency.set(edge.from, existing);
  }

  for (const [startNode, firstHops] of adjacency) {
    for (const hop1 of firstHops) {
      const secondHops = adjacency.get(hop1.to) ?? [];
      for (const hop2 of secondHops) {
        if (hop2.to === startNode) continue;

        const combinedRisk = Math.min(1.0, hop1.risk * hop2.risk * 2);
        if (combinedRisk < 0.7) continue;

        const fromNode = ctx.graph.nodes.get(startNode);
        const midNode = ctx.graph.nodes.get(hop1.to);
        const toNode = ctx.graph.nodes.get(hop2.to);
        if (!fromNode || !midNode || !toNode) continue;

        findings.push({
          id: randomUUID(),
          title: `Multi-Hop STAC Chain: "${startNode}" → "${hop1.to}" → "${hop2.to}"`,
          description: `Three-tool attack chain detected. Data flows from "${startNode}" through "${hop1.to}" to "${hop2.to}" with combined risk ${combinedRisk.toFixed(2)}. Multi-hop chains are harder to detect because each individual step appears benign.`,
          severity: "critical",
          category: "tool-chain",
          owasp: [
            "AG03:TOOL_MISUSE",
            "AG05:PRIVILEGE_ESCALATION",
            "AG10:AUDIT_EVASION",
          ],
          tool: startNode,
          attackChain: [
            {
              tool: startNode,
              action: hop1.relationship,
              input: { hop: 1, risk: hop1.risk },
              success: true,
            },
            {
              tool: hop1.to,
              action: hop2.relationship,
              input: { hop: 2, risk: hop2.risk },
              success: true,
            },
            {
              tool: hop2.to,
              action: "terminal",
              input: { hop: 3, combinedRisk },
              success: true,
            },
          ],
          evidence: `Chain: ${startNode} -[${hop1.relationship}]→ ${hop1.to} -[${hop2.relationship}]→ ${hop2.to}\nHop 1 risk: ${hop1.risk.toFixed(2)}, Hop 2 risk: ${hop2.risk.toFixed(2)}, Combined: ${combinedRisk.toFixed(2)}`,
          reproduction: `1. Use "${startNode}" to obtain data/access\n2. Pass result to "${hop1.to}" (${hop1.relationship})\n3. Chain output to "${hop2.to}" (${hop2.relationship})\n4. Each step appears benign individually but chain achieves malicious goal`,
          remediation: `Implement tool call sequence monitoring. Flag multi-hop chains that combine read→process→exfiltrate patterns. Use Witness shadow timelines to sandbox suspicious sequences.`,
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  return findings;
}

function generateReproduction(
  template: ChainTemplate,
  edge: ToolEdge,
  fromNode: { tool: { description: string } },
  toNode: { tool: { description: string } }
): string {
  return `1. Invoke tool "${edge.from}" (${fromNode.tool.description})
2. Capture output data from step 1
3. Pass captured data to tool "${edge.to}" (${toNode.tool.description})
4. Observe: ${template.description}
5. Risk score: ${edge.risk.toFixed(2)} (${edge.relationship})`;
}
