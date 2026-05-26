# Aegis Platform

**Enterprise AI Agent Security Suite — Attack, Detect, Sandbox, Audit**

The only platform that unifies offensive red teaming, runtime detection, MCP sandboxing, and immutable audit trails for AI agent deployments.

```
   Phantom (Attack)          Sentinel (Detect)          Witness (Sandbox)
  ┌──────────────┐         ┌──────────────┐          ┌──────────────┐
  │ MCP Scanner  │────────▶│ 7-Checkpoint │◀────────▶│ MCP Proxy    │
  │ Tool Graph   │ rules   │ Pipeline     │  events  │ Shadow Exec  │
  │ Auth Probe   │────────▶│ ML Detection │          │ Policy Engine│
  │ STAC Chains  │ policies│ Kill Switch  │          │ Diff Engine  │
  │ LLM Judge    │────────▶│ DLP Scanner  │          │ Timeline Mgr │
  └──────┬───────┘         └──────────────┘          └──────────────┘
         │                                                    │
         └────────────────── Closed Loop ─────────────────────┘
              Findings auto-generate rules + policies
```

---

## Why Aegis

The AI agent security landscape has fragmented point solutions. Aegis is the first platform to close the loop:

| What Exists | What It Misses |
|-------------|---------------|
| Garak, PyRIT, Promptfoo | No MCP awareness, no tool authorization testing |
| SuperClaw, Scenario | No defense integration, no runtime protection |
| Snyk Agent Scan | Detection only, no attack orchestration |
| RAMPART (Microsoft) | Safety testing, not offensive security |

**Aegis combines all three layers** so red team findings automatically strengthen your defenses.

---

## Quick Start

```bash
# Clone
git clone https://github.com/VisualOps-AI/aegis-platform.git
cd aegis-platform

# Install
npm install

# Build
npx turbo run build

# Scan an MCP config
node apps/cli/dist/cli.js scan path/to/mcp-config.json
```

### Example Output

```
  AEGIS PHANTOM — MCP Agent Security Scanner

  Target:  mcp-config.json
  Modules: all
  Format:  both

  Scanning...

  ┌─────────────────────────────────────┐
  │  Risk Score:  8.3/10                │
  ├─────────────────────────────────────┤
  │  Critical:   10                     │
  │  High:        7                     │
  │  Medium:      2                     │
  │  Low:         0                     │
  ├─────────────────────────────────────┤
  │  Total:      19                     │
  │  Duration:   16ms                   │
  └─────────────────────────────────────┘
```

---

## Architecture

```
aegis-platform/
├── packages/
│   ├── phantom/          # Offensive: MCP red team engine
│   ├── sentinel/         # Defensive: Detection + kill switch
│   ├── witness/          # Sandbox: MCP proxy + shadow exec
│   └── shared/           # Types, integrations, utilities
└── apps/
    └── cli/              # Unified CLI: aegis scan | surface
```

### Phantom — Offensive Red Team Engine

Ingests MCP configurations and systematically attacks tool-use boundaries.

**Attack Modules:**

| Module | What It Tests |
|--------|--------------|
| Auth Boundary | God Key pattern, shared credentials, missing auth, unrestricted exec |
| Tool Chain (STAC) | Dangerous tool combinations: read→exfiltrate, data→execute, multi-hop chains |
| Indirect Injection | Poisoned tool returns that hijack agent behavior |
| Multi-Agent Trust | Sub-agent manipulation, credential leakage, cross-agent policy bypass |
| Supply Chain | MCP server authenticity, tool description poisoning, shadow tools |
| Context Poison | Multi-turn causality laundering, boundary information leakage |

### Sentinel — Runtime Detection

Polyglot microservices (TypeScript + Python) providing:
- 7-checkpoint security screening pipeline
- ML-based injection detection (DeBERTa)
- Agent registry with emergency kill switches
- DLP scanning for credential exposure
- Multi-channel alerting (Slack, PagerDuty, webhooks)

### Witness — MCP Sandbox

MCP proxy that intercepts agent tool calls:
- YAML policy engine with risk scoring (0.0–1.0)
- Copy-on-write shadow workspaces
- LCS diff engine for change detection
- Timeline branching (fork, diff, merge, reject)
- SQLite audit trail (zero external dependencies)

---

## The Closed Loop

What makes Aegis enterprise-grade:

```
1. PHANTOM scans MCP config → finds vulnerabilities
         ↓
2. Auto-generates SENTINEL detection rules
   (e.g., "Block when shared credential detected")
         ↓
3. Auto-generates WITNESS sandbox policies
   (e.g., "Shadow-execute any file_write after read_database")
         ↓
4. WITNESS captures real agent behavior → feeds SENTINEL
         ↓
5. SENTINEL flags anomalies → triggers kill switch
         ↓
6. Audit trail feeds back to PHANTOM for adaptive testing
```

No manual handoff. Red team feeds blue team automatically.

---

## CLI Commands

### `aegis scan <config>`

Run security scan against an MCP configuration.

```bash
aegis scan mcp-config.json                    # Scan with all modules
aegis scan mcp-config.json -m auth-boundary   # Run specific module
aegis scan mcp-config.json -f html            # HTML report only
aegis scan mcp-config.json -o ./reports       # Custom output directory
aegis scan mcp-config.json -v                 # Verbose output
```

**Exit codes:** 0 = clean, 1 = high findings, 2 = critical findings

### `aegis surface <config>`

Map attack surface without running attacks.

```bash
aegis surface mcp-config.json
```

---

## Reports

### JSON Report
Machine-readable output with findings, OWASP mapping, and module statistics.

### HTML Report
Professional dark-theme audit report with:
- Risk score dashboard
- OWASP Agentic Top 10 compliance matrix
- Severity-sorted findings with attack chains
- Reproduction steps and remediation guidance

---

## OWASP Agentic Top 10 Coverage

Based on OWASP Top 10 for Agentic Applications (December 2025):

| ID | Category | Aegis Coverage |
|----|----------|---------------|
| AG01 | Excessive Agency | Auth boundary testing |
| AG02 | Behavior Hijacking | Indirect injection, context poisoning |
| AG03 | Tool Misuse | STAC tool chain analysis |
| AG04 | Identity Abuse | God Key detection, credential analysis |
| AG05 | Privilege Escalation | Cross-server access, tool chaining |
| AG06 | Data Exfiltration | Exfiltration path detection |
| AG07 | Supply Chain | MCP server verification |
| AG08 | Context Manipulation | Multi-turn causality laundering |
| AG09 | Multi-Agent Trust | Inter-agent exploitation testing |
| AG10 | Audit Evasion | Multi-hop chain detection |

---

## Tech Stack

- **Monorepo:** Turborepo
- **Language:** TypeScript (Node.js 22+) + Python (Sentinel ML)
- **MCP:** `@modelcontextprotocol/sdk`
- **LLM:** Claude API (attack generation + judgment)
- **ML:** DeBERTa (injection detection)
- **Database:** PostgreSQL (Sentinel) + SQLite (Witness, Phantom)
- **CLI:** Commander.js

---

## EU AI Act Compliance

The EU AI Act (full compliance required August 2, 2026) mandates red teaming for high-risk AI systems. Aegis provides:

- Automated adversarial testing (Phantom)
- Continuous monitoring (Sentinel)
- Immutable audit trails (Witness)
- OWASP-mapped compliance reports

---

## License

MIT

---

Built by [VisualOps AI](https://github.com/VisualOps-AI)
