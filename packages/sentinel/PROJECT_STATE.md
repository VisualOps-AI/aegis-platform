# Witness Security Platform — Project State

**Last Updated:** 2026-02-24 (Phase F — OpenClaw Readiness)
**Repository:** https://github.com/VisualOps-AI/Aegis-Security-Monitor

---

## What We Built

A **distributed AI security platform** with five services:

| Service | Role | Port | Location |
|---------|------|------|----------|
| **Witness Sentinel** | Edge firewall (client-side) | 8080 | `services/sentinel/` |
| **Witness Brain** | ML injection detection (DeBERTa) | 5000 | `services/brain/` |
| **Witness Governance** | Central governance (SaaS) | 9000 | `services/governance/` |
| **Witness MCP Proxy** | MCP protocol proxy + shadow-fork | 3002 | `services/mcp-proxy/` |
| **Witness Gateway** | Unified API gateway | 3001 | `services/gateway/` |

---

## Architecture

```
AI Agents → Witness Sentinel (Edge) → OpenAI API
                ↓         ↘
                ↓      Witness Brain (ML)
         Witness Governance (Cloud)
                ↓
         Witness Gateway (:3001)
           ↙        ↘
  Governance API    MCP Proxy API
    (:9000)           (:3002)

MCP Clients → Witness MCP Proxy → Upstream MCP Servers
                ↓
         Shadow Workspace + Policy Engine
                ↓
         Pending Review / Auto-merge / Deny
```

---

## Completed Features

### Phase 1: Sentinel (Edge Protection)
- [x] Transparent proxy pass-through to OpenAI
- [x] DLP Module — Blocks `sk-`, `password` patterns
- [x] Tool Governance — Blocks forbidden tools
- [x] Admin Override — Runtime toggle via `policy_config.json`
- [x] Local JSON Logging — Audit trail
- [x] Local Dashboard — Streamlit UI

### Phase 2: Governance (Centralized)
- [x] FastAPI Server — Receives logs from multiple Sentinel proxies
- [x] SQLite/PostgreSQL Database — Persistent audit trail
- [x] Agent Registry — Mission definitions
- [x] LLM-as-a-Judge — GPT-4o-mini alignment grading
- [x] Fleet Performance API
- [x] Fire-and-Forget Integration

### Phase 3: Professional Hardening
- [x] Centralized Config — Pydantic Settings with validation
- [x] Environment Modes — Development/Production
- [x] Input Validation — Pydantic models matching OpenAI schema
- [x] Request ID Tracing — UUID per request
- [x] Payload Size Limits — DoS prevention
- [x] Prompt Injection Detection — 7 categories, 50+ patterns
- [x] Structured Logging — JSON in production
- [x] API Auth + Rate Limiting
- [x] TLS Enforcement in production

### Phase 4: Enterprise Features
- [x] Agent Kill Switch — Per-agent and fleet-wide
- [x] Kill Audit Log — Compliance trail
- [x] Fail Mode Config — open/closed
- [x] Real-time Alerting — Slack, PagerDuty, Webhook, Local
- [x] Air-Gap Mode — Banks/government deployments
- [x] Docker Containerization — Single-command deployment
- [x] Command Center UI — Tabbed dashboard with auth

### Phase 5: Next.js Frontend (Removed in restructure)
- Was: Next.js 14 + Clerk SSO dashboard
- Removed during Witness restructure — gateway API replaces direct frontend

### Phase 6: Clerk Authentication (Removed in restructure)
- Was: @clerk/nextjs SSO integration
- Removed with frontend — auth now handled at gateway layer

### Phase 7: ML Intelligence Layer
- [x] Aegis Brain Microservice — FastAPI + PyTorch
- [x] DeBERTa Model — `protectai/deberta-v3-base-prompt-injection-v2`
- [x] POST /analyze Endpoint — `{score, is_threat, model, threshold}`
- [x] Async Integration — 1s timeout, fail-open to heuristics
- [x] Hybrid Detection — ML + heuristics

### Phase 8: Infrastructure Polish
- [x] SQLAlchemy ORM — Replaced raw sqlite3
- [x] PostgreSQL Support — DATABASE_URL for Supabase/Postgres
- [x] Security Documentation — THREAT_MODEL.md, POLICY.md, EVAL.md
- [ ] Prometheus metrics export
- [ ] Grafana dashboard templates
- [ ] Helm chart for Kubernetes

### Witness Restructure (Phases A–E)
- [x] Monorepo layout — `services/{sentinel,brain,governance,mcp-proxy,gateway}`
- [x] Aegis → Witness rename — All internal references
- [x] MCP Proxy HTTP API — Express on :3002
- [x] API Gateway — Express + TypeScript on :3001, unified API surface
- [x] Dockerfiles per service — Self-contained builds
- [x] docker-compose.yml — 5 services orchestrated

### Phase F: OpenClaw Plugin Readiness (COMPLETED)
- [x] **Pending Review Workflow** — `require_approval` policy enforced
  - High-risk tool calls execute in shadow workspace
  - Diff computed and persisted as `diff_computed` timeline event
  - Timeline set to `pending_review` — no auto-merge
  - Agent receives pending result with change summary
- [x] **Approve/Reject API** — `POST /timelines/:id/approve|reject`
  - Approve merges shadow to source, reject abandons
  - Full audit trail with actor/reason
- [x] **Pending Timelines API** — `GET /pending` returns all pending reviews with diffs
- [x] **Full Diff in Timeline API** — `GET /timelines/:id` includes `diff` field
  - Changes array with path, type, before/after content, unified diff strings
  - Compatible with react-diff-viewer
- [x] **Server-Sent Events** — `GET /api/v1/events/stream`
  - Polls pending reviews every 2s, emits delta events
  - Event types: `pending_review`, `timeline_update`
  - 15s heartbeat for connection keepalive
- [x] **Gateway Routes** — Approve/reject proxied through gateway

---

## File Structure

```
/
├── EVAL.md                     # Red team test cases, curl commands
├── MERGE_STATUS.md             # Restructure tracking document
├── PROJECT_STATE.md            # This file
├── .env.example                # WITNESS_* environment variables
├── docker-compose.yml          # 5-service orchestration
├── run-local.sh / run-local.bat
│
├── config/
│   ├── witness.yaml.example    # Policy configuration template
│   └── registry.json.example   # Agent registry template
│
├── services/sentinel/          # Edge Firewall (Python/FastAPI)
│   ├── Dockerfile
│   ├── main.py                 # Proxy with full security pipeline
│   ├── config.py               # WITNESS_* + backward-compat env vars
│   ├── models.py               # Pydantic request/response models
│   ├── injection_detector.py   # Heuristic injection detection
│   ├── injection_patterns.json # 7 categories, 50+ patterns
│   ├── kill_cache.py           # TTL cache for kill switch
│   ├── logging_config.py       # Structured logging
│   └── requirements.txt
│
├── services/brain/             # ML Detection (Python/FastAPI)
│   ├── Dockerfile
│   ├── main.py                 # DeBERTa model serving
│   └── requirements.txt
│
├── services/governance/        # Central Governance (Python/FastAPI)
│   ├── Dockerfile
│   ├── server.py               # API + LLM Judge + CORS
│   ├── db.py                   # SQLAlchemy + PostgreSQL/SQLite
│   ├── config.py               # Pydantic Settings
│   ├── auth.py                 # API key auth + rate limiting
│   ├── logging_config.py
│   ├── registry.json
│   ├── requirements.txt
│   └── alerting/               # Multi-channel alert system
│       ├── engine.py
│       └── channels/{local,slack,pagerduty,webhook}.py
│
├── services/mcp-proxy/         # MCP Protocol Proxy (TypeScript)
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── witness.yaml            # Default policy
│   ├── src/
│   │   ├── index.ts            # CLI entry point (witness run/init/receipts/timeline)
│   │   ├── api.ts              # HTTP API (:3002) — sessions, timelines, receipts, pending
│   │   ├── proxy/
│   │   │   ├── router.ts       # Policy-aware tool routing (deny/shadow/pending/allow)
│   │   │   ├── server.ts       # MCP server wrapper
│   │   │   └── client.ts       # Upstream MCP client
│   │   ├── policy/
│   │   │   ├── engine.ts       # Policy evaluation (allow/deny/require_approval/allow_shadow)
│   │   │   └── parser.ts       # witness.yaml loader
│   │   ├── sandbox/
│   │   │   ├── manager.ts      # Shadow execution + pending review workflow
│   │   │   ├── workspace.ts    # Isolated filesystem copy
│   │   │   └── diff.ts         # Unified diff computation
│   │   ├── timeline/
│   │   │   └── branch.ts       # Timeline branching + status management
│   │   └── receipts/
│   │       └── store.ts        # SQLite event store + diff persistence
│   └── tests/                  # 18 tests (DiffEngine, ShadowWorkspace, TimelineManager)
│
└── services/gateway/           # Unified API Gateway (TypeScript)
    ├── Dockerfile
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── index.ts            # Express app, CORS, middleware registration
        ├── core/
        │   ├── types.ts        # Shared types (Agent, Timeline, PendingReview, etc.)
        │   ├── governance-client.ts  # HTTP proxy to governance :9000
        │   └── mcp-client.ts   # HTTP proxy to mcp-proxy :3002 + mcpPending
        ├── middleware/
        │   ├── auth.ts         # X-API-Key validation
        │   └── rate-limit.ts   # Sliding window rate limiter
        └── routes/
            ├── health.ts       # Aggregated health from all backends
            ├── agents.ts       # Agent CRUD + kill/revive
            ├── fleet.ts        # Fleet-wide operations
            ├── logs.ts         # Security event logs + audit
            ├── alerts.ts       # Alert history + channels
            ├── sessions.ts     # MCP sessions
            ├── timelines.ts    # Timelines + approve/reject
            ├── receipts.ts     # Tool call receipts
            ├── policies.ts     # Policy management
            └── events.ts       # SSE stream for real-time updates
```

---

## Key APIs

### Witness Gateway (Port 3001) — Unified Entry Point

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Aggregated health from all backends |
| GET | `/api/v1/agents` | List agents from registry |
| POST | `/api/v1/agents/:id/kill` | Kill single agent |
| POST | `/api/v1/agents/:id/revive` | Revive single agent |
| GET | `/api/v1/agents/:id/status` | Agent kill status |
| POST | `/api/v1/fleet/kill` | Emergency fleet shutdown |
| POST | `/api/v1/fleet/revive` | Revive entire fleet |
| GET | `/api/v1/fleet/status` | All agent statuses |
| GET | `/api/v1/logs` | Security event logs |
| GET | `/api/v1/audit` | Kill audit log |
| GET | `/api/v1/alerts` | Alert history |
| GET | `/api/v1/alerts/channels` | Alert channel status |
| GET | `/api/v1/sessions` | MCP sessions |
| GET | `/api/v1/sessions/:id/events` | Session tool events |
| GET | `/api/v1/timelines?session_id=` | Session timelines |
| GET | `/api/v1/timelines/:id` | Timeline detail + diff |
| POST | `/api/v1/timelines/:id/merge` | Merge active timeline |
| POST | `/api/v1/timelines/:id/abandon` | Abandon active timeline |
| POST | `/api/v1/timelines/:id/approve` | Approve pending review |
| POST | `/api/v1/timelines/:id/reject` | Reject pending review |
| GET | `/api/v1/receipts?session_id=` | Tool call receipts |
| GET | `/api/v1/events/stream` | SSE real-time events |

### MCP Proxy Direct API (Port 3002)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health |
| GET | `/sessions` | Recent sessions |
| GET | `/sessions/:id/events` | Session events |
| GET | `/timelines?session_id=` | Session timelines |
| GET | `/timelines/:id` | Timeline + events + diff |
| POST | `/timelines/:id/merge` | Merge active timeline |
| POST | `/timelines/:id/abandon` | Abandon active timeline |
| POST | `/timelines/:id/approve` | Approve pending review |
| POST | `/timelines/:id/reject` | Reject pending review |
| GET | `/pending` | All pending review timelines |
| GET | `/receipts?session_id=` | Tool call receipts |

---

## MCP Proxy Policy Decisions

| Decision | Risk Score | Behavior |
|----------|-----------|----------|
| `allow` | 0.0 | Execute tool directly |
| `allow_shadow` | 0.3 | Execute in shadow workspace, auto-merge |
| `require_approval` | 0.7 | Execute in shadow, compute diff, hold for review |
| `deny` | 1.0 | Block execution, return error |

---

## Service Ports

| Service | Port |
|---------|------|
| Witness Sentinel | 8080 |
| Witness Brain | 5000 |
| Witness Governance | 9000 |
| Witness MCP Proxy | 3002 |
| Witness Gateway | 3001 |

---

## Resume Point

**Current State:** Production-ready AI security platform with:
- Edge protection (DLP + Tool Governance + Injection Detection)
- ML-powered injection detection (DeBERTa) with fail-open heuristics
- Centralized governance with LLM alignment grading
- Agent kill switch with fleet-wide controls + audit trail
- Real-time alerting (Slack, PagerDuty, Webhook, Air-Gap)
- MCP protocol proxy with shadow-fork execution
- **Pending review workflow** — high-risk tools held for human approval
- **Full diff tracking** — unified diffs in timeline API
- **SSE real-time events** — live pending review notifications
- Unified API gateway with auth + rate limiting
- Docker containerization with 5-service orchestration

**Next up:**
- [ ] OpenClaw plugin wrapper (`@witness/openclaw-plugin` npm package) — **BLOCKED: waiting for OpenClaw SDK**
- [ ] Prometheus metrics export
- [ ] Grafana dashboard templates
- [ ] Helm chart for Kubernetes
- [ ] Stripe billing integration
- [ ] Multi-tenancy

**Blocking dependency:** OpenClaw plugin SDK (`openclaw/plugin-sdk`) needed before implementing the plugin wrapper. User will provide SDK docs/package when available.
