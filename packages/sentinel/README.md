# Witness

AI agent security platform. Injection detection, kill switch, DLP, tool governance, shadow execution, cryptographic receipts — unified behind a single REST API.

## Architecture

Five microservices under a polyglot monorepo:

| Service | Runtime | Port | Role |
|---------|---------|------|------|
| **Gateway** | TypeScript | 3001 | Unified REST API for frontends |
| **Sentinel** | Python | 8080 | 7-checkpoint security pipeline (OpenAI proxy) |
| **Governance** | Python | 9000 | Agent registry, kill switch, alerting, audit log |
| **Brain** | Python | 5000 | DeBERTa ML injection detection |
| **MCP Proxy** | TypeScript | 3002 | MCP shadow fork proxy with policy engine |

```
Frontend (Lovable) → Gateway :3001 → Governance :9000
                                   → MCP Proxy  :3002
                                   → Sentinel   :8080 → OpenAI
                                   → Brain      :5000
```

## Quick Start

### Docker

```bash
cp .env.example .env
# Edit .env with your OPENAI_API_KEY and DATABASE_URL
docker compose up --build
```

### Local Development

```bash
# Linux/Mac
./run-local.sh

# Windows
run-local.bat
```

## API

All endpoints are served through the gateway on port 3001. Full reference in [EVAL.md](EVAL.md).

```
GET    /health                             # Aggregated service health

GET    /api/v1/agents                      # List agents + status
GET    /api/v1/agents/:id                  # Agent detail
POST   /api/v1/agents/:id/kill             # Kill agent
POST   /api/v1/agents/:id/revive           # Revive agent

GET    /api/v1/fleet/status                # Fleet overview
GET    /api/v1/fleet/performance            # Alignment metrics
POST   /api/v1/fleet/kill                   # Emergency shutdown
POST   /api/v1/fleet/revive                 # Fleet revive

GET    /api/v1/logs                         # Security events
GET    /api/v1/audit/kills                  # Kill switch audit trail

GET    /api/v1/alerts                       # Alert history
GET    /api/v1/alerts/channels              # Channel status
POST   /api/v1/alerts/test                  # Test alert channels

GET    /api/v1/sessions                     # MCP sessions
GET    /api/v1/sessions/:id/events          # Tool call events

GET    /api/v1/timelines?session_id=X       # Shadow timelines
GET    /api/v1/timelines/:id                # Timeline detail + diff
POST   /api/v1/timelines/:id/merge          # Approve merge
POST   /api/v1/timelines/:id/abandon        # Reject

GET    /api/v1/receipts?session_id=X        # Cryptographic receipts
GET    /api/v1/receipts/:id                 # Receipt detail
```

## Security Features

- **Injection Detection**: 58 heuristic patterns (7 categories) + DeBERTa ML model
- **DLP Scanning**: Blocks API keys, passwords, and sensitive data in prompts
- **Tool Governance**: Deny-list for dangerous function calls
- **Kill Switch**: Per-agent and fleet-wide emergency shutdown
- **LLM-as-Judge**: Alignment scoring via GPT-4o-mini
- **Shadow Execution**: Copy-on-write sandboxes for risky tool calls
- **Timeline Branching**: Fork, diff, merge/abandon agent actions
- **Policy Engine**: YAML-driven rules for MCP tool governance
- **Alerting**: Slack, PagerDuty, webhook, and local channels
- **Immutable Audit Log**: PostgreSQL + SQLAlchemy ORM

## Directory Structure

```
witness/
├── services/
│   ├── gateway/          TypeScript API gateway
│   ├── sentinel/         Python security proxy
│   ├── governance/       Python agent management
│   ├── brain/            Python ML model
│   └── mcp-proxy/        TypeScript MCP proxy
├── config/               Example configurations
├── docker-compose.yml
├── EVAL.md               Testing methodology
├── THREAT_MODEL.md       Threat analysis
└── POLICY.md             Security policy
```

## Environment Variables

See [.env.example](.env.example) for the full list. Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | OpenAI API key for proxy and alignment grading |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `WITNESS_API_KEY` | No | API key for gateway authentication |
| `WITNESS_GOVERNANCE_URL` | No | Override governance URL (default: http://localhost:9000) |
| `WITNESS_BRAIN_URL` | No | Override brain URL (default: http://localhost:5000) |

## MCP Proxy CLI

The MCP proxy also works as a standalone CLI:

```bash
cd services/mcp-proxy && npm install

# Proxy an MCP server with Witness protection
npx witness run --server "npx @modelcontextprotocol/server-filesystem ."

# View sessions
npx witness receipts

# View timelines
npx witness timeline --session <SESSION_ID>
```
