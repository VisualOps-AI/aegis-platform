# Witness

MCP proxy that intercepts agent tool calls, executes them in isolated shadow timelines, and logs everything to a local audit trail. Policy engine controls what gets allowed, sandboxed, or denied.

**"Agency without accountability is liability."**

## Why

AI agents that can write files, run commands, and call APIs need a trust layer. Witness sits between the agent and its tools — every action is evaluated against policy, executed in isolation, diffed, and recorded. Nothing touches your real filesystem until it's been verified.

## Architecture

```
Agent (Claude Code, etc.)
    │
    │  MCP JSON-RPC (tools/call)
    ▼
┌─────────────────────────────────────────────┐
│              WITNESS PROXY                   │
│                                              │
│  Intercept → Policy Engine → Shadow Timeline │
│                                    │         │
│                              Diff Engine     │
│                                    │         │
│                              Event Store     │
│                             (SQLite)         │
└─────────────────────────────────────────────┘
    │
    ▼
Real Tool Servers (filesystem, terminal, http)
```

## How It Works

1. Agent calls a tool (e.g. `filesystem.write` on `src/utils.ts`)
2. **Policy Engine** evaluates the call against `witness.yaml` rules — regex for commands, glob for paths
3. Decision routes the call:
   - `allow` → execute directly
   - `allow_shadow` → clone workspace to temp dir, execute there, compute diff, auto-merge back
   - `deny` → reject with reason
4. **Event Store** logs the call, args, result, duration, and any diffs to SQLite
5. Agent receives the result transparently

## Features

| Component | What It Does |
|-----------|-------------|
| **MCP Proxy** | stdio server/client pair — drop-in between any agent and its tool servers |
| **Policy Engine** | YAML-configured rules with regex (commands) and glob (paths) matching, risk scoring (0.0–1.0) |
| **Shadow Workspace** | Copy-on-write temp directory clone with SHA256 file tracking, configurable size limits |
| **Diff Engine** | LCS-based unified diff generation — git-compatible output with insertion/deletion counts |
| **Timeline Manager** | Branching model for shadow executions — tracks lifecycle (active → merged/abandoned) |
| **Event Store** | SQLite with 4 tables: sessions, events, timelines, timeline_events — zero external dependencies |

## Quick Start

```bash
# Requires Node.js 22+
npm install
npm run build

# Initialize config
npx witness init

# Run agent through Witness
npx witness run --server "npx -y @anthropic-ai/mcp-server-filesystem ."
```

## Policy Configuration

`witness.yaml` controls what agents can do:

```yaml
tools:
  terminal.exec:
    default: require_approval
    rules:
      - match: "^git (status|diff|log|add|commit)"
        decision: allow_shadow
      - match: "rm -rf"
        decision: deny
        reason: "destructive_delete"

  filesystem.write:
    default: allow_shadow
    allowed_paths:
      - "./src/**"
      - "./tests/**"
    denied_paths:
      - "**/.env*"
      - "**/secrets/**"

risk_thresholds:
  auto_approve_max: 0.3
  require_approval_min: 0.7
```

See [`witness.yaml.example`](witness.yaml.example) for the full template.

## CLI

```bash
witness run --server <command>    # Proxy agent through Witness
witness init [--force]            # Create witness.yaml
witness receipts list             # Show recent sessions
witness receipts --session <id>   # Show events for a session
witness timeline --session <id>   # Show shadow timelines
```

## Tests

18 tests across 3 suites using Node.js built-in test runner:

```bash
npm test
```

| Suite | Tests | Coverage |
|-------|-------|----------|
| Shadow Workspace | 6 | Creation, exclusions, snapshots, change detection, cleanup |
| Diff Engine | 5 | Added/modified/deleted files, unified format, no-change handling |
| Timeline Manager | 7 | CRUD, branching, status transitions, event logging |

## Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| Runtime | Node.js 22+ | Built-in SQLite, no native deps |
| Protocol | MCP SDK | Standard agent protocol |
| Database | `node:sqlite` | Zero-dependency, local-first |
| Diff | Custom LCS | Git-compatible output without shelling out |
| Config | YAML | Human-readable policy files |

## Project Structure

```
src/
├── index.ts              # CLI entry (commander.js)
├── proxy/
│   ├── server.ts         # MCP server (stdio transport)
│   ├── client.ts         # MCP client (upstream connection)
│   └── router.ts         # Policy evaluation + shadow routing
├── policy/
│   ├── engine.ts         # Rule matching + risk scoring
│   └── parser.ts         # YAML config parsing
├── sandbox/
│   ├── manager.ts        # Shadow timeline orchestration
│   ├── workspace.ts      # Copy-on-write filesystem overlay
│   └── diff.ts           # LCS unified diff engine
├── timeline/
│   └── branch.ts         # Timeline branching + lifecycle
└── receipts/
    └── store.ts          # SQLite event store
```

## Roadmap

Weeks 1–3 are shipped. See [ROADMAP.md](ROADMAP.md) for the full plan.

| Phase | Status |
|-------|--------|
| MCP proxy + event logging | Done |
| Shadow timelines + diff engine | Done |
| Policy engine + risk scoring | Done |
| Ed25519 cryptographic receipts | Planned |
| Time travel (replay, restore, branch) | Planned |
| Proof Explorer web UI | Planned |

## License

MIT
