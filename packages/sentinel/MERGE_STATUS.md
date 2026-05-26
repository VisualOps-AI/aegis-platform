# Witness Merge Status

**Last Updated:** 2026-02-24
**Status:** Phases A-F COMPLETE.

## What Was Done

### Phase A: Restructure (DONE)
- Created `services/` directory
- Moved `aegis-proxy/` → `services/sentinel/`
- Moved `aegis-brain/` → `services/brain/`
- Moved `overwatch-server/` → `services/governance/`
- Moved `witness-protocol/` → `services/mcp-proxy/`
- Created `config/` with `witness.yaml.example` and `registry.json.example`
- Moved Dockerfiles into each service directory (self-contained builds)
- Deleted old root-level Dockerfiles, old source directories, overwatch-frontend
- Updated `.gitignore` for new paths

### Phase B: Rename (DONE)
- `docker-compose.yml` rewritten with 5 services: witness-governance, witness-brain, witness-sentinel, witness-mcp-proxy, witness-gateway
- Volume renamed: `aegis-data` → `witness-data`
- Sentinel `config.py`: added WITNESS_* env vars with backward-compat (old OVERWATCH_* still work)
- Sentinel `config.py`: default agent_id changed to `witness-local-01`
- All FastAPI titles: "Aegis Proxy" → "Witness Sentinel", "Overwatch" → "Witness Governance", "Aegis Brain" → "Witness Brain"
- All logger names updated: `aegis-proxy` → `witness-sentinel`, `overwatch` → `witness-governance`, `aegis-brain` → `witness-brain`
- All health endpoints: `service` field updated to new names
- Governance CORS: added localhost:3001 origin

### Phase C: MCP Proxy HTTP API (DONE)
- Created `services/mcp-proxy/src/api.ts` — Express server on port 3002
- Endpoints: /health, /sessions, /sessions/:id/events, /timelines, /timelines/:id, /timelines/:id/merge, /timelines/:id/abandon, /receipts, /receipts/:id
- Added express + @types/express dependencies
- Fixed test runner: `--loader tsx` → `--import tsx` (Node 24 compat)
- All 18 existing tests pass

### Phase D: API Gateway (DONE)
- Created `services/gateway/` — Express + TypeScript on port 3001
- `src/core/types.ts` — shared domain types (Agent, Timeline, Receipt, Alert, etc.)
- `src/core/governance-client.ts` — HTTP proxy to governance :9000
- `src/core/mcp-client.ts` — HTTP proxy to mcp-proxy :3002
- `src/middleware/auth.ts` — API key validation via X-API-Key header
- `src/middleware/rate-limit.ts` — sliding window rate limiter
- Route files for: agents, fleet, logs, alerts, sessions, timelines, receipts, policies, health
- Aggregated `/health` checks all 4 backend services
- TypeScript compiles clean (tsc --noEmit passes)

### Phase E: Polish (DONE)
- Rewrote `README.md` for Witness product
- Rewrote `EVAL.md` — all curl commands point to gateway :3001, updated service names
- Created `.env.example` with WITNESS_* variables
- Removed root `.env` (contained secrets)
- Updated `run-local.sh` and `run-local.bat` for new paths

### Phase F: OpenClaw Plugin Readiness (DONE)

**Committed:** `9fe3902` — 10 files changed, 251 insertions

#### Feature F1: Pending State for High-Risk Tools
- `router.ts`: New `require_approval` branch — executes in shadow workspace, computes diff, persists result, sets timeline to `pending_review`, returns pending result to agent. Does NOT auto-merge.
- `store.ts`: 3 new methods — `getPendingTimelines()`, `storeDiffResult()`, `getDiffResult()`
- `manager.ts`: 3 new methods — `setPendingReview()`, `approvePending()`, `rejectPending()`
- `branch.ts`: `pending_review` status now logged as timeline event, `diff_computed` added to event type union
- `api.ts`: 3 new endpoints — `GET /pending`, `POST /timelines/:id/approve`, `POST /timelines/:id/reject`

#### Feature F2: Server-Sent Events (SSE) in Gateway
- `gateway/src/routes/events.ts` (NEW): SSE endpoint at `GET /api/v1/events/stream`
  - Polls mcp-proxy `/pending` every 2s
  - Emits `pending_review` for new items, `timeline_update` for resolved items
  - 15s heartbeat to keep connection alive
- `gateway/src/core/mcp-client.ts`: Added `mcpPending()` helper
- `gateway/src/core/types.ts`: Added `PendingReview` and `DiffSummary` interfaces
- `gateway/src/routes/timelines.ts`: Added approve/reject proxy routes
- `gateway/src/index.ts`: Registered events route

#### Feature F3: Full Diff in Timeline API Response
- `manager.ts`: `computeDiff()` now persists structured metadata as `diff_computed` timeline event
- `api.ts`: `GET /timelines/:id` includes `diff` field from stored diff result (changes array, summary, unified diff strings — compatible with react-diff-viewer)

#### Verification
- [x] `npx tsc --noEmit` in mcp-proxy — clean
- [x] `npx tsc --noEmit` in gateway — clean
- [x] `npm test` in mcp-proxy — 18/18 pass
- [x] All existing shadow/deny paths unchanged (regression safe)

---

## What Remains

### Future Work (not yet implemented)
- [ ] OpenClaw plugin wrapper (`@witness/openclaw-plugin` npm package) — **BLOCKED: waiting for SDK**
- [ ] Prometheus metrics export
- [ ] Grafana dashboard templates
- [ ] Helm chart for Kubernetes
- [ ] Stripe billing integration
- [ ] Multi-tenancy

### Resume Instructions
- OpenClaw plugin wrapper is next but **blocked** on receiving the `openclaw/plugin-sdk` package/docs
- When SDK is available, the plugin should: expose `slot: "tool"` with `onToolCall` hook → forward to Witness policy engine, expose `witness_review` tool for approve/reject, connect to gateway via HTTP
- Independent work available: Prometheus, Grafana, Helm, Stripe — any can proceed in parallel

### Optional Cleanup
- [ ] Remove `services/mcp-proxy/roadmap.md` or move to root `docs/`

## Git History

| Commit | Description |
|--------|-------------|
| `37c3a3f` | Restructure Aegis → Witness: monorepo with gateway and MCP proxy (Phases A-E) |
| `9fe3902` | Add Phase F: pending-review workflow, SSE events, and diff API |
