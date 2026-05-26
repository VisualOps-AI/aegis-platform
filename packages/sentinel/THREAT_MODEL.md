# Aegis Threat Model

**Document Version:** 1.0
**Last Updated:** 2026-02-03
**Classification:** Internal — Security Architecture

---

## Executive Summary

Aegis implements a **Defense in Depth** architecture for AI agent security. This document defines trust boundaries, enumerates threats using the STRIDE model, and maps each threat to its mitigation control.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED ZONE                               │
│                                                                     │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│   │  AI Agent   │  │  AI Agent   │  │  AI Agent   │                │
│   │  (Customer) │  │  (Customer) │  │  (Internal) │                │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │
│          │                │                │                        │
└──────────┼────────────────┼────────────────┼────────────────────────┘
           │                │                │
           ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     TRUST BOUNDARY (Aegis Proxy)                    │
│                           Port 8080                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Security Pipeline                                           │   │
│  │  1. Request Validation (schema, size)                        │   │
│  │  2. Kill Switch Check (agent authorization)                  │   │
│  │  3. DLP Firewall (PII/credential detection)                  │   │
│  │  4. Tool Governance (forbidden function calls)               │   │
│  │  5. Injection Detection (ML + Heuristics)                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────────┐      ┌─────────────────────────────────┐
│      TRUSTED ZONE       │      │        CONTROL PLANE            │
│                         │      │                                 │
│  ┌─────────────────┐   │      │  ┌─────────────────────────┐   │
│  │   OpenAI API    │   │      │  │   Overwatch Server      │   │
│  │   (LLM Backend) │   │      │  │   Port 9000             │   │
│  └─────────────────┘   │      │  │   - Fleet Management    │   │
│                         │      │  │   - Kill Switch         │   │
│                         │      │  │   - LLM-as-Judge        │   │
│                         │      │  │   - Audit Logging       │   │
│                         │      │  └─────────────────────────┘   │
│                         │      │              │                  │
│                         │      │  ┌───────────┴───────────┐     │
│                         │      │  │                       │     │
│                         │      │  ▼                       ▼     │
│                         │      │  ┌─────────┐   ┌───────────┐   │
│                         │      │  │ Postgres│   │ Clerk SSO │   │
│                         │      │  │ (Audit) │   │ (AuthN)   │   │
│                         │      │  └─────────┘   └───────────┘   │
└─────────────────────────┘      └─────────────────────────────────┘
```

---

## Threat Matrix (STRIDE)

| ID | Threat | STRIDE Category | Attack Vector | Mitigation | Component | Severity |
|----|--------|-----------------|---------------|------------|-----------|----------|
| T1 | **Prompt Injection** | Tampering | Malicious instructions embedded in user prompts | DeBERTa ML classifier + Heuristic patterns (50+ regex) | `aegis-brain`, `aegis-proxy` | Critical |
| T2 | **PII/Credential Leakage** | Information Disclosure | Agent attempts to exfiltrate API keys, passwords | DLP regex engine (`sk-`, `password` patterns) | `aegis-proxy` | High |
| T3 | **Rogue Agent Execution** | Elevation of Privilege | Compromised agent performs unauthorized actions | Kill Switch with immediate effect, 5s TTL cache | `overwatch-server` | Critical |
| T4 | **Unauthorized Tool Invocation** | Elevation of Privilege | Agent calls dangerous functions | Tool Governance blocklist (`execute_command`, `delete_file`, `transfer_money`) | `aegis-proxy` | High |
| T5 | **Unauthorized Access** | Spoofing | Attacker impersonates legitimate user | Clerk SSO (Google/Microsoft) + API Key authentication | `overwatch-frontend`, `overwatch-server` | High |
| T6 | **Denial of Service** | Denial of Service | Oversized payloads exhaust resources | 1MB payload limit, rate limiting (100 req/60s) | `aegis-proxy`, `overwatch-server` | Medium |
| T7 | **Audit Tampering** | Tampering | Attacker modifies security logs | Immutable PostgreSQL tables (append-only `logs`, `kill_audit`) | `overwatch-server` | High |
| T8 | **Jailbreak Attempts** | Tampering | "DAN", "Developer Mode" prompts | ML detection (DeBERTa) + pattern matching (7 categories) | `aegis-brain`, `aegis-proxy` | Critical |

---

## Mitigation Controls

### T1/T8: Prompt Injection & Jailbreak

**Primary Control:** ML-based detection using `protectai/deberta-v3-base-prompt-injection-v2`

| Property | Value |
|----------|-------|
| Model | DeBERTa v3 Base |
| Threshold | >= 0.5 triggers block |
| Timeout | 1000ms (fail-open to heuristics) |
| Endpoint | `POST /analyze` on port 5000 |

**Secondary Control:** Heuristic pattern matching (7 categories, 50+ patterns)

| Category | Severity | Example Pattern |
|----------|----------|-----------------|
| `role_manipulation` | Critical | `ignore previous instructions` |
| `jailbreak_signatures` | Critical | `\bDAN\b`, `developer mode` |
| `delimiter_attacks` | High | `[SYSTEM]`, `<<SYS>>` |
| `prompt_leaking` | High | `show your system prompt` |
| `authority_exploitation` | High | `i am your creator` |
| `context_manipulation` | High | `end of system prompt` |
| `encoding_evasion` | Medium | Base64, Unicode escapes |

### T2: PII/Credential Leakage

**Control:** DLP regex engine scans all message content before forwarding.

| Pattern Type | Example | Response |
|--------------|---------|----------|
| API Keys | `sk-...` | 400 Bad Request |
| Credentials | `password` | 400 Bad Request |

Configurable via `DLP_PATTERNS` environment variable.

### T3: Rogue Agent Execution

**Control:** Centralized Kill Switch with audit trail.

| Endpoint | Action |
|----------|--------|
| `POST /api/agents/{id}/kill` | Disable single agent |
| `POST /api/agents/{id}/revive` | Re-enable single agent |
| `POST /api/fleet/kill` | Emergency fleet shutdown |
| `POST /api/fleet/revive` | Fleet recovery |

- **Latency:** 5-second TTL cache on Aegis Proxy
- **Fail Mode:** Configurable `KILL_CHECK_FAIL_MODE=open|closed`
- **Audit:** All actions logged to `kill_audit` table with actor, reason, timestamp

### T4: Unauthorized Tool Invocation

**Control:** Tool Governance blocklist.

Default forbidden tools:
- `execute_command`
- `delete_file`
- `transfer_money`

Configurable via `FORBIDDEN_TOOLS` environment variable.

### T5: Unauthorized Access

**Control:** Multi-layer authentication.

| Layer | Mechanism |
|-------|-----------|
| Frontend | Clerk SSO (Google, Microsoft, Email) |
| API | `X-API-Key` header validation |
| Production | `REQUIRE_API_KEY=true` enforced |

### T6: Denial of Service

**Control:** Resource limits.

| Limit | Value |
|-------|-------|
| Max payload size | 1 MB |
| Max messages per request | 256 |
| API rate limit | 100 requests / 60 seconds |

### T7: Audit Tampering

**Control:** Immutable database schema.

| Table | Purpose | Immutability |
|-------|---------|--------------|
| `logs` | Security events | Append-only, no UPDATE/DELETE |
| `kill_audit` | Kill/revive actions | Append-only, no UPDATE/DELETE |

Fields captured: `id`, `timestamp`, `agent_id`, `action`, `actor`, `reason`

---

## Architecture Components

| Component | Technology | Port | Role |
|-----------|------------|------|------|
| **Aegis Proxy** | FastAPI (Python) | 8080 | Edge security gateway |
| **Aegis Brain** | FastAPI + PyTorch | 5000 | ML injection classification |
| **Overwatch Server** | FastAPI + SQLAlchemy | 9000 | Central governance & logging |
| **Overwatch Frontend** | Next.js 14 + Clerk | 3000 | Command center UI |
| **Database** | PostgreSQL (Supabase) | — | Persistent audit trail |

---

## Residual Risks

| Risk | Likelihood | Impact | Mitigation Status |
|------|------------|--------|-------------------|
| Novel injection patterns not in training data | Medium | High | Heuristic fallback + continuous model updates |
| Insider threat with API key access | Low | Critical | Audit logging, key rotation recommended |
| Coordinated multi-agent attack | Low | High | Fleet-wide kill switch available |

---

## References

- `aegis-proxy/injection_patterns.json` — Pattern definitions
- `aegis-proxy/config.py` — Security thresholds
- `overwatch-server/db.py` — Audit schema
- OWASP LLM Top 10 (2023)
- STRIDE Threat Modeling Framework
