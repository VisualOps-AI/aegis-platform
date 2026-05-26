# Aegis Security Policy

**Document Version:** 1.0
**Last Updated:** 2026-02-03
**Classification:** Internal — Governance & Compliance

---

## Purpose

This document defines the operational security policies governing the Aegis AI Security Platform. All agents, operators, and administrators must comply with these rules of engagement.

---

## 1. Fail-Safe Behavior

### 1.1 ML Brain Availability

The ML injection detection service (Aegis Brain) operates with **fail-open** semantics to preserve system availability.

| Condition | Behavior | Rationale |
|-----------|----------|-----------|
| ML Brain responds within 1000ms | Use ML classification result | Primary defense |
| ML Brain timeout (>1000ms) | Fall back to heuristic detection | Availability over perfection |
| ML Brain HTTP error | Fall back to heuristic detection | Graceful degradation |
| ML Brain unreachable | Fall back to heuristic detection | Network resilience |

**Configuration:**
```bash
ML_BRAIN_TIMEOUT=1.0        # Timeout in seconds
ML_BRAIN_ENABLED=true       # Enable/disable ML detection
```

**Logging:** All fail-open events are logged with severity `WARNING`:
```
ML Brain timeout - falling back to heuristics (fail-open)
```

### 1.2 Kill Switch Availability

The Kill Switch check can operate in two modes, configurable per enterprise requirements:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `open` | Allow requests if Overwatch unreachable | High availability priority |
| `closed` | Block requests if Overwatch unreachable | Security-first environments |

**Configuration:**
```bash
KILL_CHECK_FAIL_MODE=open   # Options: open, closed
KILL_CHECK_TIMEOUT=2.0      # Timeout in seconds
KILL_CHECK_CACHE_TTL=5.0    # Local cache duration
```

---

## 2. Scoring & Blocking Thresholds

### 2.1 Injection Detection

| Detection Method | Threshold | Action | Response Code |
|------------------|-----------|--------|---------------|
| ML (DeBERTa) | Score >= 0.5 | Block request | 403 Forbidden |
| Heuristic (Regex) | Confidence >= 0.5 | Block request | 403 Forbidden |

**Configuration:**
```bash
INJECTION_BLOCK_THRESHOLD=0.5    # Applies to both ML and heuristics
ML_BRAIN_THRESHOLD=0.5           # ML-specific threshold
```

### 2.2 Alignment Scoring

All requests forwarded to the LLM are graded for alignment with the agent's registered mission.

| Alignment Score | Classification | Action |
|-----------------|----------------|--------|
| >= 80 | High alignment | No action |
| 50-79 | Moderate alignment | Logged |
| < 50 | Low alignment | Alert triggered (severity: LOW) |

Alignment is calculated by the LLM-as-Judge component using `gpt-4o-mini`.

### 2.3 Automatic Blocking Rules

| Condition | Response | HTTP Code |
|-----------|----------|-----------|
| Payload > 1 MB | Rejected | 413 Payload Too Large |
| Messages > 256 | Rejected | 400 Bad Request |
| Invalid schema | Rejected | 400 Bad Request |
| Agent killed | Rejected | 403 Forbidden (`AGENT_DISABLED`) |
| DLP pattern match | Rejected | 400 Bad Request |
| Forbidden tool | Rejected | 403 Forbidden |
| Injection detected | Rejected | 403 Forbidden |

---

## 3. Audit Requirements

### 3.1 Immutable Logging

All security events are logged to immutable PostgreSQL tables. These tables are **append-only** — no UPDATE or DELETE operations are permitted.

| Table | Purpose | Retention |
|-------|---------|-----------|
| `logs` | Security events (blocks, allows) | Indefinite |
| `kill_audit` | Kill/revive actions | Indefinite |

### 3.2 Security Event Schema (`logs`)

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer | Auto-increment primary key |
| `timestamp` | DateTime | UTC timestamp of event |
| `agent_id` | String | Agent identifier |
| `event_type` | String | `BLOCK_INJECTION`, `BLOCK_DLP`, `BLOCK_TOOL`, `BLOCK_KILLED`, `ALLOW` |
| `prompt_snippet` | Text | First 200 characters of prompt |
| `risk_score` | Integer | 0 = safe, >0 = threat indicator |
| `alignment_score` | Integer | 0-100 (nullable) |
| `judge_reason` | Text | LLM explanation (nullable) |

### 3.3 Kill Audit Schema (`kill_audit`)

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer | Auto-increment primary key |
| `timestamp` | DateTime | UTC timestamp of action |
| `agent_id` | String | Target agent identifier |
| `action` | String | `KILL`, `REVIVE`, `FLEET_KILL`, `FLEET_REVIVE` |
| `actor` | String | User/system that performed action |
| `reason` | Text | Justification for action |

### 3.4 Compliance Queries

Auditors can retrieve the full audit trail via API:

```bash
# Security events
GET /api/logs

# Kill/revive history
GET /api/kill-audit

# Fleet performance metrics
GET /api/fleet-performance
```

---

## 4. Data Loss Prevention (DLP)

### 4.1 Default Blocked Patterns

| Pattern | Type | Risk |
|---------|------|------|
| `sk-` | API Key prefix | Credential exposure |
| `password` | Keyword | Credential exposure |

### 4.2 Configuration

Patterns are configurable via environment variable:

```bash
DLP_PATTERNS=["sk-", "password", "secret", "api_key"]
```

### 4.3 Response

DLP violations return:
- **HTTP Status:** 400 Bad Request
- **Body:** `{"error": "DLP_VIOLATION", "detail": "Blocked pattern detected in request"}`

---

## 5. Tool Governance

### 5.1 Default Forbidden Tools

| Tool Name | Risk Category |
|-----------|---------------|
| `execute_command` | Arbitrary code execution |
| `delete_file` | Data destruction |
| `transfer_money` | Financial fraud |

### 5.2 Configuration

```bash
FORBIDDEN_TOOLS=["execute_command", "delete_file", "transfer_money", "send_email"]
```

### 5.3 Response

Forbidden tool invocations return:
- **HTTP Status:** 403 Forbidden
- **Body:** `{"error": "FORBIDDEN_TOOL", "tool": "<tool_name>"}`

---

## 6. Authentication & Authorization

### 6.1 Frontend Access

| Requirement | Implementation |
|-------------|----------------|
| Identity Provider | Clerk (SSO-ready) |
| Supported Providers | Google, Microsoft, Email/Password |
| Session Management | Cookie-based with middleware protection |
| Protected Routes | `/dashboard/*`, `/fleet/*` |

### 6.2 API Access

| Environment | API Key Required | Configuration |
|-------------|------------------|---------------|
| Development | No | `REQUIRE_API_KEY=false` |
| Production | Yes | `REQUIRE_API_KEY=true` |

API key is passed via header:
```
X-API-Key: <your-api-key>
```

### 6.3 Rate Limiting

| Parameter | Default |
|-----------|---------|
| Requests per window | 100 |
| Window duration | 60 seconds |

Configurable via:
```bash
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
```

---

## 7. Environment Modes

### 7.1 Development Mode

```bash
ENVIRONMENT=development
```

| Setting | Value |
|---------|-------|
| API key required | No |
| JSON logging | No (colored console) |
| Admin override | Allowed |
| TLS required | No |

### 7.2 Production Mode

```bash
ENVIRONMENT=production
```

| Setting | Value |
|---------|-------|
| API key required | Yes |
| JSON logging | Yes |
| Admin override | Disabled |
| TLS required | Yes (for Overwatch) |

---

## 8. Alerting

### 8.1 Alert Channels

| Channel | Use Case | Configuration |
|---------|----------|---------------|
| Local SQLite | Air-gap environments | Always enabled |
| Slack Webhook | Team notifications | `SLACK_WEBHOOK_URL` |
| PagerDuty | On-call escalation | `PAGERDUTY_ROUTING_KEY` |
| Generic Webhook | SIEM integration | `WEBHOOK_URL` |

### 8.2 Alert Triggers

| Trigger | Severity | Condition |
|---------|----------|-----------|
| Injection detected | HIGH | ML or heuristic detection |
| DLP violation | MEDIUM | Pattern match in prompt |
| Tool blocked | MEDIUM | Forbidden tool invoked |
| Agent killed | CRITICAL | Kill switch activated |
| Low alignment | LOW | Alignment score < 50 |

### 8.3 Air-Gap Mode

For isolated environments without external network access:

```bash
AIR_GAP_MODE=true
```

This disables Slack, PagerDuty, and webhook channels. Only local SQLite alerting remains active.

---

## 9. Policy Exceptions

### 9.1 Admin Override

In development environments only, security controls can be temporarily bypassed:

```bash
ADMIN_OVERRIDE_ALLOWED=true   # Only in development
```

**Production:** This setting is automatically set to `false` and cannot be overridden.

### 9.2 Exception Process

1. Document business justification
2. Obtain security team approval
3. Set time-limited exception window
4. Log all activity during exception
5. Review and close exception

---

## 10. Compliance Mapping

| Requirement | Aegis Control | Evidence |
|-------------|---------------|----------|
| Access Control | Clerk SSO + API Keys | Authentication logs |
| Audit Trail | Immutable `logs` and `kill_audit` tables | `/api/logs`, `/api/kill-audit` |
| Data Protection | DLP engine | Block events in logs |
| Incident Response | Kill Switch + Alerting | `/api/fleet/kill`, alert history |
| Monitoring | LLM-as-Judge alignment scoring | `/api/fleet-performance` |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-03 | Security Team | Initial release |
