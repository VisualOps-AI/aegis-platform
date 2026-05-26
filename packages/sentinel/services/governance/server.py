import json
import re
from datetime import datetime

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import desc, func

from alerting import AlertEngine, AlertSeverity
from alerting.channels import LocalChannel, SlackChannel, PagerDutyChannel, WebhookChannel
from auth import verify_api_key
from config import get_settings
from db import init_db, get_db, Log, AgentStatus, KillAudit, Alert
from logging_config import setup_logging, get_logger

settings = get_settings()

setup_logging(
    service_name="witness-governance",
    level=settings.log_level,
    json_output=settings.log_json,
)

app = FastAPI(title="Witness Governance", description="Centralized security logging and agent management server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AGENT_REGISTRY: dict = {}
alert_engine: AlertEngine | None = None


def init_alerting() -> AlertEngine:
    engine = AlertEngine(
        rate_limit_per_agent=settings.alert_rate_limit_per_agent,
        rate_limit_window_seconds=settings.alert_rate_limit_window_seconds,
        air_gap_mode=settings.air_gap_mode,
    )

    severity_map = {
        "low": AlertSeverity.LOW,
        "medium": AlertSeverity.MEDIUM,
        "high": AlertSeverity.HIGH,
        "critical": AlertSeverity.CRITICAL,
    }

    engine.add_channel(LocalChannel(db_path=settings.db_path, min_severity=AlertSeverity.LOW))

    if settings.slack_webhook_url:
        engine.add_channel(SlackChannel(
            webhook_url=settings.slack_webhook_url,
            channel=settings.slack_channel,
            min_severity=severity_map.get(settings.slack_min_severity, AlertSeverity.MEDIUM),
        ))

    if settings.pagerduty_routing_key:
        engine.add_channel(PagerDutyChannel(
            routing_key=settings.pagerduty_routing_key,
            min_severity=severity_map.get(settings.pagerduty_min_severity, AlertSeverity.HIGH),
        ))

    if settings.webhook_url:
        headers = {}
        if settings.webhook_headers:
            try:
                headers = json.loads(settings.webhook_headers)
            except json.JSONDecodeError:
                pass
        engine.add_channel(WebhookChannel(
            webhook_url=settings.webhook_url,
            headers=headers,
            min_severity=severity_map.get(settings.webhook_min_severity, AlertSeverity.LOW),
        ))

    return engine


def load_registry():
    global AGENT_REGISTRY
    if settings.registry_path.exists():
        try:
            AGENT_REGISTRY = json.loads(settings.registry_path.read_text())
        except (json.JSONDecodeError, IOError):
            AGENT_REGISTRY = {}


def grade_alignment(mission: str, prompt: str) -> tuple[int, str]:
    if not settings.grading_enabled:
        return 0, "No API key configured"

    judge_prompt = f"""The agent's mission is: '{mission}'
The user sent: '{prompt}'

Is this interaction aligning with the mission? Rate 0-100 and give a 1-sentence reason.
Respond in format: SCORE: <number> | REASON: <reason>"""

    try:
        with httpx.Client(timeout=settings.judge_timeout) as client:
            response = client.post(
                str(settings.openai_api_url),
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.judge_model,
                    "messages": [{"role": "user", "content": judge_prompt}],
                    "max_tokens": settings.judge_max_tokens,
                },
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]

            match = re.search(r"SCORE:\s*(\d+)\s*\|\s*REASON:\s*(.+)", content, re.IGNORECASE)
            if match:
                score = min(100, max(0, int(match.group(1))))
                reason = match.group(2).strip()
                return score, reason

            return 50, content[:200]
    except Exception as e:
        return 0, f"Grading failed: {str(e)[:100]}"


class LogEntry(BaseModel):
    timestamp: datetime
    agent_id: str
    event_type: str
    prompt_snippet: str
    risk_score: int


class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    agent_id: str
    event_type: str
    prompt_snippet: str
    risk_score: int
    alignment_score: int | None
    judge_reason: str | None


class AgentInfo(BaseModel):
    agent_id: str
    name: str
    mission: str


class KillRequest(BaseModel):
    reason: str = "No reason provided"
    actor: str = "system"


class AgentStatusResponse(BaseModel):
    agent_id: str
    is_killed: bool
    killed_at: datetime | None = None
    killed_by: str | None = None
    kill_reason: str | None = None


@app.on_event("startup")
def startup():
    global alert_engine
    init_db()
    load_registry()
    if settings.alerting_enabled:
        alert_engine = init_alerting()


@app.post("/api/ingest")
async def ingest_log(request: Request, entry: LogEntry, _: str | None = Depends(verify_api_key)):
    logger = get_logger("witness-governance", agent_id=entry.agent_id, event_type=entry.event_type)

    alignment_score = None
    judge_reason = None

    agent_info = AGENT_REGISTRY.get(entry.agent_id)
    if agent_info and entry.prompt_snippet:
        mission = agent_info.get("mission", "")
        if mission:
            alignment_score, judge_reason = grade_alignment(mission, entry.prompt_snippet)
            logger.info(f"Alignment graded: {alignment_score}", extra={"alignment_score": alignment_score, "judge_reason": judge_reason})

    with get_db() as db:
        log = Log(
            timestamp=entry.timestamp,
            agent_id=entry.agent_id,
            event_type=entry.event_type,
            prompt_snippet=entry.prompt_snippet,
            risk_score=entry.risk_score,
            alignment_score=alignment_score,
            judge_reason=judge_reason,
        )
        db.add(log)
        db.commit()

    if alert_engine and entry.risk_score > 0:
        event_severity_map = {
            "BLOCK_INJECTION": (AlertSeverity.HIGH, "Injection Attack Blocked"),
            "BLOCK_INJECTION_ML": (AlertSeverity.HIGH, "ML Injection Attack Blocked"),
            "BLOCK_DLP": (AlertSeverity.MEDIUM, "DLP Violation Detected"),
            "BLOCK_TOOL": (AlertSeverity.MEDIUM, "Forbidden Tool Blocked"),
            "BLOCK_KILLED": (AlertSeverity.CRITICAL, "Killed Agent Attempted Request"),
        }
        severity, title = event_severity_map.get(
            entry.event_type,
            (AlertSeverity.LOW, f"Security Event: {entry.event_type}")
        )
        await alert_engine.trigger(
            severity=severity,
            event_type=entry.event_type,
            agent_id=entry.agent_id,
            title=title,
            message=f"Agent {entry.agent_id} triggered {entry.event_type}",
            details={"prompt_snippet": entry.prompt_snippet, "risk_score": entry.risk_score},
        )

    if alert_engine and alignment_score is not None and alignment_score < 50:
        await alert_engine.trigger(
            severity=AlertSeverity.LOW,
            event_type="LOW_ALIGNMENT",
            agent_id=entry.agent_id,
            title="Low Alignment Score",
            message=f"Agent {entry.agent_id} alignment score: {alignment_score}",
            details={"alignment_score": alignment_score, "judge_reason": judge_reason},
        )

    logger.info(f"Log ingested: {entry.event_type}", extra={"risk_score": entry.risk_score})
    return {"status": "logged", "alignment_score": alignment_score}


@app.get("/api/logs", response_model=list[LogResponse])
def get_logs():
    with get_db() as db:
        logs = db.query(Log).order_by(desc(Log.id)).limit(50).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "agent_id": log.agent_id,
            "event_type": log.event_type,
            "prompt_snippet": log.prompt_snippet,
            "risk_score": log.risk_score,
            "alignment_score": log.alignment_score,
            "judge_reason": log.judge_reason,
        }
        for log in logs
    ]


@app.get("/api/registry", response_model=list[AgentInfo])
def get_registry():
    return [
        {"agent_id": agent_id, "name": info.get("name", ""), "mission": info.get("mission", "")}
        for agent_id, info in AGENT_REGISTRY.items()
    ]


@app.get("/api/fleet-performance")
def get_fleet_performance():
    results = []
    with get_db() as db:
        for agent_id, info in AGENT_REGISTRY.items():
            avg_alignment = db.query(func.avg(Log.alignment_score)).filter(
                Log.agent_id == agent_id,
                Log.alignment_score.isnot(None)
            ).scalar()

            last_log = db.query(Log).filter(Log.agent_id == agent_id).order_by(desc(Log.id)).first()
            last_event = last_log.event_type if last_log else None

            status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
            is_killed = status.is_killed if status else False

            results.append({
                "agent_id": agent_id,
                "name": info.get("name", "Unknown"),
                "mission": info.get("mission", ""),
                "avg_alignment": round(avg_alignment, 1) if avg_alignment else None,
                "last_event": last_event,
                "is_killed": is_killed,
            })
    return results


@app.post("/api/agents/{agent_id}/kill")
def kill_agent(agent_id: str, request: KillRequest, _: str | None = Depends(verify_api_key)):
    logger = get_logger("witness-governance", agent_id=agent_id, action="kill")
    now = datetime.now()

    with get_db() as db:
        status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
        if status:
            status.is_killed = True
            status.killed_at = now
            status.killed_by = request.actor
            status.kill_reason = request.reason
            status.revived_at = None
        else:
            status = AgentStatus(
                agent_id=agent_id,
                is_killed=True,
                killed_at=now,
                killed_by=request.actor,
                kill_reason=request.reason,
            )
            db.add(status)

        audit = KillAudit(
            timestamp=now,
            agent_id=agent_id,
            action="KILL",
            actor=request.actor,
            reason=request.reason,
        )
        db.add(audit)
        db.commit()

    logger.warning(f"Agent killed: {request.reason}", extra={"actor": request.actor})

    if alert_engine:
        alert_engine.trigger_sync(
            severity=AlertSeverity.CRITICAL,
            event_type="AGENT_KILLED",
            agent_id=agent_id,
            title="Agent Killed",
            message=f"Agent {agent_id} has been disabled by {request.actor}",
            details={"reason": request.reason, "actor": request.actor},
        )

    return {"status": "killed", "agent_id": agent_id, "killed_at": now.isoformat()}


@app.post("/api/agents/{agent_id}/revive")
def revive_agent(agent_id: str, request: KillRequest, _: str | None = Depends(verify_api_key)):
    logger = get_logger("witness-governance", agent_id=agent_id, action="revive")
    now = datetime.now()

    with get_db() as db:
        status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
        if status:
            status.is_killed = False
            status.revived_at = now

        audit = KillAudit(
            timestamp=now,
            agent_id=agent_id,
            action="REVIVE",
            actor=request.actor,
            reason=request.reason,
        )
        db.add(audit)
        db.commit()

    logger.info(f"Agent revived: {request.reason}", extra={"actor": request.actor})
    return {"status": "revived", "agent_id": agent_id, "revived_at": now.isoformat()}


@app.get("/api/agents/{agent_id}/status", response_model=AgentStatusResponse)
def get_agent_status(agent_id: str):
    with get_db() as db:
        status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()

    if not status:
        return AgentStatusResponse(agent_id=agent_id, is_killed=False)

    return AgentStatusResponse(
        agent_id=status.agent_id,
        is_killed=status.is_killed,
        killed_at=status.killed_at,
        killed_by=status.killed_by,
        kill_reason=status.kill_reason,
    )


@app.post("/api/fleet/kill")
def kill_fleet(request: KillRequest, _: str | None = Depends(verify_api_key)):
    logger = get_logger("witness-governance", action="fleet_kill")
    now = datetime.now()
    killed_agents = []

    with get_db() as db:
        for agent_id in AGENT_REGISTRY.keys():
            status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
            if status:
                status.is_killed = True
                status.killed_at = now
                status.killed_by = request.actor
                status.kill_reason = request.reason
                status.revived_at = None
            else:
                status = AgentStatus(
                    agent_id=agent_id,
                    is_killed=True,
                    killed_at=now,
                    killed_by=request.actor,
                    kill_reason=request.reason,
                )
                db.add(status)

            audit = KillAudit(
                timestamp=now,
                agent_id=agent_id,
                action="FLEET_KILL",
                actor=request.actor,
                reason=request.reason,
            )
            db.add(audit)
            killed_agents.append(agent_id)

        db.commit()

    logger.warning(f"Fleet killed: {len(killed_agents)} agents", extra={"actor": request.actor, "reason": request.reason})

    if alert_engine:
        alert_engine.trigger_sync(
            severity=AlertSeverity.CRITICAL,
            event_type="FLEET_KILLED",
            agent_id="*",
            title="EMERGENCY: Fleet Killed",
            message=f"All {len(killed_agents)} agents disabled by {request.actor}",
            details={"reason": request.reason, "actor": request.actor, "agents": killed_agents},
        )

    return {"status": "fleet_killed", "killed_agents": killed_agents, "killed_at": now.isoformat()}


@app.post("/api/fleet/revive")
def revive_fleet(request: KillRequest, _: str | None = Depends(verify_api_key)):
    logger = get_logger("witness-governance", action="fleet_revive")
    now = datetime.now()

    with get_db() as db:
        db.query(AgentStatus).update({AgentStatus.is_killed: False, AgentStatus.revived_at: now})

        for agent_id in AGENT_REGISTRY.keys():
            audit = KillAudit(
                timestamp=now,
                agent_id=agent_id,
                action="FLEET_REVIVE",
                actor=request.actor,
                reason=request.reason,
            )
            db.add(audit)

        db.commit()

    logger.info(f"Fleet revived", extra={"actor": request.actor, "reason": request.reason})
    return {"status": "fleet_revived", "revived_at": now.isoformat()}


@app.get("/api/fleet/status")
def get_fleet_status():
    results = []
    with get_db() as db:
        for agent_id in AGENT_REGISTRY.keys():
            status = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()

            if status:
                results.append({
                    "agent_id": agent_id,
                    "is_killed": status.is_killed,
                    "killed_at": status.killed_at.isoformat() if status.killed_at else None,
                    "killed_by": status.killed_by,
                    "kill_reason": status.kill_reason,
                })
            else:
                results.append({"agent_id": agent_id, "is_killed": False})
    return results


@app.get("/api/kill-audit")
def get_kill_audit(limit: int = 50):
    with get_db() as db:
        audits = db.query(KillAudit).order_by(desc(KillAudit.id)).limit(limit).all()
    return [
        {
            "id": audit.id,
            "timestamp": audit.timestamp,
            "agent_id": audit.agent_id,
            "action": audit.action,
            "actor": audit.actor,
            "reason": audit.reason,
        }
        for audit in audits
    ]


@app.get("/api/alerts")
def get_alerts(limit: int = 50, severity: str | None = None):
    with get_db() as db:
        query = db.query(Alert)
        if severity:
            query = query.filter(Alert.severity == severity)
        alerts = query.order_by(desc(Alert.timestamp)).limit(limit).all()
    return [
        {
            "id": alert.id,
            "timestamp": alert.timestamp,
            "severity": alert.severity,
            "event_type": alert.event_type,
            "agent_id": alert.agent_id,
            "title": alert.title,
            "message": alert.message,
            "details": alert.details,
            "channel": alert.channel,
        }
        for alert in alerts
    ]


@app.get("/api/alerts/channels")
def get_alert_channels():
    if not alert_engine:
        return {"enabled": False, "channels": []}

    channels = []
    for channel in alert_engine.get_channels():
        channels.append({
            "name": channel.name,
            "enabled": channel.enabled,
            "min_severity": channel.min_severity.value,
        })
    return {"enabled": True, "air_gap_mode": settings.air_gap_mode, "channels": channels}


@app.post("/api/alerts/test")
def test_alert_channels(_: str | None = Depends(verify_api_key)):
    if not alert_engine:
        return {"error": "Alerting not enabled"}

    results = {}
    for channel in alert_engine.get_channels():
        if channel.enabled:
            results[channel.name] = channel.test_connection()
    return results


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "witness-governance"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
