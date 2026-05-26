import asyncio
import json
import uuid
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from config import get_settings
from injection_detector import InjectionDetector
from kill_cache import check_kill_status, KillCheckFailMode
from logging_config import setup_logging, get_logger
from models import ChatCompletionRequest, get_payload_size, sanitize_for_logging

settings = get_settings()
injection_detector = InjectionDetector(settings.injection_patterns_file) if settings.injection_detection_enabled else None

setup_logging(
    service_name="witness-sentinel",
    level=settings.log_level,
    json_output=settings.log_json,
)


def load_policy() -> dict:
    if not settings.policy_file.exists():
        return {"admin_override": False}
    try:
        return json.loads(settings.policy_file.read_text())
    except (json.JSONDecodeError, IOError):
        return {"admin_override": False}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(timeout=settings.http_timeout)
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="Witness Sentinel", lifespan=lifespan)


def check_dlp(payload: dict[str, Any]) -> str | None:
    messages = payload.get("messages", [])
    for msg in messages:
        content = msg.get("content", "").lower()
        for pattern in settings.dlp_patterns:
            if pattern in content:
                return pattern
    return None


def check_tools(payload: dict[str, Any]) -> str | None:
    tools = payload.get("tools", [])
    for tool in tools:
        if tool.get("type") == "function":
            func_name = tool.get("function", {}).get("name", "")
            if func_name in settings.forbidden_tools:
                return func_name

    functions = payload.get("functions", [])
    for func in functions:
        func_name = func.get("name", "")
        if func_name in settings.forbidden_tools:
            return func_name

    return None


def check_injection(payload: dict[str, Any]) -> dict | None:
    if not injection_detector:
        return None

    result = injection_detector.check_payload(payload)
    if result.is_injection and result.confidence >= settings.injection_block_threshold:
        return result.to_dict()
    return None


async def check_ml_injection(text: str, request_id: str) -> dict | None:
    """Query ML brain for injection detection. Fail-open on timeout/error."""
    if not settings.ml_brain_enabled:
        return None

    logger = get_logger("witness-sentinel", request_id=request_id)

    try:
        async with httpx.AsyncClient(timeout=settings.ml_brain_timeout) as client:
            response = await client.post(
                settings.ml_brain_analyze_url,
                json={"text": text},
            )
            response.raise_for_status()
            result = response.json()

            if result.get("is_threat", False):
                return {
                    "ml_score": result.get("score", 0),
                    "ml_threshold": result.get("threshold", settings.ml_brain_threshold),
                    "ml_model": result.get("model", "unknown"),
                }
            return None

    except httpx.TimeoutException:
        logger.warning("ML Brain timeout - falling back to heuristics (fail-open)")
        return None
    except httpx.HTTPStatusError as e:
        logger.warning(f"ML Brain error {e.response.status_code} - falling back to heuristics (fail-open)")
        return None
    except Exception as e:
        logger.warning(f"ML Brain connection failed: {e} - falling back to heuristics (fail-open)")
        return None


def extract_all_text(payload: dict[str, Any]) -> str:
    """Extract all user message text for ML analysis."""
    texts = []
    for msg in payload.get("messages", []):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(part.get("text", ""))
    return " ".join(texts)


def get_prompt_snippet(payload: dict[str, Any], max_len: int | None = None) -> str:
    if max_len is None:
        max_len = settings.prompt_snippet_max_length
    messages = payload.get("messages", [])
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return sanitize_for_logging(content, max_len)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        return sanitize_for_logging(part.get("text", ""), max_len)
    return ""


async def _send_to_overwatch(payload: dict) -> None:
    if not settings.overwatch_enabled:
        return
    try:
        headers = {}
        if settings.overwatch_api_key:
            headers["X-API-Key"] = settings.overwatch_api_key

        async with httpx.AsyncClient(
            timeout=settings.overwatch_timeout,
            verify=settings.overwatch_verify_tls,
        ) as client:
            await client.post(settings.overwatch_ingest_url, json=payload, headers=headers)
    except Exception:
        pass


def log_event(event_type: str, details: str, status_code: int, payload: dict[str, Any], request_id: str = "") -> None:
    prompt_snippet = get_prompt_snippet(payload)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    entry = {
        "timestamp": timestamp,
        "request_id": request_id,
        "event_type": event_type,
        "status_code": status_code,
        "details": details,
        "prompt_snippet": prompt_snippet,
    }

    logs = []
    if settings.log_file.exists():
        try:
            logs = json.loads(settings.log_file.read_text())
        except (json.JSONDecodeError, IOError):
            logs = []

    logs.append(entry)
    settings.log_file.write_text(json.dumps(logs, indent=2))

    overwatch_payload = {
        "agent_id": settings.agent_id,
        "event_type": event_type,
        "prompt_snippet": prompt_snippet,
        "risk_score": 100 if "BLOCK" in event_type else 0,
        "timestamp": datetime.now().isoformat(),
        "request_id": request_id,
    }
    try:
        asyncio.get_event_loop().create_task(_send_to_overwatch(overwatch_payload))
    except RuntimeError:
        pass


def log_request(payload: dict[str, Any], blocked: bool = False, reason: str = "", admin_override: bool = False, request_id: str = "") -> None:
    logger = get_logger("witness-sentinel", request_id=request_id)
    prompt_snippet = get_prompt_snippet(payload)

    if blocked:
        logger.extra["event_type"] = "BLOCKED"
        logger.warning(reason, extra={"prompt_snippet": prompt_snippet})
    elif admin_override:
        logger.extra["event_type"] = "ADMIN_OVERRIDE"
        logger.warning(reason, extra={"prompt_snippet": prompt_snippet})
    else:
        logger.extra["event_type"] = "REQUEST"
        logger.info(f"Intercepted request: {prompt_snippet}")


@app.post("/v1/chat/completions")
async def proxy_chat_completions(payload: dict[str, Any]) -> JSONResponse:
    request_id = str(uuid.uuid4())

    if settings.request_validation_enabled:
        payload_size = get_payload_size(payload)
        if payload_size > settings.max_payload_size_bytes:
            log_event("BLOCK_SIZE", f"Payload too large: {payload_size} bytes", 413, payload, request_id)
            return JSONResponse(
                content={"error": f"Payload too large ({payload_size} bytes). Maximum: {settings.max_payload_size_bytes} bytes.", "request_id": request_id},
                status_code=413,
            )

        try:
            ChatCompletionRequest.model_validate(payload)
        except ValidationError as e:
            errors = [f"{err['loc']}: {err['msg']}" for err in e.errors()[:3]]
            log_event("BLOCK_VALIDATION", f"Invalid request: {errors}", 400, payload, request_id)
            return JSONResponse(
                content={"error": "Invalid request format", "details": errors, "request_id": request_id},
                status_code=400,
            )

    if settings.kill_check_enabled and settings.overwatch_enabled:
        is_killed, kill_reason = await check_kill_status(
            agent_id=settings.agent_id,
            overwatch_url=settings.overwatch_base_url,
            api_key=settings.overwatch_api_key,
            fail_mode=KillCheckFailMode(settings.kill_check_fail_mode.value),
            timeout=settings.kill_check_timeout,
            verify_tls=settings.overwatch_verify_tls,
        )
        if is_killed:
            reason = kill_reason or "Agent has been disabled by administrator"
            log_event("BLOCK_KILLED", f"Agent killed: {reason}", 403, payload, request_id)
            return JSONResponse(
                content={
                    "error": "AGENT_DISABLED: This agent has been disabled by the security administrator.",
                    "reason": reason,
                    "request_id": request_id,
                },
                status_code=403,
            )

    policy = load_policy()
    admin_override = settings.admin_override_allowed and policy.get("admin_override", False)

    dlp_violation = check_dlp(payload)
    if dlp_violation:
        log_request(payload, blocked=True, reason=f"DLP violation: '{dlp_violation}' detected", request_id=request_id)
        log_event("BLOCK_DLP", f"Blocked '{dlp_violation}' pattern", 400, payload, request_id)
        return JSONResponse(
            content={"error": "Security Alert: Sensitive data (API Key/Password) detected. Request blocked by Aegis.", "request_id": request_id},
            status_code=400,
        )

    tool_violation = check_tools(payload)
    if tool_violation:
        if admin_override:
            log_request(payload, admin_override=True, reason=f"Tool '{tool_violation}' allowed via override", request_id=request_id)
            log_event("ALLOW (Admin Override)", f"Tool '{tool_violation}' allowed via admin override", 200, payload, request_id)
        else:
            log_request(payload, blocked=True, reason=f"Tool violation: '{tool_violation}' forbidden", request_id=request_id)
            log_event("BLOCK_TOOL", f"Blocked '{tool_violation}' tool", 403, payload, request_id)
            return JSONResponse(
                content={"error": f"Security Alert: Unauthorized Tool Use ('{tool_violation}') blocked by Aegis.", "request_id": request_id},
                status_code=403,
            )

    # Run heuristic and ML checks in parallel
    user_text = extract_all_text(payload)
    heuristic_result = check_injection(payload)
    ml_result = await check_ml_injection(user_text, request_id) if user_text else None

    # ML detection takes precedence if available
    if ml_result:
        log_request(payload, blocked=True, reason=f"ML injection detected (score: {ml_result['ml_score']:.2f})", request_id=request_id)
        log_event(
            "BLOCK_INJECTION_ML",
            f"Blocked by ML model (score: {ml_result['ml_score']:.4f}, threshold: {ml_result['ml_threshold']}, model: {ml_result['ml_model']})",
            403,
            payload,
            request_id,
        )
        return JSONResponse(
            content={
                "error": "Security Alert: Potential prompt injection detected. Request blocked by Aegis.",
                "details": {
                    "detection": "ml",
                    "score": ml_result["ml_score"],
                    "model": ml_result["ml_model"],
                },
                "request_id": request_id,
            },
            status_code=403,
        )

    # Fall back to heuristic detection
    if heuristic_result:
        categories = ", ".join(heuristic_result["matched_categories"])
        log_request(payload, blocked=True, reason=f"Injection detected: {categories}", request_id=request_id)
        log_event(
            "BLOCK_INJECTION",
            f"Blocked injection attempt (confidence: {heuristic_result['confidence']}, severity: {heuristic_result['severity']}, categories: {categories})",
            403,
            payload,
            request_id,
        )
        return JSONResponse(
            content={
                "error": "Security Alert: Potential prompt injection detected. Request blocked by Aegis.",
                "details": {
                    "detection": "heuristic",
                    "severity": heuristic_result["severity"],
                    "categories": heuristic_result["matched_categories"],
                },
                "request_id": request_id,
            },
            status_code=403,
        )

    if not tool_violation:
        log_request(payload, request_id=request_id)
        log_event("ALLOW", "Request forwarded to OpenAI", 200, payload, request_id)
    payload["stream"] = False

    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = await app.state.http_client.post(
            str(settings.openai_api_url),
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return JSONResponse(content={"error": e.response.text}, status_code=e.response.status_code)
    except httpx.RequestError as e:
        return JSONResponse(content={"error": f"Error forwarding request: {e}"}, status_code=502)

    return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "witness-sentinel"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
