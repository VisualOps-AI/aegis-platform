import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from fastapi import HTTPException, Request, status
from fastapi.security import APIKeyHeader

from config import get_settings
from logging_config import get_logger

settings = get_settings()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class RateLimitState:
    requests: list[float] = field(default_factory=list)

    def is_allowed(self, window_seconds: int, max_requests: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        self.requests = [t for t in self.requests if t > cutoff]

        if len(self.requests) >= max_requests:
            return False

        self.requests.append(now)
        return True

    @property
    def remaining(self) -> int:
        return max(0, settings.rate_limit_requests - len(self.requests))


class RateLimiter:
    def __init__(self):
        self._states: dict[str, RateLimitState] = defaultdict(RateLimitState)

    def check(self, key: str) -> tuple[bool, int]:
        state = self._states[key]
        allowed = state.is_allowed(
            settings.rate_limit_window_seconds,
            settings.rate_limit_requests,
        )
        return allowed, state.remaining

    def reset(self, key: str) -> None:
        if key in self._states:
            del self._states[key]


rate_limiter = RateLimiter()


async def verify_api_key(request: Request) -> str | None:
    logger = get_logger("overwatch", event_type="AUTH")

    if not settings.require_api_key:
        return None

    api_key = request.headers.get("X-API-Key")

    if not api_key:
        logger.warning("Missing API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
        )

    if api_key != settings.api_key:
        logger.warning("Invalid API key attempted")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )

    allowed, remaining = rate_limiter.check(api_key)
    if not allowed:
        logger.warning(f"Rate limit exceeded for API key")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {settings.rate_limit_window_seconds} seconds.",
            headers={"Retry-After": str(settings.rate_limit_window_seconds)},
        )

    request.state.rate_limit_remaining = remaining
    return api_key


def require_auth(func: Callable) -> Callable:
    async def wrapper(request: Request, *args, **kwargs):
        await verify_api_key(request)
        return await func(request, *args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper
