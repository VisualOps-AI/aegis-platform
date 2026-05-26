import time
from dataclasses import dataclass
from enum import Enum
from threading import Lock

import httpx


class KillCheckFailMode(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass
class CacheEntry:
    is_killed: bool
    cached_at: float


class KillStatusCache:
    def __init__(self, ttl_seconds: float = 5.0):
        self._cache: dict[str, CacheEntry] = {}
        self._lock = Lock()
        self._ttl = ttl_seconds

    def get(self, agent_id: str) -> bool | None:
        with self._lock:
            entry = self._cache.get(agent_id)
            if entry is None:
                return None
            if time.time() - entry.cached_at > self._ttl:
                del self._cache[agent_id]
                return None
            return entry.is_killed

    def set(self, agent_id: str, is_killed: bool) -> None:
        with self._lock:
            self._cache[agent_id] = CacheEntry(is_killed=is_killed, cached_at=time.time())

    def invalidate(self, agent_id: str) -> None:
        with self._lock:
            self._cache.pop(agent_id, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


_cache = KillStatusCache()


async def check_kill_status(
    agent_id: str,
    overwatch_url: str,
    api_key: str | None = None,
    fail_mode: KillCheckFailMode = KillCheckFailMode.OPEN,
    timeout: float = 2.0,
    verify_tls: bool = True,
) -> tuple[bool, str | None]:
    cached = _cache.get(agent_id)
    if cached is not None:
        return cached, None

    try:
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key

        status_url = f"{overwatch_url.rstrip('/')}/api/agents/{agent_id}/status"

        async with httpx.AsyncClient(timeout=timeout, verify=verify_tls) as client:
            response = await client.get(status_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            is_killed = data.get("is_killed", False)
            _cache.set(agent_id, is_killed)
            return is_killed, data.get("kill_reason")

    except Exception:
        if fail_mode == KillCheckFailMode.CLOSED:
            return True, "Overwatch unreachable (fail-closed mode)"
        return False, None


def get_cache() -> KillStatusCache:
    return _cache
