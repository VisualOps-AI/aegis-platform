import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock

from .channels.base import Alert, AlertChannel, AlertSeverity


@dataclass
class RateLimitEntry:
    count: int = 0
    window_start: float = field(default_factory=time.time)


class AlertEngine:
    def __init__(
        self,
        rate_limit_per_agent: int = 5,
        rate_limit_window_seconds: int = 60,
        air_gap_mode: bool = False,
    ):
        self._channels: list[AlertChannel] = []
        self._rate_limits: dict[str, RateLimitEntry] = {}
        self._rate_limit_lock = Lock()
        self._rate_limit_per_agent = rate_limit_per_agent
        self._rate_limit_window = rate_limit_window_seconds
        self._air_gap_mode = air_gap_mode

    def add_channel(self, channel: AlertChannel) -> None:
        if self._air_gap_mode and channel.name in ("slack", "pagerduty"):
            channel.disable()
        self._channels.append(channel)

    def remove_channel(self, name: str) -> None:
        self._channels = [c for c in self._channels if c.name != name]

    def get_channels(self) -> list[AlertChannel]:
        return self._channels.copy()

    def set_air_gap_mode(self, enabled: bool) -> None:
        self._air_gap_mode = enabled
        for channel in self._channels:
            if channel.name in ("slack", "pagerduty"):
                if enabled:
                    channel.disable()
                else:
                    channel.enable()

    def _check_rate_limit(self, agent_id: str) -> bool:
        with self._rate_limit_lock:
            now = time.time()
            entry = self._rate_limits.get(agent_id)

            if entry is None:
                self._rate_limits[agent_id] = RateLimitEntry(count=1, window_start=now)
                return True

            if now - entry.window_start > self._rate_limit_window:
                self._rate_limits[agent_id] = RateLimitEntry(count=1, window_start=now)
                return True

            if entry.count >= self._rate_limit_per_agent:
                return False

            entry.count += 1
            return True

    def create_alert(
        self,
        severity: AlertSeverity,
        event_type: str,
        agent_id: str,
        title: str,
        message: str,
        details: dict | None = None,
    ) -> Alert:
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=severity,
            event_type=event_type,
            agent_id=agent_id,
            title=title,
            message=message,
            details=details,
        )

    async def send_alert(self, alert: Alert) -> dict[str, bool]:
        if not self._check_rate_limit(alert.agent_id):
            return {"rate_limited": True}

        results = {}
        tasks = []

        for channel in self._channels:
            if channel.should_send(alert):
                tasks.append((channel.name, channel.send(alert)))

        if tasks:
            for name, coro in tasks:
                try:
                    results[name] = await coro
                except Exception:
                    results[name] = False

        return results

    async def trigger(
        self,
        severity: AlertSeverity,
        event_type: str,
        agent_id: str,
        title: str,
        message: str,
        details: dict | None = None,
    ) -> dict[str, bool]:
        alert = self.create_alert(
            severity=severity,
            event_type=event_type,
            agent_id=agent_id,
            title=title,
            message=message,
            details=details,
        )
        return await self.send_alert(alert)

    def trigger_sync(
        self,
        severity: AlertSeverity,
        event_type: str,
        agent_id: str,
        title: str,
        message: str,
        details: dict | None = None,
    ) -> None:
        alert = self.create_alert(
            severity=severity,
            event_type=event_type,
            agent_id=agent_id,
            title=title,
            message=message,
            details=details,
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.send_alert(alert))
            else:
                loop.run_until_complete(self.send_alert(alert))
        except RuntimeError:
            asyncio.run(self.send_alert(alert))


# Re-export for convenience
__all__ = ["AlertEngine", "Alert", "AlertSeverity"]
