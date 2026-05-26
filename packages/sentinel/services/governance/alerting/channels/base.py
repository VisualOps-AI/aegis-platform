from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    id: str
    timestamp: datetime
    severity: AlertSeverity
    event_type: str
    agent_id: str
    title: str
    message: str
    details: dict | None = None


class AlertChannel(ABC):
    def __init__(self, name: str, min_severity: AlertSeverity = AlertSeverity.LOW):
        self.name = name
        self.min_severity = min_severity
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    def disable(self) -> None:
        self._enabled = False

    def enable(self) -> None:
        self._enabled = True

    def should_send(self, alert: Alert) -> bool:
        if not self._enabled:
            return False

        severity_order = {
            AlertSeverity.LOW: 0,
            AlertSeverity.MEDIUM: 1,
            AlertSeverity.HIGH: 2,
            AlertSeverity.CRITICAL: 3,
        }
        return severity_order[alert.severity] >= severity_order[self.min_severity]

    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        pass
