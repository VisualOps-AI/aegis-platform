import httpx

from .base import Alert, AlertChannel, AlertSeverity


class PagerDutyChannel(AlertChannel):
    PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    SEVERITY_MAP = {
        AlertSeverity.LOW: "info",
        AlertSeverity.MEDIUM: "warning",
        AlertSeverity.HIGH: "error",
        AlertSeverity.CRITICAL: "critical",
    }

    def __init__(
        self,
        routing_key: str,
        min_severity: AlertSeverity = AlertSeverity.HIGH,
        timeout: float = 5.0,
    ):
        super().__init__(name="pagerduty", min_severity=min_severity)
        self.routing_key = routing_key
        self.timeout = timeout

    def _build_payload(self, alert: Alert) -> dict:
        return {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"aegis-{alert.agent_id}-{alert.event_type}-{alert.id}",
            "payload": {
                "summary": f"[{alert.severity.value.upper()}] {alert.title}",
                "source": f"aegis-agent-{alert.agent_id}",
                "severity": self.SEVERITY_MAP[alert.severity],
                "timestamp": alert.timestamp.isoformat(),
                "component": "aegis-overwatch",
                "group": alert.agent_id,
                "class": alert.event_type,
                "custom_details": {
                    "message": alert.message,
                    "agent_id": alert.agent_id,
                    "event_type": alert.event_type,
                    **(alert.details or {}),
                },
            },
        }

    async def send(self, alert: Alert) -> bool:
        try:
            payload = self._build_payload(alert)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.PAGERDUTY_EVENTS_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                return response.status_code in (200, 201, 202)
        except Exception:
            return False

    def test_connection(self) -> bool:
        try:
            test_payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "dedup_key": "aegis-connection-test",
                "payload": {
                    "summary": "Aegis Overwatch connection test",
                    "source": "aegis-overwatch",
                    "severity": "info",
                },
            }

            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.PAGERDUTY_EVENTS_URL,
                    json=test_payload,
                    headers={"Content-Type": "application/json"},
                )
                return response.status_code in (200, 201, 202)
        except Exception:
            return False
