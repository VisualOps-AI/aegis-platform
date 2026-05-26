import httpx

from .base import Alert, AlertChannel, AlertSeverity


class WebhookChannel(AlertChannel):
    def __init__(
        self,
        webhook_url: str,
        min_severity: AlertSeverity = AlertSeverity.LOW,
        timeout: float = 5.0,
        headers: dict | None = None,
    ):
        super().__init__(name="webhook", min_severity=min_severity)
        self.webhook_url = webhook_url
        self.timeout = timeout
        self.headers = headers or {}

    def _build_payload(self, alert: Alert) -> dict:
        return {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "event_type": alert.event_type,
            "agent_id": alert.agent_id,
            "title": alert.title,
            "message": alert.message,
            "details": alert.details,
            "source": "aegis-overwatch",
        }

    async def send(self, alert: Alert) -> bool:
        try:
            payload = self._build_payload(alert)
            headers = {"Content-Type": "application/json", **self.headers}

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
                )
                return response.status_code < 400
        except Exception:
            return False

    def test_connection(self) -> bool:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.webhook_url,
                    json={"test": True, "source": "aegis-overwatch"},
                    headers={"Content-Type": "application/json", **self.headers},
                )
                return response.status_code < 400
        except Exception:
            return False
