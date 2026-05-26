import httpx

from .base import Alert, AlertChannel, AlertSeverity


class SlackChannel(AlertChannel):
    SEVERITY_COLORS = {
        AlertSeverity.LOW: "#36a64f",
        AlertSeverity.MEDIUM: "#ff9800",
        AlertSeverity.HIGH: "#f44336",
        AlertSeverity.CRITICAL: "#9c27b0",
    }

    SEVERITY_EMOJI = {
        AlertSeverity.LOW: ":information_source:",
        AlertSeverity.MEDIUM: ":warning:",
        AlertSeverity.HIGH: ":rotating_light:",
        AlertSeverity.CRITICAL: ":skull:",
    }

    def __init__(
        self,
        webhook_url: str,
        channel: str | None = None,
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
        timeout: float = 5.0,
    ):
        super().__init__(name="slack", min_severity=min_severity)
        self.webhook_url = webhook_url
        self.channel = channel
        self.timeout = timeout

    def _build_payload(self, alert: Alert) -> dict:
        emoji = self.SEVERITY_EMOJI[alert.severity]
        color = self.SEVERITY_COLORS[alert.severity]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {alert.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.value.upper()}"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n{alert.agent_id}"},
                    {"type": "mrkdwn", "text": f"*Event:*\n{alert.event_type}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": alert.message},
            },
        ]

        if alert.details:
            details_text = "\n".join(f"• {k}: {v}" for k, v in alert.details.items())
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n{details_text}"},
            })

        payload = {
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if self.channel:
            payload["channel"] = self.channel

        return payload

    async def send(self, alert: Alert) -> bool:
        try:
            payload = self._build_payload(alert)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                )
                return response.status_code == 200
        except Exception:
            return False

    def test_connection(self) -> bool:
        try:
            test_payload = {
                "text": ":white_check_mark: Aegis Overwatch connection test successful!",
            }
            if self.channel:
                test_payload["channel"] = self.channel

            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.webhook_url, json=test_payload)
                return response.status_code == 200
        except Exception:
            return False
