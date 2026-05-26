import sqlite3
from pathlib import Path

from .base import Alert, AlertChannel, AlertSeverity


class LocalChannel(AlertChannel):
    def __init__(
        self,
        db_path: Path,
        min_severity: AlertSeverity = AlertSeverity.LOW,
    ):
        super().__init__(name="local", min_severity=min_severity)
        self.db_path = db_path

    async def send(self, alert: Alert) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO alerts (id, timestamp, severity, event_type, agent_id, title, message, details, channel)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.id,
                        alert.timestamp.isoformat(),
                        alert.severity.value,
                        alert.event_type,
                        alert.agent_id,
                        alert.title,
                        alert.message,
                        str(alert.details) if alert.details else None,
                        self.name,
                    ),
                )
                conn.commit()
            return True
        except Exception:
            return False

    def test_connection(self) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("SELECT 1 FROM alerts LIMIT 1")
            return True
        except Exception:
            return False
