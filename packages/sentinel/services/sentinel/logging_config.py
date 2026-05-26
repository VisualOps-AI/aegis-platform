import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    def __init__(self, service_name: str = "witness-sentinel"):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "message": record.getMessage(),
        }

        if hasattr(record, "request_id") and record.request_id:
            log_data["request_id"] = record.request_id

        if hasattr(record, "event_type") and record.event_type:
            log_data["event_type"] = record.event_type

        if hasattr(record, "extra_data") and record.extra_data:
            log_data.update(record.extra_data)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class ConsoleFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[95m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        request_id = getattr(record, "request_id", "")
        req_id_str = f" [{request_id[:8]}]" if request_id else ""

        event_type = getattr(record, "event_type", "")
        event_str = f" [{event_type}]" if event_type else ""

        return f"{color}[{timestamp}]{req_id_str}{event_str} {record.getMessage()}{self.RESET}"


class StructuredLogger(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        extra = kwargs.get("extra", {})
        extra["request_id"] = self.extra.get("request_id", "")
        extra["event_type"] = self.extra.get("event_type", "")
        extra["extra_data"] = self.extra.get("extra_data", {})
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging(
    service_name: str = "witness-sentinel",
    level: str = "INFO",
    json_output: bool = False,
) -> logging.Logger:
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if json_output:
        handler.setFormatter(JSONFormatter(service_name))
    else:
        handler.setFormatter(ConsoleFormatter())

    logger.addHandler(handler)
    logger.propagate = False

    return logger


def get_logger(
    service_name: str = "witness-sentinel",
    request_id: str = "",
    event_type: str = "",
    **extra_data: Any,
) -> StructuredLogger:
    logger = logging.getLogger(service_name)
    return StructuredLogger(
        logger,
        {
            "request_id": request_id,
            "event_type": event_type,
            "extra_data": extra_data,
        },
    )
