"""Structured (JSON-lines) logging. Usage: log.info("detection.matched", rule_id=..., host=...)."""

import json
import logging
import sys
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class StructLogger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, event: str, **fields):
        self._log.log(level, event, extra={"fields": fields})

    def debug(self, event: str, **f): self._emit(logging.DEBUG, event, **f)
    def info(self, event: str, **f): self._emit(logging.INFO, event, **f)
    def warning(self, event: str, **f): self._emit(logging.WARNING, event, **f)
    def error(self, event: str, **f): self._emit(logging.ERROR, event, **f)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("sentinelforge")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    root.propagate = False


def get_logger(name: str) -> StructLogger:
    return StructLogger(f"sentinelforge.{name}")
