"""Event-style structured logging on top of the stdlib `logging` module.

    log = get_logger("rules"); log.info("rules.loaded", total=32)

The library only emits records on the "sentinelforge.*" loggers; the host application decides formatting.
"""

import logging


class StructLogger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, event: str, **fields):
        self._log.log(level, event, extra={"fields": fields})

    def debug(self, event: str, **f): self._emit(logging.DEBUG, event, **f)
    def info(self, event: str, **f): self._emit(logging.INFO, event, **f)
    def warning(self, event: str, **f): self._emit(logging.WARNING, event, **f)
    def error(self, event: str, **f): self._emit(logging.ERROR, event, **f)


def get_logger(name: str) -> StructLogger:
    return StructLogger(f"sentinelforge.{name}")
