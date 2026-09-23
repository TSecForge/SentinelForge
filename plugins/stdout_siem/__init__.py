"""Example SentinelForge plugin: a SIEM adapter that writes each detection as one JSON line to stdout.

Useful when a log shipper (Fluent Bit, Vector, the Splunk UF, Elastic Agent) already tails the
container's stdout. Enable with:

    PLUGIN_PATHS=./plugins
    PLUGINS=stdout_siem
    SIEM_MODE=stdout

It also shows the other extension points (event parser, observable extractor).
"""

import json
import sys


class StdoutAdapter:
    name = "stdout"

    def __init__(self, settings):
        self.settings = settings

    def configured(self) -> bool:
        return True

    def target(self) -> str:
        return "stdout (JSON lines)"

    def send(self, doc: dict):
        sys.stdout.write(json.dumps({"sentinelforge": doc}, default=str) + "\n")
        sys.stdout.flush()
        return True, None, None


def parse_simple_csv(data: dict) -> dict:
    """Example parser for {"line": "host,event_type,user"} records."""
    host, event_type, user = (data.get("line", "") + ",,").split(",")[:3]
    return {"host": host, "event_type": event_type or "csv_event", "actor": {"user": user or None}}


def extract_ticket_ids(event: dict):
    """Example observable extractor: pull INC-12345 style ticket references from command lines."""
    import re

    text = (event.get("process") or {}).get("command_line") or ""
    return [("command_line", m, "plugin:ticket_ref") for m in re.findall(r"\bINC-\d{4,8}\b", text)]


def register(registry) -> None:
    registry.siem_adapters["stdout"] = StdoutAdapter
    registry.event_parsers["simple_csv"] = parse_simple_csv
    registry.ioc_extractors.append(extract_ticket_ids)
