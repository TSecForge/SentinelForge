"""Extension registry shared by the library and the SentinelForge server.

Built-in parsers, SIEM adapters and observable extractors register here exactly as plugins do:

    from sentinelforge.registry import registry
    registry.event_parsers["zeek_conn"] = parse_zeek_conn    # raw dict -> normalized-event fields
    registry.ioc_extractors.append(extract_ticket_ids)       # event dict -> [(type, value, context)]
    registry.siem_adapters["syslog"] = SyslogAdapter          # used by the server's SIEM gateway
"""

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Registry:
    event_parsers: dict[str, Callable[[dict], dict]] = field(default_factory=dict)
    siem_adapters: dict[str, Callable] = field(default_factory=dict)
    ioc_extractors: list[Callable[[dict], list[tuple[str, str, str]]]] = field(default_factory=list)
    loaded_plugins: list[str] = field(default_factory=list)


registry = Registry()
