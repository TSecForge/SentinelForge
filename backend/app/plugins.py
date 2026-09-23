"""Extension registry. The core engine only talks to these tables; built-ins and plugins register the same way.

A plugin is a Python package in a directory listed in PLUGIN_PATHS, named in PLUGINS, exposing:

    def register(registry):
        registry.event_parsers["syslog"] = parse_syslog          # raw dict -> normalized dict
        registry.siem_adapters["stdout"] = StdoutAdapter          # class(settings) with .name and .send(doc)
        registry.ioc_extractors.append(extract_custom)            # event dict -> [(type, value, context)]

Plugins are code: only the operator (via environment variables) can enable them, never the API.
Collectors are external by design - anything that emits inventory schema 1.0 can POST /discovery/run (mode=import).
"""

import importlib
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("plugins")


@dataclass
class Registry:
    event_parsers: dict[str, Callable[[dict], dict]] = field(default_factory=dict)
    siem_adapters: dict[str, Callable] = field(default_factory=dict)
    ioc_extractors: list[Callable[[dict], list[tuple[str, str, str]]]] = field(default_factory=list)
    loaded_plugins: list[str] = field(default_factory=list)


registry = Registry()


def load_plugins() -> None:
    s = get_settings()
    for path in s.split(s.plugin_paths):
        if path not in sys.path:
            sys.path.append(path)
    for name in s.split(s.plugins):
        if name in registry.loaded_plugins:
            continue
        try:
            importlib.import_module(name).register(registry)
            registry.loaded_plugins.append(name)
            log.info("plugin.loaded", plugin=name)
        except Exception as e:  # a broken plugin must not take the platform down
            log.error("plugin.failed", plugin=name, error=str(e))
