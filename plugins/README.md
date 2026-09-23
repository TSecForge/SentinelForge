# Plugins

A plugin is a Python module or package exposing `register(registry)`. It can add:

| Registry | Purpose | Selected by |
|---|---|---|
| `registry.siem_adapters[name]` | where detections are sent | `SIEM_MODE=name` |
| `registry.event_parsers[source]` | how a raw record becomes a normalized event | `{"source": "<source>", ...}` in `/events` |
| `registry.ioc_extractors` (list) | extra observables from an event | always applied |

Enable plugins with:

```env
PLUGIN_PATHS=../plugins
PLUGINS=stdout_siem
SIEM_MODE=stdout
```

`stdout_siem/` is a complete example: a SIEM adapter that writes JSON lines to stdout (handy with a log shipper),
a `simple_csv` parser, and an observable extractor. It is exercised by `backend/tests/test_plugins.py`.

Plugins are trusted code. Only the operator can enable them (through environment variables), never the API. A
plugin that fails to import is logged and skipped. See [docs/extending.md](../docs/extending.md).
