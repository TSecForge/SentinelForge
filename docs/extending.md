# Extending and customizing SentinelForge

SentinelForge is meant to be forked, rebranded, and extended without editing the core engine.

```
                 SENTINELFORGE
                       │
          ┌────────────┴────────────┐
      Core engine              Extension layer
  (discovery, profiler,     ┌───────┼────────┬──────────┐
   rule writer, engine,   Rule packs  Plugins  Collectors  Branding
   pipeline, gateway)
```

## Branding (no code changes)

| Variable | Effect |
|---|---|
| `PROJECT_NAME` | product name in the sidebar and browser title |
| `PROJECT_DESCRIPTION` | dashboard subtitle |
| `ORGANIZATION_NAME` | shown under the product name |
| `ORGANIZATION_LOGO` | `https://…` or `/path` served by the frontend (other schemes are ignored) |
| `PRIMARY_BRAND_COLOR` | hex color used for accents (validated client-side) |
| `DASHBOARD_TITLE` | dashboard heading |
| `FOOTER_TEXT` | extra footer line |

When the branding differs from the default, the footer shows "Powered by SentinelForge", and the About page
shows "<your name> is customized from SentinelForge" along with the upstream metadata (name, original creator,
license). That metadata comes from `GET /api/v1/about → upstream` and is not configurable. It exists so the
software's origin stays discoverable, as the Apache-2.0 NOTICE mechanism intends. You are free to change how
prominent it is in your own UI. The license requires you to keep the notices in your distribution, not in
your product's UI.

## Rule packs

```env
RULE_PATHS=builtin,./custom-rules,/opt/acme/rules    # builtin = packs shipped in the sentinelforge package
```

Every `*.yml` / `*.yaml` under these directories is loaded recursively. Use `source: organization`, `user`, or
`community` and your own `author`. `custom-rules/example-org/ORG-WIN-001-*.yml` is a working example. Rule IDs
must be unique per version across all packs. See [detection-engine.md](detection-engine.md).

## Plugins

```env
PLUGIN_PATHS=./plugins          # directories added to the import path
PLUGINS=stdout_siem,acme_syslog # module names to load
```

A plugin is a Python module or package with a `register(registry)` function:

```python
def register(registry):
    registry.siem_adapters["syslog"] = SyslogAdapter        # class(settings): name, configured(), target(), send(doc)
    registry.event_parsers["zeek_conn"] = parse_zeek_conn   # dict -> fields of the normalized event
    registry.ioc_extractors.append(extract_ticket_ids)      # event dict -> [(type, value, context)]
```

- A **SIEM adapter** is selected with `SIEM_MODE=<name>`.
- An **event parser** is registered under a source name and receives `data` from `{"source": "<name>", "data": {...}}`.
  It must return a dict with at least `host` and `event_type`, and the result is validated against the normalized
  event schema. You can register a new source name (for example `simple_csv`) or replace a built-in parser.
  Events for a source with no registered parser are counted as rejected.
- An **observable extractor** returns extra observables. Exceptions are swallowed, so a plugin bug can't drop a detection.

Plugins are trusted code. Only the operator can enable them (through environment variables), never the API. A plugin
that fails to import is logged (`plugin.failed`) and skipped. `GET /api/v1/about` lists the loaded plugins.

`plugins/stdout_siem/` shows all three extension points and is covered by `backend/tests/test_plugins.py`.

## Collectors

Collectors are external. Anything that produces inventory schema 1.0 (`schemas/inventory.schema.json`) can
feed SentinelForge through `POST /api/v1/discovery/run {"mode":"import"}` or `sentinelforge-server discovery --file ... --save`.
That covers Ansible facts converters, an osquery export, a Linux shell script, or a CMDB export.

## Dashboard

The frontend is a plain React + Tailwind app. Pages live in `frontend/src/pages`, shared widgets in
`frontend/src/components`, and all API calls go through `frontend/src/services/api.ts`. New widgets can use
`GET /api/v1/dashboard/summary` or add a backend route that calls the existing services.

There is no runtime widget plugin system. It would add complexity without a current use case. Fork and add a component.
