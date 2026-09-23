# Architecture

SentinelForge is an environment-aware detection layer that sits in front of, or next to, a SIEM.
The design keeps five concerns separate, and each one lives in its own service package under
`backend/app/services/`. API routes contain no business logic.

```
            discovery/          profiling/            rules/                     detection/            siem/
 collector ──► Inventory ──► EnvironmentProfile ──► RuleAssignment(generated) ──► Detection ──► Gateway ──► adapters
 (PS/WinRM,     (schema 1.0)   (types, techs,        (template × profile,          (engine +      (webhook, splunk,
  import)                       exposure, params,     validated, versioned)         pipeline)      elastic, plugins)
                                evidence)                                               ▲
                                                                     normalization/ ────┘
                                                                     enrichment/ (context + observables)
```

## Data flow

1. **Discover**: `services/discovery` gets an inventory from a demo template, an uploaded JSON document, or
   the bundled PowerShell collector, then validates it against `schemas/inventory.py`.
2. **Profile**: `services/profiling.build_profile()` derives:
   - `environment_type`: windows/linux, server/workstation, web_server, remote_access, container_host,
     kubernetes_node, database_server, domain_controller, domain_joined
   - `technologies`, each with **evidence** (for example, "service W3SVC present", "TCP 5985 listening")
   - `exposed_services`: non-loopback listeners, mapped port → well-known service → owning process
   - `risk_context`: remote access, internet-facing *indicator*, containerized, firewall profiles off,
     Defender real-time off
   - `parameters`: facts that templates can reference (`listening_ports`, `approved_images`, `container_ports`,
     `internal_cidrs`, `known_admins`)
   Each discovery adds a new profile row, so profile history is kept.
3. **Generate rules**: `services/rules.generate_rules()` evaluates every current template against the latest
   profile:
   - **Matching**: `applicability()` checks platform, `applies_when`, and the technology a platform implies
     (docker/kubernetes rules require that technology).
   - **Generation**: `resolve_template()` replaces `$profile.*` references with the host's values.
   - **Validation**: `compile_rule()` must succeed before a rule can become `active`.
   - **Persistence**: `RuleAssignment` rows record status (`active | disabled | not_applicable | rejected |
     superseded`), the reason, and the fully resolved rule. An unchanged assignment is kept. A changed one
     supersedes the old row, and an analyst's `disabled` decision survives regeneration.
4. **Detect**: `services/detection/pipeline.ingest()` normalizes, deduplicates, evaluates the host's active
   compiled rules (cached per environment), then enriches, persists, and forwards.
5. **Forward**: `services/siem/gateway.forward()` sends each detection document to the configured adapter and
   records a `DeliveryAttempt`. If delivery fails, the detection is kept locally.

## Rule lifecycle

```
DISCOVERED ─► PROFILE CREATED ─► RULE CANDIDATES ─► VALIDATED ─► ACTIVE ─► TRIGGERED ─► VERSIONED
 inventory     profile row        templates ×         compile      assignment   trigger_count   new (rule_id, version) row;
 stored                            applicability       gate         status        last_triggered  old rows marked superseded
```

Rule templates on disk are keyed by `(rule_id, version)` and are never overwritten. If a file's content changes
without a version bump, the change is refused and reported under `GET /rules/load-errors`.

## Storage

SQLAlchemy 2.0 models (`backend/app/models`). SQLite is the default. Setting `DATABASE_URL=postgresql+psycopg://…` selects PostgreSQL.
Portable `JSON` columns are used, with no database-specific SQL.

| Table | Purpose |
|---|---|
| `environments` | one row per hostname, holding the latest inventory |
| `environment_profiles` | profile history |
| `rules` | rule template versions (definition JSON + original YAML + hash) |
| `rule_assignments` | template × environment → status, reason, generated rule, trigger stats |
| `events` | normalized events (unmatched ones are kept only if `STORE_UNMATCHED_EVENTS=true`) |
| `detections` | `sentinelforge.detection.v1` documents plus indexed columns |
| `observables` | extracted observables per detection |
| `delivery_attempts` | every SIEM send, whether it succeeded or failed |
| `pipeline_counters` | monotonic metrics, independent of event retention |

SIEM integration settings are configuration rather than data. They come from environment variables, so there is no
`siem_integrations` table.

## Metrics

| Counter | Meaning |
|---|---|
| `events_received` | records submitted |
| `events_rejected` | failed normalization/validation |
| `events_duplicate` | event_id already processed |
| `events_evaluated` | ran through the engine |
| `events_matched` | matched at least one rule |
| `events_filtered` | evaluated but matched nothing, so not forwarded |
| `events_forwarded` | source events that left as one or more detections |
| `detections_created` | detection documents (one event can match several rules) |
| `siem_delivered` / `siem_failed` | adapter results |

`reduction_percentage = (events_received - events_forwarded) / events_received * 100`, computed over the
workload this instance actually processed.

## Extension points

`backend/app/plugins.py` holds one registry: `event_parsers`, `siem_adapters`, and `ioc_extractors`. The built-ins
register themselves there exactly the way plugins do. Rule packs are directories listed in `RULE_PATHS`. Collectors
are external producers of inventory schema 1.0. See [extending.md](extending.md).

## Observability

`app/core/logging.py` writes JSON lines. The main events are `discovery.started`, `discovery.completed`,
`profile.created`, `rules.loaded`, `rules.load_error`, `rules.generated`, `detection.matched`,
`event.batch_processed`, `siem.forwarded`, `siem.failed`, `plugin.loaded`, and `api.unhandled_error`.
