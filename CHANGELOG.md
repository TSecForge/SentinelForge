# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/). While the
major version is 0, minor versions may change APIs.

## [0.2.0] - 2026-09-26

SentinelForge can now be used as an add-on in other people's pipelines, not only as a standalone app.

### Added
- **`sentinelforge-detect` Python package** (`pip install sentinelforge-detect`, import `sentinelforge`). It contains the
  detection core: schemas, safe rule evaluator, environment selection, normalization, profiling, enrichment, rule
  testing and ATT&CK coverage. The built-in rule packs ship inside the wheel. The only dependencies are Pydantic and PyYAML.
- `Engine` API for embedding detection in your own code (`Engine.from_paths([...], inventory=...)`, `process()`).
- Library CLI `sentinelforge`: `rules validate`, `rules test`, `coverage export`, `profile`, `evaluate` (offline,
  NDJSON in, detections out), and `forward` (stream records to a server).
- **GitHub Action** (`uses: TSecForge/SentinelForge@v0.2.0`) that validates and tests *your* rule repository and
  writes an ATT&CK coverage summary. Example repository in `examples/rule-repo/`.
- **Shipper ingest endpoint** `POST /api/v1/ingest/{source}` accepting JSON arrays, `{"events": [...]}`, NDJSON and
  Kubernetes audit `EventList` batches, with `?host=` for sources without hostnames.
- Parsers for Winlogbeat/ECS Windows events, Fluent Bit, Vector and journald Linux records.
- Reference configs in `integrations/`: Winlogbeat → Logstash, Fluent Bit, Vector, the Kubernetes audit webhook
  (with an audit policy that never logs secret contents), and Docker events via `sentinelforge forward` (with a systemd unit).
- `Authorization: Bearer <API_KEY>` accepted alongside `X-API-Key`.
- 7 new rules (event log cleared, Kerberos RC4 service tickets, Defender tampering, Run-key persistence,
  discovery bursts, `curl | sh`, Kubernetes secrets listing), bringing the total to 32 across 24 ATT&CK techniques.
- Detection-as-code: per-rule match / no-match tests for every rule, coverage report generation, and CI.
- Release workflow: tagged versions build the wheel and sdist, attach them to a GitHub release and (once enabled)
  publish to PyPI through trusted publishing.

### Changed
- The server (`backend/`, distribution `sentinelforge-server`) is now built on the library. Its CLI is
  `sentinelforge-server` (discovery, demo, simulation, schema export). Rule tooling moved to `sentinelforge`.
- `RULE_PATHS` accepts `builtin` for the packaged rules. The default is now `builtin,<repo>/custom-rules`.
- Missing rule paths are reported as load errors instead of being skipped silently.

## [0.1.0] - 2026-09-23

Initial MVP: agentless Windows discovery, environment profiler, Rule Writer engine, deterministic detection,
observable extraction, SIEM gateway (webhook, Splunk HEC, Elastic), demo mode and dashboard.

[0.2.0]: https://github.com/TSecForge/SentinelForge/releases/tag/v0.2.0
[0.1.0]: https://github.com/TSecForge/SentinelForge/commit/7bcc524
