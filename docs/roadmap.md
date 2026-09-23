# Roadmap

| Version | Theme | Main work |
|---|---|---|
| **v1** (current MVP) | Agentless discovery + rule engine + simulated events | PowerShell/WinRM collector, profiler, Rule Writer, safe evaluator, normalization, observables, webhook/Splunk/Elastic, dashboard, demo mode |
| **v2** | Windows Event Forwarding | WEC subscription templates generated *from the profile* (only the channels and event IDs the active rules need), a WEF → JSON bridge, Sysmon config suggestions |
| **v3** | Linux / syslog | read-only SSH collector emitting inventory 1.0, syslog/journald ingestion, auditd parsing |
| **v4** | Docker / Kubernetes telemetry | Docker events stream consumer, Kubernetes audit webhook receiver, namespace/workload inventory through a least-privilege read-only service account |
| **v5** | Distributed collectors | collector registration with per-collector credentials/mTLS, a queue between ingest and detection, horizontal workers with shared threshold state |
| **v6** | Correlation | sequence rules (A then B within T on the same host/user), cross-host chains, suppression and deduplication windows |
| **v7** | Threat intelligence enrichment | local and offline feeds, MISP/STIX/TAXII lookups on observables, still reported as context rather than verdicts |
| **v8** | Detection-as-code | Git-backed rule packs, CI validation, per-rule test events (positive and negative), coverage reports against ATT&CK |
| **v9** | Multi-tenant enterprise | tenants, RBAC, SSO/OIDC, audit log, retention policies, Alembic migrations, HA PostgreSQL |

## Also planned

- An optional LLM assistant that explains why a rule applies, summarizes detections, and suggests detection ideas.
  It would stay out of the execution path. Anything it proposes would have to pass the same deterministic
  validation and human review, and the system must keep working without an API key.
- The RE2 regex engine for rule `re` operators.
- Profile drift alerts: new listening ports or technologies between discoveries.
- Batched SIEM delivery with a retry queue.
- Frontend tests (Vitest + Testing Library) and code splitting.
