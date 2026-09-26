# Integrations: plugging SentinelForge into an existing log pipeline

SentinelForge doesn't need its own agent. Point the shipper you already run at the server's ingest endpoint:

```
POST /api/v1/ingest/{source}[?host=NAME]
     source = windows | linux | docker | kubernetes | generic | <plugin parser>
     body   = JSON array, one JSON object, {"events": [...]}, a Kubernetes audit EventList, or NDJSON
     auth   = X-API-Key: <API_KEY>   or   Authorization: Bearer <API_KEY>
```

`?host=` fills in the hostname for records that don't carry one, such as Docker events or a Kubernetes cluster's audit log.
The response reports `received / accepted / rejected / matched / detections`, and detections continue to your SIEM
through the configured SIEM gateway.

| Telemetry | Shipper | Config |
|---|---|---|
| Windows Security, System, Sysmon | Winlogbeat → Logstash | [`winlogbeat/winlogbeat.yml`](winlogbeat/winlogbeat.yml), [`logstash/sentinelforge.conf`](logstash/sentinelforge.conf) |
| Linux sshd / journald, Kubernetes audit file | Fluent Bit | [`fluent-bit/fluent-bit.conf`](fluent-bit/fluent-bit.conf) |
| Linux journald, Kubernetes audit file | Vector | [`vector/vector.yaml`](vector/vector.yaml) |
| Kubernetes API audit (no shipper) | kube-apiserver audit webhook | [`kubernetes/`](kubernetes/) |
| Docker Engine events (no shipper) | `sentinelforge forward` (library CLI) | [`docker/`](docker/) |

## Without a server

The library can evaluate records inside your own pipeline, with no API or database:

```bash
pip install sentinelforge-detect
sentinelforge evaluate --source windows --inventory host.json events.ndjson > detections.ndjson
```

```python
from sentinelforge import Engine
engine = Engine.from_paths(["builtin", "./org-rules"], inventory="host.json")
detections = engine.process({"source": "windows", "data": record})
```

## Status

The record shapes these configs produce are covered by tests in `backend/tests/test_ingest.py`: Winlogbeat/ECS
Windows events, Fluent Bit syslog/systemd records, Vector journald records, NDJSON Docker events, and Kubernetes
`EventList` batches. The configuration files themselves are **reference configs**. They follow each tool's documented
options, but CI does not run the shippers end-to-end. Please open an issue if a config needs adjusting for your version.

Tips:
- Filter at the shipper. Forward only the event IDs and units the active rules use (the configs do this). That is
  where most of the volume reduction happens, before SentinelForge's own filtering.
- Put TLS in front of SentinelForge and set `API_KEY`. Every config reads the key from the `SENTINELFORGE_API_KEY`
  environment variable rather than hard-coding it.
