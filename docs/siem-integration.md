# SIEM integration

The gateway (`backend/app/services/siem/gateway.py`) sends every detection document to one adapter, chosen by
`SIEM_MODE`, and records a `DeliveryAttempt` with success, status code, latency, and error text.
A failed delivery never loses a detection. It stays in the local store with `delivery_status=failed`.

## Payload: `sentinelforge.detection.v1`

Schema: `schemas/detection-event.schema.json`. Example (from a simulated run): `sample-data/detections/example-detection.json`.

```json
{
  "schema": "sentinelforge.detection.v1",
  "detection_id": "det-…",
  "timestamp": "2026-09-23T10:22:11Z",
  "host": "WEB-SRV-01",
  "rule": {"id": "DET-WIN-001", "name": "Office Application Spawning PowerShell", "version": "1.0", "source": "builtin", "author": "Sujhal Gurav"},
  "severity": "high",
  "confidence": 0.9,
  "confidence_basis": "rule fidelity 'high' = 0.9",
  "mitre": {"tactic": "execution", "technique": "T1059.001"},
  "observables": [{"type": "process", "value": "powershell.exe", "context": "process.name"}],
  "evidence": {"process.name": "powershell.exe", "process.parent_name": "winword.exe"},
  "context": {"environment_id": 1, "technologies": ["IIS", "..."], "rule_selected_because": "..."},
  "source": {"type": "windows", "event_id": "…", "raw_reference": "Microsoft-Windows-Sysmon/Operational/1"},
  "simulated": true,
  "event": { "...normalized event..." }
}
```

`simulated: true` is always set for demo data. Filter on it in the SIEM.

## Generic webhook

```env
SIEM_MODE=webhook
WEBHOOK_URL=https://soar.example.net/hooks/sentinelforge
WEBHOOK_AUTH_HEADER=Bearer <token>        # optional, sent as the Authorization header
```

Each document is POSTed as JSON. Redirects are not followed.

**Built-in receiver for demos:** `WEBHOOK_URL=http://127.0.0.1:8000/api/v1/siem/events`. The last 200 documents
are kept in memory and shown on the SIEM page (`GET /api/v1/siem/events`).

## Splunk HTTP Event Collector

```env
SIEM_MODE=splunk
SPLUNK_HEC_URL=https://splunk.example.net:8088/services/collector/event
SPLUNK_HEC_TOKEN=<hec token>
SPLUNK_INDEX=security            # optional; the token's default index is used otherwise
SPLUNK_SOURCE=sentinelforge
SPLUNK_VERIFY_TLS=true
```

Body: `{"time": <epoch>, "host": "<host>", "source": "...", "sourcetype": "sentinelforge:detection", "index": "...", "event": <detection>}`
with header `Authorization: Splunk <token>`.

## Elasticsearch / OpenSearch

```env
SIEM_MODE=elastic
ELASTIC_URL=https://es.example.net:9200
ELASTIC_API_KEY=<base64 id:key>
ELASTIC_INDEX=sentinelforge-detections
```

`POST {ELASTIC_URL}/{ELASTIC_INDEX}/_doc` with `Authorization: ApiKey …`. The document gets an `@timestamp`.
OpenSearch accepts the same index API. Use a reverse proxy or plugin adapter if you need basic auth or SigV4.

## Status and testing

- `GET /api/v1/siem/status` returns mode, whether the adapter is configured, the **redacted** target (no userinfo or query
  string), delivered/failed counts, last success, last error, and recent attempts.
- `POST /api/v1/siem/test` sends a `sentinelforge.test.v1` document.

Tokens are `SecretStr` values read from the environment. They are never logged, returned, or stored in the database.

## Adding an adapter

Write a class with `name`, `configured()`, `target()`, and `send(doc) -> (ok, status_code, error)`, then register it
from a plugin (`registry.siem_adapters["myadapter"] = MyAdapter`). Select it with `SIEM_MODE=myadapter`.
`plugins/stdout_siem` is a complete example. HTTP adapters can subclass `HttpAdapter` and implement only
`build(doc) -> (url, headers, body)`.

Batching is not implemented. Each detection is one request, which is fine for detection volumes but not for
raw telemetry.
