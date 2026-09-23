# Threat model

**Scope.** The SentinelForge MVP: the FastAPI backend, the PowerShell collector, rule packs, SIEM adapters, and the
dashboard.

**Assets.**
- integrity of detections, since missed or forged detections cause harm
- confidentiality of inventories, which map the attack surface
- SIEM credentials
- the availability of the pipeline

**Trust boundaries.**
1. Collector output entering the platform
2. Events entering the API
3. Rule files entering the rule store
4. API clients (UI and scripts)
5. Outbound connections to the SIEM
6. The host that runs the API when live discovery is enabled

| # | Threat | Impact | Mitigations in the MVP | Residual risk / next step |
|---|---|---|---|---|
| 1 | **Malicious discovery target**: a compromised host returns crafted inventory (huge payloads, fake services, injection strings) | DoS, a misleading profile, rules disabled by fake "absence" | Strict Pydantic schema. Unknown keys dropped, strings truncated, list sizes bounded, 50 MB cap, hostname pattern. Inventory is data only, never executed or templated. React escapes output. Evidence is shown for every conclusion. | A lying host can hide technologies and cause rules to be marked not applicable. Compare with independent sources (CMDB, network scans) and alert on profile drift. |
| 2 | **Compromised endpoint** tampers with telemetry or the collector | Blind spots | Discovery is read-only and leaves nothing behind. Hosts without profiles still get baseline rules. Detections record `raw_reference`. | Endpoint-originated telemetry can't be trusted after compromise. Pair with network sensors and WEF with Kerberos-authenticated collectors. |
| 3 | **Malicious event injection**: an attacker posts fake events to trigger noise or bury real alerts | Alert fatigue, SIEM cost | Optional `API_KEY`, per-IP rate limit, batch-size limit, body-size limit, strict event schema (`extra="forbid"`), 422 errors that don't echo input. All detections are marked `simulated` / real. | A single shared key has no per-source identity. Next: per-collector credentials or mTLS, and source-to-host binding. |
| 4 | **Malicious rule upload / rule tampering** | Disabled detections, ReDoS, code execution | Rules load only from operator-controlled directories (`RULE_PATHS`). The API can *validate* but cannot store rules. There is no eval. The operator table is fixed, lookups are dict-only, and dunder paths are rejected. Depth, node, and list limits apply. Versions are immutable (changed content without a bump is refused). | Python `re` has no timeout, so a pathological regex in a trusted rule pack could still be slow. Next: the `re2` engine, signed rule packs, detection-as-code review. |
| 5 | **YAML parser attacks** (object construction, alias bombs) | RCE, memory exhaustion | `yaml.safe_load` only (Python tags rejected). Anchors and aliases are refused before parsing. 64 KB per rule file. | None known. Keep PyYAML updated. |
| 6 | **API abuse**: enumeration, scraping inventories, resetting data | Information disclosure, data loss | Auth-ready (`API_KEY`), CORS restricted to configured origins, rate limit, no command execution endpoints. Live discovery is off by default and runs only the fixed bundled script with a validated hostname, `shell=False`, and a timeout. | No RBAC. `/demo/reset` is available to any authenticated client, so disable or restrict it in real deployments. Next: users and roles, audit log. |
| 7 | **SIEM credential exposure** | SIEM compromise, data injection into the SIEM | Credentials come from the environment only (`SecretStr`). They are never logged, stored, or returned, and target URLs are shown without userinfo or query strings. TLS verification is on by default. The webhook URL is operator config, not API-settable, which avoids SSRF through the API. Redirects are not followed. | Environment variables are visible to anyone with host or container access. Next: a secret manager integration. |
| 8 | **Replayed events** | Duplicate detections, threshold manipulation | `event_id` is unique. Missing IDs are derived from a content hash, so exact replays are dropped and counted as `events_duplicate`. | Replays with modified content get new IDs. Next: signed or timestamped batches from collectors, and max clock skew. |
| 9 | **Spoofed host identity**: events claim to come from another host | Wrong rule set, misattribution | Unknown hosts fall back to baseline rules rather than none. Detections carry `environment_profiled`. | A spoofed *known* hostname gets that host's rule set. Next: bind API credentials to the hosts they may report for. |
| 10 | **Sensitive data in inventories** | Credential leakage | The collector does not read secrets. Command lines are redacted (`-NoCommandLine` available). `.gitignore` excludes inventory files. | Redaction is pattern-based. Review inventories before sharing. |
| 11 | **Supply chain** (dependencies, plugins) | Compromise of the platform | Few dependencies. Plugins load only from operator-set `PLUGIN_PATHS`/`PLUGINS`, and a failing plugin is isolated. | Plugins run as trusted code. Pin and hash dependencies for production. |
| 12 | **Denial of service via volume** | Pipeline backlog | Batch and body limits, rate limit, in-memory threshold key cap (100k). | Single process and synchronous forwarding. Next: a queue between ingest and detection. |

## Operational guidance

- Set `API_KEY`, put the API behind TLS, and restrict network access to the collectors and the UI.
- Keep `ENABLE_LIVE_DISCOVERY=false` unless the API host is an administrative jump host. When it is enabled,
  the API's service account's Windows rights define what remote discovery can reach.
- Treat rule packs as code: review them, version them, and test them.
- Filter `simulated=true` in the SIEM, or send demo traffic to a separate index.
