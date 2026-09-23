# SentinelForge

**Agentless Environment-Aware Detection Engineering & Event Intelligence Platform**

SentinelForge discovers the security-relevant characteristics of a host without installing a custom
endpoint agent, builds an **environment profile**, activates only the detection rules that make sense
for that environment, evaluates incoming telemetry against them with a deterministic engine, extracts
observables, and forwards normalized detection events to a SIEM.

```
DISCOVER  →  PROFILE  →  GENERATE / SELECT RULES  →  DETECT  →  ENRICH  →  FORWARD
```

> **Status: MVP / prototype.** It demonstrates an architecture. It is not a complete detection
> capability, it will produce false positives and negatives, and it is not hardened for enterprise use.
> See [Limitations](#limitations).

---

## The problem

SIEM pipelines often receive every event from every host and apply one global rule set. Much of that
telemetry is irrelevant to the host it came from: Docker rules on hosts without Docker, IIS web-shell
rules on workstations, RDP rules where RDP is disabled.

SentinelForge explores a different approach. It learns what exists on a host first, adapts the
detection logic to it (including environment-specific parameters such as "the container images that were
present at discovery"), and forwards security-relevant detections instead of raw volume.

It does **not** eliminate logs. It acts as a detection and filtering layer before, or alongside, a SIEM:

```
Raw telemetry ──► Detection / filtering layer ──┬──► benign / irrelevant events ──► counted, not forwarded
                                                 └──► security-relevant events
                                                          │
                                                          ▼
                                              enrichment + observable extraction
                                                          │
                                                          ▼
                                            normalized detection (sentinelforge.detection.v1)
                                                          │
                                                          ▼
                                                      SIEM / SOC
```

## Architecture

```
                               SENTINELFORGE
                                     │
            ┌────────────────────────┴────────────────────────┐
            ▼                                                 ▼
     Discovery Engine                                   Event Pipeline
  (PowerShell / WinRM, import)                    (windows, linux, docker, k8s, generic)
            │                                                 │
            ▼                                                 ▼
   Environment Profiler                               Event Normalizer
 (technologies, exposure, risk,                               │
  rule parameters + evidence)                                 ▼
            │                                         Detection Engine
            ▼                                   (safe evaluator, thresholds)
  Detection Rule Writer ──► Rule Store                        │
 (match → resolve → validate)  (versioned)                    ▼
            │                                        Enrichment Engine
            └──── environment-specific active rules ──►       │
                                                              ▼
                                                        IOC / observable extractor
                                                              │
                                                              ▼
                                                      Detection Event
                                                              │
                              ┌───────────────────┬───────────┴──────────┐
                              ▼                   ▼                      ▼
                          Dashboard           Webhook              SIEM Gateway
                                                                         │
                                                         ┌───────────────┼───────────────┐
                                                         ▼               ▼               ▼
                                                      Splunk HEC     Elastic/OpenSearch   plugins
```

The five core concepts:

| Concept | Role | Where |
|---|---|---|
| Discovery | Foundation: know what exists | `collectors/windows/discovery.ps1`, `backend/app/services/discovery` |
| **Rule Writer Engine** | Differentiator: activate and parameterize rules per environment | `backend/app/services/rules` |
| Detection Engine | Execution: deterministic evaluation | `backend/app/services/detection` |
| SIEM Gateway | Integration | `backend/app/services/siem` |
| Dashboard | Analyst interface | `frontend/` |

More detail: [docs/architecture.md](docs/architecture.md).

## Features

- **Agentless Windows discovery**: read-only PowerShell collector (local or remote via WinRM). It collects OS,
  interfaces, CIDRs, routes, DNS, listening TCP/UDP ports with owning processes, services, processes
  (secrets in command lines are redacted), local users and admins, installed software, scheduled tasks,
  Defender, firewall and audit posture, RDP/WinRM/SSH, IIS/Apache/Nginx, Docker containers/images, and
  Kubernetes indicators. It does not collect secrets.
- **Versioned inventory schema 1.0** with strict validation. Any collector that emits it can be imported.
- **Environment profiler** that derives environment types (web_server, remote_access, container_host,
  kubernetes_node, ...), technologies with the evidence behind each one, exposed services (service ↔ port ↔
  process), risk context, and the rule parameters the templates use.
- **Rule Writer Engine**:
  - Sigma-inspired YAML templates with `applies_when` applicability.
  - Environment-specific parameters (`$profile.approved_images`, `$profile.listening_ports`,
    `$profile.internal_cidrs`, `$profile.known_admins`, `$profile.container_ports`).
  - A validation gate that must pass before any rule becomes active.
  - Versioned assignments, and the reason each rule was or wasn't activated.
- **25 rules** (24 built-in plus 1 example organization rule) covering Windows/PowerShell, IIS, RDP, WinRM,
  accounts, persistence, network, Docker, Kubernetes, and Linux.
- **Safe, deterministic evaluator**: no `eval`, a fixed operator table, dict-only field access,
  bounded depth/size, and refusal of YAML anchors and Python tags. Supports threshold rules (N events in T seconds per group).
- **Event normalization** for Windows Security/System/Sysmon records, Linux (JSON and sshd syslog), Docker
  Engine events, Kubernetes audit events, and generic JSON.
- **Observable extraction** (IPv4/IPv6/domain/URL/hash/path/process/command line/user/host/image/port).
  IPs are labelled internal/external relative to the host's own ranges. Observables are not verdicts.
- **Detection events** (`sentinelforge.detection.v1`) with evidence, environment context, a rule-selection
  reason, and a documented, deterministic confidence.
- **SIEM gateway**: generic webhook, Splunk HEC, and Elasticsearch/OpenSearch. Every delivery attempt is recorded.
  A built-in webhook receiver lets you demo forwarding without a SIEM.
- **Event reduction metrics** measured on the actual workload.
- **Demo mode** with simulated, clearly labelled telemetry and 21 attack scenarios.
- **Dashboard** covering Dashboard, Environments (with topology), Rules (YAML, applicability, validation), Events,
  Detections, SIEM, and About.
- **Open-source extension points**: rule packs, plugins (SIEM adapters, event parsers, observable extractors),
  branding, and a CLI.

## Quick start

Requirements: Python 3.11+, Node.js 20+. Windows is only needed for live discovery.

```bash
# backend
cd backend
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload                        # http://127.0.0.1:8000  (API docs: /api/docs)
```

```bash
# frontend (second terminal)
cd frontend
npm install
npm run dev                                          # http://localhost:5173
```

SQLite is used by default (`backend/sentinelforge.db`); no database setup is needed.
To see SIEM forwarding without a real SIEM, start the backend with:

```bash
SIEM_MODE=webhook WEBHOOK_URL=http://127.0.0.1:8000/api/v1/siem/events uvicorn app.main:app --reload
```

(PowerShell: `$env:SIEM_MODE="webhook"; $env:WEBHOOK_URL="http://127.0.0.1:8000/api/v1/siem/events"; uvicorn app.main:app --reload`)

### With Docker

```bash
cp .env.example .env     # optional
docker compose up --build
# UI: http://localhost:8080   API: http://localhost:8000/api/docs   (PostgreSQL backend)
```

## Running Demo Mode

1. Open the dashboard and click **▶ Demo Mode**.
2. **Create Demo Environment** creates `WEB-SRV-01` (Windows Server 2022, IIS, RDP, WinRM, Docker with 7
   containers). It is marked **SIMULATED** everywhere.
3. Review the **Environment Profile**: technologies, environment types, exposed services, and risk.
4. **Generate Rules** activates the rules this host needs. With the shipped packs that is 20 active and 5 not applicable
   (Kubernetes and Linux), each with a reason.
5. **Simulate Security Event** runs the default scenario, *Office application spawning PowerShell*. It produces
   **HIGH · Office Application Spawning PowerShell** (plus *PowerShell Downloading Remote Content*).
6. Click the detection to see the host, timestamp, rule, description, severity, MITRE technique, observables,
   evidence, environment context, the source event, and SIEM delivery.
7. **Simulate full workload** sends 1,000 benign events plus every scenario relevant to the host. The dashboard then shows
   events received, filtered, detections, forwarded, and the reduction percentage.

The same flow from the CLI: `sentinelforge demo --benign 10000`.

Measured on the development machine (SQLite, synthetic workload): 10,044 events received, 17 matched,
18 detection documents, 99.83% of events not forwarded. Every scenario fired its expected rule and no
benign event matched. That describes this synthetic workload only. Real telemetry is noisier.

## Windows discovery

```powershell
# local, writes a schema-1.0 inventory (no install, read-only)
powershell -NoProfile -ExecutionPolicy Bypass -File collectors\windows\discovery.ps1 -OutFile inventory.json

# remote over WinRM with your current Windows credentials
.\collectors\windows\discovery.ps1 -ComputerName WEB-SRV-01 -OutFile web-srv-01.json
```

Import the file in the UI (**Environments → Import inventory**), with `sentinelforge discovery --file inventory.json --save`,
or via `POST /api/v1/discovery/run {"mode":"import","inventory":{...}}`.
The API can also run the collector itself (`mode: local | remote`), but only when `ENABLE_LIVE_DISCOVERY=true`.

*Agentless discovery is not the same as having no telemetry mechanism.* Discovery is agentless. Continuous events
still have to arrive through something native, such as Windows Event Forwarding, Sysmon + WEF, or an existing log shipper posting to
`/api/v1/events/batch`. See [docs/discovery.md](docs/discovery.md).

## Detection rules

```yaml
id: DET-WIN-001
name: Office Application Spawning PowerShell
version: "1.0"
author: Sujhal Gurav
source: builtin            # builtin | organization | user | community
platform: windows
event_type: process_creation
severity: high
fidelity: high             # drives the documented confidence score
applies_when:
  technologies: [PowerShell]
selection:
  process.name: [powershell.exe, pwsh.exe]
condition:
  process.parent_name: [winword.exe, excel.exe, outlook.exe]
summary: "{process.parent_name} spawned {process.name} on {host}"
mitre: {tactic: execution, technique: T1059.001}
tags: [windows, powershell]
```

Environment-specific template:

```yaml
selection:
  container.image|not_in: $profile.approved_images   # resolved per host at generation time
```

Operators: `eq` (default), `contains`, `startswith`, `endswith`, `re`, `not_in`, `cidr`, `not_cidr`, `gt`,
`gte`, `lt`, `lte`, `exists`, combined with `all` / `any` / `not`. Full reference:
[docs/detection-engine.md](docs/detection-engine.md).

Organization rules go in `custom-rules/`, or any directory listed in `RULE_PATHS`. The core engine does not need to change. Validate them with
`sentinelforge rules validate`, then reload with **Rules → Reload rule packs**.

## Event pipeline

`POST /api/v1/events` or `/api/v1/events/batch` with `{"source": "windows|linux|docker|kubernetes|generic", "data": {...}}`.
The pipeline then runs these steps:

1. Normalize into the common event model.
2. Drop duplicates by `event_id` (replay protection).
3. Look up the host's environment (hosts without a profile get the baseline rules).
4. Evaluate the active rules, including thresholds.
5. Enrich and extract observables.
6. Persist, count, and forward.

Sample batches are in `sample-data/events/`.

## SIEM integration

| `SIEM_MODE` | Settings |
|---|---|
| `disabled` (default) | detections stay in the local store |
| `webhook` | `WEBHOOK_URL`, optional `WEBHOOK_AUTH_HEADER` |
| `splunk` | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SPLUNK_INDEX`, `SPLUNK_SOURCE` |
| `elastic` | `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX` |
| plugin name | e.g. `stdout` from `plugins/stdout_siem` |

Secrets come from the environment only and are never returned by the API. Target URLs are shown with their credentials
and query strings removed. See [docs/siem-integration.md](docs/siem-integration.md).

## API

Interactive docs are at `http://127.0.0.1:8000/api/docs`. Main endpoints:

```
GET  /api/v1/health                          GET  /api/v1/about
POST /api/v1/discovery/run                   GET  /api/v1/environments[/{id}]
POST /api/v1/profiles/{environment_id}/generate-rules
PATCH /api/v1/environments/{id}/rules/{assignment_id}
GET  /api/v1/rules[/{rule_id}]               POST /api/v1/rules/validate | /reload
POST /api/v1/events | /events/batch          GET  /api/v1/events[/{id}]
GET  /api/v1/detections[/{id}]               GET  /api/v1/metrics | /dashboard/summary
GET  /api/v1/siem/status                     POST /api/v1/siem/test | /siem/events
POST /api/v1/demo/environment | /demo/simulate | /demo/run | /demo/reset
```

## CLI

```bash
pip install -e backend        # provides the `sentinelforge` command (or: python -m app.cli from backend/)
sentinelforge discovery --save                 # live local discovery
sentinelforge profile --template windows-web-server
sentinelforge rules validate
sentinelforge rules generate --file inventory.json
sentinelforge events simulate --scenario office_powershell
sentinelforge demo --benign 10000
sentinelforge schemas export                   # regenerates schemas/*.schema.json
```

## Customization and extension

- **Branding**: `PROJECT_NAME`, `PROJECT_DESCRIPTION`, `ORGANIZATION_NAME`, `ORGANIZATION_LOGO`,
  `PRIMARY_BRAND_COLOR`, `DASHBOARD_TITLE`, `FOOTER_TEXT`. You don't need to change any code. A customized UI shows
  "Powered by SentinelForge" in the footer, and the About page keeps the upstream project metadata.
- **Rule packs**: `RULE_PATHS=./detection-rules,./custom-rules,/opt/acme-rules`.
- **Plugins**: `PLUGIN_PATHS` + `PLUGINS`. A plugin's `register(registry)` can add SIEM adapters, event parsers,
  and observable extractors. See `plugins/stdout_siem` and [docs/extending.md](docs/extending.md).
- **Collectors**: anything that emits inventory schema 1.0 (`schemas/inventory.schema.json`).

The core engine never imports plugins directly. Integrations use the same registry as the built-ins.
There is no telemetry, no license check, no phone-home, and no activation.

## Security considerations

This is a security tool, so it is built to be secure by default:

- Pydantic validation at every boundary, strict rule schema (`extra="forbid"`), and bounded sizes.
- `yaml.safe_load` only, with anchors/aliases refused (alias bombs) and no Python tags.
- No `eval`/`exec`. Rule field paths walk dict keys only, and dunder segments are rejected.
- The API cannot run arbitrary commands. The only subprocess is the fixed, bundled collector, run with `shell=False`, a timeout,
  and a regex-validated hostname argument. It is off unless `ENABLE_LIVE_DISCOVERY=true`.
- Secrets come from environment variables only (`SecretStr`) and are never logged or returned.
- Optional API key (`API_KEY`, constant-time comparison), a per-IP rate limit, a request size limit, restrictive CORS,
  and error responses that don't echo input.
- Structured JSON logs (`discovery.completed`, `profile.created`, `rules.generated`, `detection.matched`, `siem.forwarded`, ...).

Threat model: [docs/threat-model.md](docs/threat-model.md). Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

> **Antivirus note:** demo scenarios contain *inert text* that looks like attack command lines (download
> cradles, reverse-shell strings). Endpoint AV may flag or lock files or logs that contain them. The simulator
> builds those strings at runtime to keep its own source file clean, but exported detections can still
> trigger AV. Nothing is ever executed.

## Limitations

- **Coverage**: 25 rules is a demonstration set, not complete detection coverage. There will be false positives
  and false negatives.
- **Telemetry**: discovery is agentless, but continuous collection (WEF, syslog forwarding) is not implemented yet.
  Events must be pushed to the API.
- **Linux/Kubernetes discovery**: only the inventory *schema* and sample inventories exist. There is no bundled Linux collector yet,
  and Kubernetes support is detection-oriented (audit events), not cluster integration.
- **State**: threshold windows and the rate limiter live in process memory. Run a single worker, or move them to Redis.
- **Database**: tables are created with `create_all`, and there are no Alembic migrations yet.
  PostgreSQL is wired in docker-compose but was not exercised in development testing (SQLite was).
- **Auth**: a single shared API key. There are no users or roles. A `VITE_API_KEY` given to the frontend is visible to its users.
- **Confidence**: a static, per-rule fidelity rating (0.9/0.7/0.5, minus 0.1 when the host has no profile).
  It is not statistical.
- **Reduction numbers** only describe the workload measured. Simulated workloads are cleaner than real ones.
- **Baselines** (approved images, listening ports, admins) come from the last discovery. Legitimate change
  looks like drift until you re-discover.

## Roadmap

| Version | Focus |
|---|---|
| v1 (this) | Agentless discovery, rule writer, deterministic engine, simulated events, SIEM adapters |
| v2 | Windows Event Forwarding / WEC subscription ingestion |
| v3 | Linux collector (SSH, read-only) and syslog/journald ingestion |
| v4 | Docker events streaming and Kubernetes audit webhook |
| v5 | Distributed collectors and a message queue between collection and detection |
| v6 | Correlation across events and hosts (sequences, multi-stage chains) |
| v7 | Threat intelligence enrichment (local feeds, MISP/STIX), still marked as context rather than verdicts |
| v8 | Detection-as-code: Git-backed rule packs, CI validation, test events per rule |
| v9 | Multi-tenant architecture, RBAC, SSO |

Details: [docs/roadmap.md](docs/roadmap.md). An optional LLM assistant (explanations, rule ideas) is also on the list. It would sit
outside the execution path, and any rule it proposed would have to pass the same deterministic validation.

## Repository layout

```
backend/            FastAPI app (api/ core/ db/ models/ schemas/ services/), CLI, tests
frontend/           React + Vite + TypeScript + Tailwind dashboard
collectors/windows/ agentless PowerShell discovery collector
detection-rules/    built-in rule packs (windows, network, docker, kubernetes, linux)
custom-rules/       organization/user rule packs (loaded alongside built-ins)
plugins/            example plugin (stdout SIEM adapter, parser, extractor)
schemas/            JSON Schemas (inventory, profile, rule, normalized event, detection event)
sample-data/        synthetic environments, events and an example detection
docs/               architecture, detection engine, discovery, SIEM, extending, threat model, roadmap
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): how to add rules, collectors, parsers, and SIEM adapters, plus testing
expectations. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Attribution

SentinelForge was originally created by **Sujhal Gurav**.

The project is open-source and designed to be extended, customized, and adapted for different security
environments. If you build a project, product, research project, organization-specific implementation,
or derivative work using SentinelForge, the Apache License 2.0 requires that you keep the copyright and license notices
and include the attribution notices from the [NOTICE](NOTICE) file in your distribution. It does
**not** require you to show the original author's name in your product's UI. Branding is yours to change.

## License

License: **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
