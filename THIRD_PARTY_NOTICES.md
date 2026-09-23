# Third-Party Notices

SentinelForge does not vendor (copy into this repository) any third-party source code. The components
below are installed as dependencies by `pip` / `npm` / container builds and remain under their own
licenses. Versions are those verified during development; see `backend/requirements.txt` and
`frontend/package.json` for the ranges actually requested.

## Runtime dependencies (backend)

| Component | Version checked | License |
|---|---|---|
| FastAPI | 0.128.0 | MIT |
| Starlette (via FastAPI) | 0.50.0 | BSD-3-Clause |
| Uvicorn | 0.40.0 | BSD-3-Clause |
| Pydantic | 2.11.7 | MIT |
| pydantic-settings | 2.10.1 | MIT |
| SQLAlchemy | 2.0.36 | MIT |
| PyYAML | 6.0.2 | MIT |
| HTTPX | 0.28.1 | BSD-3-Clause |
| psycopg 3 (optional, PostgreSQL only) | >=3.1 | LGPL-3.0 (used as an unmodified, dynamically imported library) |

## Frontend dependencies

| Component | Version checked | License |
|---|---|---|
| React / React DOM | 18.3.1 | MIT |
| Recharts | 2.15.4 | MIT |
| Vite | 5.4.21 | MIT |
| @vitejs/plugin-react | 4.7.0 | MIT |
| Tailwind CSS / @tailwindcss/vite | 4.3.3 | MIT |
| TypeScript | 5.5.4 | Apache-2.0 |

## Container base images (docker-compose only)

`python:3.12-slim`, `node:22-alpine`, `nginx:1.27-alpine`, `postgres:16-alpine` - each under the
licenses of the software they contain (PSF, MIT, BSD-2-Clause, PostgreSQL License, and the licenses
of the Debian/Alpine packages included).

## Concepts and references (no content copied)

- **Sigma** (SigmaHQ): SentinelForge's rule format is *inspired by* the Sigma idea of YAML detection
  rules with selections, modifiers (`field|contains`) and metadata. The schema, evaluator and every
  rule in `detection-rules/` were written for this project; no Sigma rules are included. Sigma rules
  are published under the Detection Rule License (DRL) 1.1 - if you import them into a rule pack,
  keep their license and author attribution.
- **MITRE ATT&CK®**: rules reference ATT&CK tactic names and technique IDs (e.g. `T1059.001`) as
  identifiers only. ATT&CK is a registered trademark of The MITRE Corporation; see MITRE's ATT&CK
  Terms of Use if you reproduce ATT&CK content itself.
- **Apache License 2.0 text** in `LICENSE` is the standard text published by the Apache Software Foundation.

Documentation and sample data use only reserved documentation IP ranges (RFC 5737 / RFC 3849),
private ranges (RFC 1918 / RFC 4193) and reserved domain names (RFC 2606, `example.*`).
