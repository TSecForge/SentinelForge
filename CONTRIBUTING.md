# Contributing to SentinelForge

Thanks for helping. SentinelForge was originally created by Sujhal Gurav and is licensed under Apache-2.0. By
submitting a contribution, you agree it is licensed under the same terms (Apache-2.0 section 5).

## Development setup

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest
cd frontend && npm install && npm run build      # type-checks and builds
```

Run both with `uvicorn app.main:app --reload` (from `backend/`) and `npm run dev` (from `frontend/`).

## Adding a detection rule

1. Pick the pack: `detection-rules/<platform>/` for general-purpose rules, `custom-rules/` for organization rules.
2. Name the file `<ID>-<slug>.yml` and use a unique `id` (`DET-WIN-0xx`, `DET-NET-0xx`, … for built-ins).
3. Required fields: `id`, `name`, `description`, `version` (quoted), `author`, `source`, `platform`,
   `event_type`, `severity`, `selection`. Also add `mitre`, `tags`, and `false_positives` where they apply.
4. Declare **applicability** with `applies_when` (technologies / environment types / platforms). Rules that only
   make sense when something exists must say so. That is the core idea of the project.
5. Use `$profile.<param>` for environment-specific values rather than hard-coding them.
6. Validate with `python -m app.cli rules validate`.
7. Add a test in `backend/tests/test_detection.py` with **a matching and a non-matching event**. If you add a demo
   scenario, add it in `app/services/simulation` and list its expected rules.
8. When you change an existing rule, **bump `version`**. The store refuses changed content under an old version.

Keep rules deterministic and explainable. Every match should be explainable from the `evidence` fields.

## Adding a collector

Collectors live under `collectors/<platform>/` and must:

- be read-only and leave nothing installed or running
- never collect passwords, keys, tokens, cookies, or secret file contents, and redact command lines
- emit inventory schema `1.0` (`schemas/inventory.schema.json`)
- have a README documenting what is and isn't collected and the privileges needed

Add a representative (synthetic) output under `sample-data/environments/` and a parsing test in
`backend/tests/test_discovery.py`.

## Adding an integration (SIEM adapter, event parser, observable extractor)

Prefer a **plugin** (see `plugins/stdout_siem` and `docs/extending.md`). Built-in adapters belong in
`backend/app/services/siem/adapters.py` only if they need no extra dependencies. Requirements:

- secrets only from settings (`SecretStr`), never logged or returned; `target()` must redact
- timeouts on all network calls; no redirects unless required
- tests for payload formatting (see `backend/tests/test_siem.py`)

## Coding standards

- **Python**: 3.11+, type hints, Pydantic schemas at boundaries. Business logic goes in `services/`, not routes.
  No `eval`/`exec`/`shell=True`. Use `get_logger(...)` with event-style names (`thing.happened`).
- **TypeScript**: strict mode, API calls only through `src/services/api.ts`, and simulated data must display `SimBadge`.
- Keep dependencies minimal. Explain any new dependency in the PR.
- Match the style of the surrounding code, and keep functions small and readable.

## Tests

- `python -m pytest` must pass. `SF_TEST_LIVE=1` additionally runs the live Windows collector test.
- `npm run build` must pass (it type-checks).
- New behaviour needs a test. Bug fixes need a regression test.

## Pull requests

- One logical change per PR, with a description of what and why.
- Mention detection impact: new or changed rules, expected false positives, MITRE mapping.
- Don't include real inventories, real hostnames or IPs, customer data, or real malicious infrastructure.
  Use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and `example.*` domains.
- Don't commit `.env`, databases, or inventory files.
- Offensive functionality (exploitation, persistence, evasion, credential access) will not be accepted.
  SentinelForge observes, detects, and forwards.
