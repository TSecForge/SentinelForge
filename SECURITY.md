# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Use the repository host's private
vulnerability reporting (for example, GitHub → Security → Report a vulnerability) or contact the maintainers privately.

Include affected versions/commits, reproduction steps, and impact. We aim to acknowledge reports within 7 days
and to agree on a disclosure timeline with you.

## Supported versions

This is an MVP. Only the latest `main` branch receives fixes.

## Scope

In scope:
- the backend API
- rule parsing and evaluation
- the collector
- SIEM adapters
- the dashboard

Examples: remote code execution, rule-evaluator escapes, authentication bypass, secret disclosure, injection through
inventories or events, and SSRF.

Out of scope:
- findings that require `ENABLE_LIVE_DISCOVERY=true` combined with an attacker who already controls the API host
- deployments that expose the API without `API_KEY`/TLS contrary to the documentation
- detection gaps. Missing or weak rules are welcome as regular issues or PRs.

## Hardening checklist for deployments

- Set `API_KEY`, terminate TLS in front of the API, and restrict `CORS_ORIGINS`.
- Keep `ENABLE_LIVE_DISCOVERY=false` unless it is required.
- Store SIEM tokens in a secret manager or an orchestrator secret, not in files committed anywhere.
- Treat rule packs and plugins as code: review, pin, and version them.
- See [docs/threat-model.md](docs/threat-model.md).
