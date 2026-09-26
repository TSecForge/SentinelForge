## What and why

<!-- What does this change do, and what problem does it solve? Link issues: "Closes #123". -->

## Type of change

- [ ] Detection rule (new / changed)
- [ ] Collector or event parser
- [ ] SIEM adapter / plugin
- [ ] Core engine / API
- [ ] Dashboard
- [ ] Docs / CI / packaging

## Detection changes (if any)

<!-- Rule IDs, ATT&CK techniques, expected false positives, telemetry required. -->

## Checklist

- [ ] `python -m pytest` passes (from `backend/`)
- [ ] `python -m sentinelforge rules validate builtin custom-rules` and `python -m sentinelforge rules test --rules builtin custom-rules --inventory-dir sample-data/environments` pass (from the repo root)
- [ ] New or changed rules have `rule-tests/<ID>.yml` with match **and** no_match cases, and changed rules bump `version`
- [ ] `python -m sentinelforge coverage export --rules builtin custom-rules` was run and `docs/attack-coverage.md` is committed
- [ ] `npm run build` passes (if the frontend changed)
- [ ] Docs updated where behaviour or configuration changed
- [ ] No real hostnames, IPs, credentials, customer data or malicious infrastructure in code, tests or samples
- [ ] Defensive scope only: no exploitation, persistence, evasion or credential-access tooling
