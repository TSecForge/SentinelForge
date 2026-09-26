# Example: your own detection rule repository

This folder is shaped like a standalone repo that keeps an organization's detections as code and tests them with
the SentinelForge GitHub Action. SentinelForge's own CI runs the action against it.

```
rules/          your SentinelForge-format YAML rules
rule-tests/     one test file per rule: events that must and must not fire it
.github/workflows/detections.yml
```

`.github/workflows/detections.yml` in *your* repository:

```yaml
name: Detections
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: TSecForge/SentinelForge@v0.2.0
        with:
          rules: rules
          tests: rule-tests
          include-builtin: "true"      # catch ID clashes with built-in rules; show combined coverage
```

Every push then:
1. validates the rules (schema, safe YAML, operators, regex compile)
2. runs each rule's match / no-match cases, failing for rules without tests
3. writes an ATT&CK coverage table to the job summary

Run the same checks locally:

```bash
pip install sentinelforge-detect
sentinelforge rules validate rules
sentinelforge rules test --rules rules --tests rule-tests
sentinelforge coverage export --rules builtin rules --summary
```
