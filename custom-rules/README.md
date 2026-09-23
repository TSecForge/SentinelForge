# Custom rule packs

Everything under this directory is loaded alongside the built-in `detection-rules/`, as long as it is listed in
`RULE_PATHS` (it is by default). Use it for organization, user, or community rules without touching the core packs.

```
custom-rules/
└── example-org/
    └── ORG-WIN-001-powershell-from-temp.yml   # working example (source: organization, status: experimental)
```

1. Copy the example, then change `id` (unique), `author`, and `source` (`organization | user | community`).
2. Validate: `cd backend && python -m app.cli rules validate ../custom-rules`
3. Load: restart the API or click **Rules → Reload rule packs**, then **Regenerate Rules** on your environments.
4. Change a rule later by **bumping `version`**. Changed content under the same version is refused.

To keep private rules out of this repository, point `RULE_PATHS` at another directory, for example
`RULE_PATHS=../detection-rules,/opt/acme/sentinelforge-rules`.

Format reference: [docs/detection-engine.md](../docs/detection-engine.md).
