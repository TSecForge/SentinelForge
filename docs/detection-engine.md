# Detection engine and rule format

Rules are **data, not code**. A YAML rule is parsed with `yaml.safe_load` (after refusing anchors and aliases),
validated by a strict Pydantic schema (`backend/app/schemas/rule.py`, `extra="forbid"`), and compiled into a
tree of predicates built from a fixed operator table (`backend/app/services/rules/evaluator.py`).
Nothing in a rule is evaluated as Python.

## Rule fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `^[A-Z0-9][A-Z0-9-]{2,63}$`, e.g. `DET-WIN-001`, `ORG-WIN-001` |
| `name`, `description` | yes | |
| `version` | yes | `"1.0"` style. Quote it: an unquoted YAML `1.10` becomes the float `1.1`. |
| `author`, `source` | yes | `source`: `builtin \| organization \| user \| community` |
| `status` | no | `stable` (default) `\| experimental \| deprecated` |
| `platform` | yes | `windows \| linux \| network \| docker \| kubernetes \| any` |
| `event_type` | yes | the normalized `event_type` this rule inspects |
| `severity` | yes | `informational \| low \| medium \| high \| critical` |
| `fidelity` | no | `low \| medium \| high` (default medium) → confidence 0.5 / 0.7 / 0.9 |
| `category` | no | free-form grouping (`powershell`, `container`, …) |
| `applies_when` | no | `platforms`, `technologies`, `environment_types`. Each key that is set must match (any-of within the key). |
| `selection` | yes | leaf mapping (all keys ANDed) |
| `condition` | no | node (see grammar), ANDed with `selection` |
| `threshold` | no | `count`, `window_seconds`, `group_by` |
| `summary` | no | `"{process.name} spawned by {process.parent_name}"`. Only dict lookups, not `str.format`. |
| `mitre` | no | `tactic`, `technique` (`T1234` or `T1234.001`) |
| `tags`, `references`, `false_positives` | no | |

## Condition grammar

```
node  := {"all": [node, ...]} | {"any": [node, ...]} | {"not": node} | leaf
leaf  := {"<field.path>[|<operator>]": value, ...}     # every key ANDed
value := scalar | [scalar, ...]                         # a list means any-of (a set for not_in / not_cidr)
```

| Operator | Meaning |
|---|---|
| `eq` (default) | case-insensitive equality; a list means any-of |
| `contains`, `startswith`, `endswith` | case-insensitive substring tests |
| `re` | Python regex, `IGNORECASE`, at most 512 characters, compiled at validation time |
| `not_in` | at least one field value is outside the set |
| `cidr`, `not_cidr` | IP inside / outside any listed network. Unparseable IPs never match. |
| `gt`, `gte`, `lt`, `lte` | numeric comparison |
| `exists` | `true` / `false` |

Semantics:
- If the event field is a **list** (for example `container.host_ports`), a leaf matches when **any element** matches.
- A **missing field never matches**, except `exists: false`. Absent data does not make a rule fire.
- Limits: depth ≤ 8, ≤ 256 nodes, ≤ 1000 values per list. Field paths are `[a-z][a-z0-9_]*` segments,
  at most 5 deep, so there are no dunder segments and lookups walk dict keys only.

## Environment-specific parameters

A template value can be `"$profile.<name>"`, or a list that contains such references (they are flattened in place):

| Reference | Source |
|---|---|
| `$profile.listening_ports` | all TCP listening ports at discovery |
| `$profile.approved_images` | images plus running-container images at discovery, normalized to `name:tag` |
| `$profile.container_ports` | host ports published by containers at discovery |
| `$profile.internal_cidrs` | interface subnets (non-global) plus RFC1918, loopback, link-local, ULA |
| `$profile.known_admins` | Administrators group members plus users flagged as admin |

References are resolved when rules are **generated**, so the executed rule holds concrete values. You can see
the executed rule in the UI under *Rule → Generated rule as executed*. Unknown references fail validation.

Hosts that send events but have no profile are evaluated against **baseline rules**: templates that need no
`$profile` values. Their detections carry a 0.1 confidence penalty. A spoofed or unknown hostname therefore
still gets evaluated.

## Thresholds

```yaml
threshold:
  count: 5
  window_seconds: 300
  group_by: [host, network.src_ip]
```

For each `(rule, environment, group values)`, the engine keeps a sliding window of event timestamps. It fires once
the count is reached and then resets, so a long burst produces one detection per `count` events rather than one
per event. Windows live in process memory.

## Confidence

`confidence` = the rule's fidelity rating (high 0.9, medium 0.7, low 0.5), minus 0.1 when the host has no
environment profile. `confidence_basis` states this in every detection. It is not a model output and does not
learn.

## Writing a rule

1. Copy an existing rule into `custom-rules/<your-org>/`.
2. Set a new `id`, `author`, and `source: organization`.
3. Run `sentinelforge rules validate` or `POST /api/v1/rules/validate`.
4. Reload with `POST /api/v1/rules/reload` or the UI button, then regenerate rules for your environments.
5. Add a test with a matching and a non-matching event (see `backend/tests/test_detection.py`).

To change a rule later, **bump `version`**. The store refuses changed content under an existing version.
