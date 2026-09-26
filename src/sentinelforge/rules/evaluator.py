"""Safe condition evaluator.

Rules are data, never code: selections/conditions compile into a small tree of closures built from a fixed
operator table. No eval/exec, no attribute access (field paths only walk dict keys), bounded depth/size.

Grammar
    node  := {"all": [node, ...]} | {"any": [node, ...]} | {"not": node} | leaf
    leaf  := {"<field.path>[|<op>]": value, ...}        # all keys ANDed
    value := scalar | [scalar, ...]                      # a list means any-of (set for not_in / not_cidr)

Semantics
    * string comparisons are case-insensitive
    * if the event field is a list, the leaf matches when any element matches
    * a missing field never matches (except `exists: false`), so rules don't fire on absent data
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.schemas.rule import FIELD_PATH, RuleDefinition
from sentinelforge._util import get_path

MAX_DEPTH = 8
MAX_NODES = 256
MAX_LIST = 1000
MAX_REGEX_LEN = 512
PROFILE_REF = "$profile."

_FIELD_RE = re.compile(FIELD_PATH)
Pred = Callable[[dict], bool]


class RuleCompileError(ValueError):
    pass


def _norm(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).casefold()


def _values(actual: Any) -> list:
    if actual is None:
        return []
    if isinstance(actual, list):
        return [a for a in actual if a is not None and a != ""]
    return [] if actual == "" else [actual]


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _net(v: Any):
    try:
        return ipaddress.ip_network(str(v), strict=False)
    except ValueError as e:
        raise RuleCompileError(f"invalid CIDR {v!r}") from e


def _ip(v: Any):
    try:
        return ipaddress.ip_address(str(v).split("%")[0])
    except ValueError:
        return None


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _make_op(op: str, raw: Any) -> Callable[[Any], bool]:
    """Return fn(actual_value) -> bool. `raw` is the (already profile-resolved) rule value."""
    vals = _as_list(raw)
    if len(vals) > MAX_LIST:
        raise RuleCompileError(f"value list too long ({len(vals)} > {MAX_LIST})")
    for v in vals:
        if isinstance(v, (dict, list)):
            raise RuleCompileError("values must be scalars or a flat list of scalars")
        if isinstance(v, str) and v.startswith(PROFILE_REF):
            raise RuleCompileError(f"unresolved profile reference {v!r}")

    if op == "exists":
        want = bool(raw)
        return lambda actual: (len(_values(actual)) > 0) == want
    if op in ("eq", "contains", "startswith", "endswith"):
        needles = [_norm(v) for v in vals]
        test = {
            "eq": lambda a, n: a == n,
            "contains": lambda a, n: n in a,
            "startswith": lambda a, n: a.startswith(n),
            "endswith": lambda a, n: a.endswith(n),
        }[op]
        return lambda actual: any(test(_norm(a), n) for a in _values(actual) for n in needles)
    if op == "not_in":
        allowed = {_norm(v) for v in vals}
        return lambda actual: any(_norm(a) not in allowed for a in _values(actual))
    if op == "re":
        pats = []
        for v in vals:
            if not isinstance(v, str) or len(v) > MAX_REGEX_LEN:
                raise RuleCompileError(f"regex must be a string of at most {MAX_REGEX_LEN} chars")
            try:
                pats.append(re.compile(v, re.IGNORECASE))
            except re.error as e:
                raise RuleCompileError(f"invalid regex {v!r}: {e}") from e
        return lambda actual: any(p.search(str(a)) for a in _values(actual) for p in pats)
    if op in ("cidr", "not_cidr"):
        nets = [_net(v) for v in vals]

        def in_nets(a: Any) -> bool | None:
            ip = _ip(a)
            return None if ip is None else any(ip.version == n.version and ip in n for n in nets)

        if op == "cidr":
            return lambda actual: any(in_nets(a) is True for a in _values(actual))
        return lambda actual: any(in_nets(a) is False for a in _values(actual))
    if op in ("gt", "gte", "lt", "lte"):
        if len(vals) != 1 or _num(vals[0]) is None:
            raise RuleCompileError(f"{op} needs a single number")
        ref = _num(vals[0])
        cmp = {"gt": lambda a: a > ref, "gte": lambda a: a >= ref, "lt": lambda a: a < ref, "lte": lambda a: a <= ref}[op]
        return lambda actual: any((n := _num(a)) is not None and cmp(n) for a in _values(actual))
    raise RuleCompileError(f"unknown operator {op!r}")


OPERATORS = ("eq", "contains", "startswith", "endswith", "re", "not_in", "cidr", "not_cidr", "gt", "gte", "lt", "lte", "exists")


@dataclass
class _Ctx:
    nodes: int = 0
    fields: list[str] = field(default_factory=list)


def _compile_leaf(mapping: dict, ctx: _Ctx) -> Pred:
    preds: list[Pred] = []
    for key, raw in mapping.items():
        if not isinstance(key, str):
            raise RuleCompileError(f"field key must be a string, got {key!r}")
        path, _, op = key.partition("|")
        op = op or "eq"
        if not (path == "host" or path == "event_type" or _FIELD_RE.match(path)):
            raise RuleCompileError(f"invalid field path {path!r}")
        if op not in OPERATORS:
            raise RuleCompileError(f"unknown operator {op!r} (allowed: {', '.join(OPERATORS)})")
        fn = _make_op(op, raw)
        if path not in ctx.fields:
            ctx.fields.append(path)
        preds.append(lambda ev, p=path, f=fn: f(get_path(ev, p)))
    return lambda ev: all(p(ev) for p in preds)


def compile_node(node: Any, ctx: _Ctx | None = None, depth: int = 0) -> Pred:
    ctx = ctx or _Ctx()
    ctx.nodes += 1
    if depth > MAX_DEPTH:
        raise RuleCompileError(f"condition nested deeper than {MAX_DEPTH}")
    if ctx.nodes > MAX_NODES:
        raise RuleCompileError(f"condition has more than {MAX_NODES} nodes")
    if not isinstance(node, dict) or not node:
        raise RuleCompileError("condition node must be a non-empty mapping")
    keys = set(node)
    if keys & {"all", "any", "not"}:
        if len(keys) != 1:
            raise RuleCompileError("'all'/'any'/'not' must be the only key in their node")
        (k, v), = node.items()
        if k == "not":
            inner = compile_node(v, ctx, depth + 1)
            return lambda ev: not inner(ev)
        if not isinstance(v, list) or not v:
            raise RuleCompileError(f"'{k}' needs a non-empty list")
        children = [compile_node(c, ctx, depth + 1) for c in v]
        return (lambda ev: all(c(ev) for c in children)) if k == "all" else (lambda ev: any(c(ev) for c in children))
    return _compile_leaf(node, ctx)


# ----------------------------------------------------------------- profile references

def find_profile_refs(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out += find_profile_refs(v)
    elif isinstance(obj, list):
        for v in obj:
            out += find_profile_refs(v)
    elif isinstance(obj, str) and obj.startswith(PROFILE_REF):
        out.append(obj[len(PROFILE_REF):])
    return sorted(set(out))


def resolve_profile_refs(obj: Any, params: dict[str, Any]) -> Any:
    """Replace "$profile.<name>" with the profile's value. Refs inside lists are flattened in place.
    Only names that exist in RuleParameters resolve - there is no expression language."""
    if isinstance(obj, dict):
        return {k: resolve_profile_refs(v, params) for k, v in obj.items()}
    if isinstance(obj, list):
        out: list = []
        for v in obj:
            r = resolve_profile_refs(v, params)
            out.extend(r if isinstance(v, str) and v.startswith(PROFILE_REF) and isinstance(r, list) else [r])
        return out
    if isinstance(obj, str) and obj.startswith(PROFILE_REF):
        name = obj[len(PROFILE_REF):]
        if name not in params:
            raise RuleCompileError(f"unknown profile reference {obj!r} (allowed: {sorted(params)})")
        return list(params[name]) if isinstance(params[name], (list, tuple)) else params[name]
    return obj


# ----------------------------------------------------------------- compiled rule

@dataclass
class CompiledRule:
    definition: RuleDefinition
    predicate: Pred
    fields: list[str]

    def matches(self, event: dict) -> bool:
        return event.get("event_type") == self.definition.event_type and self.predicate(event)


def compile_rule(defn: RuleDefinition) -> CompiledRule:
    """Compile a *resolved* rule (no $profile refs left)."""
    ctx = _Ctx()
    sel = compile_node(defn.selection, ctx)
    cond = compile_node(defn.condition, ctx) if defn.condition else None
    pred = (lambda ev: sel(ev) and cond(ev)) if cond else sel
    return CompiledRule(defn, pred, ctx.fields)


_TEMPLATE_FIELD = re.compile(r"\{([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,4})\}")


def render_summary(template: str, event: dict) -> str:
    """'{process.name} spawned by {process.parent_name}' -> values from the event. Not str.format:
    only dict-key lookups, values truncated."""
    def sub(m: re.Match) -> str:
        v = get_path(event, m.group(1))
        return "?" if v in (None, "", []) else str(v)[:200]
    return _TEMPLATE_FIELD.sub(sub, template)
