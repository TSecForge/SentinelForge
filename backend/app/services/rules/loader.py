"""Rule pack loading and validation (YAML -> RuleDefinition -> compile check)."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.schemas.environment import RuleParameters
from app.schemas.rule import RuleDefinition, RuleValidationResult
from app.services.rules.evaluator import RuleCompileError, compile_rule, find_profile_refs, resolve_profile_refs

MAX_RULE_BYTES = 64 * 1024
ALLOWED_PROFILE_REFS = set(RuleParameters.model_fields)
# Placeholder values used only to check that a template compiles once refs are filled in.
_PLACEHOLDER = {"listening_ports": [1], "approved_images": ["x:latest"], "container_ports": [1],
                "internal_cidrs": ["10.0.0.0/8"], "known_admins": ["administrator"]}


@dataclass
class LoadedRule:
    definition: RuleDefinition
    yaml_text: str
    path: str


@dataclass
class LoadReport:
    rules: list[LoadedRule] = field(default_factory=list)
    errors: dict[str, list[str]] = field(default_factory=dict)


def _safe_yaml(text: str):
    """yaml.safe_load, but anchors/aliases are refused outright (alias-expansion / billion-laughs)."""
    for tok in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(tok, (yaml.AliasToken, yaml.AnchorToken)):
            raise ValueError("YAML anchors/aliases are not allowed in rules")
    return yaml.safe_load(text)


def validate_rule_text(text: str) -> tuple[RuleDefinition | None, RuleValidationResult]:
    if len(text.encode()) > MAX_RULE_BYTES:
        return None, RuleValidationResult(valid=False, errors=[f"rule larger than {MAX_RULE_BYTES} bytes"])
    try:
        data = _safe_yaml(text)
    except (yaml.YAMLError, ValueError) as e:
        return None, RuleValidationResult(valid=False, errors=[f"YAML error: {e}"])
    if not isinstance(data, dict):
        return None, RuleValidationResult(valid=False, errors=["rule must be a YAML mapping"])
    try:
        defn = RuleDefinition.model_validate(data)
    except ValidationError as e:
        errs = [f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()]
        return None, RuleValidationResult(valid=False, rule_id=data.get("id") if isinstance(data.get("id"), str) else None, errors=errs)
    refs = find_profile_refs({"s": defn.selection, "c": defn.condition})
    errors = [f"unknown profile reference $profile.{r} (allowed: {sorted(ALLOWED_PROFILE_REFS)})" for r in refs if r not in ALLOWED_PROFILE_REFS]
    if not errors:
        try:
            compile_rule(resolve_template(defn, _PLACEHOLDER))
        except RuleCompileError as e:
            errors.append(str(e))
    return (None if errors else defn), RuleValidationResult(valid=not errors, rule_id=defn.id, errors=errors, profile_references=refs)


def resolve_template(defn: RuleDefinition, params: dict) -> RuleDefinition:
    data = defn.model_dump()
    data["selection"] = resolve_profile_refs(defn.selection, params)
    data["condition"] = resolve_profile_refs(defn.condition, params) if defn.condition else None
    return RuleDefinition.model_validate(data)


def load_rule_paths(paths: list[str]) -> LoadReport:
    report = LoadReport()
    seen: dict[tuple[str, str], str] = {}
    for base in paths:
        root = Path(base)
        if not root.is_dir():
            continue
        for f in sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")]):
            text = f.read_text(encoding="utf-8")
            defn, result = validate_rule_text(text)
            if not defn:
                report.errors[str(f)] = result.errors
                continue
            key = (defn.id, defn.version)
            if key in seen:
                report.errors[str(f)] = [f"duplicate rule {defn.id} v{defn.version} (already loaded from {seen[key]})"]
                continue
            seen[key] = str(f)
            report.rules.append(LoadedRule(defn, text, str(f)))
    return report
