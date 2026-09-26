"""Rule Store + Rule Writer Engine.

Separation of concerns:
    templates   - static security knowledge in YAML rule packs (loader.py)
    matching    - does a template apply to this environment? (applicability)
    generation  - produce the environment-specific rule (resolve $profile.* refs)
    validation  - schema + compile check, before anything becomes active
    execution   - app.services.detection (never here)
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import Environment, EnvironmentProfile as ProfileRow, Rule, RuleAssignment
from app.schemas.environment import EnvironmentProfile
from sentinelforge.schemas.rule import RuleDefinition
from sentinelforge.rules.evaluator import RuleCompileError, compile_rule
from sentinelforge.rules.loader import LoadReport, load_rule_paths, resolve_template
from sentinelforge.rules.selection import applicability  # noqa: F401  (re-exported)
from app.utils import stable_hash

log = get_logger("rules")

last_load_errors: dict[str, list[str]] = {}


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def sync_rule_store(db: Session) -> dict:
    """Load rule packs from RULE_PATHS into the store. Existing (id, version) rows are never overwritten;
    changed content without a version bump is rejected and reported."""
    global last_load_errors
    report: LoadReport = load_rule_paths(get_settings().split(get_settings().rule_paths))
    errors = dict(report.errors)
    new = unchanged = 0
    for lr in report.rules:
        d = lr.definition
        h = stable_hash(d.model_dump())
        row = db.scalar(select(Rule).where(Rule.rule_id == d.id, Rule.version == d.version))
        if row:
            if row.content_hash != h:
                errors[lr.path] = [f"{d.id} v{d.version} changed on disk without a version bump; stored version kept"]
            else:
                unchanged += 1
            continue
        db.add(Rule(rule_id=d.id, version=d.version, name=d.name, platform=d.platform, event_type=d.event_type,
                    severity=d.severity, source=d.source, author=d.author,
                    mitre_technique=d.mitre.technique if d.mitre else None, definition=d.model_dump(),
                    yaml_text=lr.yaml_text, content_hash=h, file_path=lr.path))
        new += 1
    db.flush()
    # mark older versions superseded
    latest: dict[str, Rule] = {}
    for r in db.scalars(select(Rule)):
        if r.rule_id not in latest or _vkey(r.version) > _vkey(latest[r.rule_id].version):
            latest[r.rule_id] = r
    for r in db.scalars(select(Rule)):
        r.status = "validated" if latest[r.rule_id].id == r.id else "superseded"
    db.commit()
    last_load_errors = errors
    for path, errs in errors.items():
        log.warning("rules.load_error", path=path, errors=errs)
    log.info("rules.loaded", new=new, unchanged=unchanged, errors=len(errors), total=len(latest))
    return {"new": new, "unchanged": unchanged, "total": len(latest), "errors": errors}


def current_templates(db: Session) -> list[Rule]:
    return list(db.scalars(select(Rule).where(Rule.status == "validated").order_by(Rule.rule_id)))


def generate_rules(db: Session, env: Environment) -> dict:
    """Rule Writer: match every current template against the environment's latest profile and write
    versioned assignments. Unchanged assignments are kept; changed ones supersede the old row."""
    profile_row: ProfileRow = env.profiles[-1]
    profile = EnvironmentProfile.model_validate(profile_row.profile)
    params = profile.parameters.model_dump()
    auto = get_settings().auto_activate_rules

    existing = {a.rule_id: a for a in db.scalars(select(RuleAssignment).where(
        RuleAssignment.environment_id == env.id, RuleAssignment.status != "superseded"))}
    counts = {"active": 0, "disabled": 0, "not_applicable": 0, "rejected": 0, "unchanged": 0, "new_or_updated": 0}

    for tpl in current_templates(db):
        defn = RuleDefinition.model_validate(tpl.definition)
        ok, reason = applicability(defn, profile)
        generated, status = None, "not_applicable"
        if ok:
            try:
                resolved = resolve_template(defn, params)
                compile_rule(resolved)  # deterministic validation gate before activation
                generated, status = resolved.model_dump(), "active" if auto else "disabled"
            except (RuleCompileError, ValueError) as e:
                status, reason = "rejected", f"generation failed validation: {e}"

        prev = existing.get(defn.id)
        if prev and prev.status == "disabled" and status == "active":
            status = "disabled"  # respect an analyst's decision to disable
        if prev and prev.rule_version == tpl.version and prev.status == status and stable_hash(prev.generated) == stable_hash(generated):
            prev.profile_id, prev.reason = profile_row.id, reason
            counts["unchanged"] += 1
        else:
            if prev:
                prev.status = "superseded"
            db.add(RuleAssignment(environment_id=env.id, profile_id=profile_row.id, rule_pk=tpl.id, rule_id=defn.id,
                                  rule_version=tpl.version, status=status, reason=reason, generated=generated,
                                  trigger_count=prev.trigger_count if prev and prev.rule_version == tpl.version else 0,
                                  last_triggered_at=prev.last_triggered_at if prev and prev.rule_version == tpl.version else None))
            counts["new_or_updated"] += 1
        counts[status] += 1
    db.commit()
    from app.services.detection.engine import engine  # local import: avoid cycle
    engine.invalidate(env.id)
    log.info("rules.generated", host=env.hostname, **counts)
    return counts
