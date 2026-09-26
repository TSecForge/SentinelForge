from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Environment, Rule, RuleAssignment
from sentinelforge.schemas.rule import RuleValidateRequest
from app.services import rules
from app.services.detection.engine import engine
from sentinelforge.rules.loader import validate_rule_text
from app.utils import iso

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("")
def list_rules(db: Session = Depends(get_db)):
    hosts = {e.id: e.hostname for e in db.scalars(select(Environment))}
    by_rule: dict[str, list] = defaultdict(list)
    for a in db.scalars(select(RuleAssignment).where(RuleAssignment.status != "superseded")):
        by_rule[a.rule_id].append({"environment_id": a.environment_id, "hostname": hosts.get(a.environment_id),
                                   "status": a.status, "reason": a.reason, "trigger_count": a.trigger_count})
    out = []
    for r in rules.current_templates(db):
        d = r.definition
        envs = by_rule.get(r.rule_id, [])
        out.append({"rule_id": r.rule_id, "version": r.version, "name": r.name, "platform": r.platform,
                    "event_type": r.event_type, "severity": r.severity, "source": r.source, "author": r.author,
                    "category": d.get("category"), "status": d.get("status"), "mitre_technique": r.mitre_technique,
                    "mitre_tactic": (d.get("mitre") or {}).get("tactic"), "applies_when": d.get("applies_when"),
                    "active_environments": sum(1 for e in envs if e["status"] == "active"),
                    "triggers": sum(e["trigger_count"] for e in envs), "environments": envs})
    return out


@router.get("/load-errors")
def load_errors():
    return rules.last_load_errors


@router.post("/reload")
def reload_rules(db: Session = Depends(get_db)):
    """Re-read RULE_PATHS. New versions are added; changed content without a version bump is refused."""
    result = rules.sync_rule_store(db)
    engine.invalidate()
    return result


@router.post("/validate")
def validate_rule(body: RuleValidateRequest):
    """Validate a YAML rule without storing it (schema, safe-YAML, operator and regex compile checks)."""
    _, result = validate_rule_text(body.yaml)
    return result


@router.get("/{rule_id}")
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    versions = db.scalars(select(Rule).where(Rule.rule_id == rule_id).order_by(Rule.id)).all()
    if not versions:
        raise HTTPException(404, "rule not found")
    cur = next((v for v in versions if v.status == "validated"), versions[-1])
    hosts = {e.id: e.hostname for e in db.scalars(select(Environment))}
    assigns = db.scalars(select(RuleAssignment).where(RuleAssignment.rule_id == rule_id).order_by(RuleAssignment.id)).all()
    return {"rule_id": rule_id, "version": cur.version, "definition": cur.definition, "yaml": cur.yaml_text,
            "file_path": cur.file_path, "loaded_at": iso(cur.loaded_at),
            "versions": [{"version": v.version, "status": v.status, "loaded_at": iso(v.loaded_at), "content_hash": v.content_hash[:12]} for v in versions],
            "assignments": [{"assignment_id": a.id, "environment_id": a.environment_id, "hostname": hosts.get(a.environment_id),
                             "version": a.rule_version, "status": a.status, "reason": a.reason, "trigger_count": a.trigger_count,
                             "generated_at": iso(a.generated_at), "generated": a.generated} for a in assigns]}
