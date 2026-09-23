"""Persisting inventories/profiles and shaping environment views."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Environment, EnvironmentProfile as ProfileRow, RuleAssignment
from app.schemas.inventory import Inventory
from app.services.profiling import build_profile
from app.utils import iso


def upsert_environment(db: Session, inv: Inventory, mode: str) -> Environment:
    """Store an inventory and a fresh profile. Re-discovery of the same hostname keeps history (new profile row)."""
    profile = build_profile(inv)
    env = db.scalar(select(Environment).where(func.lower(Environment.hostname) == inv.host.hostname.lower()))
    data = inv.model_dump(mode="json")
    if env is None:
        env = Environment(hostname=inv.host.hostname, platform=inv.host.platform, os=inv.host.os, discovery_mode=mode,
                          simulated=inv.simulated, inventory=data)
        db.add(env)
    else:
        env.platform, env.os, env.discovery_mode, env.simulated, env.inventory = inv.host.platform, inv.host.os, mode, inv.simulated, data
    db.flush()
    db.add(ProfileRow(environment_id=env.id, profile=profile.model_dump(mode="json")))
    db.commit()
    db.refresh(env)
    return env


def summary(db: Session, env: Environment) -> dict:
    p = env.profiles[-1].profile if env.profiles else {}
    active = db.scalar(select(func.count()).select_from(RuleAssignment).where(
        RuleAssignment.environment_id == env.id, RuleAssignment.status == "active")) or 0
    return {
        "id": env.id, "hostname": env.hostname, "platform": env.platform, "os": env.os, "discovery_mode": env.discovery_mode,
        "simulated": env.simulated, "discovered_at": iso(env.discovered_at), "technologies": p.get("technologies", []),
        "environment_type": p.get("environment_type", []), "ip_addresses": p.get("network", {}).get("ip_addresses", []),
        "cidrs": p.get("network", {}).get("cidrs", []), "active_rules": active,
    }


def assignments(db: Session, env_id: int) -> list[dict]:
    rows = db.scalars(select(RuleAssignment).where(RuleAssignment.environment_id == env_id, RuleAssignment.status != "superseded")
                      .order_by(RuleAssignment.rule_id)).all()
    return [{"assignment_id": a.id, "rule_id": a.rule_id, "version": a.rule_version, "name": a.rule.name,
             "severity": a.rule.severity, "platform": a.rule.platform, "event_type": a.rule.event_type,
             "mitre_technique": a.rule.mitre_technique, "source": a.rule.source, "status": a.status, "reason": a.reason,
             "trigger_count": a.trigger_count, "last_triggered_at": iso(a.last_triggered_at), "generated_at": iso(a.generated_at),
             "generated": a.generated} for a in rows]


def detail(db: Session, env: Environment) -> dict:
    return {**summary(db, env), "inventory": env.inventory, "profile": env.profiles[-1].profile if env.profiles else None,
            "profile_id": env.profiles[-1].id if env.profiles else None, "profile_count": len(env.profiles),
            "rules": assignments(db, env.id)}
