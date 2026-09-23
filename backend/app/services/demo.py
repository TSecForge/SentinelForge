"""Demo Mode orchestration: DISCOVER -> PROFILE -> GENERATE RULES -> SIMULATE -> DETECT -> ENRICH -> FORWARD."""

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import (DeliveryAttempt, Detection, Environment, EnvironmentProfile, Event, Observable,
                        PipelineCounter, RuleAssignment)
from app.services import discovery, environments, rules
from app.services.detection.engine import engine
from app.services.detection.pipeline import ingest
from app.services.simulation import SCENARIOS, benign_events, scenario_events, scenarios_for
from app.services.siem.gateway import local_sink


def create_demo_environment(db: Session, template: str = "windows-web-server") -> Environment:
    inv = discovery.load_demo_inventory(template)
    return environments.upsert_environment(db, inv, "demo")


def simulate(db: Session, env: Environment, scenario_names: list[str] | None, benign_count: int) -> dict:
    profile = env.profiles[-1].profile
    if scenario_names == ["all"] or scenario_names is None:
        scenario_names = scenarios_for(env.platform, profile.get("technologies", []))
    unknown = [n for n in scenario_names if n not in SCENARIOS]
    if unknown:
        raise KeyError(f"unknown scenarios: {unknown}")
    items = benign_events(env.hostname, env.platform, profile, benign_count) + scenario_events(scenario_names, env.hostname)
    result = ingest(db, items)
    return {"scenarios": scenario_names, "benign_events": benign_count, "result": result.model_dump()}


def run_full_demo(db: Session, template: str = "windows-web-server", benign_count: int = 1000) -> dict:
    env = create_demo_environment(db, template)
    counts = rules.generate_rules(db, env)
    sim = simulate(db, env, None, benign_count)
    return {"environment_id": env.id, "hostname": env.hostname, "rules": counts, **sim}


def reset(db: Session) -> None:
    """Delete environments, events, detections and counters (rule templates are kept)."""
    for model in (Observable, DeliveryAttempt, Detection, Event, RuleAssignment, EnvironmentProfile, Environment, PipelineCounter):
        db.execute(delete(model))
    db.commit()
    engine.reset_state()
    local_sink.clear()
