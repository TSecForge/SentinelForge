"""Event pipeline: normalize -> dedupe -> find applicable rules -> evaluate -> enrich -> IOC -> persist -> forward."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import Detection, Environment, Event, Observable, RuleAssignment
from app.schemas.event import EventIn, IngestResult
from app.schemas.rule import SEVERITY_ORDER
from app.services import metrics
from app.services.detection.engine import engine
from app.services.enrichment import build_detection
from app.services.normalization import NormalizationError, normalize
from app.services.siem import gateway
from app.utils import utcnow

log = get_logger("pipeline")


def _environment_index(db: Session) -> dict[str, dict]:
    out = {}
    for env in db.scalars(select(Environment)):
        if env.profiles:
            out[env.hostname.lower()] = {"id": env.id, "profile": env.profiles[-1].profile}
    return out


def ingest(db: Session, items: list[EventIn], forward: bool = True) -> IngestResult:
    settings = get_settings()
    res = IngestResult(received=len(items), accepted=0, duplicates=0, rejected=0, matched=0, detections=0)
    normalized = []
    for i, item in enumerate(items):
        try:
            normalized.append(normalize(item))
        except NormalizationError as e:
            res.rejected += 1
            if len(res.errors) < 20:
                res.errors.append(f"[{i}] {e}")

    ids = [e.event_id for e in normalized]
    known: set[str] = set()
    for i in range(0, len(ids), 500):
        known |= set(db.scalars(select(Event.event_id).where(Event.event_id.in_(ids[i:i + 500]))))

    envs = _environment_index(db)
    created: list[Detection] = []
    for ev in normalized:
        if ev.event_id in known:
            res.duplicates += 1
            continue
        known.add(ev.event_id)
        res.accepted += 1
        evd = ev.model_dump(mode="json", exclude_none=True)
        env = envs.get(ev.host.lower())
        env_id = env["id"] if env else None
        hits = engine.evaluate(evd, ev.timestamp, engine.rules_for(db, env_id), env_id)
        if not hits and not settings.store_unmatched_events:
            continue
        row = Event(event_id=ev.event_id, timestamp=ev.timestamp, source=ev.source, host=ev.host, event_type=ev.event_type,
                    environment_id=env_id, simulated=ev.simulated, matched=bool(hits), data=evd,
                    max_severity=max((c.definition.severity for c, _ in hits), key=SEVERITY_ORDER.get) if hits else None)
        db.add(row)
        if not hits:
            continue
        res.matched += 1
        db.flush()
        for cr, assignment in hits:
            doc = build_detection(evd, cr, env, assignment)
            d = cr.definition
            det = Detection(detection_id=doc["detection_id"], timestamp=ev.timestamp, host=ev.host, environment_id=env_id,
                            event_pk=row.id, rule_id=d.id, rule_name=d.name, rule_version=d.version, severity=d.severity,
                            confidence=doc["confidence"], event_type=ev.event_type, description=doc["summary"],
                            mitre_tactic=d.mitre.tactic if d.mitre else None, mitre_technique=d.mitre.technique if d.mitre else None,
                            simulated=ev.simulated, payload=doc,
                            observables=[Observable(type=o["type"], value=o["value"]) for o in doc["observables"]])
            db.add(det)
            created.append(det)
            if assignment and (a := db.get(RuleAssignment, assignment["id"])):
                a.trigger_count += 1
                a.last_triggered_at = utcnow()
            log.info("detection.matched", rule_id=d.id, host=ev.host, severity=d.severity, event_id=ev.event_id, simulated=ev.simulated)

    metrics.bump(db, events_received=res.received, events_rejected=res.rejected, events_duplicate=res.duplicates,
                 events_evaluated=res.accepted, events_matched=res.matched, events_filtered=res.accepted - res.matched,
                 detections_created=len(created), events_forwarded=res.matched)
    db.commit()
    log.info("event.batch_processed", received=res.received, accepted=res.accepted, matched=res.matched,
             detections=len(created), rejected=res.rejected, duplicates=res.duplicates)
    if created and forward:
        gateway.forward(db, created)
    res.detections = len(created)
    res.detection_ids = [d.detection_id for d in created][:500]
    return res
