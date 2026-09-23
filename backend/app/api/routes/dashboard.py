from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.api.serializers import detection_out
from app.db.session import get_db
from app.models import Detection, Environment, Event, RuleAssignment
from app.services import metrics
from app.utils import as_utc, iso

router = APIRouter(tags=["dashboard"])


@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    return metrics.get_metrics(db)


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    sev = dict(db.execute(select(Detection.severity, func.count()).group_by(Detection.severity)).all())
    top_rules = db.execute(select(Detection.rule_id, Detection.rule_name, func.count().label("n"))
                           .group_by(Detection.rule_id, Detection.rule_name).order_by(func.count().desc()).limit(8)).all()
    techniques = db.execute(select(Detection.mitre_technique, Detection.mitre_tactic, func.count())
                            .where(Detection.mitre_technique.is_not(None))
                            .group_by(Detection.mitre_technique, Detection.mitre_tactic).order_by(func.count().desc()).limit(10)).all()
    recent = db.scalars(select(Detection).options(selectinload(Detection.observables))
                        .order_by(Detection.timestamp.desc(), Detection.id.desc()).limit(8)).all()

    # Event volume: 5-minute buckets over the most recent 2 hours of event time.
    rows = db.execute(select(Event.timestamp, Event.matched).order_by(Event.timestamp.desc()).limit(20000)).all()
    volume = []
    if rows:
        end = as_utc(rows[0][0])
        start = end - timedelta(hours=2)
        buckets: Counter = Counter()
        matched: Counter = Counter()
        for ts, m in rows:
            ts = as_utc(ts)
            if ts < start:
                continue
            b = int((ts - start).total_seconds() // 300)
            buckets[b] += 1
            matched[b] += int(m)
        for b in range(0, 25):
            volume.append({"t": iso(start + timedelta(minutes=5 * b)), "events": buckets[b], "matched": matched[b]})

    return {
        "hosts": db.scalar(select(func.count()).select_from(Environment)) or 0,
        "simulated_hosts": db.scalar(select(func.count()).select_from(Environment).where(Environment.simulated.is_(True))) or 0,
        "active_rules": db.scalar(select(func.count()).select_from(RuleAssignment).where(RuleAssignment.status == "active")) or 0,
        "distinct_active_rules": db.scalar(select(func.count(func.distinct(RuleAssignment.rule_id))).where(RuleAssignment.status == "active")) or 0,
        "detections": sum(sev.values()),
        "high_severity": sev.get("high", 0) + sev.get("critical", 0),
        "severity_distribution": [{"severity": s, "count": sev.get(s, 0)} for s in ("critical", "high", "medium", "low", "informational")],
        "metrics": metrics.get_metrics(db),
        "recent_detections": [detection_out(d) for d in recent],
        "event_volume": volume,
        "top_rules": [{"rule_id": r, "name": n, "count": c} for r, n, c in top_rules],
        "mitre": [{"technique": t, "tactic": ta, "count": c} for t, ta, c in techniques],
    }
