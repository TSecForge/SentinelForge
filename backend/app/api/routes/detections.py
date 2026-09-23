from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.serializers import detection_out, event_out
from app.db.session import get_db
from app.models import Detection, DeliveryAttempt, Event
from app.utils import iso

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("")
def list_detections(db: Session = Depends(get_db), host: str | None = None, severity: str | None = None,
                    rule_id: str | None = None, technique: str | None = None, q: str | None = Query(None, max_length=200),
                    since: datetime | None = None, until: datetime | None = None,
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    stmt = select(Detection)
    for col, val in ((Detection.host, host), (Detection.severity, severity), (Detection.rule_id, rule_id),
                     (Detection.mitre_technique, technique)):
        if val:
            stmt = stmt.where(col == val)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Detection.description.ilike(like), Detection.rule_name.ilike(like), Detection.host.ilike(like)))
    if since:
        stmt = stmt.where(Detection.timestamp >= since)
    if until:
        stmt = stmt.where(Detection.timestamp <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.options(selectinload(Detection.observables)).order_by(Detection.timestamp.desc(), Detection.id.desc())
                      .limit(limit).offset(offset)).all()
    return {"total": total, "items": [detection_out(d) for d in rows]}


@router.get("/{detection_id}")
def get_detection(detection_id: str, db: Session = Depends(get_db)):
    d = db.scalar(select(Detection).where(Detection.detection_id == detection_id))
    if not d and detection_id.isdigit():
        d = db.get(Detection, int(detection_id))
    if not d:
        raise HTTPException(404, "detection not found")
    ev = db.get(Event, d.event_pk) if d.event_pk else None
    attempts = db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.detection_pk == d.id).order_by(DeliveryAttempt.id)).all()
    return {**detection_out(d, full=True), "source_event": event_out(ev, full=True) if ev else None,
            "delivery_attempts": [{"adapter": a.adapter, "success": a.success, "status_code": a.status_code,
                                   "error": a.error, "latency_ms": a.latency_ms, "at": iso(a.attempted_at)} for a in attempts]}
