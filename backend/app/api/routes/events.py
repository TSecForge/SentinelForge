from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import event_out
from app.core.config import get_settings
from app.db.session import get_db
from app.models import Event
from app.schemas.event import EventBatchIn, EventIn
from app.services.detection.pipeline import ingest

router = APIRouter(prefix="/events", tags=["events"])


@router.post("")
def ingest_one(item: EventIn, db: Session = Depends(get_db)):
    return ingest(db, [item])


@router.post("/batch")
def ingest_batch(batch: EventBatchIn, db: Session = Depends(get_db)):
    if len(batch.events) > get_settings().max_batch_events:
        raise HTTPException(413, f"batch larger than MAX_BATCH_EVENTS={get_settings().max_batch_events}")
    return ingest(db, batch.events)


@router.get("")
def list_events(db: Session = Depends(get_db), host: str | None = None, source: str | None = None,
                event_type: str | None = None, severity: str | None = None, matched: bool | None = None,
                simulated: bool | None = None, since: datetime | None = None, until: datetime | None = None,
                limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    q = select(Event)
    for col, val in ((Event.host, host), (Event.source, source), (Event.event_type, event_type),
                     (Event.max_severity, severity), (Event.matched, matched), (Event.simulated, simulated)):
        if val is not None:
            q = q.where(col == val)
    if since:
        q = q.where(Event.timestamp >= since)
    if until:
        q = q.where(Event.timestamp <= until)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(Event.timestamp.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [event_out(e) for e in rows]}


@router.get("/facets")
def event_facets(db: Session = Depends(get_db)):
    return {c: sorted(v for v in db.scalars(select(getattr(Event, c)).distinct()) if v)
            for c in ("host", "source", "event_type", "max_severity")}


@router.get("/{event_pk}")
def get_event(event_pk: int, db: Session = Depends(get_db)):
    e = db.get(Event, event_pk)
    if not e:
        raise HTTPException(404, "event not found")
    return event_out(e, full=True)
