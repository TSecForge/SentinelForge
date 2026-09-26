import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from starlette.concurrency import run_in_threadpool
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import event_out
from app.core.config import get_settings
from app.db.session import get_db
from app.models import Event
from sentinelforge.schemas.event import EventBatchIn, EventIn
from app.services.detection.pipeline import ingest

router = APIRouter(prefix="/events", tags=["events"])
ingest_router = APIRouter(tags=["events"])

SOURCE_RE = r"^[a-z][a-z0-9_]{1,31}$"
HOST_RE = r"^[A-Za-z0-9][A-Za-z0-9.\-_]{0,254}$"


def _parse_body(body: bytes) -> list:
    text = body.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:  # NDJSON (Vector, Fluent Bit json_lines, `docker events --format '{{json .}}'`)
        try:
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"body is neither JSON nor NDJSON: {e}") from e
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):
        return doc["events"]
    if isinstance(doc, dict) and doc.get("kind") == "EventList" and isinstance(doc.get("items"), list):
        return doc["items"]  # kube-apiserver audit webhook batch
    return doc if isinstance(doc, list) else [doc]


@ingest_router.post("/ingest/{source}")
async def ingest_raw(request: Request, source: str = Path(pattern=SOURCE_RE),
                     host: str | None = Query(None, pattern=HOST_RE), db: Session = Depends(get_db)):
    """Log-shipper endpoint: raw records of one source, as a JSON array, one object, {"events": [...]} or NDJSON.
    `host` fills in the hostname for records that don't carry one (Docker events, Kubernetes audit logs)."""
    records = _parse_body(await request.body())
    if len(records) > get_settings().max_batch_events:
        raise HTTPException(413, f"more than MAX_BATCH_EVENTS={get_settings().max_batch_events} records")
    items = []
    for r in records:
        if not isinstance(r, dict):
            raise HTTPException(422, "every record must be a JSON object")
        if host:
            r.setdefault("host", host)
        items.append(EventIn(source=source, data=r))
    return await run_in_threadpool(ingest, db, items)


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
