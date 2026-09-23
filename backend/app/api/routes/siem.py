from typing import Any

from fastapi import APIRouter, Body, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.siem import gateway
from app.utils import iso, utcnow

router = APIRouter(prefix="/siem", tags=["siem"])


@router.get("/status")
def siem_status(db: Session = Depends(get_db)):
    return gateway.status(db)


@router.post("/test")
def siem_test(db: Session = Depends(get_db)):
    return gateway.test_connection(db)


@router.post("/events", status_code=202)
def receive_webhook(doc: dict[str, Any] = Body(...)):
    """Built-in generic-webhook receiver for demos/tests. Point WEBHOOK_URL at
    http://localhost:8000/api/v1/siem/events to see forwarded detections without an external SIEM."""
    gateway.local_sink.appendleft({"received_at": iso(utcnow()), "document": doc})
    return {"accepted": True}


@router.get("/events")
def list_received():
    return {"count": len(gateway.local_sink), "items": list(gateway.local_sink)[:50]}
