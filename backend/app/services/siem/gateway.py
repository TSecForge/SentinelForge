"""SIEM Gateway: routes detection events to the configured adapter and records every delivery attempt.
Delivery failures never lose a detection - it stays in the local store with delivery_status=failed."""

import time
from collections import deque

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import DeliveryAttempt, Detection
from sentinelforge.registry import registry
from app.services import metrics
from app.services.siem import adapters as _builtin  # noqa: F401  (registers built-in adapters)
from app.utils import iso, utcnow

log = get_logger("siem")

# Built-in local receiver for POST /api/v1/siem/events, so the webhook path can be demoed without a SIEM.
local_sink: deque = deque(maxlen=200)


def get_adapter():
    mode = get_settings().siem_mode
    if mode == "disabled":
        return None
    factory = registry.siem_adapters.get(mode)
    return factory(get_settings()) if factory else None


def forward(db: Session, detections: list[Detection]) -> dict:
    adapter = get_adapter()
    if adapter is None or not adapter.configured():
        return {"mode": get_settings().siem_mode, "delivered": 0, "failed": 0, "note": "stored locally"}
    delivered = failed = 0
    for det in detections:
        t0 = time.perf_counter()
        ok, code, err = adapter.send(det.payload)
        db.add(DeliveryAttempt(detection_pk=det.id, adapter=adapter.name, success=ok, status_code=code, error=err,
                               latency_ms=round((time.perf_counter() - t0) * 1000, 1)))
        det.delivery_status = "delivered" if ok else "failed"
        if ok:
            delivered += 1
            log.info("siem.forwarded", adapter=adapter.name, detection_id=det.detection_id, status=code)
        else:
            failed += 1
            log.warning("siem.failed", adapter=adapter.name, detection_id=det.detection_id, status=code, error=err)
    metrics.bump(db, siem_delivered=delivered, siem_failed=failed)
    db.commit()
    return {"mode": adapter.name, "delivered": delivered, "failed": failed}


def test_connection(db: Session) -> dict:
    adapter = get_adapter()
    if adapter is None:
        return {"ok": False, "mode": "disabled", "message": "SIEM_MODE=disabled; detections are stored locally only"}
    if not adapter.configured():
        return {"ok": False, "mode": adapter.name, "message": f"{adapter.name} adapter is not fully configured"}
    doc = {"schema": "sentinelforge.test.v1", "timestamp": iso(utcnow()), "host": "sentinelforge",
           "message": "SentinelForge SIEM connectivity test", "simulated": True}
    t0 = time.perf_counter()
    ok, code, err = adapter.send(doc)
    db.add(DeliveryAttempt(detection_pk=None, adapter=adapter.name, success=ok, status_code=code, error=err,
                           latency_ms=round((time.perf_counter() - t0) * 1000, 1)))
    db.commit()
    log.info("siem.test", adapter=adapter.name, ok=ok, status=code)
    return {"ok": ok, "mode": adapter.name, "status_code": code, "error": err, "target": adapter.target()}


def status(db: Session) -> dict:
    s = get_settings()
    adapter = get_adapter()
    last_ok = db.scalar(select(func.max(DeliveryAttempt.attempted_at)).where(DeliveryAttempt.success.is_(True)))
    last_fail = db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.success.is_(False)).order_by(DeliveryAttempt.id.desc()).limit(1)).first()
    recent = db.scalars(select(DeliveryAttempt).order_by(DeliveryAttempt.id.desc()).limit(20)).all()
    return {
        "mode": s.siem_mode,
        "available_adapters": sorted(["disabled", *registry.siem_adapters]),
        "configured": bool(adapter and adapter.configured()),
        "target": adapter.target() if adapter else None,  # redacted, never includes tokens
        "delivered": db.scalar(select(func.count()).select_from(DeliveryAttempt).where(DeliveryAttempt.success.is_(True))) or 0,
        "failed": db.scalar(select(func.count()).select_from(DeliveryAttempt).where(DeliveryAttempt.success.is_(False))) or 0,
        "pending_local": db.scalar(select(func.count()).select_from(Detection).where(Detection.delivery_status == "local")) or 0,
        "last_success": iso(last_ok),
        "last_error": {"at": iso(last_fail.attempted_at), "status_code": last_fail.status_code, "error": last_fail.error} if last_fail else None,
        "recent_attempts": [{"id": a.id, "adapter": a.adapter, "success": a.success, "status_code": a.status_code,
                             "latency_ms": a.latency_ms, "at": iso(a.attempted_at), "error": a.error} for a in recent],
        "local_sink_received": len(local_sink),
    }
