"""Pipeline counters and the event-reduction calculation."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PipelineCounter

COUNTERS = [
    "events_received",    # records submitted to the pipeline
    "events_rejected",    # failed normalization/validation
    "events_duplicate",   # event_id already seen (replay protection)
    "events_evaluated",   # normalized and run through the detection engine
    "events_matched",     # evaluated events that matched at least one rule
    "events_filtered",    # evaluated events that matched nothing (not forwarded)
    "detections_created", # detection documents; one event matching two rules yields two
    "events_forwarded",   # source events that left the filter as >=1 detection (to the SIEM, or the local store when SIEM is disabled)
    "siem_delivered",
    "siem_failed",
]


def bump(db: Session, **counts: int) -> None:
    for name, n in counts.items():
        if not n:
            continue
        row = db.get(PipelineCounter, name)
        if row is None:
            row = PipelineCounter(name=name, value=0)
            db.add(row)
        row.value += n


def reduction_percentage(received: int, forwarded: int) -> float:
    """(received - forwarded) / received * 100, for the workload actually measured."""
    if received <= 0:
        return 0.0
    return round((received - forwarded) / received * 100, 2)


def get_metrics(db: Session) -> dict:
    values = {c: 0 for c in COUNTERS}
    for row in db.scalars(select(PipelineCounter)):
        values[row.name] = row.value
    values["reduction_percentage"] = reduction_percentage(values["events_received"], values["events_forwarded"])
    values["statement"] = (
        f"In this workload, SentinelForge forwarded {values['events_forwarded']:,} of {values['events_received']:,} "
        f"received events as {values['detections_created']:,} detection(s) "
        f"({values['reduction_percentage']}% fewer events sent downstream)."
        if values["events_received"] else "No events processed yet."
    )
    return values
