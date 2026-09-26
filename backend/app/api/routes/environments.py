from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Environment, RuleAssignment
from sentinelforge.schemas.rule import AssignmentStatusUpdate
from app.services import environments, rules
from app.services.detection.engine import engine

router = APIRouter(tags=["environments"])


def _env(db: Session, env_id: int) -> Environment:
    env = db.get(Environment, env_id)
    if not env:
        raise HTTPException(404, "environment not found")
    return env


@router.get("/environments")
def list_environments(db: Session = Depends(get_db)):
    return [environments.summary(db, e) for e in db.scalars(select(Environment).order_by(Environment.id))]


@router.get("/environments/{env_id}")
def get_environment(env_id: int, db: Session = Depends(get_db)):
    return environments.detail(db, _env(db, env_id))


@router.post("/profiles/{env_id}/generate-rules")
def generate_rules(env_id: int, db: Session = Depends(get_db)):
    env = _env(db, env_id)
    if not env.profiles:
        raise HTTPException(409, "environment has no profile yet")
    counts = rules.generate_rules(db, env)
    return {"environment_id": env.id, "counts": counts, "rules": environments.assignments(db, env.id)}


@router.patch("/environments/{env_id}/rules/{assignment_id}")
def set_assignment_status(env_id: int, assignment_id: int, body: AssignmentStatusUpdate, db: Session = Depends(get_db)):
    a = db.get(RuleAssignment, assignment_id)
    if not a or a.environment_id != env_id:
        raise HTTPException(404, "assignment not found")
    if a.status not in ("active", "disabled") or a.generated is None:
        raise HTTPException(409, f"cannot change a rule in status {a.status!r}")
    a.status = body.status
    db.commit()
    engine.invalidate(env_id)
    return {"assignment_id": a.id, "status": a.status}
