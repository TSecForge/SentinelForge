from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Environment
from app.services import demo, discovery, environments
from app.services.simulation import SCENARIOS, scenarios_for

router = APIRouter(prefix="/demo", tags=["demo"])


class DemoEnvRequest(BaseModel):
    template: str = Field("windows-web-server", pattern=r"^[a-z0-9\-]{1,64}$")


class SimulateRequest(BaseModel):
    environment_id: int
    scenarios: list[str] = Field(default_factory=lambda: ["office_powershell"], max_length=50)
    benign_count: int = Field(0, ge=0, le=20000)


class DemoRunRequest(DemoEnvRequest):
    benign_count: int = Field(1000, ge=0, le=20000)


@router.get("/scenarios")
def list_scenarios(environment_id: int | None = None, db: Session = Depends(get_db)):
    relevant = None
    if environment_id and (env := db.get(Environment, environment_id)) and env.profiles:
        relevant = set(scenarios_for(env.platform, env.profiles[-1].profile.get("technologies", [])))
    return [{"name": k, "title": s.title, "description": s.description, "platform": s.platform,
             "expected_rules": s.expected_rules, "relevant": relevant is None or k in relevant} for k, s in SCENARIOS.items()]


@router.post("/environment")
def create_environment(req: DemoEnvRequest, db: Session = Depends(get_db)):
    try:
        env = demo.create_demo_environment(db, req.template)
    except discovery.DiscoveryError as e:
        raise HTTPException(400, str(e)) from e
    return environments.detail(db, env)


@router.post("/simulate")
def simulate(req: SimulateRequest, db: Session = Depends(get_db)):
    env = db.get(Environment, req.environment_id)
    if not env or not env.profiles:
        raise HTTPException(404, "environment not found")
    try:
        return demo.simulate(db, env, req.scenarios, req.benign_count)
    except KeyError as e:
        raise HTTPException(422, str(e)) from e


@router.post("/run")
def run_demo(req: DemoRunRequest, db: Session = Depends(get_db)):
    try:
        return demo.run_full_demo(db, req.template, req.benign_count)
    except discovery.DiscoveryError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/reset")
def reset(db: Session = Depends(get_db)):
    demo.reset(db)
    return {"reset": True}
