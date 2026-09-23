from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.environment import DiscoveryRequest
from app.services import discovery, environments

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.post("/run")
def run_discovery(req: DiscoveryRequest, db: Session = Depends(get_db)):
    """Create/refresh an environment from: a demo template, an uploaded inventory (any collector that emits
    schema 1.0), or the bundled PowerShell collector (local / remote over WinRM; requires ENABLE_LIVE_DISCOVERY)."""
    try:
        if req.mode == "demo":
            inv = discovery.load_demo_inventory(req.template or "windows-web-server")
        elif req.mode == "import":
            if not req.inventory:
                raise HTTPException(422, "inventory is required for mode=import")
            inv = req.inventory
        elif req.mode == "remote":
            if not req.target:
                raise HTTPException(422, "target is required for mode=remote")
            inv = discovery.run_powershell_collector(req.target)
        else:
            inv = discovery.run_powershell_collector()
    except discovery.DiscoveryError as e:
        raise HTTPException(400, str(e)) from e
    env = environments.upsert_environment(db, inv, req.mode)
    return environments.detail(db, env)


@router.get("/templates")
def demo_templates():
    return {"templates": discovery.list_demo_templates()}
