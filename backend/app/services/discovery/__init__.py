"""Discovery: obtain an inventory (demo template, uploaded JSON, or live PowerShell collector) and validate it."""

import platform
import shutil
import subprocess

from sentinelforge.inventory import InventoryError as DiscoveryError
from sentinelforge.inventory import parse_inventory
from sentinelforge.schemas.inventory import Inventory

from app.core.config import REPO_ROOT, get_settings
from app.core.logging import get_logger

__all__ = ["DiscoveryError", "parse_inventory", "list_demo_templates", "load_demo_inventory", "run_powershell_collector"]

log = get_logger("discovery")

COLLECTOR_SCRIPT = REPO_ROOT / "collectors" / "windows" / "discovery.ps1"
DEMO_DIR = REPO_ROOT / "sample-data" / "environments"


def list_demo_templates() -> list[str]:
    return sorted(p.stem for p in DEMO_DIR.glob("*.json"))


def load_demo_inventory(template: str) -> Inventory:
    if template not in list_demo_templates():  # allowlist: only files that ship in sample-data
        raise DiscoveryError(f"unknown demo template {template!r}; available: {list_demo_templates()}")
    inv = parse_inventory((DEMO_DIR / f"{template}.json").read_text(encoding="utf-8"))
    inv.simulated = True
    return inv


def run_powershell_collector(target: str | None = None) -> Inventory:
    """Run the bundled collector. The command line is fixed; the only variable is an already
    regex-validated hostname passed as a discrete argv element (no shell, no string building)."""
    settings = get_settings()
    if not settings.enable_live_discovery:
        raise DiscoveryError("live discovery is disabled; set ENABLE_LIVE_DISCOVERY=true")
    if platform.system() != "Windows" and not target:
        raise DiscoveryError("local live discovery requires a Windows host")
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        raise DiscoveryError("PowerShell not found")
    argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(COLLECTOR_SCRIPT)]
    if target:
        argv += ["-ComputerName", target]
    log.info("discovery.started", mode="remote" if target else "local", target=target or "localhost")
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=settings.discovery_timeout_seconds, shell=False, check=False)
    except subprocess.TimeoutExpired as e:
        raise DiscoveryError("collector timed out") from e
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")[-500:]
        raise DiscoveryError(f"collector failed (exit {proc.returncode}): {err}")
    inv = parse_inventory(proc.stdout)
    log.info("discovery.completed", host=inv.host.hostname, services=len(inv.services), ports=len(inv.network.listening_ports))
    return inv
