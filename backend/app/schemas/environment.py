from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from sentinelforge.schemas.inventory import Inventory
from sentinelforge.schemas.profile import EnvironmentProfile

HOSTNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$"


class DiscoveryRequest(BaseModel):
    mode: Literal["demo", "import", "local", "remote"]
    template: str | None = Field(default=None, pattern=r"^[a-z0-9\-]{1,64}$")  # demo mode
    inventory: Inventory | None = None  # import mode
    target: str | None = Field(default=None, pattern=HOSTNAME_RE)  # remote mode (WinRM)

    @field_validator("target")
    @classmethod
    def _no_option_like_target(cls, v: str | None) -> str | None:
        if v is not None and v.startswith("-"):
            raise ValueError("invalid target")
        return v


class EnvironmentSummary(BaseModel):
    id: int
    hostname: str
    platform: str
    os: str
    discovery_mode: str
    simulated: bool
    discovered_at: datetime
    technologies: list[str] = []
    environment_type: list[str] = []
    ip_addresses: list[str] = []
    cidrs: list[str] = []
    active_rules: int = 0


class EnvironmentDetail(EnvironmentSummary):
    inventory: dict[str, Any]
    profile: EnvironmentProfile | None
    profile_id: int | None
    rules: list[dict[str, Any]] = []
