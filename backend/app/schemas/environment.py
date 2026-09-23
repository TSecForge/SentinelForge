from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.inventory import Inventory

HOSTNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$"


class ExposedService(BaseModel):
    port: int
    protocol: str
    service: str
    process: str = ""
    bind: str = ""


class RiskContext(BaseModel):
    remote_access: bool = False
    internet_facing_indicator: bool = False
    containerized: bool = False
    firewall_disabled_profiles: list[str] = []
    defender_realtime_disabled: bool = False


class NetworkSummary(BaseModel):
    ip_addresses: list[str] = []
    cidrs: list[str] = []
    gateways: list[str] = []
    dns_servers: list[str] = []
    route_count: int = 0


class RuleParameters(BaseModel):
    """Environment facts that rule templates may reference as `$profile.<name>`."""

    listening_ports: list[int] = []
    approved_images: list[str] = []
    container_ports: list[int] = []
    internal_cidrs: list[str] = []
    known_admins: list[str] = []


class EnvironmentProfile(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    hostname: str
    platform: str
    os: str
    environment_type: list[str]
    technologies: list[str]
    exposed_services: list[ExposedService]
    risk_context: RiskContext
    network: NetworkSummary
    rule_categories: list[str]
    parameters: RuleParameters
    evidence: dict[str, list[str]] = Field(default_factory=dict)  # technology -> why we think it's present


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
