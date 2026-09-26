"""Environment profile: what the profiler derives from an inventory."""

from typing import Literal

from pydantic import BaseModel, Field


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
