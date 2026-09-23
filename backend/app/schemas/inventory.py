"""Discovery inventory, schema_version 1.0. This is the contract between collectors and the platform.

Collectors are untrusted input: every field is length/size bounded, unknown keys are dropped, and
PowerShell's habit of collapsing one-element arrays into a single object is tolerated.
"""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _listify(v: Any) -> Any:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _truncating(limit: int):
    # Real command lines (Electron apps, Java classpaths) exceed any sane limit; truncate rather than
    # rejecting the whole inventory.
    return lambda v: "" if v is None else str(v)[:limit]


Str = Annotated[str, BeforeValidator(_truncating(8192))]
ShortStr = Annotated[str, BeforeValidator(_truncating(512))]


def ListOf(t, max_len: int = 5000):  # noqa: N802
    return Annotated[list[t], BeforeValidator(_listify), Field(default_factory=list, max_length=max_len)]


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Collector(_M):
    name: ShortStr = "unknown"
    version: ShortStr = ""
    mode: ShortStr = ""


class Host(_M):
    hostname: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-_]{0,254}$")]
    platform: Literal["windows", "linux", "macos", "unknown"] = "windows"
    os: ShortStr = ""
    os_version: ShortStr = ""
    build: ShortStr = ""
    architecture: ShortStr = ""
    domain: ShortStr = ""
    part_of_domain: bool = False
    boot_time: datetime | None = None
    uptime_seconds: int | None = None


class IPAddr(_M):
    address: ShortStr
    prefix_length: int | None = None


class Interface(_M):
    name: ShortStr = ""
    description: ShortStr = ""
    mac: ShortStr = ""
    status: ShortStr = ""
    ipv4: ListOf(IPAddr, 64)
    ipv6: ListOf(IPAddr, 64)
    gateways: ListOf(ShortStr, 16)
    dns_servers: ListOf(ShortStr, 16)


class Route(_M):
    destination: ShortStr = ""
    next_hop: ShortStr = ""
    interface: ShortStr = ""
    metric: int | None = None


class ListeningPort(_M):
    protocol: Literal["tcp", "udp"] = "tcp"
    address: ShortStr = ""
    port: Annotated[int, Field(ge=0, le=65535)]
    pid: int | None = None
    process: ShortStr = ""


class Network(_M):
    interfaces: ListOf(Interface, 256)
    routes: ListOf(Route, 2000)
    listening_ports: ListOf(ListeningPort, 5000)


class Service(_M):
    name: ShortStr
    display_name: ShortStr = ""
    status: ShortStr = ""
    start_type: ShortStr = ""
    path: Str = ""


class Process(_M):
    name: ShortStr
    pid: int | None = None
    parent_pid: int | None = None
    path: Str = ""
    command_line: Str = ""


class User(_M):
    name: ShortStr
    enabled: bool | None = None
    is_admin: bool = False
    last_logon: ShortStr = ""


class Software(_M):
    name: ShortStr
    version: ShortStr = ""
    publisher: ShortStr = ""


class ScheduledTask(_M):
    name: ShortStr
    path: ShortStr = ""
    state: ShortStr = ""
    actions: ListOf(Str, 32)


class FirewallProfile(_M):
    name: ShortStr
    enabled: bool | None = None


class Security(_M):
    defender: dict[str, Any] = Field(default_factory=dict)
    firewall_profiles: ListOf(FirewallProfile, 8)
    audit_policy: dict[str, ShortStr] = Field(default_factory=dict)
    security_services: ListOf(ShortStr, 64)


class RemoteAccess(_M):
    rdp_enabled: bool = False
    rdp_port: int | None = None
    winrm_enabled: bool = False
    ssh_present: bool = False


class WebServers(_M):
    iis: bool = False
    apache: bool = False
    nginx: bool = False
    iis_sites: ListOf(dict, 256)


class Container(_M):
    id: ShortStr = ""
    name: ShortStr = ""
    image: ShortStr = ""
    ports: ListOf(ShortStr, 128)
    status: ShortStr = ""


class Containers(_M):
    docker: bool = False
    docker_service_status: ShortStr = ""
    containers: ListOf(Container, 2000)
    images: ListOf(ShortStr, 2000)
    kubernetes: bool = False
    kubernetes_indicators: ListOf(ShortStr, 64)


class Inventory(_M):
    schema_version: Literal["1.0"] = "1.0"
    collection_time: datetime
    collector: Collector = Field(default_factory=Collector)
    simulated: bool = False
    host: Host
    network: Network = Field(default_factory=Network)
    services: ListOf(Service, 5000)
    processes: ListOf(Process, 10000)
    users: ListOf(User, 5000)
    admin_group_members: ListOf(ShortStr, 1000)
    software: ListOf(Software, 5000)
    scheduled_tasks: ListOf(ScheduledTask, 5000)
    security: Security = Field(default_factory=Security)
    remote_access: RemoteAccess = Field(default_factory=RemoteAccess)
    web_servers: WebServers = Field(default_factory=WebServers)
    containers: Containers = Field(default_factory=Containers)
