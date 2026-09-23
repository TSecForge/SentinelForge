"""Common normalized event model. Every source parser produces one of these."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Built-ins: windows, linux, docker, kubernetes, generic. Plugins may register more parsers, so the value is
# validated against the parser registry at normalization time rather than a fixed list here.
Source = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")]


class _E(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Actor(_E):
    user: str | None = None
    domain: str | None = None
    target_user: str | None = None


class ProcessInfo(_E):
    name: str | None = None
    pid: int | None = None
    path: str | None = None
    command_line: str | None = Field(default=None, max_length=32768)
    parent_name: str | None = None
    parent_pid: int | None = None
    parent_command_line: str | None = Field(default=None, max_length=32768)
    hash_sha256: str | None = None


class NetworkInfo(_E):
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dst_domain: str | None = None
    protocol: str | None = None
    direction: Literal["inbound", "outbound", "listen", "unknown"] | None = None
    outcome: str | None = None


class AuthInfo(_E):
    outcome: Literal["success", "failure"] | None = None
    logon_type: int | None = None
    method: str | None = None


class ServiceInfo(_E):
    name: str | None = None
    path: str | None = None
    start_type: str | None = None
    account: str | None = None


class TaskInfo(_E):
    name: str | None = None
    command: str | None = Field(default=None, max_length=32768)
    author: str | None = None


class GroupInfo(_E):
    name: str | None = None
    member: str | None = None
    action: Literal["added", "removed"] | None = None


class ContainerInfo(_E):
    id: str | None = None
    name: str | None = None
    image: str | None = None
    host_ports: list[int] = Field(default_factory=list)
    privileged: bool | None = None
    action: str | None = None


class K8sInfo(_E):
    verb: str | None = None
    resource: str | None = None
    subresource: str | None = None
    namespace: str | None = None
    name: str | None = None
    privileged: bool | None = None
    role: str | None = None


class FileInfo(_E):
    path: str | None = None
    hash_sha256: str | None = None


class NormalizedEvent(_E):
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    source: Source
    host: str = Field(min_length=1, max_length=255)
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    simulated: bool = False
    actor: Actor = Field(default_factory=Actor)
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    auth: AuthInfo = Field(default_factory=AuthInfo)
    service: ServiceInfo = Field(default_factory=ServiceInfo)
    task: TaskInfo = Field(default_factory=TaskInfo)
    group: GroupInfo = Field(default_factory=GroupInfo)
    container: ContainerInfo = Field(default_factory=ContainerInfo)
    k8s: K8sInfo = Field(default_factory=K8sInfo)
    file: FileInfo = Field(default_factory=FileInfo)
    raw_reference: str | None = Field(default=None, max_length=512)
    message: str | None = Field(default=None, max_length=8192)


class EventIn(BaseModel):
    """Inbound envelope. `source` picks the parser; `data` is the raw source-specific record
    (or an already-normalized event for source=generic)."""

    model_config = ConfigDict(extra="forbid")

    source: Source
    data: dict[str, Any]
    simulated: bool = False


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1)


class IngestResult(BaseModel):
    received: int
    accepted: int
    duplicates: int
    rejected: int
    matched: int
    detections: int
    errors: list[str] = []
    detection_ids: list[str] = []
