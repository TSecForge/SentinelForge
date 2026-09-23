"""sentinelforge.detection.v1 - the document forwarded to SIEMs."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.rule import Severity

ObservableType = Literal[
    "ipv4", "ipv6", "domain", "url", "file_path", "hash_md5", "hash_sha1", "hash_sha256",
    "process", "command_line", "user", "hostname", "container_image", "port",
]


class ObservableOut(BaseModel):
    type: ObservableType
    value: str
    context: str | None = None  # e.g. "network.dst_ip", "process.command_line"; never a verdict


class RuleRef(BaseModel):
    id: str
    name: str
    version: str
    source: str
    author: str


class MitreRef(BaseModel):
    tactic: str
    technique: str


class DetectionEvent(BaseModel):
    schema_: Literal["sentinelforge.detection.v1"] = Field("sentinelforge.detection.v1", alias="schema")
    detection_id: str
    timestamp: datetime
    host: str
    rule: RuleRef
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    confidence_basis: str
    event_type: str
    description: str
    summary: str
    mitre: MitreRef | None = None
    observables: list[ObservableOut]
    evidence: dict[str, Any]
    context: dict[str, Any]
    source: dict[str, Any]
    simulated: bool
    event: dict[str, Any]

    model_config = {"populate_by_name": True}
