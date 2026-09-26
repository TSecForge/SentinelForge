"""Sigma-inspired rule schema. YAML is parsed with yaml.safe_load and then validated here with extra="forbid",
so typos and unexpected keys are errors, not silently ignored."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

FIELD_PATH = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,4}$"  # segments start with a letter: no dunders


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Mitre(_Strict):
    tactic: str = Field(pattern=r"^[a-z\-]{3,40}$")
    technique: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")


class Applicability(_Strict):
    """When a template is relevant. Every key that is set must be satisfied; within a key it's any-of.
    Empty = applies to any environment on the rule's platform."""

    platforms: list[str] = []
    technologies: list[str] = []
    environment_types: list[str] = []


class Threshold(_Strict):
    count: int = Field(ge=2, le=100000)
    window_seconds: int = Field(ge=1, le=86400)
    group_by: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("group_by")
    @classmethod
    def _paths(cls, v: list[str]) -> list[str]:
        import re

        for p in v:
            if p != "host" and not re.match(FIELD_PATH, p):
                raise ValueError(f"invalid group_by field {p!r}")
        return v


class RuleDefinition(_Strict):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9\-]{2,63}$")
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=4000)
    version: str = Field(pattern=r"^\d+\.\d+(\.\d+)?$")
    author: str = Field(min_length=1, max_length=200)
    source: Literal["builtin", "organization", "user", "community"]
    status: Literal["stable", "experimental", "deprecated"] = "stable"
    platform: Literal["windows", "linux", "network", "docker", "kubernetes", "any"]
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    severity: Severity
    fidelity: Literal["low", "medium", "high"] = "medium"
    category: str = Field(default="general", pattern=r"^[a-z][a-z0-9_\-]{1,40}$")
    applies_when: Applicability = Field(default_factory=Applicability)
    selection: dict[str, Any] = Field(min_length=1)
    condition: dict[str, Any] | None = None
    threshold: Threshold | None = None
    summary: str | None = Field(default=None, max_length=500)  # "{process.name} spawned by {process.parent_name}"
    mitre: Mitre | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)
    references: list[str] = Field(default_factory=list, max_length=16)
    false_positives: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("version", mode="before")
    @classmethod
    def _version_to_str(cls, v: Any) -> Any:
        # `version: 1.0` in YAML is a float. Quote versions like "1.10" to keep them exact.
        return str(v) if isinstance(v, (int, float)) else v


class RuleValidationResult(BaseModel):
    valid: bool
    rule_id: str | None = None
    errors: list[str] = []
    profile_references: list[str] = []


class RuleValidateRequest(BaseModel):
    yaml: str = Field(max_length=65536)


class AssignmentStatusUpdate(BaseModel):
    status: Literal["active", "disabled"]
