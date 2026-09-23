from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.utils import utcnow


class Rule(Base):
    """A rule template version loaded from a rule pack (YAML on disk). Rows are never overwritten:
    a changed file must bump `version`, which creates a new row."""

    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("rule_id", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(32))
    author: Mapped[str] = mapped_column(String(255))
    mitre_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    definition: Mapped[dict] = mapped_column(JSON)  # validated JSON representation
    yaml_text: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    file_path: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="validated")  # validated | superseded
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuleAssignment(Base):
    """A rule template evaluated against one environment profile.

    status: active | disabled | not_applicable | rejected | superseded
    `generated` holds the environment-specific, fully-resolved rule the engine executes.
    """

    __tablename__ = "rule_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("environment_profiles.id", ondelete="CASCADE"))
    rule_pk: Mapped[int] = mapped_column(ForeignKey("rules.id"))
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    generated: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[Rule] = relationship()
