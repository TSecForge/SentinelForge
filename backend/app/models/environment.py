from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.utils import utcnow


class Environment(Base):
    """A discovered host. One row per hostname; re-discovery updates inventory and adds a new profile."""

    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(32))
    os: Mapped[str] = mapped_column(String(255), default="")
    discovery_mode: Mapped[str] = mapped_column(String(32))  # demo | import | local | remote
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    inventory: Mapped[dict] = mapped_column(JSON)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    profiles: Mapped[list["EnvironmentProfile"]] = relationship(
        back_populates="environment", cascade="all, delete-orphan", order_by="EnvironmentProfile.id"
    )


class EnvironmentProfile(Base):
    __tablename__ = "environment_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), index=True)
    profile: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    environment: Mapped[Environment] = relationship(back_populates="profiles")
