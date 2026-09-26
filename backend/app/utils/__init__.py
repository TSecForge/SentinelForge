from datetime import datetime, timezone

from sentinelforge._util import get_path, stable_hash, utcnow

__all__ = ["as_utc", "get_path", "iso", "stable_hash", "utcnow"]


def as_utc(dt: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip; treat naive datetimes as UTC."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return as_utc(dt).isoformat().replace("+00:00", "Z") if dt else None
