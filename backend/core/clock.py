"""Time helpers.

Every timestamp the system stores or compares goes through this module.
Centralizing it is what makes the SLA engine trustworthy: a mix of naive
`datetime.now()`, `utcnow()`, and `fromtimestamp()` is the classic way to get
a "one hour negative" breach window in production.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    """Timezone-aware current UTC time.

    `datetime.now(UTC)`, not `utcnow()` -- the naive form is exactly the bug
    this function exists to prevent.
    """
    return datetime.now(UTC)


def ensure_aware(value: datetime) -> datetime:
    """Attach UTC to a naive datetime; convert an aware one to UTC.

    Postgres `TIMESTAMP WITH TIME ZONE` round-trips aware values, but data
    that came from SQLite, a fixture, or a hand-edited CSV will not be. This
    keeps one comparison path in the SLA engine instead of two.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def hours_between(start: datetime, end: datetime) -> float:
    """Whole-precision hours from `start` to `end`, safe for mixed awareness."""
    return (ensure_aware(end) - ensure_aware(start)).total_seconds() / 3600.0


def to_epoch_millis(value: datetime) -> int:
    """Milliseconds since the Unix epoch, for the protobuf Timestamp field."""
    return int(ensure_aware(value).timestamp() * 1000)


def from_epoch_millis(value: int) -> datetime:
    """Inverse of `to_epoch_millis`."""
    return datetime.fromtimestamp(value / 1000.0, tz=UTC)


def deadline_from_now(hours: float) -> datetime:
    """The SLA deadline `hours` from now."""
    return utc_now() + timedelta(hours=hours)
