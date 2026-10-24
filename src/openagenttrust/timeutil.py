"""AgentProof timestamps: UTC, whole seconds, ``YYYY-MM-DDTHH:MM:SSZ``."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def format_ts(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text: str) -> datetime:
    if not re.fullmatch(TIMESTAMP_PATTERN, text):
        raise ValueError(f"not an AgentProof timestamp: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def parse_duration(text: str) -> timedelta:
    """Parse ``30s``, ``15m``, ``24h`` or ``7d``."""
    match = _DURATION.fullmatch(text.strip())
    if not match:
        raise ValueError(f"invalid duration {text!r}; use e.g. 30s, 15m, 24h, 7d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})
