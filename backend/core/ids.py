"""Identity helpers: fingerprints, correlation ids, and ticket keys.

`compute_fingerprint()` is the load-bearing function in this project. It is
what makes a re-run of a scan *update* findings instead of duplicating them,
and getting it wrong produces the classic security-tool failure mode where a
daily scan reports 400 "new" findings every day and the real backlog is
invisible. See `backend/services/scanning.py` for the upsert that depends on
it.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime

# Windows path separators must normalize to POSIX ones, or the same file
# produces two different fingerprints depending on which scanner reported it
# (Semgrep emits POSIX, an editor-driven scan on Windows may emit backslashes).
_WINDOWS_SEPARATOR = re.compile(r"[\\/]+")

# A line number is not part of a finding's identity: adding a blank line above
# a vulnerable statement moves it without changing the vulnerability, and
# keying on it would re-open a "fixed" finding every time someone reformatted
# the file above it.
_LOCATION_TOLERANT_FIELDS = ("scanner_kind", "rule_id", "file_path")


def normalize_path(path: str) -> str:
    """Collapse separators and strip a leading `./` or drive letter."""
    normalized = _WINDOWS_SEPARATOR.sub("/", path.strip())
    normalized = re.sub(r"^[A-Za-z]:/", "", normalized)
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def compute_fingerprint(
    *,
    scanner_kind: str,
    rule_id: str,
    file_path: str | None,
    target: str,
    title: str = "",
) -> str:
    """Content-derived stable identity for a finding.

    Hashes `scanner_kind | rule_id | normalized file path | target` plus the
    title when there is no file path (DAST and dependency findings have a
    target but no line to point at, so the title is what distinguishes two
    alerts from the same scanner against the same host).

    Deliberately *not* included: the snippet, the line numbers, the
    description, and the severity. All four change for reasons that are not
    "this is a different finding" -- an upgraded scanner changes its rule
    description, a severity re-rating changes the label, and a whitespace
    reformat changes the snippet. Including any of them would split one
    vulnerability into several rows and reset its SLA clock on every upgrade.
    """
    location = normalize_path(file_path) if file_path else f"target:{target.strip()}"
    if not file_path:
        location = f"{location}|{title.strip().lower()}"

    parts = [
        scanner_kind.strip().lower(),
        rule_id.strip().lower(),
        location,
        target.strip(),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:64]


def new_correlation_id() -> str:
    """A correlation id for one externally-triggered operation.

    Threaded through the scan, the persistence, the agent loop, the audit rows,
    and the telemetry events, so one operator action can be reconstructed end
    to end from four different tables.
    """
    return uuid.uuid4().hex


def ticket_key(sequence: int) -> str:
    """Human-facing ticket identifier, e.g. `SEC-1042`.

    Sequence-based rather than a UUID suffix because it is read aloud in calls
    and pasted into chat; `SEC-1042` survives that, a UUID does not.
    """
    return f"SEC-{sequence}"


def isoformat_utc(value: datetime) -> str:
    """RFC 3339 / ISO 8601 in UTC, with a `Z` suffix.

    Hand-rolled because `datetime.isoformat()` renders UTC as `+00:00` and most
    log aggregators and `date` parsers prefer `Z`.
    """

    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")
