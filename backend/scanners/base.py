"""The scanner interface every finding source implements.

A scanner is anything that can turn a *target* into a list of findings. Real
ones (Semgrep, OWASP ZAP) shell out to a third-party binary; the bundled
`FixtureScanner` reads canned JSON. The gRPC service holds a registry of these
and nothing above it knows or cares which is in use, which is the whole reason
the gRPC boundary is worth having -- see
`docs/adr/003-grpc-scanning-boundary.md`.

The contract a scanner must honour:

1. `scan()` returns a `ScanResult` with a list of findings. It does **not**
   raise for "I found nothing" -- an empty list is a legitimate result.
2. `scan()` raises `ScannerUnavailableError` when the scanner *cannot run*
   (binary missing, target unreadable). That is a different claim from "no
   issues", and the gRPC layer deliberately reports it as `ScanResponse.error`
   so a failed scan is never silently read as a clean one.
3. `scan()` is synchronous. Async scanners wrap themselves with
   `asyncio.to_thread`; making the interface async would force every
   subprocess-based scanner to pretend to be concurrent.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from backend.core.clock import utc_now
from backend.database.enums import Confidence, ScannerKind, Severity


class ScannerError(RuntimeError):
    """Base class for every scanner failure."""


class ScannerUnavailableError(ScannerError):
    """The scanner exists but cannot run right now (missing binary, bad target).

    Distinct from a scanner that ran and found nothing. See contract note 2.
    """


class ScannerExecutionError(ScannerError):
    """The scanner ran and failed part-way through.

    Findings collected before the failure are still returned on the result
    object (`ScanResult.partial`), because a Semgrep run that trips on one
    unparseable file still produced real findings for the other forty.
    """


@dataclass(frozen=True, slots=True)
class RawFinding:
    """A finding as a scanner produced it, before persistence.

    Deliberately scanner-shaped rather than domain-shaped: this is what a
    scanner *knows*, and `backend/services/scanning.py` is responsible for
    mapping it onto the `Finding` model. Keeping the translation in one place
    means adding a scanner does not mean touching every consumer.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    cwe_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    detected_at: Any = None  # datetime; typed loosely to keep this module import-light

    def __post_init__(self) -> None:
        if self.detected_at is None:
            object.__setattr__(self, "detected_at", utc_now())


@dataclass(slots=True)
class ScanResult:
    """What one scanner produced for one target."""

    scanner_kind: ScannerKind
    target: str
    findings: list[RawFinding] = field(default_factory=list)
    started_at: Any = None  # datetime
    duration_ms: float = 0.0
    error: str | None = None
    """Set when the scan failed. `findings` may still be non-empty -- see
    `partial`."""

    @property
    def partial(self) -> bool:
        """True when an error occurred but some findings were still produced."""
        return self.error is not None and bool(self.findings)

    def counts_by_severity(self) -> dict[Severity, int]:
        """Severity histogram, including zero entries for absent severities.

        Every severity is present so a dashboard can render a fixed set of
        rows without inventing missing keys.
        """
        counts = dict.fromkeys(
            (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO), 0
        )
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def filtered_by_severity(self, minimum: Severity) -> ScanResult:
        """A copy with findings below `minimum` removed.

        Filtering happens scanner-side so an operator asking for "high and
        critical only" does not pay to serialize five hundred low findings
        over the wire and then throw them away.
        """
        return ScanResult(
            scanner_kind=self.scanner_kind,
            target=self.target,
            findings=[f for f in self.findings if f.severity.rank <= minimum.rank],
            started_at=self.started_at,
            duration_ms=self.duration_ms,
            error=self.error,
        )


class Scanner(abc.ABC):
    """Base class for a finding source."""

    #: Stable identifier, matched against `SENTINEL_ENABLED_SCANNERS`.
    kind: ScannerKind = ScannerKind.UNSPECIFIED

    #: Whether this scanner can run in the current environment. Checked at
    #: server startup so `Health.available_scanners` is truthful.
    available: bool = True

    #: Why it is unavailable, when it is. Surfaced on the health endpoint and
    #: in the startup log, so "no findings" can be distinguished from "the
    #: scanner was never wired up".
    unavailable_reason: str | None = None

    @abc.abstractmethod
    def scan(self, target: str) -> ScanResult:
        """Scan `target` and return what was found.

        Raises `ScannerUnavailableError` if the scanner cannot run at all.
        Returns a result carrying `error` (and possibly partial findings) if it
        failed part-way.
        """

    def describe(self) -> str:
        """One-line identity for logs and the health endpoint."""
        state = "available" if self.available else f"unavailable: {self.unavailable_reason}"
        return f"{self.kind.value} ({state})"
