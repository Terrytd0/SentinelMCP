"""Conversions between protobuf messages and the scanner domain types.

Kept in its own module so `server.py` (which owns gRPC concerns) and
`client.py` (which owns the client side) do not both carry a copy of the
mapping, and so a wire-format change is one edit rather than two.

Two rules the mapping enforces:

1. `RawFinding` -> `Finding` never invents data. A missing field stays
   missing.
2. `Finding` -> `RawFinding` is lossless for everything a scanner needs, so a
   client can read a finding, edit it, and write it back without a downgrade.
"""

from __future__ import annotations

from typing import Any

from google.protobuf.timestamp_pb2 import Timestamp

from backend.core.clock import from_epoch_millis, to_epoch_millis, utc_now
from backend.core.ids import compute_fingerprint
from backend.database.enums import Confidence, ScannerKind, Severity
from backend.scanners.base import RawFinding, ScanResult

from .generated import scanner_pb2

# Our enum <-> protobuf enum translation. Explicit rather than `int()`
# round-tripping so a value that somehow arrives out of range degrades to
# `UNSPECIFIED` instead of raising inside a request handler.
_SEVERITY_TO_PB: dict[Severity, int] = {
    Severity.UNSPECIFIED: scanner_pb2.SEVERITY_UNSPECIFIED,
    Severity.CRITICAL: scanner_pb2.SEVERITY_CRITICAL,
    Severity.HIGH: scanner_pb2.SEVERITY_HIGH,
    Severity.MEDIUM: scanner_pb2.SEVERITY_MEDIUM,
    Severity.LOW: scanner_pb2.SEVERITY_LOW,
    Severity.INFO: scanner_pb2.SEVERITY_INFO,
}
_PB_TO_SEVERITY: dict[int, Severity] = {v: k for k, v in _SEVERITY_TO_PB.items()}

_CONFIDENCE_TO_PB: dict[Confidence, int] = {
    Confidence.UNSPECIFIED: scanner_pb2.CONFIDENCE_UNSPECIFIED,
    Confidence.LOW: scanner_pb2.CONFIDENCE_LOW,
    Confidence.MEDIUM: scanner_pb2.CONFIDENCE_MEDIUM,
    Confidence.HIGH: scanner_pb2.CONFIDENCE_HIGH,
}
_PB_TO_CONFIDENCE: dict[int, Confidence] = {v: k for k, v in _CONFIDENCE_TO_PB.items()}

_SCANNER_TO_PB: dict[ScannerKind, int] = {
    ScannerKind.UNSPECIFIED: scanner_pb2.SCANNER_KIND_UNSPECIFIED,
    ScannerKind.FIXTURE: scanner_pb2.SCANNER_KIND_FIXTURE,
    ScannerKind.SEMGREP: scanner_pb2.SCANNER_KIND_SEMGREP,
    ScannerKind.ZAP: scanner_pb2.SCANNER_KIND_ZAP,
    ScannerKind.DEPENDENCY: scanner_pb2.SCANNER_KIND_DEPENDENCY,
}
_PB_TO_SCANNER: dict[int, ScannerKind] = {v: k for k, v in _SCANNER_TO_PB.items()}


def scanner_kind_to_pb(kind: ScannerKind) -> int:
    """Our scanner enum -> protobuf int, for request and response fields."""
    return _SCANNER_TO_PB.get(kind, scanner_pb2.SCANNER_KIND_UNSPECIFIED)


# Exported under a private name for the health-response mapping in
# `client.py`, which has to render protobuf scanner ints as our enum values.
_PB_SCANNER: dict[int, ScannerKind] = _PB_TO_SCANNER


def _min_severity_to_pb(minimum: Severity | None) -> int:
    """`None` and `UNSPECIFIED` both mean "no severity filter"."""
    if minimum is None or minimum is Severity.UNSPECIFIED:
        return scanner_pb2.SEVERITY_UNSPECIFIED
    return _SEVERITY_TO_PB.get(minimum, scanner_pb2.SEVERITY_UNSPECIFIED)


def to_timestamp(value: Any) -> Timestamp:
    """Python datetime -> protobuf Timestamp, defaulting to now."""
    stamp = Timestamp()
    stamp.FromMilliseconds(to_epoch_millis(value if value is not None else utc_now()))
    return stamp


def from_timestamp(stamp: Timestamp) -> Any:
    """Protobuf Timestamp -> aware UTC datetime. Missing stamp means now."""
    if stamp is None or (stamp.seconds == 0 and stamp.nanos == 0):
        return utc_now()
    return from_epoch_millis(int(stamp.seconds * 1000 + stamp.nanos // 1_000_000))


def raw_finding_to_pb(
    finding: RawFinding, *, scanner_kind: ScannerKind, target: str
) -> scanner_pb2.Finding:
    """Map a scanner result onto the wire, computing its fingerprint.

    The fingerprint is computed here rather than in the scanner, because it is a
    property of the finding as recorded rather than of how it was found -- so a
    scanner that reports the same location twice gets the same identity, and the
    re-scan upsert deduplicates it.

    Note that `scanner_kind` *is* part of the hash. Two scanners reporting the
    same flaw at the same location are deliberately two findings, not one:
    silently merging them would hide one scanner's coverage and make it
    impossible to answer "what does Semgrep catch that this tool misses?".
    See `tests/unit/core/test_fingerprints.py`.
    """
    return scanner_pb2.Finding(
        fingerprint=compute_fingerprint(
            scanner_kind=scanner_kind.value,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            target=target,
            title=finding.title,
        ),
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        severity=_SEVERITY_TO_PB.get(finding.severity, scanner_pb2.SEVERITY_UNSPECIFIED),
        confidence=_CONFIDENCE_TO_PB.get(finding.confidence, scanner_pb2.CONFIDENCE_UNSPECIFIED),
        scanner_kind=_SCANNER_TO_PB.get(scanner_kind, scanner_pb2.SCANNER_KIND_UNSPECIFIED),
        target=target,
        file_path=finding.file_path or "",
        start_line=finding.start_line or 0,
        end_line=finding.end_line or 0,
        snippet=finding.snippet or "",
        cwe_ids=list(finding.cwe_ids),
        cve_ids=list(finding.cve_ids),
        raw_payload_json=_dumps(finding.raw_payload),
        detected_at=to_timestamp(finding.detected_at),
    )


def pb_to_raw_finding(message: scanner_pb2.Finding) -> RawFinding:
    """Wire -> domain, for a client that wants to reason about findings locally."""
    return RawFinding(
        rule_id=message.rule_id,
        title=message.title,
        description=message.description,
        severity=_PB_TO_SEVERITY.get(message.severity, Severity.UNSPECIFIED),
        confidence=_PB_TO_CONFIDENCE.get(message.confidence, Confidence.UNSPECIFIED),
        file_path=message.file_path or None,
        start_line=message.start_line or None,
        end_line=message.end_line or None,
        snippet=message.snippet or None,
        cwe_ids=list(message.cwe_ids),
        cve_ids=list(message.cve_ids),
        raw_payload=_loads(message.raw_payload_json),
        detected_at=from_timestamp(message.detected_at),
    )


def scan_result_to_pb(
    result: ScanResult, *, scan_id: str, correlation_id: str = ""
) -> scanner_pb2.ScanResponse:
    """Domain result -> wire response, including the severity histogram.

    The counts are computed on the server rather than left to the client: a
    client that sums a list it did not build can get the total wrong, and the
    total is what a dashboard displays most prominently.
    """
    counts = result.counts_by_severity()
    return scanner_pb2.ScanResponse(
        scan_id=scan_id,
        scanner_kind=_SCANNER_TO_PB.get(result.scanner_kind, scanner_pb2.SCANNER_KIND_UNSPECIFIED),
        target=result.target,
        findings=[
            raw_finding_to_pb(f, scanner_kind=result.scanner_kind, target=result.target)
            for f in result.findings
        ],
        counts=scanner_pb2.SeverityCounts(
            critical=counts.get(Severity.CRITICAL, 0),
            high=counts.get(Severity.HIGH, 0),
            medium=counts.get(Severity.MEDIUM, 0),
            low=counts.get(Severity.LOW, 0),
            info=counts.get(Severity.INFO, 0),
            total=len(result.findings),
        ),
        started_at=to_timestamp(result.started_at),
        duration_ms=int(result.duration_ms),
        correlation_id=correlation_id,
        error=result.error or "",
    )


def pb_to_scan_result(message: scanner_pb2.ScanResponse) -> ScanResult:
    """Wire response -> domain result.

    Preserves `error` rather than raising on it, so a caller can distinguish
    "the scanner failed after finding three things" from "the scanner failed
    immediately" and still act on what did come back.
    """
    return ScanResult(
        scanner_kind=_PB_TO_SCANNER.get(message.scanner_kind, ScannerKind.UNSPECIFIED),
        target=message.target,
        findings=[pb_to_raw_finding(f) for f in message.findings],
        started_at=from_timestamp(message.started_at),
        duration_ms=float(message.duration_ms),
        error=message.error or None,
    )


def _dumps(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, separators=(",", ":"), default=str)


def _loads(raw: str) -> dict[str, Any]:
    import json

    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"_unparseable": raw[:500]}
    return parsed if isinstance(parsed, dict) else {"_value": parsed}
