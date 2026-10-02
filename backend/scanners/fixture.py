"""Deterministic fixture scanner.

Reads canned findings from JSON so the entire pipeline -- scan, persist, MCP
tool call, agent loop, SLA dashboard, audit log -- is runnable and testable
with no third-party binary, no network, and no repository to scan.

This is not a stub. It is the scanner that makes the rest of the system
testable, and it is the default in `SENTINEL_ENABLED_SCANNERS`, because a
portfolio project that only runs when you happen to have Semgrep installed is
a project nobody can run.

File format (`data/fixtures/<name>.json`):

    {
      "target": "app/",
      "findings": [
        {
          "rule_id": "python.lang.security.audit.eval-detected",
          "title": "Use of eval() detected",
          "description": "...",
          "severity": "critical",
          "confidence": "high",
          "file_path": "app/handlers/report.py",
          "start_line": 42, "end_line": 42,
          "snippet": "report = eval(request.args['expr'])",
          "cwe_ids": ["CWE-95"],
          "cve_ids": []
        }
      ]
    }

Unknown severities and malformed records are skipped with a warning rather than
raising: one bad fixture entry should not take the whole scan down, and the
count of skipped records is logged so the omission is visible.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.enums import Confidence, ScannerKind, Severity
from backend.scanners.base import (
    RawFinding,
    Scanner,
    ScannerUnavailableError,
    ScanResult,
)

logger = get_logger(__name__)


class FixtureScanner(Scanner):
    """Serves findings from a directory of JSON files, deterministically."""

    kind = ScannerKind.FIXTURE

    def __init__(self, fixtures_dir: str | Path = "data/fixtures") -> None:
        self._fixtures_dir = Path(fixtures_dir)
        self.available = self._fixtures_dir.is_dir()
        if not self.available:
            self.unavailable_reason = f"fixtures directory not found: {self._fixtures_dir}"
        self._cache: dict[str, list[RawFinding]] | None = None

    def _load(self) -> dict[str, list[RawFinding]]:
        """Read and cache every fixture file.

        Cached after the first read because fixtures are static by definition
        and a re-scan of unchanged fixtures should produce byte-identical
        findings -- that is what makes the fingerprint-based upsert testable.
        """
        if self._cache is not None:
            return self._cache

        loaded: dict[str, list[RawFinding]] = {}
        for path in sorted(self._fixtures_dir.glob("*.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "skipping unreadable fixture file=%s error_type=%s",
                    path.name,
                    type(exc).__name__,
                )
                continue

            target = str(document.get("target") or path.stem)
            records = document.get("findings")
            if not isinstance(records, list):
                logger.warning("fixture has no 'findings' list file=%s", path.name)
                continue

            parsed: list[RawFinding] = []
            skipped = 0
            for record in records:
                finding = _parse_record(record, target)
                if finding is None:
                    skipped += 1
                    continue
                parsed.append(finding)

            if skipped:
                logger.warning(
                    "skipped malformed fixture records file=%s skipped=%d", path.name, skipped
                )
            loaded[target] = parsed
            logger.info(
                "loaded fixture file=%s target=%s findings=%d", path.name, target, len(parsed)
            )

        self._cache = loaded
        return loaded

    def available_targets(self) -> list[str]:
        """Every target this scanner can serve, for discovery and tests."""
        return sorted(self._load().keys())

    def scan(self, target: str) -> ScanResult:
        """Return the fixture findings registered for `target`.

        An unknown target returns an *empty* result rather than raising: "this
        target has no known findings" is a true and useful answer, and treating
        it as an error would make a typo look like a broken scanner. Use
        `available_targets()` to discover what exists.
        """
        if not self.available:
            raise ScannerUnavailableError(self.unavailable_reason or "fixtures directory missing")

        catalogue = self._load()
        if target not in catalogue:
            logger.info(
                "fixture target not found target=%s known_targets=%d", target, len(catalogue)
            )

        started = utc_now()
        clock = time.perf_counter()
        findings = list(catalogue.get(target, []))
        duration_ms = (time.perf_counter() - clock) * 1000.0

        return ScanResult(
            scanner_kind=self.kind,
            target=target,
            findings=findings,
            started_at=started,
            duration_ms=duration_ms,
        )


def _parse_record(record: Any, target: str) -> RawFinding | None:
    """Build a `RawFinding` from one fixture record, or `None` if unusable.

    Returns `None` for anything missing the fields a finding cannot exist
    without (`rule_id`, `title`, `severity`) or carrying an unrecognised
    severity. A record with a bad `severity` is dropped rather than coerced
    down to `LOW`, because quietly downgrading a finding is how a real
    critical gets filed as a chore.
    """
    if not isinstance(record, dict):
        return None

    rule_id = record.get("rule_id")
    title = record.get("title")
    severity_value = record.get("severity")

    if not isinstance(rule_id, str) or not rule_id.strip():
        return None
    if not isinstance(title, str) or not title.strip():
        return None

    try:
        severity = Severity(str(severity_value).strip().lower())
    except (ValueError, AttributeError):
        return None

    confidence_value = record.get("confidence", Confidence.MEDIUM)
    try:
        confidence = Confidence(str(confidence_value).strip().lower())
    except (ValueError, AttributeError):
        confidence = Confidence.MEDIUM

    return RawFinding(
        rule_id=rule_id.strip(),
        title=title.strip(),
        description=str(record.get("description") or ""),
        severity=severity,
        file_path=(str(record["file_path"]) if record.get("file_path") else None),
        start_line=(int(record["start_line"]) if record.get("start_line") else None),
        end_line=(int(record["end_line"]) if record.get("end_line") else None),
        snippet=(str(record["snippet"]) if record.get("snippet") is not None else None),
        confidence=confidence,
        cwe_ids=[str(c) for c in (record.get("cwe_ids") or [])],
        cve_ids=[str(c) for c in (record.get("cve_ids") or [])],
        raw_payload={k: v for k, v in record.items() if k not in ("description", "snippet")},
    )
