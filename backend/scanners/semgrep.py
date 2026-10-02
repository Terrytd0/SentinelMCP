"""Semgrep (SAST) scanner -- the roadmap's stretch goal, implemented for real.

Shells out to the `semgrep` binary and parses its JSON output into
`RawFinding`s. This is the adapter that makes the system a genuine SAST
pipeline rather than a consumer of canned data, and it is the reference for
how every future third-party scanner is added: implement `Scanner`, map the
vendor's output into `RawFinding`, register it, done.

Availability is detected, not assumed. If the binary is missing the scanner
reports itself unavailable with a reason, the gRPC service excludes it from
`Health.available_scanners`, and a scan request naming it returns a clear
error instead of an empty result. That distinction -- "cannot look" versus
"looked and found nothing" -- is the whole reason `ScannerUnavailableError`
exists.

Install the binary with either:

    pip install semgrep        # provides the `semgrep` console script
    # or a standalone release from semgrep.dev

Point at a non-default location with `SENTINEL_SEMGREP_BINARY`.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.enums import Confidence, ScannerKind, Severity
from backend.scanners.base import (
    RawFinding,
    Scanner,
    ScannerExecutionError,
    ScannerUnavailableError,
    ScanResult,
)

logger = get_logger(__name__)

# Semgrep runs are CPU-bound and can take minutes on a real repository. Long
# enough for a small project, short enough that a wedged subprocess is
# reported as a failure rather than hanging the gRPC worker forever.
DEFAULT_TIMEOUT_SECONDS = 300

# Semgrep's own severity vocabulary -> ours.
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Semgrep's impact vocabulary is finer-grained than ours and is the better
# signal when present -- `security.audit` rules carry it.
_IMPACT_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class SemgrepScanner(Scanner):
    """Static analysis via the `semgrep` CLI."""

    kind = ScannerKind.SEMGREP

    def __init__(
        self,
        binary: str = "semgrep",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._binary = binary
        self._timeout = timeout_seconds
        self._resolved: str | None = None
        self._detect()

    def _detect(self) -> None:
        """Locate the binary once, at construction.

        An explicit path in the settings is used as-is (so a container can
        point at `/opt/semgrep/semgrep`); otherwise the name is resolved
        against PATH.
        """
        candidate = Path(self._binary)
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = str(candidate) if candidate.is_file() else None
        else:
            resolved = shutil.which(self._binary)

        self._resolved = resolved
        self.available = resolved is not None
        if not self.available:
            self.unavailable_reason = (
                f"semgrep binary not found (looked for {self._binary!r} on PATH). "
                "Install with `pip install semgrep` or set SENTINEL_SEMGREP_BINARY."
            )
            logger.info("semgrep scanner unavailable: %s", self.unavailable_reason)

    @property
    def resolved_binary(self) -> str | None:
        """The absolute path to the binary, or None when it was not found.

        Public because a caller that runs Semgrep itself still needs the same
        resolution this scanner performed -- `backend/evidence/semgrep_check.py`
        pins its own `--config` set rather than using `--config auto`, and
        re-implementing the lookup would be a second place for "semgrep is not
        on PATH" to be answered differently.
        """
        return self._resolved

    def scan(self, target: str) -> ScanResult:
        """Run `semgrep --json` over `target` and map the results.

        Uses `--json` rather than parsing human-readable output: the JSON
        schema is versioned, whereas the text output changes between releases
        and would turn every Semgrep upgrade into a silent parsing bug.
        """
        if not self.available or self._resolved is None:
            raise ScannerUnavailableError(self.unavailable_reason or "semgrep unavailable")

        path = Path(target)
        if not path.exists():
            raise ScannerUnavailableError(f"semgrep target does not exist: {target}")

        started = utc_now()
        clock = time.perf_counter()
        findings, error = self._run_and_parse(path)
        duration_ms = (time.perf_counter() - clock) * 1000.0

        if error is not None and not findings:
            # Nothing at all came back, and something went wrong. Let the
            # caller see an exception rather than a clean-looking empty scan.
            raise ScannerExecutionError(error)

        return ScanResult(
            scanner_kind=self.kind,
            target=target,
            findings=findings,
            started_at=started,
            duration_ms=duration_ms,
            error=error,
        )

    def _run_and_parse(self, path: Path) -> tuple[list[RawFinding], str | None]:
        """Run the subprocess and parse stdout.

        Returns `(findings, error)`. A non-zero exit is not automatically an
        error -- Semgrep exits non-zero when it *finds* problems, so the exit
        code is only read after checking whether stdout parsed.
        """
        command = [
            self._resolved or "semgrep",
            "--json",
            "--quiet",
            "--config",
            "auto",
            # Config download needs the network. Scoped to `path` so a scan of
            # an untrusted repository cannot make Semgrep execute anything
            # from that repository's own config.
            str(path),
        ]
        logger.info("running semgrep target=%s", target_label(path))

        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [], f"semgrep timed out after {self._timeout}s"
        except OSError as exc:
            return [], f"semgrep could not be executed: {type(exc).__name__}"

        stdout = completed.stdout.strip()
        if not stdout:
            message = (completed.stderr or "").strip().splitlines()
            detail = message[-1] if message else f"exit code {completed.returncode}"
            return [], f"semgrep produced no output: {detail}"

        try:
            document = json.loads(stdout)
        except json.JSONDecodeError:
            return [], "semgrep output was not valid JSON"

        results = document.get("results")
        if not isinstance(results, list):
            return [], "semgrep JSON had no 'results' list"

        findings = [f for f in (self._map_result(r, path) for r in results) if f is not None]
        logger.info("semgrep completed target=%s findings=%d", target_label(path), len(findings))
        return findings, None

    def _map_result(self, record: Any, base: Path) -> RawFinding | None:
        """Map one Semgrep result object onto a `RawFinding`.

        Returns `None` for a record missing the fields that make a finding
        addressable, rather than inventing a placeholder -- a finding with no
        rule id cannot be fingerprinted, and an un-fingerprintable finding
        breaks the re-scan upsert downstream.
        """
        if not isinstance(record, dict):
            return None

        extra = record.get("extra")
        if not isinstance(extra, dict):
            return None

        rule_id = record.get("check_id")
        message = extra.get("message")
        if not isinstance(rule_id, str) or not rule_id:
            return None

        start = record.get("start")
        end = record.get("end")
        start_line = start.get("line") if isinstance(start, dict) else None
        end_line = end.get("line") if isinstance(end, dict) else None

        # Semgrep's `impact` is a more specific signal than its `severity`;
        # prefer it and fall back to the coarse mapping.
        impact = str(extra.get("impact") or "").strip().upper()
        severity = _IMPACT_MAP.get(impact) or _SEVERITY_MAP.get(
            str(extra.get("severity") or "").strip().upper(), Severity.MEDIUM
        )

        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}

        cwe = extra.get("cwe")
        cwe_ids = _normalize_cwes(cwe)

        # Semgrep metadata uses CWE-* strings; normalize to the CWE-N form the
        # rest of the system stores.
        cve_ids = [str(c) for c in (metadata.get("cve") or []) if isinstance(c, str)]

        return RawFinding(
            rule_id=rule_id,
            title=str(message or rule_id).splitlines()[0][:500],
            description=str(message or ""),
            severity=severity,
            file_path=self._relative_path(record.get("path"), base),
            start_line=int(start_line) if isinstance(start_line, int) else None,
            end_line=int(end_line) if isinstance(end_line, int) else None,
            snippet=str(extra.get("lines") or "") or None,
            # Semgrep is pattern matching, not exploitation. A rule that names a
            # known CWE with a reference is a confident finding; one without is
            # a lead. This is deliberately not HIGH by default.
            confidence=Confidence.MEDIUM if cwe_ids else Confidence.LOW,
            cwe_ids=cwe_ids,
            cve_ids=cve_ids,
            raw_payload={
                "check_id": rule_id,
                "severity": extra.get("severity"),
                "impact": impact or None,
                "engine_kind": extra.get("engine_kind"),
                "references": metadata.get("references"),
            },
        )

    @staticmethod
    def _relative_path(raw_path: Any, base: Path) -> str | None:
        """Normalize Semgrep's path to a repo-relative POSIX path.

        Absolute paths must become relative or the same finding produces a
        different fingerprint on every machine, which would make the
        re-scan upsert useless outside the original developer's laptop.
        """
        if not isinstance(raw_path, str) or not raw_path:
            return None
        candidate = Path(raw_path)
        try:
            return candidate.resolve().relative_to(base.resolve()).as_posix()
        except (ValueError, OSError):
            return candidate.as_posix()


def _normalize_cwes(raw: object) -> list[str]:
    """Extract bare `CWE-NN` identifiers from Semgrep's `cwe` metadata.

    Semgrep does not emit `"CWE-95"`; it emits
    `"CWE-95: Improper Neutralization of Special Elements used in an OS Command"`
    -- an ID *and* the weakness's full name. Taking the string verbatim stored
    an 80-character pseudo-identifier in `findings.cwe_ids`, which then matched
    nothing when `evaluate_auto_remediation` compared it against a bare CWE set,
    so every CWE-scoped eligibility rule silently stopped applying to Semgrep
    findings.

    Handles a bare string, a list, and a comma-joined string, and returns
    sorted unique IDs so the value is stable in the database.
    """
    if isinstance(raw, str):
        candidates: list[object] = [raw]
    elif isinstance(raw, list):
        candidates = list(raw)
    else:
        return []

    found: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        for match in _CWE_TOKEN.finditer(candidate):
            found.add(f"CWE-{match.group(1)}")
    return sorted(found)


# `CWE-` followed by digits, anywhere in the string. Anchored on the digits so a
# trailing description is simply not matched.
_CWE_TOKEN = re.compile(r"CWE-\s*(\d+)", re.IGNORECASE)


def target_label(path: Path) -> str:
    """A short, non-sensitive identifier for logs (paths may be deep)."""
    return path.name or str(path)
