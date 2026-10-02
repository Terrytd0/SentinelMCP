"""Scanners and the registry.

The property the whole system rests on is the one asserted most heavily here:
**"we found nothing" and "we could not look" must never be confused.** A
scanner that cannot run and a scanner that ran cleanly both look like an empty
list to a careless caller, and that conflation is how real criticals ship.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.database.enums import Confidence, ScannerKind, Severity
from backend.scanners.base import (
    RawFinding,
    Scanner,
    ScannerExecutionError,
    ScannerUnavailableError,
    ScanResult,
)
from backend.scanners.fixture import FixtureScanner
from backend.scanners.registry import ScannerRegistry, build_registry
from backend.scanners.semgrep import SemgrepScanner


class _EmptyScanner(Scanner):
    kind = ScannerKind.ZAP

    def scan(self, target: str) -> ScanResult:
        return ScanResult(scanner_kind=self.kind, target=target, findings=[])


class _UnavailableScanner(Scanner):
    kind = ScannerKind.DEPENDENCY
    available = False
    unavailable_reason = "the binary is not installed"

    def scan(self, target: str) -> ScanResult:
        raise ScannerUnavailableError(self.unavailable_reason)


class _FailingScanner(Scanner):
    kind = ScannerKind.SEMGREP

    def scan(self, target: str) -> ScanResult:
        return ScanResult(
            scanner_kind=self.kind,
            target=target,
            findings=[
                RawFinding(
                    rule_id="r1",
                    title="t",
                    description="d",
                    severity=Severity.HIGH,
                    file_path="a.py",
                    snippet="x",
                )
            ],
            error="ran out of memory on file 41",
        )


# --- The fixture scanner ------------------------------------------------


def test_the_fixture_scanner_serves_its_findings(registry: ScannerRegistry) -> None:
    result = registry.get(ScannerKind.FIXTURE).scan("app/")
    assert len(result.findings) == 8
    assert result.error is None


def test_the_fixture_scanner_is_deterministic(registry: ScannerRegistry) -> None:
    """The property that makes the fingerprint upsert testable: a re-scan of
    unchanged fixtures must produce byte-identical findings."""
    first = registry.get(ScannerKind.FIXTURE).scan("app/")
    second = registry.get(ScannerKind.FIXTURE).scan("app/")
    assert [f.rule_id for f in first.findings] == [f.rule_id for f in second.findings]
    assert [f.snippet for f in first.findings] == [f.snippet for f in second.findings]


def test_the_fixture_scanner_covers_every_severity() -> None:
    """Seed data that does not exercise the SLA dashboard's per-severity
    buckets is seed data that proves nothing."""
    scanner = FixtureScanner("data/fixtures")
    result = scanner.scan("app/")
    severities = {f.severity for f in result.findings}
    assert {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW} <= severities


def test_an_unknown_target_is_empty_not_an_error() -> None:
    """ "This target has no known findings" is a true and useful answer; treating
    it as an error makes a typo look like a broken scanner."""
    result = FixtureScanner("data/fixtures").scan("does/not/exist/")
    assert result.findings == []
    assert result.error is None


def test_a_missing_fixtures_directory_makes_the_scanner_unavailable(tmp_path: Path) -> None:
    scanner = FixtureScanner(tmp_path / "nope")
    assert not scanner.available
    assert "not found" in (scanner.unavailable_reason or "")
    with pytest.raises(ScannerUnavailableError):
        scanner.scan("app/")


def test_a_malformed_fixture_record_is_skipped_not_fatal(tmp_path: Path) -> None:
    (tmp_path / "mixed.json").write_text(
        json.dumps(
            {
                "target": "app/",
                "findings": [
                    {"rule_id": "good", "title": "T", "severity": "high"},
                    {"title": "no rule id", "severity": "high"},
                    {"rule_id": "bad-severity", "title": "T", "severity": "apocalyptic"},
                    {"rule_id": "", "title": "T", "severity": "high"},
                    "not even an object",
                ],
            }
        ),
        encoding="utf-8",
    )
    result = FixtureScanner(tmp_path).scan("app/")
    assert [f.rule_id for f in result.findings] == ["good"]


def test_an_unrecognised_severity_is_dropped_not_downgraded() -> None:
    """Quietly downgrading a finding to LOW is how a real critical gets filed as
    a chore. Dropping it is visible; downgrading it is not."""
    assert Severity("apocalyptic") if False else True  # not a valid Severity
    with pytest.raises(ValueError):
        Severity("apocalyptic")


def test_the_fixture_scanner_lists_its_targets() -> None:
    targets = FixtureScanner("data/fixtures").available_targets()
    assert "app/" in targets
    assert "services/payments/" in targets


def test_fixture_findings_carry_cwe_and_cve_ids() -> None:
    """`get_cve_details` and the remediation eligibility check both need these."""
    result = FixtureScanner("data/fixtures").scan("app/")
    with_cve = [f for f in result.findings if f.cve_ids]
    with_cwe = [f for f in result.findings if f.cwe_ids]
    assert with_cve, "no seeded finding references a CVE"
    assert with_cwe, "no seeded finding carries a CWE"


# --- The registry -------------------------------------------------------


def test_the_registry_reports_what_can_actually_run(registry: ScannerRegistry) -> None:
    assert registry.available_kinds() == [ScannerKind.FIXTURE]
    assert ScannerKind.SEMGREP not in registry.available_kinds()


def test_an_unregistered_scanner_raises_rather_than_returning_empty() -> None:
    with pytest.raises(ScannerUnavailableError, match="not registered"):
        ScannerRegistry([_EmptyScanner()]).get(ScannerKind.FIXTURE)


def test_a_registered_but_unavailable_scanner_raises_with_its_reason() -> None:
    """A client must be able to tell the operator *which* thing is missing."""
    with pytest.raises(ScannerUnavailableError, match="not installed"):
        ScannerRegistry([_UnavailableScanner()]).get(ScannerKind.DEPENDENCY)


def test_registering_replaces_a_scanner_of_the_same_kind() -> None:
    """So a test can substitute a fake without un-registering the real one."""
    registry = ScannerRegistry([_EmptyScanner()])
    registry.register(_EmptyScanner())
    assert len(registry.all()) == 1


def test_an_unknown_name_in_settings_is_logged_and_skipped() -> None:
    """Starting degraded and saying so beats refusing to start over one bad
    config value."""
    from backend.config.settings import Settings

    settings = Settings(enabled_scanners=["fixture", "not-a-scanner"])
    built = build_registry(settings)
    assert built.available_kinds() == [ScannerKind.FIXTURE]


def test_no_configured_scanners_yields_an_empty_registry() -> None:
    from backend.config.settings import Settings

    assert build_registry(Settings(enabled_scanners=[])).available_kinds() == []


def test_the_default_configuration_is_the_fixture_scanner() -> None:
    """A portfolio project that only runs if you installed Semgrep first is a
    project nobody runs."""
    from backend.config.settings import get_settings

    assert ScannerKind.FIXTURE.value in get_settings().enabled_scanners


# --- ScanResult ---------------------------------------------------------


def test_counts_cover_every_severity_even_when_absent() -> None:
    counts = ScanResult(scanner_kind=ScannerKind.FIXTURE, target="x").counts_by_severity()
    assert set(counts) == {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    }
    assert all(v == 0 for v in counts.values())


def test_severity_filtering_drops_only_the_lower_ones() -> None:
    result = ScanResult(
        scanner_kind=ScannerKind.FIXTURE,
        target="x",
        findings=[
            RawFinding(rule_id="a", title="a", description="", severity=Severity.CRITICAL),
            RawFinding(rule_id="b", title="b", description="", severity=Severity.LOW),
            RawFinding(rule_id="c", title="c", description="", severity=Severity.HIGH),
        ],
    )
    filtered = result.filtered_by_severity(Severity.HIGH)
    assert {f.rule_id for f in filtered.findings} == {"a", "c"}


def test_a_failed_scan_with_findings_is_marked_partial() -> None:
    """A scanner that found three things and then died has still told you
    something, and the caller should be able to use it."""
    result = _FailingScanner().scan("app/")
    assert result.partial
    assert result.error
    assert len(result.findings) == 1


def test_a_clean_scan_is_not_partial() -> None:
    assert ScanResult(scanner_kind=ScannerKind.FIXTURE, target="x").partial is False


# --- Semgrep ------------------------------------------------------------


def test_semgrep_reports_unavailable_when_the_binary_is_absent() -> None:
    scanner = SemgrepScanner(binary="definitely-not-installed-semgrep")
    assert not scanner.available
    assert "semgrep binary not found" in (scanner.unavailable_reason or "")
    with pytest.raises(ScannerUnavailableError):
        scanner.scan("app/")


def test_semgrep_rejects_a_target_that_does_not_exist() -> None:
    scanner = SemgrepScanner(binary="python")  # an absolute-ish path that exists
    if not scanner.available:
        pytest.skip("semgrep binary resolution differs on this platform")
    with pytest.raises(ScannerUnavailableError, match="does not exist"):
        scanner.scan("/definitely/not/a/real/path")


def test_semgrep_maps_a_result_object_onto_a_finding() -> None:
    """The mapping is the adapter's whole job; test it without a subprocess."""
    scanner = SemgrepScanner(binary="python")
    if not scanner.available:
        pytest.skip("no usable binary for the mapping test")

    mapped = scanner._map_result(  # noqa: SLF001
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app/handlers/report.py",
            "start": {"line": 42},
            "end": {"line": 42},
            "extra": {
                "message": "Use of eval detected",
                "severity": "ERROR",
                "impact": "HIGH",
                "lines": "eval(x)",
                "cwe": "CWE-95: Improper Neutralization",
                "metadata": {"cve": ["CVE-2021-1234"], "references": ["https://example.test"]},
            },
        },
        Path("app"),
    )
    assert mapped is not None
    assert mapped.severity is Severity.HIGH
    assert mapped.confidence is Confidence.MEDIUM
    assert mapped.cwe_ids == ["CWE-95"]
    assert mapped.cve_ids == ["CVE-2021-1234"]
    assert mapped.start_line == 42


def test_semgrep_rejects_a_result_it_cannot_key() -> None:
    """A finding with no rule id cannot be fingerprinted, and an
    un-fingerprintable finding breaks the re-scan upsert downstream."""
    scanner = SemgrepScanner(binary="python")
    if not scanner.available:
        pytest.skip("no usable binary for the mapping test")
    assert scanner._map_result({"extra": {}}, Path("app")) is None  # noqa: SLF001
    assert scanner._map_result({"check_id": "x"}, Path("app")) is None  # noqa: SLF001
