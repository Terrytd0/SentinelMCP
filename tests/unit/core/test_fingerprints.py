"""Fingerprinting and correlation ids.

The fingerprint is what makes a re-run of a scan *update* findings rather than
duplicating them. Getting it wrong produces the classic security-tool failure
where a daily scan reports 40 "new" findings every day and the real backlog
becomes invisible, so the edge cases are tested rather than assumed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.core.ids import (
    compute_fingerprint,
    isoformat_utc,
    new_correlation_id,
    normalize_path,
    ticket_key,
)


def _fp(**overrides: object) -> str:
    base: dict[str, object] = {
        "scanner_kind": "fixture",
        "rule_id": "python.eval-detected",
        "file_path": "app/handlers/report.py",
        "target": "app/",
    }
    base.update(overrides)
    return compute_fingerprint(**base)  # type: ignore[arg-type]


def test_the_same_finding_always_gets_the_same_fingerprint() -> None:
    assert _fp() == _fp()
    assert len(_fp()) == 64


def test_a_different_rule_is_a_different_finding() -> None:
    assert _fp() != _fp(rule_id="python.sql-injection")


def test_a_different_file_is_a_different_finding() -> None:
    assert _fp() != _fp(file_path="app/handlers/other.py")


def test_a_different_target_is_a_different_finding() -> None:
    assert _fp() != _fp(target="services/payments/")


def test_a_different_scanner_is_a_different_finding() -> None:
    """Two scanners reporting the same code are two findings until a human
    decides otherwise; silently merging them would hide one scanner's coverage."""
    assert _fp() != _fp(scanner_kind="semgrep")


def test_case_and_whitespace_do_not_change_identity() -> None:
    assert _fp() == _fp(scanner_kind="  FIXTURE ", rule_id="  Python.Eval-Detected  ")


# --- The fields deliberately excluded from identity ---------------------


def test_a_line_number_is_not_part_of_identity() -> None:
    """Adding a blank line above a vulnerable statement moves it without
    changing the vulnerability. Keying on the line would re-open a "fixed"
    finding every time someone reformatted the file above it."""
    # The signature has no line parameter at all -- this test documents that
    # as the contract rather than a behaviour.
    import inspect

    assert "start_line" not in inspect.signature(compute_fingerprint).parameters
    assert "snippet" not in inspect.signature(compute_fingerprint).parameters


def test_a_different_title_changes_identity_only_when_there_is_no_file() -> None:
    """DAST and dependency findings have a target but no line to point at, so
    the title is the only thing distinguishing two alerts from the same host."""
    assert _fp(file_path="app/x.py", title="one") == _fp(file_path="app/x.py", title="two")
    assert _fp(file_path=None, title="one") != _fp(file_path=None, title="two")


# --- Path normalization -------------------------------------------------


def test_windows_and_posix_separators_normalise_identically() -> None:
    """Semgrep on Windows can emit backslashes; the same file must not become
    two findings depending on which OS reported it."""
    assert _fp(file_path="app/handlers/report.py") == _fp(file_path="app\\handlers\\report.py")


def test_a_drive_letter_is_stripped() -> None:
    assert normalize_path(r"C:\app\x.py") == "app/x.py"


def test_a_leading_dot_slash_is_stripped() -> None:
    assert normalize_path("./app/x.py") == "app/x.py"


def test_repeated_separators_collapse() -> None:
    assert normalize_path("app//handlers///report.py") == "app/handlers/report.py"


# --- Other helpers ------------------------------------------------------


def test_correlation_ids_are_unique() -> None:
    assert new_correlation_id() != new_correlation_id()
    assert len(new_correlation_id()) == 32


def test_ticket_keys_are_readable() -> None:
    """Read aloud in calls and pasted into chat; a UUID suffix would not
    survive either."""
    assert ticket_key(1042) == "SEC-1042"


def test_isoformat_utc_uses_a_z_suffix() -> None:
    """Most log aggregators and `date` parsers prefer `Z` over `+00:00`."""
    rendered = isoformat_utc(datetime(2026, 9, 27, 10, 11, 12, tzinfo=UTC))
    assert rendered == "2026-09-27T10:11:12Z"


def test_isoformat_utc_treats_naive_input_as_utc() -> None:
    assert isoformat_utc(datetime(2026, 1, 1, 0, 0, 0)) == "2026-01-01T00:00:00Z"
