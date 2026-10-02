"""SLA classification: the states people get wrong."""

from __future__ import annotations

from datetime import timedelta

import pytest

from backend.core.clock import utc_now
from backend.database.enums import Severity
from backend.policy.rules import evaluate_sla, sla_hours_for


def _at(**overrides: object) -> object:
    base: dict[str, object] = {"severity": Severity.HIGH, "due_at": None, "closed_at": None}
    base.update(overrides)
    return base


def test_a_finding_with_no_deadline_is_not_started() -> None:
    state = evaluate_sla(**_at(due_at=None))  # type: ignore[arg-type]
    assert state.state == "not_started"
    assert not state.breached
    assert state.notes


def test_a_future_deadline_is_on_track() -> None:
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(due_at=utc_now() + timedelta(hours=10))
    )
    assert state.state == "on_track"
    assert not state.breached
    assert state.hours_remaining and state.hours_remaining > 0


def test_a_past_deadline_is_breached() -> None:
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(due_at=utc_now() - timedelta(hours=3))
    )
    assert state.state == "breached"
    assert state.breached
    assert state.hours_remaining and state.hours_remaining < 0


def test_nearing_the_deadline_is_at_risk_not_yet_breached() -> None:
    """The amber state: past the at-risk fraction but not past the deadline.

    A dashboard with only "fine" and "breached" is useless -- everything is
    fine until the moment it is not.
    """
    total = sla_hours_for(Severity.HIGH)
    remaining = total * 0.1  # 90% elapsed, at_risk_fraction is 0.75
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(due_at=utc_now() + timedelta(hours=remaining))
    )
    assert state.state == "at_risk"
    assert not state.breached, "at-risk must not be counted as a breach"
    assert state.fraction_elapsed >= 0.75


def test_closed_before_the_deadline_is_met_not_breached() -> None:
    """A fixed finding must not appear in a breach count just because
    `due_at` has since passed."""
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(
            due_at=utc_now() + timedelta(hours=1),
            closed_at=utc_now() - timedelta(hours=5),
        )
    )
    assert state.state == "met"
    assert not state.breached


def test_closed_after_the_deadline_is_a_breach() -> None:
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(
            due_at=utc_now() - timedelta(hours=10),
            closed_at=utc_now() - timedelta(hours=1),
        )
    )
    assert state.state == "breached"
    assert state.breached


def test_a_closed_finding_stops_accruing_breach_time() -> None:
    """The single most important property of the closed-state handling.

    Without it, an `accepted_risk` finding three weeks old reports a
    three-week-old breach, the breach count only ever rises, and people stop
    looking at the dashboard.
    """
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(
            due_at=utc_now() - timedelta(hours=10),
            closed_at=utc_now() - timedelta(hours=9),
        )
    )
    assert state.breached
    # Elapsed is measured to the close, not to now.
    assert state.fraction_elapsed == 1.0
    assert state.hours_remaining is None, "a stopped clock has no remaining time"


def test_closed_with_no_deadline_is_stopped() -> None:
    state = evaluate_sla(  # type: ignore[arg-type]
        **_at(due_at=None, closed_at=utc_now())
    )
    assert state.state == "stopped"
    assert not state.breached


@pytest.mark.parametrize("severity", list(Severity))
def test_every_severity_is_classifiable(severity: Severity) -> None:
    """No severity may fall through to a default or raise."""
    for due in (None, utc_now() - timedelta(hours=1), utc_now() + timedelta(hours=1)):
        state = evaluate_sla(severity=severity, due_at=due)  # type: ignore[arg-type]
        assert state.state in {
            "not_started",
            "on_track",
            "at_risk",
            "breached",
            "met",
            "stopped",
        }


def test_naive_datetimes_are_treated_as_utc() -> None:
    """A `sla_due_at` that lost its timezone must not blow up the comparison."""
    # 20h remaining on a 24h HIGH SLA: comfortably on_track, so a mis-read
    # timezone cannot accidentally make this test pass by going amber.
    naive = (utc_now() + timedelta(hours=20)).replace(tzinfo=None)
    state = evaluate_sla(severity=Severity.HIGH, due_at=naive, closed_at=None)  # type: ignore[arg-type]
    assert state.state == "on_track"
