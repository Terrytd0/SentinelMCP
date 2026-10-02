"""Tests for the `run_remediation` CLI's control flow.

Not its remediation logic -- that lives in `backend/services/remediation.py` and
is covered by `tests/integration/test_api_and_approval.py`. What is worth
testing here is the part that only exists in the script: batch bookkeeping, the
per-target error boundary, and the exit code.

The exit code is the contract with whatever scheduler runs this nightly, so it
gets the most attention: a refusal is a *legitimate* outcome and must not fail
the run, while an unexpected exception must.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any

import pytest

from backend.scripts import run_remediation as script
from backend.services.remediation import RemediationRefusedError

# The fake service below reads this, because the script constructs its own
# service internally -- threading a fake through the call site would mean
# testing a signature different from the one that ships.
BEHAVIOURS: dict[uuid.UUID, Any] = {}


def _refusal() -> RemediationRefusedError:
    from backend.policy.rules import AutoRemediationRefusal

    return RemediationRefusedError(
        AutoRemediationRefusal.PATH_OUTSIDE_SOURCE_ROOTS,
        "file path is outside the permitted source roots",
    )


def _outcome(*, approved: bool, outcome: str, pull_request_id: uuid.UUID | None = None) -> Any:
    """A `RemediationOutcome` shaped just enough for the script to summarise.

    `finding` and `proposal` are `None` because the script only ever reads
    `result` and `pull_request_id` off the outcome -- the rows themselves are the
    service's business, covered by the integration tests.
    """
    from backend.agents.autogen_loop import LoopResult
    from backend.services.remediation import RemediationOutcome

    result = LoopResult(
        approved=approved,
        patch="--- a/x\n+++ b/x\n" if approved else None,
        summary="summary",
        rationale="rationale",
        outcome=outcome,
        rounds_completed=1,
    )
    return RemediationOutcome(
        finding=None,  # type: ignore[arg-type]
        proposal=None,  # type: ignore[arg-type]
        result=result,
        pull_request_id=pull_request_id,
    )


class _FakeService:
    """A `RemediationService` stand-in driven by `BEHAVIOURS`.

    Each target maps to an exception instance (raised) or an outcome object
    (returned), which is what lets one test cover approve, reject, escalate,
    refuse, and crash in a single call.
    """

    def __init__(self, _session: Any = None, **_kwargs: Any) -> None:
        pass

    async def remediate(self, finding_id: uuid.UUID, **_: Any) -> Any:
        behaviour = BEHAVIOURS[finding_id]
        if isinstance(behaviour, Exception):
            raise behaviour
        return behaviour


class _FakeRepo:
    """Stands in for `RemediationRepository` on the approved path.

    The script only asks it for a pull request's number, and a real approval
    would need the database. An escalated outcome carries a `pull_request_id` of
    `None` and so never reaches this at all.
    """

    def __init__(self, _session: Any) -> None:
        pass

    async def get_pull_request(self, _pull_request_id: uuid.UUID) -> Any:
        class _PR:
            number = 4242

        return _PR()


class _FakeSessionScope:
    """Async context manager standing in for `session_scope`.

    Yields a sentinel the fake service accepts, and swallows the commit/rollback
    the real one does.
    """

    async def __aenter__(self) -> Any:
        return object()

    async def __aexit__(self, *_exc: object) -> bool:
        return False


async def _noop() -> None:
    return None


@pytest.fixture
def offline(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[dict[uuid.UUID, Any]]:
    """Run the script with no database, no network, and a scripted service.

    Yields the behaviour mapping so a test can populate it before the batch runs.
    """
    BEHAVIOURS.clear()
    monkeypatch.setattr("backend.scripts.run_remediation.session_scope", _FakeSessionScope)
    monkeypatch.setattr("backend.scripts.run_remediation.RemediationService", _FakeService)
    monkeypatch.setattr("backend.scripts.run_remediation.RemediationRepository", _FakeRepo)
    monkeypatch.setattr("backend.scripts.run_remediation.build_engine", lambda: object())
    monkeypatch.setattr("backend.scripts.run_remediation.AuditRepository", lambda _s: object())
    monkeypatch.setattr("backend.scripts.run_remediation.dispose_engines", _noop)
    monkeypatch.setattr("backend.scripts.run_remediation.shutdown_background_loop", _noop)
    yield BEHAVIOURS
    BEHAVIOURS.clear()


# --- batch bookkeeping and the exit-code contract ---------------------------


async def test_a_clean_batch_records_the_approval(offline: Any) -> None:
    target = uuid.uuid4()
    offline[target] = _outcome(approved=True, outcome="approved", pull_request_id=uuid.uuid4())

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.attempted == 1
    assert report.approved == 1
    assert report.failed == 0
    # The fake repository reports 4242 for any PR id, so the number is
    # attributed to the report and shows up in the summary a scheduler reads.
    assert report.draft_pull_requests == [4242]


async def test_an_approval_with_no_pull_request_still_reports_cleanly(offline: Any) -> None:
    """A missing PR must not print `#None` or crash the batch.

    An approved outcome with no draft PR is not supposed to happen -- the
    service creates one before returning -- but "suppose it did" has to produce
    a legible line rather than a NoneType traceback in a nightly job.
    """
    target = uuid.uuid4()
    offline[target] = _outcome(approved=True, outcome="approved")

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.approved == 1
    assert report.draft_pull_requests == []
    assert report.failed == 0


async def test_a_policy_refusal_is_not_a_failure(offline: Any) -> None:
    """The whole point of the batch: refusal is a decision, not a crash.

    If refusals counted as failures, a nightly run over a backlog containing
    ineligible findings would exit nonzero forever and the scheduler would page
    someone for a system working exactly as designed.
    """
    target = uuid.uuid4()
    offline[target] = _refusal()

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.refused == 1
    assert report.failed == 0
    assert report.refusals == {"path_outside_source_roots": 1}


async def test_an_unexpected_error_is_counted_as_failed(offline: Any) -> None:
    target = uuid.uuid4()
    offline[target] = RuntimeError("the database fell over")

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.failed == 1
    assert report.refused == 0


async def test_one_bad_finding_does_not_end_the_batch(offline: Any) -> None:
    """A batch that stops at the first error is not a batch.

    The regression test for the error boundary: the failing target is isolated
    and every later target is still attempted.
    """
    first, second, third = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    offline[first] = RuntimeError("boom")
    offline[second] = _outcome(approved=False, outcome="escalated")
    offline[third] = _refusal()

    report = await script.run_batch([first, second, third], actor="test", open_ticket=True)

    assert report.attempted == 3
    assert report.failed == 1
    assert report.escalated == 1
    assert report.refused == 1


async def test_a_missing_finding_is_reported_not_crashed(offline: Any) -> None:
    target = uuid.uuid4()
    offline[target] = LookupError(f"finding {target} does not exist")

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.attempted == 1
    assert report.failed == 1


async def test_a_budget_exhaustion_counts_as_an_escalation(offline: Any) -> None:
    """Budget exhaustion is the cost bound working, so it is not a failure.

    It is also not a success: the finding still needs a human, which is exactly
    what an escalation means downstream.
    """
    from backend.agents.autogen_loop import LoopBudgetExhausted

    target = uuid.uuid4()
    offline[target] = LoopBudgetExhausted("LLM call budget of 8 reached")

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.escalated == 1
    assert report.failed == 0
    assert report.approved == 0


async def test_a_rejection_is_its_own_outcome(offline: Any) -> None:
    target = uuid.uuid4()
    offline[target] = _outcome(approved=False, outcome="rejected")

    report = await script.run_batch([target], actor="test", open_ticket=True)

    assert report.rejected == 1
    assert report.escalated == 0
    assert report.draft_pull_requests == []


async def test_an_empty_batch_reports_nothing_attempted(offline: Any) -> None:
    report = await script.run_batch([], actor="test", open_ticket=True)

    assert report.attempted == 0
    assert report.as_dict()["draft_pull_requests"] == []


# --- CLI surface ------------------------------------------------------------


def test_finding_id_and_list_candidates_are_mutually_exclusive() -> None:
    """Two ways to say "no explicit target" in one invocation is a mistake.

    argparse enforces it, so the user gets an error rather than a silently
    ignored flag.
    """
    with pytest.raises(SystemExit):
        script._parse_args(["--finding-id", str(uuid.uuid4()), "--list-candidates"])


def test_there_is_no_flag_that_can_enable_auto_merge() -> None:
    """A guard against the most damaging change anyone could make here.

    Not a functional test -- the code has no auto-merge path, and
    `backend/policy/rules.py::assert_human_merge_required` refuses to start
    with the setting enabled. This exists so that adding a merge-related flag is
    a *test failure*, not a code-review question somebody has to think to ask.
    """
    options = {
        option
        for action in script.build_parser()._actions  # noqa: SLF001
        for option in action.option_strings
    }
    assert not any("merge" in option.lower() for option in options), (
        f"a merge-related flag was added to the CLI: {sorted(options)}"
    )


def test_an_unknown_severity_is_rejected() -> None:
    with pytest.raises(SystemExit):
        script._parse_args(["--severity", "apocalyptic"])


def test_the_report_is_json_serializable() -> None:
    """`--json` is a contract with a scheduler; a report that only serializes
    when nothing interesting happened would fail at 3am."""
    import json

    report = script.BatchReport(attempted=2, approved=1, escalated=1, draft_pull_requests=[1001])
    restored = json.loads(json.dumps(report.as_dict()))
    assert restored["approved"] == 1
    assert restored["draft_pull_requests"] == [1001]
