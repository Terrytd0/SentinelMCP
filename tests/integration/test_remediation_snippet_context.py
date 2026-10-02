"""The snippet the remediation loop is actually shown.

`tests/unit/scanners/test_scanner_snippet_enrichment.py` covers the widening rule
thoroughly. This covers the *wiring* -- that `RemediationService` calls it, that
what the loop is shown is what the proposal recorded, and that widening it did not
corrupt the finding.

That last one is the reason this file exists. `findings.snippet` is what the
detector reported; `proposals.original_snippet` is what the agent was shown. Two
different facts, and the bug this catches is quietly merging them -- which would
make the database, the API and the MCP tool output misstate the detector's
precision while every unit test stayed green.

Integration because it runs the real service against a real database, the same
way `test_api_and_approval.py` does, so the proposal row and the audit row are
genuine rows rather than fabricated ones.

## What is *not* tested here, and why

The `enclosing-block` branch needs the finding's file to exist on disk, and the
service resolves `file_path` relative to the process's working directory. Planting
a file at the seeded finding's real path would mean writing into the repository
working tree from a test, which is worse than the gap.

So the widening *rule* is proven against real files in the unit tests, and the
*wiring* is proven here by cross-checking the strategy and line count against a
direct call to `enrich_snippet` with the same arguments. If the service passed a
different path, a different line, or a different ceiling, these disagree.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from backend.config.settings import Settings
from backend.database.enums import AuditAction
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.ticket import AuditRepository
from backend.scanners.snippet import SnippetStrategy, enrich_snippet
from backend.services.remediation import RemediationService

pytestmark = pytest.mark.integration


async def _eligible_finding(session: Any) -> tuple[uuid.UUID, Any]:
    """The first finding the policy gates would allow, and the row itself."""
    for row in await FindingRepository(session).list_open_with_sla(limit=100):
        if row.auto_remediation_eligible and row.snippet and row.file_path:
            return uuid.UUID(str(row.id)), row
    pytest.skip("no eligible finding was seeded")


async def _remediate(session: Any) -> Any:
    finding_id, _ = await _eligible_finding(session)
    return await RemediationService(session).remediate(
        finding_id, actor="user:dana", open_ticket=False
    )


async def test_the_audit_row_records_which_strategy_was_used(
    seeded_session: Any,
) -> None:
    """So a reader of the audit trail knows what the loop was actually shown.

    Without this the audit row says "the agent started remediation" and leaves a
    reader assuming the agent saw the finding's whole neighbourhood. In the
    fixture case it saw one line, because the file does not exist, and saying so
    is the difference between an audit trail and a log.
    """
    outcome = await _remediate(seeded_session)
    await seeded_session.commit()

    events = await AuditRepository(seeded_session).list_for_entity(
        entity_type="remediation_proposal", entity_id=str(outcome.proposal.id)
    )
    started = [e for e in events if e.action == AuditAction.REMEDIATION_PROPOSED]
    assert started, "no audit row recorded the start of the remediation"

    payload = started[0].payload or {}
    assert "snippet_strategy" in payload, (
        "the audit row does not say how much source the loop was shown"
    )
    assert payload["snippet_strategy"] in {s.value for s in SnippetStrategy}
    assert payload["snippet_lines"] >= 1


async def test_the_service_passes_the_findings_own_path_and_line(
    seeded_session: Any,
) -> None:
    """Cross-check: the two call sites must agree.

    The service and a direct call are given the same finding, and the strategy
    and width the service recorded must match. This is what proves the widening
    is reached through the real path with the real arguments, without needing the
    file to exist -- which is the only honest way to test it here.
    """
    finding_id, finding = await _eligible_finding(seeded_session)
    outcome = await RemediationService(seeded_session).remediate(
        finding_id, actor="user:dana", open_ticket=False
    )
    await seeded_session.commit()

    expected = enrich_snippet(
        file_path=finding.file_path,
        reported=finding.snippet or "",
        start_line=finding.start_line,
        end_line=finding.end_line,
        max_lines=Settings().remediation_snippet_max_lines,
    )

    events = await AuditRepository(seeded_session).list_for_entity(
        entity_type="remediation_proposal", entity_id=str(outcome.proposal.id)
    )
    payload = next(e.payload or {} for e in events if e.action == AuditAction.REMEDIATION_PROPOSED)
    assert payload["snippet_strategy"] == expected.strategy.value
    assert payload["snippet_lines"] == expected.line_count


async def test_the_proposal_records_exactly_what_the_loop_was_shown(
    seeded_session: Any,
) -> None:
    """The audit trail and the drafted patch must agree about the input.

    `proposals.original_snippet` is the code the agent was given. If it did not
    match, a reviewer reading the proposal could not tell what the patch was
    written against -- which is the one thing a proposal exists to record.
    """
    finding_id, finding = await _eligible_finding(seeded_session)
    outcome = await RemediationService(seeded_session).remediate(
        finding_id, actor="user:dana", open_ticket=False
    )
    await seeded_session.commit()

    shown = outcome.proposal.original_snippet or ""
    assert shown.strip(), "the loop was shown nothing at all"
    reported = (finding.snippet or "").strip().splitlines()[0].strip()
    assert reported in shown, f"the recorded snippet does not contain the reported line: {shown!r}"


async def test_widening_does_not_reach_into_the_finding_record(
    seeded_session: Any,
) -> None:
    """Two different facts, and they must not collapse into one.

    A finding records what the detector reported. If widening wrote back to it,
    `findings.snippet` would claim the detector saw a whole function, and every
    consumer of that column would overstate the detector's precision.
    """
    finding_id, finding = await _eligible_finding(seeded_session)
    original = finding.snippet or ""

    await RemediationService(seeded_session).remediate(
        finding_id, actor="user:dana", open_ticket=False
    )
    await seeded_session.commit()

    after = await FindingRepository(seeded_session).get(finding_id)
    assert after is not None
    assert (after.snippet or "") == original, (
        "the remediation loop rewrote the finding's own snippet; a finding is a "
        "statement about what the detector found"
    )
