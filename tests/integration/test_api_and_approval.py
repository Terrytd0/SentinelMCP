"""The HTTP API, and the human approval gate over it.

The most important assertions in this file are the authorization ones: that an
analyst cannot approve, that a second approval is refused, that approving never
merges, and that a merge cannot be recorded without an approval having happened
first. Those four together are the project's central claim expressed through its
public interface.

Every test is `async def` and drives the app through `httpx.ASGITransport`.
An earlier version of this file mixed sync tests with an async database session
and called `asyncio.run` from inside them, which deadlocked: a SQLAlchemy async
session is bound to the event loop that created it, so driving its `commit()`
from a second loop waits on a connection the first loop owns. One loop, one
session, one client -- no bridging.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from backend.auth.hashing import hash_password
from backend.auth.jwt import create_access_token
from backend.database.enums import FindingStatus, UserRole
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.session import session_scope  # noqa: F401  (documented dependency)
from backend.main import create_app
from backend.services.remediation import RemediationService

pytestmark = pytest.mark.integration


@pytest.fixture
def app(db_session: Any) -> Any:
    """The real application, with the test session injected.

    Overriding only the database session is deliberate: the auth dependency is
    left alone, because that is what is under test. Everything else -- routers,
    middleware, the lifespan's policy assertions -- runs for real.
    """
    from backend.auth.dependencies import get_db_session

    application = create_app()

    async def _session() -> Any:
        yield db_session

    application.dependency_overrides[get_db_session] = _session
    return application


@pytest.fixture
async def client(app: Any) -> Any:
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


def _headers(role: UserRole, username: str = "tester") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(subject=username, role=role)}"}


async def _add_user(
    session: Any, username: str, role: UserRole, password: str = "ironclad-demo-analyst"
) -> Any:
    """Insert a user with a real Argon2 hash, so login exercises the real path."""
    from backend.database.models.audit_log import User

    user = User(username=username, role=role, hashed_password=hash_password(password))
    session.add(user)
    await session.commit()
    return user


async def _draft(session: Any) -> dict[str, Any]:
    """Run a real remediation end to end and return the draft's identifiers.

    Not a fabricated row: the draft is produced by the actual agent loop through
    the actual service, so the approval tests are asserting against the state the
    system really reaches.
    """
    finding_id = None
    for row in await FindingRepository(session).list_open_with_sla(limit=100):
        if row.auto_remediation_eligible and row.snippet and row.file_path:
            finding_id = uuid.UUID(str(row.id))
            break
    assert finding_id is not None, "no eligible finding was seeded"

    outcome = await RemediationService(session).remediate(
        finding_id, actor="user:dana", open_ticket=False
    )
    assert outcome.pull_request_id is not None, (
        f"the remediation did not produce a draft: {outcome.result.escalated_reason}"
    )
    pull_request = await RemediationRepository(session).get_pull_request(outcome.pull_request_id)
    assert pull_request is not None
    await session.commit()
    return {
        "id": str(pull_request.id),
        "number": pull_request.number,
        "proposal_id": pull_request.proposal_id,
    }


# --- Liveness and the runtime policy check -------------------------------


async def test_health_never_fails_on_a_dependency_outage(client: Any) -> None:
    """A container that restarts because Postgres blinked has turned a degraded
    service into a down one, so liveness must not depend on it."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["policy"]["auto_merge_blocked"] is True
    assert body["policy"]["human_merge_required"] is True


async def test_readiness_checks_its_dependencies(client: Any) -> None:
    """The separation of liveness from readiness is the point: this one *does*
    gate on them."""
    response = await client.get("/health/ready")
    assert response.status_code in (200, 503)
    body = response.json()
    assert "database" in body["checks"]
    assert "scanning_service" in body["checks"]


async def test_the_policy_check_verifies_the_rails_at_runtime(client: Any) -> None:
    """ "Is auto-merge still blocked?" answerable on demand rather than claimed in
    a README."""
    body = (await client.get("/health/policy")).json()
    assert body["auto_merge"] == "blocked"
    assert body["human_approval_required"] is True
    assert body["verified"] is True


async def test_every_request_gets_a_correlation_id(client: Any) -> None:
    """One id ties an API call to its audit rows, its telemetry events, and its
    log lines."""
    response = await client.get("/")
    assert response.headers["x-correlation-id"]


async def test_an_inbound_correlation_id_is_preserved(client: Any) -> None:
    """So this composes with an existing gateway's trace id."""
    response = await client.get("/", headers={"X-Correlation-Id": "trace-from-gateway"})
    assert response.headers["x-correlation-id"] == "trace-from-gateway"


# --- Scans --------------------------------------------------------------


async def test_a_scan_reports_new_and_refreshed_separately(
    seeded_session: Any, client: Any
) -> None:
    """`new_findings: 0` and `new_findings: 8` are different claims.

    No user row is needed: a bearer token is verified cryptographically and
    `POST /scans` needs a principal, not a database lookup. That trade is
    documented in `backend/auth/dependencies.py`.
    """
    first = await client.post("/scans", json={"target": "app/"}, headers=_headers(UserRole.ANALYST))
    assert first.status_code == 200, first.text
    assert first.json()["new_findings"] == 0, "the fixture was already scanned"
    assert first.json()["refreshed_findings"] == 8

    second = await client.post(
        "/scans", json={"target": "services/payments/"}, headers=_headers(UserRole.ANALYST)
    )
    assert second.status_code == 200
    assert second.json()["new_findings"] == 5


async def test_a_scan_of_an_empty_target_is_200_not_an_error(client: Any) -> None:
    response = await client.post(
        "/scans",
        json={"target": "does/not/exist/"},
        headers=_headers(UserRole.ANALYST),
    )
    assert response.status_code == 200
    assert response.json()["new_findings"] == 0


async def test_scanning_targets_are_discoverable(client: Any) -> None:
    body = (await client.get("/scans/targets")).json()
    assert "app/" in body["fixture_targets"]


# --- Findings -----------------------------------------------------------


async def test_the_triage_queue_defaults_to_open_findings(seeded_session: Any, client: Any) -> None:
    body = (await client.get("/findings")).json()
    assert body["total"] == 8
    assert body["findings"][0]["severity"] == "critical"


async def test_the_list_omits_snippets_but_the_detail_includes_them(
    seeded_session: Any, client: Any
) -> None:
    """The snippet is the most sensitive field in the system; a queue of 200
    findings must not ship 200 blocks of source into every cache and proxy log
    on the way to a browser."""
    listed = (await client.get("/findings")).json()["findings"]
    assert all("snippet" in f for f in listed)
    assert all(f["snippet"] is None for f in listed)

    detail = (await client.get(f"/findings/{listed[0]['finding_id']}")).json()
    assert detail["snippet"], "the detail endpoint must return the snippet"


async def test_an_unknown_finding_is_a_clean_404(client: Any) -> None:
    response = await client.get(f"/findings/{uuid.UUID(int=0)}")
    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"


async def test_a_status_change_stamps_the_terminal_timestamps(
    seeded_session: Any, client: Any
) -> None:
    critical = (await client.get("/findings?severity=critical")).json()["findings"]
    finding_id = critical[0]["finding_id"]
    response = await client.post(
        f"/findings/{finding_id}/status",
        json={"status": "remediated", "reason": "fixed by hand"},
        headers=_headers(UserRole.ANALYST),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "remediated"
    assert body["sla"]["state"] == "met"


async def test_a_stale_status_update_is_a_conflict(seeded_session: Any, client: Any) -> None:
    """Two analysts triaging from two tabs is a real scenario, and
    last-write-wins would silently discard one of them."""
    finding_id = (await client.get("/findings")).json()["findings"][0]["finding_id"]

    first = await client.post(
        f"/findings/{finding_id}/status",
        json={"status": "triaged", "expected_current_status": "open"},
        headers=_headers(UserRole.ANALYST),
    )
    assert first.status_code == 200

    stale = await client.post(
        f"/findings/{finding_id}/status",
        json={"status": "false_positive", "expected_current_status": "open"},
        headers=_headers(UserRole.ANALYST, "someone-else"),
    )
    assert stale.status_code == 409
    assert "re-read" in stale.json()["detail"]


# --- The SLA dashboard ---------------------------------------------------


async def test_the_sla_dashboard_groups_by_severity(seeded_session: Any, client: Any) -> None:
    response = await client.get("/sla/dashboard")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["totals"]["open"] == 8
    assert {"critical", "high", "medium", "low"} <= {b["severity"] for b in body["by_severity"]}
    for bucket in body["by_severity"]:
        assert bucket["sla_hours"] > 0
        assert 0.0 <= bucket["breach_rate"] <= 1.0


async def test_the_sla_summary_is_the_lightweight_view(seeded_session: Any, client: Any) -> None:
    """A dashboard widget polling every 30 seconds should not drag the whole
    per-severity breakdown with it."""
    body = (await client.get("/sla/summary")).json()
    assert body["open"] == 8
    assert "by_severity" not in body


async def test_a_breached_finding_shows_up_in_the_breached_list(
    seeded_session: Any, client: Any
) -> None:
    from datetime import timedelta

    from backend.core.clock import utc_now

    critical = (await client.get("/findings?severity=critical")).json()["findings"]
    finding_id = critical[0]["finding_id"]
    row = await FindingRepository(seeded_session).get(uuid.UUID(finding_id))
    assert row is not None
    row.sla_due_at = utc_now() - timedelta(hours=2)
    await seeded_session.commit()

    breached = (await client.get("/sla/breached")).json()
    assert any(b["finding_id"] == finding_id for b in breached)
    assert all(b["hours_overdue"] > 0 for b in breached)


# --- CVE lookup ----------------------------------------------------------


async def test_cve_lookup_returns_the_advisory_and_its_band(client: Any) -> None:
    body = (await client.get("/cves/CVE-2023-46695")).json()
    assert body["cve_id"] == "CVE-2023-46695"
    assert body["cvss_band"] == "high"
    assert body["remediation"]


async def test_an_unknown_cve_is_a_404_that_says_why(client: Any) -> None:
    """ "Not in our local feed" is a different answer from "has no description",
    and a client rendering a triage view needs to tell them apart."""
    response = await client.get("/cves/CVE-1999-00001")
    assert response.status_code == 404
    assert "NVD" in response.json()["detail"]


async def test_cve_search_by_product(client: Any) -> None:
    body = (await client.get("/cves?product=jinja2")).json()
    assert body["count"] == 1
    assert body["advisories"][0]["cve_id"] == "CVE-2024-22195"


# --- The audit trail -----------------------------------------------------


async def test_the_audit_log_is_readable_by_correlation_id(client: Any) -> None:
    """The forensic view: one externally-triggered operation, one id, every
    action in order."""
    await client.post(
        "/scans",
        json={"target": "does/not/exist/", "correlation_id": "trace-abc"},
        headers=_headers(UserRole.ANALYST),
    )
    entries = (await client.get("/audit/correlation/trace-abc")).json()
    assert entries["total"] >= 1
    assert entries["entries"][0]["correlation_id"] == "trace-abc"


async def test_an_unknown_correlation_id_is_a_404_that_says_why(client: Any) -> None:
    response = await client.get("/audit/correlation/never-happened")
    assert response.status_code == 404
    assert "no audit entries" in response.json()["detail"]


async def test_machine_activity_is_separable_from_human_activity(
    seeded_session: Any, client: Any
) -> None:
    """The `mcp:` / `agent:` / `system:` actor prefix is what makes this one
    filter rather than a join."""
    machine = (await client.get("/audit/machine-activity")).json()
    assert machine["entries"]
    assert all(e["actor"].startswith(("mcp:", "agent:", "system:")) for e in machine["entries"])


def test_the_audit_router_exposes_no_mutations() -> None:
    """An audit log that can be edited is not one, so the absence of a write
    route is enforced structurally rather than by convention."""
    spec = create_app().openapi()
    for path, methods in spec["paths"].items():
        if path.startswith("/audit"):
            assert not ({"post", "put", "patch", "delete"} & set(methods)), (
                f"the audit router exposes a mutation: {methods} {path}"
            )


# --- Authentication ------------------------------------------------------


async def test_login_issues_a_token(db_session: Any, client: Any) -> None:
    await _add_user(db_session, "dana", UserRole.ANALYST)
    response = await client.post(
        "/auth/login", json={"username": "dana", "password": "ironclad-demo-analyst"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "analyst"
    assert body["expires_in_minutes"] > 0


async def test_a_wrong_password_and_an_unknown_user_fail_identically(
    db_session: Any, client: Any
) -> None:
    """Different messages would tell an attacker which usernames exist -- an
    embarrassing finding on a security product's own API."""
    await _add_user(db_session, "dana", UserRole.ANALYST)

    wrong = await client.post("/auth/login", json={"username": "dana", "password": "nope"})
    unknown = await client.post("/auth/login", json={"username": "nobody", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_whoami_reports_what_the_caller_may_do(db_session: Any, client: Any) -> None:
    await _add_user(db_session, "priya", UserRole.APPROVER, "pw")
    token = (await client.post("/auth/login", json={"username": "priya", "password": "pw"})).json()[
        "access_token"
    ]

    body = (await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})).json()
    assert body["role"] == "approver"
    assert body["can_approve_remediation"] is True


async def test_a_missing_token_is_a_401_with_a_challenge_header(client: Any) -> None:
    response = await client.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


# --- The human approval gate ---------------------------------------------


async def test_a_draft_pull_request_starts_blocked_and_unapproved(
    seeded_session: Any, client: Any
) -> None:
    draft = await _draft(seeded_session)
    body = (await client.get(f"/pull-requests/{draft['id']}")).json()

    assert body["status"] == "draft"
    assert body["auto_merge_blocked"] is True
    assert body["human_approved_at"] is None
    assert body["human_approver"] is None


async def test_an_analyst_cannot_approve(seeded_session: Any, client: Any) -> None:
    """The first of the four authorization facts."""
    draft = await _draft(seeded_session)
    response = await client.post(
        f"/pull-requests/{draft['id']}/approve", json={}, headers=_headers(UserRole.ANALYST, "dana")
    )
    assert response.status_code == 403
    assert "not permitted" in response.json()["detail"]


async def test_an_approver_can_approve_and_it_still_does_not_merge(
    seeded_session: Any, client: Any
) -> None:
    """The second fact: approval authorizes the PR to be opened, and the response
    says so in a field a client cannot misread."""
    draft = await _draft(seeded_session)
    response = await client.post(
        f"/pull-requests/{draft['id']}/approve",
        json={},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["decision"] == "approved"
    assert body["approver"] == "priya"
    assert body["auto_merge_blocked"] is True
    assert body["requires_human_merge"] is True
    assert body["status"] == "open"


async def test_a_second_approval_is_refused(seeded_session: Any, client: Any) -> None:
    """Either a double-click or a genuine second opinion; treating them as the
    same event loses the fact that two people weighed in."""
    draft = await _draft(seeded_session)
    await client.post(
        f"/pull-requests/{draft['id']}/approve",
        json={},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    again = await client.post(
        f"/pull-requests/{draft['id']}/approve", json={}, headers=_headers(UserRole.APPROVER, "sam")
    )
    assert again.status_code == 409
    assert "already approved by" in again.json()["detail"]


async def test_a_merge_cannot_be_recorded_without_an_approval(
    seeded_session: Any, client: Any
) -> None:
    """The third fact, and the one an audit depends on: the trail can never
    contain a merge with no authorizing human."""
    draft = await _draft(seeded_session)
    response = await client.post(
        f"/pull-requests/{draft['id']}/merged",
        json={"merged_by": "priya"},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    assert response.status_code == 409
    assert "no recorded human approval" in response.json()["detail"]


async def test_a_recorded_external_merge_marks_the_finding_remediated(
    seeded_session: Any, client: Any
) -> None:
    """The fourth fact: `merged` is reachable, but only by recording a human
    action that happened elsewhere."""
    draft = await _draft(seeded_session)
    await client.post(
        f"/pull-requests/{draft['id']}/approve",
        json={},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    response = await client.post(
        f"/pull-requests/{draft['id']}/merged",
        json={"merged_by": "priya"},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "merged"
    assert "performed no merge itself" in body["note"]

    proposal = await RemediationRepository(seeded_session).get_proposal(draft["proposal_id"])
    assert proposal is not None
    finding = await FindingRepository(seeded_session).get(proposal.finding_id)
    assert finding is not None
    assert finding.status is FindingStatus.REMEDIATED


async def test_a_rejection_requires_a_reason(seeded_session: Any, client: Any) -> None:
    """A rejection with no explanation is unusable to the agent and useless to
    the next analyst, so the field is required rather than nullable."""
    draft = await _draft(seeded_session)
    response = await client.post(
        f"/pull-requests/{draft['id']}/reject",
        json={"reason": "   "},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    assert response.status_code == 422


async def test_a_rejection_keeps_the_finding_on_the_clock(seeded_session: Any, client: Any) -> None:
    """A human rejecting the agent's approach is not a decision that the finding
    is not a problem, so the SLA keeps running."""
    draft = await _draft(seeded_session)
    response = await client.post(
        f"/pull-requests/{draft['id']}/reject",
        json={"reason": "the rewrite changes the return type of a public API"},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"

    proposal = await RemediationRepository(seeded_session).get_proposal(draft["proposal_id"])
    assert proposal is not None
    finding = await FindingRepository(seeded_session).get(proposal.finding_id)
    assert finding is not None
    assert finding.status is FindingStatus.TRIAGED
    assert finding.sla_due_at is not None, "a rejected patch must not stop the SLA clock"
    assert finding.closed_at is None


async def test_the_approver_queue_lists_unapproved_drafts(seeded_session: Any, client: Any) -> None:
    draft = await _draft(seeded_session)
    queue = (await client.get("/pull-requests/awaiting-approval")).json()
    assert any(pr["pull_request_id"] == draft["id"] for pr in queue)

    await client.post(
        f"/pull-requests/{draft['id']}/approve",
        json={},
        headers=_headers(UserRole.APPROVER, "priya"),
    )
    after = (await client.get("/pull-requests/awaiting-approval")).json()
    assert all(pr["pull_request_id"] != draft["id"] for pr in after)


async def test_agent_runs_are_readable_per_finding(seeded_session: Any, client: Any) -> None:
    """ "Why did the agent touch this file?" answerable without filing a ticket."""
    draft = await _draft(seeded_session)
    proposal = await RemediationRepository(seeded_session).get_proposal(draft["proposal_id"])
    assert proposal is not None

    runs = (await client.get(f"/findings/{proposal.finding_id}/agent-runs")).json()
    assert len(runs) >= 2
    assert runs[0]["role"] == "developer"
    assert runs[1]["role"] == "reviewer"
    assert all(r["decision"] for r in runs)


async def test_the_pull_request_body_answers_should_i_trust_this_first(
    seeded_session: Any, client: Any
) -> None:
    """Structured so the human's first question is answered before they read a
    line of the diff."""
    draft = await _draft(seeded_session)
    body = (await client.get(f"/pull-requests/{draft['id']}")).json()["body"]

    assert body.index("## Finding") < body.index("## Diff")
    assert "auto_merge_blocked" in body
    assert "rotated" in body, "a leaked credential needs a rotation step, not just a move"
    assert "```diff" in body
