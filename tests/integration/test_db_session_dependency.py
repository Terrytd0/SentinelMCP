"""The real `get_db_session`, executed rather than overridden.

Every other integration test in this suite replaces `get_db_session` with a
fake that yields a pre-made session. That is the right call for testing routes,
and it had one bad consequence: the real dependency was never executed by a
single test.

So it shipped broken. Its teardown called `asend(None)`, which resumes a
generator that has already yielded once; it runs to completion and raises
`StopAsyncIteration`, which PEP 479 converts into
`RuntimeError: async generator raised StopAsyncIteration` on the way out of a
coroutine. Being in a `finally`, that replaced the response of *every
authenticated request* with a 500 -- and a fake dependency meant the suite
stayed green.

The rule these tests exist to enforce: **if a test overrides a dependency, some
other test has to run the real one.** Otherwise the override is not a test
double, it is a hole.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_db_session
from backend.database.session import session_scope

pytestmark = pytest.mark.integration


class _Recorder:
    """Wraps the real generator so we can assert on how it was torn down."""

    def __init__(self) -> None:
        self.closed = False
        self.rolled_back = False
        self.inner: Any = None


async def _drive(body: Any) -> tuple[Any, _Recorder, BaseException | None]:
    """Run `get_db_session` as a FastAPI dependency would, and finish it.

    Mirrors what `solve_dependencies` does: `__anext__` to get the session, run
    the body, then close the generator. The `aclose()` at the end is the whole
    point -- if teardown is broken, this is where it surfaces.
    """
    generator = get_db_session()
    recorder = _Recorder()
    try:
        session = await generator.__anext__()
        recorder.inner = session
    except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
        return None, recorder, exc

    error: BaseException | None = None
    try:
        result = await body(session)
    except BaseException as exc:  # noqa: BLE001 - re-raised after teardown
        result, error = None, exc
    finally:
        # The line under test. A broken teardown raises here.
        try:
            await generator.aclose()
            recorder.closed = True
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            error = error or exc
    return result, recorder, error


# --- the regression itself ------------------------------------------------


async def test_a_clean_request_tears_down_without_raising() -> None:
    """A request that succeeded must not turn into a 500 on the way out.

    This is the assertion that was missing. `aclose()` must not raise, and in
    particular must not raise `StopAsyncIteration` -- the failure that made every
    authenticated request return 500 while the test suite stayed green.
    """

    async def body(session: AsyncSession) -> str:
        result = await session.execute(text("SELECT 1"))
        return str(result.scalar())

    value, recorder, error = await _drive(body)

    assert error is None, f"teardown raised: {error!r}"
    assert value == "1"
    assert recorder.closed
    assert isinstance(recorder.inner, AsyncSession)


async def test_teardown_does_not_raise_stop_async_iteration() -> None:
    """Named explicitly, because that is the exact error that shipped.

    If someone "simplifies" `aclose()` back to `asend(None)`, this fails by name
    rather than as an anonymous `RuntimeError` in somebody's 500 handler.
    """

    async def body(session: AsyncSession) -> None:
        return None

    _, _, error = await _drive(body)
    assert not isinstance(error, StopAsyncIteration)
    assert error is None


# --- the contract around it -----------------------------------------------


async def test_a_failing_request_rolls_back_and_still_tears_down() -> None:
    """The error path must roll back *and* close cleanly.

    Teardown in a `finally` is the only reason a rolled-back request does not
    also leave an unclosed session.
    """

    class _Boom(RuntimeError):
        pass

    async def body(session: AsyncSession) -> None:
        await session.execute(text("SELECT 1"))
        raise _Boom("handler blew up")

    _, recorder, error = await _drive(body)

    assert isinstance(error, _Boom), f"the original error must survive, got {error!r}"
    assert recorder.closed


async def test_the_session_is_usable_inside_the_body() -> None:
    """It is a real session on a real connection, not a stand-in."""

    async def body(session: AsyncSession) -> bool:
        return bool(await session.execute(text("SELECT 1")))

    value, _, error = await _drive(body)
    assert error is None
    assert value is True


async def test_each_call_gets_its_own_session() -> None:
    """Two requests must not share a session.

    The dependency is called per request; if it cached, a second request would
    inherit the first one's uncommitted transaction.
    """

    async def body(session: AsyncSession) -> None:
        return None

    _, first_recorder, first_error = await _drive(body)
    _, second_recorder, second_error = await _drive(body)

    assert first_error is None and second_error is None
    assert isinstance(first_recorder.inner, AsyncSession)
    assert isinstance(second_recorder.inner, AsyncSession)
    assert first_recorder.inner is not second_recorder.inner


# --- and the commit, through a real HTTP request --------------------------
#
# The tests above drive the generator by hand. These go through the actual
# FastAPI app so the commit, the teardown, and the response are all exercised
# together -- which is how the missing commit shipped unnoticed.


@pytest.fixture
def real_app(test_database_url: str) -> Any:
    """The real app, pointed at the test database, with NO dependency override.

    The point is the absence of an override. Every other integration test
    replaces `get_db_session` with a session it manages itself, which is right
    for testing a route and wrong for testing the dependency.
    """
    import os

    from backend.config.settings import reload_settings
    from backend.main import create_app

    previous = os.environ.get("SENTINEL_DATABASE_URL")
    os.environ["SENTINEL_DATABASE_URL"] = test_database_url
    reload_settings()
    try:
        yield create_app()
    finally:
        if previous is None:
            os.environ.pop("SENTINEL_DATABASE_URL", None)
        else:
            os.environ["SENTINEL_DATABASE_URL"] = previous
        reload_settings()


@pytest.fixture
async def real_client(real_app: Any) -> Any:
    import httpx

    transport = httpx.ASGITransport(app=real_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """A real JWT for a user who does not need to exist.

    The write routes require a principal; the token is verified by signature and
    claims, not by a `users` lookup, so no row is needed.
    """
    from backend.auth.jwt import create_access_token
    from backend.database.enums import UserRole

    token = create_access_token(subject="session-dep-test", role=UserRole.ANALYST)
    return {"Authorization": f"Bearer {token}"}


async def _count_tickets(session: AsyncSession) -> int:
    return int((await session.execute(text("SELECT count(*) FROM tickets"))).scalar() or 0)


async def test_a_write_made_through_the_api_actually_persists(
    real_client: Any, db_session: AsyncSession, auth_headers: dict[str, str]
) -> None:
    """The regression. A route's writes must survive the request.

    `get_session` promised "commits on clean exit" and did not commit, so
    closing the session discarded everything. `POST /tickets` returned 201 with
    a `ticket_key`, and a follow-up read found no such ticket.
    """
    from backend.core.clock import utc_now
    from backend.database.models.finding import Finding, Ticket

    now = utc_now()
    finding = Finding(
        fingerprint="a" * 64,
        rule_id="TEST-1",
        title="synthetic finding for the session dependency test",
        description="",
        severity="high",
        target="app/",
        file_path="app/demo.py",
        start_line=1,
        snippet="x = 1",
        # NOT NULL in the schema, and stamped by the scanning service rather
        # than defaulted -- which is why a real scan fills it but a hand-built
        # row has to.
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    before = await _count_tickets(db_session)
    assert before == 0

    response = await real_client.post(
        "/tickets",
        json={"finding_id": str(finding.id), "title": "written through the real API"},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text

    key = response.json()["ticket_key"]

    # Read it back on an *independent* session, so a row still sitting in an
    # uncommitted transaction cannot be seen.
    async with session_scope() as verify:
        persisted = await verify.scalar(select(Ticket).where(Ticket.ticket_key == key))
        assert persisted is not None, (
            f"ticket {key} was returned by the API but is not in the database: "
            "the request's writes are being rolled back"
        )
    assert await _count_tickets(db_session) == before + 1


async def test_a_read_only_request_does_not_error(real_client: Any) -> None:
    """A GET runs the same dependency, commit included, and must stay green."""
    response = await real_client.get("/findings")
    assert response.status_code == 200, response.text
    body = response.json()
    assert isinstance(body, dict) and "findings" in body


async def test_a_failing_route_still_rolls_back(
    real_client: Any, auth_headers: dict[str, str]
) -> None:
    """A 4xx must not leave a half-written row behind.

    Creating a ticket for a finding that does not exist fails validation; the
    dependency has to discard the transaction, not commit a partial one.
    """
    async with session_scope() as verify:
        before = await _count_tickets(verify)

    response = await real_client.post(
        "/tickets",
        json={"finding_id": "00000000-0000-0000-0000-000000000000", "title": "nope"},
        headers=auth_headers,
    )
    assert response.status_code in (400, 404), response.text

    async with session_scope() as verify:
        assert await _count_tickets(verify) == before
