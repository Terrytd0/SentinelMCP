"""FastAPI dependencies: the current principal, and the role gate.

`get_current_principal` is the single place a request's identity is resolved.
Routes consume it; they never decode a token themselves.

The `require_role` dependency is what guards the human approval gate. Note
what it is *not*: it is not a check that a human is present, and it is not
sufficient on its own to make the system safe. A token with `role=approver` in
it proves a human logged in once, an hour ago. The rest of the safety argument
lives in `backend/services/approvals.py` and `backend/policy/rules.py` -- this
is one layer of four, and the README says so rather than implying the role
check is the whole story.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.jwt import TokenError, decode_token
from backend.config.settings import get_settings
from backend.core.logging import get_logger
from backend.database.enums import UserRole

logger = get_logger(__name__)

# `auto_error=False` so a missing header produces our own 401 (with a
# WWW-Authenticate header) rather than FastAPI's default, which is a bare
# `{"detail": "Not authenticated"}`. With auth disabled this scheme is never
# consulted at all -- see `get_current_principal`.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    auto_error=False,
)


@dataclass(frozen=True, slots=True)
class Principal:
    """A resolved caller."""

    username: str
    role: UserRole
    is_authenticated: bool

    @property
    def can_approve(self) -> bool:
        return self.is_authenticated and self.role.can_approve_remediation

    @property
    def audit_actor(self) -> str:
        """The string written to `audit_logs.actor`.

        Prefixed so an audit query can tell a human action from a machine one
        without needing a second column.
        """
        return f"user:{self.username}" if self.is_authenticated else "anonymous"


# Identity used when `SENTINEL_AUTH_ENABLED=false`.
ANONYMOUS = Principal(username="anonymous", role=UserRole.ANALYST, is_authenticated=False)


# Identity used when `SENTINEL_AUTH_ENABLED=false` is `ANONYMOUS`, above.
# It deliberately holds only ANALYST rights: running the stack locally with
# auth off should give you the dashboard and the MCP tools, and must never
# silently hand out the ability to approve your own agent's patch.


async def get_current_principal(
    request: Request, token: Annotated[str | None, Depends(oauth2_scheme)]
) -> Principal:
    """Resolve the caller from the bearer token, or fall back to anonymous.

    With `SENTINEL_AUTH_ENABLED=false` this returns `ANONYMOUS` without looking
    at the token at all. The anonymous principal has `ANALYST` rights, so
    read-only routes work and approval routes still refuse.
    """
    if not get_settings().auth_enabled:
        return ANONYMOUS

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = decode_token(token)
    except TokenError as exc:
        # The specific reason is logged, not returned. Telling a caller
        # "expired" versus "bad signature" tells them which part of a forgery
        # to correct.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = str(claims.get("sub") or "")
    raw_role = str(claims.get("role") or UserRole.ANALYST.value)
    try:
        role = UserRole(raw_role)
    except ValueError:
        # An unrecognised role in a validly-signed token means the token was
        # minted by a version of this service that had a role we do not know.
        # Refuse rather than defaulting to the lowest privilege, because
        # defaulting hides the mismatch.
        logger.warning("token for %s carries unknown role %r", username, raw_role)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    return Principal(username=username, role=role, is_authenticated=True)


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_principal(*allowed: UserRole) -> Callable[[Principal], Coroutine[Any, Any, Principal]]:
    """Build a dependency that asserts a role **and returns the principal**.

    Returning the principal (rather than only asserting) is what lets an
    approval route both enforce the role and read `principal.username` for the
    audit row from a single parameter:

        async def approve(pr_id: UUID, approver: ApproverPrincipal): ...

    One dependency, one parameter, no double resolution of the same principal.
    """

    async def _dependency(principal: CurrentPrincipal) -> Principal:
        if principal.role not in allowed:
            logger.warning(
                "authorization denied user=%s role=%s needs=%s",
                principal.username,
                principal.role.value,
                [r.value for r in allowed],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"role {principal.role.value!r} is not permitted; "
                    f"one of {[r.value for r in allowed]} required"
                ),
            )
        return principal

    return _dependency


# The gate in front of every approval transition. Named so a route's signature
# reads as the policy statement it is, and so the OpenAPI schema FastAPI
# generates carries the requirement alongside the endpoint.
ApproverPrincipal = Annotated[
    Principal,
    Depends(require_principal(UserRole.APPROVER, UserRole.ADMIN)),
]
AdminPrincipal = Annotated[Principal, Depends(require_principal(UserRole.ADMIN))]

# Bare `Depends` objects, for a caller that wants the assertion but not the
# principal value.
require_approver = Depends(require_principal(UserRole.APPROVER, UserRole.ADMIN))
require_admin = Depends(require_principal(UserRole.ADMIN))


async def get_db_session() -> AsyncGenerator[AsyncSession]:
    """Session dependency, delegating to the database layer's transaction.

    Exists here as well as in `backend/database/session.py` so that a route
    module has one obvious import for "everything about who I am and what
    session I am working in".

    It used to re-drive `get_session` by hand -- `__anext__` to take the
    session, `aclose` at the end -- and that was two bugs in one place. The
    teardown was `asend(None)`, which resumes a generator that has already
    yielded once, so it finished and raised `StopAsyncIteration`, which PEP 479
    turns into `RuntimeError` on the way out of a coroutine; being in a
    `finally`, it turned every authenticated request into a 500. Changing it to
    `aclose` removed the 500 and introduced a quieter one: `aclose` throws
    `GeneratorExit` at the `yield`, so the commit never ran and every write was
    rolled back anyway.

    Wrapping the shared `transaction` context manager sidesteps the whole
    question. There is no manual generator to drive, so there is no way to
    resume it wrongly, and the commit is the same code path every other caller
    uses.

    The reason this went unnoticed for so long: every route test overrides this
    dependency with a session the test manages itself, so this function was
    never executed by a test. `tests/integration/test_db_session_dependency.py`
    runs the real one.
    """
    from backend.database.session import transaction

    async with transaction() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]
