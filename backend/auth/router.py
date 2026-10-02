"""Authentication routes: `POST /auth/login` and `GET /auth/me`.

Small on purpose. The point of auth in this project is to demonstrate the
authorization boundary in front of the human approval gate, not to be an
identity provider.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import CurrentPrincipal, get_db_session
from backend.auth.hashing import verify_password
from backend.auth.jwt import create_access_token, decode_token
from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.repositories.user import UserRepository
from backend.schemas.auth import LoginRequest, TokenResponse, WhoAmIResponse

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> TokenResponse:
    """Exchange credentials for a short-lived access token.

    Identical failure for an unknown username and a wrong password -- a
    different message for each tells an attacker which usernames exist, and
    username enumeration on a security product's own API would be an
    embarrassing finding in its own dashboard.
    """
    users = UserRepository(session)
    user = await users.get_by_username(payload.username)

    if user is None or not verify_password(payload.password, user.hashed_password):
        logger.info("login failed username=%s reason=invalid_credentials", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.info("login refused username=%s reason=inactive", payload.username)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token(subject=user.username, role=user.role)
    await users.touch_login(user.id)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        username=user.username,
        role=user.role,
        expires_in_minutes=_token_minutes(token),
    )


@router.get("/me", response_model=WhoAmIResponse)
async def whoami(principal: CurrentPrincipal) -> WhoAmIResponse:
    """Report the caller's identity and what they are allowed to do.

    Useful for a client deciding whether to render the approve button, and as
    a cheap way to confirm a token is still valid.
    """
    return WhoAmIResponse(
        username=principal.username,
        role=principal.role,
        is_authenticated=principal.is_authenticated,
        can_approve_remediation=principal.can_approve,
    )


def _token_minutes(token: str) -> int:
    """Whole minutes until this token expires, for the client's cache hint."""
    claims = decode_token(token)
    remaining = int(claims["exp"]) - int(utc_now().timestamp())
    return max(1, remaining // 60)
