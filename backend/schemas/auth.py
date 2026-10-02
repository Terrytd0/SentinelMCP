"""Auth-related schemas.

Split from `contracts.py` because `backend/auth/router.py` imports these and
should not have to pull in the whole API contract surface to do it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from backend.database.enums import UserRole


class LoginRequest(BaseModel):
    """Credentials.

    Deliberately no `extra = "forbid"`: a client that sends an extra field
    should still get a 401 for bad credentials, not a 422 that confirms the
    request shape was understood.
    """

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: UserRole
    expires_in_minutes: int


class WhoAmIResponse(BaseModel):
    username: str
    role: UserRole
    is_authenticated: bool
    can_approve_remediation: bool


class PasswordChangeRequest(BaseModel):
    """Not wired to a route -- the platform IdP owns password changes.

    Present to make the boundary explicit: this project authenticates, it does
    not manage credentials, and a reviewer should not have to read the route
    table to learn that.
    """

    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=12, max_length=512)
