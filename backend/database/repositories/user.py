"""User repository.

Exists so `backend/auth/` can resolve a principal without a raw SQLAlchemy
query, and so the "one repository per aggregate" convention holds even for the
smallest table in the schema.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.clock import utc_now
from backend.database.enums import UserRole
from backend.database.models.audit_log import User


class UserRepository:
    """Data access for `users`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_username(self, username: str) -> User | None:
        result = await self._session.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def get(self, user_id: object) -> User | None:
        return await self._session.get(User, user_id)

    async def list_all(self) -> list[User]:
        result = await self._session.execute(select(User).order_by(User.username.asc()))
        return list(result.scalars().all())

    async def create(
        self, *, username: str, hashed_password: str, role: UserRole = UserRole.ANALYST
    ) -> User:
        user = User(username=username, hashed_password=hashed_password, role=role)
        self._session.add(user)
        await self._session.flush()
        return user

    async def touch_login(self, user_id: object, *, now: datetime | None = None) -> None:
        """Record a successful login. Best-effort diagnostics, not security."""
        user = await self.get(user_id)
        if user is not None:
            user.last_login_at = now or utc_now()
            await self._session.flush()
