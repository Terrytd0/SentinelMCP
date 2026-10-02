"""JWT issuing and verification.

Deliberately minimal, and the comments say what a reviewer would ask about:

  * HS256 with a shared secret. A real deployment should use RS256 (or an
    external IdP entirely) so that verifying a token does not require the
    ability to *mint* one. `jwt_secret` is required to be set in production and
    startup refuses to boot with the development default.
  * No refresh tokens and no revocation list. Both belong to the platform's
    existing identity provider; reimplementing them here would be worse than
    delegating.
  * The role travels in the token, so a role change requires re-issuance. That
    is a real limitation and it is deliberate: it is short-lived (one hour by
    default) and the alternative -- a database lookup per request -- would put
    a round trip in front of every authorization check.

The important part of this file is not the cryptography, it is that
`decode_token` refuses to trust anything it did not sign.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

import jwt

from backend.config.settings import get_settings
from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.enums import UserRole

logger = get_logger(__name__)

# The development-only secret. Refused in production by
# `assert_secret_is_not_default`; defined here so that check has something
# concrete to compare against.
DEV_DEFAULT_SECRET = "dev-only-insecure-secret-change-me"


class TokenError(Exception):
    """The token was missing, malformed, expired, or signed by someone else.

    One exception for all four, deliberately. Distinguishing "expired" from
    "bad signature" in the error a client receives tells an attacker which part
    of a forged token to fix. The specific reason goes to the log, not the
    caller.
    """


def create_access_token(
    *,
    subject: str,
    role: UserRole,
    expires_delta: timedelta | None = None,
) -> str:
    """Mint an access token for a user.

    `sub` is the username, not a database id: usernames are what appear in the
    audit log, and a token whose subject matches the audit actor is one less
    place for the two to disagree.
    """
    settings = get_settings()
    now = utc_now()
    expires = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))

    payload: dict[str, Any] = {
        "sub": subject,
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        # A unique token id. Present so a future revocation list has something
        # to key on; PyJWT's `jti` claim is the conventional home for it.
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Verify and decode a token, or raise `TokenError`.

    Verifies the signature, the expiry, and the algorithm. The explicit
    algorithm allowlist is the important line: without
    `algorithms=[...]`, PyJWT will accept whatever algorithm is in the token's
    header, which is the `alg: none` / algorithm-confusion family of attack.
    """
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        logger.info("token rejected: expired")
        raise TokenError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        logger.info("token rejected: %s", type(exc).__name__)
        raise TokenError("token is invalid") from exc


def token_expiry(token: str) -> datetime:
    """The token's `exp` as an aware datetime. For a client's cache hint."""
    claims = decode_token(token)
    return datetime.fromtimestamp(int(claims["exp"]), tz=utc_now().tzinfo)


def assert_secret_is_not_default() -> None:
    """Refuse to run in production with the shipped development secret.

    Called at startup. Without it, `docker compose up` with no `.env` in a
    real deployment would serve a publicly-known signing key -- anyone could
    mint an APPROVER token and walk through the human approval gate.
    """
    settings = get_settings()
    if settings.app_env.lower() != "production":
        return
    if settings.jwt_secret == DEV_DEFAULT_SECRET:
        raise RuntimeError(
            "SENTINEL_JWT_SECRET is still the development default while "
            "SENTINEL_APP_ENV=production. Anyone could mint an APPROVER token. "
            "Set a real secret, or set SENTINEL_APP_ENV to something other than production."
        )
    logger.info("production secret check passed")
