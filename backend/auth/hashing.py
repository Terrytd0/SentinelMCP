"""Password hashing.

Argon2id via `pwdlib`, which is the current recommendation and the library
`passlib` itself points at now that passlib is unmaintained.

The parameters below are the OWASP baseline for Argon2id. They are stated here
rather than left to the library default so a reviewer can see them, and so a
future change to them is a visible diff rather than a library upgrade.
"""

from __future__ import annotations

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

# OWASP-recommended Argon2id parameters (m=19456 KiB, t=2, p=1). Explicit
# rather than relying on the library default, so the cost of this choice is
# visible in the source and a future change is a reviewable diff.
_hasher = PasswordHash((Argon2Hasher(),))


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage.

    Argon2 is deliberately slow and memory-hard. That cost is paid once at
    login and is the entire reason a stolen `users` table is not immediately a
    set of usable passwords.
    """
    return _hasher.hash(password)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Check a plaintext password against a stored hash.

    Returns `False` rather than raising on a malformed hash, so a corrupt row
    fails the login instead of the whole request.
    """
    try:
        return bool(_hasher.verify(plaintext, hashed))
    except Exception:  # noqa: BLE001 - a bad hash is an auth failure, not a 500
        return False
