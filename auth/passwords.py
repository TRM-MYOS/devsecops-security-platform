"""Passwords are only persisted as Argon2id hashes."""

import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError


PASSWORD_HASHER = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID
)
# Unknown accounts perform the same expensive verification as existing accounts.
_DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 128:
        raise ValueError("Password must contain between 12 and 128 characters")
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        verified = PASSWORD_HASHER.verify(password_hash or _DUMMY_HASH, password)
        return bool(password_hash) and verified
    except (VerificationError, InvalidHashError):
        return False
