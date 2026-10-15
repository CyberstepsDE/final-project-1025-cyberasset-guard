"""Password hashing with scrypt (Python standard library, memory-hard KDF).

Stored format:  scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
The parameters are stored with each hash, so the cost can be raised later
without invalidating existing passwords (see needs_rehash).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

SCRYPT_N = 2 ** 15          # CPU/memory cost (32 MiB with r=8)
SCRYPT_R = 8
SCRYPT_P = 1
_MAXMEM = 128 * 1024 * 1024
_DKLEN = 32

MIN_LENGTH = 12
MAX_LENGTH = 128            # bounds hashing work per request


class PasswordPolicyError(ValueError):
    pass


def check_policy(password: str, username: str | None = None) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_LENGTH} characters long")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_LENGTH} characters long")
    if not password.strip():
        raise PasswordPolicyError("password must not be blank")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("password must not contain the username")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=_MAXMEM, dklen=_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt" or len(password) > MAX_LENGTH:
            return False
        digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r),
                                p=int(p), maxmem=_MAXMEM, dklen=len(base64.b64decode(expected)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, base64.b64decode(expected))


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, *_ = stored.split("$")
        return (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    except ValueError:
        return True


# Verified against when the username does not exist, so unknown and known users
# take the same time (no username enumeration via timing).
_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None or needs_rehash(_DUMMY_HASH):
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _DUMMY_HASH)
