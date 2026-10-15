"""Authentication, sessions and user management.

Every state change records an audit event in the same transaction.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import config
from ..audit import service as audit
from ..audit.models import Outcome
from ..database import utcnow
from . import passwords
from .models import User, UserSession
from .permissions import Role

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
LAST_SEEN_RESOLUTION = timedelta(seconds=60)      # limit DB writes per request


class AuthError(Exception):
    """Login failed. Deliberately carries no detail about *why* (no user enumeration)."""


class UserNotFound(LookupError):
    pass


class UserConflict(ValueError):
    pass


@dataclass
class LoginResult:
    user: User
    token: str                 # plaintext cookie value - never stored


def normalize_username(username: str) -> str:
    name = (username or "").strip().lower()
    if not USERNAME_RE.match(name):
        raise ValueError("username must be 3-64 characters: lower-case letters, digits, '.', '_' or '-', "
                         "starting with a letter or digit")
    return name


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user_label(user: User) -> str:
    return user.username


# --- users ----------------------------------------------------------------------

def count_users(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(User)) or 0


def get_user(session: Session, user_id: str) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise UserNotFound(f"User '{user_id}' was not found")
    return user


def get_user_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username.strip().lower()))


def list_users(session: Session) -> list[User]:
    return list(session.scalars(select(User).order_by(User.username)).all())


def _active_admins(session: Session, excluding: str | None = None) -> int:
    stmt = select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.is_active.is_(True))
    if excluding:
        stmt = stmt.where(User.id != excluding)
    return session.scalar(stmt) or 0


def create_user(session: Session, ctx: audit.AuditContext, username: str, password: str, role: Role,
                display_name: str | None = None) -> User:
    name = normalize_username(username)
    passwords.check_policy(password, name)
    if get_user_by_username(session, name):
        raise UserConflict(f"username '{name}' is already taken")
    now = utcnow()
    user = User(username=name, display_name=(display_name or "").strip() or None, role=Role(role),
                password_hash=passwords.hash_password(password), is_active=True,
                password_changed_at=now, created_at=now, updated_at=now)
    session.add(user)
    session.flush()
    audit.record(session, ctx, "user.create", target_type="user", target_id=user.id, target_label=name,
                 details={"role": user.role.value, "display_name": user.display_name})
    session.commit()
    return user


def update_user(session: Session, ctx: audit.AuditContext, user_id: str, *, display_name=..., role=None,
                is_active=None) -> User:
    """Change display name, role or active flag. Keeps at least one active admin."""
    user = get_user(session, user_id)
    before = {"display_name": user.display_name, "role": user.role.value, "is_active": user.is_active}

    demotes_admin = user.role == Role.ADMIN and user.is_active and (
        (role is not None and Role(role) != Role.ADMIN) or is_active is False)
    if demotes_admin and _active_admins(session, excluding=user.id) == 0:
        raise UserConflict("the last active administrator cannot be demoted or deactivated")

    if display_name is not ...:
        user.display_name = (display_name or "").strip() or None
    if role is not None:
        user.role = Role(role)
    if is_active is not None:
        user.is_active = is_active
        if is_active:
            user.failed_logins, user.locked_until = 0, None

    after = {"display_name": user.display_name, "role": user.role.value, "is_active": user.is_active}
    changes = audit.diff(before, after)
    if changes:
        user.updated_at = utcnow()
        if not user.is_active or "role" in changes:
            # Deactivation or a role change takes effect immediately: end all sessions.
            _end_sessions(session, user.id)
        action = "user.update"
        if "is_active" in changes:
            action = "user.enable" if user.is_active else "user.disable"
        elif "role" in changes:
            action = "user.role_change"
        audit.record(session, ctx, action, target_type="user", target_id=user.id,
                     target_label=_user_label(user), details={"changes": changes})
        session.commit()
    return user


def set_password(session: Session, ctx: audit.AuditContext, user_id: str, new_password: str, *,
                 current_password: str | None = None, keep_session: str | None = None) -> User:
    """Change a password. With current_password (self-service) the old one must match.
    Ends all other sessions of the user and unlocks the account."""
    user = get_user(session, user_id)
    self_service = current_password is not None
    if current_password is not None and not passwords.verify_password(current_password, user.password_hash):
        audit.record(session, ctx, "auth.password_change", outcome=Outcome.FAILURE, target_type="user",
                     target_id=user.id, target_label=user.username,
                     details={"reason": "current password incorrect"})
        session.commit()
        raise AuthError("current password is incorrect")
    passwords.check_policy(new_password, user.username)
    if passwords.verify_password(new_password, user.password_hash):
        raise passwords.PasswordPolicyError("the new password must differ from the current one")
    user.password_hash = passwords.hash_password(new_password)
    user.password_changed_at = user.updated_at = utcnow()
    user.failed_logins, user.locked_until = 0, None
    _end_sessions(session, user.id, keep=keep_session)
    audit.record(session, ctx, "auth.password_change" if self_service else "user.password_reset",
                 target_type="user", target_id=user.id, target_label=user.username)
    session.commit()
    return user


# --- login / sessions ------------------------------------------------------------

def authenticate(session: Session, username: str, password: str, ip: str | None) -> LoginResult:
    now = utcnow()
    name = (username or "").strip().lower()
    user = get_user_by_username(session, name) if name else None
    ctx = audit.AuditContext(user_id=user.id if user else None, username=name[:64] or None, ip_address=ip)

    if user is None:
        passwords.dummy_verify(password or "")            # same timing as a real check
        audit.record(session, ctx, "auth.login", outcome=Outcome.FAILURE,
                     details={"reason": "unknown user"})
        session.commit()
        raise AuthError()

    if user.locked_until and user.locked_until > now:
        passwords.dummy_verify(password or "")
        audit.record(session, ctx, "auth.login", outcome=Outcome.DENIED, target_type="user",
                     target_id=user.id, target_label=user.username,
                     details={"reason": "account locked", "locked_until": user.locked_until})
        session.commit()
        raise AuthError()

    valid = passwords.verify_password(password or "", user.password_hash)
    if not valid or not user.is_active:
        reason = "inactive account" if valid else "wrong password"
        details: dict = {"reason": reason}
        if not valid:
            user.failed_logins += 1
            if user.failed_logins >= config.LOGIN_MAX_FAILURES:
                user.locked_until = now + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)
                user.failed_logins = 0
                details["locked_until"] = user.locked_until
                audit.record(session, ctx, "auth.lockout", target_type="user", target_id=user.id,
                             target_label=user.username,
                             details={"failures": config.LOGIN_MAX_FAILURES,
                                      "minutes": config.LOGIN_LOCKOUT_MINUTES})
        audit.record(session, ctx, "auth.login", outcome=Outcome.FAILURE, target_type="user",
                     target_id=user.id, target_label=user.username, details=details)
        session.commit()
        raise AuthError()

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    session.execute(delete(UserSession).where(UserSession.expires_at <= now))   # housekeeping
    token = secrets.token_urlsafe(32)
    session.add(UserSession(token_hash=_token_hash(token), user_id=user.id, created_at=now,
                            last_seen_at=now, ip_address=ip,
                            expires_at=now + timedelta(hours=config.SESSION_MAX_HOURS)))
    audit.record(session, ctx, "auth.login", target_type="user", target_id=user.id,
                 target_label=user.username)
    session.commit()
    return LoginResult(user=user, token=token)


def resolve_session(session: Session, token: str) -> tuple[User, UserSession] | None:
    """Return (user, session) for a valid, unexpired token of an active user, else None."""
    if not token:
        return None
    row = session.get(UserSession, _token_hash(token))
    if row is None:
        return None
    now = utcnow()
    idle_limit = row.last_seen_at + timedelta(minutes=config.SESSION_IDLE_MINUTES)
    user = session.get(User, row.user_id)
    if row.expires_at <= now or idle_limit <= now or user is None or not user.is_active:
        session.delete(row)
        session.commit()
        return None
    if now - row.last_seen_at >= LAST_SEEN_RESOLUTION:
        row.last_seen_at = now
        session.commit()
    return user, row


def logout(session: Session, ctx: audit.AuditContext, token: str) -> None:
    row = session.get(UserSession, _token_hash(token)) if token else None
    if row is not None:
        session.delete(row)
        audit.record(session, ctx, "auth.logout", target_type="user", target_id=row.user_id,
                     target_label=ctx.username)
        session.commit()


def _end_sessions(session: Session, user_id: str, keep: str | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if keep:
        stmt = stmt.where(UserSession.token_hash != keep)
    session.execute(stmt)


def session_expiry(row: UserSession) -> datetime:
    """When the session ends if the user stays idle (for the client's information)."""
    return min(row.expires_at, row.last_seen_at + timedelta(minutes=config.SESSION_IDLE_MINUTES))
