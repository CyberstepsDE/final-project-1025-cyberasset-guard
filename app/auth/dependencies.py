"""FastAPI dependencies for authentication and permission checks.

Usage:  user = Depends(require(Permission.ASSETS_WRITE))
Denied requests (authenticated but lacking the permission) are audit-logged.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..audit import service as audit
from ..audit.models import Outcome
from ..database import get_session
from . import service
from .models import User, UserSession
from .permissions import Permission, permissions_for

COOKIE_NAME = "cag_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class CurrentUser:
    user: User
    session: UserSession
    ctx: audit.AuditContext

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.user.role)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def anonymous_context(request: Request) -> audit.AuditContext:
    return audit.AuditContext(user_id=None, username=None, ip_address=client_ip(request))


def get_current_user(request: Request, session: Session = Depends(get_session)) -> CurrentUser:
    token = request.cookies.get(COOKIE_NAME, "")
    resolved = service.resolve_session(session, token) if token else None
    if resolved is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required",
                            headers={"WWW-Authenticate": "Cookie"})
    user, row = resolved
    current = CurrentUser(user=user, session=row, ctx=audit.AuditContext(
        user_id=user.id, username=user.username, ip_address=client_ip(request)))
    request.state.audit_ctx = current.ctx          # used by the monitoring audit middleware
    return current


def _deny(request: Request, current: CurrentUser, permission: Permission):
    audit.record_now(current.ctx, "access.denied", outcome=Outcome.DENIED,
                     details={"method": request.method, "path": request.url.path,
                              "permission": permission.value, "role": current.user.role.value})
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Your role does not allow this action (requires '{permission.value}')")


def require(permission: Permission):
    """Dependency factory: the current user must hold `permission`."""
    def dependency(request: Request, current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if permission not in current.permissions:
            _deny(request, current, permission)
        return current
    dependency.__name__ = f"require_{permission.name.lower()}"
    return dependency


def require_by_method(read: Permission, write: Permission):
    """Router-level guard: safe methods need `read`, everything else `write`."""
    def dependency(request: Request, current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        needed = read if request.method in SAFE_METHODS else write
        if needed not in current.permissions:
            _deny(request, current, needed)
        return current
    return dependency
