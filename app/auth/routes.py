"""Login/logout/self-service (/auth) and user administration (/users)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import config
from ..audit.service import AuditContext
from ..database import get_session
from . import passwords, service
from .dependencies import COOKIE_NAME, CurrentUser, anonymous_context, client_ip, get_current_user, require
from .permissions import Permission
from .schemas import AuthStatus, LoginRequest, Me, PasswordChange, PasswordReset, UserCreate, UserRead, UserUpdate

auth_router = APIRouter(prefix="/auth", tags=["authentication"])
users_router = APIRouter(prefix="/users", tags=["user management"])

INVALID_LOGIN = "Invalid username or password"


def _me(current: CurrentUser) -> Me:
    return Me(id=current.user.id, username=current.user.username, display_name=current.user.display_name,
              role=current.user.role, permissions=sorted(p.value for p in current.permissions),
              session_expires_at=service.session_expiry(current.session))


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(COOKIE_NAME, token, max_age=config.SESSION_MAX_HOURS * 3600, httponly=True,
                        secure=config.COOKIE_SECURE, samesite="strict", path="/")


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


# --- /auth ---------------------------------------------------------------------------

@auth_router.get("/status", response_model=AuthStatus)
def auth_status(session: Session = Depends(get_session)):
    """Public: tells the login page whether an initial administrator still has to be created."""
    return AuthStatus(setup_required=service.count_users(session) == 0)


@auth_router.post("/login", response_model=Me,
                  responses={401: {"description": "Invalid username or password"}})
def login(data: LoginRequest, request: Request, response: Response, session: Session = Depends(get_session)):
    """Start a session. Sets an HttpOnly, SameSite=Strict session cookie."""
    try:
        result = service.authenticate(session, data.username, data.password, client_ip(request))
    except service.AuthError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_LOGIN) from None
    _set_cookie(response, result.token)
    resolved = service.resolve_session(session, result.token)
    assert resolved is not None  # noqa: S101  # the session was created immediately above
    user, row = resolved
    return _me(CurrentUser(user=user, session=row,
                           ctx=AuditContext(user.id, user.username, client_ip(request))))


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, session: Session = Depends(get_session)):
    """End the current session (no-op if there is none)."""
    token = request.cookies.get(COOKIE_NAME, "")
    resolved = service.resolve_session(session, token) if token else None
    ctx = anonymous_context(request)
    if resolved:
        ctx = AuditContext(resolved[0].id, resolved[0].username, ctx.ip_address)
    service.logout(session, ctx, token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(COOKIE_NAME, path="/", secure=config.COOKIE_SECURE, httponly=True,
                           samesite="strict")
    return response


@auth_router.get("/me", response_model=Me)
def me(current: CurrentUser = Depends(get_current_user)):
    return _me(current)


@auth_router.post("/password", status_code=status.HTTP_204_NO_CONTENT,
                  responses={400: {"description": "Current password incorrect"}})
def change_own_password(data: PasswordChange, current: CurrentUser = Depends(get_current_user),
                        session: Session = Depends(get_session)):
    """Change your own password. Other sessions of your account are signed out."""
    try:
        service.set_password(session, current.ctx, current.user.id, data.new_password,
                             current_password=data.current_password, keep_session=current.session.token_hash)
    except service.AuthError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Current password is incorrect") from None
    except passwords.PasswordPolicyError as exc:
        raise _bad_request(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- /users (administrators) -------------------------------------------------------------

manage = require(Permission.USERS_MANAGE)


def _user(session: Session, user_id: str):
    try:
        return service.get_user(session, user_id)
    except service.UserNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@users_router.get("", response_model=list[UserRead])
def list_users(_: CurrentUser = Depends(manage), session: Session = Depends(get_session)):
    return service.list_users(session)


@users_router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(data: UserCreate, current: CurrentUser = Depends(manage),
                session: Session = Depends(get_session)):
    try:
        return service.create_user(session, current.ctx, data.username, data.password, data.role,
                                   data.display_name)
    except service.UserConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:                      # username format, password policy
        raise _bad_request(exc) from exc


@users_router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: str, _: CurrentUser = Depends(manage), session: Session = Depends(get_session)):
    return _user(session, user_id)


@users_router.patch("/{user_id}", response_model=UserRead)
def update_user(user_id: str, data: UserUpdate, current: CurrentUser = Depends(manage),
                session: Session = Depends(get_session)):
    """Change display name, role or active flag. Role changes and deactivation end the user's sessions."""
    _user(session, user_id)
    fields = data.model_dump(exclude_unset=True)
    if fields.get("role", ...) is None or fields.get("is_active", ...) is None:
        raise _bad_request(ValueError("role and is_active cannot be null"))
    try:
        return service.update_user(session, current.ctx, user_id,
                                   display_name=fields.get("display_name", ...),
                                   role=fields.get("role"), is_active=fields.get("is_active"))
    except service.UserConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@users_router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(user_id: str, data: PasswordReset, current: CurrentUser = Depends(manage),
                   session: Session = Depends(get_session)):
    """Set a new password for a user (e.g. forgotten password). Ends their sessions and unlocks the account."""
    _user(session, user_id)
    keep = current.session.token_hash if user_id == current.user.id else None
    try:
        service.set_password(session, current.ctx, user_id, data.new_password, keep_session=keep)
    except passwords.PasswordPolicyError as exc:
        raise _bad_request(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
