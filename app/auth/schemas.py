"""API schemas for authentication and user management."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .passwords import MAX_LENGTH
from .permissions import Role


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=MAX_LENGTH)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(..., min_length=1, max_length=MAX_LENGTH)
    new_password: str = Field(..., min_length=1, max_length=MAX_LENGTH)


class PasswordReset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_password: str = Field(..., min_length=1, max_length=MAX_LENGTH)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    username: str = Field(..., min_length=3, max_length=64, examples=["jdoe"])
    display_name: str | None = Field(None, max_length=200, examples=["Jane Doe"])
    role: Role = Role.VIEWER
    password: str = Field(..., min_length=1, max_length=MAX_LENGTH,
                          description="Initial password (min. 12 characters)")


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    display_name: str | None = Field(None, max_length=200)
    role: Role | None = None
    is_active: bool | None = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    display_name: str | None
    role: Role
    is_active: bool
    locked_until: datetime | None
    last_login_at: datetime | None
    password_changed_at: datetime
    created_at: datetime
    updated_at: datetime


class Me(BaseModel):
    id: str
    username: str
    display_name: str | None
    role: Role
    permissions: list[str]
    session_expires_at: datetime


class AuthStatus(BaseModel):
    setup_required: bool = Field(description="True while no user account exists yet")
