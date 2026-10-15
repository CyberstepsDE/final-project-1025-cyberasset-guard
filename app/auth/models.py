"""User accounts and login sessions."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Enum, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, UTCDateTime, utcnow
from .permissions import Role


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # stored lower-case
    display_name: Mapped[str | None] = mapped_column(String(200))
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False, create_constraint=True, validate_strings=True, length=16,
             values_callable=lambda e: [m.value for m in e], name="ck_user_role"),
        nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    password_changed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


class UserSession(Base):
    """Server-side session. Only a SHA-256 hash of the cookie token is stored,
    so a database copy cannot be used to hijack sessions."""

    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))

    __table_args__ = (Index("ix_user_sessions_user_id", "user_id"),)
