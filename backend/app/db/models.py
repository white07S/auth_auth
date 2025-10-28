from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    oid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    upn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list["Session"]] = relationship(back_populates="user")
    audits: Mapped[list["Audit"]] = relationship(back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: uuid.uuid4().hex
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    roles_json: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    group_cache_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_cache_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    csrf_token: Mapped[str | None] = mapped_column(String(128), nullable=True)

    user: Mapped["User"] = relationship(back_populates="sessions")


class TokenCache(Base):
    __tablename__ = "token_caches"

    cache_key: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: uuid.uuid4().hex
    )
    encrypted_cache_blob: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    user: Mapped["User | None"] = relationship(back_populates="audits")


class AuthRequest(Base):
    """
    PKCE + state tracking for the current OIDC flow.  Rows are short-lived and
    cleaned up automatically once a session is established.
    """

    __tablename__ = "auth_requests"

    request_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: uuid.uuid4().hex
    )
    state: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    code_verifier: Mapped[str] = mapped_column(String(256))
    redirect_uri: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


Index("ix_session_expires_at", Session.expires_at)
Index("ix_session_last_seen", Session.last_seen)
Index("ix_audit_event_created", Audit.event_type, Audit.created_at)
