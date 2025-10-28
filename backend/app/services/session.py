from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AppConfig
from ..core.security import generate_state, now_utc, session_expiry
from ..db import models


@dataclass
class SessionData:
    session_id: str
    user_id: int
    roles: list[str]
    expires_at: datetime
    last_seen: datetime
    csrf_token: Optional[str]
    token_cache_key: Optional[str]


class SessionService:
    def __init__(self, config: AppConfig):
        self._config = config
        self._signing_secret = config.session.signing_secret.encode("utf-8")

    def encode_cookie_value(self, session_id: str) -> str:
        signature = self._sign(session_id)
        return f"{session_id}.{signature}"

    def decode_cookie_value(self, cookie_value: str) -> str | None:
        try:
            raw_id, signature = cookie_value.rsplit(".", 1)
        except ValueError:
            return None
        if self._sign(raw_id) != signature:
            return None
        return raw_id

    def _sign(self, session_id: str) -> str:
        digest = hmac.new(self._signing_secret, session_id.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    async def create_session(
        self,
        db: AsyncSession,
        user: models.User,
        roles: list[str],
        token_cache_key: str | None,
        csrf_token: str | None,
    ) -> SessionData:
        session = models.Session(
            user_id=user.id,
            roles_json={"roles": roles},
            expires_at=session_expiry(self._config.session.max_age_minutes),
            last_seen=now_utc(),
            group_cache_expires_at=now_utc()
            + timedelta(minutes=self._config.rbac.group_refresh_ttl_minutes),
            token_cache_key=token_cache_key,
            csrf_token=csrf_token,
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
        return SessionData(
            session_id=session.session_id,
            user_id=session.user_id,
            roles=roles,
            expires_at=session.expires_at,
            last_seen=session.last_seen,
            csrf_token=session.csrf_token,
            token_cache_key=session.token_cache_key,
        )

    async def rotate_session_id(self, db: AsyncSession, session_id: str) -> str | None:
        """
        Regenerate the underlying session id for defence-in-depth.
        """
        result = await db.execute(
            select(models.Session).where(models.Session.session_id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            return None

        new_id = generate_state()
        session.session_id = new_id
        await db.commit()
        return new_id

    async def touch_session(self, db: AsyncSession, session_id: str) -> None:
        await db.execute(
            update(models.Session)
            .where(models.Session.session_id == session_id)
            .values(last_seen=now_utc())
        )
        await db.commit()

    async def delete_session(self, db: AsyncSession, session_id: str) -> None:
        result = await db.execute(
            select(models.Session).where(models.Session.session_id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            return

        if session.token_cache_key:
            await db.execute(
                delete(models.TokenCache).where(
                    models.TokenCache.cache_key == session.token_cache_key
                )
            )

        await db.delete(session)
        await db.commit()

    async def get_session(self, db: AsyncSession, session_id: str) -> SessionData | None:
        result = await db.execute(
            select(models.Session).where(models.Session.session_id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            return None

        roles = session.roles_json.get("roles", [])
        return SessionData(
            session_id=session.session_id,
            user_id=session.user_id,
            roles=roles,
            expires_at=session.expires_at,
            last_seen=session.last_seen,
            csrf_token=session.csrf_token,
            token_cache_key=session.token_cache_key,
        )


class AuthRequestService:
    """
    Handles the short-lived PKCE/state records that underpin the login flow.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl_seconds = ttl_seconds

    async def create_auth_request(
        self,
        db: AsyncSession,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> models.AuthRequest:
        auth_req = models.AuthRequest(
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
        db.add(auth_req)
        await db.commit()
        return auth_req

    async def consume_auth_request(
        self, db: AsyncSession, state: str
    ) -> models.AuthRequest | None:
        result = await db.execute(
            select(models.AuthRequest).where(models.AuthRequest.state == state)
        )
        auth_req = result.scalar_one_or_none()
        if not auth_req:
            return None
        await db.delete(auth_req)
        await db.commit()
        return auth_req
