from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Dict, Optional, Tuple

from fastapi import Response

from ..config import Config


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass
class AuthFlowState:
    flow: Dict[str, Any]
    created_at: datetime


@dataclass
class SessionUser:
    name: str
    email: str
    oid: Optional[str]
    tenant_id: Optional[str]


@dataclass
class SessionData:
    session_id: str
    user: SessionUser
    roles: Tuple[str, ...]
    allowed_routes: Tuple[str, ...]
    expires_at: datetime
    token_expires_at: datetime
    refresh_token: Optional[str]
    access_token: str
    id_token_claims: Dict[str, Any] = field(default_factory=dict)
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    last_active_at: datetime = field(default_factory=_now)

    def is_expired(self) -> bool:
        return _now() >= self.expires_at


@dataclass
class CachedRoles:
    roles: Tuple[str, ...]
    allowed_routes: Tuple[str, ...]
    expires_at: datetime

    def is_expired(self) -> bool:
        return _now() >= self.expires_at


class SessionManager:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._lock = RLock()
        self._sessions: Dict[str, SessionData] = {}
        self._auth_flows: Dict[str, AuthFlowState] = {}
        self._role_cache: Dict[str, CachedRoles] = {}

    # --- Auth flow management -------------------------------------------------
    def store_login_flow(self, flow: Dict[str, Any]) -> None:
        state = flow.get("state")
        if not state:
            raise ValueError("MSAL flow missing state")
        with self._lock:
            self._auth_flows[state] = AuthFlowState(flow=flow, created_at=_now())

    def pop_login_flow(self, state: str) -> Dict[str, Any]:
        with self._lock:
            auth_flow = self._auth_flows.pop(state, None)
        if not auth_flow:
            raise KeyError("Unknown or expired state")
        return auth_flow.flow

    def clean_expired_flows(self, max_age_seconds: int = 600) -> None:
        cutoff = _now() - timedelta(seconds=max_age_seconds)
        with self._lock:
            stale = [state for state, flow in self._auth_flows.items() if flow.created_at < cutoff]
            for state in stale:
                self._auth_flows.pop(state, None)

    # --- Session cache --------------------------------------------------------
    def create_session(
        self,
        user: SessionUser,
        roles: Tuple[str, ...],
        allowed_routes: Tuple[str, ...],
        access_token: str,
        refresh_token: Optional[str],
        id_token_claims: Dict[str, Any],
        expires_in_seconds: int,
        token_expires_in: int,
    ) -> SessionData:
        session_id = secrets.token_urlsafe(48)
        csrf_token = self._new_csrf_token()
        now = _now()
        session = SessionData(
            session_id=session_id,
            user=user,
            roles=roles,
            allowed_routes=allowed_routes,
            access_token=access_token,
            refresh_token=refresh_token,
            id_token_claims=id_token_claims,
            expires_at=now + timedelta(seconds=expires_in_seconds),
            token_expires_at=now + timedelta(seconds=token_expires_in),
            csrf_token=csrf_token,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[SessionData]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            return None
        if session.is_expired():
            self.clear_session(session_id)
            return None
        session.last_active_at = _now()
        return session

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def should_refresh(self, session: SessionData) -> bool:
        skew = self._config.session.refresh_skew_seconds
        return _now() >= session.token_expires_at - timedelta(seconds=skew)

    def update_tokens(
        self,
        session: SessionData,
        access_token: str,
        refresh_token: Optional[str],
        expires_in: int,
        id_token_claims: Optional[Dict[str, Any]] = None,
    ) -> None:
        session.access_token = access_token
        if refresh_token:
            session.refresh_token = refresh_token
        session.token_expires_at = _now() + timedelta(seconds=expires_in)
        if id_token_claims:
            session.id_token_claims = id_token_claims

    def rotate_csrf(self, session: SessionData) -> str:
        session.csrf_token = self._new_csrf_token()
        return session.csrf_token

    # --- Role cache -----------------------------------------------------------
    def cache_roles(self, subject: str, roles: Tuple[str, ...], allowed_routes: Tuple[str, ...]) -> None:
        ttl_seconds = self._config.session.role_cache_ttl_seconds
        cache_entry = CachedRoles(
            roles=roles,
            allowed_routes=allowed_routes,
            expires_at=_now() + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._role_cache[subject] = cache_entry

    def get_cached_roles(self, subject: str) -> Optional[CachedRoles]:
        with self._lock:
            cached = self._role_cache.get(subject)
        if not cached:
            return None
        if cached.is_expired():
            with self._lock:
                self._role_cache.pop(subject, None)
            return None
        return cached

    # --- Cookie helpers ------------------------------------------------------
    def set_session_cookie(self, response: Response, session: SessionData) -> None:
        cookie_cfg = self._config.cookie
        response.set_cookie(
            cookie_cfg.name,
            session.session_id,
            max_age=cookie_cfg.max_age_minutes * 60,
            secure=cookie_cfg.secure,
            httponly=cookie_cfg.http_only,
            samesite=cookie_cfg.samesite,
            domain=cookie_cfg.domain,
            path="/",
        )

    def set_csrf_cookie(self, response: Response, csrf_token: str) -> None:
        csrf_cfg = self._config.csrf
        cookie_cfg = self._config.cookie
        response.set_cookie(
            csrf_cfg.cookie_name,
            csrf_token,
            max_age=cookie_cfg.max_age_minutes * 60,
            secure=cookie_cfg.secure,
            httponly=False,
            samesite=cookie_cfg.samesite,
            domain=self._config.cookie.domain,
            path="/",
        )

    def clear_cookies(self, response: Response) -> None:
        cookie_cfg = self._config.cookie
        csrf_cfg = self._config.csrf
        for name in (cookie_cfg.name, csrf_cfg.cookie_name):
            response.set_cookie(
                name,
                "",
                max_age=0,
                secure=cookie_cfg.secure,
                httponly=(name == cookie_cfg.name),
                samesite=cookie_cfg.samesite,
                domain=cookie_cfg.domain,
                path="/",
            )

    # --- Token / CSRF validation ----------------------------------------------
    def verify_csrf(self, session: SessionData, presented_token: Optional[str]) -> bool:
        return bool(presented_token) and secrets.compare_digest(session.csrf_token, presented_token)

    # --- Housekeeping ---------------------------------------------------------
    def prune(self) -> None:
        now = _now()
        with self._lock:
            expired_sessions = [sid for sid, sess in self._sessions.items() if sess.expires_at <= now]
            for sid in expired_sessions:
                self._sessions.pop(sid, None)
            expired_roles = [sub for sub, cache in self._role_cache.items() if cache.expires_at <= now]
            for sub in expired_roles:
                self._role_cache.pop(sub, None)

    def _new_csrf_token(self) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(48))
