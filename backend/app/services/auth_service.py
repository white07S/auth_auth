from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx
import msal
from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool

from ..config import Settings
from ..db import Database
from ..models import (
    AuthState,
    CallbackResult,
    Session,
    SessionContext,
    User,
    format_timestamp,
    parse_timestamp,
)
from ..rbac import RBACResolver
from ..security import (
    TokenEncryptor,
    constant_time_compare,
    generate_csrf_token,
    generate_pkce_pair,
    generate_session_id,
    generate_state_nonce,
    hash_value,
)

logger = logging.getLogger(__name__)


@dataclass
class SessionCheckResult:
    session: Session
    user: User
    roles: List[str]
    permissions: List[str]
    idle_remaining_seconds: int


class AuthService:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.encryptor = TokenEncryptor(settings.ensure_token_key())
        self.rbac = RBACResolver(
            settings.resolved_groups_to_roles(),
            settings.resolved_roles_to_permissions(),
        )

    async def start_login(self, redirect_target: Optional[str]) -> str:
        state, nonce = generate_state_nonce()
        verifier, challenge = generate_pkce_pair()
        created_at = format_timestamp(datetime.now(timezone.utc))

        await run_in_threadpool(
            self.database.execute,
            "INSERT OR REPLACE INTO auth_states (state, code_verifier, nonce, redirect_target, created_at) VALUES (?, ?, ?, ?, ?)",
            (state, verifier, nonce, redirect_target or None, created_at),
        )

        params = {
            "client_id": self.settings.client_id,
            "response_type": "code",
            "redirect_uri": self.settings.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.settings.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        authorize_url = f"{self.settings.authority}/oauth2/v2.0/authorize?{urlencode(params)}"
        return authorize_url

    async def complete_login(
        self,
        *,
        code: str,
        state: str,
        user_agent: str,
        ip_address: Optional[str],
    ) -> CallbackResult:
        now = datetime.now(timezone.utc)
        state_row = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT * FROM auth_states WHERE state = ?",
            (state,),
        )
        if not state_row:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state.")
        auth_state = self._parse_auth_state(state_row)
        if now - auth_state.created_at > timedelta(seconds=self.settings.state_ttl_seconds):
            await run_in_threadpool(
                self.database.execute,
                "DELETE FROM auth_states WHERE state = ?",
                (state,),
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login state expired.")

        await run_in_threadpool(
            self.database.execute,
            "DELETE FROM auth_states WHERE state = ?",
            (state,),
        )

        token_response, cache = await self._exchange_code(code=code, code_verifier=auth_state.code_verifier)
        claims = token_response.get("id_token_claims", {})
        if not claims:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing ID token claims.")
        if claims.get("nonce") and not constant_time_compare(claims["nonce"], auth_state.nonce):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce mismatch.")

        oid = claims.get("oid") or claims.get("sub")
        if not oid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User identifier missing.")

        display_name = claims.get("name")
        email = claims.get("email") or claims.get("preferred_username")
        upn = claims.get("preferred_username")
        now_iso = format_timestamp(now)

        await self._upsert_user(oid=oid, upn=upn, display_name=display_name, email=email, last_seen=now_iso)
        await self._persist_token_cache(oid=oid, cache=cache, updated_at=now_iso)

        access_token = token_response.get("access_token")
        groups = self._extract_groups_from_claims(claims)
        if not groups and access_token:
            groups = await self._fetch_groups_from_graph(access_token)

        roles, permissions = self.rbac.resolve(groups)
        await self._persist_role_cache(oid=oid, roles=roles, permissions=permissions, now=now)

        session_id = generate_session_id()
        idle_expires_at = now + timedelta(seconds=self.settings.idle_timeout)
        absolute_expires_at = now + timedelta(seconds=self.settings.absolute_timeout)
        user_agent_hash = hash_value(user_agent) if user_agent else None
        ip_hash = hash_value(ip_address) if ip_address else None

        await run_in_threadpool(
            self.database.execute,
            """
            INSERT INTO sessions (session_id, oid, issued_at, last_seen_at, idle_expires_at, expires_at, user_agent_hash, ip_hash, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                session_id,
                oid,
                now_iso,
                now_iso,
                format_timestamp(idle_expires_at),
                format_timestamp(absolute_expires_at),
                user_agent_hash,
                ip_hash,
            ),
        )

        csrf_token = generate_csrf_token()
        csrf_expiry = now + timedelta(seconds=self.settings.csrf_ttl_seconds)
        await run_in_threadpool(
            self.database.execute,
            """
            INSERT OR REPLACE INTO csrf (session_id, csrf_token, issued_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                session_id,
                csrf_token,
                now_iso,
                format_timestamp(min(csrf_expiry, absolute_expires_at)),
            ),
        )

        await self._record_audit(
            action="auth.login.success",
            oid=oid,
            session_id=session_id,
            meta={"roles": roles, "permissions": permissions},
            ts=now_iso,
        )

        idle_remaining = max(int((idle_expires_at - now).total_seconds()), 0)

        user = await self._get_user(oid)
        if not user:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User record missing.")
        return CallbackResult(
            session_id=session_id,
            csrf_token=csrf_token,
            redirect_to=auth_state.redirect_target or self.settings.post_login_redirect,
            user=user,
            roles=roles,
            permissions=permissions,
            idle_remaining_seconds=idle_remaining,
            idle_expires_at=idle_expires_at,
            expires_at=absolute_expires_at,
        )

    async def validate_csrf(self, session_id: str, token: str) -> None:
        record = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT csrf_token, expires_at FROM csrf WHERE session_id = ?",
            (session_id,),
        )
        if not record:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing.")

        stored_token = record["csrf_token"]
        expires_at = parse_timestamp(record["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token expired.")
        if not constant_time_compare(stored_token, token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid.")

    async def get_session_context(self, session_id: str) -> Optional[SessionContext]:
        session = await self._get_active_session(session_id)
        if not session:
            return None

        if not self._session_is_active(session):
            await self._expire_session(session.session_id)
            return None

        user = await self._get_user(session.oid)
        if not user:
            await self._expire_session(session.session_id)
            return None

        roles, permissions = await self._load_roles(session.oid)
        if roles is None or permissions is None:
            refreshed = await self.refresh_roles(session.oid)
            roles, permissions = refreshed

        idle_remaining = max(int((session.idle_expires_at - datetime.now(timezone.utc)).total_seconds()), 0)
        return SessionContext(
            session=session,
            user=user,
            roles=roles,
            permissions=permissions,
            idle_remaining_seconds=idle_remaining,
            expires_at=session.expires_at,
        )

    async def refresh_tokens_if_needed(self, oid: str) -> Tuple[bool, Optional[int]]:
        cache = await self._load_token_cache(oid)
        if cache is None:
            return False, None

        app = self._build_msal_client(cache)
        accounts = app.get_accounts()
        if not accounts:
            return False, None

        result = await run_in_threadpool(
            lambda: app.acquire_token_silent(self.settings.scopes, account=accounts[0])
        )
        if not result or "access_token" not in result:
            return False, None

        expires_in = result.get("expires_in")
        should_force_refresh = expires_in is not None and expires_in <= self.settings.token_refresh_margin_seconds

        if should_force_refresh:
            result = await run_in_threadpool(
                lambda: app.acquire_token_silent(self.settings.scopes, account=accounts[0], force_refresh=True)
            )
            if not result or "access_token" not in result:
                return False, expires_in

        if cache.has_state_changed:
            await self._persist_serialized_cache(oid=oid, cache=cache)

        return True, expires_in

    async def refresh_roles(self, oid: str) -> Tuple[List[str], List[str]]:
        cache = await self._load_token_cache(oid)
        if cache is None:
            return [], []
        app = self._build_msal_client(cache)
        accounts = app.get_accounts()
        if not accounts:
            return [], []
        result = await run_in_threadpool(
            lambda: app.acquire_token_silent(["https://graph.microsoft.com/.default"], account=accounts[0])
        )
        access_token = result.get("access_token") if result else None
        groups: List[str] = []
        if access_token:
            groups = await self._fetch_groups_from_graph(access_token)
        roles, permissions = self.rbac.resolve(groups)
        await self._persist_role_cache(oid=oid, roles=roles, permissions=permissions, now=datetime.now(timezone.utc))
        if cache.has_state_changed:
            await self._persist_serialized_cache(oid=oid, cache=cache)
        return roles, permissions

    async def touch_session(self, session_id: str) -> Optional[int]:
        session = await self._get_active_session(session_id)
        if not session:
            return None
        now = datetime.now(timezone.utc)
        idle_expires_at = now + timedelta(seconds=self.settings.idle_timeout)
        idle_remaining = max(int((idle_expires_at - now).total_seconds()), 0)

        await run_in_threadpool(
            self.database.execute,
            """
            UPDATE sessions
            SET last_seen_at = ?, idle_expires_at = ?
            WHERE session_id = ?
            """,
            (format_timestamp(now), format_timestamp(min(idle_expires_at, session.expires_at)), session_id),
        )
        await run_in_threadpool(
            self.database.execute,
            "UPDATE users SET last_seen_at = ? WHERE oid = ?",
            (format_timestamp(now), session.oid),
        )
        return idle_remaining

    async def logout(self, session_id: str) -> None:
        session = await self._get_active_session(session_id)
        oid = session.oid if session else None
        now_iso = format_timestamp(datetime.now(timezone.utc))
        await run_in_threadpool(
            self.database.execute,
            "UPDATE sessions SET is_active = 0, expires_at = ?, idle_expires_at = ? WHERE session_id = ?",
            (now_iso, now_iso, session_id),
        )
        await run_in_threadpool(
            self.database.execute,
            "DELETE FROM csrf WHERE session_id = ?",
            (session_id,),
        )
        await self._record_audit("auth.logout", oid, session_id, {}, now_iso)

    async def _fetch_groups_from_graph(self, access_token: str) -> List[str]:
        headers = {"Authorization": f"Bearer {access_token}"}
        timeout = httpx.Timeout(self.settings.graph_request_timeout_seconds)
        url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id"
        groups: List[str] = []
        async with httpx.AsyncClient(timeout=timeout) as client:
            next_url: Optional[str] = url
            while next_url:
                response = await client.get(next_url, headers=headers)
                if response.status_code >= 400:
                    logger.warning("Graph call failed: %s %s", response.status_code, response.text)
                    break
                payload = response.json()
                for entry in payload.get("value", []):
                    group_id = entry.get("id")
                    if group_id:
                        groups.append(group_id)
                next_url = payload.get("@odata.nextLink")
        return groups

    async def _upsert_user(
        self,
        *,
        oid: str,
        upn: Optional[str],
        display_name: Optional[str],
        email: Optional[str],
        last_seen: str,
    ) -> None:
        existing = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT oid FROM users WHERE oid = ?",
            (oid,),
        )
        if existing:
            await run_in_threadpool(
                self.database.execute,
                """
                UPDATE users
                SET upn = ?, display_name = ?, email = ?, last_seen_at = ?
                WHERE oid = ?
                """,
                (upn, display_name, email, last_seen, oid),
            )
        else:
            await run_in_threadpool(
                self.database.execute,
                """
                INSERT INTO users (oid, upn, display_name, email, created_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (oid, upn, display_name, email, last_seen, last_seen),
            )

    async def _persist_token_cache(self, *, oid: str, cache: msal.SerializableTokenCache, updated_at: str) -> None:
        await self._persist_serialized_cache(oid=oid, cache=cache, updated_at=updated_at)

    async def _persist_serialized_cache(
        self,
        *,
        oid: str,
        cache: msal.SerializableTokenCache,
        updated_at: Optional[str] = None,
    ) -> None:
        if not cache.has_state_changed:
            return
        serialized = cache.serialize()
        encrypted = self.encryptor.encrypt(serialized)
        timestamp = updated_at or format_timestamp(datetime.now(timezone.utc))
        await run_in_threadpool(
            self.database.execute,
            """
            INSERT INTO token_cache (oid, cache_json_encrypted, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(oid) DO UPDATE SET cache_json_encrypted = excluded.cache_json_encrypted, updated_at = excluded.updated_at
            """,
            (oid, encrypted, timestamp),
        )

    async def _persist_role_cache(
        self,
        *,
        oid: str,
        roles: List[str],
        permissions: List[str],
        now: datetime,
    ) -> None:
        ttl = now + timedelta(seconds=self.settings.role_cache_ttl_seconds)
        await run_in_threadpool(
            self.database.execute,
            """
            INSERT INTO role_cache (oid, roles_json, permissions_json, updated_at, ttl_expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(oid) DO UPDATE SET
                roles_json = excluded.roles_json,
                permissions_json = excluded.permissions_json,
                updated_at = excluded.updated_at,
                ttl_expires_at = excluded.ttl_expires_at
            """,
            (
                oid,
                json.dumps(roles),
                json.dumps(permissions),
                format_timestamp(now),
                format_timestamp(ttl),
            ),
        )

    async def _load_roles(self, oid: str) -> Tuple[Optional[List[str]], Optional[List[str]]]:
        record = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT roles_json, permissions_json, ttl_expires_at FROM role_cache WHERE oid = ?",
            (oid,),
        )
        if not record:
            return None, None
        ttl_expires_at = parse_timestamp(record["ttl_expires_at"])
        if datetime.now(timezone.utc) > ttl_expires_at:
            return None, None
        roles = json.loads(record["roles_json"])
        permissions = json.loads(record["permissions_json"])
        return roles, permissions

    async def _load_token_cache(self, oid: str) -> Optional[msal.SerializableTokenCache]:
        record = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT cache_json_encrypted FROM token_cache WHERE oid = ?",
            (oid,),
        )
        if not record:
            return None
        encrypted = record["cache_json_encrypted"]
        serialized = self.encryptor.decrypt(encrypted)
        cache = msal.SerializableTokenCache()
        cache.deserialize(serialized)
        return cache

    async def _get_active_session(self, session_id: str) -> Optional[Session]:
        record = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        )
        if not record:
            return None
        session = Session.from_row(record)
        return session if session.is_active else None

    async def _expire_session(self, session_id: str) -> None:
        await run_in_threadpool(
            self.database.execute,
            "UPDATE sessions SET is_active = 0 WHERE session_id = ?",
            (session_id,),
        )

    async def _get_user(self, oid: str) -> Optional[User]:
        record = await run_in_threadpool(
            self.database.fetch_one,
            "SELECT * FROM users WHERE oid = ?",
            (oid,),
        )
        if not record:
            return None
        return User.from_row(record)

    def _session_is_active(self, session: Session) -> bool:
        now = datetime.now(timezone.utc)
        return session.is_active and now < session.expires_at and now < session.idle_expires_at

    def _build_msal_client(self, cache: msal.SerializableTokenCache) -> msal.ConfidentialClientApplication:
        return msal.ConfidentialClientApplication(
            self.settings.client_id,
            authority=self.settings.authority,
            token_cache=cache,
            **self.settings.client_credential,
        )

    async def _exchange_code(self, *, code: str, code_verifier: str) -> Tuple[Dict[str, str], msal.SerializableTokenCache]:
        cache = msal.SerializableTokenCache()
        app = msal.ConfidentialClientApplication(
            self.settings.client_id,
            authority=self.settings.authority,
            token_cache=cache,
            **self.settings.client_credential,
        )

        def _exchange() -> Dict[str, str]:
            return app.acquire_token_by_authorization_code(
                code,
                scopes=self.settings.scopes,
                redirect_uri=self.settings.redirect_uri,
                code_verifier=code_verifier,
            )

        token_response = await run_in_threadpool(_exchange)
        if not token_response or "error" in token_response:
            error = token_response.get("error_description") if token_response else "Unknown error"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Token exchange failed: {error}")
        return token_response, cache

    def _extract_groups_from_claims(self, claims: Dict[str, Any]) -> List[str]:
        if "groups" in claims:
            return list(claims["groups"])
        claim_names = claims.get("_claim_names", {})
        if isinstance(claim_names, dict) and "groups" in claim_names:
            return []
        if claims.get("hasgroups") is True:
            return []
        return []

    def _parse_auth_state(self, row: Dict[str, str]) -> AuthState:
        return AuthState(
            state=row["state"],
            code_verifier=row["code_verifier"],
            nonce=row.get("nonce", ""),
            redirect_target=row.get("redirect_target"),
            created_at=parse_timestamp(row["created_at"]),
        )

    async def _record_audit(
        self,
        action: str,
        oid: Optional[str],
        session_id: Optional[str],
        meta: Dict[str, Any],
        ts: str,
    ) -> None:
        if not self.settings.audit_log_enabled:
            return
        await run_in_threadpool(
            self.database.execute,
            """
            INSERT INTO audit (event_id, ts, oid, session_id, action, meta_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                generate_session_id(),
                ts,
                oid,
                session_id,
                action,
                json.dumps(meta or {}),
            ),
        )
