from __future__ import annotations

from typing import AsyncIterator, Optional, Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .container import AppContainer
from .services.session import SessionData
from .core.security import now_utc


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


async def get_db_session(
    container: AppContainer = Depends(get_container),
) -> AsyncIterator[AsyncSession]:
    async with container.database.session() as session:
        yield session


async def get_current_session(
    request: Request,
    container: AppContainer = Depends(get_container),
    db: AsyncSession = Depends(get_db_session),
) -> Optional[SessionData]:
    session_cookie = container.config.session.cookie_name
    cookie_value = request.cookies.get(session_cookie)
    if not cookie_value:
        return None

    session_id = container.session_service.decode_cookie_value(cookie_value)
    if not session_id:
        return None

    session_data = await container.session_service.get_session(db, session_id)
    if not session_data:
        return None

    if session_data.expires_at <= now_utc():
        await container.session_service.delete_session(db, session_id)
        return None

    await container.session_service.touch_session(db, session_id)
    return session_data


async def get_graph_access_token(
    container: AppContainer = Depends(get_container),
    session: SessionData | None = Depends(get_current_session),
    db: AsyncSession = Depends(get_db_session),
) -> str:
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not session.token_cache_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token cache missing")

    cache = await container.token_cache.load_cache(db, session.token_cache_key)
    if not cache:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token cache missing")

    access_token, cache = await container.oidc.exchange_on_behalf_of(
        cache,
        container.config.azure.graph_scopes,
    )
    await container.token_cache.update_cache(db, session.token_cache_key, cache)
    return access_token


async def require_session(
    session: SessionData | None = Depends(get_current_session),
) -> SessionData:
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return session


def require_roles(*roles: str) -> Callable[[SessionData], SessionData]:
    async def _dependency(
        container: AppContainer = Depends(get_container),
        session: SessionData = Depends(require_session),
    ) -> SessionData:
        decision = container.rbac.evaluate(roles, session.roles)
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"missing_roles": decision.missing_roles},
            )
        return session

    return _dependency


async def enforce_csrf(
    request: Request,
    container: AppContainer = Depends(get_container),
    session: SessionData = Depends(require_session),
) -> None:
    if not container.config.csrf.enabled:
        return
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    header_token = request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRF")
    cookie_token = request.cookies.get("csrf_token")
    if not header_token or not cookie_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing CSRF token")
    if header_token != cookie_token or session.csrf_token != cookie_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
