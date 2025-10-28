from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import dependencies
from ..config import AppConfig
from ..core.security import generate_code_verifier, generate_nonce, generate_state
from ..db import models
from ..schemas.session import LoginStartResponse, LogoutResponse, SessionResponse, UserInfo
from ..services.session import SessionData

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, config: AppConfig, cookie_value: str) -> None:
    max_age = config.session.max_age_minutes * 60
    response.set_cookie(
        key=config.session.cookie_name,
        value=cookie_value,
        max_age=max_age,
        secure=config.session.secure,
        httponly=config.session.http_only,
        samesite=config.session.same_site.capitalize(),
    )


def _clear_session_cookies(response: Response, config: AppConfig) -> None:
    response.delete_cookie(config.session.cookie_name)
    if config.csrf.enabled:
        response.delete_cookie("csrf_token")


@router.get("/login", response_model=LoginStartResponse)
async def start_login(
    container=Depends(dependencies.get_container),
    db: AsyncSession = Depends(dependencies.get_db_session),
) -> LoginStartResponse:
    state = generate_state()
    nonce = generate_nonce()
    code_verifier = generate_code_verifier()
    redirect_uri = str(container.config.azure.redirect_uri)

    await container.auth_request_service.create_auth_request(
        db,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )

    authorization_url = container.oidc.build_authorization_url(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )

    return LoginStartResponse(authorization_url=authorization_url, state=state)


@router.get("/callback")
async def oidc_callback(
    code: str,
    state: str,
    container=Depends(dependencies.get_container),
    db: AsyncSession = Depends(dependencies.get_db_session),
):
    config = container.config
    auth_req = await container.auth_request_service.consume_auth_request(db, state)
    if not auth_req:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter")

    token_result, token_cache = await container.oidc.redeem_code(
        code=code,
        redirect_uri=auth_req.redirect_uri,
        code_verifier=auth_req.code_verifier,
    )

    id_claims = token_result.get("id_token_claims", {})
    if config.security.validate_state_nonce and id_claims.get("nonce") != auth_req.nonce:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce mismatch")

    access_token = token_result.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication did not return an access token",
        )

    profile = await container.graph.get_user_profile(access_token)
    groups = await container.graph.get_user_groups(access_token)

    user = await container.user_service.upsert_user(
        db,
        oid=id_claims.get("oid") or profile.get("id"),
        profile=profile,
    )

    group_ids = [group.get("id") for group in groups if group.get("id")]
    roles = container.rbac.groups_to_roles(group_ids)

    token_cache_key = await container.token_cache.store_cache(db, token_cache)
    csrf_token = generate_state() if config.csrf.enabled else None
    session_data = await container.session_service.create_session(
        db,
        user=user,
        roles=roles,
        token_cache_key=token_cache_key,
        csrf_token=csrf_token,
    )

    response = RedirectResponse(
        url=config.ui.default_authenticated_route, status_code=status.HTTP_303_SEE_OTHER
    )
    cookie_value = container.session_service.encode_cookie_value(session_data.session_id)
    _set_session_cookie(response, config, cookie_value)
    if config.csrf.enabled and csrf_token:
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            secure=config.session.secure,
            httponly=False,
            samesite=config.session.same_site.capitalize(),
        )
    return response


@router.get("/session", response_model=SessionResponse)
async def current_session(
    container=Depends(dependencies.get_container),
    session_data: Optional[SessionData] = Depends(dependencies.get_current_session),
    db: AsyncSession = Depends(dependencies.get_db_session),
) -> SessionResponse:
    if not session_data:
        return SessionResponse(is_authenticated=False, user=None, roles=[], expires_at=None)

    result = await db.execute(select(models.User).where(models.User.id == session_data.user_id))
    user = result.scalar_one_or_none()
    if not user:
        await container.session_service.delete_session(db, session_data.session_id)
        return SessionResponse(is_authenticated=False, user=None, roles=[], expires_at=None)

    return SessionResponse(
        is_authenticated=True,
        user=UserInfo(oid=user.oid, display_name=user.display_name, email=user.email),
        roles=session_data.roles,
        expires_at=session_data.expires_at,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    container=Depends(dependencies.get_container),
    db: AsyncSession = Depends(dependencies.get_db_session),
) -> JSONResponse:
    session_cookie = container.config.session.cookie_name
    cookie_value = request.cookies.get(session_cookie)
    if cookie_value:
        session_id = container.session_service.decode_cookie_value(cookie_value)
        if session_id:
            await container.session_service.delete_session(db, session_id)

    payload = LogoutResponse(success=True)
    if container.config.azure.tenant_id:
        redirect = container.config.ui.default_logged_out_route
        payload.redirect_url = (
            "https://login.microsoftonline.com/"
            f"{container.config.azure.tenant_id}/oauth2/v2.0/logout"
            f"?post_logout_redirect_uri={redirect}"
        )

    response = JSONResponse(content=payload.model_dump())
    _clear_session_cookies(response, container.config)
    return response
