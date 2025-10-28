from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from ..runtime import RuntimeContext
from .claims import extract_user, resolve_roles_and_routes
from .sessions import SessionUser


router = APIRouter(prefix="/auth", tags=["auth"])


def get_runtime(request: Request) -> RuntimeContext:
    runtime: RuntimeContext = request.app.state.runtime  # type: ignore[attr-defined]
    return runtime

@router.post("/login")
async def login(
    runtime: RuntimeContext = Depends(get_runtime),
) -> Response:
    runtime.session_manager.clean_expired_flows()
    flow = runtime.msal_client.initiate_auth_flow()
    runtime.session_manager.store_login_flow(flow)
    auth_uri = flow.get("auth_uri")
    if not auth_uri:
        raise HTTPException(status_code=500, detail="Failed to initiate Microsoft login flow")
    return RedirectResponse(auth_uri, status_code=status.HTTP_302_FOUND)


@router.get("/callback")
async def callback(
    request: Request,
    runtime: RuntimeContext = Depends(get_runtime),
) -> Response:
    state = request.query_params.get("state")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing state")
    try:
        flow = runtime.session_manager.pop_login_flow(state)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state") from exc

    token_response = await runtime.msal_client.acquire_tokens(flow, request.query_params)

    id_token_claims: Dict[str, Any] = token_response.get("id_token_claims") or {}
    user_info = extract_user(id_token_claims)
    subject = user_info.get("oid") or user_info.get("email") or user_info.get("name") or ""

    cached_roles = runtime.session_manager.get_cached_roles(subject) if subject else None
    if cached_roles:
        roles, allowed_routes = cached_roles.roles, cached_roles.allowed_routes
    else:
        roles, allowed_routes = await resolve_roles_and_routes(
            config=runtime.config,
            id_token_claims=id_token_claims,
            access_token=token_response.get("access_token", ""),
            graph_client=runtime.graph_client,
        )
        if subject:
            runtime.session_manager.cache_roles(subject, roles, allowed_routes)

    expires_in_seconds = runtime.config.cookie.max_age_minutes * 60
    token_expires_in = int(token_response.get("expires_in", 3600))
    refresh_token = token_response.get("refresh_token")
    access_token = token_response.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Missing access token in response")

    session = runtime.session_manager.create_session(
        user=SessionUser(
            name=user_info.get("name") or "Unknown user",
            email=user_info.get("email"),
            oid=user_info.get("oid"),
            tenant_id=user_info.get("tenant_id"),
        ),
        roles=roles,
        allowed_routes=allowed_routes,
        access_token=access_token,
        refresh_token=refresh_token,
        id_token_claims=id_token_claims,
        expires_in_seconds=expires_in_seconds,
        token_expires_in=token_expires_in,
    )

    response = RedirectResponse(runtime.config.redirect_uri, status_code=status.HTTP_302_FOUND)
    runtime.session_manager.set_session_cookie(response, session)
    runtime.session_manager.set_csrf_cookie(response, session.csrf_token)
    return response


@router.post("/logout")
async def logout(
    request: Request,
    runtime: RuntimeContext = Depends(get_runtime),
) -> Response:
    session_cookie = runtime.config.cookie.name
    session_id = request.cookies.get(session_cookie)
    if session_id:
        runtime.session_manager.clear_session(session_id)
    response = RedirectResponse(runtime.msal_client.build_logout_url(), status_code=status.HTTP_302_FOUND)
    runtime.session_manager.clear_cookies(response)
    return response


@router.get("/post-logout")
async def post_logout(runtime: RuntimeContext = Depends(get_runtime)) -> Response:
    return RedirectResponse(runtime.config.post_logout_redirect_uri, status_code=status.HTTP_302_FOUND)


@router.get("/session")
async def session_info(
    request: Request,
    runtime: RuntimeContext = Depends(get_runtime),
) -> Response:
    session_cookie = runtime.config.cookie.name
    session_id = request.cookies.get(session_cookie)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session = runtime.session_manager.get_session(session_id)
    if not session:
        response = JSONResponse({"detail": "Not authenticated"}, status_code=status.HTTP_401_UNAUTHORIZED)
        runtime.session_manager.clear_cookies(response)
        return response

    if runtime.session_manager.should_refresh(session) and session.refresh_token:
        try:
            refreshed = await runtime.msal_client.refresh_tokens(session.refresh_token)
        except RuntimeError:
            runtime.session_manager.clear_session(session.session_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
        runtime.session_manager.update_tokens(
            session,
            access_token=refreshed.get("access_token", session.access_token),
            refresh_token=refreshed.get("refresh_token"),
            expires_in=int(refreshed.get("expires_in", 3600)),
            id_token_claims=refreshed.get("id_token_claims"),
        )

    body = {
        "user": {
            "name": session.user.name,
            "email": session.user.email,
            "tenant_id": session.user.tenant_id,
            "oid": session.user.oid,
        },
        "roles": list(session.roles),
        "allowed_routes": list(session.allowed_routes),
        "expires_at": session.expires_at.isoformat(),
        "token_expires_at": session.token_expires_at.isoformat(),
    }
    response = JSONResponse(body)
    runtime.session_manager.set_csrf_cookie(response, session.csrf_token)
    return response
