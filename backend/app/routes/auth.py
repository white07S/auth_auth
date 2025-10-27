from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from ..config import Settings, get_settings
from ..services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    # Lazy import to avoid circular dependency when module is imported during app startup.
    from ..main import get_auth_service_instance

    return get_auth_service_instance()


@router.get("/login")
async def login(
    request: Request,
    redirect: Optional[str] = None,
    service: AuthService = Depends(get_auth_service),
) -> Response:
    authorize_url = await service.start_login(redirect_target=redirect)
    return RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)


@router.get("/callback")
async def callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    if error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=error)
    if not code or not state:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Missing authorization parameters.")

    user_agent = request.headers.get("user-agent", "")
    ip_address = request.client.host if request.client else None
    result = await service.complete_login(code=code, state=state, user_agent=user_agent, ip_address=ip_address)

    redirect_response = RedirectResponse(url=result.redirect_to, status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(redirect_response, settings, result.session_id, result.idle_remaining_seconds)
    _set_csrf_cookie(redirect_response, settings, result.csrf_token)
    return redirect_response


@router.get("/me")
async def me(
    request: Request,
    service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    session_id = _require_session_cookie(request, settings)
    context = await service.get_session_context(session_id)
    if not context:
        return JSONResponse(
            {"authenticated": False},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    await service.refresh_tokens_if_needed(context.user.oid)

    return JSONResponse(
        {
            "authenticated": True,
            "user": {
                "displayName": context.user.display_name,
                "email": context.user.email,
            },
            "roles": context.roles,
            "permissions": context.permissions,
            "exp": int(context.expires_at.timestamp()),
            "idleRemainingSec": context.idle_remaining_seconds,
        }
    )


@router.post("/refresh")
async def refresh(
    request: Request,
    service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    session_id = _require_session_cookie(request, settings)
    csrf_token = _require_csrf_header(request, settings)
    await service.validate_csrf(session_id, csrf_token)

    context = await service.get_session_context(session_id)
    if not context:
        return JSONResponse(
            {"authenticated": False},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    refreshed, expires_in = await service.refresh_tokens_if_needed(context.user.oid)
    idle_remaining = await service.touch_session(session_id)

    payload = {
        "refreshed": refreshed,
        "expiresIn": expires_in,
        "idleRemainingSec": idle_remaining or context.idle_remaining_seconds,
    }
    response = JSONResponse(payload)
    if idle_remaining:
        _set_session_cookie(response, settings, session_id, idle_remaining)
    return response


@router.post("/logout")
async def logout(
    request: Request,
    service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    session_id = _require_session_cookie(request, settings)
    csrf_token = _require_csrf_header(request, settings)
    await service.validate_csrf(session_id, csrf_token)
    await service.logout(session_id)

    response = JSONResponse({"success": True, "redirectTo": settings.post_logout_redirect})
    _clear_session_cookie(response, settings)
    _clear_csrf_cookie(response, settings)
    return response


@router.post("/heartbeat")
async def heartbeat(
    request: Request,
    service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    session_id = _require_session_cookie(request, settings)
    csrf_token = _require_csrf_header(request, settings)
    await service.validate_csrf(session_id, csrf_token)

    idle_remaining = await service.touch_session(session_id)
    if idle_remaining is None:
        return JSONResponse({"authenticated": False}, status_code=status.HTTP_401_UNAUTHORIZED)

    response = JSONResponse({"alive": True, "idleRemainingSec": idle_remaining})
    _set_session_cookie(response, settings, session_id, idle_remaining)
    return response


def _require_session_cookie(request: Request, settings: Settings) -> str:
    session_id = request.cookies.get(settings.cookie_name)
    if not session_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session missing.")
    return session_id


def _require_csrf_header(request: Request, settings: Settings) -> str:
    token = request.headers.get(settings.csrf_header_name)
    if not token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Missing CSRF token.")
    return token


def _set_session_cookie(response: Response, settings: Settings, value: str, max_age: int) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=value,
        max_age=max_age,
        path=settings.cookie_path,
        domain=settings.cookie_domain,
        secure=settings.use_https_cookies,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _set_csrf_cookie(response: Response, settings: Settings, value: str) -> None:
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=value,
        max_age=settings.csrf_ttl_seconds,
        path=settings.cookie_path,
        domain=settings.cookie_domain,
        secure=settings.use_https_cookies,
        httponly=False,
        samesite=settings.cookie_samesite,
    )


def _clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.cookie_name,
        path=settings.cookie_path,
        domain=settings.cookie_domain,
    )


def _clear_csrf_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        path=settings.cookie_path,
        domain=settings.cookie_domain,
    )
