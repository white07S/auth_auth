from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .api.routes import router as api_router
from .auth.routes import router as auth_router
from .auth.sessions import SessionData, SessionManager
from .auth.ms_client import MsalClient
from .bff.graph import GraphClient
from .config import Config, load_config
from .runtime import RuntimeContext


def create_app(config_path: Optional[Path] = None) -> FastAPI:
    base_path = Path(__file__).resolve().parent
    cfg_path = config_path or base_path / "config.yaml"
    config = load_config(cfg_path)
    session_manager = SessionManager(config)
    msal_client = MsalClient(config)
    graph_client = GraphClient()

    runtime = RuntimeContext(
        config=config,
        session_manager=session_manager,
        msal_client=msal_client,
        graph_client=graph_client,
    )

    app = FastAPI(title="Auth BFF")
    app.state.runtime = runtime  # type: ignore[attr-defined]

    allowed_origins = config.cors.get("allowed_origins") or []
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )

    app.add_middleware(RBACMiddleware, runtime=runtime)

    app.include_router(auth_router)
    app.include_router(api_router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


class RBACMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, runtime: RuntimeContext) -> None:
        super().__init__(app)
        self._runtime = runtime
        self._allowed_without_auth = {
            "/openapi.json",
            "/docs",
            "/docs/index.html",
            "/redoc",
            "/healthz",
            "/favicon.ico",
        }

    async def dispatch(self, request: Request, call_next: Callable[[Request], Response]) -> Response:
        path = request.url.path
        if path.startswith("/auth") or path in self._allowed_without_auth:
            return await call_next(request)

        self._runtime.session_manager.prune()

        session_id = request.cookies.get(self._runtime.config.cookie.name)
        if not session_id:
            return self._unauthorized_response()

        session = self._runtime.session_manager.get_session(session_id)
        if not session:
            return self._unauthorized_response(clear=True)

        if request.method not in ("GET", "HEAD", "OPTIONS"):
            csrf_header = request.headers.get(self._runtime.config.csrf.header_name)
            if not self._runtime.session_manager.verify_csrf(session, csrf_header):
                return JSONResponse({"detail": "Invalid CSRF token"}, status_code=status.HTTP_403_FORBIDDEN)

        if self._runtime.session_manager.should_refresh(session) and session.refresh_token:
            try:
                refreshed = await self._runtime.msal_client.refresh_tokens(session.refresh_token)
            except RuntimeError:
                self._runtime.session_manager.clear_session(session.session_id)
                return self._unauthorized_response(clear=True)
            self._runtime.session_manager.update_tokens(
                session,
                access_token=refreshed.get("access_token", session.access_token),
                refresh_token=refreshed.get("refresh_token"),
                expires_in=int(refreshed.get("expires_in", 3600)),
                id_token_claims=refreshed.get("id_token_claims"),
            )

        if not self._is_route_allowed(session, path):
            return JSONResponse({"detail": "Forbidden"}, status_code=status.HTTP_403_FORBIDDEN)

        request.state.session = session
        return await call_next(request)

    def _is_route_allowed(self, session: SessionData, path: str) -> bool:
        normalized = self._normalize_path(path)
        route_policies = self._runtime.config.route_policies

        required_roles = route_policies.get(normalized)
        if not required_roles and normalized.startswith("/api/"):
            trimmed = self._normalize_path("/" + normalized[len("/api/") :])
            required_roles = route_policies.get(trimmed)

        if not required_roles:
            return False

        return any(role in session.roles for role in required_roles)

    def _normalize_path(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return path

    def _unauthorized_response(self, clear: bool = False) -> Response:
        response = JSONResponse({"detail": "Not authenticated"}, status_code=status.HTTP_401_UNAUTHORIZED)
        if clear:
            self._runtime.session_manager.clear_cookies(response)
        return response


app = create_app()
