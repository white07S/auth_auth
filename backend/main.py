from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import AppConfig, load_config
from app.container import AppContainer
from app.routers import auth, graph, secured


def _resolve_config_path() -> Path:
    candidate = os.environ.get("APP_CONFIG_PATH")
    if candidate:
        return Path(candidate)
    return Path(__file__).resolve().parent / "config.yaml"


def create_application() -> FastAPI:
    config_path = _resolve_config_path()
    config: AppConfig = load_config(config_path)
    container = AppContainer.build(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await container.startup(app)
        try:
            yield
        finally:
            await container.shutdown(app)

    app = FastAPI(title="Auth BFF", version="0.1.0", lifespan=lifespan)

    if config.server.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.server.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(auth.router)
    app.include_router(graph.router)
    app.include_router(secured.router)

    @app.get("/")
    async def root():
        return {
            "name": "Auth BFF",
            "ui": {
                "authenticated": config.ui.default_authenticated_route,
                "loggedOut": config.ui.default_logged_out_route,
            },
        }

    return app


app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
