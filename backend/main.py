from __future__ import annotations

import logging
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.db import Database
from app.routes.auth import router as auth_router
from app.routes.internal import router as internal_router
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)

settings: Settings = get_settings()
database = Database(settings.database_path, pool_size=settings.database_pool_size)
auth_service = AuthService(settings, database)


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)
    origins: List[str] = settings.allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    async def on_startup() -> None:
        database.initialize()

    app.include_router(auth_router)
    app.include_router(internal_router)
    return app


def get_auth_service_instance() -> AuthService:
    return auth_service


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
