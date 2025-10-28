from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI

from .config import AppConfig
from .core.crypto import CryptoService
from .db import Database
from .services.oidc import GraphService, OIDCService
from .services.rbac import RBACService
from .services.session import AuthRequestService, SessionService
from .services.token_cache import TokenCacheService
from .services.user import UserService


@dataclass
class AppContainer:
    config: AppConfig
    database: Database
    crypto: CryptoService
    oidc: OIDCService
    graph: GraphService
    token_cache: TokenCacheService
    session_service: SessionService
    auth_request_service: AuthRequestService
    rbac: RBACService
    user_service: UserService

    @classmethod
    def build(cls, config: AppConfig) -> "AppContainer":
        database = Database(config)
        crypto = CryptoService(config.security.token_encryption_secret)
        token_cache = TokenCacheService(config, crypto)
        oidc_service = OIDCService(config, token_cache)
        graph_service = GraphService()
        session_service = SessionService(config)
        auth_request_service = AuthRequestService()
        rbac_service = RBACService(config)
        user_service = UserService()

        return cls(
            config=config,
            database=database,
            crypto=crypto,
            oidc=oidc_service,
            graph=graph_service,
            token_cache=token_cache,
            session_service=session_service,
            auth_request_service=auth_request_service,
            rbac=rbac_service,
            user_service=user_service,
        )

    async def startup(self, app: FastAPI) -> None:
        await self.database.create_all()
        await self.database.apply_sqlite_pragmas()
        app.state.container = self

    async def shutdown(self, app: FastAPI) -> None:
        await self.graph.close()
