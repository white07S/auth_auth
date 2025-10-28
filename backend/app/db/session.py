from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import AppConfig
from .base import Base


class Database:
    """
    Wrapper around SQLAlchemy async engine/session creation to keep the rest of
    the codebase tidy.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        db_url = f"sqlite+aiosqlite:///{config.sqlite.db_path}"
        self._engine: AsyncEngine = create_async_engine(db_url, future=True, echo=False)
        self._session_factory = async_sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session:
            yield session

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def apply_sqlite_pragmas(self) -> None:
        pragmas = self._config.sqlite.pragmas
        if not pragmas:
            return
        async with self._engine.connect() as conn:
            for key, value in pragmas.items():
                await conn.execute(f"PRAGMA {key}={value}")
            await conn.commit()


__all__ = ["Database"]
