from __future__ import annotations

from typing import Optional

import msal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AppConfig
from ..core.crypto import CryptoService
from ..db import models


class TokenCacheService:
    def __init__(self, config: AppConfig, crypto: CryptoService | None = None) -> None:
        self._config = config
        self._crypto = crypto

    def new_cache(self) -> msal.SerializableTokenCache:
        return msal.SerializableTokenCache()

    def _encrypt(self, payload: bytes) -> bytes:
        if self._config.security.token_at_rest_encryption and self._crypto:
            return self._crypto.encrypt(payload)
        return payload

    def _decrypt(self, payload: bytes) -> bytes:
        if self._config.security.token_at_rest_encryption and self._crypto:
            return self._crypto.decrypt(payload)
        return payload

    async def store_cache(self, db: AsyncSession, cache: msal.SerializableTokenCache) -> str:
        payload = cache.serialize()
        if not payload:
            raise ValueError("Token cache is empty; nothing to persist")

        token_cache = models.TokenCache(
            encrypted_cache_blob=self._encrypt(payload.encode("utf-8"))
        )
        db.add(token_cache)
        await db.commit()
        await db.refresh(token_cache)
        return token_cache.cache_key

    async def load_cache(
        self, db: AsyncSession, cache_key: str
    ) -> Optional[msal.SerializableTokenCache]:
        result = await db.execute(
            select(models.TokenCache).where(models.TokenCache.cache_key == cache_key)
        )
        token_cache = result.scalar_one_or_none()
        if not token_cache:
            return None

        blob = self._decrypt(token_cache.encrypted_cache_blob)
        cache = msal.SerializableTokenCache()
        cache.deserialize(blob.decode("utf-8"))
        return cache

    async def update_cache(
        self, db: AsyncSession, cache_key: str, cache: msal.SerializableTokenCache
    ) -> None:
        payload = cache.serialize()
        if not payload:
            return
        result = await db.execute(
            select(models.TokenCache).where(models.TokenCache.cache_key == cache_key)
        )
        token_cache = result.scalar_one_or_none()
        if not token_cache:
            raise ValueError("Token cache not found")

        token_cache.encrypted_cache_blob = self._encrypt(payload.encode("utf-8"))
        await db.commit()
