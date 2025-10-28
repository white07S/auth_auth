from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.security import now_utc
from ..db import models


class UserService:
    async def upsert_user(
        self,
        db: AsyncSession,
        oid: str,
        profile: Dict[str, Any],
    ) -> models.User:
        result = await db.execute(select(models.User).where(models.User.oid == oid))
        user = result.scalar_one_or_none()
        if not user:
            user = models.User(
                oid=oid,
                upn=profile.get("userPrincipalName"),
                email=profile.get("mail") or profile.get("userPrincipalName"),
                display_name=profile.get("displayName"),
                created_at=now_utc(),
                last_login=now_utc(),
            )
            db.add(user)
        else:
            user.last_login = now_utc()
            user.display_name = profile.get("displayName", user.display_name)
            user.email = profile.get("mail") or profile.get("userPrincipalName", user.email)

        await db.commit()
        await db.refresh(user)
        return user
