from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import dependencies
from ..db import models
from ..services.session import SessionData

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/health")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/me")
async def me(
    session: SessionData = Depends(dependencies.require_session),
    db: AsyncSession = Depends(dependencies.get_db_session),
):
    result = await db.execute(select(models.User).where(models.User.id == session.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return {
        "id": user.oid,
        "displayName": user.display_name,
        "email": user.email,
        "roles": session.roles,
    }


@router.get("/admin/summary")
async def admin_summary(
    session: SessionData = Depends(dependencies.require_roles("admin")),
):
    return {
        "message": "Restricted admin summary",
        "user": session.session_id,
        "roles": session.roles,
    }


@router.post("/audit")
async def audit_event(
    payload: dict,
    session: SessionData = Depends(dependencies.require_session),
    _: None = Depends(dependencies.enforce_csrf),
) -> dict:
    # This route demonstrates the CSRF protection dependency pattern.
    return {
        "received": payload,
        "user": session.session_id,
    }
