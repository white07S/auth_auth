from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth.sessions import SessionData


router = APIRouter(prefix="/api", tags=["api"])


def get_session(request: Request) -> SessionData:
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return session


@router.get("/docs")
async def docs_endpoint(session: SessionData = Depends(get_session)) -> dict:
    return {"page": "docs", "user": session.user.name, "roles": session.roles}


@router.get("/scenario")
async def scenario_endpoint(session: SessionData = Depends(get_session)) -> dict:
    return {"page": "scenario", "user": session.user.name}


@router.get("/chat")
async def chat_endpoint(session: SessionData = Depends(get_session)) -> dict:
    return {"page": "chat", "user": session.user.name}


@router.get("/task")
async def task_endpoint(session: SessionData = Depends(get_session)) -> dict:
    return {"page": "task", "user": session.user.name}


@router.get("/dashboard")
async def dashboard_endpoint(session: SessionData = Depends(get_session)) -> dict:
    return {"page": "dashboard", "user": session.user.name, "roles": session.roles}
