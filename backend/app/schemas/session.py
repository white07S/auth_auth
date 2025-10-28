from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class UserInfo(BaseModel):
    id: str = Field(alias="oid")
    display_name: str | None = None
    email: str | None = None

    model_config = {"populate_by_name": True}


class SessionResponse(BaseModel):
    is_authenticated: bool
    user: UserInfo | None = None
    roles: List[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class LoginStartResponse(BaseModel):
    authorization_url: str
    state: str


class LogoutResponse(BaseModel):
    success: bool = True
    redirect_url: str | None = None
