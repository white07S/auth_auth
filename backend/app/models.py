from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class User:
    oid: str
    upn: Optional[str]
    display_name: Optional[str]
    email: Optional[str]
    created_at: datetime
    last_seen_at: datetime

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "User":
        return cls(
            oid=row["oid"],
            upn=row.get("upn"),
            display_name=row.get("display_name"),
            email=row.get("email"),
            created_at=parse_timestamp(row["created_at"]),
            last_seen_at=parse_timestamp(row["last_seen_at"]),
        )


@dataclass
class Session:
    session_id: str
    oid: str
    issued_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    expires_at: datetime
    user_agent_hash: Optional[str]
    ip_hash: Optional[str]
    is_active: bool

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Session":
        return cls(
            session_id=row["session_id"],
            oid=row["oid"],
            issued_at=parse_timestamp(row["issued_at"]),
            last_seen_at=parse_timestamp(row["last_seen_at"]),
            idle_expires_at=parse_timestamp(row["idle_expires_at"]),
            expires_at=parse_timestamp(row["expires_at"]),
            user_agent_hash=row.get("user_agent_hash"),
            ip_hash=row.get("ip_hash"),
            is_active=bool(row.get("is_active", 0)),
        )


@dataclass
class RoleCache:
    oid: str
    roles: List[str]
    permissions: List[str]
    updated_at: datetime
    ttl_expires_at: datetime

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "RoleCache":
        return cls(
            oid=row["oid"],
            roles=row.get("roles_json", []),
            permissions=row.get("permissions_json", []),
            updated_at=parse_timestamp(row["updated_at"]),
            ttl_expires_at=parse_timestamp(row["ttl_expires_at"]),
        )


@dataclass
class AuthState:
    state: str
    code_verifier: str
    nonce: str
    redirect_target: Optional[str]
    created_at: datetime

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "AuthState":
        return cls(
            state=row["state"],
            code_verifier=row["code_verifier"],
            nonce=row.get("nonce", ""),
            redirect_target=row.get("redirect_target"),
            created_at=parse_timestamp(row["created_at"]),
        )


@dataclass
class CallbackResult:
    session_id: str
    csrf_token: str
    redirect_to: str
    user: User
    roles: List[str]
    permissions: List[str]
    idle_remaining_seconds: int
    idle_expires_at: datetime
    expires_at: datetime


@dataclass
class SessionContext:
    session: Session
    user: User
    roles: List[str]
    permissions: List[str]
    idle_remaining_seconds: int
    expires_at: datetime
