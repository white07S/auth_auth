from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class CookieSettings:
    name: str
    domain: Optional[str]
    secure: bool
    samesite: str
    http_only: bool
    max_age_minutes: int


@dataclass
class CsrfSettings:
    cookie_name: str
    header_name: str


@dataclass
class SessionSettings:
    refresh_skew_seconds: int
    role_cache_ttl_seconds: int


@dataclass
class RBACSettings:
    group_to_role: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class Config:
    tenant_id: str
    client_id: str
    client_secret: Optional[str]
    client_certificate: Optional[Dict[str, Any]]
    authority_base: str
    redirect_uri: str
    post_logout_redirect_uri: str
    scopes: List[str]
    graph_scopes: List[str]
    cookie: CookieSettings
    csrf: CsrfSettings
    rbac: RBACSettings
    route_policies: Dict[str, List[str]]
    session: SessionSettings
    cors: Dict[str, Any]

    @property
    def authority(self) -> str:
        return f"{self.authority_base.rstrip('/')}/{self.tenant_id}"


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def load_config(path: Path) -> Config:
    data = yaml.safe_load(path.read_text())

    cookie_raw = data.get("cookie", {})
    csrf_raw = data.get("csrf", {})
    session_raw = data.get("session", {})
    cors_raw: Dict[str, Any] = data.get("cors", {})

    return Config(
        tenant_id=str(data["tenant_id"]),
        client_id=str(data["client_id"]),
        client_secret=data.get("client_secret"),
        client_certificate=data.get("client_certificate"),
        authority_base=str(data.get("authority_base", "https://login.microsoftonline.com")),
        redirect_uri=str(data["redirect_uri"]),
        post_logout_redirect_uri=str(data["post_logout_redirect_uri"]),
        scopes=_ensure_list(data.get("scopes", [])),
        graph_scopes=_ensure_list(data.get("graph_scopes", [])),
        cookie=CookieSettings(
            name=str(cookie_raw["name"]),
            domain=cookie_raw.get("domain"),
            secure=bool(cookie_raw.get("secure", True)),
            samesite=str(cookie_raw.get("samesite", "Lax")),
            http_only=bool(cookie_raw.get("http_only", True)),
            max_age_minutes=int(cookie_raw.get("max_age_minutes", 480)),
        ),
        csrf=CsrfSettings(
            cookie_name=str(csrf_raw["cookie_name"]),
            header_name=str(csrf_raw["header_name"]),
        ),
        rbac=RBACSettings(group_to_role={k: _ensure_list(v) for k, v in data.get("rbac", {}).get("group_to_role", {}).items()}),
        route_policies={k: _ensure_list(v) for k, v in data.get("route_policies", {}).items()},
        session=SessionSettings(
            refresh_skew_seconds=int(session_raw.get("refresh_skew_seconds", 300)),
            role_cache_ttl_seconds=int(session_raw.get("role_cache_ttl_seconds", 300)),
        ),
        cors=cors_raw,
    )
