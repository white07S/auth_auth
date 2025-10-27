from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


def _parse_comma_separated(value: Optional[str]) -> List[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    app_name: str = Field(default="Auth BFF")
    environment: str = Field(default="development")

    authority: str = Field(
        default="https://login.microsoftonline.com/common",
        alias="AUTHORITY",
    )
    tenant_id: Optional[str] = Field(default=None, alias="TENANT_ID")
    client_id: str = Field(default="00000000-0000-0000-0000-000000000000", alias="CLIENT_ID")
    client_secret: Optional[str] = Field(default=None, alias="CLIENT_SECRET")
    client_certificate_path: Optional[Path] = Field(default=None, alias="CLIENT_CERTIFICATE_PATH")
    client_certificate_password: Optional[str] = Field(default=None, alias="CLIENT_CERTIFICATE_PASSWORD")
    redirect_uri: str = Field(default="http://localhost:8000/auth/callback", alias="REDIRECT_URI")

    graph_scopes: List[str] = Field(
        default_factory=lambda: ["openid", "profile", "email", "offline_access", "User.Read", "GroupMember.Read.All"],
        alias="GRAPH_SCOPES",
    )

    cors_allowed_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        alias="CORS_ALLOWED_ORIGINS",
    )

    database_path: Path = Field(default=Path("./.data/auth.db"), alias="DATABASE_PATH")
    database_pool_size: int = Field(default=5, alias="DATABASE_POOL_SIZE")

    cookie_name: str = Field(default="__Host_session", alias="COOKIE_NAME")
    cookie_domain: Optional[str] = Field(default=None, alias="COOKIE_DOMAIN")
    cookie_secure: bool = Field(default=False, alias="COOKIE_SECURE")
    cookie_samesite: str = Field(default="lax", alias="COOKIE_SAMESITE")
    cookie_path: str = Field(default="/", alias="COOKIE_PATH")
    cookie_idle_timeout_seconds: int = Field(default=20 * 60, alias="COOKIE_MAX_AGE")
    cookie_absolute_timeout_seconds: int = Field(default=8 * 60 * 60, alias="COOKIE_ABSOLUTE_MAX_AGE")

    csrf_cookie_name: str = Field(default="XSRF-TOKEN", alias="CSRF_COOKIE_NAME")
    csrf_header_name: str = Field(default="X-CSRF-Token", alias="CSRF_HEADER_NAME")
    csrf_ttl_seconds: int = Field(default=60 * 60 * 2, alias="CSRF_TTL_SECONDS")

    state_ttl_seconds: int = Field(default=10 * 60, alias="STATE_TTL_SECONDS")
    role_cache_ttl_seconds: int = Field(default=15 * 60, alias="ROLE_CACHE_TTL_SECONDS")
    token_refresh_margin_seconds: int = Field(default=5 * 60, alias="TOKEN_REFRESH_MARGIN_SECONDS")

    post_login_redirect: str = Field(default="/#/dashboard", alias="POST_LOGIN_REDIRECT")
    post_logout_redirect: str = Field(default="/#/logged-out", alias="POST_LOGOUT_REDIRECT")

    rbac_config_path: Optional[Path] = Field(default=None, alias="RBAC_CONFIG_PATH")
    groups_to_roles: Dict[str, List[str]] = Field(default_factory=dict, alias="GROUPS_TO_ROLES")
    roles_to_permissions: Dict[str, List[str]] = Field(default_factory=dict, alias="ROLES_TO_PERMISSIONS")

    token_encryption_key: Optional[str] = Field(default=None, alias="TOKEN_ENCRYPTION_KEY")

    graph_request_timeout_seconds: float = Field(default=5.0, alias="GRAPH_REQUEST_TIMEOUT_SECONDS")
    graph_page_size: int = Field(default=100, alias="GRAPH_PAGE_SIZE")

    audit_log_enabled: bool = Field(default=True, alias="AUDIT_LOG_ENABLED")

    def allowed_origins(self) -> List[str]:
        return self.cors_allowed_origins

    @property
    def use_https_cookies(self) -> bool:
        return self.cookie_secure or self.environment.lower() == "production"

    @property
    def idle_timeout(self) -> int:
        return self.cookie_idle_timeout_seconds

    @property
    def absolute_timeout(self) -> int:
        return self.cookie_absolute_timeout_seconds

    @property
    def scopes(self) -> List[str]:
        return self.graph_scopes

    @property
    def client_credential(self) -> Dict[str, Any]:
        if self.client_secret:
            return {"client_secret": self.client_secret}
        if self.client_certificate_path:
            cert_file = Path(self.client_certificate_path).expanduser()
            if not cert_file.exists():
                raise RuntimeError(f"Client certificate path not found: {cert_file}")
            with open(cert_file, "rb") as handle:
                cert_data = handle.read()
            return {
                "thumbprint": self.client_certificate_password or "",
                "private_key": cert_data.decode("utf-8"),
            }
        raise RuntimeError("CLIENT_SECRET or CLIENT_CERTIFICATE_PATH must be configured.")

    @model_validator(mode="before")
    @classmethod
    def _inflate_lists(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        def maybe_json(value: Any) -> Any:
            if isinstance(value, str):
                value = value.strip()
                if not value:
                    return []
                if value.startswith("[") or value.startswith("{"):
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        pass
                return _parse_comma_separated(value)
            return value

        list_fields = ("GRAPH_SCOPES", "CORS_ALLOWED_ORIGINS")
        mapping_fields = ("GROUPS_TO_ROLES", "ROLES_TO_PERMISSIONS")

        for field in list_fields:
            if field in data and not isinstance(data[field], list):
                data[field] = maybe_json(data[field])

        for field in mapping_fields:
            value = data.get(field)
            if value is None:
                continue
            if isinstance(value, str):
                value = value.strip()
                if not value:
                    data[field] = {}
                    continue
                if value.startswith("{"):
                    try:
                        data[field] = json.loads(value)
                        continue
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse JSON for %s", field)
                try:
                    parsed: Dict[str, List[str]] = {}
                    for pair in value.split(";"):
                        if not pair.strip():
                            continue
                        key, _, values = pair.partition("=")
                        parsed[key.strip()] = [v.strip() for v in values.split(",") if v.strip()]
                    data[field] = parsed
                except Exception as exc:
                    logger.warning("Could not parse mapping for %s: %s", field, exc)
                    data[field] = {}
        return data

    @model_validator(mode="after")
    def _load_rbac_config(self) -> "Settings":
        if self.rbac_config_path:
            config_path = Path(self.rbac_config_path).expanduser()
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as handle:
                    raw = yaml.safe_load(handle) or {}
                self.groups_to_roles = raw.get("groups_to_roles", self.groups_to_roles)
                self.roles_to_permissions = raw.get("roles_to_permissions", self.roles_to_permissions)
            else:
                logger.warning("RBAC config path not found: %s", config_path)
        return self

    def resolved_groups_to_roles(self) -> Dict[str, List[str]]:
        return self.groups_to_roles or {}

    def resolved_roles_to_permissions(self) -> Dict[str, List[str]]:
        return self.roles_to_permissions or {}

    def ensure_token_key(self) -> str:
        if self.token_encryption_key:
            return self.token_encryption_key
        logger.warning("TOKEN_ENCRYPTION_KEY is not set; generating ephemeral key (development only).")
        from cryptography.fernet import Fernet

        generated = Fernet.generate_key().decode("utf-8")
        self.token_encryption_key = generated
        return generated


@lru_cache
def get_settings() -> Settings:
    return Settings()
