"""
Application configuration loader and validation.

The entire backend is driven from a single ``config.yaml`` file so projects can
be bootstrapped and customised without code changes.  The schema below captures
the requirements outlined in ``requirements.txt`` while remaining flexible for
future expansion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_validator


class AzureConfig(BaseModel):
    tenant_id: str
    client_id: str
    authority_url: Optional[AnyHttpUrl] = None
    client_secret: Optional[str] = Field(default=None, repr=False)
    client_certificate_path: Optional[Path] = Field(default=None)
    client_certificate_thumbprint: Optional[str] = None
    redirect_uri: AnyHttpUrl
    graph_scopes: List[str] = Field(default_factory=lambda: ["User.Read"])
    require_pkce: bool = True
    validate_state_nonce: bool = True
    enforce_issuer_aud: bool = True

    @model_validator(mode="after")
    def validate_credentials(cls, values: "AzureConfig") -> "AzureConfig":
        if not values.client_secret and not values.client_certificate_path:
            raise ValueError("One of client_secret or client_certificate_path must be set")
        if values.client_certificate_path and not values.client_certificate_thumbprint:
            raise ValueError(
                "client_certificate_thumbprint must be set when client_certificate_path is provided"
            )
        return values


class RBACConfig(BaseModel):
    group_role_map: Dict[str, List[str]] = Field(default_factory=dict)
    route_policies: Dict[str, List[str]] = Field(default_factory=dict)
    evaluation_mode: str = Field(default="any_of")
    group_refresh_ttl_minutes: int = Field(default=60, ge=1)

    @field_validator("evaluation_mode")
    @classmethod
    def validate_eval_mode(cls, value: str) -> str:
        if value not in {"any_of", "all_of"}:
            raise ValueError("evaluation_mode must be 'any_of' or 'all_of'")
        return value


class SessionCookieConfig(BaseModel):
    cookie_name: str = "session_id"
    same_site: str = "strict"
    secure: bool = True
    http_only: bool = True
    signing_secret: str
    max_age_minutes: int = Field(default=60, gt=0)

    @field_validator("same_site")
    @classmethod
    def normalize_same_site(cls, value: str) -> str:
        allowed = {"strict", "lax", "none"}
        value_lower = value.lower()
        if value_lower not in allowed:
            raise ValueError(f"same_site must be one of {allowed}")
        return value_lower


class CSRFConfig(BaseModel):
    enabled: bool = True
    secret: str = Field(default="change-me")


class SecurityConfig(BaseModel):
    require_pkce: bool = True
    validate_state_nonce: bool = True
    enforce_issuer_aud: bool = True
    token_at_rest_encryption: bool = True
    token_encryption_secret: str = Field(default="change-me", repr=False)


class SQLiteConfig(BaseModel):
    db_path: Path = Path("./data/app.db")
    busy_timeout_ms: int = Field(default=5000, ge=0)
    pragmas: Dict[str, Any] = Field(
        default_factory=lambda: {"journal_mode": "WAL", "synchronous": "NORMAL"}
    )


class ServerConfig(BaseModel):
    base_url: AnyHttpUrl | None = None
    cors_allowed_origins: List[str] = Field(default_factory=list)
    log_level: str = Field(default="INFO")


class UIConfig(BaseModel):
    default_authenticated_route: str = "/#/home"
    default_logged_out_route: str = "/#/login"


class AppConfig(BaseModel):
    azure: AzureConfig
    rbac: RBACConfig
    session: SessionCookieConfig
    csrf: CSRFConfig = CSRFConfig()
    security: SecurityConfig = SecurityConfig()
    sqlite: SQLiteConfig = SQLiteConfig()
    server: ServerConfig = ServerConfig()
    ui: UIConfig = UIConfig()


def load_config(path: Path | str) -> AppConfig:
    """
    Load the application configuration from yaml.

    Parameters
    ----------
    path:
        Path to a YAML file.  Relative paths are resolved relative to the caller.
    """

    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Configuration file not found: {path_obj}")

    with path_obj.open("r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file) or {}

    return AppConfig.model_validate(raw_config)
