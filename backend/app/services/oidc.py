from __future__ import annotations

from typing import Any, Dict, Tuple

import httpx
import msal
from fastapi import HTTPException, status

from ..config import AppConfig
from ..core.security import derive_code_challenge
from ..services.token_cache import TokenCacheService


class OIDCService:
    """
    Orchestrates the Azure AD / Entra ID OAuth2 flow using MSAL.
    """

    def __init__(self, config: AppConfig, token_cache_service: TokenCacheService):
        self._config = config
        self._token_cache_service = token_cache_service

    def _client(
        self, cache: msal.SerializableTokenCache | None = None
    ) -> msal.ConfidentialClientApplication:
        credential: str | dict[str, str]
        if self._config.azure.client_secret:
            credential = self._config.azure.client_secret
        else:
            if not self._config.azure.client_certificate_path:
                raise ValueError("client_certificate_path must be configured when no client_secret is set")
            cert_path = self._config.azure.client_certificate_path
            private_key = cert_path.read_text(encoding="utf-8")
            credential = {
                "private_key": private_key,
                "thumbprint": self._config.azure.client_certificate_thumbprint or "",
            }

        authority = (
            str(self._config.azure.authority_url)
            if self._config.azure.authority_url
            else f"https://login.microsoftonline.com/{self._config.azure.tenant_id}"
        )

        return msal.ConfidentialClientApplication(
            client_id=self._config.azure.client_id,
            client_credential=credential,
            authority=authority,
            token_cache=cache,
        )

    def build_authorization_url(
        self,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        code_challenge = derive_code_challenge(code_verifier)
        client = self._client()

        url = client.get_authorization_request_url(
            scopes=self._config.azure.graph_scopes,
            state=state,
            redirect_uri=redirect_uri,
            response_type="code",
            response_mode="query",
            prompt=None,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )
        return url

    async def redeem_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> Tuple[Dict[str, Any], msal.SerializableTokenCache]:
        cache = self._token_cache_service.new_cache()
        client = self._client(cache)
        result = client.acquire_token_by_authorization_code(
            code=code,
            scopes=self._config.azure.graph_scopes,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        if "error" in result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failure: {result.get('error_description')}",
            )
        return result, cache

    async def exchange_on_behalf_of(
        self,
        cache_blob: msal.SerializableTokenCache,
        scopes: list[str],
    ) -> Tuple[str, msal.SerializableTokenCache]:
        client = self._client(cache_blob)
        accounts = client.get_accounts()
        if not accounts:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No account cached")

        result = client.acquire_token_silent(scopes, account=accounts[0])
        if not result or "access_token" not in result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unable to acquire Graph token: {result.get('error_description')}",
            )
        return result["access_token"], cache_blob


class GraphService:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=10)

    async def get_user_profile(self, access_token: str) -> dict[str, Any]:
        response = await self._client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()

    async def get_user_groups(self, access_token: str) -> list[dict[str, Any]]:
        response = await self._client.get(
            "https://graph.microsoft.com/v1.0/me/memberOf?$select=id,displayName",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("value", [])

    async def close(self) -> None:
        await self._client.aclose()
