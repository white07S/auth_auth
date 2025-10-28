from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, Mapping, Sequence
from urllib.parse import urlencode

import msal

from ..config import Config


class MsalClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._app = msal.ConfidentialClientApplication(
            client_id=config.client_id,
            client_credential=self._client_credential(config),
            authority=config.authority,
        )

    @property
    def scopes(self) -> Sequence[str]:
        return tuple(dict.fromkeys([*self._config.scopes, *self._config.graph_scopes]))

    def initiate_auth_flow(self) -> Dict[str, Any]:
        flow = self._app.initiate_auth_code_flow(
            scopes=self.scopes,
            redirect_uri=self._config.redirect_uri,
        )
        if "state" not in flow:
            raise RuntimeError("MSAL did not return state for auth code flow")
        return flow

    async def acquire_tokens(self, flow: Mapping[str, Any], query_params: Mapping[str, Any]) -> Dict[str, Any]:
        result = await asyncio.to_thread(self._app.acquire_token_by_auth_code_flow, flow, dict(query_params))
        self._raise_if_error(result)
        return result

    async def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        result = await asyncio.to_thread(
            self._app.acquire_token_by_refresh_token,
            refresh_token,
            scopes=self.scopes,
        )
        self._raise_if_error(result)
        return result

    def build_logout_url(self) -> str:
        params = {"post_logout_redirect_uri": self._config.post_logout_redirect_uri}
        return f"{self._config.authority}/oauth2/v2.0/logout?{urlencode(params)}"

    @staticmethod
    def _raise_if_error(result: Mapping[str, Any]) -> None:
        if "error" in result:
            error_description = result.get("error_description", "unknown error")
            raise RuntimeError(f"MSAL error: {result['error']} - {error_description}")

    @staticmethod
    def _client_credential(config: Config) -> Any:
        if config.client_secret:
            return config.client_secret
        if config.client_certificate:
            return config.client_certificate
        raise ValueError("Configure client_secret or client_certificate")
