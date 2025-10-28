from __future__ import annotations

from typing import List

import httpx


class GraphClient:
    def __init__(self, base_url: str = "https://graph.microsoft.com/v1.0") -> None:
        self._base_url = base_url.rstrip("/")

    async def get_member_groups(self, access_token: str) -> List[str]:
        if not access_token:
            return []
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        url = f"{self._base_url}/me/getMemberObjects"
        payload = {"securityEnabledOnly": True}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        data = response.json()
        values = data.get("value", [])
        return [str(item) for item in values if isinstance(item, str)]
