"""Async HTTP transport for the EZVIZ cloud API."""
from __future__ import annotations

from typing import Any

import httpx

from ..exceptions import EzvizError


class EzvizHttp:
    """Thin async wrapper over httpx for the EZVIZ cloud REST API.

    Sends the session id header and unwraps the standard ``{"meta": {...}}`` envelope.
    """

    def __init__(self, domain: str, *, timeout: float = 15.0) -> None:
        self._domain = domain
        self._session: str | None = None
        self._client = httpx.AsyncClient(
            base_url=f"https://{domain}", timeout=timeout,
            headers={"User-Agent": "ezviz-python/0.1"},
        )

    def set_session(self, session_id: str | None) -> None:
        self._session = session_id

    def set_domain(self, domain: str) -> None:
        self._domain = domain
        self._client.base_url = httpx.URL(f"https://{domain}")

    async def post_form(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        headers = {"sessionId": self._session} if self._session else {}
        resp = await self._client.post(path, data=data, headers=headers)
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        code = int(payload.get("meta", {}).get("code", 200))
        if code != 200:
            msg = payload.get("meta", {}).get("message", f"api code {code}")
            raise EzvizError(f"{path}: {msg}")
        return payload

    async def post_form_or_get(
        self, path: str, *, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        headers = {"sessionId": self._session} if self._session else {}
        resp = await self._client.get(path, params=params, headers=headers)
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        code = int(payload.get("meta", {}).get("code", 200))
        if code != 200:
            raise EzvizError(f"{path}: api code {code}")
        return payload

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> EzvizHttp:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
