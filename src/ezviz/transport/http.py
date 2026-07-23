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

    @property
    def domain(self) -> str:
        return self._domain

    def set_session(self, session_id: str | None) -> None:
        self._session = session_id

    def set_domain(self, domain: str) -> None:
        self._domain = domain
        self._client.base_url = httpx.URL(f"https://{domain}")

    def _session_headers(self) -> dict[str, str]:
        return {"sessionId": self._session} if self._session else {}

    def _unwrap(self, payload: dict[str, Any], path: str) -> dict[str, Any]:
        code = int(payload.get("meta", {}).get("code", 200))
        if code != 200:
            msg = payload.get("meta", {}).get("message", f"api code {code}")
            raise EzvizError(f"{path}: {msg}")
        return payload

    async def post_raw(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """POST a form and return the parsed JSON payload as-is.

        Unlike :meth:`post_form`, this does NOT raise on a non-200 ``meta.code`` —
        it's for callers (like login) that need to branch on specific API codes
        themselves (e.g. region-redirect/MFA) rather than treat them as errors.
        """
        resp = await self._client.post(path, data=data, headers=self._session_headers())
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        return payload

    async def post_form(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        resp = await self._client.post(path, data=data, headers=self._session_headers())
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        return self._unwrap(payload, path)

    async def get_json(self, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        resp = await self._client.get(path, params=params, headers=self._session_headers())
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        return self._unwrap(payload, path)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> EzvizHttp:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
