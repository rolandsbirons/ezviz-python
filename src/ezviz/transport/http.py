"""Async HTTP transport for the EZVIZ cloud API."""
from __future__ import annotations

from typing import Any

import httpx

from ..exceptions import EzvizError
from ..feature_code import feature_code


def _default_headers() -> dict[str, str]:
    """The standard EZVIZ app request headers, required on every call.

    Ported from the reference ``REQUEST_HEADER`` (pyEzvizApi constants) — the API
    rejects requests (HTTP 400) without ``appId``/``clientType``/``customno`` etc.
    """
    return {
        "featureCode": feature_code(),
        "clientType": "3",
        "osVersion": "",
        "clientVersion": "",
        "netType": "WIFI",
        "customno": "1000001",
        "ssid": "",
        "clientNo": "web_site",
        "appId": "ys7",
        "language": "en_GB",
        "lang": "en",
        "User-Agent": "okhttp/3.12.1",
    }


class EzvizHttp:
    """Thin async wrapper over httpx for the EZVIZ cloud REST API.

    Sends the standard app headers + session id and unwraps the ``{"meta": {...}}``
    envelope.
    """

    def __init__(self, domain: str, *, timeout: float = 15.0) -> None:
        self._domain = domain
        self._session: str | None = None
        self._client = httpx.AsyncClient(
            base_url=f"https://{domain}", timeout=timeout,
            headers=_default_headers(),
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
        # follow_redirects=False matches the reference (requests' allow_redirects=
        # False in client.py::_login) -- httpx already defaults to this, but it's
        # made explicit here since login's behavior depends on it.
        resp = await self._client.post(
            path, data=data, headers=self._session_headers(), follow_redirects=False
        )
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

    async def get_bytes(self, url: str) -> bytes:
        """GET a URL and return the raw response body.

        ``url`` is typically an absolute image-CDN URL (picture/alarm-image
        download links point off the account API host); httpx uses an
        absolute URL as-is instead of joining it with ``base_url``, while
        this still carries the same session headers as every other call
        (reference: ``client.py``'s ``_http_request`` sends the persistent
        session's headers on every request, image downloads included).
        """
        resp = await self._client.get(url, headers=self._session_headers())
        resp.raise_for_status()
        return resp.content

    async def put_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """PUT a JSON body (vs. :meth:`put_form`'s form encoding).

        Reference: client.py::_iot_request -- explicitly sets
        ``Content-Type: application/json`` and a ``json.dumps`` body for the
        IoT feature/action endpoints (e.g. PTZ coordinate control), unlike
        the form-encoded ``PUT``s used elsewhere in the API.
        """
        headers = {**self._session_headers(), "Content-Type": "application/json"}
        resp = await self._client.put(path, json=payload, headers=headers)
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        return self._unwrap(body, path)

    async def put_form(self, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._client.put(path, data=data, headers=self._session_headers())
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        return self._unwrap(payload, path)

    async def post_device(self, serial: str, suffix: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.post_form(f"/v3/devices/{serial}{suffix}", data)

    async def put_device(
        self, serial: str, suffix: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self.put_form(f"/v3/devices/{serial}{suffix}", data)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> EzvizHttp:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
