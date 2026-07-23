"""Public async facade."""
from __future__ import annotations

from .auth import Session, login
from .camera import Camera
from .exceptions import AuthError
from .models import Device, Region
from .transport.http import EzvizHttp

DEVICES_PATH = "/v3/userdevices/v1/resources/pagelist"


class EzvizClient:
    def __init__(self, region: str = "eu") -> None:
        self._http = EzvizHttp(domain=Region.from_str(region).api_domain)
        self._session: Session | None = None

    async def login(self, account: str, password: str) -> None:
        self._session = await login(self._http, account, password)

    async def cameras(self) -> dict[str, Camera]:
        if self._session is None:
            raise AuthError("not logged in")
        payload = await self._http.get_json(
            DEVICES_PATH, params={"filter": "CLOUD,TIME_PLAN,STATUS"}
        )
        out: dict[str, Camera] = {}
        for info in payload.get("deviceInfos", []) or []:
            dev = Device.from_api(info)
            out[dev.serial] = Camera(dev)
        return out

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> EzvizClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
