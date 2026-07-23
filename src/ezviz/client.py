"""Public async facade."""
from __future__ import annotations

from .auth import Session, login
from .camera import Camera
from .exceptions import AuthError
from .models import DefenceMode, Device, Region
from .transport.http import EzvizHttp

DEVICES_PATH = "/v3/userdevices/v1/resources/pagelist"
DEFENCE_MODE_PATH = "/v3/userdevices/v1/group/defenceMode"
SWITCH_DEFENCE_MODE_PATH = "/v3/userdevices/v1/group/switchDefenceMode"
# -1 means "all devices" -- the account-level defence panel on the app's home page.
_ALL_DEVICES_GROUP_ID = "-1"


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
            out[dev.serial] = Camera(dev, http=self._http)
        return out

    async def set_defence_mode(self, mode: DefenceMode) -> None:
        """Set the account-level (all devices) defence/arm mode.

        Reference: client.py::api_set_defence_mode -- ``POST``
        ``/v3/userdevices/v1/group/switchDefenceMode`` with body
        ``{"groupId": -1, "mode": <int>}``. Note the field is ``mode``, not
        ``type``.
        """
        await self._http.post_form(
            SWITCH_DEFENCE_MODE_PATH,
            {"groupId": _ALL_DEVICES_GROUP_ID, "mode": str(mode.value)},
        )

    async def defence_mode(self) -> DefenceMode:
        """Get the account-level defence/arm mode.

        Reference: client.py::get_group_defence_mode -- ``GET``
        ``/v3/userdevices/v1/group/defenceMode?groupId=-1``, response top-level
        key ``mode``.
        """
        data = await self._http.get_json(
            DEFENCE_MODE_PATH, params={"groupId": _ALL_DEVICES_GROUP_ID}
        )
        return DefenceMode(int(data.get("mode", 0)))

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> EzvizClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
