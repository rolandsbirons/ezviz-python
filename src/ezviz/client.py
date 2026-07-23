"""Public async facade."""
from __future__ import annotations

from .auth import Session, login
from .camera import Camera
from .exceptions import AuthError, EzvizError
from .models import DefenceMode, Device, DeviceEndpoint, Region
from .transport.cas import CasClient, CasCredentials
from .transport.http import EzvizHttp

DEVICES_PATH = "/v3/userdevices/v1/resources/pagelist"
DEFENCE_MODE_PATH = "/v3/userdevices/v1/group/defenceMode"
SWITCH_DEFENCE_MODE_PATH = "/v3/userdevices/v1/group/switchDefenceMode"
# Reference: client.py::get_service_urls -- API_ENDPOINT_SERVER_INFO.
SERVER_INFO_PATH = "/v3/configurations/system/info"
# -1 means "all devices" -- the account-level defence panel on the app's home page.
_ALL_DEVICES_GROUP_ID = "-1"
# Confirmed by reading client.py::get_device_infos -> _get_page_list ->
# _api_get_pagelist: it's the SAME pagelist endpoint as device discovery
# (DEVICES_PATH above), just with a broader `filter` (includes "CONNECTION")
# and explicit groupId/limit/offset -- NOT a different endpoint path.
_PAGELIST_GROUP_ID = "-1"
_PAGELIST_LIMIT = "30"
_PAGELIST_OFFSET = "0"
# Reference: cas.py's EzvizCAS._cloud_address reads the CAS host/port from
# the account's own login "service urls" -- systemConfigInfo.sysConf, a
# pipe-delimited string, at these fixed indices.
_CAS_SYS_CONF_HOST_INDEX = 15
_CAS_SYS_CONF_PORT_INDEX = 16
# Placeholder hardware/feature code sent as the CAS request's <Sign> field
# (reference: EzvizCAS._hardware_code, which defaults to a MAC-derived
# per-install FEATURE_CODE). Matches auth.py's login featureCode placeholder
# for consistency; a real per-install code is still a follow-up item.
_CAS_HARDWARE_CODE = "ezviz-python"


class EzvizClient:
    def __init__(self, region: str = "eu") -> None:
        self._http = EzvizHttp(domain=Region.from_str(region).api_domain)
        self._session: Session | None = None
        self._cas_address: tuple[str, int] | None = None

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
            out[dev.serial] = Camera(dev, http=self._http, client=self)
        return out

    async def cas_credentials(self, serial: str) -> CasCredentials:
        """Fetch a device's local-control CAS credentials (key + operation code).

        Reference wiring: local_stream.py::get_local_sdk_stream_credentials_
        from_client -- ``EzvizCAS(client.export_token()).cas_get_encryption(serial)``.
        """
        if self._session is None:
            raise AuthError("not logged in")
        host, port = await self._cas_cloud_address()
        cas_client = CasClient(
            host=host,
            port=port,
            session_id=self._session.session_id,
            hardware_code=_CAS_HARDWARE_CODE,
        )
        return await cas_client.get_device_credentials(serial)

    async def _cas_cloud_address(self) -> tuple[str, int]:
        """Resolve (and cache) the CAS cloud host/port from server-info sysConf."""
        if self._cas_address is None:
            payload = await self._http.get_json(SERVER_INFO_PATH)
            sys_conf_raw = str(payload.get("systemConfigInfo", {}).get("sysConf", ""))
            sys_conf = sys_conf_raw.split("|")
            if len(sys_conf) <= _CAS_SYS_CONF_PORT_INDEX:
                raise EzvizError("server info response is missing CAS sysConf entries")
            self._cas_address = (
                sys_conf[_CAS_SYS_CONF_HOST_INDEX],
                int(sys_conf[_CAS_SYS_CONF_PORT_INDEX]),
            )
        return self._cas_address

    async def device_endpoint(self, serial: str) -> DeviceEndpoint:
        """Look up a device's LAN reachability info (for the local-SDK live path).

        Reference: client.py::get_device_infos -- confirmed (not guessed) to
        reuse the SAME pagelist endpoint as ``cameras()`` above, requested
        with ``filter=CONNECTION`` (plus the pagelist's usual groupId/limit/
        offset). Response top-level key ``CONNECTION`` is itself keyed by
        device serial.
        """
        if self._session is None:
            raise AuthError("not logged in")
        payload = await self._http.get_json(
            DEVICES_PATH,
            params={
                "filter": "CONNECTION",
                "groupId": _PAGELIST_GROUP_ID,
                "limit": _PAGELIST_LIMIT,
                "offset": _PAGELIST_OFFSET,
            },
        )
        connection = (payload.get("CONNECTION") or {}).get(serial)
        if not connection:
            raise EzvizError(f"device {serial} has no CONNECTION data")
        return DeviceEndpoint.from_connection(connection)

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
