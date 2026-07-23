"""Public async facade."""
from __future__ import annotations

from .auth import Session, login
from .camera import Camera
from .exceptions import AuthError, EzvizError
from .feature_code import feature_code
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


class EzvizClient:
    def __init__(self, region: str = "eu") -> None:
        self._http = EzvizHttp(domain=Region.from_str(region).api_domain)
        self._session: Session | None = None
        self._cas_address: tuple[str, int] | None = None

    async def login(self, account: str, password: str) -> None:
        self._session = await login(self._http, account, password)

    async def cameras(self) -> dict[str, Camera]:
        """Discover cameras on the account.

        Reference filter mirrors client.py::_get_page_list's broad-filter
        single-call pattern (not a per-device fetch): ``CONNECTION`` and
        ``WIFI`` were added to the filter (alongside the pre-existing
        ``CLOUD,TIME_PLAN,STATUS``) so ``Device.wan_ip``/``local_ip``
        (``CONNECTION[serial].netIp``/``.localIp``, ``WIFI[serial].address``,
        confirmed via camera.py::status()) can be populated from the SAME
        request, without an extra per-camera round trip. ``WIFI`` is needed
        for real: some fixed-lens cameras (e.g. the C3X) report an empty
        ``CONNECTION.localIp`` and only publish their LAN address via
        ``WIFI.address`` (confirmed against a real device -- a live-
        deployment bug report). ``Device.channels`` (``deviceInfos.
        channelNumber``) needs no filter change -- it's on the same
        ``deviceInfos`` item already fetched via ``CLOUD``.
        """
        if self._session is None:
            raise AuthError("not logged in")
        payload = await self._http.get_json(
            DEVICES_PATH, params={"filter": "CLOUD,TIME_PLAN,STATUS,CONNECTION,WIFI"}
        )
        status_block = payload.get("STATUS") or {}
        connection_block = payload.get("CONNECTION") or {}
        wifi_block = payload.get("WIFI") or {}
        out: dict[str, Camera] = {}
        for info in payload.get("deviceInfos", []) or []:
            serial = str(info.get("deviceSerial", ""))
            dev = Device.from_api(
                info,
                status=status_block.get(serial),
                connection=connection_block.get(serial),
                wifi=wifi_block.get(serial),
            )
            out[dev.serial] = Camera(dev, http=self._http, client=self)
        return out

    async def cas_credentials(self, serial: str) -> CasCredentials:
        """Fetch a device's local-control CAS credentials (key + operation code).

        Reference wiring: local_stream.py::get_local_sdk_stream_credentials_
        from_client -- ``EzvizCAS(client.export_token()).cas_get_encryption(serial)``.
        The CAS request's ``<Sign>`` is the same generated ``feature_code()``
        sent as login's ``featureCode`` -- confirmed by reading
        ``EzvizCAS._hardware_code``'s fallback chain, which reads
        ``token["feature_code"]`` (set by ``client.py::_login`` to the same
        ``FEATURE_CODE`` used in its own login payload) before falling back
        to the module-level constant. Both call sites resolve to one value.
        """
        if self._session is None:
            raise AuthError("not logged in")
        host, port = await self._cas_cloud_address()
        cas_client = CasClient(
            host=host,
            port=port,
            session_id=self._session.session_id,
            hardware_code=feature_code(),
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
        with ``filter=CONNECTION,WIFI`` (plus the pagelist's usual groupId/
        limit/offset). Response top-level keys ``CONNECTION``/``WIFI`` are
        each keyed by device serial. ``WIFI`` was added for real: some
        fixed-lens cameras (e.g. the C3X) report an empty
        ``CONNECTION.localIp`` and only publish their LAN address via
        ``WIFI.address`` -- confirmed against a real device (a live-
        deployment bug report: live streaming broke on this camera). See
        ``DeviceEndpoint.from_connection``'s docstring for the WIFI-
        preference itself.
        """
        if self._session is None:
            raise AuthError("not logged in")
        payload = await self._http.get_json(
            DEVICES_PATH,
            params={
                "filter": "CONNECTION,WIFI",
                "groupId": _PAGELIST_GROUP_ID,
                "limit": _PAGELIST_LIMIT,
                "offset": _PAGELIST_OFFSET,
            },
        )
        connection = (payload.get("CONNECTION") or {}).get(serial)
        if not connection:
            raise EzvizError(f"device {serial} has no CONNECTION data")
        wifi = (payload.get("WIFI") or {}).get(serial)
        return DeviceEndpoint.from_connection(connection, wifi=wifi)

    async def switch_states(self, serial: str) -> dict[int, bool]:
        """Look up a device's switch on/off states.

        Reference: client.py::get_switch -- confirmed to reuse the SAME
        pagelist endpoint as ``cameras()``/``device_endpoint()``
        (``_api_get_pagelist``), just with ``filter=SWITCH``. The response's
        top-level ``SWITCH`` key is itself keyed by device serial -> a list
        of ``{"type": int, "enable": bool|int}`` items (confirmed via the
        reference camera.py's own SWITCH-parsing constructor logic).
        """
        if self._session is None:
            raise AuthError("not logged in")
        payload = await self._http.get_json(
            DEVICES_PATH,
            params={
                "filter": "SWITCH",
                "groupId": _PAGELIST_GROUP_ID,
                "limit": _PAGELIST_LIMIT,
                "offset": _PAGELIST_OFFSET,
            },
        )
        items = (payload.get("SWITCH") or {}).get(serial) or []
        out: dict[int, bool] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            kind, enabled = item.get("type"), item.get("enable")
            if isinstance(kind, int) and isinstance(enabled, bool | int):
                out[kind] = bool(enabled)
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
