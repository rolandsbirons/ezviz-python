"""Typed models. Field mappings mirror the EZVIZ cloud API (see pyEzvizApi as the
reference contract); we re-express them cleanly here."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .exceptions import EzvizError


class Region(Enum):
    EU = "apiieu.ezvizlife.com"
    US = "apiius.ezvizlife.com"
    RU = "apirus.ezvizru.com"

    @property
    def api_domain(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, value: str) -> Region:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown region {value!r}") from exc


@dataclass(slots=True, frozen=True)
class Device:
    """A discovered camera/device from the pagelist ``deviceInfos`` list.

    ``sub_category``/``version``/``channels`` live directly on the
    ``deviceInfos`` item itself (confirmed: camera.py::status() --
    ``self.fetch_key(["deviceInfos", "deviceSubCategory"])`` /
    ``["deviceInfos", "version"]`` / ``["deviceInfos", "channelNumber"]``
    (the latter surfaced as ``status()``'s ``supported_channels``), same
    item shape as ``name``/``status``/``deviceCategory``). ``wan_ip``/
    ``encrypted``/``local_ip`` live in SIBLING pagelist blocks keyed by
    device serial, not on the ``deviceInfos`` item -- confirmed:
    camera.py::status()'s ``wan_ip = conn.get("netIp") or
    self.fetch_key(["CONNECTION", "netIp"])``, ``bool(self.fetch_key(
    ["STATUS", "isEncrypt"]))``, and ``local_ip``'s own fallback chain
    (``_local_ip()``, which prefers ``WIFI.address`` -- when set and not
    ``"0.0.0.0"`` -- then falls back to ``CONNECTION.localIp``). The WIFI
    preference matters in practice, not just on paper: some fixed-lens
    cameras (e.g. the C3X) report an empty ``CONNECTION.localIp`` and only
    publish their LAN address via ``WIFI.address`` -- confirmed against a
    real device (a live-deployment bug report: inventory showed
    ``local_ip=None`` for exactly this camera). :meth:`from_api` takes
    ``status``/``connection``/``wifi`` as separate optional args (see
    ``EzvizClient.cameras()``, which requests ``CONNECTION``+``WIFI``
    alongside the existing ``STATUS`` filter to supply them).
    """

    serial: str
    name: str
    online: bool
    category: str
    sub_category: str = ""
    version: str = ""
    wan_ip: str | None = None
    encrypted: bool = False
    local_ip: str | None = None
    channels: int = 1

    @classmethod
    def from_api(
        cls,
        data: dict[str, Any],
        *,
        status: dict[str, Any] | None = None,
        connection: dict[str, Any] | None = None,
        wifi: dict[str, Any] | None = None,
    ) -> Device:
        status = status or {}
        connection = connection or {}
        wifi = wifi or {}
        net_ip = connection.get("netIp")
        conn_local_ip = connection.get("localIp")
        wifi_address = wifi.get("address")
        local_ip: str | None
        if isinstance(wifi_address, str) and wifi_address.strip() and wifi_address != "0.0.0.0":
            local_ip = wifi_address.strip()
        else:
            local_ip = (
                str(conn_local_ip) if isinstance(conn_local_ip, str) and conn_local_ip else None
            )
        channel_number = data.get("channelNumber")
        channels = channel_number if isinstance(channel_number, int) and channel_number > 0 else 1
        return cls(
            serial=str(data["deviceSerial"]),
            name=str(data.get("name", "")),
            online=int(data.get("status", 0)) == 1,
            category=str(data.get("deviceCategory", "")),
            sub_category=str(data.get("deviceSubCategory", "")),
            version=str(data.get("version", "")),
            wan_ip=str(net_ip) if isinstance(net_ip, str) and net_ip else None,
            encrypted=bool(status.get("isEncrypt", False)),
            local_ip=local_ip,
            channels=channels,
        )


class PtzDirection(Enum):
    """PTZ move direction. Reference: client.py::ptz_control/camera.py::move --
    the wire value is the word direction uppercased (sent as the `command`
    field), not a numeric code."""

    UP = "UP"
    DOWN = "DOWN"
    LEFT = "LEFT"
    RIGHT = "RIGHT"


class Switch(Enum):
    """Device switch ids (subset). Values confirmed against pyEzvizApi
    constants.py::DeviceSwitchType."""

    ALARM_TONE = 1
    LIGHT = 3
    PRIVACY = 7
    INFRARED_LIGHT = 10
    SLEEP = 21
    SOUND = 22
    MOBILE_TRACKING = 25


class DefenceMode(Enum):
    """Account-level (all devices) arm/disarm mode. Values confirmed against
    pyEzvizApi constants.py::DefenseModeType."""

    UNSET = 0
    HOME = 1
    AWAY = 2
    SLEEP = 3


@dataclass(slots=True, frozen=True)
class Alarm:
    """One alarm/event entry from ``/v3/alarms/v2/advanced``
    (API_ENDPOINT_ALARMINFO_GET; request params confirmed against
    client.py::get_alarminfo).

    pyEzvizApi itself never parses this endpoint's item fields anywhere --
    ``get_alarminfo`` returns the raw payload untouched, so there is no
    reference function to read for the item schema (the earlier ``label``
    mapping's ``sampleName`` guess came from an unrelated code path, the
    *unified message* normalizer, not this endpoint). The item keys below are
    instead confirmed against a real, working consumer of this exact
    endpoint: the camera-soc bridge (``app.py``'s ``api_alarms``/
    ``alarm_media``/``poll_alarms_once``), which reads ``alarmId``,
    ``alarmType``, ``alarmStartTime``, ``alarmStartTimeStr``, ``alarmName``,
    ``isEncrypt``, ``picUrl`` directly off these items.
    """

    id: str
    type: int
    start_ms: int
    #: Alarm label. Kept for backward compat; now sourced the same as
    #: ``name`` (``alarmName``), with a defensive fallback to the unrelated-
    #: endpoint key ``sampleName`` in case an older/different response shape
    #: is ever encountered.
    label: str
    pic_url: str
    time_str: str
    name: str
    encrypted: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Alarm:
        name = str(data.get("alarmName") or data.get("sampleName") or "")
        return cls(
            id=str(data.get("alarmId", "")),
            type=int(data.get("alarmType", 0)),
            start_ms=int(data.get("alarmStartTime", 0)),
            label=name,
            pic_url=str(data.get("picUrl", "")),
            time_str=str(data.get("alarmStartTimeStr", "")),
            name=name,
            encrypted=bool(data.get("isEncrypt", False)),
        )


def _first_int(*values: Any) -> int:
    """Return the first value that converts cleanly to int, else 0."""
    for value in values:
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _first_str(*values: Any) -> str:
    """Return the first non-empty value, str-coerced (not parsed); else ''."""
    for value in values:
        if value is None:
            continue
        text = str(value)
        if text:
            return text
    return ""


@dataclass(slots=True, frozen=True)
class Record:
    """One SD-card recording time-range segment (no download URL -- that's a
    separate, later API). Reference: client.py::search_records_v2 (request) +
    extract_record_list (response's top-level "records" key). Item field
    aliases mirror the defensive multi-key fallback the reference CLI itself
    uses when displaying records (__main__.py::_handle_records), since the
    exact key used by any given firmware/response variant isn't fixed.

    ``begin``/``end`` are the API's RAW segment bounds, str-coerced but
    otherwise unparsed -- confirmed against a real camera (a live-deployment
    bug report): the real per-item keys are ``B``/``E``/``Type``/``Res``/
    ``Res2``, and ``B``/``E`` are ISO-8601 datetime STRINGS (e.g.
    ``"2026-07-23T00:00:00"``), not epoch-ms ints. Coercing through
    ``int()`` (the old ``start_ms``/``stop_ms`` fields) silently produced
    ``0`` for every record. str-coercion instead of parsing keeps this
    working for BOTH the ISO-string firmware confirmed here and any
    epoch-int firmware another device/response variant might return --
    callers that need a real datetime/epoch value parse it themselves.
    """

    begin: str
    end: str
    type: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Record:
        return cls(
            begin=_first_str(
                data.get("B"), data.get("begin"), data.get("startTime"), data.get("startTimeStr")
            ),
            end=_first_str(
                data.get("E"), data.get("end"), data.get("stopTime"), data.get("stopTimeStr")
            ),
            type=_first_int(
                data.get("type"),
                data.get("Type"),
                data.get("recordType"),
                data.get("videoType"),
                data.get("recType"),
            ),
        )


# Reference default when localCmdPort is absent from CONNECTION metadata
# (hcnetsdk.py::HCNETSDK_DEFAULT_SERVER_PORT).
_DEFAULT_CMD_PORT = 8000


@dataclass(slots=True, frozen=True)
class DeviceEndpoint:
    """A device's LAN reachability info, for the local-SDK live path.

    Reference: hcnetsdk.py::HcNetSdkLanEndpoint.from_connection -- built from
    a pagelist ``CONNECTION`` block (fetched via ``EzvizClient.device_
    endpoint``, the SAME ``/v3/userdevices/v1/resources/pagelist`` endpoint
    as device discovery, just with ``filter=CONNECTION,WIFI``). ``cmd_port``/
    ``stream_port``/``net_ip`` always come from ``CONNECTION``; ``local_ip``
    prefers an optional ``wifi`` block's ``address`` (when set and not
    ``"0.0.0.0"``) over ``CONNECTION.localIp`` -- confirmed against a real
    device (a live-deployment bug report): fixed-lens cameras (e.g. the C3X)
    report an empty ``CONNECTION.localIp`` and only publish their LAN
    address via ``WIFI.address``, so live streaming broke on them before
    this fix (``from_connection`` used to unconditionally raise). NOTE: the
    reference's own local-SDK-stream endpoint resolution
    (``HcNetSdkLanEndpoint.from_connection``, ``local_stream.py::
    _local_sdk_endpoint_from_client``) does NOT have this WIFI fallback --
    it's CONNECTION-only and would raise on a C3X too. This applies the
    SAME WIFI-preference the reference itself already uses for the
    equivalent inventory-display concept (camera.py::status()'s
    ``_local_ip()``) to this endpoint-resolution path too, since it's the
    same underlying LAN address -- a deliberate improvement beyond a
    literal reference port, motivated directly by the real failure.
    """

    local_ip: str
    net_ip: str | None = None
    cmd_port: int = _DEFAULT_CMD_PORT
    stream_port: int | None = None

    @classmethod
    def from_connection(
        cls, connection: dict[str, Any], *, wifi: dict[str, Any] | None = None
    ) -> DeviceEndpoint:
        wifi_address = (wifi or {}).get("address")
        if isinstance(wifi_address, str) and wifi_address.strip() and wifi_address != "0.0.0.0":
            local_ip: str | None = wifi_address.strip()
        else:
            conn_local_ip = connection.get("localIp")
            local_ip = (
                conn_local_ip
                if isinstance(conn_local_ip, str) and conn_local_ip.strip()
                else None
            )
        if local_ip is None:
            raise EzvizError("CONNECTION/WIFI metadata is missing a usable localIp")
        net_ip = connection.get("netIp")
        cmd_port = connection.get("localCmdPort") or _DEFAULT_CMD_PORT
        stream_port = connection.get("localStreamPort")
        return cls(
            local_ip=local_ip.strip(),
            net_ip=str(net_ip) if net_ip else None,
            cmd_port=int(cmd_port),
            stream_port=int(stream_port) if stream_port else None,
        )
